/*
Userspace Virtual Filesystem

This file is part of usvfs.

usvfs is free software:
 * you can redistribute it and/or modify
it under the terms of the GNU General Public
 * License as published by
the Free Software Foundation, either version 3 of the
 * License, or
(at your option) any later version.

usvfs is distributed in the hope
 * that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty
 * of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public
 * License for more details.

You should have received a copy of the GNU General Public
 * License
along with usvfs. If not, see <http://www.gnu.org/licenses/>.
*/
#include "readcache.h"
#include "config.h"
#include "hookcallcontext.h"
#include "metacache.h"
#include "readcache_logic.h"

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <list>
#include <unordered_map>

// Read cache
// ==========
//
// Skyrim (under Wine) issues tens of thousands of small NtReadFile calls per
// second that are all served from the OS page cache, so the cost is almost
// entirely the syscall. We answer those from an in-process copy of the file.
//
// Layer 1 (always on unless USVFS_READCACHE=0): the first NtReadFile on an
// unknown handle classifies the handle (see logic::evaluateEligibility). An
// eligible handle starts on probation: its reads pass through while the small
// reads of the file are counted (per CacheEntry, so reopens accumulate). Once
// USVFS_READCACHE_ADMIT_READS have been seen the file is admitted: its
// CacheEntry holds the whole file, loaded synchronously with the real NtReadFile.
// Entries are shared between handles by {file id, size, write time, change time}. All
// eligible handles keep a "shadow" file pointer, because served reads do not move the
// real one; the position queries/updates are patched accordingly and any read
// we cannot serve first writes the shadow position back to the real pointer.
//
// Layer 2 (on by default, USVFS_READCACHE_ASYNC=0 disables): instead of filling in the
// calling thread, the fill is queued to a small worker pool. Workers read the
// file in 1 MiB chunks through their own handle and publish progress in
// CacheEntry::loadedBytes; readers wait only for the range they need.
//   The worker handle is opened *by name*: the NT name of the caller's handle
//   (NtQueryObject/ObjectNameInformation) is captured at classification time,
//   and after opening the file id, size and times are compared with the cache
//   key, so a renamed/replaced file fails the fill instead of caching wrong
//   data. (FILE_OPEN_BY_FILE_ID was not used: it needs a volume handle and its
//   behaviour under Wine is unverified. DuplicateHandle would share the file
//   pointer and is not an option.) If the name cannot be queried the fill
//   falls back to the synchronous path.
//
// Correctness rules worth remembering:
//  * the key has no volume serial: querying it is far too expensive under Wine
//    (mountmgr round trip per handle). A collision would need equal inode, size,
//    write time and change time (ns precision) on two different filesystems;
//  * the state of a handle is erased in onClose() *before* the real close:
//    handle values get reused;
//  * a handle is classified exactly once; negative results are stored too;
//  * served data is a snapshot of the file at the time of the fill. Handles
//    are only eligible if they cannot write, but another handle writing to the
//    same file would not be noticed by already classified handles.

namespace usvfs::readcache
{

std::atomic<bool> g_enabled{false};

namespace
{

  using logic::Eligibility;
  namespace chr = std::chrono;

  constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
  constexpr NTSTATUS kStatusBufferTooSmall     = static_cast<NTSTATUS>(0xC0000023L);

  // tunables (defaults here, overridden from the configuration in init())
  uint64_t kSyncChunk  = 8ull << 20;  // layer 1 fill chunk
  uint64_t kAsyncChunk = 1ull << 20;  // layer 2 fill chunk
  chr::seconds kWaitLimit{30};
  uint64_t kLogIntervalMs = 30000;
  bool g_serveEnabled     = true;  // serve small reads from memory
  bool g_infoEnabled      = true;  // answer file-information queries from the snapshot
  bool g_positionEnabled = true;  // answer FilePositionInformation of probation handles
  bool g_shareToMeta     = true;  // feed the metacache attr store from classifications
  uint64_t g_raCheckBytes = 128ull << 20;
  uint64_t g_raWastePct   = 30;
  uint64_t g_raBackoffMs  = 10000;

  // ---------------------------------------------------------------------------
  // guarded memory access (no C++ objects with destructors in these functions)

  thread_local bool t_inProtectedCopy = false;
  thread_local uint64_t t_syncFillUs =
      0;  // sync fill time on this thread, see classify()

  bool sehCopy(void* dst, const void* src, size_t n)
  {
    bool ok           = true;
    t_inProtectedCopy = true;
    __try {
      std::memcpy(dst, src, n);
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
                        GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
      ok = false;
    }
    t_inProtectedCopy = false;
    return ok;
  }

  bool sehStoreStatus(PIO_STATUS_BLOCK iosb, NTSTATUS status, ULONG_PTR info)
  {
    IO_STATUS_BLOCK local;
    std::memset(&local, 0, sizeof(local));
    local.Status      = status;
    local.Information = info;
    return sehCopy(iosb, &local, sizeof(local));
  }

  bool sehStoreInt64(void* dst, int64_t value)
  {
    return sehCopy(dst, &value, sizeof(value));
  }

  // ---------------------------------------------------------------------------
  // data structures

  struct Key
  {
    int64_t fileId  = 0;
    uint64_t size   = 0;
    int64_t written = 0;
    int64_t changed = 0;

    bool operator==(const Key& o) const
    {
      return fileId == o.fileId && size == o.size && written == o.written &&
             changed == o.changed;
    }
  };

  struct KeyHash
  {
    size_t operator()(const Key& k) const
    {
      uint64_t h = 1469598103934665603ull;
      auto mix   = [&](uint64_t v) {
        h ^= v;
        h *= 1099511628211ull;
        h ^= h >> 29;
      };
      mix(static_cast<uint64_t>(k.fileId));
      mix(k.size);
      mix(static_cast<uint64_t>(k.written));
      mix(static_cast<uint64_t>(k.changed));
      return static_cast<size_t>(h);
    }
  };

  enum EntryState : int
  {
    kEmpty = 0,  // nobody started loading
    kLoading,    // being loaded (sync filler holds `m`, or queued/running async)
    kReady,
    kFailed
  };

  struct CacheEntry
  {
    Key key;
    uint64_t size = 0;
    std::unique_ptr<uint8_t[]> data;  // null while not resident

    // Readers hold dataLock shared while they look at `data`; eviction frees the
    // buffer under an exclusive try_lock and skips entries that are busy.
    std::shared_mutex dataLock;
    std::atomic<uint64_t> lastUse{0};  // tick of the last serve/fill (approximate LRU)
    std::atomic<uint32_t> smallReads{0};  // small reads seen on any handle of this file
    std::atomic<bool> everFilled{false};  // distinguishes a refill from the first fill
    bool counted = false;  // data is included in the store's total; store mutex

    std::atomic<uint64_t> loadedBytes{0};
    std::atomic<int> state{kEmpty};

    std::mutex m;  // guards state transitions, pairs with cv
    std::condition_variable cv;

    std::wstring ntPath;  // layer 2: name used by the worker to reopen the file
  };

  // what the system told us about a file at classification; valid for the whole
  // life of an eligible handle (read-only, and the cache key holds size and times)
  struct FileSnapshot
  {
    int64_t fileId = 0, creation = 0, lastAccess = 0, written = 0, changed = 0;
    int64_t allocation = 0, endOfFile = 0;
    ULONG attributes = 0, reparseTag = 0, links = 1;
    ACCESS_MASK effectiveAccess = 0;
  };

  struct WFile;
  struct RaWindow;

  enum HandleMode : int
  {
    kHandleNone = 0,    // not classified yet
    kHandleIneligible,  // pure passthrough
    kHandleProbation,   // eligible; reads pass through (real pointer is authoritative)
    kHandleServed  // admitted; reads are served from memory, shadowPos is authoritative
  };

  struct HandleState
  {
    std::mutex m;
    std::atomic<int> mode{kHandleNone};
    uint64_t shadowPos = 0;  // guarded by m
    FileSnapshot snap;       // set during classification, immutable afterwards
    // file information snapshots are only served while nothing this process wrote
    // touched the file (per-file generation) or could not be attributed (global)
    size_t snapSlot        = 0;
    uint64_t snapFileGen   = 0;
    uint64_t snapGlobalGen = 0;
    uint64_t snapMetaGen   = 0;  // metacache generation before the snapshot was taken
    // position of a probation handle, tracked from the reads and seeks we see
    std::atomic<uint64_t> probPos{0};
    std::atomic<bool> probKnown{false};
    std::atomic<int> probInFlight{0};  // reads of this handle currently in the system
    std::atomic<bool> probOverlap{
        false};  // two of them overlapped: the position is unknowable
    // readahead: windows dropped without having served anything
    uint32_t raUnused = 0;
    bool raDisabled   = false;
    std::shared_ptr<CacheEntry> entry;

    // layer 3 (big reads); splitOk/key are set during classification, the rest is
    // guarded by m
    std::atomic<bool> splitOk{false};
    Key key;
    std::shared_ptr<WFile> wfile;
    logic::SeqState seq;
    std::shared_ptr<RaWindow> window;   // current readahead window
    std::shared_ptr<RaWindow> window2;  // the one after it
    uint32_t splitFailures = 0;

    ~HandleState();

    bool served() const
    {
      return mode.load(std::memory_order_acquire) == kHandleServed;
    }
  };

  struct BucketStats
  {
    std::atomic<uint64_t> admitted{0};
    std::atomic<uint64_t> fills{0};  // including refills
    std::atomic<uint64_t> fillBytes{0};
    std::atomic<uint64_t> served{0};
    std::atomic<uint64_t> bytesServed{0};
    std::atomic<uint64_t> probationEnd{0};  // handles closed/left on probation
  };

  struct BigStats
  {
    std::atomic<uint64_t> seen[logic::kBigBuckets]{};
    std::atomic<uint64_t> sequential[logic::kBigBuckets]{};
    std::atomic<uint64_t> splitsDone{0};
    std::atomic<uint64_t> splitsFailed{0};
    std::atomic<uint64_t> chunks{0};
    std::atomic<uint64_t> raWindows{0};
    std::atomic<uint64_t> raBytes{0};
    std::atomic<uint64_t> raServed{0};
    std::atomic<uint64_t> raServedBytes{0};
    std::atomic<uint64_t> raWaits{0};
    std::atomic<uint64_t> raWaitUs{0};
    std::atomic<uint64_t> fallbacks{0};
    std::atomic<uint64_t> raWasted{0};           // bytes read ahead and never used
    std::atomic<uint64_t> raDropped{0};          // windows dropped (any reason)
    std::atomic<uint64_t> raSpinHits{0};         // waits that ended during the spin
    std::atomic<uint64_t> raHandlesDisabled{0};  // handles that stopped using readahead
    std::atomic<uint64_t> raBackoffs{0};  // times readahead was switched off globally
  };

  struct Stats
  {
    BigStats big;
    std::atomic<uint64_t> classified{0};
    std::atomic<uint64_t> eligible{0};
    std::atomic<uint64_t> ineligible{0};
    std::atomic<uint64_t> byReason[static_cast<int>(Eligibility::Count)]{};
    BucketStats bucket[logic::kSizeBuckets];
    // layer 2
    std::atomic<uint64_t> asyncFills{0};  // completed on workers
    std::atomic<uint64_t> asyncFillFailures{0};
    std::atomic<uint64_t> syncFallbacks{0};  // queueFill failed, filled on the caller
    std::atomic<uint64_t> fallbackNameQuery{0};
    std::atomic<uint64_t> fallbackPoolStart{0};
    std::atomic<uint64_t> fallbackOther{0};
    // NtQueryInformationFile on eligible handles, per information class
    std::atomic<uint64_t> infoServed[80]{};
    std::atomic<uint64_t> infoPassed[80]{};
    std::atomic<uint64_t> infoServedSplit[80]{};
    std::atomic<uint64_t> infoServedProbationPos{
        0};  // FilePositionInformation on probation handles
    std::atomic<uint64_t> infoPassedProbationPos{0};
    std::atomic<uint64_t> fileGenFallbacks{
        0};  // writes whose file id was unknown (global bump)  // served on read-only
             // handles that are not cacheable
    std::atomic<uint64_t> fills{0};
    std::atomic<uint64_t> fillBytes{0};
    std::atomic<uint64_t> evictions{0};  // entries dropped
    std::atomic<uint64_t> dataEvictions{
        0};                            // buffers freed (entry kept for its handles)
    std::atomic<uint64_t> refills{0};  // fills of an entry that had been evicted
    std::atomic<uint64_t> passthroughs{0};
    std::atomic<uint64_t> failedClassifications{0};
    std::atomic<uint64_t> classifyUs{0};  // classification time excluding sync fills
    std::atomic<uint64_t> fillUs{0};      // sync fills and async fills on workers
  };

  // cache entries with a byte budget on the resident data. Eviction works on the
  // data buffers (entries stay alive for the handles that reference them) and
  // picks the least recently used ones; it runs only when over budget and then
  // evicts down to logic::evictionTarget() so that it is not repeated for every
  // fill.
  class Store
  {
  public:
    // returns the entry for the key, creating an empty one if necessary
    std::shared_ptr<CacheEntry> acquire(const Key& key)
    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto found = m_map.find(key);
      if (found != m_map.end())
        return found->second;

      auto entry  = std::make_shared<CacheEntry>();
      entry->key  = key;
      entry->size = key.size;
      if (entry->size == 0)
        entry->state.store(kReady);  // nothing to load
      m_map.emplace(key, entry);
      m_entriesMirror.store(m_map.size(), std::memory_order_relaxed);
      return entry;
    }

    // allocates the buffer of an entry that has none and counts it against the
    // budget, evicting other entries if necessary. May throw std::bad_alloc.
    void allocate(CacheEntry& e, uint64_t budget, Stats& stats)
    {
      std::unique_ptr<uint8_t[]> buf(new uint8_t[static_cast<size_t>(e.size)]);

      std::lock_guard<std::mutex> lock(m_mutex);
      e.data = std::move(buf);
      if (!e.counted) {
        e.counted = true;
        m_used += e.size;
      }
      evict(budget, stats);
      m_usedMirror.store(m_used, std::memory_order_relaxed);
    }

    // removes a failed entry so that later opens try again
    void discard(const std::shared_ptr<CacheEntry>& entry)
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      auto found = m_map.find(entry->key);
      if (found != m_map.end() && found->second == entry) {
        if (entry->counted) {
          entry->counted = false;
          m_used -= std::min(m_used, entry->size);
        }
        m_map.erase(found);
        m_usedMirror.store(m_used, std::memory_order_relaxed);
        m_entriesMirror.store(m_map.size(), std::memory_order_relaxed);
      }
    }

    uint64_t used() const { return m_usedMirror.load(std::memory_order_relaxed); }
    uint64_t entries() const { return m_entriesMirror.load(std::memory_order_relaxed); }

  private:
    void evict(uint64_t budget, Stats& stats)
    {
      if (m_used <= budget)
        return;

      struct Cand
      {
        uint64_t lastUse;
        CacheEntry* entry;
      };
      std::vector<Cand> cands;
      for (auto& kv : m_map) {
        CacheEntry* e = kv.second.get();
        if (e->counted)
          cands.push_back({e->lastUse.load(std::memory_order_relaxed), e});
      }
      std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        return a.lastUse < b.lastUse;
      });

      std::vector<logic::EvictCandidate> info;
      info.reserve(cands.size());
      for (const Cand& c : cands) {
        // entries being filled can't be evicted
        info.push_back(
            {c.entry->size, c.entry->state.load(std::memory_order_acquire) != kReady});
      }

      for (size_t idx :
           logic::selectEvictions(info, m_used, logic::evictionTarget(budget))) {
        CacheEntry* e = cands[idx].entry;
        if (!e->dataLock.try_lock())
          continue;  // a reader is copying, leave it
        if (e->state.load(std::memory_order_acquire) == kReady) {
          e->data.reset();
          e->loadedBytes.store(0, std::memory_order_release);
          e->state.store(kEmpty, std::memory_order_release);
          e->counted = false;
          m_used -= std::min(m_used, e->size);
          stats.dataEvictions.fetch_add(1, std::memory_order_relaxed);
        }
        e->dataLock.unlock();
      }

      // forget entries nobody references any more and that hold no data
      for (auto it = m_map.begin(); it != m_map.end();) {
        if (!it->second->counted && it->second.use_count() == 1 &&
            it->second->state.load(std::memory_order_acquire) != kLoading) {
          it = m_map.erase(it);
          stats.evictions.fetch_add(1, std::memory_order_relaxed);
        } else {
          ++it;
        }
      }
      m_entriesMirror.store(m_map.size(), std::memory_order_relaxed);
    }

    std::mutex m_mutex;
    std::unordered_map<Key, std::shared_ptr<CacheEntry>, KeyHash> m_map;
    uint64_t m_used = 0;
    std::atomic<uint64_t> m_usedMirror{0};
    std::atomic<uint64_t> m_entriesMirror{0};
  };

  struct Pool
  {
    std::mutex m;
    std::condition_variable cv;
    std::deque<std::function<void()>> queue;  // whole-file fills
    std::deque<std::function<void()>>
        hiQueue;  // split helpers and readahead: served first
    std::vector<std::thread> threads;
    bool started = false;
    std::atomic<int> alive{0};
  };

  struct State
  {
    logic::Limits limits;
    uint32_t admitReads = 8;
    bool async          = false;
    int threads         = 4;

    // layer 3
    bool splitEnabled      = true;
    bool raEnabled         = false;
    uint64_t splitMinBytes = 256ull << 10;
    uint64_t splitChunk    = 256ull << 10;
    uint64_t raCapBytes    = 64ull << 20;
    std::atomic<uint64_t> raBytesInUse{0};
    std::atomic<int> workerHandles{0};
    std::mutex wfilesLock;
    std::unordered_map<Key, std::weak_ptr<WFile>, KeyHash> wfiles;

    std::shared_mutex handlesLock;  // SRWLOCK based on MSVC
    std::unordered_map<HANDLE, std::shared_ptr<HandleState>> handles;

    Store store;
    Stats stats;
    Pool pool;

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> lastLogTick{0};
    std::atomic<uint64_t> lastLogActivity{0};
    std::atomic<uint64_t> lastSweepTick{0};

    // readahead back-off when too much of it is wasted
    std::atomic<uint64_t> raBackoffUntil{0};
    std::atomic<uint64_t> raBaseIssued{0};
    std::atomic<uint64_t> raBaseWasted{0};
  };

  // intentionally leaked: detached workers may outlive the static destructors
  State* g = nullptr;

  int kMaxWorkerHandles = 256;

  // called for every handle we close ourselves, so that the hooks' own
  // bookkeeping (handle tracker, directory cursors) forgets it too
  void (*g_forgetCallback)(HANDLE) = nullptr;

  // number of writes this process has made so far; handles classified before the
  // latest one no longer get file information from their snapshot
  std::atomic<uint64_t> g_writeGeneration{0};

  // per-file counterpart: bumped when a file is opened for writing / modified.
  // Indexed by a hash of the file id; a collision only costs a spurious miss.
  constexpr size_t kFileGenSlots = 1 << 16;
  std::atomic<uint64_t> g_fileGen[kFileGenSlots];

  size_t fileGenSlot(int64_t fileId)
  {
    return static_cast<size_t>(
        (static_cast<uint64_t>(fileId) * 0x9E3779B97F4A7C15ull) >> 48);
  }

  // true while a read cache function runs its own queries: they must see the system
  thread_local bool t_inShim = false;

  // set once a request has started doing I/O; after that it must not be re-issued
  thread_local bool t_ioStarted = false;

  // worker-owned handles to one file, opened by name (like layer 2) and shared
  // by all game handles of that file. The set lives as long as one of them does.
  struct WFile
  {
    Key key;
    std::wstring path;
    std::mutex m;
    std::vector<HANDLE> idle;
    std::atomic<uint64_t> lastUse{0};

    HANDLE acquire();  // null if no handle could be had
    void release(HANDLE h, bool good);
    ~WFile();
  };

  // data read ahead of a sequential reader
  struct RaWindow
  {
    uint64_t start  = 0;
    uint64_t length = 0;
    std::unique_ptr<uint8_t[]> buf;
    std::atomic<uint64_t> loaded{0};
    std::atomic<int> state{0};  // 0 loading, 1 done, 2 failed/cancelled
    std::atomic<bool> cancel{false};
    std::atomic<bool> started{false};    // a worker has picked the window up
    std::atomic<uint64_t> lastUse{0};    // tick of creation / last read served from it
    std::atomic<uint64_t> usedBytes{0};  // bytes served from this window
    std::mutex m;
    std::condition_variable cv;

    ~RaWindow()
    {
      g->raBytesInUse.fetch_sub(length, std::memory_order_relaxed);
      const uint64_t read = loaded.load(std::memory_order_relaxed);
      const uint64_t used = usedBytes.load(std::memory_order_relaxed);
      if (read > used)
        g->stats.big.raWasted.fetch_add(read - used, std::memory_order_relaxed);
    }
  };

  HandleState::~HandleState()
  {
    if (window)
      window->cancel.store(true, std::memory_order_relaxed);
    if (window2)
      window2->cancel.store(true, std::memory_order_relaxed);
  }

  // a big read split into chunks that the calling thread and workers share
  struct SplitJob
  {
    std::shared_ptr<WFile> wfile;
    HANDLE callerHandle = nullptr;
    uint8_t* base       = nullptr;  // user buffer
    uint64_t baseOffset = 0;        // file offset of base[0]
    std::vector<logic::Chunk> chunks;
    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    std::atomic<bool> failed{false};
    std::mutex m;
    std::condition_variable cv;
  };

  // ---------------------------------------------------------------------------
  // statistics logging (off the hot path: only every 4096th event looks at the
  // clock)

  uint64_t servedTotal()
  {
    uint64_t n = 0;
    for (const BucketStats& b : g->stats.bucket)
      n += b.served.load(std::memory_order_relaxed);
    return n;
  }

  uint64_t bytesServedTotal()
  {
    uint64_t n = 0;
    for (const BucketStats& b : g->stats.bucket)
      n += b.bytesServed.load(std::memory_order_relaxed);
    return n;
  }

  uint64_t activity()
  {
    const Stats& s = g->stats;
    return s.classified.load(std::memory_order_relaxed) + servedTotal() +
           s.passthroughs.load(std::memory_order_relaxed) +
           s.fills.load(std::memory_order_relaxed);
  }

  void logSummary(const char* prefix)
  {
    auto logger = spdlog::get("usvfs");
    if (!logger)
      return;

    const Stats& s = g->stats;
    auto ld        = [](const std::atomic<uint64_t>& a) {
      return a.load(std::memory_order_relaxed);
    };

    std::string reasons;
    for (int i = 1; i < static_cast<int>(Eligibility::Count); ++i) {
      const uint64_t n = ld(s.byReason[i]);
      if (n == 0)
        continue;
      if (!reasons.empty())
        reasons += ' ';
      reasons += logic::eligibilityName(static_cast<Eligibility>(i));
      reasons += '=';
      reasons += std::to_string(n);
    }

    logger->info(
        "{}: handles classified={} eligible={} ineligible={} [{}] "
        "reads served={} bytes={} passthrough={} fills={} refills={} fillBytes={} "
        "dataEvictions={} entryEvictions={} entries={} resident={}B "
        "classifyFailures={} classifyUs={} (avg {}) "
        "fillUs={} (avg {})",
        prefix, ld(s.classified), ld(s.eligible), ld(s.ineligible), reasons,
        servedTotal(), bytesServedTotal(), ld(s.passthroughs), ld(s.fills),
        ld(s.refills), ld(s.fillBytes), ld(s.dataEvictions), ld(s.evictions),
        g->store.entries(), g->store.used(), ld(s.failedClassifications),
        ld(s.classifyUs), ld(s.classified) ? ld(s.classifyUs) / ld(s.classified) : 0,
        ld(s.fillUs), ld(s.fills) ? ld(s.fillUs) / ld(s.fills) : 0);

    std::string buckets;
    for (size_t i = 0; i < logic::kSizeBuckets; ++i) {
      const BucketStats& b = s.bucket[i];
      buckets += std::format(
          " [{}: admitted={} fills={} fillBytes={} served={} bytes={} probationEnd={}]",
          logic::sizeBucketName(i), ld(b.admitted), ld(b.fills), ld(b.fillBytes),
          ld(b.served), ld(b.bytesServed), ld(b.probationEnd));
    }
    std::string infos;
    for (int i = 0; i < 80; ++i) {
      const uint64_t sv = ld(s.infoServed[i]), pa = ld(s.infoPassed[i]);
      if (sv || pa)
        infos += std::format(" {}={}/{}", i, sv, pa);
    }
    std::string splitInfos;
    for (int i = 0; i < 80; ++i) {
      if (ld(s.infoServedSplit[i]))
        splitInfos += std::format(" {}={}", i, ld(s.infoServedSplit[i]));
    }
    logger->info(
        "{} NtQueryInformationFile on eligible handles (class=served/passed):{} | "
        "position on probation handles served/passed={}/{} | "
        "served on read-only uncacheable handles:{} | unattributed writes={}",
        prefix, infos, ld(s.infoServedProbationPos), ld(s.infoPassedProbationPos),
        splitInfos, ld(s.fileGenFallbacks));
    logger->info("{} by file size:{}", prefix, buckets);
    logger->info("{} layer 2: asyncFills={} asyncFillFailures={} syncFallbacks={} "
                 "[name-query-failed={} pool-start-failed={} other={}]",
                 prefix, ld(s.asyncFills), ld(s.asyncFillFailures), ld(s.syncFallbacks),
                 ld(s.fallbackNameQuery), ld(s.fallbackPoolStart), ld(s.fallbackOther));

    const BigStats& b = s.big;
    std::string bigs;
    for (size_t i = 0; i < logic::kBigBuckets; ++i) {
      bigs += std::format(" [{}: seen={} sequential={}]", logic::bigBucketName(i),
                          ld(b.seen[i]), ld(b.sequential[i]));
    }
    logger->info(
        "{} big reads:{} splits done={} failed={} chunks={} | readahead windows={} "
        "bytes={} served={} servedBytes={} waits={} waitUs={} spinHits={} "
        "wastedBytes={} "
        "droppedWindows={} disabledHandles={} backoffs={} | fallbacks={}",
        prefix, bigs, ld(b.splitsDone), ld(b.splitsFailed), ld(b.chunks),
        ld(b.raWindows), ld(b.raBytes), ld(b.raServed), ld(b.raServedBytes),
        ld(b.raWaits), ld(b.raWaitUs), ld(b.raSpinHits), ld(b.raWasted),
        ld(b.raDropped), ld(b.raHandlesDisabled), ld(b.raBackoffs), ld(b.fallbacks));
  }

  void sweepScheduled();

  void maybeLog()
  {
    {
      // readahead windows of handles that went quiet give their memory back
      const uint64_t t   = GetTickCount64();
      uint64_t lastSweep = g->lastSweepTick.load(std::memory_order_relaxed);
      if (t - lastSweep >= 10000 &&
          g->lastSweepTick.compare_exchange_strong(lastSweep, t))
        sweepScheduled();
    }

    const uint64_t now = GetTickCount64();
    uint64_t last      = g->lastLogTick.load(std::memory_order_relaxed);
    if (now - last < kLogIntervalMs)
      return;

    const uint64_t act = activity();
    if (act == g->lastLogActivity.load(std::memory_order_relaxed)) {
      // nothing happened, don't spam; look again later
      g->lastLogTick.store(now, std::memory_order_relaxed);
      return;
    }
    if (!g->lastLogTick.compare_exchange_strong(last, now))
      return;  // another thread logs
    g->lastLogActivity.store(act, std::memory_order_relaxed);
    try {
      logSummary("readcache");
    } catch (...) {
    }
  }

  inline void countEvent(const std::atomic<uint64_t>& counter)
  {
    if ((counter.load(std::memory_order_relaxed) & 0xFFF) == 0)
      maybeLog();
  }

  // ---------------------------------------------------------------------------
  // thin wrappers around the real ntdll functions (callers are either inside
  // one of our hooks, where the hook barrier makes calls to the same function
  // bypass the hook, or on threads that run with all usvfs hook groups blocked)

  NTSTATUS setRealPos(HANDLE h, uint64_t pos)
  {
    FILE_POSITION_INFORMATION info;
    info.CurrentByteOffset.QuadPart = static_cast<LONGLONG>(pos);
    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));
    return ::NtSetInformationFile(h, &iosb, &info, sizeof(info),
                                  FilePositionInformation);
  }

  bool getRealPos(HANDLE h, uint64_t& pos)
  {
    FILE_POSITION_INFORMATION info;
    std::memset(&info, 0, sizeof(info));
    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));
    const NTSTATUS st = ::NtQueryInformationFile(h, &iosb, &info, sizeof(info),
                                                 FilePositionInformation);
    if (st < 0 || info.CurrentByteOffset.QuadPart < 0)
      return false;
    pos = static_cast<uint64_t>(info.CurrentByteOffset.QuadPart);
    return true;
  }

  // attributes of a file handle needed for classification
  struct FileAttrs
  {
    int64_t fileId              = 0;
    int64_t creation            = 0;
    int64_t lastAccess          = 0;
    int64_t allocation          = 0;
    ULONG reparseTag            = 0;
    ULONG numberOfLinks         = 1;
    ACCESS_MASK effectiveAccess = 0;
    int64_t written             = 0;
    int64_t changed             = 0;
    int64_t endOfFile           = 0;
    ULONG fileAttributes        = 0;
    int64_t position            = 0;
    ULONG mode                  = 0;
    ACCESS_MASK access          = 0;
  };

  uint64_t nowUs()
  {
    static const LONGLONG freq = [] {
      LARGE_INTEGER f;
      QueryPerformanceFrequency(&f);
      return f.QuadPart > 0 ? f.QuadPart : 1;
    }();
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return static_cast<uint64_t>(c.QuadPart * 1000000 / freq);
  }

  // set once the system says FileStatInformation does not exist
  std::atomic<bool> g_noStatInfo{false};

  // FileAllInformation fallback. Its name at the end is variable-length;
  // STATUS_BUFFER_OVERFLOW still fills in the fixed part; if a stack buffer is too
  // small anyway we retry with a buffer that fits any path. Some implementations
  // leave Mode/AccessFlags zeroed, so ask for them individually in that case.
  NTSTATUS queryAllFallback(HANDLE h, FileAttrs& out)
  {
    auto extract = [&out](const FILE_ALL_INFORMATION& all) {
      out.fileId          = all.InternalInformation.IndexNumber.QuadPart;
      out.creation        = all.BasicInformation.CreationTime.QuadPart;
      out.lastAccess      = all.BasicInformation.LastAccessTime.QuadPart;
      out.allocation      = all.StandardInformation.AllocationSize.QuadPart;
      out.numberOfLinks   = all.StandardInformation.NumberOfLinks;
      out.effectiveAccess = all.AccessInformation.AccessFlags;
      out.written         = all.BasicInformation.LastWriteTime.QuadPart;
      out.changed         = all.BasicInformation.ChangeTime.QuadPart;
      out.endOfFile       = all.StandardInformation.EndOfFile.QuadPart;
      out.fileAttributes  = all.BasicInformation.FileAttributes;
      if (all.StandardInformation.Directory)
        out.fileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
      out.position = all.PositionInformation.CurrentByteOffset.QuadPart;
      out.mode     = all.ModeInformation.Mode;
      out.access   = all.AccessInformation.AccessFlags;
    };

    struct
    {
      FILE_ALL_INFORMATION info;
      WCHAR extra[1024];
    } stackBuf;
    std::memset(&stackBuf, 0, sizeof(stackBuf));

    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));
    NTSTATUS st = ::NtQueryInformationFile(h, &iosb, &stackBuf, sizeof(stackBuf),
                                           FileAllInformation);
    if (st == STATUS_SUCCESS || st == STATUS_BUFFER_OVERFLOW) {
      extract(stackBuf.info);
      st = STATUS_SUCCESS;
    } else if (st == kStatusInfoLengthMismatch || st == kStatusBufferTooSmall) {
      std::vector<unsigned char> big(sizeof(FILE_ALL_INFORMATION) + 70000);
      std::memset(&iosb, 0, sizeof(iosb));
      st = ::NtQueryInformationFile(h, &iosb, big.data(),
                                    static_cast<ULONG>(big.size()), FileAllInformation);
      if (st == STATUS_SUCCESS || st == STATUS_BUFFER_OVERFLOW) {
        FILE_ALL_INFORMATION copy;
        std::memcpy(&copy, big.data(), sizeof(copy));
        extract(copy);
        st = STATUS_SUCCESS;
      }
    }
    if (st != STATUS_SUCCESS)
      return st;

    if (out.mode == 0) {
      FILE_MODE_INFORMATION mi;
      std::memset(&mi, 0, sizeof(mi));
      std::memset(&iosb, 0, sizeof(iosb));
      if (::NtQueryInformationFile(h, &iosb, &mi, sizeof(mi), FileModeInformation) >= 0)
        out.mode = mi.Mode;
    }
    if (out.access == 0) {
      FILE_ACCESS_INFORMATION ai;
      std::memset(&ai, 0, sizeof(ai));
      std::memset(&iosb, 0, sizeof(iosb));
      if (::NtQueryInformationFile(h, &iosb, &ai, sizeof(ai), FileAccessInformation) >=
          0)
        out.access = ai.AccessFlags;
    }
    return STATUS_SUCCESS;
  }

  // Preferred path: FileStatInformation + position + mode + access. Under Wine
  // the first two are plain fstat/lseek and the other two one wineserver call
  // each, while FileAllInformation needs a server round trip to build the name
  // and reports Mode/AccessFlags as 0. (EffectiveAccess of the stat information
  // is not trustworthy under Wine, so FileAccessInformation is used instead.)
  NTSTATUS queryAttrs(HANDLE h, FileAttrs& out)
  {
    IO_STATUS_BLOCK iosb;
    if (!g_noStatInfo.load(std::memory_order_relaxed)) {
      USVFS_FILE_STAT_INFORMATION stat;
      std::memset(&stat, 0, sizeof(stat));
      std::memset(&iosb, 0, sizeof(iosb));
      const NTSTATUS st =
          ::NtQueryInformationFile(h, &iosb, &stat, sizeof(stat), FileStatInformation);
      if (st == STATUS_SUCCESS) {
        FILE_POSITION_INFORMATION pos;
        FILE_MODE_INFORMATION mode;
        FILE_ACCESS_INFORMATION access;
        std::memset(&pos, 0, sizeof(pos));
        std::memset(&mode, 0, sizeof(mode));
        std::memset(&access, 0, sizeof(access));

        std::memset(&iosb, 0, sizeof(iosb));
        NTSTATUS st2 = ::NtQueryInformationFile(h, &iosb, &pos, sizeof(pos),
                                                FilePositionInformation);
        if (st2 >= 0) {
          std::memset(&iosb, 0, sizeof(iosb));
          st2 = ::NtQueryInformationFile(h, &iosb, &mode, sizeof(mode),
                                         FileModeInformation);
        }
        if (st2 >= 0) {
          std::memset(&iosb, 0, sizeof(iosb));
          st2 = ::NtQueryInformationFile(h, &iosb, &access, sizeof(access),
                                         FileAccessInformation);
        }
        if (st2 < 0)
          return st2;

        out.fileId          = stat.FileId.QuadPart;
        out.creation        = stat.CreationTime.QuadPart;
        out.lastAccess      = stat.LastAccessTime.QuadPart;
        out.allocation      = stat.AllocationSize.QuadPart;
        out.reparseTag      = stat.ReparseTag;
        out.numberOfLinks   = stat.NumberOfLinks;
        out.effectiveAccess = stat.EffectiveAccess;
        out.written         = stat.LastWriteTime.QuadPart;
        out.changed         = stat.ChangeTime.QuadPart;
        out.endOfFile       = stat.EndOfFile.QuadPart;
        out.fileAttributes  = stat.FileAttributes;
        out.position        = pos.CurrentByteOffset.QuadPart;
        out.mode            = mode.Mode;
        out.access          = access.AccessFlags;
        return STATUS_SUCCESS;
      }
      // 0xC0000003 invalid info class, 0xC0000002 not implemented,
      // 0xC00000BB not supported
      if (st == static_cast<NTSTATUS>(0xC0000003L) ||
          st == static_cast<NTSTATUS>(0xC0000002L) ||
          st == static_cast<NTSTATUS>(0xC00000BBL))
        g_noStatInfo.store(true, std::memory_order_relaxed);
    }
    return queryAllFallback(h, out);
  }

  // ---------------------------------------------------------------------------
  // filling

  bool fillFromHandle(HANDLE h, CacheEntry& e, uint64_t chunk, bool progressive)
  {
    uint64_t off = 0;
    while (off < e.size) {
      if (g->stop.load(std::memory_order_relaxed))
        return false;

      const ULONG want = static_cast<ULONG>(std::min<uint64_t>(chunk, e.size - off));
      LARGE_INTEGER bo;
      bo.QuadPart = static_cast<LONGLONG>(off);
      IO_STATUS_BLOCK iosb;
      std::memset(&iosb, 0, sizeof(iosb));
      const NTSTATUS st = ::NtReadFile(h, nullptr, nullptr, nullptr, &iosb,
                                       e.data.get() + off, want, &bo, nullptr);
      if (st != STATUS_SUCCESS || iosb.Information != want)
        return false;

      off += want;
      if (progressive) {
        e.loadedBytes.store(off, std::memory_order_release);
        {
          std::lock_guard<std::mutex> lock(e.m);
        }  // no lost wakeup
        e.cv.notify_all();
      }
    }
    e.loadedBytes.store(e.size, std::memory_order_release);
    return true;
  }

  void touch(CacheEntry& e)
  {
    const uint64_t now = GetTickCount64();
    if (e.lastUse.load(std::memory_order_relaxed) != now)
      e.lastUse.store(now, std::memory_order_relaxed);
  }

  void countFill(CacheEntry& e)
  {
    if (e.everFilled.exchange(true)) {
      g->stats.refills.fetch_add(1, std::memory_order_relaxed);
    } else {
      g->stats.fills.fetch_add(1, std::memory_order_relaxed);
    }
    g->stats.fillBytes.fetch_add(e.size, std::memory_order_relaxed);
    BucketStats& b = g->stats.bucket[logic::sizeBucket(e.size)];
    b.fills.fetch_add(1, std::memory_order_relaxed);
    b.fillBytes.fetch_add(e.size, std::memory_order_relaxed);
    touch(e);
  }

  void finishEntry(CacheEntry& e, bool ok)
  {
    {
      std::lock_guard<std::mutex> lock(e.m);
      e.state.store(ok ? kReady : kFailed, std::memory_order_release);
    }
    e.cv.notify_all();
    if (ok)
      countFill(e);
  }

  // layer 1: load the whole file through the caller's handle. The real file
  // pointer ends up at an unspecified place; the caller restores it on failure.
  bool fillSync(HANDLE h, const std::shared_ptr<CacheEntry>& e)
  {
    std::unique_lock<std::mutex> lock(e->m);
    const int state = e->state.load(std::memory_order_acquire);
    if (state == kReady)
      return true;
    if (state == kFailed)
      return false;
    if (state == kLoading) {
      // an async fill is in flight (the other entry users will wait for it)
      return true;
    }

    e->state.store(kLoading, std::memory_order_release);
    const uint64_t t0 = nowUs();
    bool ok           = false;
    try {
      g->store.allocate(*e, g->limits.budgetBytes, g->stats);
      ok = fillFromHandle(h, *e, kSyncChunk, false);
    } catch (...) {
      ok = false;
    }
    const uint64_t dt = nowUs() - t0;
    g->stats.fillUs.fetch_add(dt, std::memory_order_relaxed);
    t_syncFillUs += dt;
    e->state.store(ok ? kReady : kFailed, std::memory_order_release);
    lock.unlock();
    e->cv.notify_all();
    if (ok) {
      countFill(*e);
    } else {
      g->store.discard(e);
    }
    return ok;
  }

  // ----- layer 2: worker pool -------------------------------------------------

  // waits until [0, need) of the entry is loaded; false if the fill failed
  bool waitLoaded(CacheEntry& e, uint64_t need)
  {
    if (e.loadedBytes.load(std::memory_order_acquire) >= need)
      return true;

    std::unique_lock<std::mutex> lock(e.m);
    const auto deadline = chr::steady_clock::now() + kWaitLimit;
    for (;;) {
      if (e.loadedBytes.load(std::memory_order_acquire) >= need)
        return true;
      if (e.state.load(std::memory_order_acquire) == kFailed)
        return false;
      if (g->stop.load(std::memory_order_relaxed))
        return false;
      if (chr::steady_clock::now() >= deadline)
        return false;
      e.cv.wait_for(lock, chr::milliseconds(50));
    }
  }

  bool queryObjectName(HANDLE h, std::wstring& out)
  {
    std::vector<unsigned char> buf(2048);
    for (int attempt = 0; attempt < 2; ++attempt) {
      ULONG needed      = 0;
      const NTSTATUS st = ::NtQueryObject(h, ObjectNameInformationClass, buf.data(),
                                          static_cast<ULONG>(buf.size()), &needed);
      if (st == STATUS_SUCCESS) {
        auto* name = reinterpret_cast<OBJECT_NAME_INFORMATION*>(buf.data());
        if (!name->Name.Buffer || name->Name.Length == 0)
          return false;
        out.assign(name->Name.Buffer, name->Name.Length / sizeof(WCHAR));
        return true;
      }
      if ((st == kStatusInfoLengthMismatch || st == kStatusBufferTooSmall ||
           st == STATUS_BUFFER_OVERFLOW) &&
          needed > buf.size()) {
        buf.resize(needed);
        continue;
      }
      return false;
    }
    return false;
  }

  bool sameFile(const FileAttrs& a, const Key& k)
  {
    return a.fileId == k.fileId && a.endOfFile == static_cast<LONGLONG>(k.size) &&
           a.written == k.written && a.changed == k.changed;
  }

  bool fillAsync(const std::shared_ptr<CacheEntry>& e)
  {
    UNICODE_STRING name;
    name.Buffer        = const_cast<PWSTR>(e->ntPath.c_str());
    name.Length        = static_cast<USHORT>(e->ntPath.size() * sizeof(WCHAR));
    name.MaximumLength = name.Length;

    OBJECT_ATTRIBUTES attrs;
    std::memset(&attrs, 0, sizeof(attrs));
    attrs.Length     = sizeof(attrs);
    attrs.ObjectName = &name;
    attrs.Attributes = 0x00000040;  // OBJ_CASE_INSENSITIVE

    HANDLE file = nullptr;
    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));
    const NTSTATUS st = ::NtCreateFile(
        &file, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attrs, &iosb,
        nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0x00000001 /* FILE_OPEN */,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (st < 0 || !file)
      return false;

    bool ok = false;
    FileAttrs info;
    if (queryAttrs(file, info) == STATUS_SUCCESS && sameFile(info, e->key)) {
      const uint64_t t0 = nowUs();
      ok                = fillFromHandle(file, *e, kAsyncChunk, true);
      g->stats.fillUs.fetch_add(nowUs() - t0, std::memory_order_relaxed);
    }

    ::NtClose(file);
    return ok;
  }

  void workerMain()
  {
    // keep every usvfs hook out of the way on this thread
    HookCallContext blockHooks(MutExHookGroup::ALL_GROUPS);
    t_inShim = true;

    Pool& pool = g->pool;
    for (;;) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(pool.m);
        pool.cv.wait(lock, [&] {
          return g->stop.load(std::memory_order_relaxed) || !pool.hiQueue.empty() ||
                 !pool.queue.empty();
        });
        if (g->stop.load(std::memory_order_relaxed))
          break;
        if (!pool.hiQueue.empty()) {
          task = std::move(pool.hiQueue.front());
          pool.hiQueue.pop_front();
        } else {
          task = std::move(pool.queue.front());
          pool.queue.pop_front();
        }
      }

      try {
        task();
      } catch (...) {
      }
    }
    pool.alive.fetch_sub(1);
  }

  // runs a task on a worker thread (starting the pool on first use); false if
  // that is not possible. `high` tasks (the caller is waiting for them) go
  // before whole-file fills. May throw (allocation).
  bool submitTask(std::function<void()> task, bool high = false)
  {
    Pool& pool = g->pool;
    {
      std::lock_guard<std::mutex> lock(pool.m);
      if (g->stop.load(std::memory_order_relaxed))
        return false;
      if (!pool.started) {
        pool.started = true;
        try {
          for (int i = 0; i < g->threads; ++i) {
            pool.threads.emplace_back(workerMain);
            pool.alive.fetch_add(1);
          }
        } catch (...) {
          // run with however many threads we got
        }
        if (pool.threads.empty()) {
          pool.started = false;
          return false;
        }
      }
      (high ? pool.hiQueue : pool.queue).push_back(std::move(task));
    }
    pool.cv.notify_one();
    return true;
  }

  // queues the load of an entry; false if that is not possible (caller falls
  // back to the synchronous fill)
  bool queueFill(HANDLE h, const std::shared_ptr<CacheEntry>& e)
  {
    Stats& st = g->stats;
    {
      std::lock_guard<std::mutex> lock(e->m);
      if (e->state.load(std::memory_order_acquire) != kEmpty)
        return true;  // somebody else already took care of it
      if (!queryObjectName(h, e->ntPath)) {
        st.syncFallbacks.fetch_add(1, std::memory_order_relaxed);
        st.fallbackNameQuery.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      try {
        g->store.allocate(*e, g->limits.budgetBytes, g->stats);
      } catch (...) {
        st.syncFallbacks.fetch_add(1, std::memory_order_relaxed);
        st.fallbackOther.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      e->state.store(kLoading, std::memory_order_release);
    }

    const bool queued = submitTask([e] {
      bool ok = false;
      try {
        ok = fillAsync(e);
      } catch (...) {
        ok = false;
      }
      (ok ? g->stats.asyncFills : g->stats.asyncFillFailures)
          .fetch_add(1, std::memory_order_relaxed);
      finishEntry(*e, ok);
      if (!ok)
        g->store.discard(e);
    });
    if (!queued) {
      st.syncFallbacks.fetch_add(1, std::memory_order_relaxed);
      st.fallbackPoolStart.fetch_add(1, std::memory_order_relaxed);
      std::lock_guard<std::mutex> elock(e->m);
      e->state.store(kEmpty, std::memory_order_release);
      return false;
    }
    return true;
  }

  // ----- layer 3: worker-owned handles, split reads, readahead ----------------

  void closeRaw(HANDLE h)
  {
    if (g_forgetCallback)
      g_forgetCallback(h);
    ::NtClose(h);
  }

  void closeWorkerHandle(HANDLE h)
  {
    closeRaw(h);
    g->workerHandles.fetch_sub(1);
  }

  HANDLE openByName(const std::wstring& path, const Key& key)
  {
    UNICODE_STRING name;
    name.Buffer        = const_cast<PWSTR>(path.c_str());
    name.Length        = static_cast<USHORT>(path.size() * sizeof(WCHAR));
    name.MaximumLength = name.Length;

    OBJECT_ATTRIBUTES attrs;
    std::memset(&attrs, 0, sizeof(attrs));
    attrs.Length     = sizeof(attrs);
    attrs.ObjectName = &name;
    attrs.Attributes = 0x00000040;  // OBJ_CASE_INSENSITIVE

    HANDLE file = nullptr;
    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));
    const NTSTATUS st = ::NtCreateFile(
        &file, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attrs, &iosb,
        nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0x00000001 /* FILE_OPEN */,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (st < 0 || !file)
      return nullptr;

    FileAttrs info;
    if (queryAttrs(file, info) == STATUS_SUCCESS && sameFile(info, key))
      return file;

    closeRaw(file);
    return nullptr;
  }

  // closes the idle handles of the least recently used file; false if there were
  // none to close
  bool trimWorkerHandles()
  {
    std::shared_ptr<WFile> victim;
    uint64_t oldest = UINT64_MAX;
    {
      std::lock_guard<std::mutex> lock(g->wfilesLock);
      for (auto& kv : g->wfiles) {
        std::shared_ptr<WFile> wf = kv.second.lock();
        if (!wf)
          continue;
        {
          std::lock_guard<std::mutex> wl(wf->m);
          if (wf->idle.empty())
            continue;
        }
        const uint64_t use = wf->lastUse.load(std::memory_order_relaxed);
        if (use < oldest) {
          oldest = use;
          victim = std::move(wf);
        }
      }
    }
    if (!victim)
      return false;

    std::vector<HANDLE> toClose;
    {
      std::lock_guard<std::mutex> lock(victim->m);
      toClose.swap(victim->idle);
    }
    for (HANDLE h : toClose)
      closeWorkerHandle(h);
    return !toClose.empty();
  }

  HANDLE WFile::acquire()
  {
    lastUse.store(GetTickCount64(), std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> lock(m);
      if (!idle.empty()) {
        HANDLE h = idle.back();
        idle.pop_back();
        return h;
      }
    }
    // each concurrent reader needs its own handle: reads on a synchronous handle
    // are serialized by the system. Over the cap, make room by closing the idle
    // handles of the least recently used file.
    if (g->workerHandles.fetch_add(1) >= kMaxWorkerHandles) {
      g->workerHandles.fetch_sub(1);
      if (!trimWorkerHandles())
        return nullptr;
      if (g->workerHandles.fetch_add(1) >= kMaxWorkerHandles) {
        g->workerHandles.fetch_sub(1);
        return nullptr;
      }
    }
    HANDLE h = openByName(path, key);
    if (!h)
      g->workerHandles.fetch_sub(1);
    return h;
  }

  void WFile::release(HANDLE h, bool good)
  {
    if (good) {
      std::lock_guard<std::mutex> lock(m);
      idle.push_back(h);
      return;
    }
    closeWorkerHandle(h);
  }

  WFile::~WFile()
  {
    for (HANDLE h : idle)
      closeWorkerHandle(h);
  }

  bool readInto(HANDLE h, uint64_t fileOffset, void* dst, uint64_t length)
  {
    LARGE_INTEGER bo;
    bo.QuadPart = static_cast<LONGLONG>(fileOffset);
    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));
    const NTSTATUS st = ::NtReadFile(h, nullptr, nullptr, nullptr, &iosb, dst,
                                     static_cast<ULONG>(length), &bo, nullptr);
    return st == STATUS_SUCCESS && iosb.Information == length;
  }

  // takes chunks until none are left. `own` is the handle to read with. Never
  // throws, and every chunk it takes is counted as done, whatever happens: the
  // caller of the split waits for that before the user buffer may go away.
  void runChunks(SplitJob& job, HANDLE own, bool isCaller)
  {
    HANDLE h  = own;
    bool good = true;
    for (;;) {
      const size_t i = job.next.fetch_add(1);
      if (i >= job.chunks.size())
        break;

      try {
        if (!job.failed.load(std::memory_order_relaxed)) {
          if (!h && !isCaller) {
            h = job.wfile->acquire();
            if (!h)
              job.failed.store(true);
          }
          if (h) {
            const logic::Chunk& c = job.chunks[i];
            if (!readInto(h, c.offset, job.base + (c.offset - job.baseOffset),
                          c.length)) {
              job.failed.store(true);
              if (!isCaller)
                good = false;
            }
          }
        }
      } catch (...) {
        job.failed.store(true);
        if (!isCaller)
          good = false;
      }

      if (job.done.fetch_add(1) + 1 == job.chunks.size()) {
        try {
          {
            std::lock_guard<std::mutex> lock(job.m);
          }
          job.cv.notify_all();
        } catch (...) {
        }
      }
      if (!good)
        break;
    }
    if (!isCaller && h) {
      try {
        job.wfile->release(h, good);
      } catch (...) {
      }
    }
  }

  bool ensureWFile(HandleState& hs, HANDLE h)
  {
    if (hs.wfile)
      return true;
    std::wstring path;
    if (!queryObjectName(h, path))
      return false;

    std::lock_guard<std::mutex> lock(g->wfilesLock);
    if (g->wfiles.size() > 4096) {
      for (auto it = g->wfiles.begin(); it != g->wfiles.end();) {
        if (it->second.expired()) {
          it = g->wfiles.erase(it);
        } else {
          ++it;
        }
      }
    }
    std::weak_ptr<WFile>& slot = g->wfiles[hs.key];
    std::shared_ptr<WFile> wf  = slot.lock();
    if (!wf) {
      wf       = std::make_shared<WFile>();
      wf->key  = hs.key;
      wf->path = std::move(path);
      slot     = wf;
    }
    hs.wfile = wf;
    return true;
  }

  // a window that is thrown away without ever having served a read counts against
  // the handle: after two of those it stops using readahead
  void dropWindow(HandleState& hs, std::shared_ptr<RaWindow>& w)
  {
    if (w) {
      g->stats.big.raDropped.fetch_add(1, std::memory_order_relaxed);
      if (w->usedBytes.load(std::memory_order_relaxed) == 0 && ++hs.raUnused >= 2 &&
          !hs.raDisabled) {
        hs.raDisabled = true;
        g->stats.big.raHandlesDisabled.fetch_add(1, std::memory_order_relaxed);
      }
      w->cancel.store(true, std::memory_order_relaxed);
      w.reset();
    }
  }

  void dropWindows(HandleState& hs)
  {
    dropWindow(hs, hs.window);
    dropWindow(hs, hs.window2);
  }

  // Readahead is switched off for a while if too much of what it read was never
  // used (checked over the bytes issued since the last verdict).
  bool readaheadAllowed()
  {
    const uint64_t now = GetTickCount64();
    if (now < g->raBackoffUntil.load(std::memory_order_relaxed))
      return false;

    const uint64_t issued = g->stats.big.raBytes.load(std::memory_order_relaxed) -
                            g->raBaseIssued.load(std::memory_order_relaxed);
    const uint64_t wasted = g->stats.big.raWasted.load(std::memory_order_relaxed) -
                            g->raBaseWasted.load(std::memory_order_relaxed);
    if (issued >= g_raCheckBytes) {
      const bool bad = wasted * 100 > issued * g_raWastePct;
      g->raBaseIssued.store(g->stats.big.raBytes.load(std::memory_order_relaxed));
      g->raBaseWasted.store(g->stats.big.raWasted.load(std::memory_order_relaxed));
      if (bad) {
        g->raBackoffUntil.store(now + g_raBackoffMs, std::memory_order_relaxed);
        g->stats.big.raBackoffs.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
    }
    return true;
  }

  // drops readahead windows nobody has read from for a while
  void sweepIdleWindows()
  {
    constexpr uint64_t kIdleMs = 10000;
    const uint64_t now         = GetTickCount64();
    std::shared_lock<std::shared_mutex> lock(g->handlesLock);
    for (auto& kv : g->handles) {
      HandleState& hs = *kv.second;
      std::unique_lock<std::mutex> hl(hs.m, std::try_to_lock);
      if (!hl.owns_lock())
        continue;
      for (std::shared_ptr<RaWindow>* w : {&hs.window, &hs.window2}) {
        if (*w && now - (*w)->lastUse.load(std::memory_order_relaxed) > kIdleMs)
          dropWindow(hs, *w);
      }
    }
  }

  // The sweep takes handle locks with try_lock, which must not be done on a mutex
  // the calling thread owns (it may be inside a read): run it on a worker.
  void sweepScheduled()
  {
    try {
      submitTask([] {
        sweepIdleWindows();
      });
    } catch (...) {
    }
  }

  void raTask(const std::shared_ptr<RaWindow>& w, const std::shared_ptr<WFile>& wf)
  {
    w->started.store(true, std::memory_order_release);
    bool ok  = false;
    HANDLE h = nullptr;
    if (!w->cancel.load(std::memory_order_relaxed))
      h = wf->acquire();
    if (h) {
      ok           = true;
      uint64_t off = 0;
      while (off < w->length) {
        if (w->cancel.load(std::memory_order_relaxed) ||
            g->stop.load(std::memory_order_relaxed)) {
          ok = false;
          break;
        }
        const uint64_t want = std::min<uint64_t>(kAsyncChunk, w->length - off);
        if (!readInto(h, w->start + off, w->buf.get() + off, want)) {
          ok = false;
          break;
        }
        off += want;
        w->loaded.store(off, std::memory_order_release);
        {
          std::lock_guard<std::mutex> lock(w->m);
        }
        w->cv.notify_all();
      }
      wf->release(h, ok || w->cancel.load(std::memory_order_relaxed));
    }
    w->state.store(ok ? 1 : 2, std::memory_order_release);
    {
      std::lock_guard<std::mutex> lock(w->m);
    }
    w->cv.notify_all();
  }

  // issues a readahead window starting at `start` into `slot`. May throw; the
  // memory reservation is always given back.
  void issueWindow(HandleState& hs, HANDLE h, uint64_t start, uint64_t lastRead,
                   std::shared_ptr<RaWindow>& slot)
  {
    if (hs.raDisabled || !readaheadAllowed())
      return;
    if (!ensureWFile(hs, h))
      return;

    const uint64_t used        = g->raBytesInUse.load(std::memory_order_relaxed);
    const uint64_t left        = g->raCapBytes > used ? g->raCapBytes - used : 0;
    const logic::WindowPlan wp = logic::planWindow(start, lastRead, hs.key.size, left);
    if (wp.length == 0)
      return;

    auto w = std::make_shared<RaWindow>();  // length 0: nothing to give back yet
    if (g->raBytesInUse.fetch_add(wp.length) + wp.length > g->raCapBytes) {
      g->raBytesInUse.fetch_sub(wp.length);
      return;
    }
    w->length = wp.length;  // from here the destructor returns the reservation
    w->lastUse.store(GetTickCount64(), std::memory_order_relaxed);
    w->start = wp.start;
    w->buf.reset(new uint8_t[static_cast<size_t>(wp.length)]);

    std::shared_ptr<WFile> wf = hs.wfile;
    if (!submitTask(
            [w, wf] {
              raTask(w, wf);
            },
            true))
      return;
    slot = w;
    g->stats.big.raWindows.fetch_add(1, std::memory_order_relaxed);
    g->stats.big.raBytes.fetch_add(wp.length, std::memory_order_relaxed);
  }

  // Serves a read completely inside the given window. On true, `status` is the
  // result of the request. A window no worker has started on yet, or one that
  // does not deliver within a short time, is dropped and the read goes the
  // normal way.
  bool serveFromWindow(HandleState& hs, std::shared_ptr<RaWindow>& slot, HANDLE h,
                       PIO_STATUS_BLOCK iosb, PVOID buf, uint64_t offset,
                       uint64_t total, bool explicitOff, NTSTATUS& status)
  {
    RaWindow* w = slot.get();
    if (!w || !logic::windowCovers(w->start, w->length, offset, total))
      return false;

    const uint64_t need = offset + total - w->start;
    if (w->loaded.load(std::memory_order_acquire) < need) {
      if (!w->started.load(std::memory_order_acquire)) {
        // queued behind other work: don't wait for it
        dropWindow(hs, slot);
        return false;
      }
      BigStats& bs = g->stats.big;
      // the data is usually just about to arrive: spin briefly before sleeping
      for (int i = 0; i < 4000 && w->loaded.load(std::memory_order_acquire) < need; ++i)
        YieldProcessor();
      if (w->loaded.load(std::memory_order_acquire) >= need) {
        bs.raSpinHits.fetch_add(1, std::memory_order_relaxed);
      }
    }
    if (w->loaded.load(std::memory_order_acquire) < need) {
      BigStats& bs = g->stats.big;
      bs.raWaits.fetch_add(1, std::memory_order_relaxed);
      const uint64_t t0 = nowUs();
      {
        std::unique_lock<std::mutex> lock(w->m);
        const auto deadline = chr::steady_clock::now() + chr::milliseconds(100);
        while (w->loaded.load(std::memory_order_acquire) < need &&
               w->state.load(std::memory_order_acquire) != 2 &&
               !g->stop.load(std::memory_order_relaxed) &&
               chr::steady_clock::now() < deadline) {
          w->cv.wait_for(lock, chr::milliseconds(5));
        }
      }
      bs.raWaitUs.fetch_add(nowUs() - t0, std::memory_order_relaxed);
      if (w->loaded.load(std::memory_order_acquire) < need) {
        dropWindow(hs, slot);
        return false;
      }
    }

    // move the real pointer first: if that fails nothing has happened yet
    t_ioStarted = true;
    if (setRealPos(h, offset + total) < 0)
      return false;

    if (!sehCopy(buf, w->buf.get() + (offset - w->start), static_cast<size_t>(total)) ||
        !sehStoreStatus(iosb, STATUS_SUCCESS, static_cast<ULONG_PTR>(total))) {
      if (!explicitOff)
        setRealPos(h, offset);
      status = STATUS_ACCESS_VIOLATION;
      return true;
    }

    w->lastUse.store(GetTickCount64(), std::memory_order_relaxed);
    w->usedBytes.fetch_add(total, std::memory_order_relaxed);
    g->stats.big.raServed.fetch_add(1, std::memory_order_relaxed);
    g->stats.big.raServedBytes.fetch_add(total, std::memory_order_relaxed);
    status = STATUS_SUCCESS;
    return true;
  }

  // Splits the request over the calling thread and the workers. Returns true if
  // the request was completed (status/total set); false means "do it the normal
  // way", with the real pointer where the original request expects it. Throws
  // only before any chunk is dispatched; afterwards it always waits for every
  // chunk, so no worker writes into the buffer once this returns.
  bool trySplit(HandleState& hs, HANDLE h, PIO_STATUS_BLOCK iosb, PVOID buf, ULONG len,
                uint64_t offset, bool explicitOff, NTSTATUS& status, uint64_t& total)
  {
    BigStats& bs = g->stats.big;
    auto fail    = [&]() {
      bs.fallbacks.fetch_add(1, std::memory_order_relaxed);
      ++hs.splitFailures;
      if (hs.splitFailures >= 3)
        dropWindows(hs);
      return false;
    };

    if (!ensureWFile(hs, h))
      return fail();

    // current end of file (a real query: t_inShim keeps the hook from answering
    // it out of the snapshot), so that the result matches the unsplit call
    FILE_STANDARD_INFORMATION si;
    std::memset(&si, 0, sizeof(si));
    IO_STATUS_BLOCK qiosb;
    std::memset(&qiosb, 0, sizeof(qiosb));
    if (::NtQueryInformationFile(h, &qiosb, &si, sizeof(si), FileStandardInformation) <
            0 ||
        si.EndOfFile.QuadPart < 0)
      return fail();

    logic::SplitPlan plan =
        logic::planSplit(offset, len, static_cast<uint64_t>(si.EndOfFile.QuadPart),
                         g->splitMinBytes, g->splitChunk);

    if (plan.action == logic::SplitAction::EndOfFile) {
      status = sehStoreStatus(iosb, STATUS_END_OF_FILE, 0) ? STATUS_END_OF_FILE
                                                           : STATUS_ACCESS_VIOLATION;
      total  = 0;
      return true;
    }
    if (plan.action != logic::SplitAction::Split)
      return false;

    auto job          = std::make_shared<SplitJob>();
    job->wfile        = hs.wfile;
    job->callerHandle = h;
    job->base         = static_cast<uint8_t*>(buf);
    job->baseOffset   = offset;
    job->chunks       = std::move(plan.chunks);

    t_ioStarted = true;

    const size_t helpers =
        std::min<size_t>(job->chunks.size() - 1, static_cast<size_t>(g->threads));
    try {
      for (size_t i = 0; i < helpers; ++i) {
        if (!submitTask(
                [job] {
                  runChunks(*job, nullptr, false);
                },
                true))
          break;
      }
    } catch (...) {
      // the helpers that did get queued are waited for below
    }
    runChunks(*job, h, true);

    {
      std::unique_lock<std::mutex> lock(job->m);
      job->cv.wait(lock, [&] {
        return job->done.load() >= job->chunks.size();
      });
    }

    if (job->failed.load()) {
      bs.splitsFailed.fetch_add(1, std::memory_order_relaxed);
      // the caller's chunk reads moved the real pointer
      if (!explicitOff)
        setRealPos(h, offset);
      return fail();
    }

    if (setRealPos(h, offset + plan.total) < 0) {
      bs.splitsFailed.fetch_add(1, std::memory_order_relaxed);
      if (!explicitOff)
        setRealPos(h, offset);
      return fail();
    }

    hs.splitFailures = 0;
    bs.splitsDone.fetch_add(1, std::memory_order_relaxed);
    bs.chunks.fetch_add(job->chunks.size(), std::memory_order_relaxed);

    total  = plan.total;
    status = sehStoreStatus(iosb, STATUS_SUCCESS, static_cast<ULONG_PTR>(plan.total))
                 ? STATUS_SUCCESS
                 : STATUS_ACCESS_VIOLATION;
    return true;
  }

  // ---------------------------------------------------------------------------
  // classification

  // returns Eligible and fills the handle state, or the reason for rejection
  Eligibility classifyImpl(HandleState& hs, HANDLE h, bool eventOrApc, ULONG length)
  {
    logic::HandleAttrs a;
    a.hasEventOrApc   = eventOrApc;
    a.firstReadLength = length;

    auto early = [&](Eligibility r) {
      return r == Eligibility::EventOrApc || r == Eligibility::QueryFailed ||
             r == Eligibility::NotDisk;
    };

    if (eventOrApc)
      return Eligibility::EventOrApc;

    IO_STATUS_BLOCK iosb;
    std::memset(&iosb, 0, sizeof(iosb));

    FILE_FS_DEVICE_INFORMATION dev;
    std::memset(&dev, 0, sizeof(dev));
    NTSTATUS st = ::NtQueryVolumeInformationFile(h, &iosb, &dev, sizeof(dev),
                                                 FileFsDeviceInformation);
    if (st < 0) {
      a.queriesOk = false;
    } else {
      a.deviceType = dev.DeviceType;
    }
    if (Eligibility r = logic::evaluateEligibility(a, g->limits); early(r))
      return r;

    const uint64_t metaGen = metacache::generation();  // before the snapshot is read
    FileAttrs info;
    st = queryAttrs(h, info);
    if (st != STATUS_SUCCESS) {
      g->stats.failedClassifications.fetch_add(1, std::memory_order_relaxed);
      if (g->stats.failedClassifications.load(std::memory_order_relaxed) <= 8) {
        if (auto logger = spdlog::get("usvfs")) {
          logger->warn("readcache: attribute query failed with {:#x}",
                       static_cast<uint32_t>(st));
        }
      }
      return Eligibility::QueryFailed;
    }

    a.directory = (info.fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    a.mode      = info.mode;
    a.access    = info.access;
    a.endOfFile =
        info.endOfFile < 0 ? UINT64_MAX : static_cast<uint64_t>(info.endOfFile);

    Key key;
    key.fileId  = info.fileId;
    key.size    = a.endOfFile;
    key.written = info.written;
    key.changed = info.changed;

    // big reads of any regular file may be split/read ahead, cacheable or not
    hs.key                  = key;
    hs.snap.fileId          = info.fileId;
    hs.snap.creation        = info.creation;
    hs.snap.lastAccess      = info.lastAccess;
    hs.snap.written         = info.written;
    hs.snap.changed         = info.changed;
    hs.snap.allocation      = info.allocation;
    hs.snap.endOfFile       = info.endOfFile;
    hs.snap.attributes      = info.fileAttributes;
    hs.snap.reparseTag      = info.reparseTag;
    hs.snap.links           = info.numberOfLinks;
    hs.snap.effectiveAccess = info.effectiveAccess;
    hs.snapSlot             = fileGenSlot(info.fileId);
    hs.snapFileGen          = g_fileGen[hs.snapSlot].load(std::memory_order_acquire);
    hs.snapGlobalGen        = g_writeGeneration.load(std::memory_order_acquire);
    hs.snapMetaGen          = metaGen;
    hs.probPos.store(info.position < 0 ? 0 : static_cast<uint64_t>(info.position),
                     std::memory_order_relaxed);
    hs.probKnown.store(info.position >= 0, std::memory_order_release);
    hs.splitOk.store(logic::splitCapable(a) && a.endOfFile > 0 &&
                         a.endOfFile != UINT64_MAX,
                     std::memory_order_release);

    if (Eligibility r = logic::evaluateEligibility(a, g->limits);
        r != Eligibility::Eligible)
      return r;

    // no data is loaded yet: the handle starts on probation (see read())
    hs.entry = g->store.acquire(key);
    return Eligibility::Eligible;
  }

  void classify(HandleState& hs, HANDLE h, bool eventOrApc, ULONG length)
  {
    Eligibility r        = Eligibility::QueryFailed;
    const uint64_t t0    = nowUs();
    const uint64_t fill0 = t_syncFillUs;
    try {
      r = classifyImpl(hs, h, eventOrApc, length);
    } catch (...) {
      r = Eligibility::QueryFailed;
      g->stats.failedClassifications.fetch_add(1, std::memory_order_relaxed);
    }

    Stats& s = g->stats;
    {
      const uint64_t total = nowUs() - t0;
      const uint64_t fill  = t_syncFillUs - fill0;
      s.classifyUs.fetch_add(total > fill ? total - fill : 0,
                             std::memory_order_relaxed);
    }
    s.classified.fetch_add(1, std::memory_order_relaxed);
    if (r == Eligibility::Eligible) {
      s.eligible.fetch_add(1, std::memory_order_relaxed);
    } else {
      s.ineligible.fetch_add(1, std::memory_order_relaxed);
      s.byReason[static_cast<int>(r)].fetch_add(1, std::memory_order_relaxed);
    }
    hs.mode.store(r == Eligibility::Eligible ? kHandleProbation : kHandleIneligible,
                  std::memory_order_release);
    countEvent(s.classified);
  }

  // ---------------------------------------------------------------------------
  // handle map

  std::shared_ptr<HandleState> lookup(HANDLE h)
  {
    std::shared_lock<std::shared_mutex> lock(g->handlesLock);
    auto it = g->handles.find(h);
    return it == g->handles.end() ? nullptr : it->second;
  }

  // returns true if `fresh` was inserted, otherwise `existing` is set
  bool insertIfAbsent(HANDLE h, const std::shared_ptr<HandleState>& fresh,
                      std::shared_ptr<HandleState>& existing)
  {
    std::unique_lock<std::shared_mutex> lock(g->handlesLock);
    auto res = g->handles.try_emplace(h, fresh);
    if (!res.second)
      existing = res.first->second;
    return res.second;
  }

  // ---------------------------------------------------------------------------
  // reading

  NTSTATUS realRead(HANDLE h, HANDLE ev, PIO_APC_ROUTINE apc, PVOID ctx,
                    PIO_STATUS_BLOCK iosb, PVOID buf, ULONG len, PLARGE_INTEGER off,
                    PULONG key)
  {
    notePassthrough();
    t_ioStarted = true;
    return ::NtReadFile(h, ev, apc, ctx, iosb, buf, len, off, key);
  }

  // moves a handle from probation to served mode: loads the file (or queues
  // it) and takes over the file pointer. Caller holds hs.m. On failure the handle
  // becomes ineligible and the real pointer is as it was.
  bool admit(HandleState& hs, HANDLE h)
  {
    CacheEntry& e = *hs.entry;
    uint64_t pos  = 0;
    bool ok       = getRealPos(h, pos);

    if (ok) {
      bool loaded = false;
      if (g->async && e.size > 0 && !g->stop.load(std::memory_order_relaxed))
        loaded = queueFill(h, hs.entry);
      ok = loaded || fillSync(h, hs.entry);
      if (!ok)
        setRealPos(h, pos);  // the sync fill moved it
    }

    if (!ok) {
      hs.mode.store(kHandleIneligible, std::memory_order_release);
      hs.entry.reset();
      g->stats.byReason[static_cast<int>(Eligibility::FillFailed)].fetch_add(
          1, std::memory_order_relaxed);
      return false;
    }

    // the classification already holds what NtQueryFullAttributesFile would say about
    // this file: hand it to the metacache attribute store (exactness: only while this
    // process has not written the file since the snapshot, and the metacache refuses
    // volatile/overwrite paths and stale generations itself)
    if (g_shareToMeta && !e.ntPath.empty() && metacache::enabled() &&
        hs.snapFileGen == g_fileGen[hs.snapSlot].load(std::memory_order_acquire) &&
        hs.snapGlobalGen == g_writeGeneration.load(std::memory_order_acquire) &&
        (hs.snap.attributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        hs.snap.reparseTag == 0) {
      FILE_NETWORK_OPEN_INFORMATION n;
      std::memset(&n, 0, sizeof(n));
      n.CreationTime.QuadPart   = hs.snap.creation;
      n.LastAccessTime.QuadPart = hs.snap.lastAccess;
      n.LastWriteTime.QuadPart  = hs.snap.written;
      n.ChangeTime.QuadPart     = hs.snap.changed;
      n.AllocationSize.QuadPart = hs.snap.allocation;
      n.EndOfFile.QuadPart      = hs.snap.endOfFile;
      n.FileAttributes          = hs.snap.attributes;
      metacache::feedFull(e.ntPath, n, hs.snapMetaGen);
    }

    dropWindows(hs);  // served mode takes over
    hs.shadowPos = pos;
    g->stats.bucket[logic::sizeBucket(e.size)].admitted.fetch_add(
        1, std::memory_order_relaxed);
    hs.mode.store(kHandleServed, std::memory_order_release);
    return true;
  }

  // Reads of one handle that overlap in time leave the file pointer in an order we
  // can't know: the position becomes unknown until they are all through.
  void probEnter(HandleState& hs)
  {
    if (hs.probInFlight.fetch_add(1, std::memory_order_acq_rel) > 0)
      hs.probOverlap.store(true, std::memory_order_release);
  }

  void probLeave(HandleState& hs)
  {
    if (hs.probInFlight.fetch_sub(1, std::memory_order_acq_rel) == 1 &&
        hs.probOverlap.exchange(false, std::memory_order_acq_rel))
      hs.probKnown.store(false, std::memory_order_release);
  }

  struct ProbFlight
  {
    explicit ProbFlight(HandleState& h) : hs(h) { probEnter(hs); }
    ~ProbFlight() { probLeave(hs); }
    HandleState& hs;
  };

  // updates the tracked position of a probation handle after a read that went to
  // the system. Anything we can't account for makes the position unknown.
  void trackProbationRead(HandleState& hs, HANDLE ev, PIO_APC_ROUTINE apc,
                          PIO_STATUS_BLOCK iosb, PLARGE_INTEGER off, NTSTATUS status)
  {
    auto unknown = [&]() {
      hs.probKnown.store(false, std::memory_order_release);
    };
    if (ev != nullptr || apc != nullptr || iosb == nullptr)
      return unknown();

    int64_t requested = -2;  // FILE_USE_FILE_POINTER_POSITION
    if (off != nullptr && !sehCopy(&requested, off, sizeof(requested)))
      return unknown();
    const bool explicitOff =
        off != nullptr && requested != logic::kUseFilePointerPosition;
    if (explicitOff && requested < 0)
      return unknown();

    if (status == STATUS_SUCCESS) {
      ULONG_PTR info = 0;
      if (!sehCopy(&info, &iosb->Information, sizeof(info)))
        return unknown();
      if (explicitOff) {
        hs.probPos.store(static_cast<uint64_t>(requested) + info,
                         std::memory_order_relaxed);
        hs.probKnown.store(true, std::memory_order_release);
      } else if (hs.probKnown.load(std::memory_order_acquire)) {
        hs.probPos.store(hs.probPos.load(std::memory_order_relaxed) + info,
                         std::memory_order_relaxed);
      }
      return;
    }
    if (status == STATUS_END_OF_FILE && !explicitOff)
      return;  // the pointer stays where it was
    unknown();
  }

  // a request on an eligible handle that we don't serve: the real file pointer
  // has to match what the caller believes it to be. Caller holds hs.m.
  NTSTATUS syncedRead(HandleState& hs, HANDLE h, HANDLE ev, PIO_APC_ROUTINE apc,
                      PVOID ctx, PIO_STATUS_BLOCK iosb, PVOID buf, ULONG len,
                      PLARGE_INTEGER off, PULONG key)
  {
    if (setRealPos(h, hs.shadowPos) < 0)
      hs.mode.store(kHandleIneligible, std::memory_order_release);

    const NTSTATUS res = realRead(h, ev, apc, ctx, iosb, buf, len, off, key);

    uint64_t pos = 0;
    if (getRealPos(h, pos)) {
      hs.shadowPos = pos;
    } else {
      hs.mode.store(kHandleIneligible, std::memory_order_release);
    }
    return res;
  }

  // Big read (>= kSmallReadLimit) on a handle that isn't served from the cache:
  // try readahead data, then a parallel split, else the plain call. Caller holds
  // hs.m; the request has no event/apc/key. Once the real I/O has started nothing
  // in here can throw into the caller (the hook would re-issue the request).
  NTSTATUS bigRead(HandleState& hs, HANDLE h, PIO_STATUS_BLOCK iosb, PVOID buf,
                   ULONG len, PLARGE_INTEGER off)
  {
    BigStats& bs = g->stats.big;

    // the pointer of a probation handle is only known again if this succeeds
    ProbFlight flight(hs);
    hs.probKnown.store(false, std::memory_order_release);

    auto plain = [&]() {
      return realRead(h, nullptr, nullptr, nullptr, iosb, buf, len, off, nullptr);
    };

    const bool explicitOff =
        off != nullptr && off->QuadPart != logic::kUseFilePointerPosition;
    uint64_t offset = 0;
    if (explicitOff) {
      if (off->QuadPart < 0)
        return plain();
      offset = static_cast<uint64_t>(off->QuadPart);
    } else if (!getRealPos(h, offset)) {
      return plain();
    }

    const size_t bucket = logic::bigBucket(len);
    bs.seen[bucket].fetch_add(1, std::memory_order_relaxed);
    const bool sequential = hs.seq.valid && offset == hs.seq.lastEnd;
    if (sequential)
      bs.sequential[bucket].fetch_add(1, std::memory_order_relaxed);

    NTSTATUS status = STATUS_SUCCESS;
    uint64_t total  = 0;
    bool done       = false;

    if (g->raEnabled) {
      if (serveFromWindow(hs, hs.window, h, iosb, buf, offset, len, explicitOff,
                          status) ||
          serveFromWindow(hs, hs.window2, h, iosb, buf, offset, len, explicitOff,
                          status)) {
        total = status >= 0 ? len : 0;
        done  = true;
      }
    }

    if (!done) {
      if (!sequential)
        dropWindows(hs);  // access pattern changed
      if (g->splitEnabled && len >= g->splitMinBytes && hs.splitFailures < 3) {
        try {
          done = trySplit(hs, h, iosb, buf, len, offset, explicitOff, status, total);
        } catch (...) {
          // thrown before anything was dispatched
          done = false;
        }
      }
    }

    if (!done) {
      status = plain();
      if (status == STATUS_SUCCESS) {
        ULONG_PTR info = 0;
        total =
            readcache::guardedCopy(&info, &iosb->Information, sizeof(info)) ? info : 0;
      }
    }

    if (status == STATUS_SUCCESS && total > 0) {
      hs.probPos.store(offset + total, std::memory_order_relaxed);
      hs.probKnown.store(true, std::memory_order_release);
    }

    // bookkeeping after the I/O: failures here only cost performance
    try {
      if (status == STATUS_SUCCESS && total > 0) {
        logic::updateSequential(hs.seq, offset, total);
        const uint64_t lastEnd = hs.seq.lastEnd;

        // retire windows the stream has passed
        for (int i = 0; i < 2; ++i) {
          if (hs.window && lastEnd >= hs.window->start + hs.window->length) {
            dropWindow(hs, hs.window);  // counts as unused if it never served
            hs.window = std::move(hs.window2);
            hs.window2.reset();
          }
        }
        if (hs.window2 && lastEnd >= hs.window2->start + hs.window2->length)
          dropWindow(hs, hs.window2);

        if (g->raEnabled && !hs.raDisabled && hs.splitFailures < 3 &&
            hs.seq.run >= logic::g_sequentialRun) {
          if (!hs.window) {
            issueWindow(hs, h, lastEnd, total, hs.window);
          } else if (logic::needNextWindow(true, hs.window->start, hs.window->length,
                                           hs.window2 != nullptr, lastEnd)) {
            issueWindow(hs, h, hs.window->start + hs.window->length, total, hs.window2);
          }
        }
      } else {
        hs.seq.valid = false;
        dropWindows(hs);
      }
    } catch (...) {
      hs.seq.valid = false;
      try {
        dropWindows(hs);
      } catch (...) {
      }
    }
    return status;
  }

}  // namespace

// ---------------------------------------------------------------------------
// public interface

Peek peek(HANDLE h, ULONG length)
{
  if (!g)
    return Peek::Unknown;
  std::shared_lock<std::shared_mutex> lock(g->handlesLock);
  auto it = g->handles.find(h);
  if (it == g->handles.end())
    return Peek::Unknown;
  HandleState& hs = *it->second;
  const bool big  = hs.splitOk.load(std::memory_order_acquire) &&
                    length >= logic::g_smallReadLimit &&
                    (g->splitEnabled || g->raEnabled);
  switch (hs.mode.load(std::memory_order_acquire)) {
  case kHandleServed:
    return Peek::Serve;
  case kHandleProbation: {
    if (!logic::isSmallRead(length)) {
      if (big)
        return Peek::Big;
      probEnter(hs);  // left again by afterProbationRead()
      return Peek::PassthroughTracked;
    }
    CacheEntry& e        = *hs.entry;
    const uint32_t count = e.smallReads.fetch_add(1, std::memory_order_relaxed) + 1;
    const int state      = e.state.load(std::memory_order_relaxed);
    const bool resident  = state == kReady || state == kLoading;
    if (g_serveEnabled && logic::shouldAdmit(count, g->admitReads, resident))
      return Peek::Serve;
    probEnter(hs);  // left again by afterProbationRead()
    return Peek::PassthroughTracked;
  }
  case kHandleIneligible:
    return big ? Peek::Big : Peek::Passthrough;
  default:
    return Peek::Unknown;
  }
}

void afterProbationRead(HANDLE h, HANDLE ev, PIO_APC_ROUTINE apc, PIO_STATUS_BLOCK iosb,
                        PLARGE_INTEGER off, NTSTATUS status)
{
  if (!g)
    return;
  std::shared_lock<std::shared_mutex> lock(g->handlesLock);
  auto it = g->handles.find(h);
  if (it == g->handles.end())
    return;
  HandleState& hs = *it->second;
  if (hs.mode.load(std::memory_order_acquire) == kHandleProbation)
    trackProbationRead(hs, ev, apc, iosb, off, status);
  probLeave(hs);
}

void notePassthrough()
{
  // per-thread count, flushed in batches so the hot path has no atomic RMW
  thread_local uint32_t pending = 0;
  if (++pending < 1024)
    return;
  g->stats.passthroughs.fetch_add(pending, std::memory_order_relaxed);
  pending = 0;
  maybeLog();
}

void noteFileWritten(HANDLE handle)
{
  if (!g || handle == nullptr || handle == INVALID_HANDLE_VALUE)
    return;
  // the query must reach the system, not our snapshot
  const bool wasInShim = t_inShim;
  t_inShim             = true;
  FILE_INTERNAL_INFORMATION ii;
  std::memset(&ii, 0, sizeof(ii));
  IO_STATUS_BLOCK iosb;
  std::memset(&iosb, 0, sizeof(iosb));
  const NTSTATUS st =
      ::NtQueryInformationFile(handle, &iosb, &ii, sizeof(ii), FileInternalInformation);
  t_inShim = wasInShim;
  if (st >= 0) {
    g_fileGen[fileGenSlot(ii.IndexNumber.QuadPart)].fetch_add(
        1, std::memory_order_acq_rel);
  } else {
    g_writeGeneration.fetch_add(1, std::memory_order_acq_rel);
    g->stats.fileGenFallbacks.fetch_add(1, std::memory_order_relaxed);
  }
}

void bumpWriteGeneration()
{
  g_writeGeneration.fetch_add(1, std::memory_order_acq_rel);
}

bool guardedCopy(void* dst, const void* src, size_t length)
{
  return sehCopy(dst, src, length);
}

void setForgetCallback(void (*callback)(HANDLE))
{
  g_forgetCallback = callback;
}

bool inProtectedCopy()
{
  return t_inProtectedCopy;
}

void init()
{
  g = new State();

  const bool enabled = config::flag("USVFS_READCACHE", true);
  MEMORYSTATUSEX ms{};
  ms.dwLength             = sizeof(ms);
  const uint64_t ramBytes = GlobalMemoryStatusEx(&ms) ? ms.ullTotalPhys : (16ull << 30);
  // one combined budget (USVFS_CACHE_TOTAL_MB) splits between readcache and metacache
  uint64_t defaultMb = logic::scaledDefaultMb(ramBytes, 32);
  if (config::isSet("USVFS_CACHE_TOTAL_MB")) {
    const uint64_t total = config::number("USVFS_CACHE_TOTAL_MB", 0);
    const uint64_t pct   = config::number("USVFS_CACHE_READCACHE_PCT", 50, 0, 100);
    if (total > 0)
      defaultMb = config::logic::splitTotalBudget(total, static_cast<unsigned>(pct))
                      .readcacheMb;
  }
  g->limits.budgetBytes = config::number("USVFS_READCACHE_MB", defaultMb) << 20;
  if (auto lg = spdlog::get("usvfs"))
    lg->info("readcache: RAM {} MiB, budget {} MiB", ramBytes >> 20,
             g->limits.budgetBytes >> 20);
  g->limits.maxFileBytes = config::number("USVFS_READCACHE_MAXFILE_MB", 64) << 20;
  g->admitReads          = static_cast<uint32_t>(
      config::number("USVFS_READCACHE_ADMIT_READS", 8, 0, 1u << 20));
  g->splitEnabled  = config::flag("USVFS_READCACHE_SPLIT", true);
  g->raEnabled     = config::flag("USVFS_READCACHE_RA", false);
  g->splitMinBytes = config::number("USVFS_READCACHE_SPLIT_MIN_KB", 256, 64) << 10;
  g->splitChunk    = config::number("USVFS_READCACHE_SPLIT_CHUNK_KB", 256, 16) << 10;
  g->raCapBytes    = config::number("USVFS_READCACHE_RA_MB", 64) << 20;
  g->async         = config::flag("USVFS_READCACHE_ASYNC", true);
  g->threads = static_cast<int>(config::number("USVFS_READCACHE_THREADS", 4, 1, 16));

  // tunables that used to be constants
  logic::g_smallReadLimit = config::number("USVFS_READCACHE_SMALL_READ_KB", 64, 1)
                            << 10;
  kSyncChunk        = config::number("USVFS_READCACHE_SYNC_CHUNK_KB", 8192, 64) << 10;
  kAsyncChunk       = config::number("USVFS_READCACHE_ASYNC_CHUNK_KB", 1024, 64) << 10;
  kWaitLimit        = chr::seconds(config::number("USVFS_READCACHE_WAIT_SEC", 30, 1));
  kLogIntervalMs    = config::number("USVFS_READCACHE_LOG_SEC", 30, 1) * 1000;
  kMaxWorkerHandles = static_cast<int>(
      config::number("USVFS_READCACHE_MAX_WORKER_HANDLES", 256, 1, 100000));
  logic::g_maxWindow = config::number("USVFS_READCACHE_RA_MAX_WINDOW_KB", 4096, 64)
                       << 10;
  logic::g_sequentialRun =
      static_cast<uint32_t>(config::number("USVFS_READCACHE_RA_SEQ_RUN", 2, 1, 1000));
  g_raCheckBytes = config::number("USVFS_READCACHE_RA_BACKOFF_CHECK_MB", 128, 1) << 20;
  g_raWastePct   = config::number("USVFS_READCACHE_RA_BACKOFF_WASTE_PCT", 30, 0, 100);
  g_raBackoffMs  = config::number("USVFS_READCACHE_RA_BACKOFF_SEC", 10) * 1000;
  g_serveEnabled = config::flag("USVFS_READCACHE_SERVE", true);
  g_infoEnabled  = config::flag("USVFS_READCACHE_INFO", true);
  g_positionEnabled = config::flag("USVFS_READCACHE_POSITION", true);
  g_shareToMeta     = config::flag("USVFS_CACHE_SHARE", true);
  g->lastLogTick.store(GetTickCount64());

  if (auto logger = spdlog::get("usvfs")) {
    if (enabled) {
      logger->info(
          "readcache: split {} (min {} KiB, chunk {} KiB), readahead {} ({} MiB)",
          g->splitEnabled ? "on" : "off", g->splitMinBytes >> 10, g->splitChunk >> 10,
          g->raEnabled ? "on" : "off", g->raCapBytes >> 20);
      logger->info(
          "readcache: enabled, budget {} MiB, max file {} MiB, admit after {} small "
          "reads, {}",
          g->limits.budgetBytes >> 20, g->limits.maxFileBytes >> 20, g->admitReads,
          g->async
              ? std::format(
                    "async fill with {} threads (USVFS_READCACHE_ASYNC=0 for sync)",
                    g->threads)
              : std::string("synchronous fill"));
    } else {
      logger->info("readcache: disabled by USVFS_READCACHE");
    }
  }

  g_enabled.store(enabled, std::memory_order_release);
}

void shutdown()
{
  if (!g)
    return;

  g_enabled.store(false, std::memory_order_release);
  g->stop.store(true);
  {
    std::lock_guard<std::mutex> lock(g->pool.m);
  }  // no lost wakeup
  g->pool.cv.notify_all();

  // This runs from HookManager's destructor, i.e. outside of DllMain and the
  // loader lock, so waiting for the workers is fine. They finish at most one
  // chunk each. Give them a bounded time; if one is stuck in a slow read we
  // detach it instead of hanging process exit (State is never freed, so a late
  // worker doesn't touch freed memory).
  const auto deadline = chr::steady_clock::now() + chr::seconds(2);
  while (g->pool.alive.load() > 0 && chr::steady_clock::now() < deadline)
    Sleep(2);

  {
    std::lock_guard<std::mutex> lock(g->pool.m);
    const bool clean = g->pool.alive.load() == 0;
    for (std::thread& t : g->pool.threads) {
      if (!t.joinable())
        continue;
      if (clean) {
        t.join();
      } else {
        t.detach();
      }
    }
    g->pool.threads.clear();
  }

  {
    std::unique_lock<std::shared_mutex> lock(g->handlesLock);
    for (auto& kv : g->handles) {
      const HandleState& hs = *kv.second;
      if (hs.mode.load(std::memory_order_acquire) == kHandleProbation && hs.entry) {
        g->stats.bucket[logic::sizeBucket(hs.entry->size)].probationEnd.fetch_add(
            1, std::memory_order_relaxed);
      }
    }
    g->handles.clear();
  }

  try {
    logSummary("readcache final");
  } catch (...) {
  }
}

void onClose(HANDLE handle)
{
  if (!g || !enabled())
    return;

  {
    std::shared_lock<std::shared_mutex> lock(g->handlesLock);
    if (g->handles.empty() || g->handles.find(handle) == g->handles.end())
      return;
  }
  std::unique_lock<std::shared_mutex> lock(g->handlesLock);
  auto it = g->handles.find(handle);
  if (it == g->handles.end())
    return;
  const HandleState& hs = *it->second;
  if (hs.mode.load(std::memory_order_acquire) == kHandleProbation && hs.entry) {
    g->stats.bucket[logic::sizeBucket(hs.entry->size)].probationEnd.fetch_add(
        1, std::memory_order_relaxed);
  }
  std::shared_ptr<HandleState> dying = std::move(it->second);
  g->handles.erase(it);
  lock.unlock();
  dying.reset();  // may close worker handles: not under the map lock
}

namespace
{
  NTSTATUS readImpl(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
  {
    auto passthrough = [&]() {
      return realRead(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
                      Length, ByteOffset, Key);
    };

    if (!enabled() || FileHandle == nullptr || FileHandle == INVALID_HANDLE_VALUE)
      return ::NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                          Buffer, Length, ByteOffset, Key);

    std::shared_ptr<HandleState> hs = lookup(FileHandle);
    std::unique_lock<std::mutex> lock;
    bool justClassified = false;

    if (!hs) {
      auto fresh = std::make_shared<HandleState>();
      std::unique_lock<std::mutex> freshLock(fresh->m);
      if (insertIfAbsent(FileHandle, fresh, hs)) {
        hs   = fresh;
        lock = std::move(freshLock);
        classify(*hs, FileHandle, Event != nullptr || ApcRoutine != nullptr, Length);
        justClassified = true;
      } else {
        freshLock.unlock();
      }
    }

    // big reads on handles that are not served from memory (layer 3)
    const bool bigCandidate = hs->splitOk.load(std::memory_order_acquire) &&
                              Length >= logic::g_smallReadLimit &&
                              (g->splitEnabled || g->raEnabled) && Event == nullptr &&
                              ApcRoutine == nullptr && Key == nullptr &&
                              IoStatusBlock != nullptr && Buffer != nullptr;

    if (!lock.owns_lock()) {
      // fast path for handles we decided not to touch
      if (hs->mode.load(std::memory_order_acquire) == kHandleIneligible &&
          !bigCandidate)
        return passthrough();
      lock = std::unique_lock<std::mutex>(hs->m);
    }

    if (bigCandidate && hs->mode.load(std::memory_order_acquire) != kHandleServed)
      return bigRead(*hs, FileHandle, IoStatusBlock, Buffer, Length, ByteOffset);

    if (hs->mode.load(std::memory_order_acquire) == kHandleIneligible) {
      lock.unlock();
      return passthrough();
    }

    if (hs->mode.load(std::memory_order_acquire) == kHandleProbation) {
      // the real file pointer is authoritative on probation
      auto trackedPassthrough = [&]() {
        lock.unlock();
        ProbFlight flight(*hs);
        const NTSTATUS r = passthrough();
        trackProbationRead(*hs, Event, ApcRoutine, IoStatusBlock, ByteOffset, r);
        return r;
      };
      if (Event != nullptr || ApcRoutine != nullptr || Key != nullptr ||
          IoStatusBlock == nullptr || !g_serveEnabled)
        return trackedPassthrough();
      if (justClassified) {
        // peek() counts the reads of every later call
        bool admitNow = false;
        if (logic::isSmallRead(Length)) {
          CacheEntry& pe = *hs->entry;
          const uint32_t cnt =
              pe.smallReads.fetch_add(1, std::memory_order_relaxed) + 1;
          const int pstate = pe.state.load(std::memory_order_relaxed);
          admitNow         = logic::shouldAdmit(cnt, g->admitReads,
                                                pstate == kReady || pstate == kLoading);
        }
        if (!admitNow)
          return trackedPassthrough();
      }
      if (!admit(*hs, FileHandle)) {
        lock.unlock();
        return passthrough();
      }
    }

    // ---- admitted handle, hs->m held ----

    CacheEntry& e = *hs->entry;

    if (Event != nullptr || ApcRoutine != nullptr || IoStatusBlock == nullptr)
      return syncedRead(*hs, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                        Buffer, Length, ByteOffset, Key);

    const logic::ReadPlan plan = logic::planRead(
        e.size, hs->shadowPos, ByteOffset != nullptr,
        ByteOffset != nullptr ? ByteOffset->QuadPart : 0, Length, Key != nullptr);

    switch (plan.action) {
    case logic::ReadAction::Passthrough:
      return syncedRead(*hs, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                        Buffer, Length, ByteOffset, Key);

    case logic::ReadAction::EndOfFile:
      if (!sehStoreStatus(IoStatusBlock, STATUS_END_OF_FILE, 0))
        return STATUS_ACCESS_VIOLATION;
      return STATUS_END_OF_FILE;

    case logic::ReadAction::Copy:
      break;
    }

    // The buffer may have been evicted since the last read (the entry stays with
    // the handle): refill it. While dataLock is held shared the buffer can't go.
    std::shared_lock<std::shared_mutex> dataLock(e.dataLock);
    bool loaded = false;
    for (int attempt = 0; attempt < 3; ++attempt) {
      if (e.state.load(std::memory_order_acquire) == kEmpty) {
        dataLock.unlock();
        bool refilled = false;
        if (g->async && !g->stop.load(std::memory_order_relaxed))
          refilled = queueFill(FileHandle, hs->entry);
        if (!refilled)
          refilled = fillSync(FileHandle, hs->entry);
        dataLock.lock();
        if (!refilled)
          break;
        continue;
      }
      // layer 2: the range may still be loading
      loaded = waitLoaded(e, plan.offset + plan.count);
      break;
    }

    if (!loaded) {
      // the fill failed or timed out: continue with the real file
      dataLock.unlock();
      const uint64_t shadow = hs->shadowPos;
      hs->mode.store(kHandleIneligible, std::memory_order_release);
      hs->entry.reset();
      g->stats.byReason[static_cast<int>(Eligibility::FillFailed)].fetch_add(
          1, std::memory_order_relaxed);
      setRealPos(FileHandle, shadow);
      lock.unlock();
      return passthrough();
    }

    t_ioStarted = true;
    if (!sehCopy(Buffer, e.data.get() + plan.offset, static_cast<size_t>(plan.count)) ||
        !sehStoreStatus(IoStatusBlock, STATUS_SUCCESS,
                        static_cast<ULONG_PTR>(plan.count))) {
      return STATUS_ACCESS_VIOLATION;
    }
    touch(e);

    hs->shadowPos   = plan.newPos;
    BucketStats& bs = g->stats.bucket[logic::sizeBucket(e.size)];
    bs.bytesServed.fetch_add(plan.count, std::memory_order_relaxed);
    bs.served.fetch_add(1, std::memory_order_relaxed);
    countEvent(bs.served);
    return STATUS_SUCCESS;
  }
}  // namespace

NTSTATUS read(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
              ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
  // The hook re-issues the request if we throw, which is only right as long as
  // we haven't read anything yet.
  t_ioStarted = false;
  struct ShimScope
  {
    ShimScope() { t_inShim = true; }
    ~ShimScope() { t_inShim = false; }
  } shimScope;
  try {
    return readImpl(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
                    Length, ByteOffset, Key);
  } catch (...) {
    if (!t_ioStarted) {
      // a served handle's real file pointer is stale: re-issuing the request
      // there would read from the wrong place
      std::shared_ptr<HandleState> hs = lookup(FileHandle);
      if (hs && hs->served())
        return static_cast<NTSTATUS>(0xC000009AL);  // STATUS_INSUFFICIENT_RESOURCES
      throw;
    }
    return static_cast<NTSTATUS>(
        0xC0000001L);  // STATUS_UNSUCCESSFUL; unreachable in practice: see bigRead
  }
}

bool tryServeInfo(HANDLE h, PIO_STATUS_BLOCK iosb, PVOID info, ULONG length,
                  FILE_INFORMATION_CLASS cls, NTSTATUS& status)
{
  if (!g || !enabled() || h == nullptr || t_inShim)
    return false;

  std::shared_lock<std::shared_mutex> lock(g->handlesLock);
  auto it = g->handles.find(h);
  if (it == g->handles.end())
    return false;
  const HandleState& hs = *it->second;
  const int mode        = hs.mode.load(std::memory_order_acquire);
  // read-only synchronous regular files: eligible ones, and those that only
  // failed the cache's size/first-read rules (BSAs, big plugins)
  const bool splitOnly =
      mode == kHandleIneligible && hs.splitOk.load(std::memory_order_acquire);
  if (mode != kHandleProbation && mode != kHandleServed && !splitOnly)
    return false;

  if (!g_infoEnabled && cls != FilePositionInformation)
    return false;

  const int c        = static_cast<int>(cls);
  const bool counted = c >= 0 && c < 80;
  auto passed        = [&]() {
    if (counted && !splitOnly)
      g->stats.infoPassed[c].fetch_add(1, std::memory_order_relaxed);
    return false;
  };

  // FilePositionInformation: probation handles answer from the tracked position;
  // served handles are answered by queryInformation() (shadow position)
  if (cls == FilePositionInformation) {
    if (splitOnly || !g_positionEnabled)
      return false;
    if (mode == kHandleServed) {
      g->stats.infoServed[14].fetch_add(1, std::memory_order_relaxed);
      return false;
    }
    if (hs.probKnown.load(std::memory_order_acquire) && info && iosb &&
        length >= sizeof(FILE_POSITION_INFORMATION)) {
      FILE_POSITION_INFORMATION pos;
      pos.CurrentByteOffset.QuadPart =
          static_cast<LONGLONG>(hs.probPos.load(std::memory_order_acquire));
      if (!sehCopy(info, &pos, sizeof(pos)) ||
          !sehStoreStatus(iosb, STATUS_SUCCESS, sizeof(pos)))
        status = STATUS_ACCESS_VIOLATION;
      else
        status = STATUS_SUCCESS;
      g->stats.infoServedProbationPos.fetch_add(1, std::memory_order_relaxed);
      return true;
    }
    g->stats.infoPassedProbationPos.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  // this process modified the file (or something we couldn't attribute) since
  // the snapshot was taken
  if (hs.snapFileGen != g_fileGen[hs.snapSlot].load(std::memory_order_acquire) ||
      hs.snapGlobalGen != g_writeGeneration.load(std::memory_order_acquire))
    return passed();

  const FileSnapshot& f = hs.snap;
  union
  {
    FILE_BASIC_INFORMATION basic;
    FILE_STANDARD_INFORMATION standard;
    FILE_INTERNAL_INFORMATION internal;
    FILE_NETWORK_OPEN_INFORMATION netOpen;
    USVFS_FILE_ATTRIBUTE_TAG_INFORMATION tag;
    USVFS_FILE_STAT_INFORMATION stat;
  } out;
  size_t size = 0;
  std::memset(&out, 0, sizeof(out));

  switch (cls) {
  case FileBasicInformation:
    out.basic.CreationTime.QuadPart   = f.creation;
    out.basic.LastAccessTime.QuadPart = f.lastAccess;
    out.basic.LastWriteTime.QuadPart  = f.written;
    out.basic.ChangeTime.QuadPart     = f.changed;
    out.basic.FileAttributes          = f.attributes;
    size                              = sizeof(out.basic);
    break;
  case FileStandardInformation:
    out.standard.AllocationSize.QuadPart = f.allocation;
    out.standard.EndOfFile.QuadPart      = f.endOfFile;
    out.standard.NumberOfLinks           = f.links;
    out.standard.DeletePending           = FALSE;
    out.standard.Directory               = FALSE;
    size                                 = sizeof(out.standard);
    break;
  case FileInternalInformation:
    out.internal.IndexNumber.QuadPart = f.fileId;
    size                              = sizeof(out.internal);
    break;
  case FileNetworkOpenInformation:
    out.netOpen.CreationTime.QuadPart   = f.creation;
    out.netOpen.LastAccessTime.QuadPart = f.lastAccess;
    out.netOpen.LastWriteTime.QuadPart  = f.written;
    out.netOpen.ChangeTime.QuadPart     = f.changed;
    out.netOpen.AllocationSize.QuadPart = f.allocation;
    out.netOpen.EndOfFile.QuadPart      = f.endOfFile;
    out.netOpen.FileAttributes          = f.attributes;
    size                                = sizeof(out.netOpen);
    break;
  case FileAttributeTagInformation:
    out.tag.FileAttributes = f.attributes;
    out.tag.ReparseTag     = f.reparseTag;
    size                   = sizeof(out.tag);
    break;
  case FileStatInformation:
    out.stat.FileId.QuadPart         = f.fileId;
    out.stat.CreationTime.QuadPart   = f.creation;
    out.stat.LastAccessTime.QuadPart = f.lastAccess;
    out.stat.LastWriteTime.QuadPart  = f.written;
    out.stat.ChangeTime.QuadPart     = f.changed;
    out.stat.AllocationSize.QuadPart = f.allocation;
    out.stat.EndOfFile.QuadPart      = f.endOfFile;
    out.stat.FileAttributes          = f.attributes;
    out.stat.ReparseTag              = f.reparseTag;
    out.stat.NumberOfLinks           = f.links;
    out.stat.EffectiveAccess         = f.effectiveAccess;
    size                             = sizeof(out.stat);
    break;
  default:
    return passed();
  }

  // too small a buffer (or no buffer): let the system report it its own way
  if (!info || !iosb || length < size)
    return passed();

  if (!sehCopy(info, &out, size) || !sehStoreStatus(iosb, STATUS_SUCCESS, size)) {
    status = STATUS_ACCESS_VIOLATION;
  } else {
    status = STATUS_SUCCESS;
  }
  if (counted) {
    (splitOnly ? g->stats.infoServedSplit : g->stats.infoServed)[c].fetch_add(
        1, std::memory_order_relaxed);
  }
  return true;
}

NTSTATUS queryInformation(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                          PVOID FileInformation, ULONG Length,
                          FILE_INFORMATION_CLASS FileInformationClass)
{
  if (!g || !enabled() ||
      (FileInformationClass != FilePositionInformation &&
       FileInformationClass != FileAllInformation))
    return ::NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
                                    FileInformationClass);

  std::shared_ptr<HandleState> hs = lookup(FileHandle);
  if (!hs || !hs->served() || FileInformation == nullptr || IoStatusBlock == nullptr)
    return ::NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
                                    FileInformationClass);

  if (FileInformationClass == FilePositionInformation) {
    if (Length < sizeof(FILE_POSITION_INFORMATION))
      return ::NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
                                      Length, FileInformationClass);
    std::lock_guard<std::mutex> lock(hs->m);
    if (hs->served()) {
      if (!sehStoreInt64(FileInformation, static_cast<int64_t>(hs->shadowPos)) ||
          !sehStoreStatus(IoStatusBlock, STATUS_SUCCESS,
                          sizeof(FILE_POSITION_INFORMATION)))
        return STATUS_ACCESS_VIOLATION;
      return STATUS_SUCCESS;
    }
    // demoted in the meantime: the real pointer is correct again
    return ::NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
                                    FileInformationClass);
  }

  // FileAllInformation: let the system fill it, then correct the position
  const NTSTATUS res = ::NtQueryInformationFile(
      FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
  if ((res == STATUS_SUCCESS || res == STATUS_BUFFER_OVERFLOW) &&
      Length >= offsetof(FILE_ALL_INFORMATION, ModeInformation)) {
    std::lock_guard<std::mutex> lock(hs->m);
    if (hs->served()) {
      auto* all = static_cast<FILE_ALL_INFORMATION*>(FileInformation);
      sehStoreInt64(&all->PositionInformation.CurrentByteOffset,
                    static_cast<int64_t>(hs->shadowPos));
    }
  }
  return res;
}

NTSTATUS setInformation(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                        PVOID FileInformation, ULONG Length,
                        FILE_INFORMATION_CLASS FileInformationClass)
{
  if (!g || !enabled() || FileInformationClass != FilePositionInformation)
    return ::NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
                                  FileInformationClass);

  std::shared_ptr<HandleState> hs = lookup(FileHandle);
  if (hs && hs->mode.load(std::memory_order_acquire) == kHandleProbation &&
      FileInformation != nullptr && Length >= sizeof(FILE_POSITION_INFORMATION)) {
    // probation: the system keeps the pointer, we only follow it
    int64_t requested   = 0;
    const bool readable = sehCopy(&requested, FileInformation, sizeof(requested));
    const NTSTATUS res  = ::NtSetInformationFile(
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
    if (res >= 0 && readable && requested >= 0) {
      hs->probPos.store(static_cast<uint64_t>(requested), std::memory_order_relaxed);
      hs->probKnown.store(true, std::memory_order_release);
    } else if (res >= 0) {
      hs->probKnown.store(false, std::memory_order_release);
    }
    return res;
  }
  if (!hs || !hs->served() || FileInformation == nullptr ||
      Length < sizeof(FILE_POSITION_INFORMATION))
    return ::NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
                                  FileInformationClass);

  std::lock_guard<std::mutex> lock(hs->m);

  // read the requested position before the call so the buffer is only
  // touched through the guarded copy
  int64_t requested   = 0;
  const bool readable = sehCopy(&requested, FileInformation, sizeof(requested));

  const NTSTATUS res = ::NtSetInformationFile(
      FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
  if (res >= 0 && hs->served()) {
    if (readable && requested >= 0) {
      hs->shadowPos = static_cast<uint64_t>(requested);
    } else {
      // can't tell where the pointer went; hand the handle back to the system
      uint64_t pos = 0;
      if (getRealPos(FileHandle, pos)) {
        hs->shadowPos = pos;
      } else {
        hs->mode.store(kHandleIneligible, std::memory_order_release);
      }
    }
  }
  return res;
}

}  // namespace usvfs::readcache
