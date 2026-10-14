// replay.exe: replays a file-API trace recorded by the usvfs DLL (USVFS_TRACE)
// against the current environment, to A/B usvfs cache layers without the game.
// See Linux-Storage-DLL/Tools/harness.md for usage.
//
//   replay.exe <trace> [--timing asap|original] [--verify] [--threads-as-recorded]
//              [--single-thread] [--allow-writes] [--inherit-env] [--out results.json]
//              [--from S] [--to S] [--limit-seconds N] [--no-ff] [--ff-reads]
//              [--config NAME KEY=VAL ...]...
//
// The parent process only orchestrates: it spawns itself once per --config (with
// that environment, so the usvfs DLL injected into the child reads it); each child
// maps the trace, indexes it, and replays one pass, decoding the trace lazily per
// thread (the trace is far bigger than memory is willing to hold as records).
// Everything is logged to <out>.log.

#define PSAPI_VERSION 2
#include "../usvfs_dll/trace_format.h"
#include <ntdll_declarations.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <latch>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace usvfs::trace;

namespace
{

constexpr NTSTATUS kStatusPending   = 0x00000103;
constexpr ULONG kObjCaseInsensitive = 0x40;
constexpr ULONG kFileOpen           = 1;

struct Options
{
  std::wstring tracePath;
  bool timingOriginal = false;
  bool verify         = false;
  bool singleThread   = false;
  bool allowWrites    = false;
  bool inheritEnv     = false;
  double fromSec      = 0;
  bool noFastForward =
      false;  // --no-ff: window mode re-opens handles instead of replaying the prefix
  bool ffReads = false;  // --ff-reads: the fast-forwarded prefix also executes reads
                         // (cache warming)
  double toSec    = -1;  // < 0: to the end
  double limitSec = -1;  // < 0: none
  std::wstring vfsPath;  // --vfs: mapping manifest written by USVFS_MAPPING_DUMP
  std::wstring instanceName;  // --instance
  std::wstring usvfsDll;      // --usvfs-dll
  std::wstring outPath;
  std::wstring logPath;
  std::wstring childResult;  // set in child mode
};

struct Config
{
  std::string name;
  std::vector<std::pair<std::wstring, std::wstring>> env;
};

std::string toUtf8(const std::wstring& w)
{
  if (w.empty())
    return {};
  int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0,
                                nullptr, nullptr);
  std::string s(n, '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr,
                        nullptr);
  return s;
}

uint64_t qpcNow()
{
  LARGE_INTEGER v;
  ::QueryPerformanceCounter(&v);
  return (uint64_t)v.QuadPart;
}

uint64_t qpcFreq()
{
  static const uint64_t f = [] {
    LARGE_INTEGER v;
    ::QueryPerformanceFrequency(&v);
    return (uint64_t)v.QuadPart;
  }();
  return f;
}

double ticksToUs(uint64_t ticks)
{
  return (double)ticks * 1e6 / (double)qpcFreq();
}

// ---------------------------------------------------------------------------
// log file (<out>.log): opened for append per message, so parent and child can
// both write to it and nothing is lost if the console closes or a process dies

std::wstring g_logPath;
const char* g_role = "parent";

std::string lastErrorText(DWORD err)
{
  char buf[256] = {};
  ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   err, 0, buf, sizeof(buf), nullptr);
  std::string s = buf;
  while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
    s.pop_back();
  char head[32];
  std::snprintf(head, sizeof(head), "%lu", err);
  return std::string(head) + (s.empty() ? "" : " (" + s + ")");
}

double peakWorkingSetMb()
{
  PROCESS_MEMORY_COUNTERS pmc{};
  pmc.cb = sizeof(pmc);
  if (!::GetProcessMemoryInfo(::GetCurrentProcess(), &pmc, sizeof(pmc)))
    return 0;
  return (double)pmc.PeakWorkingSetSize / (1024.0 * 1024.0);
}

void logf(const char* fmt, ...)
{
  char msg[2048];
  va_list ap;
  va_start(ap, fmt);
  std::vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  SYSTEMTIME st;
  ::GetLocalTime(&st);
  char line[2300];
  const int n = std::snprintf(line, sizeof(line), "%02d:%02d:%02d.%03d [%s %lu] %s\n",
                              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                              g_role, ::GetCurrentProcessId(), msg);
  if (!g_logPath.empty()) {
    HANDLE f = ::CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
      DWORD w;
      ::WriteFile(f, line, (DWORD)n, &w, nullptr);
      ::CloseHandle(f);
    }
  }
  std::fputs(line, stdout);
  std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// trace file access: mapped when possible (page faults, not hooked reads), else
// read in blocks

class TraceFile
{
public:
  ~TraceFile()
  {
    if (m_view)
      ::UnmapViewOfFile(m_view);
    if (m_map)
      ::CloseHandle(m_map);
    if (m_file != INVALID_HANDLE_VALUE)
      ::CloseHandle(m_file);
  }

  bool open(const std::wstring& path)
  {
    m_file =
        ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_file == INVALID_HANDLE_VALUE) {
      logf("cannot open trace: %s", lastErrorText(::GetLastError()).c_str());
      return false;
    }
    LARGE_INTEGER sz;
    ::GetFileSizeEx(m_file, &sz);
    m_size = (uint64_t)sz.QuadPart;
    m_map  = ::CreateFileMappingW(m_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (m_map)
      m_view = (const uint8_t*)::MapViewOfFile(m_map, FILE_MAP_READ, 0, 0, 0);
    if (!m_view)
      logf("mapping the trace failed (%s), using block reads",
           lastErrorText(::GetLastError()).c_str());
    return true;
  }

  uint64_t size() const { return m_size; }

  // pointer to n bytes at off (valid until the next call with the same scratch)
  const uint8_t* get(uint64_t off, size_t n, std::vector<uint8_t>& scratch)
  {
    if (off + n > m_size)
      return nullptr;
    if (m_view)
      return m_view + off;
    scratch.resize(n);
    std::lock_guard<std::mutex> lock(m_mutex);
    LARGE_INTEGER p;
    p.QuadPart = (LONGLONG)off;
    if (!::SetFilePointerEx(m_file, p, nullptr, FILE_BEGIN))
      return nullptr;
    size_t done = 0;
    while (done < n) {
      DWORD got = 0;
      if (!::ReadFile(m_file, scratch.data() + done,
                      (DWORD)std::min<size_t>(n - done, 1u << 26), &got, nullptr) ||
          !got)
        return nullptr;
      done += got;
    }
    return scratch.data();
  }

private:
  HANDLE m_file         = INVALID_HANDLE_VALUE;
  HANDLE m_map          = nullptr;
  const uint8_t* m_view = nullptr;
  uint64_t m_size       = 0;
  std::mutex m_mutex;
};

// ---------------------------------------------------------------------------
// index of the trace (built by one streaming pass; records are NOT kept)

struct StrTable
{
  std::vector<wchar_t> arena;
  std::vector<uint32_t> off;
  void set(uint32_t id, const std::wstring& s)
  {
    if (off.size() <= id)
      off.resize((size_t)id + 1, 0xffffffffu);
    off[id] = (uint32_t)arena.size();
    arena.insert(arena.end(), s.begin(), s.end());
    arena.push_back(0);
  }
  const wchar_t* get(uint32_t id) const
  {
    return id && id < off.size() && off[id] != 0xffffffffu ? &arena[off[id]] : nullptr;
  }
  USHORT bytes(uint32_t id) const
  {
    const wchar_t* p = get(id);
    return p ? (USHORT)(wcslen(p) * sizeof(wchar_t)) : 0;
  }
};

struct Block
{
  uint64_t offset  = 0;  // of the payload
  uint32_t size    = 0;
  uint32_t tid     = 0;
  uint64_t firstTs = 0, lastTs = 0;
  uint32_t count = 0;
};

struct CreateInfo
{
  uint64_t exit = 0, ts = 0, h = 0, h2 = 0;
  uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, str = 0;
  Op op = Op::Create;
};

struct Index
{
  FileHeader hdr{};
  StrTable strings;
  std::vector<Block> blocks;
  std::vector<CreateInfo> creates;  // sorted by return time; position = instance id
  std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, int>>> byValue;
  std::vector<CreateInfo> finds;  // successful FindFirstFileExW, sorted by return time
  std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, int>>> findByValue;
  std::vector<std::pair<uint64_t, uint32_t>> cwds;    // (ts, string id)
  std::vector<std::pair<uint64_t, uint64_t>> closes;  // (handle, ts), only for windows
  uint64_t minTs = ~0ull, maxTs = 0, records = 0;

  // A handle value is reused over the trace's lifetime: the instance of a use is
  // the latest create of that value which had returned by then.
  int lookup(uint64_t h, uint64_t at) const { return lookupIn(byValue, h, at); }
  int lookupFind(uint64_t h, uint64_t at) const { return lookupIn(findByValue, h, at); }

  using ValueMap = std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, int>>>;
  static int lookupIn(const ValueMap& byValue, uint64_t h, uint64_t at)
  {
    if (!h)
      return -1;
    auto it = byValue.find(h);
    if (it == byValue.end())
      return -1;
    const auto& v = it->second;
    auto pos      = std::upper_bound(v.begin(), v.end(), at,
                                     [](uint64_t a, const std::pair<uint64_t, int>& e) {
                                  return a < e.first;
                                     });
    return pos == v.begin() ? -1 : std::prev(pos)->second;
  }
};

bool buildIndex(TraceFile& tf, bool needCloses, Index& ix)
{
  std::vector<uint8_t> scratch;
  const uint8_t* hdr = tf.get(0, sizeof(FileHeader), scratch);
  if (!hdr) {
    logf("trace too short");
    return false;
  }
  std::memcpy(&ix.hdr, hdr, sizeof(FileHeader));
  if (std::memcmp(ix.hdr.magic, kMagic, sizeof(kMagic)) != 0 ||
      ix.hdr.version != kVersion) {
    logf("not a usvfs trace (bad magic/version)");
    return false;
  }

  uint64_t pos     = sizeof(FileHeader);
  uint64_t lastLog = qpcNow();
  while (pos + 4 <= tf.size()) {
    std::vector<uint8_t> s1, s2;
    const uint8_t* p4 = tf.get(pos, 4, s1);
    if (!p4)
      break;
    uint32_t size;
    std::memcpy(&size, p4, 4);
    if (size > tf.size() - pos - 4)
      break;  // truncated tail (process was killed)
    const uint8_t* data = tf.get(pos + 4, size, s2);
    if (!data)
      break;

    Block b;
    b.offset   = pos + 4;
    b.size     = size;
    size_t off = 0;
    bool first = true;
    while (off < size) {
      Record r;
      const size_t n = decodeRecord(data + off, size - off, r);
      if (n == 0)
        break;
      off += n;
      if (r.op == Op::StringDef) {
        ix.strings.set(r.str, r.text);
        continue;
      }
      if (first) {
        b.tid     = r.tid;
        b.firstTs = r.ts;
        first     = false;
      }
      b.lastTs = r.ts;
      ++b.count;
      ix.minTs = std::min(ix.minTs, r.ts);
      ix.maxTs = std::max(ix.maxTs, r.ts);
      if ((r.op == Op::Create || r.op == Op::Open) && (int32_t)r.status >= 0 && r.h) {
        CreateInfo c;
        c.exit = r.ts + r.dur;
        c.ts   = r.ts;
        c.h    = r.h;
        c.h2   = r.h2;
        c.a    = (uint32_t)r.a;
        c.b    = (uint32_t)r.b;
        c.c    = (uint32_t)r.c;
        c.d    = (uint32_t)r.d;
        c.e    = (uint32_t)r.e;
        c.str  = r.str;
        c.op   = r.op;
        ix.creates.push_back(c);
      } else if (r.op == Op::FindFirst && r.status == 1 && r.h) {
        CreateInfo c;
        c.exit = r.ts + r.dur;
        c.ts   = r.ts;
        c.h    = r.h;
        c.op   = r.op;
        ix.finds.push_back(c);
      } else if (r.op == Op::SetCwd) {
        ix.cwds.push_back({r.ts, r.str});
      } else if (needCloses && r.op == Op::Close) {
        ix.closes.push_back({r.h, r.ts});
      }
    }
    ix.records += b.count;
    if (b.count)
      ix.blocks.push_back(b);
    pos += 4 + size;

    if (ticksToUs(qpcNow() - lastLog) > 5e6) {
      lastLog = qpcNow();
      logf("indexing: %.0f%% of the trace, %llu records, %.0f MB peak working set",
           100.0 * (double)pos / (double)tf.size(), (unsigned long long)ix.records,
           peakWorkingSetMb());
    }
  }

  std::stable_sort(ix.creates.begin(), ix.creates.end(),
                   [](const CreateInfo& a, const CreateInfo& b) {
                     return a.exit < b.exit;
                   });
  for (size_t k = 0; k < ix.creates.size(); ++k)
    ix.byValue[ix.creates[k].h].push_back({ix.creates[k].exit, (int)k});
  std::stable_sort(ix.finds.begin(), ix.finds.end(),
                   [](const CreateInfo& a, const CreateInfo& b) {
                     return a.exit < b.exit;
                   });
  for (size_t k = 0; k < ix.finds.size(); ++k)
    ix.findByValue[ix.finds[k].h].push_back({ix.finds[k].exit, (int)k});
  std::sort(ix.cwds.begin(), ix.cwds.end());
  std::sort(ix.closes.begin(), ix.closes.end());
  if (ix.minTs == ~0ull)
    ix.minTs = 0;
  return true;
}

// ---------------------------------------------------------------------------
// replay pass

struct OpStat
{
  uint64_t count = 0, ticks = 0, diffs = 0, recCount = 0, recTicks = 0;
};

// latency histogram: 8 buckets per power of two of nanoseconds
struct Hist
{
  std::vector<uint64_t> b;
  uint64_t maxNs = 0, n = 0;
  static size_t index(uint64_t ns)
  {
    const uint64_t v   = ns ? ns : 1;
    const int lg       = (int)std::bit_width(v) - 1;
    const uint64_t sub = lg >= 3 ? (v >> (lg - 3)) & 7 : (v << (3 - lg)) & 7;
    return (size_t)lg * 8 + (size_t)sub;
  }
  static double lowerNs(size_t idx)
  {
    return std::ldexp(1.0 + (double)(idx % 8) / 8.0, (int)(idx / 8));
  }
  void add(uint64_t ns)
  {
    if (b.empty())
      b.assign(512, 0);
    ++b[index(ns)];
    ++n;
    maxNs = std::max(maxNs, ns);
  }
  void merge(const Hist& o)
  {
    if (o.b.empty())
      return;
    if (b.empty())
      b.assign(512, 0);
    for (size_t i = 0; i < 512; ++i)
      b[i] += o.b[i];
    n += o.n;
    maxNs = std::max(maxNs, o.maxNs);
  }
  double percentileNs(double p) const
  {
    if (!n)
      return 0;
    const uint64_t want = (uint64_t)std::ceil(p * (double)n);
    uint64_t acc        = 0;
    for (size_t i = 0; i < b.size(); ++i) {
      acc += b[i];
      if (acc >= want && b[i])
        return lowerNs(i) * (1.0 + 1.0 / 16.0);  // bucket middle
    }
    return (double)maxNs;
  }
};

struct ThreadStats
{
  Hist hist[kOpCount];
  uint32_t tid = 0;
  uint64_t ops = 0, busyTicks = 0, startTicks = 0, endTicks = 0;
  uint64_t skipped = 0, unmapped = 0, verifyChecked = 0, verifyMismatch = 0;
  OpStat op[kOpCount];
  std::vector<std::string> samples;
};

struct Inst
{
  std::atomic<HANDLE> live{nullptr};
  std::atomic<bool> resolved{false};
  bool sync = true;
};

bool isWriteIntent(const Record& r)
{
  constexpr uint64_t writeBits =
      0x2 /*FILE_WRITE_DATA*/ | 0x4 /*FILE_APPEND_DATA*/ | 0x10 /*FILE_WRITE_EA*/ |
      0x10000 /*DELETE*/ | 0x40000 /*WRITE_DAC*/ | 0x80000 /*WRITE_OWNER*/ |
      0x40000000 /*GENERIC_WRITE*/ | 0x10000000 /*GENERIC_ALL*/;
  if (r.a & writeBits)
    return true;
  if (r.op == Op::Create && r.c != kFileOpen)
    return true;  // as the DLL: only FILE_OPEN is a read
  if (r.d & 0x1000 /*FILE_DELETE_ON_CLOSE*/)
    return true;
  return false;
}

// the records of one recorded thread, decoded block by block, restricted to the window
class Cursor
{
public:
  Cursor(TraceFile& tf, const Index& ix, std::vector<size_t> blocks, uint64_t fromTs,
         uint64_t toTs)
      : m_tf(tf), m_ix(ix), m_blocks(std::move(blocks)), m_from(fromTs), m_to(toTs)
  {}

  const Record* peek()
  {
    while (m_ci >= m_cur.size()) {
      if (!loadNext())
        return nullptr;
    }
    return &m_cur[m_ci];
  }
  void advance() { ++m_ci; }

private:
  bool loadNext()
  {
    m_cur.clear();
    m_ci = 0;
    while (m_cur.empty()) {
      if (m_bi >= m_blocks.size())
        return false;
      const Block& b = m_ix.blocks[m_blocks[m_bi++]];
      if (b.lastTs < m_from)
        continue;
      if (b.firstTs >= m_to) {
        m_bi = m_blocks.size();
        return false;
      }
      const uint8_t* data = m_tf.get(b.offset, b.size, m_scratch);
      if (!data) {
        m_bi = m_blocks.size();
        return false;
      }
      size_t off = 0;
      while (off < b.size) {
        Record r;
        const size_t n = decodeRecord(data + off, b.size - off, r);
        if (n == 0)
          break;
        off += n;
        if (r.op == Op::StringDef || r.ts < m_from)
          continue;
        if (r.ts >= m_to) {
          m_bi = m_blocks.size();
          break;
        }
        m_cur.push_back(std::move(r));
      }
    }
    return true;
  }

  TraceFile& m_tf;
  const Index& m_ix;
  std::vector<size_t> m_blocks;
  uint64_t m_from, m_to;
  size_t m_bi = 0;
  std::vector<Record> m_cur;
  size_t m_ci = 0;
  std::vector<uint8_t> m_scratch;
};

class Pass
{
public:
  Pass(TraceFile& tf, const Index& ix, const Options& o)
      : m_tf(tf), m_ix(ix), m_o(o),
        m_insts(new Inst[std::max<size_t>(ix.creates.size(), 1)]),
        m_finds(new Inst[std::max<size_t>(ix.finds.size(), 1)])
  {
    const double f = (double)ix.hdr.qpcFreq;
    m_fromTs       = ix.minTs + (uint64_t)(o.fromSec * f);
    m_toTs         = ~0ull;
    double to      = o.toSec;
    if (o.limitSec >= 0)
      to = (to < 0) ? o.fromSec + o.limitSec : std::min(to, o.fromSec + o.limitSec);
    if (to >= 0)
      m_toTs = ix.minTs + (uint64_t)(to * f);
  }

  uint64_t fromTs() const { return m_fromTs; }
  uint64_t toTs() const { return m_toTs; }

  // planned number of ops (blocks overlapping the window; an upper bound)
  uint64_t planned() const { return m_planned; }
  uint64_t done() const
  {
    uint64_t d = 0;
    for (size_t i = 0; i < m_nProgress; ++i)
      d += m_progress[i].load(std::memory_order_relaxed);
    return d;
  }

  std::vector<ThreadStats> run(uint64_t& wallTicks)
  {
    std::map<uint32_t, std::vector<size_t>> perThread;
    for (size_t i = 0; i < m_ix.blocks.size(); ++i) {
      const Block& b = m_ix.blocks[i];
      if (b.lastTs < m_fromTs || b.firstTs >= m_toTs)
        continue;
      perThread[b.tid].push_back(i);
      m_planned += b.count;
    }
    for (auto& [tid, v] : perThread)
      std::stable_sort(v.begin(), v.end(), [&](size_t a, size_t b) {
        return m_ix.blocks[a].firstTs < m_ix.blocks[b].firstTs;
      });

    applyStartDirectory();
    if (m_fromTs > m_ix.minTs && !m_o.noFastForward)
      fastForward();
    else
      preOpen();

    std::vector<std::unique_ptr<Cursor>> cursors;
    std::vector<uint32_t> tids;
    for (auto& [tid, v] : perThread) {
      cursors.push_back(std::make_unique<Cursor>(m_tf, m_ix, v, m_fromTs, m_toTs));
      tids.push_back(tid);
    }

    const size_t nThreads = m_o.singleThread ? 1 : cursors.size();
    std::vector<ThreadStats> stats(nThreads);
    m_progress.reset(new std::atomic<uint64_t>[std::max<size_t>(nThreads, 1)]);
    m_nProgress = nThreads;
    for (size_t i = 0; i < nThreads; ++i)
      m_progress[i] = 0;

    std::latch ready((ptrdiff_t)nThreads);
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    for (size_t i = 0; i < nThreads; ++i) {
      stats[i].tid = m_o.singleThread ? 0 : tids[i];
      threads.emplace_back([&, i] {
        if (m_o.singleThread) {
          for (auto& c : cursors)
            c->peek();
        } else {
          cursors[i]->peek();  // first block decoded before the clock starts
        }
        ready.count_down();
        while (!go.load(std::memory_order_acquire))
          std::this_thread::yield();
        if (m_o.singleThread)
          runMerged(cursors, stats[i], i);
        else
          runThread(*cursors[i], stats[i], i);
      });
    }
    ready.wait();
    m_start = qpcNow();
    go.store(true, std::memory_order_release);
    for (auto& th : threads)
      th.join();
    wallTicks = qpcNow() - m_start;
    return stats;
  }

private:
  // the application's working directory at the start of the window (relative paths!)
  void applyStartDirectory()
  {
    const std::pair<uint64_t, uint32_t>* pick = nullptr;
    for (auto& c : m_ix.cwds) {
      if (!pick || c.first < m_fromTs)
        pick = &c;  // the last one before the window, else the first
    }
    const wchar_t* dir = pick ? str(pick->second) : nullptr;
    if (!dir) {
      logf("trace has no working directory record; keeping the current one");
      return;
    }
    if (::SetCurrentDirectoryW(dir))
      logf("working directory set to %s", toUtf8(dir).c_str());
    else
      logf("SetCurrentDirectoryW(%s) failed: %s", toUtf8(dir).c_str(),
           lastErrorText(::GetLastError()).c_str());
  }

  // handles that were already open when the window starts are opened up front
  void preOpen()
  {
    if (m_fromTs <= m_ix.minTs)
      return;
    ThreadStats ts;
    std::vector<uint8_t> buf(4096);
    uint64_t opened = 0, total = 0;
    for (size_t k = 0; k < m_ix.creates.size(); ++k) {
      const CreateInfo& c = m_ix.creates[k];
      if (c.ts >= m_fromTs)
        continue;  // replayed by its thread
      auto it = std::lower_bound(m_ix.closes.begin(), m_ix.closes.end(),
                                 std::make_pair(c.h, c.exit));
      if (it != m_ix.closes.end() && it->first == c.h && it->second < m_fromTs)
        continue;  // closed before
      ++total;
      Record r;
      r.op     = c.op;
      r.ts     = c.ts;
      r.dur    = c.exit - c.ts;
      r.h      = c.h;
      r.h2     = c.h2;
      r.a      = c.a;
      r.b      = c.b;
      r.c      = c.c;
      r.d      = c.d;
      r.e      = c.e;
      r.str    = c.str;
      r.status = 0;
      exec(r, buf, nullptr, ts, true);
      if (m_insts[k].live.load())
        ++opened;
    }
    logf("window starts at +%.1fs: re-opened %llu of %llu handles that were open at "
         "that point",
         (double)(m_fromTs - m_ix.minTs) / (double)m_ix.hdr.qpcFreq,
         (unsigned long long)opened, (unsigned long long)total);
  }

  // --from S without --no-ff: replay the trace's prefix (everything before S) as one
  // merged stream in timestamp order, executing only the state-building ops: opens,
  // closes, file positions, cwd. Search handles still open at S are re-created
  // (FindFirst + the recorded number of FindNext calls). Reads only with --ff-reads.
  // Nothing here is timed or counted in the results.
  void fastForward()
  {
    const uint64_t tStart = qpcNow();
    std::map<uint32_t, std::vector<size_t>> perThread;
    for (size_t i = 0; i < m_ix.blocks.size(); ++i)
      if (m_ix.blocks[i].firstTs < m_fromTs)
        perThread[m_ix.blocks[i].tid].push_back(i);
    std::vector<std::unique_ptr<Cursor>> cursors;
    for (auto& [tid, v] : perThread) {
      std::stable_sort(v.begin(), v.end(), [&](size_t a, size_t b) {
        return m_ix.blocks[a].firstTs < m_ix.blocks[b].firstTs;
      });
      cursors.push_back(std::make_unique<Cursor>(m_tf, m_ix, v, 0, m_fromTs));
    }
    auto cmp = [&](size_t a, size_t b) {
      return cursors[a]->peek()->ts > cursors[b]->peek()->ts;
    };
    std::priority_queue<size_t, std::vector<size_t>, decltype(cmp)> heap(cmp);
    for (size_t i = 0; i < cursors.size(); ++i)
      if (cursors[i]->peek())
        heap.push(i);

    struct OpenFind
    {
      Record first;
      uint64_t nexts = 0;
    };
    std::map<int, OpenFind> openFinds;
    ThreadStats scratch;  // discarded
    std::vector<uint8_t> buf(4096);
    HANDLE event   = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    uint64_t nOpen = 0, nClose = 0, nPos = 0, nCwd = 0, nRead = 0, nSkipped = 0;
    m_quiet = true;
    while (!heap.empty()) {
      const size_t i = heap.top();
      heap.pop();
      const Record& r = *cursors[i]->peek();
      switch (r.op) {
      case Op::Create:
      case Op::Open:
        if ((int32_t)r.status >= 0) {
          exec(r, buf, event, scratch, true);
          ++nOpen;
        } else
          ++nSkipped;
        break;
      case Op::Close:
        exec(r, buf, event, scratch, true);
        ++nClose;
        break;
      case Op::SetInfo:
        exec(r, buf, event, scratch, true);
        ++nPos;
        break;
      case Op::SetCwd:
        exec(r, buf, event, scratch, true);
        ++nCwd;
        break;
      case Op::Read:
        if (m_o.ffReads) {
          exec(r, buf, event, scratch, true);
          ++nRead;
        } else
          ++nSkipped;
        break;
      case Op::FindFirst: {
        const int fid = r.h ? m_ix.lookupFind(r.h, r.ts + r.dur) : -1;
        if (fid >= 0)
          openFinds[fid] = OpenFind{r, 0};
        break;
      }
      case Op::FindNext: {
        auto it = openFinds.find(m_ix.lookupFind(r.h, r.ts));
        if (it != openFinds.end())
          ++it->second.nexts;
        break;
      }
      case Op::FindClose:
        openFinds.erase(m_ix.lookupFind(r.h, r.ts));
        break;
      default:
        ++nSkipped;
        break;
      }
      cursors[i]->advance();
      if (cursors[i]->peek())
        heap.push(i);
    }
    uint64_t nFinds = 0, nNexts = 0;
    for (auto& [fid, of] : openFinds) {
      exec(of.first, buf, event, scratch, true);
      HANDLE fh = m_finds[fid].live.load();
      if (!fh)
        continue;
      ++nFinds;
      WIN32_FIND_DATAW fd;
      for (uint64_t k = 0; k < of.nexts; ++k, ++nNexts)
        if (!::FindNextFileW(fh, &fd))
          break;
    }
    m_quiet = false;
    ::CloseHandle(event);
    logf("fast-forward to +%.1fs done in %.1f ms: %llu opens, %llu closes, %llu "
         "positions, %llu cwd, %llu reads%s, "
         "%llu/%zu search handles re-created (%llu FindNext), %llu other records "
         "skipped",
         (double)(m_fromTs - m_ix.minTs) / (double)m_ix.hdr.qpcFreq,
         ticksToUs(qpcNow() - tStart) / 1000.0, (unsigned long long)nOpen,
         (unsigned long long)nClose, (unsigned long long)nPos, (unsigned long long)nCwd,
         (unsigned long long)nRead, m_o.ffReads ? "" : " (off)",
         (unsigned long long)nFinds, openFinds.size(), (unsigned long long)nNexts,
         (unsigned long long)nSkipped);
  }

  void runThread(Cursor& cur, ThreadStats& ts, size_t slot)
  {
    HANDLE event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<uint8_t> buf(4096);
    ts.startTicks = qpcNow();
    while (const Record* r = cur.peek()) {
      step(*r, buf, event, ts, slot);
      cur.advance();
    }
    ts.endTicks = qpcNow();
    ::CloseHandle(event);
  }

  // all recorded threads serially, in timestamp order
  void runMerged(std::vector<std::unique_ptr<Cursor>>& cursors, ThreadStats& ts,
                 size_t slot)
  {
    HANDLE event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<uint8_t> buf(4096);
    auto cmp = [&](size_t a, size_t b) {
      return cursors[a]->peek()->ts > cursors[b]->peek()->ts;
    };
    std::priority_queue<size_t, std::vector<size_t>, decltype(cmp)> heap(cmp);
    for (size_t i = 0; i < cursors.size(); ++i)
      if (cursors[i]->peek())
        heap.push(i);
    ts.startTicks = qpcNow();
    while (!heap.empty()) {
      const size_t i = heap.top();
      heap.pop();
      step(*cursors[i]->peek(), buf, event, ts, slot);
      cursors[i]->advance();
      if (cursors[i]->peek())
        heap.push(i);
    }
    ts.endTicks = qpcNow();
    ::CloseHandle(event);
  }

  void step(const Record& r, std::vector<uint8_t>& buf, HANDLE event, ThreadStats& ts,
            size_t slot)
  {
    if (m_o.timingOriginal)
      waitUntil(r.ts);
    OpStat& os = ts.op[(int)r.op];
    ++os.recCount;
    os.recTicks += r.dur;
    exec(r, buf, event, ts, false);
    m_progress[slot].store(ts.ops + ts.skipped + ts.unmapped,
                           std::memory_order_relaxed);
  }

  void waitUntil(uint64_t recTs)
  {
    const double scale = (double)qpcFreq() / (double)m_ix.hdr.qpcFreq;
    const uint64_t due =
        m_start + (uint64_t)((double)(recTs - std::max(m_fromTs, m_ix.minTs)) * scale);
    for (;;) {
      const uint64_t now = qpcNow();
      if (now >= due)
        return;
      const double leftMs = ticksToUs(due - now) / 1000.0;
      if (leftMs > 2.0)
        ::Sleep((DWORD)(leftMs - 1.0));
      else
        std::this_thread::yield();
    }
  }

  // live handle of an instance, waiting for the thread that opens it; null = skip
  HANDLE resolve(int id, ThreadStats& ts) { return resolveIn(m_insts.get(), id, ts); }

  HANDLE resolveIn(Inst* arr, int id, ThreadStats& ts)
  {
    if (id < 0) {
      ++ts.unmapped;
      return nullptr;
    }
    Inst& in          = arr[id];
    const uint64_t t0 = qpcNow();
    while (!in.resolved.load(std::memory_order_acquire)) {
      if (ticksToUs(qpcNow() - t0) > 30e6) {  // never opened: don't wait again
        in.resolved.store(true, std::memory_order_release);
        break;
      }
      std::this_thread::yield();
    }
    HANDLE h = in.live.load(std::memory_order_acquire);
    if (!h)
      ++ts.skipped;
    return h;
  }

  void note(ThreadStats& ts, const Record& r, NTSTATUS got, const char* what)
  {
    if (m_quiet)
      return;
    OpStat& s = ts.op[(int)r.op];
    if ((uint32_t)got != r.status) {
      ++s.diffs;
      if (m_diffSamples.fetch_add(1) <
          20) {  // the first 20 failing calls overall, with their paths
        const wchar_t* path = str(r.str);
        std::string p       = path ? toUtf8(path) : std::string();
        if (p.size() > 220)
          p.resize(220);
        char b[512];
        std::snprintf(
            b, sizeof(b),
            "%s tid %u ts +%.2fs: %s recorded 0x%08x got 0x%08x err %lu path '%s'",
            opName(r.op), r.tid, (double)(r.ts - m_ix.minTs) / (double)m_ix.hdr.qpcFreq,
            what, r.status, (uint32_t)got, ::GetLastError(), p.c_str());
        ts.samples.push_back(b);
        logf("status diff: %s", b);
      }
    }
  }

  const wchar_t* str(uint32_t id) const { return m_ix.strings.get(id); }

  static std::string toAnsi(const wchar_t* w)
  {
    const int n = ::WideCharToMultiByte(CP_ACP, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 1)
      ::WideCharToMultiByte(CP_ACP, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
  }

  struct Name
  {
    UNICODE_STRING us{};
    OBJECT_ATTRIBUTES oa{};
  };

  bool makeName(const Record& r, ThreadStats& ts, Name& n)
  {
    HANDLE root = nullptr;
    if (r.h2) {
      root = resolve(m_ix.lookup(r.h2, r.ts), ts);
      if (!root)
        return false;
    }
    const wchar_t* s = str(r.str);
    if (s) {
      n.us.Buffer        = const_cast<PWSTR>(s);
      n.us.Length        = m_ix.strings.bytes(r.str);
      n.us.MaximumLength = n.us.Length + sizeof(WCHAR);
    }
    n.oa.Length        = sizeof(n.oa);
    n.oa.RootDirectory = root;
    n.oa.ObjectName    = s ? &n.us : nullptr;
    n.oa.Attributes    = kObjCaseInsensitive;
    return true;
  }

  static void need(std::vector<uint8_t>& buf, size_t n)
  {
    if (buf.size() < n + 64)
      buf.resize(n + 64);
  }

  void exec(const Record& r, std::vector<uint8_t>& buf, HANDLE event, ThreadStats& ts,
            bool preopen)
  {
    IO_STATUS_BLOCK iosb{};
    NTSTATUS st = 0;
    uint64_t t0 = 0, t1 = 0;
    OpStat& os = ts.op[(int)r.op];
    int self   = -1;  // instance of r.h (creates: the one this call produced)
    if (r.op != Op::FindFirst && r.op != Op::FindNext && r.op != Op::FindClose && r.h)
      self = m_ix.lookup(r.h, (r.op == Op::Create || r.op == Op::Open) ? r.ts + r.dur
                                                                       : r.ts);

    switch (r.op) {
    case Op::Create:
    case Op::Open: {
      Name n;
      if (!makeName(r, ts, n) || (!m_o.allowWrites && isWriteIntent(r))) {
        ++ts.skipped;
        if (self >= 0)
          m_insts[self].resolved.store(true, std::memory_order_release);
        return;
      }
      HANDLE h = nullptr;
      t0       = qpcNow();
      if (r.op == Op::Create)
        st = NtCreateFile(&h, (ACCESS_MASK)r.a, &n.oa, &iosb, nullptr, (ULONG)r.e,
                          (ULONG)r.b, (ULONG)r.c, (ULONG)r.d, nullptr, 0);
      else
        st = NtOpenFile(&h, (ACCESS_MASK)r.a, &n.oa, &iosb, (ULONG)r.b, (ULONG)r.d);
      t1 = qpcNow();
      if (self >= 0) {
        Inst& in = m_insts[self];
        if (st >= 0) {
          in.sync = (r.d & 0x30) != 0;
          in.live.store(h, std::memory_order_release);
        }
        in.resolved.store(true, std::memory_order_release);
      } else if (st >= 0 && h) {
        NtClose(h);  // succeeded now, failed when recorded
      }
      if (!preopen)
        note(ts, r, st, "path");
      break;
    }
    case Op::Read: {
      HANDLE h = resolve(self, ts);
      if (!h)
        return;
      need(buf, r.a);
      LARGE_INTEGER off;
      off.QuadPart    = r.off;
      const bool sync = m_insts[self].sync;
      if (!sync)
        ::ResetEvent(event);
      t0 = qpcNow();
      st = NtReadFile(h, sync ? nullptr : event, nullptr, nullptr, &iosb, buf.data(),
                      (ULONG)r.a, r.b ? &off : nullptr, nullptr);
      if (st == kStatusPending) {
        ::WaitForSingleObject(event, INFINITE);
        st = iosb.Status;
      }
      t1 = qpcNow();
      note(ts, r, st, "read");
      if (m_o.verify && r.hasCrc && st >= 0) {
        ++ts.verifyChecked;
        const uint32_t crc = crc32Update(0, buf.data(), iosb.Information);
        if (crc != r.crc || iosb.Information != r.info) {
          ++ts.verifyMismatch;
          if (m_verifySamples.fetch_add(1) < 20) {
            char b[200];
            std::snprintf(b, sizeof(b),
                          "verify tid %u ts +%.2fs: len %llu off %lld recorded crc "
                          "%08x/%llu got %08x/%llu",
                          r.tid, (double)(r.ts - m_ix.minTs) / (double)m_ix.hdr.qpcFreq,
                          (unsigned long long)r.a, (long long)r.off, r.crc,
                          (unsigned long long)r.info, crc,
                          (unsigned long long)iosb.Information);
            ts.samples.push_back(b);
          }
        }
      }
      break;
    }
    case Op::QueryInfo: {
      HANDLE h = resolve(self, ts);
      if (!h)
        return;
      need(buf, r.b);
      t0 = qpcNow();
      st = NtQueryInformationFile(h, &iosb, buf.data(), (ULONG)r.b,
                                  (FILE_INFORMATION_CLASS)r.a);
      t1 = qpcNow();
      note(ts, r, st, "queryinfo");
      break;
    }
    case Op::SetInfo: {
      // only the file position; renames/deletes/etc. must not touch the data
      if ((FILE_INFORMATION_CLASS)r.a != FilePositionInformation) {
        ++ts.skipped;
        return;
      }
      HANDLE h = resolve(self, ts);
      if (!h)
        return;
      FILE_POSITION_INFORMATION pi;
      pi.CurrentByteOffset.QuadPart = r.off;
      t0                            = qpcNow();
      st = NtSetInformationFile(h, &iosb, &pi, sizeof(pi), FilePositionInformation);
      t1 = qpcNow();
      note(ts, r, st, "setpos");
      break;
    }
    case Op::QueryDir:
    case Op::QueryDirEx: {
      HANDLE h = resolve(self, ts);
      if (!h)
        return;
      need(buf, r.b);
      UNICODE_STRING mask{};
      PUNICODE_STRING pm = nullptr;
      if (const wchar_t* m = str(r.str)) {
        mask.Buffer        = const_cast<PWSTR>(m);
        mask.Length        = m_ix.strings.bytes(r.str);
        mask.MaximumLength = mask.Length + sizeof(WCHAR);
        pm                 = &mask;
      }
      t0 = qpcNow();
      if (r.op == Op::QueryDir)
        st = NtQueryDirectoryFile(h, nullptr, nullptr, nullptr, &iosb, buf.data(),
                                  (ULONG)r.b, (FILE_INFORMATION_CLASS)r.a,
                                  (r.c & 2) != 0, pm, (r.c & 1) != 0);
      else
        st = NtQueryDirectoryFileEx(h, nullptr, nullptr, nullptr, &iosb, buf.data(),
                                    (ULONG)r.b, (FILE_INFORMATION_CLASS)r.a, (ULONG)r.c,
                                    pm);
      t1 = qpcNow();
      note(ts, r, st, "querydir");
      break;
    }
    case Op::QueryAttr:
    case Op::QueryFullAttr: {
      Name n;
      if (!makeName(r, ts, n)) {
        ++ts.skipped;
        return;
      }
      FILE_BASIC_INFORMATION bi;
      FILE_NETWORK_OPEN_INFORMATION ni;
      t0 = qpcNow();
      st = r.op == Op::QueryAttr ? NtQueryAttributesFile(&n.oa, &bi)
                                 : NtQueryFullAttributesFile(&n.oa, &ni);
      t1 = qpcNow();
      note(ts, r, st, "attr");
      break;
    }
    case Op::Close: {
      HANDLE h = resolve(self, ts);
      if (!h)
        return;
      t0 = qpcNow();
      st = NtClose(h);
      t1 = qpcNow();
      m_insts[self].live.store(nullptr, std::memory_order_release);
      note(ts, r, st, "close");
      break;
    }
    case Op::GetAttr:
    case Op::GetAttrEx:
    case Op::FindFirst: {
      const wchar_t* path = str(r.str);
      if (!path) {
        ++ts.skipped;
        return;
      }
      if (r.op == Op::GetAttr) {
        t0 = qpcNow();
        st = (NTSTATUS)::GetFileAttributesW(path);
        t1 = qpcNow();
        note(ts, r, st, "getattr");
      } else if (r.op == Op::GetAttrEx) {
        WIN32_FILE_ATTRIBUTE_DATA d;
        t0            = qpcNow();
        const BOOL ok = ::GetFileAttributesExW(path, (GET_FILEEX_INFO_LEVELS)r.a, &d);
        t1            = qpcNow();
        note(ts, r, ok ? 1 : 0, "getattrex");
      } else {
        // only the FindFirst itself: the app's FindNext/FindClose calls are separate
        // records
        const int fid = r.h ? m_ix.lookupFind(r.h, r.ts + r.dur) : -1;
        WIN32_FIND_DATAW fd;
        t0        = qpcNow();
        HANDLE fh = ::FindFirstFileExW(path, (FINDEX_INFO_LEVELS)r.a, &fd,
                                       (FINDEX_SEARCH_OPS)r.b, nullptr, (DWORD)r.c);
        t1        = qpcNow();
        if (fid >= 0) {
          if (fh != INVALID_HANDLE_VALUE)
            m_finds[fid].live.store(fh, std::memory_order_release);
          m_finds[fid].resolved.store(true, std::memory_order_release);
        } else if (fh != INVALID_HANDLE_VALUE) {
          ::FindClose(fh);
        }
        note(ts, r, fh != INVALID_HANDLE_VALUE ? 1 : 0, "findfirst");
      }
      break;
    }
    case Op::ProfString:
    case Op::ProfSection: {
      const wchar_t* file = str(r.str);
      const wchar_t* app  = str((uint32_t)r.a);
      const wchar_t* key  = str((uint32_t)r.b);
      if (!file) {
        ++ts.skipped;
        return;
      }
      const DWORD n = (DWORD)r.c;
      need(buf, (size_t)n * sizeof(wchar_t) + 16);
      DWORD got;
      if (r.d) {  // the app called the ANSI function
        const std::string f = toAnsi(file), a = app ? toAnsi(app) : std::string(),
                          k = key ? toAnsi(key) : std::string();
        t0                  = qpcNow();
        got = r.op == Op::ProfString
                  ? ::GetPrivateProfileStringA(app ? a.c_str() : nullptr,
                                               key ? k.c_str() : nullptr, "",
                                               (char*)buf.data(), n, f.c_str())
                  : ::GetPrivateProfileSectionA(app ? a.c_str() : nullptr,
                                                (char*)buf.data(), n, f.c_str());
      } else {
        t0  = qpcNow();
        got = r.op == Op::ProfString
                  ? ::GetPrivateProfileStringW(app, key, L"", (wchar_t*)buf.data(), n,
                                               file)
                  : ::GetPrivateProfileSectionW(app, (wchar_t*)buf.data(), n, file);
      }
      t1 = qpcNow();
      note(ts, r, (NTSTATUS)got, "profile");
      break;
    }
    case Op::FindNext:
    case Op::FindClose: {
      const int fid = m_ix.lookupFind(r.h, r.ts);
      HANDLE fh     = resolveIn(m_finds.get(), fid, ts);
      if (!fh)
        return;
      BOOL ok;
      if (r.op == Op::FindNext) {
        WIN32_FIND_DATAW fd;
        t0 = qpcNow();
        ok = ::FindNextFileW(fh, &fd);
        t1 = qpcNow();
      } else {
        t0 = qpcNow();
        ok = ::FindClose(fh);
        t1 = qpcNow();
        m_finds[fid].live.store(nullptr, std::memory_order_release);
      }
      note(ts, r, ok ? 1 : 0, r.op == Op::FindNext ? "findnext" : "findclose");
      break;
    }
    case Op::SetCwd: {
      const wchar_t* dir = str(r.str);
      if (!dir) {
        ++ts.skipped;
        return;
      }
      t0            = qpcNow();
      const BOOL ok = ::SetCurrentDirectoryW(dir);
      t1            = qpcNow();
      note(ts, r, ok ? 1 : 0, "setcwd");
      break;
    }
    case Op::WriteMarker:
      ++ts.skipped;  // writes are never replayed
      return;
    default:
      return;
    }
    if (preopen)
      return;
    ++ts.ops;
    ++os.count;
    os.ticks += t1 - t0;
    ts.hist[(int)r.op].add((uint64_t)((double)(t1 - t0) * 1e9 / (double)qpcFreq()));
    ts.busyTicks += t1 - t0;
  }

  TraceFile& m_tf;
  const Index& m_ix;
  const Options& m_o;
  std::unique_ptr<Inst[]> m_insts;
  std::unique_ptr<Inst[]> m_finds;
  std::atomic<int> m_diffSamples{0}, m_verifySamples{0};
  std::unique_ptr<std::atomic<uint64_t>[]> m_progress;
  size_t m_nProgress = 0;
  uint64_t m_fromTs = 0, m_toTs = ~0ull, m_start = 0, m_planned = 0;
  bool m_quiet = false;  // fast-forward prefix: no status-diff accounting
};

// child: one pass, results as simple "key value" lines for the parent
int runChild(const Options& o)
{
  g_role    = "child";
  g_logPath = o.logPath;
  logf("child start: trace %s, timing %s%s%s", toUtf8(o.tracePath).c_str(),
       o.timingOriginal ? "original" : "asap", o.verify ? ", verify" : "",
       o.singleThread ? ", single-thread" : "");
  for (const char* v :
       {"USVFS_READCACHE", "USVFS_READCACHE_ASYNC", "USVFS_READCACHE_SPLIT",
        "USVFS_READCACHE_RA", "USVFS_METACACHE"}) {
    char b[64];
    const DWORD n = ::GetEnvironmentVariableA(v, b, sizeof(b));
    logf("  env %s=%s", v, n && n < sizeof(b) ? b : "(unset)");
  }

  TraceFile tf;
  if (!tf.open(o.tracePath))
    return 2;
  const bool windowed =
      o.fromSec > 0 && o.noFastForward;  // closes index is only for the --no-ff re-open
  Index ix;
  logf("indexing %.0f MB trace ...", (double)tf.size() / 1048576.0);
  if (!buildIndex(tf, windowed, ix))
    return 2;
  if (ix.records == 0) {
    logf("trace holds no records");
    return 2;
  }
  logf("indexed: %llu records in %zu blocks, %zu successful opens, %.1f s of trace, "
       "%.0f MB peak working set",
       (unsigned long long)ix.records, ix.blocks.size(), ix.creates.size(),
       (double)(ix.maxTs - ix.minTs) / (double)ix.hdr.qpcFreq, peakWorkingSetMb());

  Pass pass(tf, ix, o);
  std::atomic<bool> stopMonitor{false};
  uint64_t wall     = 0;
  const uint64_t t0 = qpcNow();
  std::thread monitor([&] {
    uint64_t last = qpcNow();
    while (!stopMonitor.load()) {
      ::Sleep(200);
      if (ticksToUs(qpcNow() - last) < 5e6)
        continue;
      last = qpcNow();
      logf("progress: %llu of ~%llu ops, %.0f s elapsed, %.0f MB peak working set",
           (unsigned long long)pass.done(), (unsigned long long)pass.planned(),
           ticksToUs(qpcNow() - t0) / 1e6, peakWorkingSetMb());
    }
  });
  std::vector<ThreadStats> stats = pass.run(wall);
  Hist hist[kOpCount];
  for (auto& s : stats)
    for (int i = 0; i < kOpCount; ++i)
      hist[i].merge(s.hist[i]);
  stopMonitor = true;
  monitor.join();

  OpStat total[kOpCount];
  uint64_t skipped = 0, unmapped = 0, vc = 0, vm = 0;
  for (auto& s : stats) {
    skipped += s.skipped;
    unmapped += s.unmapped;
    vc += s.verifyChecked;
    vm += s.verifyMismatch;
    for (int i = 0; i < kOpCount; ++i) {
      total[i].count += s.op[i].count;
      total[i].ticks += s.op[i].ticks;
      total[i].diffs += s.op[i].diffs;
      total[i].recCount += s.op[i].recCount;
      total[i].recTicks += s.op[i].recTicks;
    }
  }
  const double recScale = 1e6 / (double)ix.hdr.qpcFreq;

  std::ofstream f(o.childResult, std::ios::binary | std::ios::trunc);
  if (!f) {
    logf("cannot write result file %s", toUtf8(o.childResult).c_str());
    return 3;
  }
  f << "wall_us " << (uint64_t)ticksToUs(wall) << "\n";
  f << "recorded_ops " << pass.planned() << "\n";
  f << "skipped " << skipped << "\n";
  f << "unmapped " << unmapped << "\n";
  f << "verify_checked " << vc << "\n";
  f << "verify_mismatches " << vm << "\n";
  f << "peak_ws_mb " << (uint64_t)peakWorkingSetMb() << "\n";
  uint64_t diffs = 0;
  for (int i = 2; i < kOpCount; ++i) {
    diffs += total[i].diffs;
    f << "op " << opName((Op)i) << " " << total[i].count << " "
      << (uint64_t)ticksToUs(total[i].ticks) << " " << total[i].diffs << " "
      << total[i].recCount << " " << (uint64_t)((double)total[i].recTicks * recScale)
      << "\n";
  }
  f << "status_diffs " << diffs << "\n";
  for (int i = 2; i < kOpCount; ++i)
    if (hist[i].n)
      f << "hist " << opName((Op)i) << " " << (uint64_t)hist[i].percentileNs(0.5) << " "
        << (uint64_t)hist[i].percentileNs(0.95) << " " << hist[i].maxNs << "\n";
  for (auto& s : stats)
    f << "thread " << s.tid << " " << s.ops << " " << (uint64_t)ticksToUs(s.busyTicks)
      << " " << (uint64_t)ticksToUs(s.endTicks - s.startTicks) << "\n";
  for (auto& s : stats)
    for (auto& x : s.samples)
      f << "sample " << x << "\n";
  logf("child done: wall %.1f ms, skipped %llu, unmapped %llu, status diffs %llu, "
       "verify mismatches %llu, %.0f MB peak working set",
       ticksToUs(wall) / 1000.0, (unsigned long long)skipped,
       (unsigned long long)unmapped, (unsigned long long)diffs, (unsigned long long)vm,
       peakWorkingSetMb());
  return 0;
}

// ---------------------------------------------------------------------------
// parent (never touches the trace)

struct OpResult
{
  std::string name;
  uint64_t count = 0, us = 0, diffs = 0, recCount = 0, recUs = 0;
};
struct HistResult
{
  uint64_t p50 = 0, p95 = 0, max = 0;
};
struct ThreadResult
{
  uint64_t tid = 0, ops = 0, busyUs = 0, spanUs = 0;
};

struct Result
{
  Config cfg;
  DWORD exitCode   = 0;
  double processMs = 0;
  std::map<std::string, uint64_t> scalars;
  std::vector<OpResult> ops;
  std::vector<ThreadResult> threads;
  std::map<std::string, HistResult> hists;
  std::vector<std::string> samples;
  uint64_t sc(const char* k) const
  {
    auto it = scalars.find(k);
    return it == scalars.end() ? 0 : it->second;
  }
};

void parseResult(const std::wstring& path, Result& r)
{
  std::ifstream f(path, std::ios::binary);
  std::string line;
  while (std::getline(f, line)) {
    std::istringstream ss(line);
    std::string key;
    ss >> key;
    if (key == "op") {
      OpResult o;
      ss >> o.name >> o.count >> o.us >> o.diffs >> o.recCount >> o.recUs;
      r.ops.push_back(o);
    } else if (key == "hist") {
      std::string name;
      HistResult h;
      ss >> name >> h.p50 >> h.p95 >> h.max;
      r.hists[name] = h;
    } else if (key == "thread") {
      ThreadResult t;
      ss >> t.tid >> t.ops >> t.busyUs >> t.spanUs;
      r.threads.push_back(t);
    } else if (key == "sample") {
      r.samples.push_back(line.size() > 7 ? line.substr(7) : "");
    } else {
      uint64_t v = 0;
      ss >> v;
      r.scalars[key] = v;
    }
  }
}

std::wstring quote(const std::wstring& s)
{
  return L"\"" + s + L"\"";
}

std::wstring selfPath()
{
  wchar_t buf[MAX_PATH * 4];
  DWORD n = ::GetModuleFileNameW(nullptr, buf, (DWORD)std::size(buf));
  return std::wstring(buf, n);
}

bool startsWithNoCase(const std::wstring& s, const wchar_t* prefix)
{
  return _wcsnicmp(s.c_str(), prefix, wcslen(prefix)) == 0;
}

// Applies a config's env overrides to OUR OWN environment for the duration of a spawn
// (and, unless inherit, removes inherited USVFS_* vars), restoring everything
// afterwards. The child then inherits it with a NULL lpEnvironment and no
// CREATE_UNICODE_ENVIRONMENT: stock usvfs 0.5.6.1 reportedly fails (87) a spawn that
// passes an explicit environment block (suspected; unverified), our fork does not care.
struct EnvScope
{
  std::vector<std::pair<std::wstring, std::wstring>>
      saved;  // name -> old value (empty+!had = was unset)
  std::vector<bool> had;
  void set(const std::wstring& name, const wchar_t* value)
  {
    wchar_t probe[2];
    const DWORD n = ::GetEnvironmentVariableW(name.c_str(), probe, 2);
    std::wstring old;
    bool exists = n != 0 || ::GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    if (exists) {
      std::vector<wchar_t> buf(32768);
      const DWORD m =
          ::GetEnvironmentVariableW(name.c_str(), buf.data(), (DWORD)buf.size());
      old.assign(buf.data(), m < buf.size() ? m : 0);
    }
    saved.emplace_back(name, old);
    had.push_back(exists);
    ::SetEnvironmentVariableW(name.c_str(), value);
  }
  ~EnvScope()
  {
    for (size_t i = saved.size(); i-- > 0;)
      ::SetEnvironmentVariableW(saved[i].first.c_str(),
                                had[i] ? saved[i].second.c_str() : nullptr);
  }
};

void applyEnv(EnvScope& scope, const Config& c, bool inherit)
{
  if (!inherit) {
    std::vector<std::wstring> names;
    wchar_t* block = ::GetEnvironmentStringsW();
    for (const wchar_t* p = block; *p; p += wcslen(p) + 1) {
      std::wstring e  = p;
      const size_t eq = e.find(L'=', 1);  // entries like "=C:=C:\" start with '='
      const std::wstring name = e.substr(0, eq);
      if (startsWithNoCase(name, L"USVFS_"))
        names.push_back(name);
    }
    ::FreeEnvironmentStringsW(block);
    for (auto& n : names)
      scope.set(n, nullptr);
  }
  for (auto& kv : c.env)
    scope.set(kv.first, kv.second.c_str());
}

// ---------------------------------------------------------------------------
// --vfs: build our own usvfs instance (as MO2 does) from a USVFS_MAPPING_DUMP manifest
// and spawn the children through usvfsCreateProcessHooked, so replay does not need to
// be started inside MO2's VFS.

struct VfsApi
{
  HMODULE dll                                                        = nullptr;
  bool ready                                                         = false;
  void*(WINAPI* createParameters)()                                  = nullptr;
  void(WINAPI* freeParameters)(void*)                                = nullptr;
  void(WINAPI* setInstanceName)(void*, const char*)                  = nullptr;
  void(WINAPI* setDebugMode)(void*, BOOL)                            = nullptr;
  void(WINAPI* setLogLevel)(void*, int)                              = nullptr;
  void(WINAPI* setCrashDumpType)(void*, int)                         = nullptr;
  void(WINAPI* setCrashDumpPath)(void*, const char*)                 = nullptr;
  void(WINAPI* setProcessDelay)(void*, int)                          = nullptr;
  void(WINAPI* initLogging)(bool)                                    = nullptr;
  BOOL(WINAPI* createVFS)(const void*)                               = nullptr;
  void(WINAPI* disconnectVFS)()                                      = nullptr;
  void(WINAPI* clearMappings)()                                      = nullptr;
  BOOL(WINAPI* linkFile)(LPCWSTR, LPCWSTR, unsigned)                 = nullptr;
  BOOL(WINAPI* linkDir)(LPCWSTR, LPCWSTR, unsigned)                  = nullptr;
  void(WINAPI* blacklist)(LPWSTR)                                    = nullptr;
  void(WINAPI* skipSuffix)(LPWSTR)                                   = nullptr;
  void(WINAPI* skipDir)(LPWSTR)                                      = nullptr;
  void(WINAPI* forceLoad)(LPWSTR, LPWSTR)                            = nullptr;
  BOOL(WINAPI* createProcess)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                              LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                              LPSTARTUPINFOW, LPPROCESS_INFORMATION) = nullptr;
  bool(WINAPI* getLogMessages)(LPSTR, size_t, bool)                  = nullptr;
  const char*(WINAPI* version)()                                     = nullptr;
};
VfsApi g_vfs;
std::atomic<bool> g_vfsLogStop{false};
std::thread g_vfsLogThread;

std::wstring fromUtf8(const std::string& s)
{
  if (s.empty())
    return {};
  const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w((size_t)n, L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
  return w;
}

std::vector<std::string> splitManifestLine(const std::string& line)
{
  std::vector<std::string> f(1);
  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (c == '\t')
      f.emplace_back();
    else if (c == '\\' && i + 1 < line.size()) {
      const char d = line[++i];
      f.back() += d == 't' ? '\t' : d == 'n' ? '\n' : d == 'r' ? '\r' : d;
    } else
      f.back() += c;
  }
  return f;
}

bool fileExists(const std::wstring& p)
{
  return ::GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool setupVfs(const Options& o)
{
  // DLL: --usvfs-dll, else next to replay.exe, else the MO2 install used by the harness
  std::vector<std::wstring> cands;
  if (!o.usvfsDll.empty())
    cands.push_back(o.usvfsDll);
  else {
    std::wstring self = selfPath();
    const size_t sl   = self.find_last_of(L"\\/");
    cands.push_back(
        (sl == std::wstring::npos ? std::wstring() : self.substr(0, sl + 1)) +
        L"usvfs_x64.dll");
    cands.push_back(L"Z:\\mnt\\gaming\\modlists\\LoreRim\\usvfs_x64.dll");
  }
  std::wstring dllPath;
  for (auto& c : cands)
    if (fileExists(c)) {
      dllPath = c;
      break;
    }
  if (dllPath.empty()) {
    logf("--vfs: usvfs_x64.dll not found (tried %zu location(s); use --usvfs-dll)",
         cands.size());
    return false;
  }
  g_vfs.dll = ::LoadLibraryW(dllPath.c_str());
  if (!g_vfs.dll) {
    logf("--vfs: LoadLibrary(%s) failed: %s", toUtf8(dllPath).c_str(),
         lastErrorText(::GetLastError()).c_str());
    return false;
  }
  bool ok  = true;
  auto sym = [&](auto& fn, const char* name) {
    fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(
        ::GetProcAddress(g_vfs.dll, name));
    if (!fn) {
      logf("--vfs: export %s missing", name);
      ok = false;
    }
  };
  sym(g_vfs.createParameters, "usvfsCreateParameters");
  sym(g_vfs.freeParameters, "usvfsFreeParameters");
  sym(g_vfs.setInstanceName, "usvfsSetInstanceName");
  sym(g_vfs.setDebugMode, "usvfsSetDebugMode");
  sym(g_vfs.setLogLevel, "usvfsSetLogLevel");
  sym(g_vfs.setCrashDumpType, "usvfsSetCrashDumpType");
  sym(g_vfs.setCrashDumpPath, "usvfsSetCrashDumpPath");
  sym(g_vfs.setProcessDelay, "usvfsSetProcessDelay");
  sym(g_vfs.initLogging, "usvfsInitLogging");
  sym(g_vfs.createVFS, "usvfsCreateVFS");
  sym(g_vfs.disconnectVFS, "usvfsDisconnectVFS");
  sym(g_vfs.clearMappings, "usvfsClearVirtualMappings");
  sym(g_vfs.linkFile, "usvfsVirtualLinkFile");
  sym(g_vfs.linkDir, "usvfsVirtualLinkDirectoryStatic");
  sym(g_vfs.blacklist, "usvfsBlacklistExecutable");
  sym(g_vfs.skipSuffix, "usvfsAddSkipFileSuffix");
  sym(g_vfs.skipDir, "usvfsAddSkipDirectory");
  sym(g_vfs.forceLoad, "usvfsForceLoadLibrary");
  sym(g_vfs.createProcess, "usvfsCreateProcessHooked");
  sym(g_vfs.getLogMessages, "usvfsGetLogMessages");
  sym(g_vfs.version, "usvfsVersionString");
  if (!ok)
    return false;
  logf("--vfs: loaded %s (usvfs %s)", toUtf8(dllPath).c_str(), g_vfs.version());

  std::ifstream f(o.vfsPath, std::ios::binary);
  if (!f) {
    logf("--vfs: cannot read manifest %s", toUtf8(o.vfsPath).c_str());
    return false;
  }
  std::string line;
  std::vector<std::vector<std::string>> rows;
  bool header = false;
  while (std::getline(f, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty())
      continue;
    auto fld = splitManifestLine(line);
    if (!header) {
      if (fld[0] != "USVFSMAP" || fld.size() < 2 || fld[1] != "1") {
        logf("--vfs: %s is not a version 1 manifest", toUtf8(o.vfsPath).c_str());
        return false;
      }
      header = true;
      continue;
    }
    rows.push_back(std::move(fld));
  }
  if (!header) {
    logf("--vfs: manifest is empty");
    return false;
  }

  // PARAMS (last wins)
  std::string inst = "replay", dumpPath;
  bool debug       = false;
  int logLevel = 1, dumpType = 0, delayMs = 0;
  for (auto& r : rows)
    if (r[0] == "PARAMS" && r.size() >= 7) {
      inst     = r[1];
      debug    = r[2] == "1";
      logLevel = atoi(r[3].c_str());
      dumpType = atoi(r[4].c_str());
      dumpPath = r[5];
      delayMs  = atoi(r[6].c_str());
    }
  if (!o.instanceName.empty())
    inst = toUtf8(o.instanceName);
  else
    inst += "_replay";  // never collide with a live MO2 instance of the captured name
  if (inst.size() > 60)
    inst.resize(60);
  logf("--vfs: instance '%s', debug %d, log level %d, dump type %d, delay %d ms, %zu "
       "manifest entries",
       inst.c_str(), (int)debug, logLevel, dumpType, delayMs, rows.size());

  g_vfs.initLogging(false);
  void* p = g_vfs.createParameters();
  g_vfs.setInstanceName(p, inst.c_str());
  g_vfs.setDebugMode(p, debug);
  g_vfs.setLogLevel(p, logLevel);
  g_vfs.setCrashDumpType(p, dumpType);
  g_vfs.setCrashDumpPath(p, dumpPath.c_str());
  g_vfs.setProcessDelay(p, delayMs);
  if (!g_vfs.createVFS(p)) {
    logf("--vfs: usvfsCreateVFS failed");
    g_vfs.freeParameters(p);
    return false;
  }
  g_vfs.freeParameters(p);
  g_vfs.ready = true;

  // drain the usvfs shared-memory log (injected children log into it) to
  // <out>.usvfs.log
  const std::wstring usvfsLog = o.outPath + L".usvfs.log";
  g_vfsLogThread              = std::thread([usvfsLog] {
    std::ofstream lf(usvfsLog, std::ios::binary | std::ios::trunc);
    std::vector<char> buf(8192);
    while (true) {
      bool got = false;
      while (g_vfs.getLogMessages(buf.data(), buf.size(), false)) {
        lf << buf.data() << "\n";
        got = true;
      }
      if (got)
        lf.flush();
      if (g_vfsLogStop.load())
        break;
      ::Sleep(100);
    }
  });

  // mapping calls in manifest order (skip suffixes / dirs / blacklist precede the links
  // as in MO2)
  size_t links = 0, failed = 0;
  const uint64_t t0 = qpcNow();
  auto wbuf         = [](const std::string& s) {
    std::wstring w = fromUtf8(s);
    w.push_back(L'\0');
    return w;
  };
  for (auto& r : rows) {
    const std::string& t = r[0];
    if (t == "BLACKLIST" && r.size() >= 2) {
      auto w = wbuf(r[1]);
      g_vfs.blacklist(w.data());
    } else if (t == "SKIPSUFFIX" && r.size() >= 2) {
      auto w = wbuf(r[1]);
      g_vfs.skipSuffix(w.data());
    } else if (t == "SKIPDIR" && r.size() >= 2) {
      auto w = wbuf(r[1]);
      g_vfs.skipDir(w.data());
    } else if (t == "FORCELOAD" && r.size() >= 3) {
      auto a = wbuf(r[1]);
      auto b = wbuf(r[2]);
      g_vfs.forceLoad(a.data(), b.data());
    }
  }
  for (auto& r : rows) {
    if ((r[0] == "LINKFILE" || r[0] == "LINKDIR") && r.size() >= 4) {
      const std::wstring src = fromUtf8(r[1]), dst = fromUtf8(r[2]);
      const unsigned flags = (unsigned)strtoul(r[3].c_str(), nullptr, 10);
      const BOOL ok        = r[0] == "LINKFILE"
                                 ? g_vfs.linkFile(src.c_str(), dst.c_str(), flags)
                                 : g_vfs.linkDir(src.c_str(), dst.c_str(), flags);
      ++links;
      if (!ok && ++failed <= 20)
        logf("--vfs: %s failed (error %lu): %s -> %s", r[0].c_str(), ::GetLastError(),
             r[1].c_str(), r[2].c_str());
    }
  }
  logf("--vfs: %zu link call(s) issued (%zu failed) in %.1f s", links, failed,
       ticksToUs(qpcNow() - t0) / 1e6);
  return true;
}

void teardownVfs()
{
  if (g_vfsLogThread.joinable()) {
    g_vfsLogStop = true;
    g_vfsLogThread.join();
  }
  if (g_vfs.ready)
    g_vfs.disconnectVFS();
}

bool runConfig(const Options& o, const Config& c, size_t index, Result& res)
{
  res.cfg = c;
  const std::wstring resultFile =
      o.outPath + L".cfg" + std::to_wstring(index) + L".tmp";
  ::DeleteFileW(resultFile.c_str());
  wchar_t num[32];
  std::swprintf(num, 32, L"%g", o.fromSec);
  std::wstring cmd = quote(selfPath()) + L" " + quote(o.tracePath) + L" --child " +
                     quote(resultFile) + L" --log " + quote(o.logPath) + L" --timing " +
                     (o.timingOriginal ? L"original" : L"asap") + L" --from " + num;
  if (o.toSec >= 0) {
    std::swprintf(num, 32, L"%g", o.toSec);
    cmd += std::wstring(L" --to ") + num;
  }
  if (o.limitSec >= 0) {
    std::swprintf(num, 32, L"%g", o.limitSec);
    cmd += std::wstring(L" --limit-seconds ") + num;
  }
  if (o.verify)
    cmd += L" --verify";
  if (o.singleThread)
    cmd += L" --single-thread";
  if (o.allowWrites)
    cmd += L" --allow-writes";
  if (o.noFastForward)
    cmd += L" --no-ff";
  if (o.ffReads)
    cmd += L" --ff-reads";

  EnvScope envScope;
  applyEnv(envScope, c, o.inheritEnv);
  logf("config '%s': spawning child, command line %zu chars, environment: parent's "
       "own, adjusted in place "
       "(%zu overrides%s; spawn mode: NULL lpEnvironment, flags 0)",
       c.name.c_str(), cmd.size(), c.env.size(),
       o.inheritEnv ? "" : ", inherited USVFS_* stripped");
  for (auto& kv : c.env)
    logf("  %s=%s", toUtf8(kv.first).c_str(), toUtf8(kv.second).c_str());

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  const uint64_t t0 = qpcNow();
  bool started      = false;
  for (int attempt = 1; attempt <= 3 && !started; ++attempt) {
    // normal CreateProcessW: the usvfs hooks inject the child (or, with --vfs, our own
    // VFS instance does)
    if (g_vfs.ready)
      started = g_vfs.createProcess(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                                    nullptr, nullptr, &si, &pi) != 0;
    else
      started = ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                                 nullptr, nullptr, &si, &pi) != 0;
    if (!started) {
      logf("CreateProcessW failed (attempt %d): %s; working set peak %.0f MB%s",
           attempt, lastErrorText(::GetLastError()).c_str(), peakWorkingSetMb(),
           g_vfs.ready ? " (with --vfs, 87 can also be a failed injection: see "
                         "<out>.usvfs.log; stock usvfs looks up "
                         "usvfs_x64.dll [+ usvfs_proxy_x86.exe] next to the DLL it was "
                         "loaded from)"
                       : "");
      if (attempt < 3)
        ::Sleep(3000);
    }
  }
  if (!started) {
    res.exitCode = 0xFFFFFFFF;
    return false;
  }
  ::WaitForSingleObject(pi.hProcess, INFINITE);
  ::GetExitCodeProcess(pi.hProcess, &res.exitCode);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  res.processMs = ticksToUs(qpcNow() - t0) / 1000.0;
  logf("config '%s': child exited with code 0x%08lx after %.1f s", c.name.c_str(),
       res.exitCode, res.processMs / 1000.0);
  if (res.exitCode == 0)
    parseResult(resultFile, res);
  else
    logf("config '%s': no results (child crashed or failed; see the child lines above)",
         c.name.c_str());
  ::DeleteFileW(resultFile.c_str());
  return res.exitCode == 0;
}

std::string jsonEscape(const std::string& s)
{
  std::string o;
  for (unsigned char ch : s) {
    if (ch == '"' || ch == '\\') {
      o += '\\';
      o += (char)ch;
    } else if (ch < 0x20) {
      char b[8];
      std::snprintf(b, sizeof(b), "\\u%04x", ch);
      o += b;
    } else
      o += (char)ch;
  }
  return o;
}

std::string writeJson(const Options& o, const std::vector<Result>& results)
{
  std::ostringstream j;
  j << "{\n  \"trace\": \"" << jsonEscape(toUtf8(o.tracePath))
    << "\",\n  \"timing\": \"" << (o.timingOriginal ? "original" : "asap")
    << "\",\n  \"verify\": " << (o.verify ? "true" : "false")
    << ",\n  \"from_s\": " << o.fromSec << ",\n  \"to_s\": " << o.toSec
    << ",\n  \"limit_s\": " << o.limitSec << ",\n  \"configs\": [\n";
  for (size_t i = 0; i < results.size(); ++i) {
    const Result& r = results[i];
    auto sc         = [&](const char* k) {
      return (unsigned long long)r.sc(k);
    };
    j << "    {\n      \"name\": \"" << jsonEscape(r.cfg.name)
      << "\",\n      \"env\": {";
    for (size_t k = 0; k < r.cfg.env.size(); ++k)
      j << (k ? ", " : "") << "\"" << jsonEscape(toUtf8(r.cfg.env[k].first)) << "\": \""
        << jsonEscape(toUtf8(r.cfg.env[k].second)) << "\"";
    j << "},\n      \"exit_code\": " << r.exitCode
      << ",\n      \"process_ms\": " << r.processMs
      << ",\n      \"wall_us\": " << sc("wall_us")
      << ",\n      \"planned_ops\": " << sc("recorded_ops")
      << ",\n      \"skipped\": " << sc("skipped")
      << ",\n      \"unmapped\": " << sc("unmapped")
      << ",\n      \"verify_checked\": " << sc("verify_checked")
      << ",\n      \"verify_mismatches\": " << sc("verify_mismatches")
      << ",\n      \"status_diffs\": " << sc("status_diffs")
      << ",\n      \"peak_ws_mb\": " << sc("peak_ws_mb") << ",\n      \"ops\": {";
    for (size_t k = 0; k < r.ops.size(); ++k) {
      const OpResult& x = r.ops[k];
      j << (k ? ",\n        " : "\n        ") << "\"" << x.name
        << "\": {\"count\": " << x.count << ", \"total_us\": " << x.us
        << ", \"status_diffs\": " << x.diffs << ", \"recorded_count\": " << x.recCount
        << ", \"recorded_us\": " << x.recUs << "}";
    }
    j << "\n      },\n      \"latency_ns\": {";
    {
      size_t k = 0;
      for (auto& [name, h] : r.hists)
        j << (k++ ? ", " : "") << "\"" << name << "\": {\"p50\": " << h.p50
          << ", \"p95\": " << h.p95 << ", \"max\": " << h.max << "}";
    }
    j << "},\n      \"threads\": [";
    for (size_t k = 0; k < r.threads.size(); ++k) {
      const ThreadResult& t = r.threads[k];
      j << (k ? ", " : "") << "{\"tid\": " << t.tid << ", \"ops\": " << t.ops
        << ", \"busy_us\": " << t.busyUs << ", \"span_us\": " << t.spanUs << "}";
    }
    j << "],\n      \"samples\": [";
    for (size_t k = 0; k < r.samples.size(); ++k)
      j << (k ? ", " : "") << "\"" << jsonEscape(r.samples[k]) << "\"";
    j << "]\n    }" << (i + 1 < results.size() ? "," : "") << "\n";
  }
  j << "  ]\n}\n";
  return j.str();
}

std::string table(const std::vector<Result>& results)
{
  std::string out;
  char b[256];
  std::snprintf(b, sizeof(b), "%-18s %10s %9s %9s %9s %9s %9s %7s %5s\n", "config",
                "wall_ms", "ops", "skipped", "unmapped", "mismatch", "stat_diff",
                "peakMB", "exit");
  out += b;
  for (const Result& r : results) {
    uint64_t ops = 0;
    for (auto& x : r.ops)
      ops += x.count;
    std::snprintf(
        b, sizeof(b), "%-18.18s %10.1f %9llu %9llu %9llu %9llu %9llu %7llu %5lx\n",
        r.cfg.name.c_str(), r.sc("wall_us") / 1000.0, (unsigned long long)ops,
        (unsigned long long)r.sc("skipped"), (unsigned long long)r.sc("unmapped"),
        (unsigned long long)r.sc("verify_mismatches"),
        (unsigned long long)r.sc("status_diffs"),
        (unsigned long long)r.sc("peak_ws_mb"), (unsigned long)r.exitCode);
    out += b;
  }
  out += "\nper op type: count / total ms   (recorded = in the original run, with its "
         "caches)\n";
  std::snprintf(b, sizeof(b), "%-27s %20s", "op", "recorded");
  out += b;
  for (const Result& r : results) {
    std::snprintf(b, sizeof(b), " %20.20s", r.cfg.name.c_str());
    out += b;
  }
  out += "\n";
  std::vector<std::string> names;
  for (const Result& r : results)
    for (auto& x : r.ops)
      if (std::find(names.begin(), names.end(), x.name) == names.end())
        names.push_back(x.name);
  for (const std::string& n : names) {
    const OpResult* first = nullptr;
    for (const Result& r : results)
      for (auto& x : r.ops)
        if (x.name == n && !first)
          first = &x;
    if (!first || (first->recCount == 0 && first->count == 0))
      continue;
    std::snprintf(b, sizeof(b), "%-27s %9llu/%9.1f", n.c_str(),
                  (unsigned long long)first->recCount, first->recUs / 1000.0);
    out += b;
    for (const Result& r : results) {
      const OpResult* x = nullptr;
      for (auto& y : r.ops)
        if (y.name == n)
          x = &y;
      std::snprintf(b, sizeof(b), " %9llu/%9.1f",
                    x ? (unsigned long long)x->count : 0ull, x ? x->us / 1000.0 : 0.0);
      out += b;
    }
    out += "\n";
  }
  out += "\nlatency per call in us: p50 / p95 / max   (histogram, ~6% resolution)\n";
  std::snprintf(b, sizeof(b), "%-27s", "op");
  out += b;
  for (const Result& r : results) {
    std::snprintf(b, sizeof(b), " %26.26s", r.cfg.name.c_str());
    out += b;
  }
  out += "\n";
  for (const std::string& n : names) {
    bool any = false;
    for (const Result& r : results)
      any |= r.hists.count(n) != 0;
    if (!any)
      continue;
    std::snprintf(b, sizeof(b), "%-27s", n.c_str());
    out += b;
    for (const Result& r : results) {
      auto it = r.hists.find(n);
      if (it == r.hists.end()) {
        std::snprintf(b, sizeof(b), " %26s", "-");
      } else {
        char cell[64];
        std::snprintf(cell, sizeof(cell), "%.1f/%.1f/%.0f", it->second.p50 / 1000.0,
                      it->second.p95 / 1000.0, it->second.max / 1000.0);
        std::snprintf(b, sizeof(b), " %26s", cell);
      }
      out += b;
    }
    out += "\n";
  }
  out += "\nbusiest threads per config (busy ms in replayed calls / thread span ms):\n";
  for (const Result& r : results) {
    std::vector<ThreadResult> t = r.threads;
    std::sort(t.begin(), t.end(), [](auto& a, auto& b2) {
      return a.busyUs > b2.busyUs;
    });
    out += "  " + r.cfg.name + ":";
    for (size_t i = 0; i < t.size() && i < 4; ++i) {
      std::snprintf(b, sizeof(b), " [tid %llu: %.1f/%.1f]",
                    (unsigned long long)t[i].tid, t[i].busyUs / 1000.0,
                    t[i].spanUs / 1000.0);
      out += b;
    }
    out += "\n";
  }
  for (const Result& r : results) {
    if (r.exitCode != 0) {
      std::snprintf(b, sizeof(b),
                    "config %s: child failed, exit code 0x%lx (see the .log)\n",
                    r.cfg.name.c_str(), (unsigned long)r.exitCode);
      out += b;
    }
    for (auto& s : r.samples)
      out += "  [" + r.cfg.name + "] " + s + "\n";
  }
  return out;
}

void usage()
{
  std::fputs("usage: replay.exe <trace> [--timing asap|original] [--verify] "
             "[--threads-as-recorded]\n"
             "                  [--single-thread] [--allow-writes] [--inherit-env] "
             "[--out results.json]\n"
             "                  [--from S] [--to S] [--limit-seconds N] [--no-ff] "
             "[--ff-reads]\n"
             "                  [--vfs MANIFEST [--instance NAME] [--usvfs-dll PATH]]\n"
             "                  [--config NAME KEY=VAL ...]...\n",
             stderr);
}

// Response files: "@path" arguments are replaced by the tokens read from that file
// (UTF-8 or UTF-16 with BOM; whitespace separated; a line starting with '#' is a
// comment; double quotes group a token with spaces).
bool readResponseFile(const std::wstring& path, std::vector<std::wstring>& out)
{
  std::ifstream f(path, std::ios::binary);
  if (!f)
    return false;
  std::string raw((std::istreambuf_iterator<char>(f)),
                  std::istreambuf_iterator<char>());
  std::wstring text;
  auto u8 = [](const char* p, size_t n) {
    if (!n)
      return std::wstring();
    const int len = ::MultiByteToWideChar(CP_UTF8, 0, p, (int)n, nullptr, 0);
    std::wstring w((size_t)len, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, p, (int)n, w.data(), len);
    return w;
  };
  const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
  if (raw.size() >= 2 && b[0] == 0xFF && b[1] == 0xFE) {
    text.assign(reinterpret_cast<const wchar_t*>(raw.data() + 2), (raw.size() - 2) / 2);
  } else if (raw.size() >= 2 && b[0] == 0xFE && b[1] == 0xFF) {
    for (size_t i = 2; i + 1 < raw.size(); i += 2)
      text.push_back((wchar_t)((b[i] << 8) | b[i + 1]));
  } else if (raw.size() >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) {
    text = u8(raw.data() + 3, raw.size() - 3);
  } else {
    text = u8(raw.data(), raw.size());
  }
  std::wstring cur;
  bool inTok = false, inQuote = false, lineStart = true;
  auto flush = [&] {
    if (inTok)
      out.push_back(cur);
    cur.clear();
    inTok = false;
  };
  for (size_t i = 0; i < text.size(); ++i) {
    const wchar_t c = text[i];
    if (!inQuote && lineStart && c == L'#') {
      while (i < text.size() && text[i] != L'\n')
        ++i;
      continue;
    }
    if (c == L'\n') {
      if (!inQuote) {
        flush();
        lineStart = true;
        continue;
      }
    } else if (!inQuote && (c == L' ' || c == L'\t' || c == L'\r')) {
      flush();
      continue;
    }
    if (c == L'"') {
      inQuote   = !inQuote;
      inTok     = true;
      lineStart = false;
      continue;
    }
    cur.push_back(c);
    inTok     = true;
    lineStart = false;
  }
  flush();
  return true;
}

}  // namespace

int wmain(int argc, wchar_t** argv)
{
  Options o;
  std::vector<Config> configs;
  std::vector<std::wstring> args;
  bool expanded = false;
  for (int i = 1; i < argc; ++i) {
    const std::wstring a = argv[i];
    if (a.size() > 1 && a[0] == L'@') {
      expanded = true;
      if (!readResponseFile(a.substr(1), args)) {
        std::fprintf(stderr, "replay: cannot read response file '%s'\n",
                     toUtf8(a.substr(1)).c_str());
        return 1;
      }
    } else
      args.push_back(a);
  }
  const int n = (int)args.size();
  for (int i = 0; i < n; ++i) {
    const std::wstring a = args[i];
    auto next            = [&]() -> std::wstring {
      return i + 1 < n ? args[++i] : std::wstring();
    };
    if (a == L"--timing")
      o.timingOriginal = next() == L"original";
    else if (a == L"--verify")
      o.verify = true;
    else if (a == L"--threads-as-recorded")
      o.singleThread = false;
    else if (a == L"--single-thread")
      o.singleThread = true;
    else if (a == L"--allow-writes")
      o.allowWrites = true;
    else if (a == L"--inherit-env")
      o.inheritEnv = true;
    else if (a == L"--out")
      o.outPath = next();
    else if (a == L"--vfs")
      o.vfsPath = next();
    else if (a == L"--instance")
      o.instanceName = next();
    else if (a == L"--usvfs-dll")
      o.usvfsDll = next();
    else if (a == L"--log")
      o.logPath = next();
    else if (a == L"--child")
      o.childResult = next();
    else if (a == L"--no-ff")
      o.noFastForward = true;
    else if (a == L"--ff-reads")
      o.ffReads = true;
    else if (a == L"--from")
      o.fromSec = _wtof(next().c_str());
    else if (a == L"--to")
      o.toSec = _wtof(next().c_str());
    else if (a == L"--limit-seconds")
      o.limitSec = _wtof(next().c_str());
    else if (a == L"--config") {
      Config c;
      c.name = toUtf8(next());
      while (i + 1 < n && args[i + 1].rfind(L"--", 0) != 0) {
        const std::wstring kv = args[++i];
        const size_t eq       = kv.find(L'=');
        if (eq == std::wstring::npos || eq == 0) {
          std::fprintf(stderr, "replay: bad KEY=VAL '%s'\n", toUtf8(kv).c_str());
          return 1;
        }
        c.env.push_back({kv.substr(0, eq), kv.substr(eq + 1)});
      }
      configs.push_back(std::move(c));
    } else if (!a.empty() && a[0] != L'-' && o.tracePath.empty())
      o.tracePath = a;
    else {
      usage();
      return 1;
    }
  }
  if (o.tracePath.empty()) {
    usage();
    return 1;
  }

  if (!o.childResult.empty())
    return runChild(o);

  if (o.outPath.empty())
    o.outPath = o.tracePath + L".results.json";
  o.logPath = o.outPath + L".log";
  g_logPath = o.logPath;
  if (expanded) {
    std::string l;
    for (auto& x : args)
      l += (l.empty() ? "" : " ") + toUtf8(x);
    logf("expanded arguments: %s", l.c_str());
  }
  logf("replay start: trace %s, %zu config(s), window %g..%g s (limit %g), timing %s",
       toUtf8(o.tracePath).c_str(), configs.size(), o.fromSec, o.toSec, o.limitSec,
       o.timingOriginal ? "original" : "asap");
  if (::GetFileAttributesW(o.tracePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
    logf("trace file not found: %s", lastErrorText(::GetLastError()).c_str());
    return 1;
  }
  if (configs.empty())
    configs.push_back(Config{"default", {}});

  if (!o.vfsPath.empty()) {
    if (!setupVfs(o)) {
      teardownVfs();
      return 1;
    }
  }
  std::vector<Result> results(configs.size());
  for (size_t i = 0; i < configs.size(); ++i) {
    logf("running config %zu/%zu: %s", i + 1, configs.size(), configs[i].name.c_str());
    runConfig(o, configs[i], i, results[i]);
  }

  teardownVfs();
  const std::string json = writeJson(o, results);
  const std::string tab  = table(results);
  {
    std::ofstream f(o.outPath, std::ios::binary | std::ios::trunc);
    f << json;
  }
  {
    std::ofstream f(o.outPath + L".txt", std::ios::binary | std::ios::trunc);
    f << tab;
  }
  std::fputs(tab.c_str(), stdout);
  logf("results: %s (table in .txt, log in .log)", toUtf8(o.outPath).c_str());
  for (auto& r : results)
    if (r.exitCode != 0)
      return 4;
  return 0;
}
