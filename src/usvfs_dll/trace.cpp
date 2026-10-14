#include "trace.h"
#include "hookcallcontext.h"
#include "readcache.h"
#include "trace_format.h"

#include "config.h"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace usvfs::trace
{

std::atomic<bool> g_enabled{false};

namespace
{

  constexpr size_t kFlushBytes =
      64 * 1024;  // a thread hands over its buffer at this size
  constexpr auto kFlushPeriod = std::chrono::milliseconds(250);

  // per-thread buffer; the lock is only contended while the writer steals the
  // partial contents
  struct ThreadBuf
  {
    std::atomic_flag lock;
    std::vector<uint8_t> data;
  };

  struct State
  {
    HANDLE file      = INVALID_HANDLE_VALUE;
    bool crc         = false;
    uint64_t qpcBase = 0;

    std::mutex mutex;  // queue, registry, cv
    std::condition_variable cv;
    std::deque<std::vector<uint8_t>> queue;
    std::vector<ThreadBuf*> bufs;
    bool stop = false;
    std::thread writer;

    std::mutex strMutex;
    std::unordered_map<std::wstring, uint32_t> strings;
  };

  State* g_state                = nullptr;
  thread_local ThreadBuf* t_buf = nullptr;
  thread_local int t_depth      = 0;
  thread_local bool t_internal  = false;

  inline uint64_t qpc()
  {
    LARGE_INTEGER v;
    ::QueryPerformanceCounter(&v);
    return static_cast<uint64_t>(v.QuadPart);
  }

  struct BufLock
  {
    explicit BufLock(ThreadBuf& b) : m_b(b)
    {
      while (m_b.lock.test_and_set(std::memory_order_acquire))
        std::this_thread::yield();
    }
    ~BufLock() { m_b.lock.clear(std::memory_order_release); }
    ThreadBuf& m_b;
  };

  ThreadBuf& threadBuf()
  {
    if (!t_buf) {
      t_buf = new ThreadBuf();  // never freed: the writer may still drain it
      t_buf->data.reserve(kFlushBytes + 4096);
      std::lock_guard lock(g_state->mutex);
      g_state->bufs.push_back(t_buf);
    }
    return *t_buf;
  }

  void emit(const Record* recs[], int n)
  {
    State& st     = *g_state;
    ThreadBuf& tb = threadBuf();
    std::vector<uint8_t> full;
    {
      BufLock lock(tb);
      for (int i = 0; i < n; ++i)
        encodeRecord(*recs[i], tb.data);
      if (tb.data.size() >= kFlushBytes) {
        full.swap(tb.data);
        tb.data.reserve(kFlushBytes + 4096);
      }
    }
    if (!full.empty()) {
      {
        std::lock_guard lock(st.mutex);
        st.queue.push_back(std::move(full));
      }
      st.cv.notify_one();
    }
  }

  // string table id of `text` (never 0); defs are the StringDef records to emit
  // first when the string is new
  uint32_t intern(const wchar_t* text, size_t chars, Record& def, bool& isNew)
  {
    State& st = *g_state;
    std::wstring key(text, chars);
    std::lock_guard lock(st.strMutex);
    auto [it, inserted] = st.strings.try_emplace(std::move(key), 0u);
    isNew               = inserted;
    if (inserted) {
      it->second = static_cast<uint32_t>(st.strings.size());
      def.op     = Op::StringDef;
      def.str    = it->second;
      def.text   = it->first;
    }
    return it->second;
  }

  // finishes a record (common fields) and emits it, preceded by the definition of
  // `name` if one is given
  void submit(const Scope& s, Record& r, const UNICODE_STRING* name, bool hasName)
  {
    r.tid              = ::GetCurrentThreadId();
    const uint64_t now = qpc();
    r.ts               = s.startTicks() - g_state->qpcBase;
    r.dur              = now - s.startTicks();

    Record def;
    bool isNew = false;
    if (hasName) {
      const size_t chars = name && name->Buffer ? name->Length / sizeof(WCHAR) : 0;
      r.str = intern(name && name->Buffer ? name->Buffer : L"", chars, def, isNew);
    }
    const Record* recs[2];
    int n = 0;
    if (isNew)
      recs[n++] = &def;
    recs[n++] = &r;
    emit(recs, n);
  }

  bool writeAll(HANDLE file, const void* data, size_t size)
  {
    const char* p = static_cast<const char*>(data);
    while (size) {
      DWORD done = 0;
      if (!::WriteFile(file, p, static_cast<DWORD>(std::min<size_t>(size, 1u << 24)),
                       &done, nullptr) ||
          done == 0)
        return false;
      p += done;
      size -= done;
    }
    return true;
  }

  void writeBlock(State& st, const std::vector<uint8_t>& block)
  {
    if (block.empty() || st.file == INVALID_HANDLE_VALUE)
      return;
    const uint32_t size = static_cast<uint32_t>(block.size());
    writeAll(st.file, &size, sizeof(size));
    writeAll(st.file, block.data(), block.size());
  }

  // moves every thread's partial buffer and the queue into `out`
  void drain(State& st, std::vector<std::vector<uint8_t>>& out)
  {
    std::vector<ThreadBuf*> bufs;
    {
      std::lock_guard lock(st.mutex);
      for (auto& q : st.queue)
        out.push_back(std::move(q));
      st.queue.clear();
      bufs = st.bufs;
    }
    for (ThreadBuf* tb : bufs) {
      std::vector<uint8_t> part;
      {
        BufLock lock(*tb);
        part.swap(tb->data);
        tb->data.reserve(kFlushBytes + 4096);
      }
      if (!part.empty())
        out.push_back(std::move(part));
    }
  }

  void writerMain(State* st)
  {
    for (;;) {
      bool stop;
      {
        std::unique_lock lock(st->mutex);
        st->cv.wait_for(lock, kFlushPeriod, [&] {
          return st->stop;
        });
        stop = st->stop;
      }
      std::vector<std::vector<uint8_t>> blocks;
      drain(*st, blocks);
      for (auto& b : blocks)
        writeBlock(*st, b);
      if (stop)
        break;
    }
  }

  bool envVar(const char* name, std::wstring& out)
  {
    // environment first, then the config file (USVFS_CONFIG, else usvfs-cache.ini next
    // to the DLL) ([trace] path / crc)
    const std::string v = config::text(name);
    if (v.empty())
      return false;
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, v.c_str(),
                                        static_cast<int>(v.size()), nullptr, 0);
    if (n <= 0)
      return false;
    out.resize(n);
    ::MultiByteToWideChar(CP_UTF8, 0, v.c_str(), static_cast<int>(v.size()), out.data(),
                          n);
    return true;
  }

  HANDLE openOutput(std::wstring path)
  {
    // exclusive: a second process with the same environment must not clobber it
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      path += L"." + std::to_wstring(::GetCurrentProcessId());
      h = ::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    return h;
  }

}  // namespace

static void emitInitialCwd();

std::string init()
try {
  std::wstring path;
  if (!envVar("USVFS_TRACE", path) || path.empty())
    return {};

  auto st  = std::make_unique<State>();
  st->file = openOutput(path);
  if (st->file == INVALID_HANDLE_VALUE)
    return "trace disabled: cannot create '" + std::string(path.begin(), path.end()) +
           "' (error " + std::to_string(::GetLastError()) + ")";

  std::wstring v;
  st->crc = envVar("USVFS_TRACE_CRC", v) && !v.empty() && v[0] != L'0';

  LARGE_INTEGER freq;
  ::QueryPerformanceFrequency(&freq);
  st->qpcBase = qpc();

  FileHeader hdr{};
  std::memcpy(hdr.magic, kMagic, sizeof(hdr.magic));
  hdr.version = kVersion;
  hdr.flags   = st->crc ? kFlagCrc : 0;
  hdr.qpcFreq = static_cast<uint64_t>(freq.QuadPart);
  hdr.qpcBase = st->qpcBase;
  hdr.pid     = ::GetCurrentProcessId();
  writeAll(st->file, &hdr, sizeof(hdr));

  g_state = st.release();
  try {
    g_state->writer = std::thread(writerMain, g_state);
  } catch (...) {
    ::CloseHandle(g_state->file);
    g_state = nullptr;  // leaked on purpose; tracing stays off
    return "trace disabled: cannot start the writer thread";
  }
  emitInitialCwd();
  g_enabled.store(true, std::memory_order_release);
  return "trace enabled, writing to '" + std::string(path.begin(), path.end()) + "'" +
         (g_state->crc ? " (with read crc32)" : "");
} catch (...) {
  g_enabled.store(false);
  return "trace disabled: exception during init";
}

void shutdown()
{
  if (!g_state)
    return;
  g_enabled.store(false, std::memory_order_release);
  {
    std::lock_guard lock(g_state->mutex);
    g_state->stop = true;
  }
  g_state->cv.notify_all();
  if (g_state->writer.joinable())
    g_state->writer.join();
  // the state is intentionally leaked: threads that were mid-record still hold
  // pointers into it
  ::FlushFileBuffers(g_state->file);
  ::CloseHandle(g_state->file);
  g_state->file = INVALID_HANDLE_VALUE;
}

void setInternalThread(bool internal)
{
  t_internal = internal;
}

void Scope::begin()
try {
  if (t_depth > 0 || t_internal)
    return;  // nested call made by one of our own hooks
  {
    // Skip when ANY hook group is active on this thread: that is either one of
    // our worker threads (ALL_GROUPS) or an ntdll call made by a kernel32 hook,
    // whose paths may be rerouted and are not what the application asked for.
    // (LAST == NO_GROUP is not a bit of the group set: probing it throws)
    for (int g = 0; g < static_cast<int>(MutExHookGroup::LAST); ++g) {
      HookCallContext probe(static_cast<MutExHookGroup>(g));
      if (!probe.active())
        return;
    }
  }
  m_err   = ::GetLastError();
  m_start = qpc();
  m_on    = true;
  ++t_depth;
} catch (...) {
  m_on = false;
}

void Scope::end()
{
  --t_depth;
  if (m_restore)
    ::SetLastError(m_err);
}

namespace
{
  uint64_t h64(HANDLE h)
  {
    return reinterpret_cast<uint64_t>(h);
  }

  uint64_t ioInfo(PIO_STATUS_BLOCK iosb, NTSTATUS status)
  {
    ULONG_PTR got = 0;
    if (iosb && status >= 0 &&
        readcache::guardedCopy(&got, &iosb->Information, sizeof(got)))
      return got;
    return 0;
  }
}  // namespace

void recCreate(const Scope& s, bool isOpen, PHANDLE FileHandle, POBJECT_ATTRIBUTES oa,
               ACCESS_MASK access, ULONG share, ULONG disposition, ULONG options,
               ULONG fileAttributes, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op     = isOpen ? Op::Open : Op::Create;
    r.status = static_cast<uint32_t>(status);
    if (status >= 0 && FileHandle)
      r.h = h64(*FileHandle);
    r.h2 = oa ? h64(oa->RootDirectory) : 0;
    r.a  = access;
    r.b  = share;
    r.c  = isOpen ? 0 : disposition;
    r.d  = options;
    r.e  = fileAttributes;
    submit(s, r, oa ? oa->ObjectName : nullptr, oa && oa->ObjectName);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recRead(const Scope& s, HANDLE handle, HANDLE event, PIO_STATUS_BLOCK iosb,
             PVOID buffer, ULONG length, PLARGE_INTEGER byteOffset, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op         = Op::Read;
    r.status     = static_cast<uint32_t>(status);
    r.h          = h64(handle);
    r.a          = length;
    r.b          = byteOffset ? 1 : 0;
    LONGLONG off = 0;
    if (byteOffset && !readcache::guardedCopy(&off, byteOffset, sizeof(off)))
      r.b = 0;
    r.off               = off;
    ULONG_PTR got       = 0;
    const bool haveInfo = iosb && status >= 0 &&
                          readcache::guardedCopy(&got, &iosb->Information, sizeof(got));
    if (haveInfo)
      r.info = got;
    if (g_state->crc && status == 0 && !event && buffer && haveInfo && got <= length) {
      // checksum through guarded copies: the buffer is application memory
      uint32_t crc = 0;
      bool ok      = true;
      uint8_t chunk[16384];
      for (ULONG_PTR pos = 0; pos < got && ok; pos += sizeof(chunk)) {
        const size_t n =
            static_cast<size_t>(std::min<ULONG_PTR>(sizeof(chunk), got - pos));
        ok =
            readcache::guardedCopy(chunk, static_cast<const uint8_t*>(buffer) + pos, n);
        if (ok)
          crc = crc32Update(crc, chunk, n);
      }
      if (ok) {
        r.hasCrc = true;
        r.crc    = crc;
      }
    }
    submit(s, r, nullptr, false);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recQueryInfo(const Scope& s, HANDLE handle, PIO_STATUS_BLOCK iosb, ULONG length,
                  FILE_INFORMATION_CLASS cls, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op     = Op::QueryInfo;
    r.status = static_cast<uint32_t>(status);
    r.h      = h64(handle);
    r.a      = static_cast<uint64_t>(cls);
    r.b      = length;
    r.info   = ioInfo(iosb, status);
    submit(s, r, nullptr, false);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recSetInfo(const Scope& s, HANDLE handle, PIO_STATUS_BLOCK iosb, PVOID info,
                ULONG length, FILE_INFORMATION_CLASS cls, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op     = Op::SetInfo;
    r.status = static_cast<uint32_t>(status);
    r.h      = h64(handle);
    r.a      = static_cast<uint64_t>(cls);
    r.b      = length;
    if (cls == FilePositionInformation && info && length >= sizeof(LONGLONG)) {
      LONGLONG pos = 0;
      if (readcache::guardedCopy(&pos, info, sizeof(pos)))
        r.off = pos;
    }
    r.info = ioInfo(iosb, status);
    submit(s, r, nullptr, false);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recQueryDir(const Scope& s, bool ex, HANDLE handle, PIO_STATUS_BLOCK iosb,
                 ULONG length, FILE_INFORMATION_CLASS cls, ULONG flags,
                 PUNICODE_STRING mask, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op     = ex ? Op::QueryDirEx : Op::QueryDir;
    r.status = static_cast<uint32_t>(status);
    r.h      = h64(handle);
    r.a      = static_cast<uint64_t>(cls);
    r.b      = length;
    r.c      = flags;
    r.info   = ioInfo(iosb, status);
    submit(s, r, mask, mask != nullptr);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recQueryAttr(const Scope& s, bool full, POBJECT_ATTRIBUTES oa, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op     = full ? Op::QueryFullAttr : Op::QueryAttr;
    r.status = static_cast<uint32_t>(status);
    r.h2     = oa ? h64(oa->RootDirectory) : 0;
    submit(s, r, oa ? oa->ObjectName : nullptr, oa && oa->ObjectName);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recClose(const Scope& s, HANDLE handle, NTSTATUS status)
{
  if (!g_state)
    return;
  try {
    Record r;
    r.op     = Op::Close;
    r.status = static_cast<uint32_t>(status);
    r.h      = h64(handle);
    submit(s, r, nullptr, false);
  } catch (...) {
    // tracing must never take the application down
  }
}

// ---------------------------------------------------------------------------
// kernel32 level

namespace
{

  // NUL terminated string from application memory without faulting; returns false
  // for a NULL or unreadable pointer
  bool readAppString(const void* p, bool ansi, std::wstring& out)
  {
    out.clear();
    if (!p)
      return false;
    const size_t unit = ansi ? 1 : sizeof(wchar_t);
    const char* cur   = static_cast<const char*>(p);
    std::string narrow;
    for (size_t total = 0; total < 65536;) {
      // never cross a page within one copy
      size_t bytes = 4096 - (reinterpret_cast<uintptr_t>(cur) & 4095);
      bytes        = std::min<size_t>(bytes, 512) / unit * unit;
      if (bytes == 0)
        return false;  // misaligned wide string at a page end: give up
      char chunk[512];
      if (!readcache::guardedCopy(chunk, cur, bytes))
        return false;
      for (size_t i = 0; i < bytes; i += unit) {
        if (ansi) {
          if (chunk[i] == 0)
            goto done;
          narrow.push_back(chunk[i]);
        } else {
          wchar_t ch;
          std::memcpy(&ch, chunk + i, sizeof(ch));
          if (ch == 0)
            goto done;
          out.push_back(ch);
        }
      }
      cur += bytes;
      total += bytes;
    }
  done:
    if (ansi && !narrow.empty()) {
      const int n = ::MultiByteToWideChar(CP_ACP, 0, narrow.data(),
                                          static_cast<int>(narrow.size()), nullptr, 0);
      out.resize(n);
      ::MultiByteToWideChar(CP_ACP, 0, narrow.data(), static_cast<int>(narrow.size()),
                            out.data(), n);
    }
    return true;
  }

  struct Defs
  {
    Record def[4];
    int n = 0;
  };

  // id of a string read from application memory (0 = NULL pointer)
  uint32_t internApp(const void* p, bool ansi, Defs& defs)
  {
    std::wstring w;
    if (!readAppString(p, ansi, w))
      return 0;
    bool isNew = false;
    Record d;
    const uint32_t id = intern(w.c_str(), w.size(), d, isNew);
    if (isNew && defs.n < 4)
      defs.def[defs.n++] = std::move(d);
    return id;
  }

  void finish(const Scope& s, Record& r, Defs& defs)
  {
    r.tid              = ::GetCurrentThreadId();
    const uint64_t now = qpc();
    r.ts               = s.startTicks() - g_state->qpcBase;
    r.dur              = now - s.startTicks();
    const Record* recs[5];
    int n = 0;
    for (int i = 0; i < defs.n; ++i)
      recs[n++] = &defs.def[i];
    recs[n++] = &r;
    emit(recs, n);
  }

}  // namespace

void recGetAttr(const Scope& s, const void* path, unsigned long result,
                unsigned long err)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op     = Op::GetAttr;
    r.str    = internApp(path, false, defs);
    r.status = result;
    r.info   = result == INVALID_FILE_ATTRIBUTES ? err : 0;
    finish(s, r, defs);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recGetAttrEx(const Scope& s, const void* path, unsigned long level, int ok,
                  unsigned long err)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op     = Op::GetAttrEx;
    r.str    = internApp(path, false, defs);
    r.a      = level;
    r.status = ok ? 1 : 0;
    r.info   = ok ? 0 : err;
    finish(s, r, defs);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recFindFirst(const Scope& s, const void* path, unsigned long level,
                  unsigned long op, unsigned long flags, HANDLE result,
                  unsigned long err)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op          = Op::FindFirst;
    r.str         = internApp(path, false, defs);
    r.a           = level;
    r.b           = op;
    r.c           = flags;
    const bool ok = result != INVALID_HANDLE_VALUE;
    r.h           = ok ? h64(result) : 0;
    r.status      = ok ? 1 : 0;
    r.info        = ok ? 0 : err;
    finish(s, r, defs);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recProfile(const Scope& s, bool section, bool ansi, const void* app,
                const void* key, const void* file, unsigned long nSize,
                unsigned long result)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op     = section ? Op::ProfSection : Op::ProfString;
    r.str    = internApp(file, ansi, defs);
    r.a      = internApp(app, ansi, defs);
    r.b      = section ? 0 : internApp(key, ansi, defs);
    r.c      = nSize;
    r.d      = ansi ? 1 : 0;
    r.status = result;
    finish(s, r, defs);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recWriteMarker(const Scope& s, unsigned kind, bool ansi, const void* path)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op  = Op::WriteMarker;
    r.str = internApp(path, ansi, defs);
    r.a   = kind;
    finish(s, r, defs);
  } catch (...) {
    // tracing must never take the application down
  }
}

void recFindNext(const Scope& s, HANDLE find, int ok)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op     = Op::FindNext;
    r.h      = h64(find);
    r.status = ok ? 1 : 0;
    finish(s, r, defs);
  } catch (...) {
  }
}

void recFindClose(const Scope& s, HANDLE find, int ok)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op     = Op::FindClose;
    r.h      = h64(find);
    r.status = ok ? 1 : 0;
    finish(s, r, defs);
  } catch (...) {
  }
}

void recSetCwd(const Scope& s, const void* path, int ok)
{
  if (!g_state)
    return;
  try {
    Defs defs;
    Record r;
    r.op     = Op::SetCwd;
    r.str    = internApp(path, false, defs);
    r.status = ok ? 1 : 0;
    finish(s, r, defs);
  } catch (...) {
  }
}

// the directory the process starts in; replay restores it before anything else
static void emitInitialCwd()
{
  try {
    wchar_t cwd[2048];
    const DWORD n = ::GetCurrentDirectoryW(2048, cwd);
    if (n == 0 || n >= 2048)
      return;
    Defs defs;
    Record r;
    r.op     = Op::SetCwd;
    r.tid    = ::GetCurrentThreadId();
    r.ts     = 0;
    r.status = 1;
    r.str    = internApp(cwd, false, defs);
    const Record* recs[2];
    int k = 0;
    for (int i = 0; i < defs.n; ++i)
      recs[k++] = &defs.def[i];
    recs[k++] = &r;
    emit(recs, k);
  } catch (...) {
  }
}

}  // namespace usvfs::trace
