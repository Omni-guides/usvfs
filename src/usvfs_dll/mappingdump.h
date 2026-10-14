#pragma once
// USVFS_MAPPING_DUMP=<path>: the process that builds the VFS (Mod Organizer 2) logs
// every mapping-related export call here; usvfsCreateProcessHooked writes the current
// state to <path> atomically. replay.exe --vfs <path> re-issues the calls so it can run
// without MO2. Zero cost when the variable is unset (one cached bool).
//
// Manifest (UTF-8, one entry per line, fields TAB separated, \\ \t \n \r escaped):
//   USVFSMAP 1
//   PARAMS <instanceName> <debugMode 0/1> <logLevel int> <crashDumpsType int>
//   <crashDumpsPath> <delayProcessMs> LINKFILE <source> <destination> <flags> LINKDIR
//   <source> <destination> <flags> BLACKLIST <exe>   SKIPSUFFIX <suffix>   SKIPDIR
//   <dir>   FORCELOAD <process> <library>
// Clear* calls drop the earlier lines of their kind, so the file holds the final state
// in call order.
#include <algorithm>
#include <mutex>
#include <string>
#include <vector>
#include <windows.h>

namespace usvfs::mapdump
{

inline std::wstring& dumpPath()
{
  static std::wstring p = [] {
    wchar_t buf[2048];
    const DWORD n = ::GetEnvironmentVariableW(L"USVFS_MAPPING_DUMP", buf, 2048);
    return (n > 0 && n < 2048) ? std::wstring(buf, n) : std::wstring();
  }();
  return p;
}

inline bool enabled()
{
  static const bool e = !dumpPath().empty();
  return e;
}

struct State
{
  std::mutex mx;
  std::string params;
  std::vector<std::string> lines;
};

inline State& state()
{
  static State* s =
      new State;  // leaked on purpose: calls may arrive during process teardown
  return *s;
}

inline std::string utf8(const wchar_t* w)
{
  if (!w || !*w)
    return {};
  const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  if (n <= 1)
    return {};
  std::string s(n - 1, '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
  return s;
}

inline std::string esc(const std::string& s)
{
  std::string o;
  for (char c : s) {
    switch (c) {
    case '\\':
      o += "\\\\";
      break;
    case '\t':
      o += "\\t";
      break;
    case '\n':
      o += "\\n";
      break;
    case '\r':
      o += "\\r";
      break;
    default:
      o += c;
    }
  }
  return o;
}

inline void add(const char* tag, std::initializer_list<std::string> fields)
{
  std::string l = tag;
  for (auto& f : fields) {
    l += '\t';
    l += esc(f);
  }
  std::lock_guard g(state().mx);
  state().lines.push_back(std::move(l));
}

inline void clear(const char* tag)
{
  const std::string t = std::string(tag) + "\t";
  std::lock_guard g(state().mx);
  auto& v = state().lines;
  v.erase(std::remove_if(v.begin(), v.end(),
                         [&](const std::string& l) {
                           return l.compare(0, t.size(), t) == 0;
                         }),
          v.end());
}

inline void setParams(const char* instance, bool debug, int logLevel, int dumpType,
                      const char* dumpPathUtf8, int delayMs)
{
  std::string l =
      "PARAMS\t" + esc(instance ? instance : "") + "\t" + (debug ? "1" : "0") + "\t" +
      std::to_string(logLevel) + "\t" + std::to_string(dumpType) + "\t" +
      esc(dumpPathUtf8 ? dumpPathUtf8 : "") + "\t" + std::to_string(delayMs);
  std::lock_guard g(state().mx);
  state().params = std::move(l);
}

// write <path>.tmp then replace <path>; failures are ignored (diagnostic aid only)
inline void flush()
{
  std::string out = "USVFSMAP\t1\n";
  {
    std::lock_guard g(state().mx);
    if (!state().params.empty())
      out += state().params + "\n";
    for (auto& l : state().lines)
      out += l + "\n";
  }
  const std::wstring tmp = dumpPath() + L".tmp";
  HANDLE h = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return;
  DWORD w = 0;
  const bool ok =
      ::WriteFile(h, out.data(), (DWORD)out.size(), &w, nullptr) && w == out.size();
  ::CloseHandle(h);
  if (ok)
    ::MoveFileExW(tmp.c_str(), dumpPath().c_str(), MOVEFILE_REPLACE_EXISTING);
  else
    ::DeleteFileW(tmp.c_str());
}

// the directory link recurses through the exported function; only the outermost call is
// logged
struct NestGuard
{
  static int& depth()
  {
    thread_local int d = 0;
    return d;
  }
  bool outer;
  NestGuard() : outer(depth()++ == 0) {}
  ~NestGuard() { --depth(); }
};

}  // namespace usvfs::mapdump
