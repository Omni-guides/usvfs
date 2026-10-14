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
#pragma once

// Pure decision logic of the read cache (readcache.cpp). This header must not
// depend on any Windows/ntdll declarations so that it can be unit tested.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace usvfs::readcache::logic
{

// values of the corresponding Windows constants, repeated here on purpose
constexpr uint32_t kModeNoIntermediateBuffering = 0x00000008;
constexpr uint32_t kModeSynchronousAlert        = 0x00000010;
constexpr uint32_t kModeSynchronousNonAlert     = 0x00000020;
constexpr uint32_t kAccessReadData              = 0x00000001;
constexpr uint32_t kAccessWriteData             = 0x00000002;
constexpr uint32_t kAccessAppendData            = 0x00000004;
constexpr uint32_t kDeviceTypeDisk              = 0x00000007;  // FILE_DEVICE_DISK
// Wine reports regular files as FILE_DEVICE_DISK_FILE_SYSTEM
constexpr uint32_t kDeviceTypeDiskFileSystem = 0x00000008;

// reads of this size or more are not worth caching
constexpr uint64_t kSmallReadLimit = 64 * 1024;
// runtime values of the tunables (set once from the configuration at init)
inline uint64_t g_smallReadLimit = kSmallReadLimit;

// ByteOffset value meaning "use the current file pointer"
constexpr int64_t kUseFilePointerPosition = -2;

// ---------------------------------------------------------------------------
// eligibility

enum class Eligibility : int
{
  Eligible = 0,
  EventOrApc,   // first read had an event or apc routine
  QueryFailed,  // an attribute query failed
  NotDisk,      // device type is not FILE_DEVICE_DISK
  Directory,
  NotSynchronous,  // handle is not opened for synchronous i/o
  NoBuffering,     // FILE_NO_INTERMEDIATE_BUFFERING
  NotReadable,     // no FILE_READ_DATA access
  Writable,        // FILE_WRITE_DATA or FILE_APPEND_DATA access
  TooLarge,        // bigger than the per-file cap (or the whole budget)
  BigRead,         // first read is >= kSmallReadLimit
  FillFailed,      // loading the file failed
  Count
};

inline const char* eligibilityName(Eligibility e)
{
  switch (e) {
  case Eligibility::Eligible:
    return "eligible";
  case Eligibility::EventOrApc:
    return "event/apc";
  case Eligibility::QueryFailed:
    return "query-failed";
  case Eligibility::NotDisk:
    return "not-disk";
  case Eligibility::Directory:
    return "directory";
  case Eligibility::NotSynchronous:
    return "not-sync";
  case Eligibility::NoBuffering:
    return "no-buffering";
  case Eligibility::NotReadable:
    return "not-readable";
  case Eligibility::Writable:
    return "writable";
  case Eligibility::TooLarge:
    return "too-large";
  case Eligibility::BigRead:
    return "big-read";
  case Eligibility::FillFailed:
    return "fill-failed";
  default:
    return "?";
  }
}

// attributes of a handle gathered at its first NtReadFile
struct HandleAttrs
{
  bool hasEventOrApc       = false;
  bool queriesOk           = true;
  uint32_t deviceType      = 0;
  bool directory           = false;
  uint32_t mode            = 0;  // FILE_MODE_INFORMATION::Mode
  uint32_t access          = 0;  // FILE_ACCESS_INFORMATION::AccessFlags
  uint64_t endOfFile       = 0;
  uint64_t firstReadLength = 0;
};

struct Limits
{
  uint64_t maxFileBytes = 64ull << 20;
  uint64_t budgetBytes  = 1024ull << 20;
};

inline Eligibility evaluateEligibility(const HandleAttrs& a, const Limits& l)
{
  if (a.hasEventOrApc)
    return Eligibility::EventOrApc;
  if (!a.queriesOk)
    return Eligibility::QueryFailed;
  if (a.deviceType != kDeviceTypeDisk && a.deviceType != kDeviceTypeDiskFileSystem)
    return Eligibility::NotDisk;
  if (a.directory)
    return Eligibility::Directory;
  if ((a.mode & (kModeSynchronousAlert | kModeSynchronousNonAlert)) == 0)
    return Eligibility::NotSynchronous;
  if ((a.mode & kModeNoIntermediateBuffering) != 0)
    return Eligibility::NoBuffering;
  if ((a.access & kAccessReadData) == 0)
    return Eligibility::NotReadable;
  if ((a.access & (kAccessWriteData | kAccessAppendData)) != 0)
    return Eligibility::Writable;
  if (a.endOfFile > l.maxFileBytes || a.endOfFile > l.budgetBytes)
    return Eligibility::TooLarge;
  if (a.firstReadLength >= g_smallReadLimit)
    return Eligibility::BigRead;
  return Eligibility::Eligible;
}

// ---------------------------------------------------------------------------
// serving a read from a fully (or progressively) loaded file

enum class ReadAction : int
{
  Passthrough,  // let the real NtReadFile handle it
  EndOfFile,    // answer STATUS_END_OF_FILE, information 0
  Copy          // copy `count` bytes from `offset`
};

struct ReadPlan
{
  ReadAction action = ReadAction::Passthrough;
  uint64_t offset   = 0;
  uint64_t count    = 0;
  uint64_t newPos   = 0;  // shadow position after the request
};

// hasByteOffset: the ByteOffset parameter was non-NULL
// byteOffset:    its QuadPart (ignored if !hasByteOffset)
inline ReadPlan planRead(uint64_t fileSize, uint64_t shadowPos, bool hasByteOffset,
                         int64_t byteOffset, uint64_t length, bool hasKey)
{
  ReadPlan plan;
  plan.newPos = shadowPos;

  // lock keys are not something we can emulate, empty reads are not worth it
  if (hasKey || length == 0)
    return plan;

  uint64_t offset = shadowPos;
  if (hasByteOffset && byteOffset != kUseFilePointerPosition) {
    if (byteOffset < 0)
      return plan;  // includes FILE_WRITE_TO_END_OF_FILE, let the kernel judge
    offset = static_cast<uint64_t>(byteOffset);
  }

  plan.offset = offset;

  if (offset >= fileSize) {
    plan.action = ReadAction::EndOfFile;
    return plan;
  }

  plan.action = ReadAction::Copy;
  plan.count  = std::min<uint64_t>(length, fileSize - offset);
  plan.newPos = offset + plan.count;
  return plan;
}

// ---------------------------------------------------------------------------
// admission: only files that are actually read in small pieces get cached

inline bool isSmallRead(uint64_t length)
{
  return length < g_smallReadLimit;
}

// `smallReads` includes the current read. A file that is already resident
// (admitted through another handle) is served right away.
inline bool shouldAdmit(uint32_t smallReads, uint32_t threshold, bool resident)
{
  return resident || smallReads >= threshold;
}

constexpr size_t kSizeBuckets = 4;

// <64K, 64K-1M, 1-8M, 8M and up
inline size_t sizeBucket(uint64_t fileSize)
{
  if (fileSize < (64ull << 10))
    return 0;
  if (fileSize < (1ull << 20))
    return 1;
  if (fileSize < (8ull << 20))
    return 2;
  return 3;
}

inline const char* sizeBucketName(size_t bucket)
{
  switch (bucket) {
  case 0:
    return "<64K";
  case 1:
    return "64K-1M";
  case 2:
    return "1-8M";
  default:
    return "8M+";
  }
}

// ---------------------------------------------------------------------------
// layer 3: splitting big reads and sequential readahead

// a handle whose big reads may be split / read ahead (it need not be cacheable)
inline bool splitCapable(const HandleAttrs& a)
{
  return a.deviceType != 0 &&
         (a.deviceType == kDeviceTypeDisk ||
          a.deviceType == kDeviceTypeDiskFileSystem) &&
         !a.directory &&
         (a.mode & (kModeSynchronousAlert | kModeSynchronousNonAlert)) != 0 &&
         (a.mode & kModeNoIntermediateBuffering) == 0 &&
         (a.access & kAccessReadData) != 0 &&
         (a.access & (kAccessWriteData | kAccessAppendData)) == 0;
}

constexpr size_t kBigBuckets = 4;

// reads of at least kSmallReadLimit: 64-256K, 256K-1M, 1-4M, 4M+
inline size_t bigBucket(uint64_t length)
{
  if (length < (256ull << 10))
    return 0;
  if (length < (1ull << 20))
    return 1;
  if (length < (4ull << 20))
    return 2;
  return 3;
}

inline const char* bigBucketName(size_t bucket)
{
  switch (bucket) {
  case 0:
    return "64-256K";
  case 1:
    return "256K-1M";
  case 2:
    return "1-4M";
  default:
    return "4M+";
  }
}

struct Chunk
{
  uint64_t offset = 0;
  uint64_t length = 0;
};

enum class SplitAction : int
{
  Passthrough,  // not worth splitting
  EndOfFile,    // offset is at/after the end: STATUS_END_OF_FILE, information 0
  Split
};

struct SplitPlan
{
  SplitAction action = SplitAction::Passthrough;
  uint64_t total     = 0;  // bytes the request will return (up to EOF)
  std::vector<Chunk> chunks;
};

// `minLength`: requests shorter than this are not split. `chunk` must be > 0.
inline SplitPlan planSplit(uint64_t offset, uint64_t length, uint64_t fileSize,
                           uint64_t minLength, uint64_t chunk)
{
  SplitPlan plan;
  if (length == 0 || chunk == 0)
    return plan;
  if (offset >= fileSize) {
    plan.action = SplitAction::EndOfFile;
    return plan;
  }
  plan.total = std::min<uint64_t>(length, fileSize - offset);
  if (length < minLength || plan.total <= chunk)
    return plan;  // a single chunk gains nothing

  plan.action = SplitAction::Split;
  for (uint64_t done = 0; done < plan.total; done += chunk) {
    plan.chunks.push_back(
        {offset + done, std::min<uint64_t>(chunk, plan.total - done)});
  }
  return plan;
}

// per-handle detection of sequential big reads
struct SeqState
{
  bool valid       = false;
  uint64_t lastEnd = 0;
  uint32_t run     = 0;  // consecutive reads that continued the previous one
};

// records a read of [offset, offset+total); returns true if it continued the
// previous one. Anything else restarts the run.
inline bool updateSequential(SeqState& s, uint64_t offset, uint64_t total)
{
  const bool sequential = s.valid && offset == s.lastEnd;
  s.run                 = sequential ? s.run + 1 : 0;
  s.lastEnd             = offset + total;
  s.valid               = true;
  return sequential;
}

// readahead starts after this many sequential continuations in a row
constexpr uint32_t kSequentialRunForReadahead = 2;

struct WindowPlan
{
  uint64_t start  = 0;
  uint64_t length = 0;  // 0: no window
};

constexpr uint64_t kMaxWindow   = 4ull << 20;
inline uint64_t g_maxWindow     = kMaxWindow;
inline uint32_t g_sequentialRun = kSequentialRunForReadahead;

// next readahead window: 2x the last read (at most 1 MiB for reads below 1 MiB), capped
// at kMaxWindow, the end of the file and what is left of the readahead memory budget
inline WindowPlan planWindow(uint64_t lastEnd, uint64_t lastReadSize, uint64_t fileSize,
                             uint64_t budgetLeft)
{
  WindowPlan w;
  if (lastEnd >= fileSize)
    return w;
  uint64_t len = std::min<uint64_t>(lastReadSize * 2, g_maxWindow);
  if (lastReadSize < (1ull << 20))
    len = std::min<uint64_t>(len, 1ull << 20);  // small reads: no more than 1 MiB ahead
  len = std::min<uint64_t>(len, fileSize - lastEnd);
  len = std::min<uint64_t>(len, budgetLeft);
  if (len == 0)
    return w;
  w.start  = lastEnd;
  w.length = len;
  return w;
}

// true if [offset, offset+total) lies completely inside the window
inline bool windowCovers(uint64_t winStart, uint64_t winLength, uint64_t offset,
                         uint64_t total)
{
  return total > 0 && offset >= winStart && offset + total <= winStart + winLength;
}

// the next window (directly behind the current one) is due once the reader is
// half way through the current one
inline bool needNextWindow(bool hasCurrent, uint64_t curStart, uint64_t curLength,
                           bool hasNext, uint64_t lastEnd)
{
  return hasCurrent && !hasNext && lastEnd >= curStart + curLength / 2;
}

// a new window is due if there is none, or the current one can't satisfy
// another read of the size just done
inline bool needNewWindow(bool hasWindow, uint64_t winStart, uint64_t winLength,
                          uint64_t lastEnd, uint64_t lastReadSize)
{
  if (!hasWindow)
    return true;
  return lastEnd < winStart || lastEnd + lastReadSize > winStart + winLength;
}

// ---------------------------------------------------------------------------
// LRU budget

struct EvictCandidate
{
  uint64_t bytes = 0;
  bool pinned    = false;  // referenced by an open handle / running fill
};

// Eviction runs only when over budget and then goes below it by this margin, so
// that it isn't repeated for every single fill.
inline uint64_t evictionTarget(uint64_t budget)
{
  return budget - budget / 10;
}

// `lruOldestFirst` lists all cached entries from least to most recently used.
// Returns the indices (ascending order of age) to evict so that the remaining
// total is within `budget`, never selecting pinned entries (those being filled). `used`
// is the current total of all entries.
inline std::vector<size_t>
selectEvictions(const std::vector<EvictCandidate>& lruOldestFirst, uint64_t used,
                uint64_t budget)
{
  std::vector<size_t> result;
  for (size_t i = 0; i < lruOldestFirst.size() && used > budget; ++i) {
    const EvictCandidate& c = lruOldestFirst[i];
    if (c.pinned)
      continue;
    result.push_back(i);
    used -= std::min(used, c.bytes);
  }
  return result;
}

// ---------------------------------------------------------------------------
// configuration parsing

// returns `def` for null/empty/invalid input; otherwise the parsed number
// default cache size in MiB: totalRamBytes / divisor MiB-wise, clamped to [256, 1024]
inline uint64_t scaledDefaultMb(uint64_t totalRamBytes, uint64_t divisor)
{
  const uint64_t mb = (totalRamBytes >> 20) / (divisor ? divisor : 1);
  return mb < 256 ? 256 : (mb > 1024 ? 1024 : mb);
}

inline uint64_t parseNumber(const char* s, uint64_t def)
{
  if (!s || !*s)
    return def;
  uint64_t v = 0;
  for (const char* p = s; *p; ++p) {
    if (*p < '0' || *p > '9')
      return def;
    const uint64_t d = static_cast<uint64_t>(*p - '0');
    if (v > (UINT64_MAX - d) / 10)
      return def;
    v = v * 10 + d;
  }
  return v;
}

// "0", "false", "off", "no" disable; any other non-empty value enables
inline bool parseFlag(const char* s, bool def)
{
  if (!s || !*s)
    return def;
  auto eq = [&](const char* w) {
    const char* a = s;
    const char* b = w;
    for (; *a && *b; ++a, ++b) {
      char ca = (*a >= 'A' && *a <= 'Z') ? static_cast<char>(*a + 32) : *a;
      if (ca != *b)
        return false;
    }
    return *a == 0 && *b == 0;
  };
  if (eq("0") || eq("false") || eq("off") || eq("no"))
    return false;
  return true;
}

}  // namespace usvfs::readcache::logic
