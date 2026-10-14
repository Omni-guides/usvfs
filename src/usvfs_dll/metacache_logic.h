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

// Pure logic and data structures of the metadata cache (metacache.cpp): path
// normalization, mask matching, directory record packing and the LRU store with
// its invalidation rules. No Windows or ntdll dependencies, so it can be unit
// tested.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace usvfs::metacache::logic
{

// ---------------------------------------------------------------------------
// paths

// upper-casing of non-ASCII characters (RtlUpcaseUnicodeChar in the DLL); when
// not set they are compared exactly, which can only cause misses
inline wchar_t (*g_upcaseHook)(wchar_t) = nullptr;

inline wchar_t foldChar(wchar_t c)
{
  if (c >= L'a' && c <= L'z')
    return static_cast<wchar_t>(c - L'a' + L'A');
  if (c == L'/')
    return L'\\';
  if (c >= 0x80 && g_upcaseHook)
    return g_upcaseHook(c);
  return c;
}

// upper case, '/' -> '\\', no trailing backslash (except for a bare root)
inline std::wstring normalizePath(std::wstring_view path)
{
  std::wstring out;
  out.reserve(path.size());
  for (wchar_t c : path)
    out.push_back(foldChar(c));
  while (out.size() > 1 && out.back() == L'\\' &&
         !(out.size() >= 2 && out[out.size() - 2] == L':'))
    out.pop_back();
  return out;
}

// ---- front cache keys ----

inline bool frontIsSep(wchar_t c)
{
  return c == L'\\' || c == L'/';
}

inline bool frontIsDriveAbs(std::wstring_view p)
{
  return p.size() >= 3 &&
         ((p[0] >= L'a' && p[0] <= L'z') || (p[0] >= L'A' && p[0] <= L'Z')) &&
         p[1] == L':' && frontIsSep(p[2]);
}

// Key of the front cache (virtual path exactly as the application passed it):
// absolute drive path, folded and with unified separators. `cwd` is used for
// relative names. Empty if the name is not safe to cache: anything that the
// system would interpret (".", "..", trailing dot/space/separator, streams,
// wildcards, device/UNC/\\?\ forms, drive-relative names, empty segments).
inline std::wstring frontKey(std::wstring_view path, std::wstring_view cwd,
                             int* why = nullptr)
{
  auto fail = [&](int code) {
    if (why)
      *why = code;
    return std::wstring();
  };
  if (path.empty() || path.size() > 32000)
    return fail(2);

  std::wstring abs;
  if (frontIsDriveAbs(path)) {
    abs = std::wstring(path);
  } else if (frontIsSep(path[0])) {
    // rooted without drive: take the drive of the cwd; UNC / device forms out
    if (path.size() < 2 || frontIsSep(path[1]) || !frontIsDriveAbs(cwd))
      return fail(3);
    abs = std::wstring(cwd.substr(0, 2)) + std::wstring(path);
  } else {
    if (path.size() >= 2 && path[1] == L':')
      return fail(4);  // drive-relative
    if (!frontIsDriveAbs(cwd))
      return fail(5);
    while (cwd.size() > 3 && frontIsSep(cwd.back()))
      cwd.remove_suffix(1);
    abs = std::wstring(cwd);
    if (!frontIsSep(abs.back()))
      abs.push_back(L'\\');
    abs.append(path);
  }

  // validate segments after "X:\"
  size_t pos = 3;
  while (pos < abs.size()) {
    size_t end = pos;
    while (end < abs.size() && !frontIsSep(abs[end]))
      ++end;
    const std::wstring_view seg(abs.data() + pos, end - pos);
    if (seg.empty() || seg == L"." || seg == L".." || seg.back() == L'.' ||
        seg.back() == L' ')
      return fail(6);
    for (wchar_t c : seg) {
      if (c < 32 || c == L':' || c == L'*' || c == L'?' || c == L'<' || c == L'>' ||
          c == L'"' || c == L'|')
        return fail(7);
    }
    pos = end + 1;
  }
  if (abs.size() > 3 && frontIsSep(abs.back()))
    return fail(8);  // trailing separator (a segment ending there is empty above)
  return normalizePath(abs);
}

// Key of an enumeration front-cache entry for FindFirstFileExW(path, ...): the
// directory (frontKey rules) plus the folded mask and the search parameters.
// Empty if the search is not cacheable. `cwd` is used for a bare mask and for
// relative directories.
inline std::wstring frontEnumKey(std::wstring_view path, std::wstring_view cwd,
                                 int infoLevel, unsigned long flags,
                                 std::wstring* dirKeyOut = nullptr, int* why = nullptr)
{
  auto fail = [&](int code) {
    if (why)
      *why = code;
    return std::wstring();
  };
  if (path.empty())
    return fail(10);
  if (infoLevel != 0 && infoLevel != 1)
    return fail(11);
  if ((flags & ~6ul) != 0)  // large fetch / on-disk-only do not change the result
    return fail(12);
  const size_t pos = path.find_last_of(L"\\/");
  std::wstring dir;
  std::wstring_view mask;
  if (pos == std::wstring_view::npos) {
    if (path.size() >= 2 && path[1] == L':')
      return fail(13);  // drive-relative
    if (!frontIsDriveAbs(cwd))
      return fail(14);
    dir  = std::wstring(cwd);
    mask = path;
  } else {
    dir  = std::wstring(path.substr(0, pos));
    mask = path.substr(pos + 1);
    if (dir.size() == 2 && dir[1] == L':')
      dir.push_back(L'\\');
  }
  // the directory may carry trailing separators (the cwd of a bare mask, or a
  // doubled separator in "dir\\*"): Win32 normalisation collapses them
  while (dir.size() > 3 && frontIsSep(dir.back()))
    dir.pop_back();
  if (mask.empty() || mask.size() > 255)
    return fail(15);
  for (wchar_t c : mask) {
    if (c < 32 || c == L':')
      return fail(16);
  }
  int dirWhy                = 0;
  const std::wstring dirKey = frontKey(dir, cwd, &dirWhy);
  if (dirKey.empty())
    return fail(20 + dirWhy);
  if (dirKeyOut)
    *dirKeyOut = dirKey;
  std::wstring key = dirKey;
  key.push_back(L'\x03');
  key.push_back(static_cast<wchar_t>(L'0' + infoLevel));
  key.push_back(static_cast<wchar_t>(
      L'0' + (flags & 4)));  // large fetch does not change the result
  key.push_back(L'\x03');
  for (wchar_t c : mask)
    key.push_back(foldChar(c));
  return key;
}

// Visiting order of the enumeration front pre-warm (lower first): the "Data"
// directory (the last segment named data) and its direct children (what the game lists
// first) rank 0, every other directory ranks by its depth (breadth-first), below Data
// by 1 + depth. `vpath` uses '/' or '\\' separators.
inline int frontPrewarmRankByName(std::string_view vpath);

inline std::string normalizeDataRoot(std::string_view path)
{
  std::string r(path);
  for (char& c : r) {
    if (c == '\\')
      c = '/';
    else if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c + 32);
  }
  while (!r.empty() && r.back() == '/')
    r.pop_back();
  return r;
}

// With an explicit `dataRoot` (normalizeDataRoot form) the ranking is: the root,
// its direct children and every ancestor of the root rank 0 (ancestors must be
// walked to get there), all else 1 + depth. Without one, the name heuristic below.
inline int frontPrewarmRank(std::string_view vpath,
                            const std::string& dataRoot = std::string())
{
  if (!dataRoot.empty()) {
    const std::string v = normalizeDataRoot(vpath);
    auto depthOf        = [](const std::string& p) {
      int d = 0;
      for (size_t i = 0; i < p.size();) {
        size_t e = p.find('/', i);
        if (e == std::string::npos)
          e = p.size();
        if (e > i)
          ++d;
        i = e + 1;
      }
      return d;
    };
    if (v.empty() || v == dataRoot || dataRoot.compare(0, v.size() + 1, v + "/") == 0)
      return 0;  // root or an ancestor of it
    if (v.compare(0, dataRoot.size() + 1, dataRoot + "/") == 0 &&
        v.find('/', dataRoot.size() + 1) == std::string::npos)
      return 0;  // direct child
    return 1 + depthOf(v);
  }
  return frontPrewarmRankByName(vpath);
}

inline int frontPrewarmRankByName(std::string_view vpath)
{
  int depth = 0, dataAt = -1;
  size_t pos = 0;
  while (pos < vpath.size()) {
    size_t end = pos;
    while (end < vpath.size() && vpath[end] != '/' && vpath[end] != '\\')
      ++end;
    if (end > pos) {
      const std::string_view seg = vpath.substr(pos, end - pos);
      if (seg.size() == 4 && (seg[0] | 0x20) == 'd' && (seg[1] | 0x20) == 'a' &&
          (seg[2] | 0x20) == 't' && (seg[3] | 0x20) == 'a')
        dataAt = depth;
      ++depth;
    }
    pos = end + 1;
  }
  if (dataAt >= 0 && depth - 1 - dataAt <= 1)
    return 0;
  return 1 + depth;
}

// parent directory of a normalized path; empty if there is none
inline std::wstring parentPath(const std::wstring& normalized)
{
  const size_t pos = normalized.find_last_of(L'\\');
  if (pos == std::wstring::npos || pos == 0)
    return std::wstring();
  return normalized.substr(0, pos);
}

// true if `normalized` is `prefix` itself or lies below it
inline bool isUnderPrefix(const std::wstring& normalized, const std::wstring& prefix)
{
  if (prefix.empty() || normalized.size() < prefix.size())
    return false;
  if (normalized.compare(0, prefix.size(), prefix) != 0)
    return false;
  return normalized.size() == prefix.size() || normalized[prefix.size()] == L'\\' ||
         prefix.back() == L'\\';
}

// ---------------------------------------------------------------------------
// masks

// "" and "*" mean "everything" and are stored as "*". ("*.*" is deliberately
// NOT folded into it: at the NT level it requires a dot, and implementations
// differ in how they treat it.)
inline std::wstring normalizeMask(std::wstring_view mask)
{
  if (mask.empty() || mask == L"*")
    return L"*";
  std::wstring out;
  out.reserve(mask.size());
  for (wchar_t c : mask)
    out.push_back(foldChar(c));
  return out;
}

// DOS wildcards (< > ") have subtle semantics; those masks are not cached
inline bool isCacheableMask(std::wstring_view mask)
{
  return mask.find_first_of(L"<>\"") == std::wstring_view::npos;
}

inline bool isLiteralMask(std::wstring_view mask)
{
  return mask.find_first_of(L"*?") == std::wstring_view::npos;
}

// '*' matches any run of characters, '?' exactly one; case-insensitive (ASCII)
inline bool maskMatches(std::wstring_view pattern, std::wstring_view name)
{
  size_t p = 0, n = 0;
  size_t starP = std::wstring_view::npos, starN = 0;
  while (n < name.size()) {
    if (p < pattern.size() && pattern[p] == L'*') {
      starP = p++;
      starN = n;
    } else if (p < pattern.size() &&
               (pattern[p] == L'?' || foldChar(pattern[p]) == foldChar(name[n]))) {
      ++p;
      ++n;
    } else if (starP != std::wstring_view::npos) {
      p = starP + 1;
      n = ++starN;
    } else {
      return false;
    }
  }
  while (p < pattern.size() && pattern[p] == L'*')
    ++p;
  return p == pattern.size();
}

// Key of the "*" listing of the same directory/level/flags as `key` (built by
// frontEnumKey); empty if `key` is malformed.
inline std::wstring frontEnumStarKey(const std::wstring& key)
{
  const size_t last = key.rfind(L'\x03');
  if (last == std::wstring::npos || last == 0)
    return std::wstring();
  return key.substr(0, last + 1) + L"*";
}

// A mask whose result can be derived from the "*" listing: only literal names
// (matched exactly against the long and the short name; wildcard masks can
// match short names in ways the long names do not show), no trailing dot or
// space (stripped by the system).
inline bool isDerivableMask(std::wstring_view mask)
{
  if (mask.empty() || !isLiteralMask(mask) || !isCacheableMask(mask))
    return false;
  return mask.back() != L'.' && mask.back() != L' ';
}

// ---------------------------------------------------------------------------
// directory record packing

constexpr size_t kRecordAlign = 8;

inline size_t alignedSize(size_t rawLength)
{
  return (rawLength + kRecordAlign - 1) & ~(kRecordAlign - 1);
}

// Number of records starting at `first` that fit in `bufferSize` bytes when
// packed with 8 byte alignment (the last one needs no padding). 0 means not
// even the first fits (STATUS_BUFFER_OVERFLOW).
inline size_t countFitting(const std::vector<size_t>& rawLengths, size_t first,
                           size_t bufferSize, bool singleEntry)
{
  size_t offset = 0;
  size_t count  = 0;
  for (size_t i = first; i < rawLengths.size(); ++i) {
    if (offset + rawLengths[i] > bufferSize)
      break;
    ++count;
    offset += alignedSize(rawLengths[i]);
    if (singleEntry)
      break;
  }
  return count;
}

// size of the data written for `count` records starting at `first`
// (information value of the call)
inline size_t packedSize(const std::vector<size_t>& rawLengths, size_t first,
                         size_t count)
{
  if (count == 0)
    return 0;
  size_t offset = 0;
  for (size_t i = first; i + 1 < first + count; ++i)
    offset += alignedSize(rawLengths[i]);
  return offset + rawLengths[first + count - 1];
}

// ---------------------------------------------------------------------------
// store

struct Attr
{
  int32_t status      = 0;
  bool full           = false;  // allocation size / end of file are valid
  int64_t creation    = 0;
  int64_t access      = 0;
  int64_t write       = 0;
  int64_t change      = 0;
  int64_t allocation  = 0;
  int64_t endOfFile   = 0;
  uint32_t attributes = 0;
};

// strings stored back to back (no per-string header or allocation)
template <typename Ch>
class PackedSeq
{
public:
  size_t size() const { return m_ends.size(); }
  void push_back(std::basic_string_view<Ch> v)
  {
    m_data.append(v.data(), v.size());
    m_ends.push_back(static_cast<uint32_t>(m_data.size()));
  }
  std::basic_string_view<Ch> operator[](size_t i) const
  {
    const size_t b = i ? m_ends[i - 1] : 0;
    return std::basic_string_view<Ch>(m_data.data() + b, m_ends[i] - b);
  }

private:
  std::basic_string<Ch> m_data;
  std::vector<uint32_t> m_ends;
};

struct Listing
{
  PackedSeq<char> records;  // raw records, NextEntryOffset zeroed
  std::vector<size_t> rawLengths;
  PackedSeq<wchar_t> names;
  // hash of the folded name -> index (a multimap: collisions are verified against
  // `names`); much smaller than a map keyed by the folded strings
  std::unordered_multimap<uint64_t, uint32_t> byHash;
  size_t bytes = 0;

  static uint64_t hashFolded(std::wstring_view name, bool fold)
  {
    uint64_t h = 1469598103934665603ull;
    for (wchar_t c : name) {
      h ^= static_cast<uint16_t>(fold ? foldChar(c) : c);
      h *= 1099511628211ull;
    }
    return h;
  }

  void add(std::string_view record, std::wstring_view name)
  {
    rawLengths.push_back(record.size());
    // payload plus the container overheads of one entry (headers, hash node)
    bytes += record.size() + name.size() * sizeof(wchar_t) + 64;
    byHash.emplace(hashFolded(name, true), static_cast<uint32_t>(records.size()));
    records.push_back(record);
    names.push_back(name);
  }

  // indices (ascending) of the entries whose name equals `foldedName` (already
  // folded with foldChar, as normalizeMask does); empty if none
  std::vector<uint32_t> findLiteral(const std::wstring& foldedName) const
  {
    std::vector<uint32_t> out;
    auto range = byHash.equal_range(hashFolded(foldedName, false));
    for (auto it = range.first; it != range.second; ++it) {
      const std::wstring_view n = names[it->second];
      if (n.size() != foldedName.size())
        continue;
      bool same = true;
      for (size_t i = 0; i < n.size() && same; ++i)
        same = foldChar(n[i]) == foldedName[i];
      if (same)
        out.push_back(it->second);
    }
    std::sort(out.begin(), out.end());
    return out;
  }
};

struct StoreStats
{
  uint64_t attrHits = 0, attrNegativeHits = 0, attrMisses = 0;
  uint64_t listingHits = 0, listingMisses = 0, listingDerived = 0;
  uint64_t invalidations = 0, evictions = 0;
};

// passed to put*() to skip the generation check
constexpr uint64_t kAnyGeneration = UINT64_MAX;

class Store
{
public:
  explicit Store(uint64_t capBytes) : m_cap(capBytes) {}

  // Bumped by every invalidation. A query reads it before asking the system
  // and hands it to put*(): a result obtained before an invalidation that
  // happened meanwhile is dropped instead of re-storing stale data.
  uint64_t generation() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_generation;
  }

  // ---- attributes (keys are normalized paths) ----

  // a `full` entry satisfies both kinds of queries, a basic one only basic
  bool lookupAttr(const std::wstring& path, bool needFull, Attr& out)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = findAttr(path);
    if (it == m_attrs.end() ||
        (needFull && !it->second.attr.full && it->second.attr.status >= 0)) {
      ++m_stats.attrMisses;
      return false;
    }
    touch(it->second.lru);
    out = it->second.attr;
    if (out.status < 0) {
      ++m_stats.attrNegativeHits;
    } else {
      ++m_stats.attrHits;
    }
    return true;
  }

  void noteDerived()
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_stats.listingDerived;
  }

  bool hasListing(const std::wstring& dir, int cls, const std::wstring& mask)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto d = m_dirs.find(dir);
    if (d == m_dirs.end())
      return false;
    for (const ListSlot& slot : d->second) {
      if (slot.cls == cls && slot.mask == mask)
        return true;
    }
    return false;
  }

  bool hasAttr(const std::wstring& path)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return findAttr(path) != m_attrs.end();
  }

  void putAttr(const std::wstring& path, const Attr& attr,
               uint64_t generation = kAnyGeneration)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (isBlocked(path) || (generation != kAnyGeneration && generation != m_generation))
      return;
    auto it = findAttr(path);
    if (it != m_attrs.end()) {
      // keep a full entry rather than replacing it by a basic one
      if (it->second.attr.full && !attr.full && attr.status >= 0 &&
          it->second.attr.status >= 0) {
        touch(it->second.lru);
        return;
      }
      eraseAttr(it);
    }
    insertAttr(path, attr);
    evict();
  }

  // ---- directory listings ----

  std::shared_ptr<const Listing> lookupListing(const std::wstring& dir, int cls,
                                               const std::wstring& mask)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto d = m_dirs.find(dir);
    if (d != m_dirs.end()) {
      for (ListSlot& slot : d->second) {
        if (slot.cls == cls && slot.mask == mask) {
          touch(slot.lru);
          ++m_stats.listingHits;
          return slot.listing;
        }
      }
    }
    ++m_stats.listingMisses;
    return nullptr;
  }

  // the complete "*" listing of a directory in any information class (they all
  // carry every name); no statistics. Null if none is stored.
  std::shared_ptr<const Listing> lookupAnyStar(const std::wstring& dir)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto d = m_dirs.find(dir);
    if (d == m_dirs.end())
      return nullptr;
    for (ListSlot& slot : d->second) {
      if (slot.mask == L"*") {
        touch(slot.lru);
        return slot.listing;
      }
    }
    return nullptr;
  }

  void putListing(const std::wstring& dir, int cls, const std::wstring& mask,
                  std::shared_ptr<const Listing> listing, bool derived = false,
                  uint64_t generation = kAnyGeneration)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (isBlocked(dir) || m_volatileDirs.count(dir) ||
        (generation != kAnyGeneration && generation != m_generation))
      return;
    auto dirIt                   = m_dirs.try_emplace(dir).first;
    std::vector<ListSlot>& slots = dirIt->second;
    for (ListSlot& slot : slots) {
      if (slot.cls == cls && slot.mask == mask)
        return;  // somebody was faster
    }
    ListSlot slot;
    slot.cls     = cls;
    slot.mask    = mask;
    slot.listing = std::move(listing);
    {
      Node n;
      n.isAttr = false;
      n.dkey   = &dirIt->first;
      n.cls    = cls;
      n.mask   = std::make_unique<std::wstring>(mask);
      n.bytes  = slot.listing->bytes + dir.size() * 2 + 64;
      slot.lru = addLru(std::move(n));
    }
    m_bytes += slot.lru->bytes;
    if (derived)
      ++m_stats.listingDerived;
    slots.push_back(std::move(slot));
    evict();
  }

  // ---- invalidation ----

  // a path was (or is about to be) written/created/deleted/renamed: forget
  // what we know about it and its parent directory, and never cache either
  // again
  void invalidatePath(const std::wstring& path)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_stats.invalidations;
    ++m_generation;
    markVolatile(path);
  }

  // a directory was renamed/removed: everything below it is stale too. Above
  // the size threshold the whole cache is dropped instead of scanning.
  // a mapping of the virtual tree changed: results derived from it are stale
  void bumpGeneration()
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_generation;
  }

  void invalidateTree(const std::wstring& path)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_stats.invalidations;
    ++m_generation;
    markVolatile(path);

    if (m_attrs.size() + m_dirs.size() > kTreeScanLimit) {
      clearLocked();
      return;
    }
    for (auto it = m_attrs.begin(); it != m_attrs.end();) {
      // compare the interned directory first: no string is built for entries that
      // are clearly outside (or inside) the tree
      const std::wstring& entryDir = *m_dirNames[it->first.dir];
      const bool under             = entryDir.size() >= path.size()
                                         ? isUnderPrefix(entryDir, path)
                                         : isUnderPrefix(attrPath(it->first), path);
      if (under) {
        m_bytes -= std::min<uint64_t>(m_bytes, it->second.lru->bytes);
        m_lru.erase(it->second.lru);
        it = m_attrs.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = m_dirs.begin(); it != m_dirs.end();) {
      if (isUnderPrefix(it->first, path)) {
        for (ListSlot& slot : it->second) {
          m_bytes -= std::min<uint64_t>(m_bytes, slot.lru->bytes);
          m_lru.erase(slot.lru);
        }
        it = m_dirs.erase(it);
      } else {
        ++it;
      }
    }
  }

  // true if nothing under this path may be cached (volatile or excluded)
  bool isBlockedPath(const std::wstring& path)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_overflowed || isBlocked(path) || m_volatileDirs.count(path) != 0;
  }

  bool overflowed() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_overflowed;
  }

  bool isVolatile(const std::wstring& path)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return isBlocked(path) || m_volatilePaths.count(path) != 0 ||
           m_volatileDirs.count(path) != 0;
  }

  // nothing at or below this path is ever cached (e.g. the overwrite folder)
  void addNoCachePrefix(const std::wstring& prefix)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (std::find(m_noCache.begin(), m_noCache.end(), prefix) == m_noCache.end())
      m_noCache.push_back(prefix);
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    clearLocked();
  }

  // ---- introspection ----

  uint64_t bytes() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_bytes;
  }

  // true if more than `percent` of the memory cap is in use
  bool usedAbove(unsigned percent) const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_bytes > m_cap / 100 * percent;
  }

  bool nearlyFull() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_bytes > m_cap - m_cap / 10;
  }

  size_t attrCount() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_attrs.size();
  }

  // accounted bytes of attribute entries and of listings, and the entries in the
  // listings
  void breakdown(uint64_t& attrBytes, uint64_t& listBytes, uint64_t& listEntries) const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    attrBytes = listBytes = listEntries = 0;
    for (const Node& n : m_lru)
      (n.isAttr ? attrBytes : listBytes) += n.bytes;
    for (const auto& d : m_dirs) {
      for (const ListSlot& slot : d.second)
        listEntries += slot.listing->records.size();
    }
  }

  size_t listingCount() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t n = 0;
    for (const auto& d : m_dirs)
      n += d.second.size();
    return n;
  }

  StoreStats stats() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
  }

  // accounted cost of one attribute entry with a leaf name of `leafChars`
  static size_t attrCost(size_t leafChars) { return leafChars * 2 + 240; }

private:
  static constexpr size_t kTreeScanLimit = 200000;
  static constexpr size_t kMaxVolatile   = 200000;

  // key of an attribute entry: interned directory + leaf name (directories share
  // their long path prefixes, which dominated the per-entry cost)
  struct AttrKey
  {
    uint32_t dir = 0;
    std::wstring leaf;
    bool operator==(const AttrKey& o) const { return dir == o.dir && leaf == o.leaf; }
  };
  struct AttrKeyHash
  {
    size_t operator()(const AttrKey& k) const
    {
      return std::hash<std::wstring>()(k.leaf) * 31 + k.dir;
    }
  };

  struct Node
  {
    bool isAttr              = true;
    const AttrKey* akey      = nullptr;  // attr: key inside m_attrs (node-stable)
    const std::wstring* dkey = nullptr;  // listing: key inside m_dirs
    int cls                  = 0;
    std::unique_ptr<std::wstring> mask;  // listing only
    size_t bytes = 0;
  };
  using Lru = std::list<Node>;

  struct AttrSlot
  {
    Attr attr;
    Lru::iterator lru;
  };

  struct ListSlot
  {
    int cls = 0;
    std::wstring mask;
    std::shared_ptr<const Listing> listing;
    Lru::iterator lru;
  };

  Lru::iterator addLru(Node node)
  {
    m_lru.push_front(std::move(node));
    return m_lru.begin();
  }

  void touch(Lru::iterator it) { m_lru.splice(m_lru.begin(), m_lru, it); }

  bool isBlocked(const std::wstring& path) const
  {
    if (m_overflowed)
      return true;
    for (const std::wstring& prefix : m_noCache) {
      if (isUnderPrefix(path, prefix))
        return true;
    }
    return m_volatilePaths.count(path) != 0;
  }

  // ---- interned directories of attribute keys ----

  static void splitPath(const std::wstring& path, std::wstring_view& dir,
                        std::wstring_view& leaf)
  {
    const size_t pos = path.rfind(L'\\');
    if (pos == std::wstring::npos) {
      dir  = std::wstring_view();
      leaf = path;
    } else {
      dir  = std::wstring_view(path).substr(0, pos);
      leaf = std::wstring_view(path).substr(pos + 1);
    }
  }

  std::wstring attrPath(const AttrKey& k) const
  {
    const std::wstring& d = *m_dirNames[k.dir];
    std::wstring out;
    out.reserve(d.size() + 1 + k.leaf.size());
    out = d;
    out.push_back(L'\\');
    out += k.leaf;
    return out;
  }

  std::unordered_map<AttrKey, AttrSlot, AttrKeyHash>::iterator
  findAttr(const std::wstring& path)
  {
    std::wstring_view dir, leaf;
    splitPath(path, dir, leaf);
    auto d = m_dirIds.find(std::wstring(dir));
    if (d == m_dirIds.end())
      return m_attrs.end();
    AttrKey k;
    k.dir  = d->second;
    k.leaf = std::wstring(leaf);
    return m_attrs.find(k);
  }

  void insertAttr(const std::wstring& path, const Attr& attr)
  {
    std::wstring_view dir, leaf;
    splitPath(path, dir, leaf);
    uint32_t id;
    auto d = m_dirIds.find(std::wstring(dir));
    if (d != m_dirIds.end()) {
      id = d->second;
    } else {
      id = static_cast<uint32_t>(m_dirNames.size());
      d  = m_dirIds.emplace(std::wstring(dir), id).first;
      m_dirNames.push_back(&d->first);
      m_bytes += dir.size() * 2 + 96;  // never evicted: counted once
    }
    AttrKey k;
    k.dir  = id;
    k.leaf = std::wstring(leaf);
    AttrSlot slot;
    slot.attr = attr;
    auto it   = m_attrs.emplace(std::move(k), std::move(slot)).first;
    Node n;
    n.isAttr       = true;
    n.akey         = &it->first;
    n.bytes        = attrCost(leaf.size());
    it->second.lru = addLru(std::move(n));
    m_bytes += it->second.lru->bytes;
  }

  void eraseAttr(std::unordered_map<AttrKey, AttrSlot, AttrKeyHash>::iterator it)
  {
    m_bytes -= std::min<uint64_t>(m_bytes, it->second.lru->bytes);
    m_lru.erase(it->second.lru);
    m_attrs.erase(it);
  }

  void eraseDir(const std::wstring& dir)
  {
    auto d = m_dirs.find(dir);
    if (d == m_dirs.end())
      return;
    for (ListSlot& slot : d->second) {
      m_bytes -= std::min<uint64_t>(m_bytes, slot.lru->bytes);
      m_lru.erase(slot.lru);
    }
    m_dirs.erase(d);
  }

  void markVolatile(const std::wstring& path)
  {
    auto a = findAttr(path);
    if (a != m_attrs.end())
      eraseAttr(a);
    eraseDir(path);

    const std::wstring parent = parentPath(path);
    if (!parent.empty()) {
      eraseDir(parent);
      // a directory's own times/size change when an entry is added or removed
      auto pa = findAttr(parent);
      if (pa != m_attrs.end())
        eraseAttr(pa);
      m_volatileDirs.insert(parent);
      m_volatilePaths.insert(parent);
    }
    m_volatilePaths.insert(path);

    // The volatile sets cannot be forgotten without caching written paths again,
    // so when they grow too large caching is switched off for good.
    if (m_volatilePaths.size() + m_volatileDirs.size() > kMaxVolatile) {
      clearLocked();
      m_overflowed = true;
    }
  }

  void evict()
  {
    while (m_bytes > m_cap && !m_lru.empty()) {
      Node& victim = m_lru.back();
      ++m_stats.evictions;
      if (victim.isAttr) {
        auto a = m_attrs.find(*victim.akey);
        m_bytes -= std::min<uint64_t>(m_bytes, victim.bytes);
        if (a != m_attrs.end())
          m_attrs.erase(a);
        m_lru.pop_back();
      } else {
        auto d = m_dirs.find(*victim.dkey);
        m_bytes -= std::min<uint64_t>(m_bytes, victim.bytes);
        if (d != m_dirs.end()) {
          auto& slots = d->second;
          slots.erase(std::remove_if(slots.begin(), slots.end(),
                                     [&](const ListSlot& s) {
                                       return s.cls == victim.cls &&
                                              s.mask == *victim.mask;
                                     }),
                      slots.end());
          if (slots.empty())
            m_dirs.erase(d);
        }
        m_lru.pop_back();
      }
    }
  }

  void clearLocked()
  {
    ++m_generation;
    m_attrs.clear();
    m_dirs.clear();
    m_lru.clear();
    m_dirIds.clear();
    m_dirNames.clear();
    m_bytes = 0;
  }

  mutable std::mutex m_mutex;
  uint64_t m_cap;
  uint64_t m_bytes = 0;
  Lru m_lru;  // front = most recently used
  std::unordered_map<AttrKey, AttrSlot, AttrKeyHash> m_attrs;
  std::unordered_map<std::wstring, uint32_t> m_dirIds;  // interned attr directories
  std::vector<const std::wstring*> m_dirNames;          // id -> name (node-stable)
  std::unordered_map<std::wstring, std::vector<ListSlot>> m_dirs;
  std::unordered_set<std::wstring> m_volatilePaths;
  std::unordered_set<std::wstring> m_volatileDirs;
  std::vector<std::wstring> m_noCache;
  bool m_overflowed     = false;
  uint64_t m_generation = 0;
  StoreStats m_stats;
};

// ---------------------------------------------------------------------------
// negative derivation: "X does not exist" from a virtual directory whose complete
// contents are known (tree children + complete real listings)

enum class NegVerdict
{
  Unknown,
  FileNotFound,
  PathNotFound
};
enum class NegNode
{
  None,
  Dir,
  File
};  // node of the usvfs tree
enum class NegChild
{
  Present,
  Absent,
  Unknown
};  // name in the known contents

// Splits an absolute drive path ("\\??\\C:\\A\\B", "C:/A/B", ...) into its components
// ("C:", "A", "B"). False for anything the system would interpret: empty
// segments, "." / "..", wildcards, streams, trailing dot/space, device/UNC forms.
inline bool negSplit(std::wstring_view path, std::vector<std::wstring>& comps)
{
  comps.clear();
  if (path.size() >= 4 && path.compare(0, 4, L"\\??\\") == 0)
    path.remove_prefix(4);
  if (path.empty() || path.size() > 32000)
    return false;
  size_t i = 0;
  while (i <= path.size()) {
    size_t e = i;
    while (e < path.size() && path[e] != L'\\' && path[e] != L'/')
      ++e;
    std::wstring_view seg = path.substr(i, e - i);
    if (seg.empty() || seg == L"." || seg == L"..")
      return false;
    if (comps.empty()) {
      const bool letter =
          (seg[0] >= L'a' && seg[0] <= L'z') || (seg[0] >= L'A' && seg[0] <= L'Z');
      if (seg.size() != 2 || !letter || seg[1] != L':')
        return false;
    } else {
      if (seg.find_first_of(L"*?<>\":|") != std::wstring_view::npos)
        return false;
      if (seg.back() == L'.' || seg.back() == L' ')
        return false;
    }
    for (wchar_t c : seg) {
      if (c < 0x20)
        return false;
    }
    comps.emplace_back(seg);
    if (e >= path.size())
      return true;  // no trailing separator accepted: the loop only ends here
    i = e + 1;
  }
  return false;
}

// a name that may be (or collide with) a generated 8.3 short name: never derived
inline bool negMayBeShortName(std::wstring_view name)
{
  return name.find(L'~') != std::wstring_view::npos;
}

// Decision for a path of `n` components. `node(k)` classifies the tree node of
// the first k components, `child(p)` says whether component p is present in the
// complete contents of the directory formed by the first p components (only asked
// for the deepest ancestor that is a directory node). FILE_NOT_FOUND when that
// ancestor is the parent, PATH_NOT_FOUND when an intermediate directory is missing.
inline NegVerdict deriveNegative(size_t n, const std::function<NegNode(size_t)>& node,
                                 const std::function<NegChild(size_t)>& child)
{
  if (n < 2)
    return NegVerdict::Unknown;
  if (node(n) != NegNode::None)
    return NegVerdict::Unknown;  // the name itself is mapped
  for (size_t p = n - 1; p >= 1; --p) {
    const NegNode k = node(p);
    if (k == NegNode::None)
      continue;
    if (k == NegNode::File)
      return NegVerdict::Unknown;
    if (child(p) != NegChild::Absent)
      return NegVerdict::Unknown;
    return p == n - 1 ? NegVerdict::FileNotFound : NegVerdict::PathNotFound;
  }
  return NegVerdict::Unknown;
}

}  // namespace usvfs::metacache::logic
