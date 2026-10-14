#pragma once

// On-disk format of the file-API trace written by trace.cpp (USVFS_TRACE) and
// read by replay.exe. Pure (no Windows headers) so it can be unit tested.
//
// file    = FileHeader, then blocks
// block   = u32 payloadSize, payload = back to back records of ONE thread
// record  = u8 op, u16 presence mask, varint fields (only those whose mask bit is
//           set, in field order); StringDef records carry id + UTF-16 text instead
//
// All multi-byte values are little endian (the header is stored as is).

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace usvfs::trace
{

enum class Op : uint8_t
{
  StringDef     = 1,
  Create        = 2,
  Open          = 3,
  Read          = 4,
  QueryInfo     = 5,
  SetInfo       = 6,
  QueryDir      = 7,
  QueryDirEx    = 8,
  QueryAttr     = 9,
  QueryFullAttr = 10,
  Close         = 11,
  // kernel32-level calls made by the application (the usvfs kernel32 hooks)
  GetAttr     = 12,  // GetFileAttributesW
  GetAttrEx   = 13,  // GetFileAttributesExW
  FindFirst   = 14,  // FindFirstFileExW (the enumeration is replayed to its end)
  ProfString  = 15,  // GetPrivateProfileString[AW]
  ProfSection = 16,  // GetPrivateProfileSection[AW]
  WriteMarker = 17,  // DeleteFile/MoveFile/WritePrivateProfileString: never replayed
  FindNext    = 18,  // FindNextFileW (hooked only for the trace)
  FindClose   = 19,  // FindClose (hooked only for the trace)
  SetCwd      = 20,  // current directory: once at start, then SetCurrentDirectoryW
};

constexpr int kOpCount = 21;

inline const char* opName(Op op)
{
  switch (op) {
  case Op::StringDef:
    return "StringDef";
  case Op::Create:
    return "NtCreateFile";
  case Op::Open:
    return "NtOpenFile";
  case Op::Read:
    return "NtReadFile";
  case Op::QueryInfo:
    return "NtQueryInformationFile";
  case Op::SetInfo:
    return "NtSetInformationFile";
  case Op::QueryDir:
    return "NtQueryDirectoryFile";
  case Op::QueryDirEx:
    return "NtQueryDirectoryFileEx";
  case Op::QueryAttr:
    return "NtQueryAttributesFile";
  case Op::QueryFullAttr:
    return "NtQueryFullAttributesFile";
  case Op::Close:
    return "NtClose";
  case Op::GetAttr:
    return "GetFileAttributesW";
  case Op::GetAttrEx:
    return "GetFileAttributesExW";
  case Op::FindFirst:
    return "FindFirstFileExW";
  case Op::ProfString:
    return "GetPrivateProfileString";
  case Op::ProfSection:
    return "GetPrivateProfileSection";
  case Op::WriteMarker:
    return "WriteMarker";
  case Op::FindNext:
    return "FindNextFileW";
  case Op::FindClose:
    return "FindClose";
  case Op::SetCwd:
    return "SetCurrentDirectoryW";
  }
  return "?";
}

constexpr char kMagic[8]    = {'U', 'S', 'V', 'T', 'R', 'C', '1', 0};
constexpr uint32_t kVersion = 1;
constexpr uint32_t kFlagCrc = 1;  // read records carry a crc32 of the returned data

struct FileHeader
{
  char magic[8];
  uint32_t version;
  uint32_t flags;
  uint64_t qpcFreq;
  uint64_t qpcBase;  // QPC value that timestamps are relative to
  uint32_t pid;
  uint32_t reserved;
};
static_assert(sizeof(FileHeader) == 40);

// Field meaning per op (unset fields are 0):
//   Create : h=resulting handle, h2=RootDirectory, a=access, b=share,
//            c=disposition, d=options, e=file attributes, str=path
//   Open   : h, h2, a=access, b=share, d=options, str
//   Read   : h, a=length, b=1 if ByteOffset was non-null, off=its value (-2 = use
//            file pointer), info=IoStatusBlock.Information, crc (optional)
//   QueryInfo: h, a=class, b=length, info
//   SetInfo: h, a=class, b=length, off=new position (class 14 only), info
//   QueryDir/Ex: h, a=class, b=length, c=flags (1=restart, 2=single; the Ex
//            QueryFlags as passed), str=mask (0 = none), info=bytes returned
//   QueryAttr/QueryFullAttr: h2=RootDirectory, str=path
//   Close  : h
//   kernel32 ops: `status` is the call's result (attributes / BOOL / 1 if the find
//            handle is valid / returned length), `info` the GetLastError on failure.
//   GetAttr: str=path.  GetAttrEx: str, a=info level.
//   FindFirst: str=path, a=info level, b=search op, c=additional flags, h=find handle
//   ProfString: str=file, a=app name str id (0 = NULL), b=key name str id (0 = NULL),
//            c=nSize, d=1 if the ANSI function was called (strings stored widened)
//   ProfSection: str=file, a=app name str id, c=nSize, d as above
//   FindNext: h=find handle, status=BOOL.  FindClose: h, status=BOOL.
//   SetCwd: str=directory, status=BOOL (the first record is the directory at DLL init)
//   WriteMarker: str=first path, a=1 delete / 2 move / 3 profile write
// All ops: tid, ts (QPC ticks since qpcBase, at hook entry), dur (ticks spent in
// the call), status (NTSTATUS as returned to the application).
struct Record
{
  Op op           = Op::Close;
  uint32_t tid    = 0;
  uint64_t ts     = 0;
  uint64_t dur    = 0;
  uint64_t h      = 0;
  uint64_t h2     = 0;
  uint64_t a      = 0;
  uint64_t b      = 0;
  uint64_t c      = 0;
  uint64_t d      = 0;
  int64_t off     = 0;
  uint32_t status = 0;
  uint64_t info   = 0;
  uint32_t str    = 0;  // string table id, 0 = none
  bool hasCrc     = false;
  uint32_t crc    = 0;
  uint64_t e      = 0;
  std::wstring text;  // StringDef only; its id is in `str`

  bool operator==(const Record&) const = default;
};

inline void putVarint(std::vector<uint8_t>& out, uint64_t v)
{
  while (v >= 0x80) {
    out.push_back(static_cast<uint8_t>(v | 0x80));
    v >>= 7;
  }
  out.push_back(static_cast<uint8_t>(v));
}

// false on truncated/overlong input
inline bool getVarint(const uint8_t*& p, const uint8_t* end, uint64_t& v)
{
  v = 0;
  for (int shift = 0; shift < 70; shift += 7) {
    if (p >= end)
      return false;
    const uint8_t byte = *p++;
    v |= static_cast<uint64_t>(byte & 0x7f) << shift;
    if (!(byte & 0x80))
      return true;
  }
  return false;
}

inline uint64_t zigzag(int64_t v)
{
  return (static_cast<uint64_t>(v) << 1) ^ static_cast<uint64_t>(v >> 63);
}
inline int64_t unzigzag(uint64_t v)
{
  return static_cast<int64_t>(v >> 1) ^ -static_cast<int64_t>(v & 1);
}

// field slots in the presence mask, in encoding order
enum Field : unsigned
{
  F_Tid,
  F_Ts,
  F_Dur,
  F_H,
  F_H2,
  F_A,
  F_B,
  F_C,
  F_D,
  F_Off,
  F_Status,
  F_Info,
  F_Str,
  F_Crc,
  F_E,
  F_Count
};

inline void encodeRecord(const Record& r, std::vector<uint8_t>& out)
{
  out.push_back(static_cast<uint8_t>(r.op));
  if (r.op == Op::StringDef) {
    putVarint(out, r.str);
    putVarint(out, r.text.size());
    for (wchar_t ch : r.text) {
      out.push_back(static_cast<uint8_t>(ch & 0xff));
      out.push_back(static_cast<uint8_t>((ch >> 8) & 0xff));
    }
    return;
  }

  const uint64_t v[F_Count] = {r.tid,    r.ts,   r.dur, r.h,   r.h2,
                               r.a,      r.b,    r.c,   r.d,   zigzag(r.off),
                               r.status, r.info, r.str, r.crc, r.e};
  unsigned mask             = 0;
  for (unsigned i = 0; i < F_Count; ++i) {
    if (v[i] != 0 || (i == F_Crc && r.hasCrc))
      mask |= 1u << i;
  }
  out.push_back(static_cast<uint8_t>(mask & 0xff));
  out.push_back(static_cast<uint8_t>(mask >> 8));
  for (unsigned i = 0; i < F_Count; ++i) {
    if (mask & (1u << i))
      putVarint(out, v[i]);
  }
}

// Decodes one record; returns the number of bytes consumed, 0 on malformed input.
inline size_t decodeRecord(const uint8_t* data, size_t size, Record& r)
{
  const uint8_t* p   = data;
  const uint8_t* end = data + size;
  r                  = Record();
  if (p >= end)
    return 0;
  const uint8_t op = *p++;
  if (op < 1 || op >= kOpCount)
    return 0;
  r.op = static_cast<Op>(op);

  uint64_t x = 0;
  if (r.op == Op::StringDef) {
    uint64_t n = 0;
    if (!getVarint(p, end, x) || !getVarint(p, end, n))
      return 0;
    if (n > (static_cast<uint64_t>(end - p)) / 2)
      return 0;
    r.str = static_cast<uint32_t>(x);
    r.text.resize(static_cast<size_t>(n));
    for (uint64_t i = 0; i < n; ++i, p += 2)
      r.text[i] = static_cast<wchar_t>(p[0] | (p[1] << 8));
    return static_cast<size_t>(p - data);
  }

  if (end - p < 2)
    return 0;
  const unsigned mask = p[0] | (p[1] << 8);
  p += 2;
  if (mask >> F_Count)
    return 0;
  uint64_t v[F_Count] = {};
  for (unsigned i = 0; i < F_Count; ++i) {
    if (mask & (1u << i)) {
      if (!getVarint(p, end, v[i]))
        return 0;
    }
  }
  r.tid    = static_cast<uint32_t>(v[F_Tid]);
  r.ts     = v[F_Ts];
  r.dur    = v[F_Dur];
  r.h      = v[F_H];
  r.h2     = v[F_H2];
  r.a      = v[F_A];
  r.b      = v[F_B];
  r.c      = v[F_C];
  r.d      = v[F_D];
  r.off    = unzigzag(v[F_Off]);
  r.status = static_cast<uint32_t>(v[F_Status]);
  r.info   = v[F_Info];
  r.str    = static_cast<uint32_t>(v[F_Str]);
  r.hasCrc = (mask & (1u << F_Crc)) != 0;
  r.crc    = static_cast<uint32_t>(v[F_Crc]);
  r.e      = v[F_E];
  return static_cast<size_t>(p - data);
}

// crc32 (IEEE, reflected), table-less bitwise-by-nibble variant
inline uint32_t crc32Update(uint32_t crc, const void* data, size_t len)
{
  static const uint32_t table[16] = {0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
                                     0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
                                     0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
                                     0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c};
  const uint8_t* p                = static_cast<const uint8_t*>(data);
  crc                             = ~crc;
  for (size_t i = 0; i < len; ++i) {
    crc ^= p[i];
    crc = (crc >> 4) ^ table[crc & 0x0f];
    crc = (crc >> 4) ^ table[crc & 0x0f];
  }
  return ~crc;
}

}  // namespace usvfs::trace
