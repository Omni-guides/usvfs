#include <gtest/gtest.h>

#include "../../src/usvfs_dll/trace_format.h"

using namespace usvfs::trace;

namespace
{
Record roundTrip(const Record& in, size_t* consumed = nullptr)
{
  std::vector<uint8_t> buf;
  encodeRecord(in, buf);
  Record out;
  const size_t n = decodeRecord(buf.data(), buf.size(), out);
  EXPECT_EQ(buf.size(), n);
  if (consumed)
    *consumed = n;
  return out;
}
}  // namespace

TEST(TraceFormat, VarintAndZigzag)
{
  for (uint64_t v :
       std::initializer_list<uint64_t>{0, 1, 127, 128, 300, 0xffffffffull, ~0ull}) {
    std::vector<uint8_t> b;
    putVarint(b, v);
    const uint8_t* p = b.data();
    uint64_t out     = 0;
    ASSERT_TRUE(getVarint(p, b.data() + b.size(), out));
    EXPECT_EQ(v, out);
    EXPECT_EQ(b.data() + b.size(), p);
  }
  for (int64_t v :
       std::initializer_list<int64_t>{0, 1, -1, -2, 4096, INT64_MIN, INT64_MAX})
    EXPECT_EQ(v, unzigzag(zigzag(v)));
}

TEST(TraceFormat, RoundTripFullRecord)
{
  Record r;
  r.op     = Op::Create;
  r.tid    = 1234;
  r.ts     = 987654321012ull;
  r.dur    = 55;
  r.h      = 0x1c4;
  r.h2     = 0x88;
  r.a      = 0x80100080;
  r.b      = 7;
  r.c      = 1;
  r.d      = 0x60;
  r.e      = 0x80;
  r.status = 0xc0000034;
  r.info   = 4096;
  r.str    = 17;
  EXPECT_EQ(r, roundTrip(r));
}

TEST(TraceFormat, ReadOffsetsAndCrc)
{
  Record r;
  r.op     = Op::Read;
  r.tid    = 9;
  r.h      = 0x20;
  r.a      = 65536;
  r.b      = 1;
  r.off    = -2;  // FILE_USE_FILE_POINTER_POSITION
  r.hasCrc = true;
  r.crc    = 0;  // a crc of 0 must survive
  EXPECT_EQ(r, roundTrip(r));

  r.off = 1ll << 40;
  r.crc = 0xdeadbeef;
  EXPECT_EQ(r, roundTrip(r));

  r.b              = 0;  // null ByteOffset
  r.off            = 0;
  r.hasCrc         = false;
  r.crc            = 0;
  const Record out = roundTrip(r);
  EXPECT_EQ(r, out);
  EXPECT_FALSE(out.hasCrc);
}

TEST(TraceFormat, StringDef)
{
  Record r;
  r.op   = Op::StringDef;
  r.str  = 300;
  r.text = L"\\??\\C:\\Games\\Data\\Skyrim - \u00dcber.bsa";
  EXPECT_EQ(r, roundTrip(r));

  r.text.clear();
  EXPECT_EQ(r, roundTrip(r));
}

TEST(TraceFormat, ConsecutiveRecordsAndTruncation)
{
  std::vector<uint8_t> buf;
  Record a;
  a.op  = Op::Close;
  a.tid = 1;
  a.h   = 5;
  Record b;
  b.op  = Op::QueryDir;
  b.tid = 2;
  b.c   = 3;
  b.str = 4;
  encodeRecord(a, buf);
  encodeRecord(b, buf);

  Record out;
  size_t n1 = decodeRecord(buf.data(), buf.size(), out);
  ASSERT_GT(n1, 0u);
  EXPECT_EQ(a, out);
  size_t n2 = decodeRecord(buf.data() + n1, buf.size() - n1, out);
  EXPECT_EQ(b, out);
  EXPECT_EQ(buf.size(), n1 + n2);

  // every truncation of the second record is rejected, never overread
  for (size_t cut = 0; cut < n2; ++cut)
    EXPECT_EQ(0u, decodeRecord(buf.data() + n1, cut, out));

  const uint8_t bad[] = {0xee, 0, 0};
  EXPECT_EQ(0u, decodeRecord(bad, sizeof(bad), out));
}

TEST(TraceFormat, Crc32)
{
  EXPECT_EQ(0xcbf43926u, crc32Update(0, "123456789", 9));
  // incremental == one shot
  uint32_t c = crc32Update(0, "1234", 4);
  c          = crc32Update(c, "56789", 5);
  EXPECT_EQ(0xcbf43926u, c);
  EXPECT_EQ(0u, crc32Update(0, "", 0));
}

TEST(TraceFormat, Kernel32Ops)
{
  Record r;
  r.op     = Op::ProfString;
  r.tid    = 3;
  r.str    = 10;
  r.a      = 11;
  r.b      = 12;
  r.c      = 260;
  r.d      = 1;
  r.status = 5;
  EXPECT_EQ(r, roundTrip(r));

  for (Op op : {Op::GetAttr, Op::GetAttrEx, Op::FindFirst, Op::ProfSection,
                Op::WriteMarker, Op::FindNext, Op::FindClose, Op::SetCwd}) {
    r.op = op;
    EXPECT_EQ(r, roundTrip(r));
  }
}
