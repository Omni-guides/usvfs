#include <gtest/gtest.h>

#include "../../src/usvfs_dll/readcache_logic.h"

using namespace usvfs::readcache::logic;

namespace
{

HandleAttrs goodAttrs()
{
  HandleAttrs a;
  a.hasEventOrApc   = false;
  a.queriesOk       = true;
  a.deviceType      = kDeviceTypeDisk;
  a.directory       = false;
  a.mode            = kModeSynchronousNonAlert;
  a.access          = kAccessReadData | 0x100000 /* SYNCHRONIZE */;
  a.endOfFile       = 4096;
  a.firstReadLength = 3100;
  return a;
}

}  // namespace

// ---- eligibility -----------------------------------------------------------

TEST(ReadCacheEligibility, GoodHandleIsEligible)
{
  EXPECT_EQ(Eligibility::Eligible, evaluateEligibility(goodAttrs(), Limits{}));
}

TEST(ReadCacheEligibility, DiskFileSystemDeviceTypeIsAccepted)
{
  auto a       = goodAttrs();
  a.deviceType = kDeviceTypeDiskFileSystem;
  EXPECT_EQ(Eligibility::Eligible, evaluateEligibility(a, Limits{}));
  for (uint32_t t : {0x3u /* cdrom */, 0x13u /* cdrom fs */, 0x14u /* network fs */,
                     0x11u /* named pipe */, 0x0u}) {
    a.deviceType = t;
    EXPECT_EQ(Eligibility::NotDisk, evaluateEligibility(a, Limits{})) << t;
  }
}

TEST(ReadCacheEligibility, SynchronousAlertAlsoCounts)
{
  auto a = goodAttrs();
  a.mode = kModeSynchronousAlert;
  EXPECT_EQ(Eligibility::Eligible, evaluateEligibility(a, Limits{}));
}

TEST(ReadCacheEligibility, Rejections)
{
  Limits l;
  {
    auto a          = goodAttrs();
    a.hasEventOrApc = true;
    EXPECT_EQ(Eligibility::EventOrApc, evaluateEligibility(a, l));
  }
  {
    auto a      = goodAttrs();
    a.queriesOk = false;
    EXPECT_EQ(Eligibility::QueryFailed, evaluateEligibility(a, l));
  }
  {
    auto a       = goodAttrs();
    a.deviceType = 0x12;  // network file system
    EXPECT_EQ(Eligibility::NotDisk, evaluateEligibility(a, l));
  }
  {
    auto a      = goodAttrs();
    a.directory = true;
    EXPECT_EQ(Eligibility::Directory, evaluateEligibility(a, l));
  }
  {
    auto a = goodAttrs();
    a.mode = 0;  // overlapped / asynchronous handle
    EXPECT_EQ(Eligibility::NotSynchronous, evaluateEligibility(a, l));
  }
  {
    auto a = goodAttrs();
    a.mode |= kModeNoIntermediateBuffering;
    EXPECT_EQ(Eligibility::NoBuffering, evaluateEligibility(a, l));
  }
  {
    auto a   = goodAttrs();
    a.access = 0x100000;
    EXPECT_EQ(Eligibility::NotReadable, evaluateEligibility(a, l));
  }
  {
    auto a = goodAttrs();
    a.access |= kAccessWriteData;
    EXPECT_EQ(Eligibility::Writable, evaluateEligibility(a, l));
  }
  {
    auto a = goodAttrs();
    a.access |= kAccessAppendData;
    EXPECT_EQ(Eligibility::Writable, evaluateEligibility(a, l));
  }
  {
    auto a      = goodAttrs();
    a.endOfFile = l.maxFileBytes + 1;
    EXPECT_EQ(Eligibility::TooLarge, evaluateEligibility(a, l));
  }
  {
    auto a            = goodAttrs();
    a.firstReadLength = kSmallReadLimit;
    EXPECT_EQ(Eligibility::BigRead, evaluateEligibility(a, l));
  }
}

TEST(ReadCacheEligibility, FileLimitBoundaryAndBudget)
{
  Limits l;
  l.maxFileBytes = 1000;
  l.budgetBytes  = 500;

  auto a      = goodAttrs();
  a.endOfFile = 500;
  EXPECT_EQ(Eligibility::Eligible, evaluateEligibility(a, l));
  a.endOfFile = 501;  // above the budget, even though below the file cap
  EXPECT_EQ(Eligibility::TooLarge, evaluateEligibility(a, l));

  l.budgetBytes = 5000;
  a.endOfFile   = 1000;
  EXPECT_EQ(Eligibility::Eligible, evaluateEligibility(a, l));
  a.endOfFile = 1001;
  EXPECT_EQ(Eligibility::TooLarge, evaluateEligibility(a, l));
}

TEST(ReadCacheEligibility, SmallReadBoundary)
{
  auto a            = goodAttrs();
  a.firstReadLength = kSmallReadLimit - 1;
  EXPECT_EQ(Eligibility::Eligible, evaluateEligibility(a, Limits{}));
}

// ---- read planning ---------------------------------------------------------

TEST(ReadCachePlan, SequentialReadsUseShadowPosition)
{
  ReadPlan p = planRead(1000, 0, false, 0, 100, false);
  EXPECT_EQ(ReadAction::Copy, p.action);
  EXPECT_EQ(0u, p.offset);
  EXPECT_EQ(100u, p.count);
  EXPECT_EQ(100u, p.newPos);

  p = planRead(1000, p.newPos, false, 0, 100, false);
  EXPECT_EQ(ReadAction::Copy, p.action);
  EXPECT_EQ(100u, p.offset);
  EXPECT_EQ(200u, p.newPos);
}

TEST(ReadCachePlan, UseFilePointerSentinel)
{
  ReadPlan p = planRead(1000, 300, true, kUseFilePointerPosition, 50, false);
  EXPECT_EQ(ReadAction::Copy, p.action);
  EXPECT_EQ(300u, p.offset);
  EXPECT_EQ(350u, p.newPos);
}

TEST(ReadCachePlan, ExplicitOffsetMovesShadowPosition)
{
  ReadPlan p = planRead(1000, 300, true, 10, 50, false);
  EXPECT_EQ(ReadAction::Copy, p.action);
  EXPECT_EQ(10u, p.offset);
  EXPECT_EQ(50u, p.count);
  EXPECT_EQ(60u, p.newPos);
}

TEST(ReadCachePlan, ClampsAtEndOfFile)
{
  ReadPlan p = planRead(1000, 0, true, 990, 50, false);
  EXPECT_EQ(ReadAction::Copy, p.action);
  EXPECT_EQ(10u, p.count);
  EXPECT_EQ(1000u, p.newPos);
}

TEST(ReadCachePlan, AtOrPastEndOfFile)
{
  ReadPlan p = planRead(1000, 1000, false, 0, 50, false);
  EXPECT_EQ(ReadAction::EndOfFile, p.action);
  EXPECT_EQ(1000u, p.newPos);

  p = planRead(1000, 0, true, 5000, 50, false);
  EXPECT_EQ(ReadAction::EndOfFile, p.action);
  EXPECT_EQ(0u, p.newPos);  // explicit EOF read leaves the position alone
}

TEST(ReadCachePlan, PassthroughCases)
{
  EXPECT_EQ(ReadAction::Passthrough, planRead(1000, 0, false, 0, 50, true).action);
  EXPECT_EQ(ReadAction::Passthrough, planRead(1000, 0, false, 0, 0, false).action);
  // FILE_WRITE_TO_END_OF_FILE (-1) and other negative offsets
  EXPECT_EQ(ReadAction::Passthrough, planRead(1000, 0, true, -1, 50, false).action);
  EXPECT_EQ(ReadAction::Passthrough, planRead(1000, 0, true, -3, 50, false).action);
}

TEST(ReadCachePlan, EmptyFile)
{
  EXPECT_EQ(ReadAction::EndOfFile, planRead(0, 0, false, 0, 10, false).action);
}

// ---- LRU eviction ----------------------------------------------------------

TEST(ReadCacheLru, NothingToDoWithinBudget)
{
  std::vector<EvictCandidate> c{{100, false}, {100, false}};
  EXPECT_TRUE(selectEvictions(c, 200, 200).empty());
  EXPECT_TRUE(selectEvictions(c, 200, 1000).empty());
}

TEST(ReadCacheLru, EvictsOldestFirstUntilWithinBudget)
{
  std::vector<EvictCandidate> c{{100, false}, {100, false}, {100, false}, {100, false}};
  auto r = selectEvictions(c, 400, 250);
  ASSERT_EQ(2u, r.size());
  EXPECT_EQ(0u, r[0]);
  EXPECT_EQ(1u, r[1]);
}

TEST(ReadCacheLru, SkipsPinnedEntries)
{
  std::vector<EvictCandidate> c{{100, true}, {100, false}, {100, true}, {100, false}};
  auto r = selectEvictions(c, 400, 150);
  ASSERT_EQ(2u, r.size());
  EXPECT_EQ(1u, r[0]);
  EXPECT_EQ(3u, r[1]);
}

TEST(ReadCacheLru, AllPinnedMayExceedBudget)
{
  std::vector<EvictCandidate> c{{100, true}, {100, true}};
  EXPECT_TRUE(selectEvictions(c, 200, 50).empty());
}

TEST(ReadCacheLru, StopsAsSoonAsBudgetIsMet)
{
  std::vector<EvictCandidate> c{{300, false}, {100, false}, {100, false}};
  auto r = selectEvictions(c, 500, 250);
  ASSERT_EQ(1u, r.size());
  EXPECT_EQ(0u, r[0]);
}

TEST(ReadCacheLru, EvictionTargetLeavesHeadroom)
{
  EXPECT_EQ(900u, evictionTarget(1000));
  EXPECT_EQ(0u, evictionTarget(0));
  EXPECT_LT(evictionTarget(1ull << 30), 1ull << 30);

  // evicting down to the target frees enough that the next small fill is free
  std::vector<EvictCandidate> c(10, EvictCandidate{100, false});
  auto r = selectEvictions(c, 1050, evictionTarget(1000));
  EXPECT_EQ(2u, r.size());
}

// ---- admission -------------------------------------------------------------

TEST(ReadCacheAdmission, SmallReadBoundary)
{
  EXPECT_TRUE(isSmallRead(1));
  EXPECT_TRUE(isSmallRead(kSmallReadLimit - 1));
  EXPECT_FALSE(isSmallRead(kSmallReadLimit));
  EXPECT_FALSE(isSmallRead(8u << 20));
}

TEST(ReadCacheAdmission, AdmitsAtThreshold)
{
  EXPECT_FALSE(shouldAdmit(1, 8, false));
  EXPECT_FALSE(shouldAdmit(7, 8, false));
  EXPECT_TRUE(shouldAdmit(8, 8, false));
  EXPECT_TRUE(shouldAdmit(100, 8, false));
}

TEST(ReadCacheAdmission, ResidentEntryAdmitsImmediately)
{
  EXPECT_TRUE(shouldAdmit(1, 8, true));
}

TEST(ReadCacheAdmission, ZeroOrOneThresholdAdmitsFirstRead)
{
  EXPECT_TRUE(shouldAdmit(1, 0, false));
  EXPECT_TRUE(shouldAdmit(1, 1, false));
}

TEST(ReadCacheAdmission, SizeBuckets)
{
  EXPECT_EQ(0u, sizeBucket(0));
  EXPECT_EQ(0u, sizeBucket(64 * 1024 - 1));
  EXPECT_EQ(1u, sizeBucket(64 * 1024));
  EXPECT_EQ(1u, sizeBucket((1u << 20) - 1));
  EXPECT_EQ(2u, sizeBucket(1u << 20));
  EXPECT_EQ(2u, sizeBucket((8u << 20) - 1));
  EXPECT_EQ(3u, sizeBucket(8u << 20));
  EXPECT_EQ(3u, sizeBucket(64ull << 20));
  EXPECT_LT(sizeBucket(UINT64_MAX), kSizeBuckets);
}

// ---- layer 3 ---------------------------------------------------------------

TEST(ReadCacheSplit, Capability)
{
  auto a = goodAttrs();
  EXPECT_TRUE(splitCapable(a));
  a.deviceType = kDeviceTypeDiskFileSystem;
  EXPECT_TRUE(splitCapable(a));
  a.deviceType = 0x14;
  EXPECT_FALSE(splitCapable(a));
  a           = goodAttrs();
  a.directory = true;
  EXPECT_FALSE(splitCapable(a));
  a      = goodAttrs();
  a.mode = 0;
  EXPECT_FALSE(splitCapable(a));
  a = goodAttrs();
  a.mode |= kModeNoIntermediateBuffering;
  EXPECT_FALSE(splitCapable(a));
  a = goodAttrs();
  a.access |= kAccessWriteData;
  EXPECT_FALSE(splitCapable(a));
  a        = goodAttrs();
  a.access = 0;
  EXPECT_FALSE(splitCapable(a));
}

TEST(ReadCacheSplit, PlansEqualChunks)
{
  const uint64_t K = 1024;
  SplitPlan p      = planSplit(0, 1024 * K, 10000 * K, 256 * K, 256 * K);
  ASSERT_EQ(SplitAction::Split, p.action);
  EXPECT_EQ(1024 * K, p.total);
  ASSERT_EQ(4u, p.chunks.size());
  uint64_t sum = 0;
  for (size_t i = 0; i < p.chunks.size(); ++i) {
    EXPECT_EQ(i * 256 * K, p.chunks[i].offset);
    sum += p.chunks[i].length;
  }
  EXPECT_EQ(1024 * K, sum);
}

TEST(ReadCacheSplit, ShortTailChunk)
{
  const uint64_t K = 1024;
  SplitPlan p      = planSplit(100, 600 * K, 10000 * K, 256 * K, 256 * K);
  ASSERT_EQ(SplitAction::Split, p.action);
  ASSERT_EQ(3u, p.chunks.size());
  EXPECT_EQ(100u, p.chunks[0].offset);
  EXPECT_EQ(600 * K - 512 * K, p.chunks[2].length);
  EXPECT_EQ(100 + 512 * K, p.chunks[2].offset);
}

TEST(ReadCacheSplit, ClampsToEndOfFile)
{
  const uint64_t K = 1024;
  // 1 MiB requested but only 300 KiB left
  SplitPlan p = planSplit(1000 * K, 1024 * K, 1300 * K, 256 * K, 256 * K);
  ASSERT_EQ(SplitAction::Split, p.action);
  EXPECT_EQ(300 * K, p.total);
  ASSERT_EQ(2u, p.chunks.size());
  EXPECT_EQ(256 * K, p.chunks[0].length);
  EXPECT_EQ(44 * K, p.chunks[1].length);
}

TEST(ReadCacheSplit, EndOfFileAndNotWorthIt)
{
  const uint64_t K = 1024;
  EXPECT_EQ(SplitAction::EndOfFile,
            planSplit(1000 * K, 1024 * K, 1000 * K, 256 * K, 256 * K).action);
  EXPECT_EQ(SplitAction::EndOfFile,
            planSplit(2000 * K, 1024 * K, 1000 * K, 256 * K, 256 * K).action);
  // below the minimum length
  EXPECT_EQ(SplitAction::Passthrough,
            planSplit(0, 128 * K, 10000 * K, 256 * K, 256 * K).action);
  // only one chunk worth of data left
  EXPECT_EQ(SplitAction::Passthrough,
            planSplit(900 * K, 1024 * K, 1000 * K, 256 * K, 256 * K).action);
  EXPECT_EQ(SplitAction::Passthrough,
            planSplit(0, 0, 1000 * K, 256 * K, 256 * K).action);
}

TEST(ReadCacheSequential, Detection)
{
  SeqState s;
  EXPECT_FALSE(updateSequential(s, 0, 100));   // first read
  EXPECT_TRUE(updateSequential(s, 100, 100));  // continues
  EXPECT_EQ(1u, s.run);
  EXPECT_TRUE(updateSequential(s, 200, 50));
  EXPECT_EQ(2u, s.run);
  EXPECT_GE(s.run, kSequentialRunForReadahead);
  EXPECT_FALSE(updateSequential(s, 1000, 50));  // jump
  EXPECT_EQ(0u, s.run);
  EXPECT_TRUE(updateSequential(s, 1050, 10));
  EXPECT_EQ(1u, s.run);
}

TEST(ReadCacheReadahead, WindowPlanning)
{
  const uint64_t M = 1u << 20;
  WindowPlan w     = planWindow(10 * M, 1 * M, 100 * M, 64 * M);
  EXPECT_EQ(10 * M, w.start);
  EXPECT_EQ(2 * M, w.length);

  // capped at 4 MiB
  EXPECT_EQ(4 * M, planWindow(0, 8 * M, 100 * M, 64 * M).length);
  // capped by the end of the file
  EXPECT_EQ(1 * M, planWindow(99 * M, 4 * M, 100 * M, 64 * M).length);
  EXPECT_EQ(0u, planWindow(100 * M, 1 * M, 100 * M, 64 * M).length);
  // capped by the memory budget left, none if exhausted
  EXPECT_EQ(512u * 1024, planWindow(0, 1 * M, 100 * M, 512 * 1024).length);
  EXPECT_EQ(0u, planWindow(0, 1 * M, 100 * M, 0).length);
}

TEST(ReadCacheReadahead, SmallReadsGetAtMostOneMegabyte)
{
  const uint64_t M = 1u << 20;
  EXPECT_EQ(1 * M, planWindow(0, 600 * 1024, 100 * M, 64 * M).length);
  EXPECT_EQ(512u * 1024, planWindow(0, 256 * 1024, 100 * M, 64 * M).length);
  EXPECT_EQ(2 * M, planWindow(0, 1 * M, 100 * M, 64 * M).length);
}

TEST(ReadCacheReadahead, CoverageAndRenewal)
{
  EXPECT_TRUE(windowCovers(100, 100, 100, 100));
  EXPECT_TRUE(windowCovers(100, 100, 150, 50));
  EXPECT_FALSE(windowCovers(100, 100, 150, 51));
  EXPECT_FALSE(windowCovers(100, 100, 99, 10));
  EXPECT_FALSE(windowCovers(100, 100, 100, 0));

  EXPECT_TRUE(needNewWindow(false, 0, 0, 0, 10));
  EXPECT_FALSE(needNewWindow(true, 100, 100, 100, 50));  // room for another read
  EXPECT_FALSE(needNewWindow(true, 100, 100, 150, 50));
  EXPECT_TRUE(needNewWindow(true, 100, 100, 151, 50));  // can't satisfy the next one
  EXPECT_TRUE(needNewWindow(true, 100, 100, 50, 10));   // behind the window
}

TEST(ReadCacheReadahead, NextWindowWhenHalfConsumed)
{
  EXPECT_FALSE(needNextWindow(false, 0, 100, false, 90));
  EXPECT_FALSE(needNextWindow(true, 100, 100, false, 149));
  EXPECT_TRUE(needNextWindow(true, 100, 100, false, 150));
  EXPECT_TRUE(needNextWindow(true, 100, 100, false, 200));
  EXPECT_FALSE(needNextWindow(true, 100, 100, true, 200));  // already queued
}

TEST(ReadCacheReadahead, BigBuckets)
{
  EXPECT_EQ(0u, bigBucket(64 * 1024));
  EXPECT_EQ(0u, bigBucket(256 * 1024 - 1));
  EXPECT_EQ(1u, bigBucket(256 * 1024));
  EXPECT_EQ(2u, bigBucket(1u << 20));
  EXPECT_EQ(3u, bigBucket(4u << 20));
  EXPECT_LT(bigBucket(UINT64_MAX), kBigBuckets);
}

// ---- configuration ---------------------------------------------------------

TEST(ReadCacheConfig, ParseNumber)
{
  EXPECT_EQ(7u, parseNumber(nullptr, 7));
  EXPECT_EQ(7u, parseNumber("", 7));
  EXPECT_EQ(7u, parseNumber("abc", 7));
  EXPECT_EQ(7u, parseNumber("12x", 7));
  EXPECT_EQ(7u, parseNumber("-3", 7));
  EXPECT_EQ(0u, parseNumber("0", 7));
  EXPECT_EQ(1024u, parseNumber("1024", 7));
  EXPECT_EQ(7u, parseNumber("99999999999999999999999", 7));
}

TEST(ReadCacheConfig, ParseFlag)
{
  EXPECT_TRUE(parseFlag(nullptr, true));
  EXPECT_FALSE(parseFlag(nullptr, false));
  EXPECT_FALSE(parseFlag("0", true));
  EXPECT_FALSE(parseFlag("off", true));
  EXPECT_FALSE(parseFlag("FALSE", true));
  EXPECT_TRUE(parseFlag("1", false));
  EXPECT_TRUE(parseFlag("yes", false));
}
