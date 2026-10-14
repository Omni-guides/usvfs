#include <gtest/gtest.h>

#include "../../src/usvfs_dll/metacache_logic.h"

using namespace usvfs::metacache::logic;

// ---- paths -----------------------------------------------------------------

TEST(MetaCachePath, NormalizeFoldsCaseAndSlashes)
{
  EXPECT_EQ(LR"(\??\C:\GAMES\DATA\A.ESP)",
            normalizePath(LR"(\??\c:\Games/Data\a.esp)"));
  EXPECT_EQ(LR"(\??\C:\DIR)", normalizePath(LR"(\??\C:\dir\)"));
  EXPECT_EQ(LR"(\??\C:\)", normalizePath(LR"(\??\C:\)"));  // root keeps its slash
}

TEST(MetaCachePath, ParentAndPrefix)
{
  EXPECT_EQ(LR"(\??\C:\A)", parentPath(LR"(\??\C:\A\B)"));
  EXPECT_EQ(L"", parentPath(L"NOSLASH"));

  EXPECT_TRUE(isUnderPrefix(LR"(\??\C:\OVERWRITE\X)", LR"(\??\C:\OVERWRITE)"));
  EXPECT_TRUE(isUnderPrefix(LR"(\??\C:\OVERWRITE)", LR"(\??\C:\OVERWRITE)"));
  EXPECT_FALSE(isUnderPrefix(LR"(\??\C:\OVERWRITE2\X)", LR"(\??\C:\OVERWRITE)"));
  EXPECT_FALSE(isUnderPrefix(LR"(\??\C:\A)", L""));
}

// ---- masks -----------------------------------------------------------------

TEST(MetaCacheMask, Normalization)
{
  EXPECT_EQ(L"*", normalizeMask(L""));
  EXPECT_EQ(L"*", normalizeMask(L"*"));
  EXPECT_EQ(L"*.*", normalizeMask(L"*.*"));  // not folded into "*"
  EXPECT_EQ(L"FOO.ESP", normalizeMask(L"foo.esp"));
}

TEST(MetaCacheMask, Classification)
{
  EXPECT_TRUE(isLiteralMask(L"FOO.ESP"));
  EXPECT_FALSE(isLiteralMask(L"*.ESP"));
  EXPECT_FALSE(isLiteralMask(L"A?C"));
  EXPECT_TRUE(isCacheableMask(L"*.esp"));
  EXPECT_FALSE(isCacheableMask(L"*<"));
  EXPECT_FALSE(isCacheableMask(L"\"x"));
}

TEST(MetaCacheMask, Matching)
{
  EXPECT_TRUE(maskMatches(L"*", L"anything"));
  EXPECT_TRUE(maskMatches(L"*.esp", L"Skyrim.ESP"));
  EXPECT_FALSE(maskMatches(L"*.esp", L"Skyrim.esm"));
  EXPECT_TRUE(maskMatches(L"sky*.es?", L"SkyrimSE.esm"));
  EXPECT_TRUE(maskMatches(L"a?c", L"abc"));
  EXPECT_FALSE(maskMatches(L"a?c", L"ac"));
  EXPECT_FALSE(maskMatches(L"a?c", L"abbc"));
  EXPECT_TRUE(maskMatches(L"*a*b*", L"xxaxxbxx"));
  EXPECT_FALSE(maskMatches(L"*a*b*", L"xxbxxaxx"));
  EXPECT_TRUE(maskMatches(L"foo.esp", L"FOO.ESP"));
  EXPECT_FALSE(maskMatches(L"foo.esp", L"foo.esp2"));
  EXPECT_TRUE(maskMatches(L"**", L""));
  EXPECT_FALSE(maskMatches(L"?", L""));
}

// ---- record packing --------------------------------------------------------

TEST(MetaCachePack, AlignedSize)
{
  EXPECT_EQ(0u, alignedSize(0));
  EXPECT_EQ(8u, alignedSize(1));
  EXPECT_EQ(8u, alignedSize(8));
  EXPECT_EQ(16u, alignedSize(9));
}

TEST(MetaCachePack, CountFitting)
{
  const std::vector<size_t> r{10, 20, 30};  // aligned: 16, 24, 32
  // offsets: 0, 16, 40; ends: 10, 36, 70
  EXPECT_EQ(0u, countFitting(r, 0, 9, false));  // not even one fits
  EXPECT_EQ(1u, countFitting(r, 0, 10, false));
  EXPECT_EQ(1u, countFitting(r, 0, 35, false));
  EXPECT_EQ(2u, countFitting(r, 0, 36, false));
  EXPECT_EQ(2u, countFitting(r, 0, 69, false));
  EXPECT_EQ(3u, countFitting(r, 0, 70, false));
  EXPECT_EQ(1u, countFitting(r, 0, 1000, true));   // single entry
  EXPECT_EQ(1u, countFitting(r, 2, 30, false));    // starting in the middle
  EXPECT_EQ(0u, countFitting(r, 3, 1000, false));  // nothing left
}

TEST(MetaCachePack, PackedSize)
{
  const std::vector<size_t> r{10, 20, 30};
  EXPECT_EQ(0u, packedSize(r, 0, 0));
  EXPECT_EQ(10u, packedSize(r, 0, 1));
  EXPECT_EQ(16u + 20u, packedSize(r, 0, 2));
  EXPECT_EQ(16u + 24u + 30u, packedSize(r, 0, 3));
  EXPECT_EQ(24u + 30u, packedSize(r, 1, 2));
}

// ---- store: attributes, invalidation, eviction -------------------------------

namespace
{
Attr existing(int64_t eof = 100, bool full = true)
{
  Attr a;
  a.status    = 0;
  a.full      = full;
  a.endOfFile = eof;
  return a;
}

Attr missing()
{
  Attr a;
  a.status = static_cast<int32_t>(0xC0000034);
  return a;
}
}  // namespace

TEST(MetaCacheStore, HitMissAndNegative)
{
  Store s(1 << 20);
  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"A", true, out));

  s.putAttr(L"A", existing(42));
  ASSERT_TRUE(s.lookupAttr(L"A", true, out));
  EXPECT_EQ(42, out.endOfFile);

  s.putAttr(L"B", missing());
  ASSERT_TRUE(s.lookupAttr(L"B", true, out));
  EXPECT_LT(out.status, 0);

  const StoreStats st = s.stats();
  EXPECT_EQ(1u, st.attrHits);
  EXPECT_EQ(1u, st.attrNegativeHits);
  EXPECT_EQ(1u, st.attrMisses);
}

TEST(MetaCacheStore, BasicEntryDoesNotSatisfyFullQuery)
{
  Store s(1 << 20);
  s.putAttr(L"A", existing(0, false));
  Attr out;
  EXPECT_TRUE(s.lookupAttr(L"A", false, out));
  EXPECT_FALSE(s.lookupAttr(L"A", true, out));

  // a full entry then serves both and is not downgraded by a basic result
  s.putAttr(L"A", existing(7, true));
  EXPECT_TRUE(s.lookupAttr(L"A", true, out));
  s.putAttr(L"A", existing(0, false));
  ASSERT_TRUE(s.lookupAttr(L"A", true, out));
  EXPECT_EQ(7, out.endOfFile);
}

TEST(MetaCacheStore, InvalidateRemovesEntryAndParentListing)
{
  Store s(1 << 20);
  s.putAttr(L"\\D\\F", existing());
  auto l = std::make_shared<Listing>();
  l->add(std::string(8, 'x'), L"F");
  s.putListing(L"\\D", 37, L"*", l);
  s.putListing(L"\\OTHER", 37, L"*", l);

  s.invalidatePath(L"\\D\\F");

  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\D\\F", true, out));
  EXPECT_EQ(nullptr, s.lookupListing(L"\\D", 37, L"*"));
  EXPECT_NE(nullptr, s.lookupListing(L"\\OTHER", 37, L"*"));
  EXPECT_EQ(1u, s.stats().invalidations);
}

TEST(MetaCacheStore, WrittenPathsAndTheirDirectoryAreNeverCachedAgain)
{
  Store s(1 << 20);
  s.invalidatePath(L"\\D\\F");
  EXPECT_TRUE(s.isVolatile(L"\\D\\F"));
  EXPECT_TRUE(s.isVolatile(L"\\D"));

  s.putAttr(L"\\D\\F", existing());
  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\D\\F", true, out));

  auto l = std::make_shared<Listing>();
  s.putListing(L"\\D", 37, L"*", l);
  EXPECT_EQ(nullptr, s.lookupListing(L"\\D", 37, L"*"));

  // unrelated files in the same directory are still fine
  s.putAttr(L"\\D\\G", existing());
  EXPECT_TRUE(s.lookupAttr(L"\\D\\G", true, out));
}

TEST(MetaCacheStore, InvalidateTreeDropsEverythingBelow)
{
  Store s(1 << 20);
  s.putAttr(L"\\D\\SUB\\F", existing());
  s.putAttr(L"\\D\\SUB2\\F", existing());
  auto l = std::make_shared<Listing>();
  s.putListing(L"\\D\\SUB", 37, L"*", l);

  s.invalidateTree(L"\\D\\SUB");

  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\D\\SUB\\F", true, out));
  EXPECT_EQ(nullptr, s.lookupListing(L"\\D\\SUB", 37, L"*"));
  s.putAttr(L"\\D\\SUB2\\F", existing());  // sibling with a similar prefix is untouched
  EXPECT_TRUE(s.lookupAttr(L"\\D\\SUB2\\F", true, out));
}

TEST(MetaCacheStore, NoCachePrefix)
{
  Store s(1 << 20);
  s.addNoCachePrefix(L"\\OVERWRITE");
  s.putAttr(L"\\OVERWRITE\\A\\B", existing());
  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\OVERWRITE\\A\\B", true, out));
  auto l = std::make_shared<Listing>();
  s.putListing(L"\\OVERWRITE\\A", 37, L"*", l);
  EXPECT_EQ(nullptr, s.lookupListing(L"\\OVERWRITE\\A", 37, L"*"));
  s.putAttr(L"\\OVERWRITE2\\A", existing());
  EXPECT_TRUE(s.lookupAttr(L"\\OVERWRITE2\\A", true, out));
}

TEST(MetaCacheStore, LruEvictsLeastRecentlyUsedWithinCap)
{
  const std::wstring p1 = L"\\P\\1", p2 = L"\\P\\2", p3 = L"\\P\\3";
  // each entry costs Store::attrCost(leaf) plus the interned directory once; room for
  // two
  const size_t cap = 2 * Store::attrCost(1) + 2 * 2 + 96 + 10;
  Store s(cap);
  s.putAttr(p1, existing());
  s.putAttr(p2, existing());
  Attr out;
  ASSERT_TRUE(s.lookupAttr(p1, true, out));  // p1 is now the most recent
  s.putAttr(p3, existing());                 // evicts p2

  EXPECT_TRUE(s.lookupAttr(p1, true, out));
  EXPECT_FALSE(s.lookupAttr(p2, true, out));
  EXPECT_TRUE(s.lookupAttr(p3, true, out));
  EXPECT_LE(s.bytes(), cap);
  EXPECT_GE(s.stats().evictions, 1u);
}

TEST(MetaCacheStore, ListingsKeyedByClassAndMask)
{
  Store s(1 << 20);
  auto a = std::make_shared<Listing>();
  a->add(std::string(8, 'a'), L"A");
  s.putListing(L"\\D", 37, L"*", a);

  EXPECT_NE(nullptr, s.lookupListing(L"\\D", 37, L"*"));
  EXPECT_EQ(nullptr, s.lookupListing(L"\\D", 3, L"*"));
  EXPECT_EQ(nullptr, s.lookupListing(L"\\D", 37, L"*.ESP"));
  EXPECT_TRUE(s.hasListing(L"\\D", 37, L"*"));
  EXPECT_FALSE(s.hasListing(L"\\D", 3, L"*"));
}

TEST(MetaCacheStore, ChildWriteInvalidatesParentDirectoryAttributes)
{
  Store s(1 << 20);
  s.putAttr(L"\\D", existing());  // the directory itself
  s.putAttr(L"\\D\\F", existing());
  s.invalidatePath(L"\\D\\F");

  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\D", true, out));  // its times changed
  s.putAttr(L"\\D", existing());
  EXPECT_FALSE(s.lookupAttr(L"\\D", true, out));  // and are not trusted again
}

TEST(MetaCacheStore, BlockedPathCoversVolatileExcludedAndParents)
{
  Store s(1 << 20);
  EXPECT_FALSE(s.isBlockedPath(L"\\D"));
  s.addNoCachePrefix(L"\\OVR");
  EXPECT_TRUE(s.isBlockedPath(L"\\OVR\\X"));
  s.invalidatePath(L"\\D\\F");
  EXPECT_TRUE(s.isBlockedPath(L"\\D"));
  EXPECT_TRUE(s.isBlockedPath(L"\\D\\F"));
  EXPECT_FALSE(s.isBlockedPath(L"\\E"));
}

TEST(MetaCacheStore, TooManyWrittenPathsSwitchCachingOff)
{
  Store s(1 << 20);
  s.putAttr(L"\\A", existing());
  for (int i = 0; i < 210000; ++i)
    s.invalidatePath(L"\\W\\" + std::to_wstring(i));
  EXPECT_TRUE(s.overflowed());

  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\A", true, out));
  s.putAttr(L"\\B", existing());
  EXPECT_FALSE(s.lookupAttr(L"\\B", true, out));
}

TEST(MetaCachePath, NonAsciiFoldingUsesTheHookWhenSet)
{
  EXPECT_NE(normalizePath(L"\xE9"), normalizePath(L"\xC9"));  // without a hook: exact
  g_upcaseHook = [](wchar_t c) -> wchar_t {
    return c >= 0xE0 && c <= 0xFE ? c - 0x20 : c;
  };
  EXPECT_EQ(normalizePath(L"\xE9"), normalizePath(L"\xC9"));
  g_upcaseHook = nullptr;
}

TEST(MetaCacheStore, StaleResultFromBeforeAnInvalidationIsDropped)
{
  Store s(1 << 20);
  const uint64_t gen = s.generation();
  s.invalidatePath(L"\\D\\OTHER");  // happens while a query is in flight
  s.putAttr(L"\\D\\F", existing(), gen);
  Attr out;
  EXPECT_FALSE(s.lookupAttr(L"\\D\\F", true, out));

  s.putAttr(L"\\D\\F", existing(), s.generation());
  EXPECT_TRUE(s.lookupAttr(L"\\D\\F", true, out));

  const uint64_t gen2 = s.generation();
  s.clear();
  auto l = std::make_shared<Listing>();
  s.putListing(L"\\X", 37, L"*", l, false, gen2);
  EXPECT_EQ(nullptr, s.lookupListing(L"\\X", 37, L"*"));
}

TEST(MetaCacheListing, LiteralLookupByFoldedName)
{
  Listing l;
  l.add(std::string(8, 'a'), L"Foo.ESP");
  l.add(std::string(8, 'b'), L"bar.esm");
  l.add(std::string(8, 'c'), L"foo.esp");  // same name, different case

  const std::vector<uint32_t> hit = l.findLiteral(normalizeMask(L"FOO.esp"));
  ASSERT_EQ(2u, hit.size());
  EXPECT_EQ(0u, hit[0]);
  EXPECT_EQ(2u, hit[1]);
  EXPECT_TRUE(l.findLiteral(normalizeMask(L"nothing")).empty());
  EXPECT_FALSE(l.findLiteral(normalizeMask(L"BAR.ESM")).empty());
}

TEST(MetaCacheStore, UsedAboveReportsMemoryShare)
{
  Store s(10000);
  EXPECT_FALSE(s.usedAbove(60));
  auto l = std::make_shared<Listing>();
  for (int i = 0; i < 60; ++i)
    l->add(std::string(40, 'x'), L"NAME" + std::to_wstring(i));
  s.putListing(L"\\D", 37, L"*", l);
  EXPECT_TRUE(s.usedAbove(10));
  EXPECT_FALSE(s.usedAbove(99));
}

// ---- front cache keys --------------------------------------------------------

TEST(MetaCacheFront, AbsoluteAndRelative)
{
  EXPECT_EQ(LR"(C:\GAMES\DATA\A.ESP)", frontKey(LR"(c:/Games\data/a.esp)", L""));
  EXPECT_EQ(LR"(C:\)", frontKey(LR"(C:\)", L""));
  EXPECT_EQ(LR"(C:\GAME\DATA\A.ESP)", frontKey(LR"(Data\a.esp)", LR"(C:\Game)"));
  EXPECT_EQ(LR"(C:\GAME\DATA\A.ESP)", frontKey(LR"(Data\a.esp)", LR"(C:\Game\)"));
  EXPECT_EQ(LR"(C:\GAME\A.ESP)", frontKey(LR"(a.esp)", LR"(c:\game)"));
  EXPECT_EQ(LR"(D:\X\Y)", frontKey(LR"(\x\y)", LR"(D:\Game)"));
  // same file, different spelling: same key
  EXPECT_EQ(frontKey(LR"(C:\Game\Data\a.esp)", L""),
            frontKey(LR"(data/A.ESP)", LR"(C:\game)"));
}

TEST(MetaCacheFront, Rejected)
{
  EXPECT_EQ(L"", frontKey(L"", LR"(C:\G)"));
  EXPECT_EQ(L"", frontKey(L"a.esp", L""));           // no cwd
  EXPECT_EQ(L"", frontKey(L"a.esp", L"rel"));        // cwd not absolute
  EXPECT_EQ(L"", frontKey(L"C:a.esp", LR"(C:\G)"));  // drive-relative
  EXPECT_EQ(L"", frontKey(LR"(\\?\C:\a)", L""));
  EXPECT_EQ(L"", frontKey(LR"(\\.\pipe\x)", LR"(C:\G)"));
  EXPECT_EQ(L"", frontKey(LR"(\\srv\share\a)", LR"(C:\G)"));
  EXPECT_EQ(L"", frontKey(LR"(C:\a\..\b)", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a\.\b)", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a\)", L""));  // trailing separator
  EXPECT_EQ(L"", frontKey(LR"(C:\a.)", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a )", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a\\b)", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a\b:stream)", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a\*.esp)", L""));
  EXPECT_EQ(L"", frontKey(LR"(C:\a?)", L""));
}

TEST(MetaCacheFront, EnumKey)
{
  std::wstring dir;
  const std::wstring k = frontEnumKey(LR"(c:/Game\Data\*.ESP)", L"", 0, 0, &dir);
  EXPECT_EQ(LR"(C:\GAME\DATA)", dir);
  EXPECT_EQ(std::wstring(LR"(C:\GAME\DATA)") + L"\x03" + L"00" + L"\x03" + L"*.ESP", k);
  // relative directory and bare mask use the cwd
  EXPECT_EQ(k, frontEnumKey(LR"(Data\*.esp)", LR"(C:\Game)", 0, 0));
  EXPECT_EQ(k, frontEnumKey(L"*.esp", LR"(C:\Game\Data)", 0, 0));
  EXPECT_EQ(k, frontEnumKey(L"*.esp", LR"(C:\Game\Data\)", 0, 0));
  // search parameters are part of the key
  EXPECT_NE(k, frontEnumKey(LR"(C:\Game\Data\*.esp)", L"", 1, 0));
  EXPECT_EQ(k, frontEnumKey(LR"(C:\Game\Data\*.esp)", L"", 0,
                            2));  // large fetch: same result
  EXPECT_NE(k, frontEnumKey(LR"(C:\Game\Data\*.esp)", L"", 0, 4));  // on-disk only
  EXPECT_NE(k, frontEnumKey(LR"(C:\Game\Data\*.esm)", L"", 0, 0));
  // drive root
  EXPECT_FALSE(frontEnumKey(LR"(C:\*)", L"", 0, 0).empty());
  EXPECT_EQ(L"", frontEnumKey(L"C:*", LR"(C:\G)", 0, 0));
}

TEST(MetaCacheFront, EnumKeyDoubledSeparators)
{
  const std::wstring k = frontEnumKey(LR"(C:\Game\Data\*.esp)", L"", 0, 0);
  EXPECT_EQ(k, frontEnumKey(LR"(C:\Game\Data\\*.esp)", L"", 0, 0));
  EXPECT_EQ(k, frontEnumKey(LR"(C:\Game\Data/\*.esp)", L"", 0, 0));
  EXPECT_FALSE(frontEnumKey(LR"(C:\\*)", L"", 0, 0).empty());
  EXPECT_EQ(frontEnumKey(LR"(C:\*)", L"", 0, 0), frontEnumKey(LR"(C:\\*)", L"", 0, 0));
  // still rejected: doubled separator inside the path
  EXPECT_EQ(L"", frontEnumKey(LR"(C:\Game\\Data\*)", L"", 0, 0));
}

TEST(MetaCacheFront, EnumKeyRejected)
{
  EXPECT_EQ(L"", frontEnumKey(L"", LR"(C:\G)", 0, 0));
  EXPECT_EQ(L"", frontEnumKey(LR"(C:\G\)", L"", 0, 0));      // empty mask
  EXPECT_EQ(L"", frontEnumKey(LR"(C:\G\*)", L"", 2, 0));     // info level
  EXPECT_EQ(L"", frontEnumKey(LR"(C:\G\*)", L"", 0, 1));     // case-sensitive flag
  EXPECT_EQ(L"", frontEnumKey(LR"(C:\G\a:b)", L"", 0, 0));   // stream in mask
  EXPECT_EQ(L"", frontEnumKey(LR"(C:\G\..\*)", L"", 0, 0));  // dot-dot in directory
  EXPECT_EQ(L"", frontEnumKey(LR"(\\?\C:\G\*)", L"", 0, 0));
  EXPECT_EQ(L"", frontEnumKey(L"*", L"", 0, 0));             // no cwd
  EXPECT_EQ(L"", frontEnumKey(LR"(\*)", LR"(C:\G)", 0, 0));  // rooted without drive
}

TEST(MetaCacheFront, PrewarmRank)
{
  EXPECT_EQ(0, frontPrewarmRank("Z:/game/Data"));
  EXPECT_EQ(0, frontPrewarmRank("Z:/game/data/Meshes"));
  EXPECT_EQ(0, frontPrewarmRank("Z:\\game\\DATA"));
  EXPECT_LT(frontPrewarmRank("Z:/game/data/meshes"), frontPrewarmRank("Z:/game/saves"));
  EXPECT_GT(frontPrewarmRank("Z:/game/data/meshes/actors"),
            frontPrewarmRank("Z:/game/saves"));
  EXPECT_LT(frontPrewarmRank("Z:/a"), frontPrewarmRank("Z:/a/b"));
  EXPECT_EQ(1, frontPrewarmRank(""));
  EXPECT_EQ(0, frontPrewarmRank("Z:/data/game/Data/meshes"));
  EXPECT_GT(frontPrewarmRank("Z:/data/game/Data/meshes/a"), 0);
}

TEST(MetaCacheFront, PrewarmRankExplicitRoot)
{
  const std::string root = normalizeDataRoot("Z:\\Games\\Skyrim\\Data\\");
  EXPECT_EQ("z:/games/skyrim/data", root);
  EXPECT_EQ(0, frontPrewarmRank("Z:/Games/Skyrim/Data", root));
  EXPECT_EQ(0, frontPrewarmRank("Z:/Games/Skyrim/Data/Meshes", root));
  EXPECT_EQ(0, frontPrewarmRank("Z:/Games", root));  // ancestor
  EXPECT_EQ(0, frontPrewarmRank("", root));
  EXPECT_GT(frontPrewarmRank("Z:/Games/Skyrim/Data/Meshes/a", root), 0);
  EXPECT_GT(frontPrewarmRank("Z:/Games/Other", root), 0);
  EXPECT_GT(frontPrewarmRank("Z:/Games/Skyrim/Data2", root), 0);  // not a prefix match
}

// ---- negative derivation ---------------------------------------------------

TEST(MetaCacheNegative, Split)
{
  std::vector<std::wstring> c;
  ASSERT_TRUE(negSplit(LR"(\??\C:\Games\Data\x.esp)", c));
  ASSERT_EQ(4u, c.size());
  EXPECT_EQ(L"C:", c[0]);
  EXPECT_EQ(L"x.esp", c[3]);
  ASSERT_TRUE(negSplit(L"Z:/a/b", c));
  EXPECT_EQ(3u, c.size());
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\)", c));  // trailing separator
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\..\b)", c));
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\.\b)", c));
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\b*)", c));
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\b:stream)", c));
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\b.)", c));
  EXPECT_FALSE(negSplit(LR"(\??\C:\a\\b)", c));
  EXPECT_FALSE(negSplit(LR"(\??\UNC\srv\share\x)", c));
  EXPECT_FALSE(negSplit(L"rel\\x", c));
  EXPECT_FALSE(negSplit(L"", c));
  EXPECT_TRUE(negMayBeShortName(L"PROGRA~1"));
  EXPECT_FALSE(negMayBeShortName(L"skyrim.esm"));
}

TEST(MetaCacheNegative, Decision)
{
  auto run = [](const wchar_t* path, NegChild answer) {
    std::vector<std::wstring> c;
    EXPECT_TRUE(negSplit(path, c));
    auto node = [&](size_t k) {
      std::wstring p;
      for (size_t i = 0; i < k; ++i)
        p += (i ? L"\\" : L"") + c[i];
      for (wchar_t& ch : p)
        ch = foldChar(ch);
      if (p == L"C:" || p == L"C:\\G" || p == L"C:\\G\\DATA" ||
          p == L"C:\\G\\DATA\\MESHES")
        return NegNode::Dir;
      return p == L"C:\\G\\DATA\\A.ESP" ? NegNode::File : NegNode::None;
    };
    return deriveNegative(c.size(), node, [&](size_t) {
      return answer;
    });
  };
  // parent is a directory node, name not in its contents
  EXPECT_EQ(NegVerdict::FileNotFound, run(LR"(C:\g\data\b.esp)", NegChild::Absent));
  // present / unknown contents: no answer
  EXPECT_EQ(NegVerdict::Unknown, run(LR"(C:\g\data\b.esp)", NegChild::Present));
  EXPECT_EQ(NegVerdict::Unknown, run(LR"(C:\g\data\b.esp)", NegChild::Unknown));
  // the name itself is mapped
  EXPECT_EQ(NegVerdict::Unknown, run(LR"(C:\g\data\a.esp)", NegChild::Absent));
  EXPECT_EQ(NegVerdict::Unknown, run(LR"(C:\g\data\meshes)", NegChild::Absent));
  // intermediate directory absent: PATH_NOT_FOUND
  EXPECT_EQ(NegVerdict::PathNotFound,
            run(LR"(C:\g\data\textures\x.dds)", NegChild::Absent));
  EXPECT_EQ(NegVerdict::PathNotFound,
            run(LR"(C:\g\data\textures\a\x.dds)", NegChild::Absent));
  // a file used as a directory, and no tree ancestor below the drive
  EXPECT_EQ(NegVerdict::Unknown, run(LR"(C:\g\data\a.esp\x)", NegChild::Absent));
  EXPECT_EQ(NegVerdict::Unknown, run(LR"(D:\x\y)", NegChild::Absent));
  EXPECT_EQ(NegVerdict::FileNotFound,
            run(L"C:\\x", NegChild::Absent));  // parent = drive node
}

TEST(MetaCacheNegative, ListingAnyStar)
{
  Store store(1 << 20);
  const std::wstring dir = LR"(\??\C:\G\DATA)";
  EXPECT_EQ(nullptr, store.lookupAnyStar(dir));
  auto l = std::make_shared<Listing>();
  l->add(std::string("rec"), L"Skyrim.esm");
  store.putListing(dir, 3, L"*", l, false, store.generation());
  store.putListing(dir, 3, L"FOO.ESP", std::make_shared<Listing>());
  auto got = store.lookupAnyStar(dir);
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(1u, got->findLiteral(L"SKYRIM.ESM").size());  // folded compare
  EXPECT_TRUE(got->findLiteral(L"OTHER.ESM").empty());
  // a write below invalidates the directory's listing
  store.invalidatePath(dir + L"\\new.esp");
  EXPECT_EQ(nullptr, store.lookupAnyStar(dir));
}
