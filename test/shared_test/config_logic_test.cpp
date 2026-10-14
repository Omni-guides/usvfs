#include <gtest/gtest.h>

#include "../../src/usvfs_dll/config_logic.h"

using namespace usvfs::config::logic;

TEST(ConfigLogic, KeyFromEnvName)
{
  EXPECT_EQ("readcache.mb", keyFromEnvName("USVFS_READCACHE_MB"));
  EXPECT_EQ("readcache.enabled", keyFromEnvName("USVFS_READCACHE"));
  EXPECT_EQ("metacache.front_prewarm_threads",
            keyFromEnvName("USVFS_METACACHE_FRONT_PREWARM_THREADS"));
  EXPECT_EQ("trace.path", keyFromEnvName("USVFS_TRACE"));
  EXPECT_EQ("trace.crc", keyFromEnvName("USVFS_TRACE_CRC"));
  EXPECT_EQ("cache.total_mb", keyFromEnvName("USVFS_CACHE_TOTAL_MB"));
  EXPECT_EQ("", keyFromEnvName("PATH"));
  EXPECT_EQ("", keyFromEnvName("USVFS_"));
}

TEST(ConfigLogic, ParseIni)
{
  const auto p =
      parseIni("\xEF\xBB\xBF; comment\r\n[ReadCache]\r\nMB = 512\r\n# c\r\nasync=0\r\n"
               "\r\n[metacache]\r\ndata_root = \"Z:/Games/Data\"\r\nmb=1\r\nmb=2\r\n");
  EXPECT_EQ("512", p.values.at("readcache.mb"));
  EXPECT_EQ("0", p.values.at("readcache.async"));
  EXPECT_EQ("Z:/Games/Data", p.values.at("metacache.data_root"));
  EXPECT_EQ("2", p.values.at("metacache.mb"));  // later duplicate wins
  EXPECT_TRUE(p.errors.empty());
}

TEST(ConfigLogic, ParseIniErrors)
{
  const auto p = parseIni("orphan=1\n[a]\nnoequals\n=novalue\n[broken\nk=v\n");
  EXPECT_EQ(5u, p.errors.size());
  EXPECT_TRUE(p.values.empty());  // k=v follows a broken header: no section
}

TEST(ConfigLogic, ParseIniNoTrailingNewline)
{
  const auto p = parseIni("[a]\nb=c");
  EXPECT_EQ("c", p.values.at("a.b"));
}

TEST(ConfigLogic, SplitTotalBudget)
{
  const auto s = splitTotalBudget(1400, 50);
  EXPECT_EQ(700u, s.readcacheMb);
  EXPECT_EQ(400u, s.metacacheCapMb);  // 700 / 1.75
  const auto all = splitTotalBudget(100, 100);
  EXPECT_EQ(100u, all.readcacheMb);
  EXPECT_EQ(0u, all.metacacheCapMb);
  EXPECT_EQ(100u, splitTotalBudget(100, 500).readcacheMb);
}
