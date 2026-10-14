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

// Pure parts of the configuration file support (no Windows API; unit-tested in
// test/shared_test/config_logic_test.cpp).

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace usvfs::config::logic
{

inline std::string trim(std::string_view s)
{
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n'))
    ++b;
  while (e > b &&
         (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n'))
    --e;
  return std::string(s.substr(b, e - b));
}

inline std::string lower(std::string_view s)
{
  std::string r(s);
  for (char& c : r) {
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c + 32);
  }
  return r;
}

// "USVFS_READCACHE_MB" -> "readcache.mb", "USVFS_READCACHE" -> "readcache.enabled",
// "USVFS_TRACE" -> "trace.path", "USVFS_CACHE_TOTAL_MB" -> "cache.total_mb".
// Empty if the name does not start with USVFS_.
inline std::string keyFromEnvName(std::string_view env)
{
  constexpr std::string_view prefix = "USVFS_";
  if (env.size() <= prefix.size() || env.substr(0, prefix.size()) != prefix)
    return std::string();
  const std::string rest = lower(env.substr(prefix.size()));
  const size_t us        = rest.find('_');
  if (us == std::string::npos)
    return rest + (rest == "trace" ? ".path" : ".enabled");
  return rest.substr(0, us) + "." + rest.substr(us + 1);
}

struct ParsedIni
{
  std::map<std::string, std::string> values;  // "section.key" (lower case) -> value
  std::vector<std::string> errors;  // "line N: ..." for lines that were ignored
};

// INI text: [section] headers, key=value lines, blank lines and lines starting
// with ';' or '#' ignored, a UTF-8 BOM skipped, one pair of surrounding double
// quotes removed from values. Keys before any section header are ignored with an
// error; a later duplicate overrides an earlier one.
inline ParsedIni parseIni(std::string_view text)
{
  ParsedIni out;
  if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
      static_cast<unsigned char>(text[1]) == 0xBB &&
      static_cast<unsigned char>(text[2]) == 0xBF)
    text.remove_prefix(3);

  std::string section;
  size_t lineNo = 0, pos = 0;
  while (pos <= text.size()) {
    size_t end = text.find('\n', pos);
    if (end == std::string_view::npos)
      end = text.size();
    const std::string line = trim(text.substr(pos, end - pos));
    pos                    = end + 1;
    ++lineNo;
    if (line.empty() || line[0] == ';' || line[0] == '#')
      continue;
    if (line[0] == '[') {
      const size_t close = line.find(']');
      if (close == std::string::npos) {
        out.errors.push_back("line " + std::to_string(lineNo) +
                             ": unterminated section header");
        section.clear();
        continue;
      }
      section = lower(trim(std::string_view(line).substr(1, close - 1)));
      continue;
    }
    const size_t eq = line.find('=');
    if (eq == std::string::npos || eq == 0) {
      out.errors.push_back("line " + std::to_string(lineNo) + ": expected key=value");
      continue;
    }
    if (section.empty()) {
      out.errors.push_back("line " + std::to_string(lineNo) +
                           ": key outside a section");
      continue;
    }
    std::string key = lower(trim(std::string_view(line).substr(0, eq)));
    std::string val = trim(std::string_view(line).substr(eq + 1));
    if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
      val = val.substr(1, val.size() - 2);
    out.values[section + "." + key] = val;
  }
  return out;
}

// splits a total budget between readcache and metacache: the readcache gets
// `readcachePct` percent, the metacache the rest; because the metacache's
// memory use is ~1.75x its cap value (store + enum front 0.5x + attr front 0.25x),
// the cap value handed to it is the remaining share / 1.75.
struct BudgetSplit
{
  unsigned long long readcacheMb = 0, metacacheCapMb = 0;
};

inline BudgetSplit splitTotalBudget(unsigned long long totalMb, unsigned readcachePct)
{
  if (readcachePct > 100)
    readcachePct = 100;
  BudgetSplit s;
  s.readcacheMb    = totalMb * readcachePct / 100;
  s.metacacheCapMb = (totalMb - s.readcacheMb) * 4 / 7;
  return s;
}

}  // namespace usvfs::config::logic
