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

#include <atomic>
#include <ntdll_declarations.h>
#include <string>
#include <string_view>

// In-process file metadata cache: results of NtQueryAttributesFile /
// NtQueryFullAttributesFile (including "not found") and the raw record lists of
// directory enumerations are remembered. Assumption: the files are not changed
// behind our back by other processes (the modlist is frozen while the game
// runs). Everything this process writes through usvfs's hooks is invalidated and
// excluded from caching.
//
// Configuration (environment, read once in init()):
//   USVFS_METACACHE=1|0                force on/off (default: on only in SkyrimSE.exe)
//   USVFS_METACACHE_MB=auto            memory cap (auto: RAM/64 clamped 256..1024)
//   (auto: RAM/64 clamped 256..1024) USVFS_METACACHE_FRONT_ENUM=1|0     enumeration
//   front cache (default: on with the
//                                      metacache; memory: half of USVFS_METACACHE_MB)
//   USVFS_METACACHE_FRONT=1|0          front cache for GetFileAttributesW/ExW keyed
//                                      by the virtual path (default: on with the
//                                      metacache)
//   USVFS_METACACHE_PREWARM=1|0        walk the virtual tree in the background
//                                      (default: only in SkyrimSE.exe)
//   USVFS_METACACHE_PREWARM_THREADS=4
//   USVFS_METACACHE_PREWARM_CLASSES=3        directory information classes to
//                                      pre-list (FILE_INFORMATION_CLASS values)

namespace usvfs::metacache
{

extern std::atomic<bool> g_enabled;

// hooks of the per-hook profile printed in the summary line (calls, µs spent inside
// metacache code)
enum class Hook : int
{
  NtCreateFile,
  NtOpenFile,
  NtClose,
  NtReadFile,
  NtQueryInformationFile,
  NtSetInformationFile,
  NtQueryDirectoryFile,
  NtQueryAttributesFile,
  NtQueryFullAttributesFile,
  GetFileAttributesW,
  GetFileAttributesExW,
  FindFirstFileExW,
  FindNextFileW,
  FindClose,
  Kernel32Misc,
  Count
};

// counts a call of a hook that otherwise does no metacache work (profile only)
void noteHook(Hook h);

inline bool enabled()
{
  return g_enabled.load(std::memory_order_relaxed);
}

void init();

// starts the pre-warm (if configured); call after the hooks are installed
void startPrewarm();

// stops background threads, logs final statistics; not for DllMain
void shutdown();

// cache key for an NT path ("\??\C:\x"); empty if the path should not be cached
std::wstring makeKey(std::wstring_view ntPath);

// attribute cache. Return true if answered from the cache (status is the
// result to return).
// generation counter to hand to the store*() calls (read it before asking the
// system; results from before an invalidation are then dropped)
uint64_t generation();

bool lookupBasic(const std::wstring& key, PFILE_BASIC_INFORMATION out,
                 NTSTATUS& status);
bool lookupFull(const std::wstring& key, PFILE_NETWORK_OPEN_INFORMATION out,
                NTSTATUS& status);
void storeBasic(const std::wstring& key, NTSTATUS status,
                const FILE_BASIC_INFORMATION* info, uint64_t generation);
// stores a full attribute record for a real file (NT path of its handle), e.g. one
// the readcache learned at classification. Ignored if the path is not cacheable,
// already known, excluded, or the cache is off.
//
// `generation` is the generation() read before the information was obtained (the
// record is dropped if it moved). Not fed: dot-leaves (Wine's path query adds
// HIDDEN) and reparse points/symlinks (checked by path).
void feedFull(const std::wstring& ntPath, const FILE_NETWORK_OPEN_INFORMATION& info,
              uint64_t generation);
void storeFull(const std::wstring& key, NTSTATUS status,
               const FILE_NETWORK_OPEN_INFORMATION* info, uint64_t generation);

// replacement for the real NtQueryDirectoryFile (synchronous calls without
// event/apc, RestartScan FALSE) used by usvfs's directory merging. `dirPath` is
// the path the handle was opened with, empty if unknown.
//
// `resolveContent` maps the path above to the directory whose content the
// handle really lists (after usvfs's redirection); nothing is cached for
// excluded or written directories, on either side.
NTSTATUS queryDirectory(const std::wstring& dirPath, HANDLE handle,
                        PIO_STATUS_BLOCK iosb, PVOID buffer, ULONG length,
                        FILE_INFORMATION_CLASS infoClass, BOOLEAN singleEntry,
                        PUNICODE_STRING mask,
                        std::wstring (*resolveContent)(const std::wstring&));

// forget the enumeration state of a handle; call before closing it
void onClose(HANDLE handle);

// Negative derivation (USVFS_METACACHE_NEGATIVE, default off): FILE_NOT_FOUND /
// PATH_NOT_FOUND answered without a real call when the virtual parent directory's
// complete contents are known (it is a usvfs tree node whose real directory has a
// complete cached "*" listing, and the name is neither a tree child nor in it).
// Never for volatile/overwrite paths, short-name-like names, or when the
// generation moved meanwhile.
bool negativeEnabled();
// virtual NT path (\??\C:\...) as the application passed it (RootDirectory
// resolved); STATUS_SUCCESS = no answer, else the status to return
NTSTATUS negativeNt(std::wstring_view virtualNtPath);

// Front cache: the final results of GetFileAttributesW / GetFileAttributesExW
// (GetFileExInfoStandard only) keyed by the virtual path as the application passed
// it. Valid while the store generation is unchanged, so every invalidation
// (noteWrite, noteDosPath, noteSetInformation) and every change of the usvfs
// mappings (noteMappingChange) drops all entries.
struct FrontTicket
{
  std::wstring key;  // empty: not cacheable
  uint64_t gen = 0;
};

struct FrontResult
{
  bool ok                        = false;
  DWORD err                      = 0;   // GetLastError of the call
  DWORD attr                     = 0;   // GetFileAttributesW result (ok)
  WIN32_FILE_ATTRIBUTE_DATA data = {};  // GetFileAttributesExW (ok)
};

// true if answered (`out` is filled); on a miss `ticket` is for frontStore()
bool frontLookup(bool ex, const wchar_t* name, FrontResult& out, FrontTicket& ticket);
// `reroutedName`: the real path the call was redirected to (nothing is cached
// if that is excluded or written). `canonicalName`: the absolute path the call
// resolved the name to; must match the ticket key (cwd changed meanwhile otherwise)
void frontStore(const FrontTicket& ticket, bool ex, const FrontResult& result,
                const wchar_t* reroutedName, const wchar_t* canonicalName);
// negative derivation for the front miss `ticket` (see negativeEnabled): true if
// `out` holds the answer (not found, with the Win32 error)
bool frontNegative(const FrontTicket& ticket, FrontResult& out);

// Enumeration front cache (FindFirstFileExW / FindNextFileW / FindClose). A listing
// is recorded from what the application iterated (published only when it reached
// ERROR_NO_MORE_FILES, or when FindFirstFileExW failed with a not-found error) and
// replayed verbatim for the same {virtual directory, mask, info level, flags}.
// Valid while the store generation is unchanged. Replayed searches get a
// synthetic handle: the address of a heap object that is registered here and
// freed by FindClose. It can't collide with a live real handle (those are kernel
// handles or other heap objects); any other API that is handed it just fails
// with an invalid-handle error. USVFS_METACACHE_FRONT_ENUM=0 disables it.
struct EnumTicket
{
  std::wstring key;    // empty: not cacheable
  std::wstring dirNt;  // store key of the virtual directory
  uint64_t gen = 0;
};

bool enumFrontEnabled();
// registry exists (also true after shutdown(), so open searches are still routed)
bool enumFrontActive();
// true if answered from a listing (res/err are the results; `data` is filled)
bool enumFirst(const wchar_t* name, int infoLevel, int searchOp, void* filter,
               DWORD flags, void* data, HANDLE& res, DWORD& err, EnumTicket& ticket);
// after the real FindFirstFileExW; `first`: its data (if it succeeded)
void enumRecordFirst(const EnumTicket& ticket, const wchar_t* canonicalName,
                     int infoLevel, DWORD flags, HANDLE res, DWORD err,
                     const WIN32_FIND_DATAW* first);
bool enumNext(HANDLE h, WIN32_FIND_DATAW* data, BOOL& result, DWORD& err);
void enumAfterNext(HANDLE h, BOOL result, DWORD err, const WIN32_FIND_DATAW* data);
// true if `h` was a replayed search (now freed; the caller returns TRUE)
bool enumClose(HANDLE h);

// the usvfs mappings (redirection tree, delete / fake-directory trackers) changed
void noteMappingChange();

// invalidation
bool isWriteIntent(ACCESS_MASK desiredAccess, ULONG createDisposition);
void noteWrite(std::wstring_view ntPath, Hook hook = Hook::NtCreateFile);

// like noteWrite, for a Win32 path as seen by the kernel32 hooks. `tree`: the
// path may be a directory whose content goes along (remove, rename). Relative
// paths clear the cache.
void noteDosPath(const wchar_t* dosPath, bool tree);
bool isMutatingClass(FILE_INFORMATION_CLASS infoClass);
void noteSetInformation(std::wstring_view handlePath, std::wstring_view rootPath,
                        FILE_INFORMATION_CLASS infoClass, PVOID info, ULONG length);

}  // namespace usvfs::metacache
