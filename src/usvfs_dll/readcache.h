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

// In-process read cache: small NtReadFile calls on synchronous, read-only disk
// handles are answered from a memory copy of the whole file instead of a
// syscall. See readcache.cpp for the design.
//
// Configuration (environment variables, read once in init()):
//   USVFS_READCACHE=0              disable (hooks are plain passthrough)
//   USVFS_READCACHE_MB=auto       LRU budget in MiB (auto: RAM/32 clamped 256..1024)
//   (auto: RAM/32 clamped 256..1024) USVFS_READCACHE_MAXFILE_MB=64  largest cached file
//   in MiB USVFS_READCACHE_ADMIT_READS=8  small reads of a file before it is cached
//   USVFS_READCACHE_SPLIT=1        split big reads over worker threads (default on)
//   USVFS_READCACHE_SPLIT_MIN_KB=256, USVFS_READCACHE_SPLIT_CHUNK_KB=256
//   USVFS_READCACHE_RA=0           sequential readahead (default off)
//   USVFS_READCACHE_RA_MB=64       memory cap of all readahead windows
//   USVFS_READCACHE_ASYNC=1        fill in background workers (default on; 0 = fill on
//   the caller) USVFS_READCACHE_THREADS=4      number of background workers

namespace usvfs::readcache
{

extern std::atomic<bool> g_enabled;

// the one branch every hook takes when the cache is off
inline bool enabled()
{
  return g_enabled.load(std::memory_order_relaxed);
}

// reads configuration; must be called once before the hooks are installed
void init();

// stops background workers, logs the final statistics and turns the cache
// off. Must NOT be called from DllMain (it waits for the workers).
void shutdown();

enum class Peek
{
  Unknown,
  Passthrough,
  PassthroughTracked,
  Serve,
  Big
};

// cheap look at the classification of a handle (no reference counting, no
// hook context): Passthrough handles (ineligible, or still on probation and not
// yet due for admission) bypass everything. Counts the read for probation
// handles, so call it once per NtReadFile.
Peek peek(HANDLE handle, ULONG length);

// after a read of a PassthroughTracked handle went to the system: keeps the
// tracked file position of the (probation) handle up to date
void afterProbationRead(HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                        PIO_STATUS_BLOCK iosb, PLARGE_INTEGER byteOffset,
                        NTSTATUS status);

// counts a read that was passed to the real function without further ado
void notePassthrough();

// called after a handle was opened for writing/deleting or is about to be
// modified: file information snapshots of that file are no longer served. If the
// file can't be identified, the snapshots of every file are dropped.
void noteFileWritten(HANDLE handle);
void bumpWriteGeneration();

// registers a function that is told about every handle the cache closes itself
void setForgetCallback(void (*callback)(HANDLE));

// memcpy that returns false instead of faulting on an invalid address
bool guardedCopy(void* dst, const void* src, size_t length);

// drops the state of a handle; must be called before the handle is closed
void onClose(HANDLE handle);

// true while the calling thread executes a guarded memory copy whose access
// violations are expected and handled (used to keep the crash dump handler quiet)
bool inProtectedCopy();

// replacements for the corresponding ntdll functions; the real functions are
// invoked as necessary (and bypass our hooks when called from inside a hook)
NTSTATUS read(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
              ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

// Answers a query of a file information class from the snapshot taken when the
// handle was classified (eligible handles only: read-only, synchronous regular
// files). True if `status` is the result; false means "ask the system". Takes
// no hook context and no reference counts.
bool tryServeInfo(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                  PVOID FileInformation, ULONG Length,
                  FILE_INFORMATION_CLASS FileInformationClass, NTSTATUS& status);

NTSTATUS queryInformation(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                          PVOID FileInformation, ULONG Length,
                          FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS setInformation(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                        PVOID FileInformation, ULONG Length,
                        FILE_INFORMATION_CLASS FileInformationClass);

}  // namespace usvfs::readcache
