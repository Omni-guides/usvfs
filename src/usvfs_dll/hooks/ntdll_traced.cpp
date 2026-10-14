#include "../trace.h"
#include "ntdll.h"
#include "ntdll_impl.h"

// The ntdll file hooks: the real work is in ntdll.cpp (impl_*), these record
// what the application asked for (USVFS_TRACE, see trace.h) around it.

namespace usvfs
{

NTSTATUS WINAPI hook_NtQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
  trace::Scope ts;
  const NTSTATUS res =
      impl_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
  if (ts.on())
    trace::recQueryAttr(ts, true, ObjectAttributes, res);
  return res;
}

NTSTATUS WINAPI hook_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                           PFILE_BASIC_INFORMATION FileInformation)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtQueryAttributesFile(ObjectAttributes, FileInformation);
  if (ts.on())
    trace::recQueryAttr(ts, false, ObjectAttributes, res);
  return res;
}

NTSTATUS WINAPI hook_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event,
                                          PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                          PIO_STATUS_BLOCK IoStatusBlock,
                                          PVOID FileInformation, ULONG Length,
                                          FILE_INFORMATION_CLASS FileInformationClass,
                                          BOOLEAN ReturnSingleEntry,
                                          PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtQueryDirectoryFile(
      FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
      FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
  if (ts.on()) {
    // same bit values as the Ex flags (SL_RESTART_SCAN, SL_RETURN_SINGLE_ENTRY)
    const ULONG flags = (RestartScan ? 1u : 0u) | (ReturnSingleEntry ? 2u : 0u);
    trace::recQueryDir(ts, false, FileHandle, IoStatusBlock, Length,
                       FileInformationClass, flags, FileName, res);
  }
  return res;
}

NTSTATUS WINAPI hook_NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event,
                                            PIO_APC_ROUTINE ApcRoutine,
                                            PVOID ApcContext,
                                            PIO_STATUS_BLOCK IoStatusBlock,
                                            PVOID FileInformation, ULONG Length,
                                            FILE_INFORMATION_CLASS FileInformationClass,
                                            ULONG QueryFlags, PUNICODE_STRING FileName)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtQueryDirectoryFileEx(
      FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
      FileInformationClass, QueryFlags, FileName);
  if (ts.on())
    trace::recQueryDir(ts, true, FileHandle, IoStatusBlock, Length,
                       FileInformationClass, QueryFlags, FileName, res);
  return res;
}

NTSTATUS WINAPI hook_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes,
                                PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess,
                                ULONG OpenOptions)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                                       IoStatusBlock, ShareAccess, OpenOptions);
  if (ts.on())
    trace::recCreate(ts, true, FileHandle, ObjectAttributes, DesiredAccess, ShareAccess,
                     0, OpenOptions, 0, res);
  return res;
}

NTSTATUS WINAPI hook_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes,
                                  PIO_STATUS_BLOCK IoStatusBlock,
                                  PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                  ULONG ShareAccess, ULONG CreateDisposition,
                                  ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
  trace::Scope ts;
  const NTSTATUS res =
      impl_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                        CreateOptions, EaBuffer, EaLength);
  if (ts.on())
    trace::recCreate(ts, false, FileHandle, ObjectAttributes, DesiredAccess,
                     ShareAccess, CreateDisposition, CreateOptions, FileAttributes,
                     res);
  return res;
}

NTSTATUS WINAPI hook_NtClose(HANDLE Handle)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtClose(Handle);
  if (ts.on())
    trace::recClose(ts, Handle, res);
  return res;
}

NTSTATUS WINAPI hook_NtReadFile(HANDLE FileHandle, HANDLE Event,
                                PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
                                       IoStatusBlock, Buffer, Length, ByteOffset, Key);
  if (ts.on())
    trace::recRead(ts, FileHandle, Event, IoStatusBlock, Buffer, Length, ByteOffset,
                   res);
  return res;
}

DLLEXPORT NTSTATUS WINAPI hook_NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtQueryInformationFile(
      FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
  if (ts.on())
    trace::recQueryInfo(ts, FileHandle, IoStatusBlock, Length, FileInformationClass,
                        res);
  return res;
}

NTSTATUS WINAPI hook_NtSetInformationFile(HANDLE FileHandle,
                                          PIO_STATUS_BLOCK IoStatusBlock,
                                          PVOID FileInformation, ULONG Length,
                                          FILE_INFORMATION_CLASS FileInformationClass)
{
  trace::Scope ts;
  const NTSTATUS res = impl_NtSetInformationFile(
      FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
  if (ts.on())
    trace::recSetInfo(ts, FileHandle, IoStatusBlock, FileInformation, Length,
                      FileInformationClass, res);
  return res;
}

}  // namespace usvfs
