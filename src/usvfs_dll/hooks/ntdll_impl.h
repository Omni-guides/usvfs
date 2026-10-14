#pragma once

#include <ntdll_declarations.h>

// The bodies of the ntdll file hooks (ntdll.cpp). The hooks proper
// (hook_Nt*, ntdll_traced.cpp) are thin wrappers that add the harness trace.
namespace usvfs
{

NTSTATUS WINAPI
impl_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                               PFILE_NETWORK_OPEN_INFORMATION FileInformation);
NTSTATUS WINAPI impl_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                           PFILE_BASIC_INFORMATION FileInformation);
NTSTATUS WINAPI impl_NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName, BOOLEAN RestartScan);
NTSTATUS WINAPI impl_NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event,
                                            PIO_APC_ROUTINE ApcRoutine,
                                            PVOID ApcContext,
                                            PIO_STATUS_BLOCK IoStatusBlock,
                                            PVOID FileInformation, ULONG Length,
                                            FILE_INFORMATION_CLASS FileInformationClass,
                                            ULONG QueryFlags, PUNICODE_STRING FileName);
NTSTATUS WINAPI impl_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes,
                                PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess,
                                ULONG OpenOptions);
NTSTATUS WINAPI impl_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes,
                                  PIO_STATUS_BLOCK IoStatusBlock,
                                  PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                  ULONG ShareAccess, ULONG CreateDisposition,
                                  ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS WINAPI impl_NtClose(HANDLE Handle);
NTSTATUS WINAPI impl_NtReadFile(HANDLE FileHandle, HANDLE Event,
                                PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS WINAPI impl_NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS WINAPI impl_NtSetInformationFile(HANDLE FileHandle,
                                          PIO_STATUS_BLOCK IoStatusBlock,
                                          PVOID FileInformation, ULONG Length,
                                          FILE_INFORMATION_CLASS FileInformationClass);

}  // namespace usvfs
