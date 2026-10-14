#pragma once

#include "ntdll_declarations.h"

// Bodies of the kernel32 hooks that the harness trace wraps (kernel32.cpp); the
// hook_* wrappers are in kernel32_traced.cpp.
namespace usvfs
{

BOOL WINAPI impl_GetFileAttributesExW(LPCWSTR lpFileName,
                                      GET_FILEEX_INFO_LEVELS fInfoLevelId,
                                      LPVOID lpFileInformation);
DWORD WINAPI impl_GetFileAttributesW(LPCWSTR lpFileName);
HANDLE WINAPI impl_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
                                    LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp,
                                    LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
DWORD WINAPI impl_GetPrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,
                                           LPCSTR lpDefault, LPSTR lpReturnedString,
                                           DWORD nSize, LPCSTR lpFileName);
DWORD WINAPI impl_GetPrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName,
                                           LPCWSTR lpDefault, LPWSTR lpReturnedString,
                                           DWORD nSize, LPCWSTR lpFileName);
DWORD WINAPI impl_GetPrivateProfileSectionA(LPCSTR lpAppName, LPSTR lpReturnedString,
                                            DWORD nSize, LPCSTR lpFileName);
DWORD WINAPI impl_GetPrivateProfileSectionW(LPCWSTR lpAppName, LPWSTR lpReturnedString,
                                            DWORD nSize, LPCWSTR lpFileName);
BOOL WINAPI impl_SetCurrentDirectoryW(LPCWSTR lpPathName);
BOOL WINAPI impl_DeleteFileW(LPCWSTR lpFileName);
BOOL WINAPI impl_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);
BOOL WINAPI impl_MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
                             DWORD dwFlags);
BOOL WINAPI impl_WritePrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,
                                            LPCSTR lpString, LPCSTR lpFileName);
BOOL WINAPI impl_WritePrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName,
                                            LPCWSTR lpString, LPCWSTR lpFileName);

BOOL WINAPI impl_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI impl_FindClose(HANDLE hFindFile);

// installed only while tracing or with the enumeration front cache: FindNextFileW
// and FindClose (wrappers in kernel32_traced.cpp)
BOOL WINAPI hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI hook_FindClose(HANDLE hFindFile);

}  // namespace usvfs
