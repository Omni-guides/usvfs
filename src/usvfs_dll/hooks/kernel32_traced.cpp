#include "../trace.h"
#include "kernel32.h"
#include "kernel32_impl.h"

// kernel32 hooks wrapped for the harness trace (USVFS_TRACE): the application's
// arguments are recorded at entry, when no hook group is active on the thread.
// The real work stays in kernel32.cpp (impl_*). GetLastError is the result of
// these calls, so it is captured before recording and put back after.

namespace usvfs
{

namespace
{
#define TRACE_END(call)                                                                \
  if (ts.on()) {                                                                       \
    const DWORD err_ = ::GetLastError();                                               \
    trace::call;                                                                       \
    ::SetLastError(err_);                                                              \
  }
}  // namespace

BOOL WINAPI hook_GetFileAttributesExW(LPCWSTR lpFileName,
                                      GET_FILEEX_INFO_LEVELS fInfoLevelId,
                                      LPVOID lpFileInformation)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res =
      impl_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
  TRACE_END(recGetAttrEx(ts, lpFileName, fInfoLevelId, res, err_));
  return res;
}

DWORD WINAPI hook_GetFileAttributesW(LPCWSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const DWORD res = impl_GetFileAttributesW(lpFileName);
  TRACE_END(recGetAttr(ts, lpFileName, res, err_));
  return res;
}

HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId,
                                    LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp,
                                    LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
  trace::Scope ts;
  ts.keepLastError();
  const HANDLE res =
      impl_FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp,
                            lpSearchFilter, dwAdditionalFlags);
  TRACE_END(recFindFirst(ts, lpFileName, fInfoLevelId, fSearchOp, dwAdditionalFlags,
                         res, err_));
  return res;
}

DWORD WINAPI hook_GetPrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,
                                           LPCSTR lpDefault, LPSTR lpReturnedString,
                                           DWORD nSize, LPCSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const DWORD res = impl_GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault,
                                                  lpReturnedString, nSize, lpFileName);
  TRACE_END(recProfile(ts, false, true, lpAppName, lpKeyName, lpFileName, nSize, res));
  return res;
}

DWORD WINAPI hook_GetPrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName,
                                           LPCWSTR lpDefault, LPWSTR lpReturnedString,
                                           DWORD nSize, LPCWSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const DWORD res = impl_GetPrivateProfileStringW(lpAppName, lpKeyName, lpDefault,
                                                  lpReturnedString, nSize, lpFileName);
  TRACE_END(recProfile(ts, false, false, lpAppName, lpKeyName, lpFileName, nSize, res));
  return res;
}

DWORD WINAPI hook_GetPrivateProfileSectionA(LPCSTR lpAppName, LPSTR lpReturnedString,
                                            DWORD nSize, LPCSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const DWORD res =
      impl_GetPrivateProfileSectionA(lpAppName, lpReturnedString, nSize, lpFileName);
  TRACE_END(recProfile(ts, true, true, lpAppName, nullptr, lpFileName, nSize, res));
  return res;
}

DWORD WINAPI hook_GetPrivateProfileSectionW(LPCWSTR lpAppName, LPWSTR lpReturnedString,
                                            DWORD nSize, LPCWSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const DWORD res =
      impl_GetPrivateProfileSectionW(lpAppName, lpReturnedString, nSize, lpFileName);
  TRACE_END(recProfile(ts, true, false, lpAppName, nullptr, lpFileName, nSize, res));
  return res;
}

BOOL WINAPI hook_SetCurrentDirectoryW(LPCWSTR lpPathName)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res = impl_SetCurrentDirectoryW(lpPathName);
  TRACE_END(recSetCwd(ts, lpPathName, res));
  return res;
}

// FindNext/FindClose hooks (see kernel32_impl.h), installed for tracing and for the
// enumeration front cache; the real function is reached through the hook barrier

BOOL WINAPI hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res = impl_FindNextFileW(hFindFile, lpFindFileData);
  TRACE_END(recFindNext(ts, hFindFile, res));
  return res;
}

BOOL WINAPI hook_FindClose(HANDLE hFindFile)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res = impl_FindClose(hFindFile);
  TRACE_END(recFindClose(ts, hFindFile, res));
  return res;
}

// writes: only a marker, never replayed

BOOL WINAPI hook_DeleteFileW(LPCWSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res = impl_DeleteFileW(lpFileName);
  TRACE_END(recWriteMarker(ts, 1, false, lpFileName));
  return res;
}

BOOL WINAPI hook_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res = impl_MoveFileW(lpExistingFileName, lpNewFileName);
  TRACE_END(recWriteMarker(ts, 2, false, lpExistingFileName));
  return res;
}

BOOL WINAPI hook_MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
                             DWORD dwFlags)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res = impl_MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
  TRACE_END(recWriteMarker(ts, 2, false, lpExistingFileName));
  return res;
}

BOOL WINAPI hook_WritePrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,
                                            LPCSTR lpString, LPCSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res =
      impl_WritePrivateProfileStringA(lpAppName, lpKeyName, lpString, lpFileName);
  TRACE_END(recWriteMarker(ts, 3, true, lpFileName));
  return res;
}

BOOL WINAPI hook_WritePrivateProfileStringW(LPCWSTR lpAppName, LPCWSTR lpKeyName,
                                            LPCWSTR lpString, LPCWSTR lpFileName)
{
  trace::Scope ts;
  ts.keepLastError();
  const BOOL res =
      impl_WritePrivateProfileStringW(lpAppName, lpKeyName, lpString, lpFileName);
  TRACE_END(recWriteMarker(ts, 3, false, lpFileName));
  return res;
}

}  // namespace usvfs
