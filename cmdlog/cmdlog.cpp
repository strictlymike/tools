/**
 * Adapted from:
 *  Detours Test Program (simple.cpp of simple.dll)
 *  Microsoft Research Detours Package, Version 3.0.
 *  Copyright (c) Microsoft Corporation.  All rights reserved.
 */
#define _CRT_SECURE_NO_WARNINGS /* Technical debt? I think so. */
#include <stdio.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdarg.h>
#include "detours.h"

#pragma comment(lib, "iphlpapi.lib")

#define CMD_QUERY_STATUS	L"rem status"

///////////////////////////////////////////////////////////////////////////////
// Types
///////////////////////////////////////////////////////////////////////////////

enum CmdLogState {
	clsLabel,
	clsNoLabel,
};

///////////////////////////////////////////////////////////////////////////////
// Prototypes
///////////////////////////////////////////////////////////////////////////////

static void LogToFile(FILE *out, char *fmt, ...);
void LogAdapterInfoToFile(FILE *out);
void LogInfoStampToFile(FILE *out);
void LogTimeStampToFile(FILE *out);
BOOL WINAPI LogReadConsoleW(
  HANDLE  hConsoleInput,
  LPVOID  lpBuffer,
  DWORD   nNumberOfCharsToRead,
  LPDWORD lpNumberOfCharsRead,
  PCONSOLE_READCONSOLE_CONTROL pInputControl
);
BOOL WINAPI LogWriteConsoleW(
  HANDLE  hConsoleOutput,
  const VOID    *lpBuffer,
  DWORD   nNumberOfCharsToWrite,
  LPDWORD lpNumberOfCharsWritten,
  LPVOID  lpReserved
);

///////////////////////////////////////////////////////////////////////////////
// Data
///////////////////////////////////////////////////////////////////////////////

enum CmdLogState State = clsLabel;
FILE *cmdlog = NULL;
char *cmdlog_fname_fmt = "%%USERPROFILE%%\\cmdlog-%04d.%02d.%02dT%02d.%02d.%02d.%02d-UTC-%1.1f.log";
char cmdlog_fname[MAX_PATH];
char cmdlog_fname_expanded[MAX_PATH];
static CHAR dllname[MAX_PATH];
static CHAR exename[MAX_PATH];

BOOL (__stdcall * pCreateProcessA)(
	LPCSTR a0,
	LPSTR a1,
	LPSECURITY_ATTRIBUTES a2,
	LPSECURITY_ATTRIBUTES a3,
	BOOL a4,
	DWORD a5,
	LPVOID a6,
	LPCSTR a7,
	LPSTARTUPINFOA a8,
	LPPROCESS_INFORMATION a9
) = CreateProcessA;

BOOL (__stdcall * pCreateProcessW)(
	LPCWSTR a0,
	LPWSTR a1,
	LPSECURITY_ATTRIBUTES a2,
	LPSECURITY_ATTRIBUTES a3,
	BOOL a4,
	DWORD a5,
	LPVOID a6,
	LPCWSTR a7,
	LPSTARTUPINFOW a8,
	LPPROCESS_INFORMATION a9
) = CreateProcessW;

static BOOL (WINAPI *pReadConsoleW)(
	HANDLE  hConsoleInput,
	LPVOID  lpBuffer,
	DWORD   nNumberOfCharsToRead,
	LPDWORD lpNumberOfCharsRead,
	PCONSOLE_READCONSOLE_CONTROL pInputControl
) = ReadConsoleW;

static BOOL (WINAPI *pWriteConsoleW)(
	HANDLE  hConsoleOutput,
	const VOID    *lpBuffer,
	DWORD   nNumberOfCharsToWrite,
	LPDWORD lpNumberOfCharsWritten,
	LPVOID  lpReserved
) = WriteConsoleW;

///////////////////////////////////////////////////////////////////////////////
// Definitions
///////////////////////////////////////////////////////////////////////////////

/* Adapted from Detours sample traceapi.cpp */
BOOL __stdcall HookCreateProcessA(LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
   )
{
	LogInfoStampToFile(cmdlog);
    LogToFile(cmdlog, "CreateProcessA(%hs,%hs,%p,%p,%p,%p,%p,%hs,%p,%p)\n",
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	   );

    PROCESS_INFORMATION procInfo;
    if (lpProcessInformation == NULL) {
        lpProcessInformation= &procInfo;
        ZeroMemory(&procInfo, sizeof(procInfo));
    }

    BOOL rv = 0;
    __try {
        rv = DetourCreateProcessWithDllA(lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation,
			dllname,
			pCreateProcessA
		   );
    } __finally { };
    return rv;
}

/* Adapted from Detours sample traceapi.cpp */
BOOL __stdcall HookCreateProcessW(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
   )
{
	LogInfoStampToFile(cmdlog);
    LogToFile(cmdlog, "CreateProcessW(%ls,%ls,%p,%p,%p,%p,%p,%ls,%p,%p)\n",
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	   );

    PROCESS_INFORMATION procInfo;
    if (lpProcessInformation == NULL) {
        lpProcessInformation= &procInfo;
        ZeroMemory(&procInfo, sizeof(procInfo));
    }

    BOOL rv = 0;
    __try {
        rv = DetourCreateProcessWithDllW(lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation,
			dllname,
			pCreateProcessW
		   );
    } __finally { };
    return rv;
}

BOOL WINAPI
LogReadConsoleW(
  HANDLE  hConsoleInput,
  LPVOID  lpBuffer,
  DWORD   nNumberOfCharsToRead,
  LPDWORD lpNumberOfCharsRead,
  PCONSOLE_READCONSOLE_CONTROL pInputControl
)
{
	BOOL ret = pReadConsoleW(
		hConsoleInput,
		lpBuffer,
		nNumberOfCharsToRead,
		lpNumberOfCharsRead,
		pInputControl
	   );

	/* TODO: Replace this crap code with more accurate parsing */
	if (!wcsncmp((const wchar_t *)lpBuffer, CMD_QUERY_STATUS,
				wcslen(CMD_QUERY_STATUS)))
	{
		printf("Logging to %s\n", cmdlog_fname_expanded);
		LogInfoStampToFile(stdout);
	}

	LogToFile(cmdlog, "%S", lpBuffer);
	State = clsLabel;

	return ret;
}

void
LogTimeStampToFile(FILE *out)
{
	SYSTEMTIME tm;
	TIME_ZONE_INFORMATION tzi;
	DWORD tzd;

	GetLocalTime(&tm);
	tzd = GetTimeZoneInformation(&tzi);

	LogToFile(
		out,
		"Timestamp: %04d-%02d-%02d %02d:%02d:%02d.%02d %S\n",
		tm.wYear,
		tm.wMonth,
		tm.wDay,
		tm.wHour,
		tm.wMinute,
		tm.wSecond,
		tm.wMilliseconds,
		(tzd == TIME_ZONE_ID_STANDARD)? tzi.StandardName: tzi.DaylightName
	   );
}

void
LogInfoStampToFile(FILE *out)
{
	LogToFile(
		cmdlog,
		"\n------------------------------------------------------------\n"
	   );
	LogToFile(cmdlog, "Executable module name: %s\n", exename);
	LogTimeStampToFile(out);
	LogAdapterInfoToFile(out);
	LogToFile(
		cmdlog,
		"------------------------------------------------------------\n"
	   );
}

BOOL WINAPI
LogWriteConsoleW(
  HANDLE  hConsoleOutput,
  const VOID    *lpBuffer,
  DWORD   nNumberOfCharsToWrite,
  LPDWORD lpNumberOfCharsWritten,
  LPVOID  lpReserved
)
{
	if (clsLabel == State) {
		LogInfoStampToFile(cmdlog);
		State = clsNoLabel;
	}
	LogToFile(cmdlog, "%S", lpBuffer);

	return pWriteConsoleW(
		hConsoleOutput,
		lpBuffer,
		nNumberOfCharsToWrite,
		lpNumberOfCharsWritten,
		lpReserved
	   );
}

/* Useful: http://c-faq.com/varargs/handoff.html */
static void 
_LogToFile(FILE *out, char *fmt, va_list argp)
{
	if (out) {
		vfprintf(out, fmt, argp);
		fflush(out);
	}
}

static void
LogToFile(FILE *out, char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	_LogToFile(out, fmt, argp);
	va_end(argp);
}

void
LogAdapterInfoToFile(FILE *out)
{
	DWORD Ret;
	ULONG Buflen = 0;
	PIP_ADAPTER_INFO pAdapterList = NULL;
	PIP_ADAPTER_INFO pAdapter = NULL;

	Ret = GetAdaptersInfo(NULL, &Buflen);
	if (Ret != ERROR_BUFFER_OVERFLOW) { goto exit_LogAdapterInfo; }

	pAdapterList = (PIP_ADAPTER_INFO)malloc(Buflen);
	if (pAdapterList == NULL) { goto exit_LogAdapterInfo; }

	Ret = GetAdaptersInfo(pAdapterList, &Buflen);
	if (Ret != NO_ERROR) { goto exit_LogAdapterInfo; }

	for (pAdapter = pAdapterList; pAdapter; pAdapter = pAdapter->Next) {
		switch (pAdapter->Type)
		{
			case IF_TYPE_IEEE80211:
				LogToFile(
					out,
					"Wireless: %s / %s gw %s\n",
					pAdapter->IpAddressList.IpAddress.String,
					pAdapter->IpAddressList.IpMask.String,
					pAdapter->GatewayList.IpAddress.String
				   );
				break;
			case MIB_IF_TYPE_OTHER:
			case MIB_IF_TYPE_ETHERNET:
				LogToFile(
					out,
					"Ethernet: %s / %s gw %s\n",
					pAdapter->IpAddressList.IpAddress.String,
					pAdapter->IpAddressList.IpMask.String,
					pAdapter->GatewayList.IpAddress.String
				   );
				break;

		}
	}

exit_LogAdapterInfo:
	if (pAdapterList) { free(pAdapterList); }
}

///////////////////////////////////////////////////////////////////////////////
// Entry point
///////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

		printf("Attaching logging hooks...\n");

		SYSTEMTIME tm;
		TIME_ZONE_INFORMATION tzi;
		errno_t err;
		DWORD Ret = 0;

		GetLocalTime(&tm);
		GetTimeZoneInformation(&tzi);

		_snprintf(
			cmdlog_fname,
			MAX_PATH,
			cmdlog_fname_fmt, 
			tm.wYear,
			tm.wMonth,
			tm.wDay,
			tm.wHour,
			tm.wMinute,
			tm.wSecond,
			tm.wMilliseconds,
			((float)tzi.Bias)/60
		);

		Ret = ExpandEnvironmentStringsA(
			cmdlog_fname,
			cmdlog_fname_expanded,
			MAX_PATH
		   );
		if ((Ret > MAX_PATH) || (Ret == 0)) {
			fprintf(
				stderr,
				"Failed to expand environment strings, logging disabled"
			   );
		} else {
			err = fopen_s(&cmdlog, cmdlog_fname_expanded, "a");
			if (err) {
				fprintf(
					stderr,
					"fopen_s(%s, \"a\") failed (%d), logging disabled",
					cmdlog_fname_expanded,
					err
				   );
			}
		}

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pReadConsoleW, LogReadConsoleW);
        DetourAttach(&(PVOID&)pWriteConsoleW, LogWriteConsoleW);
        DetourAttach(&(PVOID&)pCreateProcessA, HookCreateProcessA);
        DetourAttach(&(PVOID&)pCreateProcessW, HookCreateProcessW);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
			Ret = GetModuleFileNameA(hinst, dllname, ARRAYSIZE(dllname));
			if (Ret == 0) {
				LogToFile(
					cmdlog,
					"GetModuleFileNameA failed, %d\n",
					GetLastError()
				   );
			}
			/* TODO: Handle failure */

			Ret = GetModuleFileNameA(NULL, exename, ARRAYSIZE(exename));
			if (Ret == 0) {
				LogToFile(
					cmdlog,
					"GetModuleFileNameA failed, %d\n",
					GetLastError()
				   );
			}

			LogToFile(cmdlog, "Hooked by %s.\n", dllname);
			LogToFile(
				cmdlog,
				"Detoured {Read,Write}ConsoleW() and CreateProcess[AW]"
			   );
        }
        else {
            LogToFile(
				cmdlog,
				"Error detouring {Read,Write}ConsoleW(): %d\n",
				error
			   );
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)pReadConsoleW, LogReadConsoleW);
        DetourDetach(&(PVOID&)pWriteConsoleW, LogWriteConsoleW);
        error = DetourTransactionCommit();
    }
    return TRUE;
}
