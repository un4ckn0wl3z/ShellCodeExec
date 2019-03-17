/*
C++ SHELLCODE INJECTION
THANKS GUIDEDHACKING [Broihon]
RE-WRITTEN BY UN4CKN0WL3Z
VISIT	> https://guidedhacking.com/
		> https://hacked.un4ckn0wl3z.xyz/
*/
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>

HINSTANCE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR * lpModuleName);
void * GetProcAddressEx(HANDLE hTargetProc, const TCHAR * lpModuleName, const char * lpProcName);

