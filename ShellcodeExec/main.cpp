#include "StartRoutine.h"

#define DLL_PATH_X86 TEXT("C:\\Users\\unk\\Desktop\\x86.dll")
#define DLL_PATH_X64 TEXT("C:\\Users\\unk\\Desktop\\x64.dll")

#define PROCESS_NAME_X86 TEXT("X86Console - x86.exe")
#define PROCESS_NAME_X64 TEXT("X64Console - x64.exe")

#define LOAD_LIBRARY_NAME_A "LoadLibraryA"
#define LOAD_LIBRARY_NAME_W "LoadLibraryW"

#ifdef UNICODE
#define LOAD_LIBRARY_NAME LOAD_LIBRARY_NAME_W
#else
#define LOAD_LIBRARY_NAME LOAD_LIBRARY_NAME_A
#endif // UNICODE

#ifdef _WIN64
#define DLL_PATH		DLL_PATH_X64
#define PROCESS_NAME	PROCESS_NAME_X64
#else
#define DLL_PATH		DLL_PATH_X86
#define PROCESS_NAME	PROCESS_NAME_X86
#endif // _WIN64


HANDLE GetProcessByName(const TCHAR * szProcName, DWORD dwDesiredAccess = PROCESS_ALL_ACCESS)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap = INVALID_HANDLE_VALUE)
	{
		return nullptr;
	}

	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	BOOL bRet = Process32First(hSnap,&PE32);

	while (bRet)
	{
		if (!_tcsicmp(PE32.szExeFile, szProcName))
		{
			break;
		}

		bRet = Process32Next(hSnap, &PE32);

	}
	CloseHandle(hSnap);

	if (!bRet)
	{
		return nullptr;
	}

	return OpenProcess(dwDesiredAccess,FALSE,PE32.th32ProcessID);


}


bool InjectDll(const TCHAR * szProcess, const TCHAR * szPath, LAUNCH_METHOD Method) 
{
	HANDLE hProc = GetProcessByName(szProcess);
	if (!hProc)
	{
		DWORD dwErr = GetLastError();
		printf("OpenProcess failed: 0x%08X\n", dwErr);
		return false;
	}

	auto len = _tcslen(szPath) * sizeof(TCHAR);

	void * pArg = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pArg)
	{
		DWORD dwErr = GetLastError();
		printf("VirtualAllocEx failed: 0x%08X\n", dwErr);
		CloseHandle(hProc);
		return false;
	}

	BOOL bRet = WriteProcessMemory(hProc, pArg, szPath,len,nullptr);

	if (!bRet)
	{
		DWORD dwErr = GetLastError();
		printf("WriteProcessMemory failed: 0x%08X\n", dwErr);
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;
	}

	f_Routine * p_LoadLibrary = reinterpret_cast<f_Routine*>(GetProcAddressEx(hProc, TEXT("kernel32.dll"), LOAD_LIBRARY_NAME));


	if (!p_LoadLibrary)
	{
		
		printf("Search LoadLibrary Failed failed\n");
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;
	}

	UINT_PTR hDllOut = 0;
	DWORD last_error = 0;
	DWORD dwErr = StartRoutine(hProc, p_LoadLibrary, pArg, Method, last_error, hDllOut);
	if (Method != LM_QueueUserAPC) 
	{
		VirtualFreeEx(hProc, pArg, 0, MEM_RELEASE);
	}
	CloseHandle(hProc);


	if (dwErr)
	{
		printf("StartRoutine failed: 0x%08X\n", dwErr);
		printf("	LastWin32Error: 0x%08X\n", last_error);
		return false;
	}

	printf("Success LoadLibrary returned: 0x%p\n", reinterpret_cast<void*>(hDllOut));

	return true;



}


int main()
{
	bool bRet = InjectDll(PROCESS_NAME,DLL_PATH,LM_NtCreateThreadEx);

	if (!bRet)
	{
		printf("Press enter to exit.\n");
		std::cin.get();

	}
	return 0;
}


































