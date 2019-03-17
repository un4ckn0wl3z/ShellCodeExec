/*
C++ SHELLCODE INJECTION
THANKS GUIDEDHACKING [Broihon]
RE-WRITTEN BY UN4CKN0WL3Z
VISIT	> https://guidedhacking.com/
		> https://hacked.un4ckn0wl3z.xyz/
*/
#include "StartRoutine.h"


DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & RemoteRet);
DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & RemoteRet);
DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & RemoteRet);
DWORD SR_QueueUserAPC(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & RemoteRet);



DWORD StartRoutine(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, LAUNCH_METHOD Method, DWORD & LastWin32Error, UINT_PTR & RemoteRet)
{

	DWORD dwRet = 0;
	switch (Method)
	{
	case LM_NtCreateThreadEx:
		dwRet = SR_NtCreateThreadEx(hTargetProc, pRoutine, pArg, LastWin32Error, RemoteRet);
		break;
	case LM_HijackThread:
		dwRet = SR_HijackThread(hTargetProc, pRoutine, pArg, LastWin32Error, RemoteRet);
		break;
	case LM_SetWindowsHookEx:
		dwRet = SR_SetWindowsHookEx(hTargetProc, pRoutine, pArg, LastWin32Error, RemoteRet);
		break;
	case LM_QueueUserAPC:
		dwRet = SR_QueueUserAPC(hTargetProc, pRoutine, pArg, LastWin32Error, RemoteRet);
		break;
	default:
		dwRet = SR_ERR_INVALID_LAUNCH_METHOD;
		break;
	}



	return dwRet;
}

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & RemoteRet)
{
	auto p_NtCreateThreadEx = reinterpret_cast<f_NtCreateThreadEx>(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx")); // cast WINAPI to pointer func

	if (!p_NtCreateThreadEx)
	{
		LastWin32Error = GetLastError();
		return SR_NTCTE_ERR_NTCTE_MISSING;
	}

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	if(!pMem)
	{
		LastWin32Error = GetLastError();
		return SR_NTCTE_ERR_CANT_ALLOC_MEM;
	}

#ifdef _WIN64
	BYTE Shellcode[] =
	{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x10   -> argument / returned value
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x08   -> pRoutine

			0x48, 0x8B, 0xC1,                                   // + 0x00   -> mov rax, rcx
			0x48, 0x8B, 0x08,                                   // + 0x03   -> mov rcx, [rax]

			0x48, 0x83, 0xEC, 0x28,                             // + 0x06   -> sub rsp, 0x28
			0xFF, 0x50, 0x08,                                   // + 0x0A   -> call qword ptr [rax + 0x08]
			0x48, 0x83, 0xC4, 0x28,                             // + 0x0D   -> add rsp, 0x28

			0x48, 0x8D, 0x0D, 0xD8, 0xFF, 0xFF, 0xFF,           // + 0x11   -> lea rcx, [pCodecave]
			0x48, 0x89, 0x01,                                   // + 0x18   -> mov [rcx], rax
			0x48, 0x31, 0xC0,                                   // + 0x1B   -> xor rax, rax

			0xC3                                                // + 0x1E   -> ret
	}; // SIZE = 0x1F (+ 0x10)

	*reinterpret_cast<void**>		(Shellcode + 0x00) = pArg; // setup argument

	//-------------------
	/*
	//Buffer argument passed to NtCreateThreadEx function

	struct NtCreateThreadExBuffer
	{
		ULONG Size;
		ULONG Unknown1;
		ULONG Unknown2;
		PULONG Unknown3;
		ULONG Unknown4;
		ULONG Unknown5;
		ULONG Unknown6;
		PULONG Unknown7;
		ULONG Unknown8;
	};
	*/
	//-------------------


	*reinterpret_cast<f_Routine**>	(Shellcode + 0x08) = pRoutine; // setup Routine

	DWORD FuncOffset = 0x10;
	BOOL bRet = WriteProcessMemory(hTargetProc,pMem, Shellcode,sizeof(Shellcode),nullptr);

	if(!bRet)
	{
		LastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
		return SR_NTCTE_ERR_WPM_FAIL;
	}

	void * pRemoteArg = pMem;
	void * pRemoteFunc = reinterpret_cast<BYTE*>(pMem) + FuncOffset;

	HANDLE hThread = nullptr;
	/*

	typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) 
	(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended, 
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);
	
	*/
	NTSTATUS ntRet = p_NtCreateThreadEx(&hThread,THREAD_ALL_ACCESS, nullptr,hTargetProc,pRemoteFunc,pRemoteArg,0,0,0,0,nullptr);

	if (NT_FAIL(ntRet) || !hThread)
	{

		LastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
		return SR_NTCTE_ERR_NTCTE_FAIL;

	}

	DWORD dwWaitRet = WaitForSingleObject(hThread, SR_REMOTE_TIMEOUT);
	
	if (dwWaitRet != WAIT_OBJECT_0)
	{
		LastWin32Error = GetLastError();
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_TIMEOUT;
	}
	CloseHandle(hThread);

	bRet = ReadProcessMemory(hTargetProc,pMem,&RemoteRet,sizeof(RemoteRet),nullptr);

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	if (!bRet) 
	{
		LastWin32Error = GetLastError();
		return SR_NTCTE_ERR_RPM_FAIL;
	}

#else

	HANDLE hThread = nullptr;

	NTSTATUS ntRet = p_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRoutine, pArg, 0, 0, 0, 0, nullptr);


	if (NT_FAIL(ntRet) || !hThread)
	{

		LastWin32Error = GetLastError();
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);
		return SR_NTCTE_ERR_NTCTE_FAIL;

	}
	DWORD dwWaitRet = WaitForSingleObject(hThread, SR_REMOTE_TIMEOUT);

	if (dwWaitRet != WAIT_OBJECT_0)
	{
		LastWin32Error = GetLastError();
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_NTCTE_ERR_TIMEOUT;
	}

	DWORD dwRemoteRet = 0;
	BOOL bRet = GetExitCodeThread(hThread, &dwRemoteRet);
	if (!bRet)
	{
		LastWin32Error = GetLastError();
		CloseHandle(hThread);
		return SR_NTCTE_ERR_RPM_FAIL;
	}

	RemoteRet = dwRemoteRet;

	CloseHandle(hThread);

#endif // _WIN64


	return SR_ERR_SUCCESS;
}

DWORD SR_HijackThread(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & Out)
{
	return 0;
}

DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & Out)
{
	return 0;
}

DWORD SR_QueueUserAPC(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & Out)
{
	return 0;
}
