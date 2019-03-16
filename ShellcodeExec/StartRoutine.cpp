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

DWORD SR_NtCreateThreadEx(HANDLE hTargetProc, f_Routine * pRoutine, void * pArg, DWORD & LastWin32Error, UINT_PTR & Out)
{
	return 0;
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
