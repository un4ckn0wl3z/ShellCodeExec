#include "GetProAddress.h"

HINSTANCE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR * lpModuleName)
{
	MODULEENTRY32 ME32{0};
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

	if (hSnap == INVALID_HANDLE_VALUE) 
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

			if (hSnap != INVALID_HANDLE_VALUE) {
				break;
			}
		}
	}

	if (hSnap == INVALID_HANDLE_VALUE) 
	{
		return NULL;
	}

	BOOL bRet = Module32First(hSnap,&ME32);

	do
	{

		if (!_tcsicmp(lpModuleName, ME32.szModule))
		{
			break;
		}
		bRet = Module32Next(hSnap, &ME32);


	} while (bRet);

	CloseHandle(hSnap);
	if (!bRet) {
		return NULL;
	}

	ME32.hModule;

}

//------------------------------------------------

void * GetProcAddressEx(HANDLE hTargetProc, const TCHAR * lpModuleName, const char * lpProcName)
{
	BYTE * modBase = reinterpret_cast<BYTE*>(GetModuleHandleEx(hTargetProc, lpModuleName));
	
	if(!modBase)
	{
		return nullptr;
	}

	BYTE * pe_header = new BYTE[0x1000];

	if (!pe_header)
	{
		return nullptr;
	}

	if (!ReadProcessMemory(hTargetProc, modBase, pe_header,0x1000, nullptr))
	{
		delete[] pe_header;
		return nullptr;

	}

	auto * pNT = reinterpret_cast<IMAGE_NT_HEADERS*>(pe_header + reinterpret_cast<IMAGE_DOS_HEADER*>(pe_header)->e_lfanew);

	auto * pExportEntry = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!pExportEntry->Size) {
		delete[] pe_header;
		return nullptr;
	}

	BYTE * export_data = new BYTE[pExportEntry->Size];

	if (!export_data) 
	{
		delete[] pe_header;
		return nullptr;
	}

	if (!ReadProcessMemory(hTargetProc, modBase + pExportEntry->VirtualAddress, export_data, pExportEntry->Size, nullptr));
	{
		delete[] export_data;
		delete[] pe_header;
		return nullptr;

	}

	BYTE * localBase = export_data - pExportEntry->VirtualAddress;

	auto * pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(export_data);

	auto Forward = [&](DWORD FuncRVA) -> void*
	{
	
		char pFullExport[MAX_PATH + 1]{ 0 };
		auto Len = strlen(reinterpret_cast<char*>(localBase + FuncRVA));
		
		if (!Len)
		{
			return nullptr;
		}

		memcpy(pFullExport, reinterpret_cast<char*>(localBase + FuncRVA), Len);

		char * pFuncName = strchr(pFullExport,'.');
		*(pFuncName++) = 0;

		if (*pFuncName == '#')
		{
			pFuncName = reinterpret_cast<char*>(atoi(++pFuncName));
		}

#ifdef UNICODE
		TCHAR ModNameW[MAX_PATH + 1]{ 0 };
		size_t SizeOut = 0;
		mbstowcs_s(&SizeOut, ModNameW, pFullExport, MAX_PATH);
		return GetProcAddressEx(hTargetProc, ModNameW, pFuncName);
#else
		return GetProcAddressEx(hTargetProc, pFullExport, pFuncName);
#endif


	};

	if ((reinterpret_cast<UINT_PTR>(lpProcName) & 0xFFFFFF) <= MAXWORD)
	{
		WORD Base = LOWORD(pExportDir->Base-1);
		WORD Ordinal = LOWORD(lpProcName) - Base;
		DWORD FuncRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];

		delete[] export_data;
		delete[] pe_header;

		if (FuncRVA >= pExportEntry->VirtualAddress && FuncRVA < pExportEntry->VirtualAddress + pExportEntry->Size) 
		{
			return Forward(FuncRVA);
		}

		return modBase + FuncRVA;

	}

	DWORD max = pExportDir->NumberOfNames - 1;
	DWORD min = 0;
	DWORD FuncRVA = 0;

	while (min<max)
	{
		DWORD mid = (min + max) / 2;
		DWORD CurrrentNameRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfNames)[mid];
		char * szName = reinterpret_cast<char*>(localBase + CurrrentNameRVA);

		int cmp = strcmp(szName, lpProcName);
		if(cmp < 0)
		{
			min = mid + 1;
		}
		else if (cmp > 0) 
		{
			max = mid - 1;
		}
		else
		{
			WORD Ordinal = reinterpret_cast<WORD*>(localBase + pExportDir->AddressOfNameOrdinals)[mid];
			FuncRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];

			break;
		}



	}

	delete[] export_data;
	delete[] pe_header;

	if (!FuncRVA) 
	{
		return nullptr;
	}

	if (FuncRVA >= pExportEntry->VirtualAddress && FuncRVA < pExportEntry->VirtualAddress + pExportEntry->Size)
	{
		return Forward(FuncRVA);
	}

	return modBase + FuncRVA;


}

















