
#include <windows.h>
#include <vector>
#include <assert.h>

#include "shadowMap.h"

#define MAX_SECTION	28

static
PVOID		g_mapAddress = NULL;

static
ULONG_PTR	mapAddress[MAX_SECTION] = { 0 };

static
ULONG		mapSize[MAX_SECTION] = { 0 };

static
ULONG_PTR	realAddress[MAX_SECTION] = { 0 };

static
ULONG		realSize[MAX_SECTION] = { 0 };

static
DWORD		oldProtect[MAX_SECTION] = { 0 };

static
size_t		section_count = 0;

/**
 * VEH
 */
LONG WINAPI VEH(PEXCEPTION_POINTERS ExceptionInfo)
{
	PVOID	crashAddr = ExceptionInfo->ExceptionRecord->ExceptionAddress;

	for (size_t i = 0; i < section_count; i++)
	{
		if (realAddress[i] <= (ULONG_PTR)crashAddr &&
			(realAddress[i] + realSize[i]) >= (ULONG_PTR)crashAddr)
		{

#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rip = \
				(ULONG_PTR)crashAddr - realAddress[i] + mapAddress[i];
#else
			ExceptionInfo->ContextRecord->Eip = \
				(ULONG_PTR)crashAddr - realAddress[i] + mapAddress[i];
#endif

			return EXCEPTION_CONTINUE_EXECUTION;
		}


		if (mapAddress[i] <= (ULONG_PTR)crashAddr &&
			(mapAddress[i] + mapSize[i]) >= (ULONG_PTR)crashAddr)
		{

#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rip = \
				(ULONG_PTR)crashAddr - mapAddress[i] + realAddress[i];
			ExceptionInfo->ExceptionRecord->ExceptionAddress = (PVOID) \
				((ULONG_PTR)crashAddr - mapAddress[i] + realAddress[i]);

#else
			ExceptionInfo->ContextRecord->Eip = \
				(ULONG_PTR)crashAddr - mapAddress[i] + realAddress[i];
			ExceptionInfo->ExceptionRecord->ExceptionAddress = (PVOID) \
				((ULONG_PTR)crashAddr - mapAddress[i] + realAddress[i]);
#endif

			return EXCEPTION_CONTINUE_EXECUTION;
		}

	}

	return EXCEPTION_CONTINUE_SEARCH;
}


/**
* 安装hook
*/
BOOL WINAPI shadowMap_InstallHook(HMODULE hModule)
{
	assert(hModule);

	PIMAGE_DOS_HEADER		doshead_ptr;
	PIMAGE_NT_HEADERS		nthead_ptr;
	PIMAGE_SECTION_HEADER	sec_ptr;
	HANDLE					hProcess;
	DWORD					protect;

	doshead_ptr = (PIMAGE_DOS_HEADER)hModule;
	if (doshead_ptr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	nthead_ptr = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + doshead_ptr->e_lfanew);
	if (nthead_ptr->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	g_mapAddress = VirtualAlloc(NULL, nthead_ptr->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (g_mapAddress == NULL)
	{
		return FALSE;
	}

	//
	//获取首个区段
	//

	sec_ptr = IMAGE_FIRST_SECTION(nthead_ptr);

	//
	//添加VEH异常
	//

	AddVectoredExceptionHandler(0, VEH);

	section_count = 0;
	for (int i = 0; i < nthead_ptr->FileHeader.NumberOfSections; i++)
	{
		if (sec_ptr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			mapAddress[section_count] = (ULONG_PTR)g_mapAddress + sec_ptr->VirtualAddress;
			mapSize[section_count] = sec_ptr->Misc.VirtualSize;
			realAddress[section_count] = (ULONG_PTR)hModule + sec_ptr->VirtualAddress;
			realSize[section_count] = sec_ptr->Misc.VirtualSize;
			oldProtect[section_count] = sec_ptr->Characteristics;

			memcpy((void*)mapAddress[section_count],
				   (void*)realAddress[section_count],
				   sec_ptr->Misc.VirtualSize);

			section_count++;
			
		}
		sec_ptr++;
	}



	//
	//绕过VMP3.X 内存保护
	//

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProcess != NULL)
	{
		for (size_t i = 0; i < section_count; i++)
		{
			protect = PAGE_READWRITE;
			VirtualProtectEx(hProcess, (LPVOID)realAddress[i],
							 realSize[i],
							 protect,
							 &oldProtect[i]);
		}
		CloseHandle(hProcess);
	}
	else
	{
		for (size_t i = 0; i < section_count; i++)
		{
			protect = PAGE_READWRITE;
			VirtualProtectEx((HANDLE)-1, (LPVOID)realAddress[i],
							 realSize[i],
							 protect,
							 &oldProtect[i]);
		}
	
	}
	return TRUE;
}

/**
* 卸载Hook
*/
BOOL WINAPI shadowMap_UnloadHook()
{
	return TRUE;
}

/**
* 读shadowMap内存
*/
BOOL WINAPI shadowMap_ReadMem(PVOID addr, UCHAR *buf, ULONG size)
{
	return TRUE;
}

/**
* 写shadowMap内存
*/
BOOL WINAPI shadowMap_WriteMem(PVOID addr, UCHAR *buf, ULONG size)
{
	return TRUE;
}