#include "sof_client-tools.h"

#include <Windows.h>


void* MYLoadLibrary(const char *lpFileName)
{
	return LoadLibraryA(lpFileName);
}

int   MYFreeLibrary(void *hModule)
{
	return FreeLibrary((HMODULE)hModule);
}

void* MYGetProcAddress(void *hModule, const char *lpProcName)
{
	return GetProcAddress((HMODULE)hModule, lpProcName);
}