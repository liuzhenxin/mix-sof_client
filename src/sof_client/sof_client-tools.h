

#ifdef __cplusplus
extern "C" {
#endif
	void* MYLoadLibrary(const char *lpFileName);
	int   MYFreeLibrary(void *hModule);
	void* MYGetProcAddress(void *hModule, const char *lpProcName);

#ifdef __cplusplus
}
#endif
