

#ifdef __cplusplus
extern "C" {
#endif
	void* MYLoadLibrary(const char *lpFileName);
	int   MYFreeLibrary(void *hModule);
	void* MYGetProcAddress(void *hModule, const char *lpProcName);

	int MYValidWTFile(const wchar_t *pFilePath, const wchar_t *pCommonName);

	int IsFileDigitallySigned(const wchar_t *pFilePath);

#ifdef __cplusplus
}
#endif
