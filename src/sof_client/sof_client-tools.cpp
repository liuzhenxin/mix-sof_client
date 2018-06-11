#include "sof_client-tools.h"

#include <Windows.h>

#include <Softpub.h>  
#include <Wincrypt.h>  
#include <Softpub.h>  
#include <Wintrust.h>  
#include <mscat.h>  
#include <wchar.h>  

#pragma comment(lib, "Crypt32.lib")  
#pragma comment(lib, "Wintrust.lib")  

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

LPTSTR GetCertificateDescription(const PCCERT_CONTEXT pCertCtx)
{
	DWORD dwStrType;
	DWORD dwCount;
	LPTSTR szSubjectRDN = NULL;

	dwStrType = CERT_X500_NAME_STR;
	dwCount = CertGetNameString(pCertCtx,
		CERT_NAME_RDN_TYPE,
		0,
		&dwStrType,
		NULL,
		0);
	if (dwCount)
	{
		szSubjectRDN = (LPTSTR)LocalAlloc(0, dwCount * sizeof(TCHAR));
		CertGetNameString(pCertCtx,
			CERT_NAME_RDN_TYPE,
			0,
			&dwStrType,
			szSubjectRDN,
			dwCount);
	}

	return szSubjectRDN;
}

int IsFileDigitallySigned(const wchar_t *pFilePath)
{
	//Author: AD, 2009  
	PVOID Context;
	HANDLE FileHandle;
	DWORD HashSize = 0;
	PBYTE Buffer;
	PVOID CatalogContext;
	CATALOG_INFO InfoStruct;
	WINTRUST_DATA WintrustStructure;
	WINTRUST_CATALOG_INFO WintrustCatalogStructure;
	WINTRUST_FILE_INFO WintrustFileStructure;
	PWCHAR MemberTag;
	int ReturnFlag = FALSE;
	ULONG ReturnVal;
	GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	//Zero our structures.  
	memset(&InfoStruct, 0, sizeof(CATALOG_INFO));
	InfoStruct.cbStruct = sizeof(CATALOG_INFO);
	memset(&WintrustCatalogStructure, 0, sizeof(WINTRUST_CATALOG_INFO));
	WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
	memset(&WintrustFileStructure, 0, sizeof(WINTRUST_FILE_INFO));
	WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);

	//Get a context for signature verification.  
	if (!CryptCATAdminAcquireContext(&Context, NULL, 0))
	{
		return FALSE;
	}

	//Open file.  
	FileHandle = CreateFileW(pFilePath, GENERIC_READ, 7, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == FileHandle)
	{
		CryptCATAdminReleaseContext(Context, 0);
		return FALSE;
	}

	//Get the size we need for our hash.  
	CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, NULL, 0);
	if (HashSize == 0)
	{
		//0-sized has means error!  
		CryptCATAdminReleaseContext(Context, 0);
		CloseHandle(FileHandle);
		return FALSE;
	}

	//Allocate memory.  
	Buffer = (PBYTE)calloc(HashSize, 1);

	//Actually calculate the hash  
	if (!CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, Buffer, 0))
	{
		CryptCATAdminReleaseContext(Context, 0);
		free(Buffer);
		CloseHandle(FileHandle);
		return FALSE;
	}

	//Convert the hash to a string.  
	MemberTag = (PWCHAR)calloc((HashSize * 2) + 1, sizeof(WCHAR));
	for (unsigned int i = 0; i < HashSize; i++)
	{
		swprintf(&MemberTag[i * 2], 100, L"%02X", Buffer[i]);
	}

	//Get catalog for our context.  
	CatalogContext = CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, NULL);
	if (CatalogContext)
	{
		//If we couldn't get information  
		if (!CryptCATCatalogInfoFromContext(CatalogContext, &InfoStruct, 0))
		{
			//Release the context and set the context to null so it gets picked up below.  
			CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);
			CatalogContext = NULL;
		}
	}

	//If we have a valid context, we got our info.    
	//Otherwise, we attempt to verify the internal signature.  
	if (!CatalogContext)
	{
		WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
		WintrustFileStructure.pcwszFilePath = pFilePath;
		WintrustFileStructure.hFile = NULL;
		WintrustFileStructure.pgKnownSubject = NULL;

		WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
		WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE;
		WintrustStructure.pFile = &WintrustFileStructure;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
		WintrustStructure.dwStateAction = WTD_STATEACTION_IGNORE;
		WintrustStructure.dwProvFlags = WTD_SAFER_FLAG;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
	}
	else
	{
		//If we get here, we have catalog info!  Verify it.  
		WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
		WintrustStructure.pPolicyCallbackData = 0;
		WintrustStructure.pSIPClientData = 0;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
		WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG;
		WintrustStructure.pCatalog = &WintrustCatalogStructure;
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
		WintrustStructure.dwProvFlags = 0;
		WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE;

		//Fill in catalog info structure.  
		WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		WintrustCatalogStructure.dwCatalogVersion = 0;
		WintrustCatalogStructure.pcwszCatalogFilePath = InfoStruct.wszCatalogFile;
		WintrustCatalogStructure.pcwszMemberTag = MemberTag;
		WintrustCatalogStructure.pcwszMemberFilePath = pFilePath;
		WintrustCatalogStructure.hMemberFile = NULL;
	}

	//Call our verification function.  
	ReturnVal = WinVerifyTrust(0, &ActionGuid, &WintrustStructure);

	//Check return.  
	ReturnFlag = SUCCEEDED(ReturnVal);

	//Free context.  
	if (CatalogContext)
		CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);

	//If we successfully verified, we need to free.  
	if (ReturnFlag)
	{
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(0, &ActionGuid, &WintrustStructure);
	}

	//Free memory.  
	free(MemberTag);
	free(Buffer);
	CloseHandle(FileHandle);
	CryptCATAdminReleaseContext(Context, 0);

	return ReturnFlag;
}

int MYValidWTFile(const wchar_t *pFilePath,const wchar_t *pCommonName)
{
	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO sWintrustFileInfo;
	WINTRUST_DATA      sWintrustData;
	HRESULT            hr;
	BOOL res = FALSE;

	memset((void*)&sWintrustFileInfo, 0x00, sizeof(WINTRUST_FILE_INFO));
	memset((void*)&sWintrustData, 0x00, sizeof(WINTRUST_DATA));

	sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	sWintrustFileInfo.pcwszFilePath = pFilePath;
	sWintrustFileInfo.hFile = NULL;

	sWintrustData.cbStruct = sizeof(WINTRUST_DATA);
	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	sWintrustData.dwUnionChoice = WTD_CHOICE_FILE;
	sWintrustData.pFile = &sWintrustFileInfo;
	sWintrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);

	if (TRUST_E_NOSIGNATURE == hr)
	{
		//
	}
	else if (TRUST_E_BAD_DIGEST == hr)
	{
		//
	}
	else if (TRUST_E_PROVIDER_UNKNOWN == hr)
	{
		//
	}
	else if (S_OK != hr)
	{
		//
	}
	else
	{
		// retreive the signer certificate and display its information  
		CRYPT_PROVIDER_DATA const *psProvData = NULL;
		CRYPT_PROVIDER_SGNR       *psProvSigner = NULL;
		CRYPT_PROVIDER_CERT       *psProvCert = NULL;
		FILETIME                   localFt;
		SYSTEMTIME                 sysTime;

		psProvData = WTHelperProvDataFromStateData(sWintrustData.hWVTStateData);
		if (psProvData)
		{
			psProvSigner = WTHelperGetProvSignerFromChain((PCRYPT_PROVIDER_DATA)psProvData, 0, FALSE, 0);
			if (psProvSigner)
			{
				FileTimeToLocalFileTime(&psProvSigner->sftVerifyAsOf, &localFt);
				FileTimeToSystemTime(&localFt, &sysTime);

				
				psProvCert = WTHelperGetProvCertFromChain(psProvSigner, 0);
				if (psProvCert)
				{
					LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
					if (szCertDesc)
					{
						if (0 != wcsstr(szCertDesc, pCommonName))
						{
							res = TRUE;
						}

						LocalFree(szCertDesc);
					}
				}

				if (psProvSigner->csCounterSigners)
				{
					// Timestamp information  
					FileTimeToLocalFileTime(&psProvSigner->pasCounterSigners[0].sftVerifyAsOf, &localFt);
					FileTimeToSystemTime(&localFt, &sysTime);

					psProvCert = WTHelperGetProvCertFromChain(&psProvSigner->pasCounterSigners[0], 0);
					if (psProvCert)
					{
						LPTSTR szCertDesc = GetCertificateDescription(psProvCert->pCert);
						if (szCertDesc)
						{
							if (0 != wcsstr(szCertDesc, pCommonName))
							{
								res = TRUE;
							}

							LocalFree(szCertDesc);
						}
					}
				}
			}
		}
	}

	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);

	return res;
}