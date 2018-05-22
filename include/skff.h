/**
 * Created by LQQ on 2017/11/13.
 */


CK_SKF_FUNCTION_INFO(SKF_SetPackageName)
#ifdef CK_NEED_ARG_LIST
(
  LPSTR szPackageName
);
#endif


CK_SKF_FUNCTION_INFO(SKF_WaitForDevEvent)
#ifdef CK_NEED_ARG_LIST
(
  LPSTR szDevName,
  ULONG *pulDevNameLen,
  ULONG *pulEvent
);
#endif


CK_SKF_FUNCTION_INFO(SKF_CancelWaitForDevEvent)
#ifdef CK_NEED_ARG_LIST
(

);
#endif

CK_SKF_FUNCTION_INFO(SKF_EnumDev)
#ifdef CK_NEED_ARG_LIST
(
  BOOL bPresent,
  LPSTR szNameList,
  ULONG *pulSize
);
#endif

CK_SKF_FUNCTION_INFO(SKF_ConnectDev)
#ifdef CK_NEED_ARG_LIST
(
  LPSTR szName,
  DEVHANDLE *phDev
);
#endif

CK_SKF_FUNCTION_INFO(SKF_DisConnectDev)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev
);
#endif


CK_SKF_FUNCTION_INFO(SKF_GetDevState)
#ifdef CK_NEED_ARG_LIST
(
  LPSTR szDevName,
  ULONG *pulDevState
);
#endif

CK_SKF_FUNCTION_INFO(SKF_SetLabel)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  LPSTR szLabel
);
#endif

CK_SKF_FUNCTION_INFO(SKF_GetDevInfo)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  DEVINFO *pDevInfo
);
#endif


CK_SKF_FUNCTION_INFO(SKF_LockDev)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ULONG ulTimeOut
);
#endif

CK_SKF_FUNCTION_INFO(SKF_UnlockDev)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev
);
#endif

CK_SKF_FUNCTION_INFO(SKF_Transmit)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  BYTE* pbCommand,
  ULONG ulCommandLen,
  BYTE* pbData,
  ULONG* pulDataLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_ChangeDevAuthKey)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  BYTE *pbKeyValue,
  ULONG ulKeyLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_DevAuth)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  BYTE *pbAuthData,
  ULONG ulLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_ChangePIN)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  ULONG ulPINType,
  LPSTR szOldPin,
  LPSTR szNewPin,
  ULONG *pulRetryCount
);
#endif


CK_SKF_FUNCTION_INFO(SKF_GetPINInfo)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  ULONG  ulPINType,
  ULONG *pulMaxRetryCount,
  ULONG *pulRemainRetryCount,
  BOOL *pbDefaultPin
);
#endif


CK_SKF_FUNCTION_INFO(SKF_VerifyPIN)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  ULONG  ulPINType,
  LPSTR szPIN,
  ULONG *pulRetryCount
);
#endif


CK_SKF_FUNCTION_INFO(SKF_UnblockPIN)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szAdminPIN,
  LPSTR szNewUserPIN,
  ULONG *pulRetryCount
);
#endif


CK_SKF_FUNCTION_INFO(SKF_ClearSecureState)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication
);
#endif


CK_SKF_FUNCTION_INFO(SKF_CreateApplication)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  LPSTR szAppName,
  LPSTR szAdminPin,
  DWORD dwAdminPinRetryCount,
  LPSTR szUserPin,
  DWORD dwUserPinRetryCount,
  DWORD dwCreateFileRights,
  HAPPLICATION *phApplication
);
#endif


CK_SKF_FUNCTION_INFO(SKF_EnumApplication)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  LPSTR szAppName,
  ULONG *pulSize
);
#endif

CK_SKF_FUNCTION_INFO(SKF_DeleteApplication)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  LPSTR szAppName
);
#endif


CK_SKF_FUNCTION_INFO(SKF_OpenApplication)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  LPSTR szAppName,
  HAPPLICATION *phApplication
);
#endif


CK_SKF_FUNCTION_INFO(SKF_CloseApplication)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication
);
#endif

CK_SKF_FUNCTION_INFO(SKF_CreateFile)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szFileName,
  ULONG ulFileSize,
  ULONG ulReadRights,
  ULONG ulWriteRights
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DeleteFile)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szFileName
);
#endif



CK_SKF_FUNCTION_INFO(SKF_EnumFiles)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szFileList,
  ULONG *pulSize
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GetFileInfo)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szFileName,
  FILEATTRIBUTE *pFileInfo
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ReadFile)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szFileName,
  ULONG ulOffset,
  ULONG ulSize,
  BYTE * pbOutData,
  ULONG *pulOutLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_WriteFile)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szFileName,
  ULONG  ulOffset,
  BYTE *pbInData,
  ULONG ulSize
);
#endif



CK_SKF_FUNCTION_INFO(SKF_CreateContainer)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szContainerName,
  HCONTAINER *phContainer
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DeleteContainer)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szContainerName
);
#endif



CK_SKF_FUNCTION_INFO(SKF_OpenContainer)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szContainerName,
  HCONTAINER *phContainer
);
#endif



CK_SKF_FUNCTION_INFO(SKF_CloseContainer)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer
);
#endif


CK_SKF_FUNCTION_INFO(SKF_EnumContainer)
#ifdef CK_NEED_ARG_LIST
(
  HAPPLICATION hApplication,
  LPSTR szContainerName,
  ULONG *pulSize
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GetContainerType)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG *pulContainerType
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ImportCertificate)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  BOOL bSignFlag,
  BYTE* pbCert,
  ULONG ulCertLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExportCertificate)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  BOOL bSignFlag,
  BYTE* pbCert,
  ULONG *pulCertLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenRandom)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  BYTE *pbRandom,
  ULONG ulRandomLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenExtRSAKey)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ULONG ulBitsLen,
  RSAPRIVATEKEYBLOB *pBlob
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenRSAKeyPair)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer, 
  ULONG ulBitsLen, 
  RSAPUBLICKEYBLOB *pBlob
);
#endif

CK_SKF_FUNCTION_INFO(SKF_ImportRSAKeyPair)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG ulSymAlgId,
  BYTE *pbWrappedKey, 
  ULONG ulWrappedKeyLen,
  BYTE *pbEncryptedData,
  ULONG ulEncryptedDataLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_RSASignData)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  BYTE *pbData,
  ULONG  ulDataLen,
  BYTE *pbSignature,
  ULONG *pulSignLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_RSAVerify)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev ,
  RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
  BYTE *pbData,
  ULONG  ulDataLen,
  BYTE *pbSignature,
  ULONG ulSignLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_RSAExportSessionKey)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG ulAlgId,
  RSAPUBLICKEYBLOB *pPubKey,
  BYTE *pbData,
  ULONG  *pulDataLen,
  HANDLE *phSessionKey
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExtRSAPubKeyOperation)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  RSAPUBLICKEYBLOB* pRSAPubKeyBlob,
  BYTE* pbInput,
  ULONG ulInputLen,
  BYTE* pbOutput,
  ULONG* pulOutputLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExtRSAPriKeyOperation)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,
  BYTE* pbInput,
  ULONG ulInputLen,
  BYTE* pbOutput,
  ULONG* pulOutputLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenECCKeyPair)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG ulAlgId,
  ECCPUBLICKEYBLOB *pBlob
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ImportECCKeyPair)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  PENVELOPEDKEYBLOB pEnvelopedKeyBlob
);
#endif


CK_SKF_FUNCTION_INFO(SKF_ECCSignData)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  BYTE *pbData,
  ULONG  ulDataLen,
  PECCSIGNATUREBLOB pSignature
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ECCVerify)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev ,
  ECCPUBLICKEYBLOB* pECCPubKeyBlob,
  BYTE *pbData,
  ULONG  ulDataLen,
  PECCSIGNATUREBLOB pSignature
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ECCExportSessionKey)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG ulAlgId,
  ECCPUBLICKEYBLOB *pPubKey,
  PECCCIPHERBLOB pData,
  HANDLE *phSessionKey
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExtECCEncrypt)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
  BYTE* pbPlainText,
  ULONG ulPlainTextLen,
  PECCCIPHERBLOB pCipherText
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExtECCDecrypt)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ECCPRIVATEKEYBLOB*  pECCPriKeyBlob,
  PECCCIPHERBLOB pCipherText,
  BYTE* pbPlainText,
  ULONG* pulPlainTextLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExtECCSign)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ECCPRIVATEKEYBLOB*  pECCPriKeyBlob,
  BYTE* pbData,
  ULONG ulDataLen,
  PECCSIGNATUREBLOB pSignature
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExtECCVerify)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
  BYTE* pbData,
  ULONG ulDataLen,
  PECCSIGNATUREBLOB pSignature
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenerateAgreementDataWithECC)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG ulAlgId,
  ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
  BYTE* pbID,
  ULONG ulIDLen,
  HANDLE *phAgreementHandle
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenerateAgreementDataAndKeyWithECC)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hContainer,
  ULONG ulAlgId,
  ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob,
  ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
  ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
  BYTE* pbID,
  ULONG ulIDLen,
  BYTE *pbSponsorID,
  ULONG ulSponsorIDLen,
  HANDLE *phKeyHandle
);
#endif



CK_SKF_FUNCTION_INFO(SKF_GenerateKeyWithECC)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hAgreementHandle,
  ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
  ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
  BYTE* pbID,
  ULONG ulIDLen,
  HANDLE *phKeyHandle
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ExportPublicKey)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  BOOL bSignFlag,
  BYTE* pbBlob,
  ULONG* pulBlobLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_ImportSessionKey)
#ifdef CK_NEED_ARG_LIST
(
  HCONTAINER hContainer,
  ULONG ulAlgId,
  BYTE *pbWrapedData,
  ULONG ulWrapedLen,
  HANDLE *phKey
);
#endif



CK_SKF_FUNCTION_INFO(SKF_SetSymmKey)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  BYTE* pbKey,
  ULONG ulAlgID,
  HANDLE* phKey
);
#endif



CK_SKF_FUNCTION_INFO(SKF_EncryptInit)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BLOCKCIPHERPARAM EncryptParam
);
#endif



CK_SKF_FUNCTION_INFO(SKF_Encrypt)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BYTE * pbData,
  ULONG ulDataLen,
  BYTE *pbEncryptedData,
  ULONG *pulEncryptedLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_EncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BYTE * pbData,
  ULONG ulDataLen,
  BYTE *pbEncryptedData,
  ULONG *pulEncryptedLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_EncryptFinal)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BYTE *pbEncryptedData,
  ULONG *ulEncryptedDataLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DecryptInit)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BLOCKCIPHERPARAM DecryptParam
);
#endif



CK_SKF_FUNCTION_INFO(SKF_Decrypt)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BYTE * pbEncryptedData,
  ULONG ulEncryptedLen,
  BYTE * pbData,
  ULONG * pulDataLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DecryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BYTE * pbEncryptedData,
  ULONG ulEncryptedLen,
  BYTE * pbData,
  ULONG * pulDataLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DecryptFinal)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BYTE *pbDecryptedData,
  ULONG *pulDecryptedDataLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DigestInit)
#ifdef CK_NEED_ARG_LIST
(
  DEVHANDLE hDev,
  ULONG ulAlgID,
  ECCPUBLICKEYBLOB *pPubKey,
  unsigned char *pucID,
  ULONG ulIDLen,
  HANDLE *phHash
);
#endif



CK_SKF_FUNCTION_INFO(SKF_Digest)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hHash,
  BYTE *pbData,
  ULONG ulDataLen,
  BYTE *pbHashData,
  ULONG *pulHashLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_DigestUpdate)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hHash,
  BYTE *pbData,
  ULONG  ulDataLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_DigestFinal)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hHash,
  BYTE *pHashData,
  ULONG  *pulHashLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_MacInit)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hKey,
  BLOCKCIPHERPARAM* pMacParam,
  HANDLE *phMac
);
#endif



CK_SKF_FUNCTION_INFO(SKF_Mac)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hMac,
  BYTE* pbData,
  ULONG ulDataLen,
  BYTE *pbMacData,
  ULONG *pulMacLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_MacUpdate)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hMac,
  BYTE * pbData,
  ULONG ulDataLen
);
#endif



CK_SKF_FUNCTION_INFO(SKF_MacFinal)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hMac,
  BYTE *pbMacData,
  ULONG *pulMacDataLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_CloseHandle)
#ifdef CK_NEED_ARG_LIST
(
  HANDLE hHandle
);
#endif

// standard function end . those function are not standard behind

CK_SKF_FUNCTION_INFO(SKF_ECCDecrypt)
#ifdef CK_NEED_ARG_LIST
(
	HCONTAINER hContainer, 
	BYTE *pbCiphertext, 
	ULONG ulCiphertextLen, 
	BYTE *pbPlaintext, 
	ULONG *pulPlaintextLen);
#endif

CK_SKF_FUNCTION_INFO(SKF_RSAPriKeyOperation)
#ifdef CK_NEED_ARG_LIST
(
	HCONTAINER hContainer,
	BYTE *pbIn,
	ULONG ulInLen,
	BYTE *pbOut,
	ULONG *pulOutLen,
	BOOL bSignFlag
);
#endif


// add from ÁúÂö


CK_SKF_FUNCTION_INFO(SKF_ECCPrvKeyDecrypt)
#ifdef CK_NEED_ARG_LIST
(
	HCONTAINER hContainer,
	BYTE *pbCiphertext,
	ULONG ulCiphertextLen,
	BYTE *pbPlaintext,
	ULONG *pulPlaintextLen);
#endif

CK_SKF_FUNCTION_INFO(SKF_RSAPrivateOperation)
#ifdef CK_NEED_ARG_LIST
(
	HCONTAINER hContainer,
	BYTE *pbIn,
	ULONG ulInLen,
	BYTE *pbOut,
	ULONG *pulOutLen,
	ULONG bSignFlag
);
#endif

CK_SKF_FUNCTION_INFO(SKF_RSAPrvKeyDecrypt)
#ifdef CK_NEED_ARG_LIST
(
	HCONTAINER hContainer,
	BYTE *pbIn,
	ULONG ulInLen,
	BYTE *pbOut,
	ULONG *pulOutLen,
	ULONG bSignFlag
);
#endif

CK_SKF_FUNCTION_INFO(SKF_RSADecrypt)
#ifdef CK_NEED_ARG_LIST
(
	HCONTAINER hContainer,
	BYTE *pbIn,
	ULONG ulInLen,
	BYTE *pbOut,
	ULONG *pulOutLen
);
#endif


CK_SKF_FUNCTION_INFO(SKF_RunXXX)
#ifdef CK_NEED_ARG_LIST
(
	...
);
#endif



