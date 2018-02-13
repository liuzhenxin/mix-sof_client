/**
 * Created by LQQ on 2017/11/13.
 */

CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetVersion)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	VERSION *pVersion
	);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_SetSignMethod)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	ULONG ulMethod
	);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetSignMethod)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	ULONG *pulMethod
	);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_SetEncryptMethod)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	ULONG ulMethod);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetEncryptMethod)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	ULONG *pulMethod
	);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetUserList)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	BYTE *pbUserList,
	ULONG *pulUserListLen
	);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_ExportUserCert)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	LPSTR pContainerName,
	BYTE *pbCert,
	ULONG *pulCertLen
	);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_Login)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions,
	LPSTR pContainerName,
	LPSTR pPIN);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetPinRetryCount)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, ULONG *pulRetryCount);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_ChangePassWd)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPINOld, LPSTR pPINNew);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_ExportExChangeUserCert)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen);
#endif

CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetCertInfo)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, UINT16 u16Type, BYTE *pbInfo, ULONG *pulInfoLen);
#endif

CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetCertInfoByOid)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pOidString, BYTE *pbInfo, ULONG *pulInfoLen);
#endif

CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetDeviceInfo)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, ULONG ulType, BYTE *pbInfo, ULONG *pulInfoLen);
#endif

CK_SOF_CLIENT_FUNCTION_INFO(SOF_ValidateCert)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, ULONG *pulValidate);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_SignData)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_VerifySignedData)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG ulDataOutLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_SignFile)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pFileIn, BYTE *pbDataOut, ULONG *pulDataOutLen);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_VerifySignedFile)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pFileIn, BYTE *pbDataOut, ULONG ulDataOutLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_EncryptData)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_DecryptData)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_EncryptFile)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pFileIn, LPSTR pFileOut);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_DecryptFile)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pFileIn, LPSTR pFileOut);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_SignMessage)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, UINT16 u16Flag, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_VerifySignedMessage)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG ulDataOutLen);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetInfoFromSignedMessage)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_SignDataXML)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_VerifySignedDataXML)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen);
#endif



CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetXMLSignatureInfo)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_GenRandom)
#ifdef CK_NEED_ARG_LIST
(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen);
#endif


CK_SOF_CLIENT_FUNCTION_INFO(SOF_GetLastError)
#ifdef CK_NEED_ARG_LIST
(
	void * p_ckpFunctions
	);
#endif

CK_SOF_CLIENT_FUNCTION_INFO(SOF_FinalizeLibraryNative)
#ifdef CK_NEED_ARG_LIST
(
	CK_SKF_FUNCTION_LIST *p_ckpFunctions
	);
#endif

CK_SOF_CLIENT_FUNCTION_INFO(SOF_InitializeLibraryNative)
#ifdef CK_NEED_ARG_LIST
(
	char *pSKFLibraryPath,
	CK_SKF_FUNCTION_LIST **pp_ckpFunctions
	);
#endif 
