#include <string>
#include "sof_client.h"
#include "sof_client-tools.h"
#include "skf.h"
#include "assert.h"
#include "FILE_LOG.h"

typedef CK_SOF_CLIENT_FUNCTION_LIST *CK_SOF_CLIENT_FUNCTION_LIST_PTR;
typedef CK_SKF_FUNCTION_LIST *CK_SKF_FUNCTION_LIST_PTR;

#ifdef __cplusplus
extern "C" {
#endif


	ULONG SOF_GetVersion(void * p_ckpFunctions, VERSION *pVersion)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;
		DEVINFO devinfo;
		DEVHANDLE hDevHandle = 0;
		char buffer_devs[1024] = { 0 };
		ULONG buffer_devs_len = sizeof(buffer_devs);

		ulResult = ckpFunctions->SKF_EnumDev(TRUE, buffer_devs, &buffer_devs_len);
		if (ulResult)
		{
			goto err;
		}

		ulResult = ckpFunctions->SKF_ConnectDev(buffer_devs, &hDevHandle);
		if (ulResult)
		{
			goto err;
		}

		ulResult = ckpFunctions->SKF_GetDevInfo(hDevHandle,&devinfo);
		if (ulResult)
		{
			goto err;
		}

		memcpy(pVersion, &(devinfo.Version), sizeof(VERSION));

	err:

		if (hDevHandle)
		{
			ckpFunctions->SKF_DisConnectDev(hDevHandle);
		}

		return ulResult;
	}







	void finalizeLibraryNative(CK_SKF_FUNCTION_LIST_PTR p_ckpFunctions) {
		if (p_ckpFunctions) {
			// add code here
			MYFreeLibrary(p_ckpFunctions->hHandle);
			p_ckpFunctions->hHandle = NULL;

			delete (p_ckpFunctions);
		}

		return;
	}

	void initializeLibraryNative(char *pSKFLibraryPath, CK_SKF_FUNCTION_LIST_PTR *pp_ckpFunctions) {
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = new CK_SKF_FUNCTION_LIST;

		void * hHandle = MYLoadLibrary(pSKFLibraryPath);
		if (NULL == hHandle) {
			goto end;
		}

		ckpFunctions->hHandle = hHandle;

		// load
		ckpFunctions->SKF_SetPackageName = (CK_SKF_SetPackageName) MYGetProcAddress(hHandle,
			"SKF_SetPackageName");
		ckpFunctions->SKF_WaitForDevEvent = (CK_SKF_WaitForDevEvent) MYGetProcAddress(hHandle,
			"SKF_WaitForDevEvent");
		ckpFunctions->SKF_CancelWaitForDevEvent = (CK_SKF_CancelWaitForDevEvent) MYGetProcAddress(
			hHandle, "SKF_CancelWaitForDevEvent");
		ckpFunctions->SKF_EnumDev = (CK_SKF_EnumDev) MYGetProcAddress(hHandle, "SKF_EnumDev");
		ckpFunctions->SKF_ConnectDev = (CK_SKF_ConnectDev) MYGetProcAddress(hHandle,
			"SKF_ConnectDev");
		ckpFunctions->SKF_DisConnectDev = (CK_SKF_DisConnectDev) MYGetProcAddress(hHandle,
			"SKF_DisConnectDev");
		ckpFunctions->SKF_GetDevState = (CK_SKF_GetDevState) MYGetProcAddress(hHandle,
			"SKF_GetDevState");
		ckpFunctions->SKF_SetLabel = (CK_SKF_SetLabel) MYGetProcAddress(hHandle,
			"SKF_SetLabel");
		ckpFunctions->SKF_GetDevInfo = (CK_SKF_GetDevInfo) MYGetProcAddress(hHandle,
			"SKF_GetDevInfo");
		ckpFunctions->SKF_LockDev = (CK_SKF_LockDev) MYGetProcAddress(hHandle, "SKF_LockDev");
		ckpFunctions->SKF_UnlockDev = (CK_SKF_UnlockDev) MYGetProcAddress(hHandle,
			"SKF_UnlockDev");
		ckpFunctions->SKF_Transmit = (CK_SKF_Transmit) MYGetProcAddress(hHandle,
			"SKF_Transmit");
		ckpFunctions->SKF_ChangeDevAuthKey = (CK_SKF_ChangeDevAuthKey) MYGetProcAddress(hHandle,
			"SKF_ChangeDevAuthKey");
		ckpFunctions->SKF_DevAuth = (CK_SKF_DevAuth) MYGetProcAddress(hHandle, "SKF_DevAuth");
		ckpFunctions->SKF_ChangePIN = (CK_SKF_ChangePIN) MYGetProcAddress(hHandle,
			"SKF_ChangePIN");
		ckpFunctions->SKF_GetPINInfo = (CK_SKF_GetPINInfo) MYGetProcAddress(hHandle,
			"SKF_GetPINInfo");
		ckpFunctions->SKF_VerifyPIN = (CK_SKF_VerifyPIN) MYGetProcAddress(hHandle,
			"SKF_VerifyPIN");
		ckpFunctions->SKF_UnblockPIN = (CK_SKF_UnblockPIN) MYGetProcAddress(hHandle,
			"SKF_UnblockPIN");
		ckpFunctions->SKF_ClearSecureState = (CK_SKF_ClearSecureState) MYGetProcAddress(hHandle,
			"SKF_ClearSecureState");
		ckpFunctions->SKF_CreateApplication = (CK_SKF_CreateApplication) MYGetProcAddress(
			hHandle, "SKF_CreateApplication");
		ckpFunctions->SKF_EnumApplication = (CK_SKF_EnumApplication) MYGetProcAddress(hHandle,
			"SKF_EnumApplication");
		ckpFunctions->SKF_DeleteApplication = (CK_SKF_DeleteApplication) MYGetProcAddress(
			hHandle, "SKF_DeleteApplication");
		ckpFunctions->SKF_OpenApplication = (CK_SKF_OpenApplication) MYGetProcAddress(hHandle,
			"SKF_OpenApplication");
		ckpFunctions->SKF_CloseApplication = (CK_SKF_CloseApplication) MYGetProcAddress(hHandle,
			"SKF_CloseApplication");
		ckpFunctions->SKF_CreateFile = (CK_SKF_CreateFile) MYGetProcAddress(hHandle,
			"SKF_CreateFile");
		ckpFunctions->SKF_DeleteFile = (CK_SKF_DeleteFile) MYGetProcAddress(hHandle,
			"SKF_DeleteFile");
		ckpFunctions->SKF_EnumFiles = (CK_SKF_EnumFiles) MYGetProcAddress(hHandle,
			"SKF_EnumFiles");
		ckpFunctions->SKF_GetFileInfo = (CK_SKF_GetFileInfo) MYGetProcAddress(hHandle,
			"SKF_GetFileInfo");
		ckpFunctions->SKF_ReadFile = (CK_SKF_ReadFile) MYGetProcAddress(hHandle,
			"SKF_ReadFile");
		ckpFunctions->SKF_WriteFile = (CK_SKF_WriteFile) MYGetProcAddress(hHandle,
			"SKF_WriteFile");
		ckpFunctions->SKF_CreateContainer = (CK_SKF_CreateContainer) MYGetProcAddress(hHandle,
			"SKF_CreateContainer");
		ckpFunctions->SKF_DeleteContainer = (CK_SKF_DeleteContainer) MYGetProcAddress(hHandle,
			"SKF_DeleteContainer");
		ckpFunctions->SKF_OpenContainer = (CK_SKF_OpenContainer) MYGetProcAddress(hHandle,
			"SKF_OpenContainer");
		ckpFunctions->SKF_CloseContainer = (CK_SKF_CloseContainer) MYGetProcAddress(hHandle,
			"SKF_CloseContainer");
		ckpFunctions->SKF_EnumContainer = (CK_SKF_EnumContainer) MYGetProcAddress(hHandle,
			"SKF_EnumContainer");
		ckpFunctions->SKF_GetContainerType = (CK_SKF_GetContainerType) MYGetProcAddress(hHandle,
			"SKF_GetContainerType");
		ckpFunctions->SKF_ImportCertificate = (CK_SKF_ImportCertificate) MYGetProcAddress(
			hHandle, "SKF_ImportCertificate");
		ckpFunctions->SKF_ExportCertificate = (CK_SKF_ExportCertificate) MYGetProcAddress(
			hHandle, "SKF_ExportCertificate");
		ckpFunctions->SKF_GenRandom = (CK_SKF_GenRandom) MYGetProcAddress(hHandle,
			"SKF_GenRandom");
		ckpFunctions->SKF_GenExtRSAKey = (CK_SKF_GenExtRSAKey) MYGetProcAddress(hHandle,
			"SKF_GenExtRSAKey");
		ckpFunctions->SKF_GenRSAKeyPair = (CK_SKF_GenRSAKeyPair) MYGetProcAddress(hHandle,
			"SKF_GenRSAKeyPair");
		ckpFunctions->SKF_ImportRSAKeyPair = (CK_SKF_ImportRSAKeyPair) MYGetProcAddress(hHandle,
			"SKF_ImportRSAKeyPair");
		ckpFunctions->SKF_RSASignData = (CK_SKF_RSASignData) MYGetProcAddress(hHandle,
			"SKF_RSASignData");
		ckpFunctions->SKF_RSAVerify = (CK_SKF_RSAVerify) MYGetProcAddress(hHandle,
			"SKF_RSAVerify");
		ckpFunctions->SKF_RSAExportSessionKey = (CK_SKF_RSAExportSessionKey) MYGetProcAddress(
			hHandle, "SKF_RSAExportSessionKey");
		ckpFunctions->SKF_ExtRSAPubKeyOperation = (CK_SKF_ExtRSAPubKeyOperation) MYGetProcAddress(
			hHandle, "SKF_ExtRSAPubKeyOperation");
		ckpFunctions->SKF_ExtRSAPriKeyOperation = (CK_SKF_ExtRSAPriKeyOperation) MYGetProcAddress(
			hHandle, "SKF_ExtRSAPriKeyOperation");
		ckpFunctions->SKF_GenECCKeyPair = (CK_SKF_GenECCKeyPair) MYGetProcAddress(hHandle,
			"SKF_GenECCKeyPair");
		ckpFunctions->SKF_ImportECCKeyPair = (CK_SKF_ImportECCKeyPair) MYGetProcAddress(hHandle,
			"SKF_ImportECCKeyPair");
		ckpFunctions->SKF_ECCSignData = (CK_SKF_ECCSignData) MYGetProcAddress(hHandle,
			"SKF_ECCSignData");
		ckpFunctions->SKF_ECCVerify = (CK_SKF_ECCVerify) MYGetProcAddress(hHandle,
			"SKF_ECCVerify");
		ckpFunctions->SKF_ECCExportSessionKey = (CK_SKF_ECCExportSessionKey) MYGetProcAddress(
			hHandle, "SKF_ECCExportSessionKey");
		ckpFunctions->SKF_ExtECCEncrypt = (CK_SKF_ExtECCEncrypt) MYGetProcAddress(hHandle,
			"SKF_ExtECCEncrypt");
		ckpFunctions->SKF_ExtECCDecrypt = (CK_SKF_ExtECCDecrypt) MYGetProcAddress(hHandle,
			"SKF_ExtECCDecrypt");
		ckpFunctions->SKF_ExtECCSign = (CK_SKF_ExtECCSign) MYGetProcAddress(hHandle,
			"SKF_ExtECCSign");
		ckpFunctions->SKF_ExtECCVerify = (CK_SKF_ExtECCVerify) MYGetProcAddress(hHandle,
			"SKF_ExtECCVerify");
		ckpFunctions->SKF_GenerateAgreementDataWithECC = (CK_SKF_GenerateAgreementDataWithECC) MYGetProcAddress(
			hHandle, "SKF_GenerateAgreementDataWithECC");
		ckpFunctions->SKF_GenerateAgreementDataAndKeyWithECC = (CK_SKF_GenerateAgreementDataAndKeyWithECC) MYGetProcAddress(
			hHandle, "SKF_GenerateAgreementDataAndKeyWithECC");
		ckpFunctions->SKF_GenerateKeyWithECC = (CK_SKF_GenerateKeyWithECC) MYGetProcAddress(
			hHandle, "SKF_GenerateKeyWithECC");
		ckpFunctions->SKF_ExportPublicKey = (CK_SKF_ExportPublicKey) MYGetProcAddress(hHandle,
			"SKF_ExportPublicKey");
		ckpFunctions->SKF_ImportSessionKey = (CK_SKF_ImportSessionKey) MYGetProcAddress(hHandle,
			"SKF_ImportSessionKey");
		ckpFunctions->SKF_SetSymmKey = (CK_SKF_SetSymmKey) MYGetProcAddress(hHandle,
			"SKF_SetSymmKey");
		ckpFunctions->SKF_EncryptInit = (CK_SKF_EncryptInit) MYGetProcAddress(hHandle,
			"SKF_EncryptInit");
		ckpFunctions->SKF_Encrypt = (CK_SKF_Encrypt) MYGetProcAddress(hHandle, "SKF_Encrypt");
		ckpFunctions->SKF_EncryptUpdate = (CK_SKF_EncryptUpdate) MYGetProcAddress(hHandle,
			"SKF_EncryptUpdate");
		ckpFunctions->SKF_EncryptFinal = (CK_SKF_EncryptFinal) MYGetProcAddress(hHandle,
			"SKF_EncryptFinal");
		ckpFunctions->SKF_DecryptInit = (CK_SKF_DecryptInit) MYGetProcAddress(hHandle,
			"SKF_DecryptInit");
		ckpFunctions->SKF_Decrypt = (CK_SKF_Decrypt) MYGetProcAddress(hHandle, "SKF_Decrypt");
		ckpFunctions->SKF_DecryptUpdate = (CK_SKF_DecryptUpdate) MYGetProcAddress(hHandle,
			"SKF_DecryptUpdate");
		ckpFunctions->SKF_DecryptFinal = (CK_SKF_DecryptFinal) MYGetProcAddress(hHandle,
			"SKF_DecryptFinal");
		ckpFunctions->SKF_DigestInit = (CK_SKF_DigestInit) MYGetProcAddress(hHandle,
			"SKF_DigestInit");
		ckpFunctions->SKF_Digest = (CK_SKF_Digest) MYGetProcAddress(hHandle, "SKF_Digest");
		ckpFunctions->SKF_DigestUpdate = (CK_SKF_DigestUpdate) MYGetProcAddress(hHandle,
			"SKF_DigestUpdate");
		ckpFunctions->SKF_DigestFinal = (CK_SKF_DigestFinal) MYGetProcAddress(hHandle,
			"SKF_DigestFinal");
		ckpFunctions->SKF_MacInit = (CK_SKF_MacInit) MYGetProcAddress(hHandle, "SKF_MacInit");
		ckpFunctions->SKF_Mac = (CK_SKF_Mac) MYGetProcAddress(hHandle, "SKF_Mac");
		ckpFunctions->SKF_MacUpdate = (CK_SKF_MacUpdate) MYGetProcAddress(hHandle,
			"SKF_MacUpdate");
		ckpFunctions->SKF_MacFinal = (CK_SKF_MacFinal) MYGetProcAddress(hHandle,
			"SKF_MacFinal");
		ckpFunctions->SKF_CloseHandle = (CK_SKF_CloseHandle) MYGetProcAddress(hHandle,
			"SKF_CloseHandle");

		*pp_ckpFunctions = ckpFunctions;
	end:
		
		return;
	}



#if 0



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_WaitForDevEvent
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFUlong;)[B
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1SetPackageName
        (JNIEnv * env, jobject
        obj, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }
    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_SetPackageName)((char *) std::string(jBufferInput,
                                                                  jBufferInput +
                                                                  jBufferInputLength).c_str());

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}

/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_WaitForDevEvent
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFUlong;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1WaitForDevEvent
        (JNIEnv * env, jobject
        obj, jobject
        pulEvent)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;
    ULONG ulEvent = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_WaitForDevEvent)((char *) jBufferOutput,
                                              &jBufferOutputLength,
                                              &ulEvent);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_WaitForDevEvent)((char *) jBufferOutput,
                                              &jBufferOutputLength,
                                              &ulEvent);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    ckULongToObject(env, ulEvent, pulEvent);

    end:

    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CancelWaitForDevEvent
 * Signature: ()V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CancelWaitForDevEvent
        (JNIEnv * env, jobject
        obj)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_CancelWaitForDevEvent)();
    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    /* copy back generated bytes */

    end:

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EnumDev
 * Signature: (Z)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EnumDev
        (JNIEnv * env, jobject
        obj, jboolean
        bPresent)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_EnumDev)(bPresent,
                                      (char *) jBufferOutput,
                                      &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_EnumDev)(bPresent,
                                      (char *) jBufferOutput,
                                      &jBufferOutputLength
    );

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ConnectDev
 * Signature: ([BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ConnectDev
        (JNIEnv * env, jobject
        obj, jbyteArray
        jbyteArrayInput, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    HANDLE hHandle = 0;
    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_ConnectDev)(
            (char *) std::string(jBufferInput, jBufferInput + jBufferInputLength).c_str(),
            &hHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckHandleToObject(env, hHandle, jHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DisConnectDev
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DisConnectDev
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_DisConnectDev)(ckHandleFromObject(env, jHandle));

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GetDevState
 * Signature: ([B)J
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GetDevState
        (JNIEnv * env, jobject
        obj, jbyteArray
        jbyteArrayInput, jobject
        pulDevState)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    ULONG ulDevState = 0;
    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }
    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_GetDevState)(
            (char *) std::string(jBufferInput, jBufferInput + jBufferInputLength).c_str(),
            &ulDevState);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckULongToObject(env, ulDevState, pulDevState);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_SetLabel
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1SetLabel
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }
    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_SetLabel)(ckHandleFromObject(env, jHandle),
                                       (char *) std::string(jBufferInput,
                                                            jBufferInput +
                                                            jBufferInputLength).c_str());

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GetSKFDevInfo
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFDevInfo;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GetDevInfo
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jDevInfo)) {
    DEVINFO devinfo;

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_GetDevInfo)(ckHandleFromObject(env, jHandle),
                                         &devinfo);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckDataToObject(env, &devinfo, sizeof(devinfo), jDevInfo);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_LockDev
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;J)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1LockDev
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulTimeOut)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_LockDev)(ckHandleFromObject(env, jHandle),
                                      ulTimeOut);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_UnlockDev
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1UnlockDev
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_UnlockDev)(ckHandleFromObject(env, jHandle));

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_Transmit
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1Transmit
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_Transmit)(ckHandleFromObject(env, jHandle),
                                       (unsigned char *) jBufferInput,
                                       jBufferInputLength, jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_Transmit)(ckHandleFromObject(env, jHandle),
                                       (unsigned char *) jBufferInput,
                                       jBufferInputLength, jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ChangeDevAuthKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ChangeDevAuthKey
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_ChangeDevAuthKey)(ckHandleFromObject(env, jHandle),
                                               (unsigned char *) jBufferInput, jBufferInputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DevAuth
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DevAuth
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_DevAuth)(ckHandleFromObject(env, jHandle),
                                      (unsigned char *) jBufferInput,
                                      jBufferInputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ChangePIN
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;J[B[BLcom/wtsecure/safecard/sof_client/wrapper/SKFUlong;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ChangePIN
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulPINType, jbyteArray
        jbyteArrayInput, jbyteArray
        jbyteArrayInput1, jobject
        pulRetryCountCount)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;
    ULONG ulRetryCount = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);

    rv = (*ckpFunctions->SKF_ChangePIN)(ckHandleFromObject(env, jHandle), ulPINType,
                                        (char *) std::string(jBufferInput,
                                                             jBufferInput +
                                                             jBufferInputLength).c_str(),
                                        (char *) std::string(jBufferInput1,
                                                             jBufferInput1 +
                                                             jBufferInputLength1).c_str(),
                                        &ulRetryCount);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckULongToObject(env, ulRetryCount, pulRetryCountCount);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GetPINInfo
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFPinInfo;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GetPINInfo
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulPINType, jobject
        pulMaxRetryCount, jobject
        pulRemainRetryCount, jobject
        pbDefaultPin)) {
    ULONG rv = 0;

    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    ULONG ulMaxRetryCount;
    ULONG ulRemainRetryCount = 0;
    BOOL bDefaultPin;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_GetPINInfo)(ckHandleFromObject(env, jHandle), ulPINType,
                                         &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckULongToObject(env, ulMaxRetryCount, pulMaxRetryCount);
    ckULongToObject(env, ulRemainRetryCount, pulRemainRetryCount);
    ckULongToObject(env, bDefaultPin, pbDefaultPin);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_VerifyPIN
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;J[BLcom/wtsecure/safecard/sof_client/wrapper/SKFUlong;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1VerifyPIN
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulPINType, jbyteArray
        jbyteArrayInput, jobject
        pulRemainRetryCount)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;
    ULONG ulRemainRetryCount = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_VerifyPIN)(ckHandleFromObject(env, jHandle), ulPINType,
                                        (char *) std::string(jBufferInput,
                                                             jBufferInput +
                                                             jBufferInputLength).c_str(),
                                        &ulRemainRetryCount);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckULongToObject(env, ulRemainRetryCount, pulRemainRetryCount);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_UnblockPIN
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B[BLcom/wtsecure/safecard/sof_client/wrapper/SKFUlong;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1UnblockPIN
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jbyteArray
        jbyteArrayInput1, jobject
        pulRemainRetryCount)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;
    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;
    ULONG ulRemainRetryCount = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);

    rv = (*ckpFunctions->SKF_UnblockPIN)(ckHandleFromObject(env, jHandle),
                                         (char *) std::string(jBufferInput,
                                                              jBufferInput +
                                                              jBufferInputLength).c_str(),
                                         (char *) std::string(jBufferInput1,
                                                              jBufferInput1 +
                                                              jBufferInputLength1).c_str(),
                                         &ulRemainRetryCount);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckULongToObject(env, ulRemainRetryCount, pulRemainRetryCount);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ClearSecureState
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ClearSecureState
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_ClearSecureState)(ckHandleFromObject(env, jHandle));

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CreateApplication
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B[BJ[BJJLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CreateApplication
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jbyteArray
        jbyteArrayInput1, jlong
        dwAdminPinRetryCount, jbyteArray
        jbyteArrayInput2, jlong
        dwUserPinRetryCount, jlong
        dwCreateFileRights, jobject
        jAppHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;
    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;
    jbyte *jBufferInput2 = 0;
    jlong jBufferInputLength2 = 0;

    HANDLE hAppHandle = 0;
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);

    jBufferInputLength2 = env->GetArrayLength(jbyteArrayInput2);
    jBufferInput2 = env->GetByteArrayElements(jbyteArrayInput2, NULL);

    rv = (*ckpFunctions->SKF_CreateApplication)(ckHandleFromObject(env, jHandle),
                                                (char *) std::string(jBufferInput, jBufferInput +
                                                                                   jBufferInputLength).c_str(),
                                                (char *) std::string(jBufferInput1, jBufferInput1 +
                                                                                    jBufferInputLength1).c_str(),
                                                dwAdminPinRetryCount,
                                                (char *) std::string(jBufferInput2, jBufferInput2 +
                                                                                    jBufferInputLength2).c_str(),
                                                dwUserPinRetryCount,
                                                dwCreateFileRights,
                                                &hAppHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckHandleToObject(env, hAppHandle, jAppHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }

    if (jBufferInput2) {
        env->ReleaseByteArrayElements(jbyteArrayInput2, jBufferInput2, 0);
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EnumApplication
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EnumApplication
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_EnumApplication)(ckHandleFromObject(env, jHandle),
                                              (char *) jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_EnumApplication)(ckHandleFromObject(env, jHandle),
                                              (char *) jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DeleteApplication
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DeleteApplication
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_DeleteApplication)(ckHandleFromObject(env, jHandle),
                                                (char *) std::string(jBufferInput, jBufferInput +
                                                                                   jBufferInputLength).c_str());

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_OpenApplication
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1OpenApplication
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jobject
        jAppHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    HANDLE hAppHandle = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_OpenApplication)(ckHandleFromObject(env, jHandle),
                                              (char *) std::string(jBufferInput, jBufferInput +
                                                                                 jBufferInputLength).c_str(),
                                              &hAppHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hAppHandle, jAppHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CloseApplication
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CloseApplication
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_CloseApplication)(ckHandleFromObject(env, jHandle));

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CreateFile
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BJJ)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CreateFile
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jlong
        ulFileSize, jlong
        ulReadRights, jlong
        ulWriteRights)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_CreateFile)(ckHandleFromObject(env, jHandle),
                                         (char *) std::string(jBufferInput,
                                                              jBufferInput +
                                                              jBufferInputLength).c_str(),
                                         ulFileSize, ulReadRights, ulWriteRights);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DeleteFile
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DeleteFile
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_DeleteFile)(ckHandleFromObject(env, jHandle),
                                         (char *) std::string(jBufferInput, jBufferInput +
                                                                            jBufferInputLength).c_str());

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EnumFiles
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EnumFiles
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_EnumFiles)(ckHandleFromObject(env, jHandle), (char *) jBufferOutput,
                                        &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_EnumFiles)(ckHandleFromObject(env, jHandle), (char *) jBufferOutput,
                                        &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GetFileInfo
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFFileAttribute;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GetFileInfo
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jobject
        jFileInfo)) {
    FILEATTRIBUTE fileinfo;

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_GetFileInfo)(ckHandleFromObject(env, jHandle),
                                          (char *) std::string(jBufferInput, jBufferInput +
                                                                             jBufferInputLength).c_str(),
                                          &fileinfo);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckDataToObject(env, &fileinfo, sizeof(fileinfo), jFileInfo);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ReadFile
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BJJ)[B
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ReadFile
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jlong
        ulOffset,
                jlong
        ulSize, jbyteArray
        jbyteArrayOutput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyte *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferOutputLength = env->GetArrayLength(jbyteArrayOutput);
    jBufferOutput = env->GetByteArrayElements(jbyteArrayOutput, NULL);

    rv = (*ckpFunctions->SKF_ReadFile)(ckHandleFromObject(env, jHandle),
                                       (char *) std::string(jBufferInput, jBufferInput +
                                                                          jBufferInputLength).c_str(),
                                       ulOffset, ulSize,
                                       (unsigned char *) jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_WriteFile
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BJ[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1WriteFile
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jlong
        ulOffset, jbyteArray
        jbyteArrayInput1)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);

    rv = (*ckpFunctions->SKF_WriteFile)(ckHandleFromObject(env, jHandle),
                                        (char *) std::string(jBufferInput, jBufferInput +
                                                                           jBufferInputLength).c_str(),
                                        ulOffset, (unsigned char *) jBufferInput1,
                                        jBufferInputLength1);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CreateContainer
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CreateContainer
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jobject
        jConHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    HANDLE hConHandle = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_CreateContainer)(ckHandleFromObject(env, jHandle),
                                              (char *) std::string(jBufferInput,
                                                                   jBufferInput +
                                                                   jBufferInputLength).c_str(),
                                              &hConHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hConHandle, jConHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;

}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DeleteContainer
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DeleteContainer
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_DeleteContainer)(ckHandleFromObject(env, jHandle),
                                              (char *) std::string(jBufferInput, jBufferInput +
                                                                                 jBufferInputLength).c_str());

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_OpenContainer
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1OpenContainer
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jobject
        jConHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    HANDLE hConHandle = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_OpenContainer)(ckHandleFromObject(env, jHandle),
                                            (char *) std::string(jBufferInput, jBufferInput +
                                                                               jBufferInputLength).c_str(),
                                            &hConHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hConHandle, jConHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CloseContainer
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CloseContainer
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_CloseContainer)(ckHandleFromObject(env, jHandle));

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EnumContainer
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EnumContainer
        (JNIEnv * env, jobject
        obj, jobject
        jHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_EnumContainer)(ckHandleFromObject(env, jHandle),
                                            (char *) jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_EnumContainer)(ckHandleFromObject(env, jHandle),
                                            (char *) jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GetContainerType
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)J
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GetContainerType
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jConType)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    ULONG ulConType = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_GetContainerType)(ckHandleFromObject(env, jHandle),
                                               &ulConType);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckULongToObject(env, ulConType, jConType);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ImportCertificate
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Z[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ImportCertificate
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jboolean
        bFlag, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_ImportCertificate)(ckHandleFromObject(env, jHandle), bFlag,
                                                (unsigned char *) jBufferInput, jBufferInputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExportCertificate
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Z)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ExportCertificate
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jboolean
        bFlag)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_ExportCertificate)(ckHandleFromObject(env, jHandle), bFlag,
                                                jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_ExportCertificate)(ckHandleFromObject(env, jHandle), bFlag,
                                                jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenRandom
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void  JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GenRandom
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jRandomData)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    jbyte *jRandomBuffer = 0;
    jlong jRandomBufferLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jRandomBufferLength = env->GetArrayLength(jRandomData);
    jRandomBuffer = env->GetByteArrayElements(jRandomData, NULL);

    rv = (*ckpFunctions->SKF_GenRandom)(ckHandleFromObject(env, jHandle),
                                        (BYTE *) jRandomBuffer,
                                        (ULONG) jRandomBufferLength);
    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    /* copy back generated bytes */
    env->ReleaseByteArrayElements(jRandomData, jRandomBuffer, 0);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenExtRSAKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFRsaPrivateKeyBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GenExtRSAKey
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulBitsLen, jobject
        jBlob)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    RSAPRIVATEKEYBLOB blob;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_GenExtRSAKey)(ckHandleFromObject(env, jHandle), ulBitsLen, &blob);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckDataToObject(env, &blob, sizeof(blob), jBlob);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenRSAKeyPair
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFRsaPublicKeyBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GenRSAKeyPair
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulBitsLen, jobject
        jBlob)) {
    RSAPUBLICKEYBLOB blob;
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_GenRSAKeyPair)(ckHandleFromObject(env, jHandle), ulBitsLen, &blob);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckDataToObject(env, &blob, sizeof(blob), jBlob);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ImportRSAKeyPair
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;J[B[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ImportRSAKeyPair
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulSymAlgId, jbyteArray
        jbyteArrayInput, jbyteArray
        jbyteArrayInput1)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);

    rv = (*ckpFunctions->SKF_ImportRSAKeyPair)(ckHandleFromObject(env, jHandle), ulSymAlgId,
                                               (unsigned char *) jBufferInput, jBufferInputLength,
                                               (unsigned char *) jBufferInput1,
                                               jBufferInputLength1);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_RSASignData
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1RSASignData
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_RSASignData)(ckHandleFromObject(env, jHandle),
                                          (unsigned char *) jBufferInput, jBufferInputLength,
                                          jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_RSASignData)(ckHandleFromObject(env, jHandle),
                                          (unsigned char *) jBufferInput, jBufferInputLength,
                                          jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_RSAVerify
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFRsaPublicKeyBlob;[B[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1RSAVerify
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jbyteArray
        jbyteArrayInput, jbyteArray
        jbyteArrayInput1)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);

    rv = (*ckpFunctions->SKF_RSAVerify)(ckHandleFromObject(env, jHandle),
                                        (RSAPUBLICKEYBLOB *) jValue, (unsigned char *) jBufferInput,
                                        jBufferInputLength, (unsigned char *) jBufferInput1,
                                        jBufferInputLength1);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_RSAExportSessionKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFRsaPublicKeyBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1RSAExportSessionKey
        (JNIEnv * env, jobject
        obj, jobject
        hConHandle, jlong
        ulAlgId, jobject
        jBlob, jobject
        jSessionKeyHandle)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    HANDLE hSessionKeyHandle = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_RSAExportSessionKey)(ckHandleFromObject(env, hConHandle), ulAlgId,
                                                  (RSAPUBLICKEYBLOB *) jValue, jBufferOutput,
                                                  &jBufferOutputLength, &hSessionKeyHandle);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_RSAExportSessionKey)(ckHandleFromObject(env, hConHandle), ulAlgId,
                                                  (RSAPUBLICKEYBLOB *) jValue, jBufferOutput,
                                                  &jBufferOutputLength, &hSessionKeyHandle);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    ckHandleToObject(env, hSessionKeyHandle, jSessionKeyHandle);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExtRSAPubKeyOperation
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFRsaPublicKeyBlob;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC,
                                                     SKF_1ExtRSAPubKeyOperation
                                                             (JNIEnv * env, jobject
                                                             obj, jobject
                                                             jHandle, jobject
                                                             jBlob, jbyteArray
                                                             jbyteArrayInput)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_ExtRSAPubKeyOperation)(ckHandleFromObject(env, jHandle),
                                                    (RSAPUBLICKEYBLOB *) jValue,
                                                    (unsigned char *) jBufferInput,
                                                    jBufferInputLength, jBufferOutput,
                                                    &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_ExtRSAPubKeyOperation)(ckHandleFromObject(env, jHandle),
                                                    (RSAPUBLICKEYBLOB *) jValue,
                                                    (unsigned char *) jBufferInput,
                                                    jBufferInputLength, jBufferOutput,
                                                    &jBufferOutputLength);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExtRSAPriKeyOperation
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFRsaPrivateKeyBlob;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC,
                                                     SKF_1ExtRSAPriKeyOperation
                                                             (JNIEnv * env, jobject
                                                             obj, jobject
                                                             jHandle, jobject
                                                             jBlob, jbyteArray
                                                             jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_ExtRSAPriKeyOperation)(ckHandleFromObject(env, jHandle),
                                                    (RSAPRIVATEKEYBLOB *) jValue,
                                                    (unsigned char *) jBufferInput,
                                                    jBufferInputLength, jBufferOutput,
                                                    &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_ExtRSAPriKeyOperation)(ckHandleFromObject(env, jHandle),
                                                    (RSAPRIVATEKEYBLOB *) jValue,
                                                    (unsigned char *) jBufferInput,
                                                    jBufferInputLength, jBufferOutput,
                                                    &jBufferOutputLength);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenECCKeyPair
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GenECCKeyPair
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulBitsLen, jobject
        jBlob)) {
    ECCPUBLICKEYBLOB blob;
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_GenECCKeyPair)(ckHandleFromObject(env, jHandle), ulBitsLen, &blob);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckDataToObject(env, &blob, sizeof(blob), jBlob);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ImportECCKeyPair
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEnvelopedKeyBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ImportECCKeyPair
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_ImportECCKeyPair)(ckHandleFromObject(env, jHandle),
                                               (ENVELOPEDKEYBLOB *) jValue);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ECCSignData
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFEccSignatureBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ECCSignData
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jobject
        jBlob)) {

    ECCSIGNATUREBLOB blob;
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_ECCSignData)(ckHandleFromObject(env, jHandle),
                                          (unsigned char *) jBufferInput, jBufferInputLength,
                                          &blob);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckDataToObject(env, &blob, sizeof(blob), jBlob);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ECCVerify
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFEccSignatureBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ECCVerify
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jbyteArray
        jbyteArrayInput, jobject
        jBlob1)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    void *jValue1 = 0;
    size_t jValueLength1 = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    jValue1 = new unsigned char[jValueLength1];

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_ECCVerify)(ckHandleFromObject(env, jHandle),
                                        (ECCPUBLICKEYBLOB *) jValue, (unsigned char *) jBufferInput,
                                        jBufferInputLength, (ECCSIGNATUREBLOB *) jValue1);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ECCExportSessionKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccCipherBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ECCExportSessionKey
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulAlgId, jobject
        jBlob, jobject
        jBlob1, jobject
        jSessionKeyHandle)) {
    ECCCIPHERBLOB blob1;
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    HANDLE hSessionKeyHandle = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_ECCExportSessionKey)(ckHandleFromObject(env, jHandle), ulAlgId,
                                                  (ECCPUBLICKEYBLOB *) jValue, &blob1,
                                                  &hSessionKeyHandle);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckDataToObject(env, &blob1, sizeof(blob1), jBlob1);
    ckHandleToObject(env, hSessionKeyHandle, jSessionKeyHandle);

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExtECCEncrypt
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFEccCipherBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ExtECCEncrypt
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jbyteArray
        jbyteArrayInput, jobject
        jBlob1)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    ECCCIPHERBLOB blob1;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_ExtECCEncrypt)(ckHandleFromObject(env, jHandle),
                                            (ECCPUBLICKEYBLOB *) jValue,
                                            (unsigned char *) jBufferInput, jBufferInputLength,
                                            &blob1);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    delete jValue;
    ckDataToObject(env, &blob1, sizeof(blob1), jBlob1);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExtECCDecrypt
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPrivateKeyBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccCipherBlob;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ExtECCDecrypt
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jobject
        jBlob1)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    void *jValue1 = 0;
    size_t jValueLength1 = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    jValue1 = new unsigned char[jValueLength1];

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    rv = (*ckpFunctions->SKF_ExtECCDecrypt)(ckHandleFromObject(env, jHandle),
                                            (ECCPRIVATEKEYBLOB *) jValue, (ECCCIPHERBLOB *) jValue1,
                                            jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_ExtECCDecrypt)(ckHandleFromObject(env, jHandle),
                                            (ECCPRIVATEKEYBLOB *) jValue, (ECCCIPHERBLOB *) jValue1,
                                            jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    delete jValue;
    delete jValue1;

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExtECCSign
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPrivateKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFEccSignatureBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ExtECCSign
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jbyteArray
        jbyteArrayInput, jobject
        jBlob1)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    ECCSIGNATUREBLOB blob1;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    rv = (*ckpFunctions->SKF_ExtECCSign)(ckHandleFromObject(env, jHandle),
                                         (ECCPRIVATEKEYBLOB *) jValue,
                                         (unsigned char *) jBufferInput, jBufferInputLength, &blob1);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    delete jValue;
    ckDataToObject(env, &blob1, sizeof(blob1), jBlob1);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExtECCVerify
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFEccSignatureBlob;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ExtECCVerify
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jbyteArray
        jbyteArrayInput, jobject
        jBlob1)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    ECCSIGNATUREBLOB blob;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;
    void *jValue1 = 0;
    size_t jValueLength1 = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    jValue1 = new unsigned char[jValueLength1];

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    rv = (*ckpFunctions->SKF_ExtECCVerify)(ckHandleFromObject(env, jHandle),
                                           (ECCPUBLICKEYBLOB *) jValue,
                                           (unsigned char *) jBufferInput, jBufferInputLength,
                                           (ECCSIGNATUREBLOB *) jValue1);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    delete jValue;
    delete jValue1;
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenerateAgreementDataWithECC
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC,
                                               SKF_1GenerateAgreementDataWithECC
                                                       (JNIEnv * env, jobject
                                                       obj, jobject
                                                       jHandle, jlong
                                                       ulAlgId, jobject
                                                       jBlob, jbyteArray
                                                       jbyteArrayInput, jobject
                                                       jAgreementHandle)) {

//    HCONTAINER hContainer,
//    ULONG ulAlgId,
//    ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
//    BYTE* pbID,
//    ULONG ulIDLen,

    HANDLE hAgreementHandle = 0;
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_GenerateAgreementDataWithECC)(ckHandleFromObject(env, jHandle),
                                                           ulAlgId, (ECCPUBLICKEYBLOB *) jValue,
                                                           (unsigned char *) jBufferInput,
                                                           jBufferInputLength, &hAgreementHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hAgreementHandle, jAgreementHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenerateAgreementDataAndKeyWithECC
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[B[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC,
                                               SKF_1GenerateAgreementDataAndKeyWithECC
                                                       (JNIEnv * env, jobject
                                                       obj, jobject
                                                       jHandle, jlong
                                                       ulAlgId, jobject
                                                       jBlob, jobject
                                                       jBlob1, jobject
                                                       jBlob2, jbyteArray
                                                       jbyteArrayInput, jbyteArray
                                                       jbyteArrayInput1, jobject
                                                       jKeyHandle)) {

    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyte *jBufferInput1 = 0;
    jlong jBufferInputLength1 = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    void *jValue1 = 0;
    size_t jValueLength1 = 0;

    void *jValue2 = 0;
    size_t jValueLength2 = 0;

    HANDLE hKeyHandle = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    jBufferInputLength1 = env->GetArrayLength(jbyteArrayInput1);
    jBufferInput1 = env->GetByteArrayElements(jbyteArrayInput1, NULL);
    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);
    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    jValue1 = new unsigned char[jValueLength1];

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);
    ckDataFromObject(env, jValue2, &jValueLength2, jBlob2);

    jValue2 = new unsigned char[jValueLength2];

    ckDataFromObject(env, jValue2, &jValueLength2, jBlob2);
    rv = (*ckpFunctions->SKF_GenerateAgreementDataAndKeyWithECC)(ckHandleFromObject(env, jHandle),
                                                                 ulAlgId,
                                                                 (ECCPUBLICKEYBLOB *) jValue,
                                                                 (ECCPUBLICKEYBLOB *) jValue1,
                                                                 (ECCPUBLICKEYBLOB *) jValue2,
                                                                 (unsigned char *) jBufferInput,
                                                                 jBufferInputLength,
                                                                 (unsigned char *) jBufferInput1,
                                                                 jBufferInputLength1,
                                                                 &hKeyHandle);

    delete jValue;
    delete jValue1;
    delete jValue2;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hKeyHandle, jKeyHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    if (jBufferInput1) {
        env->ReleaseByteArrayElements(jbyteArrayInput1, jBufferInput1, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_GenerateKeyWithECC
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1GenerateKeyWithECC
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        jBlob, jobject
        jBlob1, jbyteArray
        jbyteArrayInput, jobject
        jKeyHandle)) {

    HANDLE hKeyHandle = 0;
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    void *jValue1 = 0;
    size_t jValueLength1 = 0;
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, jBlob);

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);

    jValue1 = new unsigned char[jValueLength1];

    ckDataFromObject(env, jValue1, &jValueLength1, jBlob1);
    rv = (*ckpFunctions->SKF_GenerateKeyWithECC)(ckHandleFromObject(env, jHandle),
                                                 (ECCPUBLICKEYBLOB *) jValue,
                                                 (ECCPUBLICKEYBLOB *) jValue1,
                                                 (unsigned char *) jBufferInput,
                                                 jBufferInputLength,
                                                 &hKeyHandle);

    delete jValue;
    delete jValue1;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hKeyHandle, jKeyHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ExportPublicKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Z)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ExportPublicKey
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jboolean
        bSignFlag)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_ExportPublicKey)(ckHandleFromObject(env, jHandle), bSignFlag,
                                              jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_ExportPublicKey)(ckHandleFromObject(env, jHandle), bSignFlag,
                                              jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_ImportSessionKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;J[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1ImportSessionKey
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jlong
        ulAlgId, jbyteArray
        jbyteArrayInput, jobject
        jSessionKeyHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    HANDLE hSessionKeyHandle = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_ImportSessionKey)(ckHandleFromObject(env, jHandle), ulAlgId,
                                               (unsigned char *) jBufferInput, jBufferInputLength,
                                               &hSessionKeyHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hSessionKeyHandle, jSessionKeyHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_SetSymmKey
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[BJLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1SetSymmKey
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput, jlong
        ulAlgID, jobject
        jKeyHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;
    HANDLE hKeyHandle = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_SetSymmKey)(ckHandleFromObject(env, jHandle),
                                         (unsigned char *) jBufferInput, ulAlgID, &hKeyHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    ckHandleToObject(env, hKeyHandle, jKeyHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EncryptInit
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFBlockCipherParam;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EncryptInit
        (JNIEnv * env, jobject
        obj, jobject
        hHandle, jobject
        pCryptParam)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, pCryptParam);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, pCryptParam);

    rv = (*ckpFunctions->SKF_EncryptInit)(ckHandleFromObject(env, hHandle),
                                          *(BLOCKCIPHERPARAM *) jValue);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_Encrypt
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1Encrypt
        (JNIEnv * env, jobject
        obj, jobject
        hHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_Encrypt)(ckHandleFromObject(env, hHandle),
                                      (unsigned char *) jBufferInput, jBufferInputLength,
                                      jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_Encrypt)(ckHandleFromObject(env, hHandle),
                                      (unsigned char *) jBufferInput, jBufferInputLength,
                                      jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EncryptUpdate
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EncryptUpdate
        (JNIEnv * env, jobject
        obj, jobject
        hHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_EncryptUpdate)(ckHandleFromObject(env, hHandle),
                                            (unsigned char *) jBufferInput, jBufferInputLength,
                                            jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_EncryptUpdate)(ckHandleFromObject(env, hHandle),
                                            (unsigned char *) jBufferInput, jBufferInputLength,
                                            jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_EncryptFinal
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1EncryptFinal
        (JNIEnv * env, jobject
        obj, jobject
        hHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_EncryptFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                           &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_EncryptFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                           &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DecryptInit
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFBlockCipherParam;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DecryptInit
        (JNIEnv * env, jobject
        obj, jobject
        hHandle, jobject
        pCryptParam)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    void *jValue = 0;
    size_t jValueLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }
    ckDataFromObject(env, jValue, &jValueLength, pCryptParam);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, pCryptParam);

    rv = (*ckpFunctions->SKF_DecryptInit)(ckHandleFromObject(env, hHandle),
                                          *(BLOCKCIPHERPARAM *) jValue);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_Decrypt
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1Decrypt
        (JNIEnv * env, jobject
        obj, jobject
        hHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_Decrypt)(ckHandleFromObject(env, hHandle),
                                      (unsigned char *) jBufferInput, jBufferInputLength,
                                      jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_Decrypt)(ckHandleFromObject(env, hHandle),
                                      (unsigned char *) jBufferInput, jBufferInputLength,
                                      jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DecryptUpdate
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DecryptUpdate
        (JNIEnv * env, jobject
        obj, jobject
        hHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_DecryptUpdate)(ckHandleFromObject(env, hHandle),
                                            (unsigned char *) jBufferInput, jBufferInputLength,
                                            jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_DecryptUpdate)(ckHandleFromObject(env, hHandle),
                                            (unsigned char *) jBufferInput, jBufferInputLength,
                                            jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DecryptFinal
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DecryptFinal
        (JNIEnv * env, jobject
        obj, jobject
        hHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_DecryptFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                           &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_DecryptFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                           &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);
    end:

    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DigestInit
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;JLcom/wtsecure/safecard/sof_client/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DigestInit
        (JNIEnv * env, jobject
        obj, jobject
        hDevHandle, jlong
        ulAlgID, jobject
        pPubKey, jbyteArray
        jbyteArrayInput, jobject
        jHashHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    void *jValue = 0;
    size_t jValueLength = 0;
    HANDLE hHashHandle = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    ckDataFromObject(env, jValue, &jValueLength, pPubKey);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, pPubKey);

    rv = (*ckpFunctions->SKF_DigestInit)(ckHandleFromObject(env, hDevHandle), ulAlgID,
                                         (ECCPUBLICKEYBLOB *) jValue,
                                         (unsigned char *) jBufferInput, jBufferInputLength,
                                         &hHashHandle);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckHandleToObject(env, hHashHandle, jHashHandle);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}



/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_Digest
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1Digest
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_Digest)(ckHandleFromObject(env, jHandle),
                                     (unsigned char *) jBufferInput, jBufferInputLength,
                                     jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_Digest)(ckHandleFromObject(env, jHandle),
                                     (unsigned char *) jBufferInput, jBufferInputLength,
                                     jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;

}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DigestUpdate
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DigestUpdate
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_DigestUpdate)(ckHandleFromObject(env, jHandle),
                                           (unsigned char *) jBufferInput, jBufferInputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_DigestFinal
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1DigestFinal
        (JNIEnv * env, jobject
        obj, jobject
        hHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_DigestFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                          &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_DigestFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                          &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_MacInit
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;Lcom/wtsecure/safecard/sof_client/wrapper/SKFBlockCipherParam;Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1MacInit
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jobject
        pMacParam, jobject
        jMacHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    void *jValue = 0;
    size_t jValueLength = 0;
    HANDLE hMacHandle;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    ckDataFromObject(env, jValue, &jValueLength, pMacParam);

    jValue = new unsigned char[jValueLength];

    ckDataFromObject(env, jValue, &jValueLength, pMacParam);

    rv = (*ckpFunctions->SKF_MacInit)(ckHandleFromObject(env, jHandle), (BLOCKCIPHERPARAM *) jValue,
                                      &hMacHandle);

    delete jValue;

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    ckHandleToObject(env, hMacHandle, jMacHandle);

    end:

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_Mac
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1Mac
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_Mac)(ckHandleFromObject(env, jHandle), (unsigned char *) jBufferInput,
                                  jBufferInputLength, jBufferOutput, &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_Mac)(ckHandleFromObject(env, jHandle), (unsigned char *) jBufferInput,
                                  jBufferInputLength, jBufferOutput, &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_MacUpdate
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;[B)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1MacUpdate
        (JNIEnv * env, jobject
        obj, jobject
        jHandle, jbyteArray
        jbyteArrayInput)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    rv = (*ckpFunctions->SKF_MacUpdate)(ckHandleFromObject(env, jHandle),
                                        (unsigned char *) jBufferInput, jBufferInputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_MacFinal
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)[B
 */
JNIEXPORT jbyteArray JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1MacFinal
        (JNIEnv * env, jobject
        obj, jobject
        hHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jbyteArray jbyteArrayOutput = 0;
    unsigned char *jBufferOutput = 0;
    ULONG jBufferOutputLength = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return jbyteArrayOutput; }

    rv = (*ckpFunctions->SKF_MacFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                       &jBufferOutputLength);

    jBufferOutput = new unsigned char[jBufferOutputLength];

    rv = (*ckpFunctions->SKF_MacFinal)(ckHandleFromObject(env, hHandle), jBufferOutput,
                                       &jBufferOutputLength);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    jbyteArrayOutput = env->NewByteArray((jsize) jBufferOutputLength);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) jBufferOutputLength,
                            (jbyte *) jBufferOutput);

    end:
    if (jBufferOutput) {
        delete jBufferOutput;
    }

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return jbyteArrayOutput;
}


/*
 * Class:     com_wtsecure_safecard_sof_client_wrapper_SKFImplementation
 * Method:    SKF_CloseHandle
 * Signature: (Lcom/wtsecure/safecard/sof_client/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CloseHandle
        (JNIEnv * env, jobject
        obj, jobject
        hHandle) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_CloseHandle)(ckHandleFromObject(env, hHandle);

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}

#endif

#ifdef __cplusplus
}
#endif
