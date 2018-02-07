#include <jni.h>
#include <string>

#include "skf.h"
#include "assert.h"
#include "FILE_LOG.h"

#include "dlfcn.h"


typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;

#ifndef MIX_PREFIX_UPAPI_CLASS_STR
#define MIX_PREFIX_UPAPI_CLASS_STR "com/wtsecure/safecard/skf/wrapper/"
#endif

#ifndef MIX_PREFIX_UPAPI_FUNC
#define MIX_PREFIX_UPAPI_FUNC Java_com_wtsecure_safecard_skf_wrapper_SKFImplementation_
#endif

#define CLASS_SKFEXCEPTION __MIX_PREFIX_STR_PASTE(MIX_PREFIX_UPAPI_CLASS_STR,"SKFException")
#define CLASS_SKFDEVINFO __MIX_PREFIX_STR_PASTE(MIX_PREFIX_UPAPI_CLASS_STR,"SKFDevInfo")

#ifdef __cplusplus
extern "C" {
#endif

jlong ckAssertReturnValueOK(JNIEnv *env, ULONG returnValue, const char *callerMethodName) {
    jclass jSKFExceptionClass;
    jmethodID jConstructor;
    jthrowable jSKFException;
    jlong jErrorCode;

    if (returnValue == SAR_OK) {
        return 0L;
    } else {
        jSKFExceptionClass = env->FindClass(CLASS_SKFEXCEPTION);
        assert(jSKFExceptionClass != 0);
        jConstructor = env->GetMethodID(jSKFExceptionClass, "<init>", "(J)V");
        assert(jConstructor != 0);
        jErrorCode = returnValue;
        jSKFException = (jthrowable) env->NewObject(jSKFExceptionClass, jConstructor, jErrorCode);
        env->Throw(jSKFException);
        FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, callerMethodName);
        return jErrorCode;
    }
}

void ckHandleToObject(JNIEnv *env, HANDLE ckHandle, jobject obj) {
    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "value", "J");

    env->SetLongField(obj, ID_value, (long) ckHandle);

    return;
}

HANDLE ckHandleFromObject(JNIEnv *env, jobject obj) {
    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "value", "J");

    return (HANDLE) env->GetLongField(obj, ID_value);
}

void ckULongToObject(JNIEnv *env, ULONG ckLong, jobject obj) {
    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "value", "J");

    env->SetLongField(obj, ID_value, ckLong);

    return;
}

void ckDataToObject(JNIEnv *env, void *ckValue, size_t ckLen, jobject obj) {
    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "value", "[B");

    jbyteArray jbyteArrayOutput = env->NewByteArray((jsize) ckLen);

    jclass jByteArrayClass = env->FindClass("[B");
    jclass jLongClass = env->FindClass("java/lang/Long");
    jclass jDevInfoClass = env->FindClass(CLASS_SKFDEVINFO);

    env->SetByteArrayRegion(jbyteArrayOutput, 0, (jsize) ckLen, (jbyte *) ckValue);

    env->SetObjectField(obj, ID_value, jbyteArrayOutput);

    if (env->IsInstanceOf(obj, jDevInfoClass)) {
        jfieldID fieldID;
        jlong jLong;
        jbyteArray jbyteArray;
        DEVINFO *devinfo = (DEVINFO *) ckValue;

//        long		VersionMajor;					//版本号	数据结构版本号，本结构的版本号为1.0
//        long		VersionMinor;					//版本号	数据结构版本号，本结构的版本号为1.0
//        byte[]		Manufacturer;			//设备厂商信息	以 '\0'为结束符的ASCII字符串
//        byte[]		Issuer;					//发行厂商信息	以 '\0'为结束符的ASCII字符串
//        byte[]		Label;					//设备标签	以 '\0'为结束符的ASCII字符串
//        byte[]		SerialNumber;			//序列号	以 '\0'为结束符的ASCII字符串
//        long		HWVersionMajor;					//设备硬件版本
//        long		HWVersionMinor;					//设备硬件版本
//        long		FirmwareVersionMajor;			//设备本身固件版本
//        long		FirmwareVersionMinor;			//设备本身固件版本
//        long		AlgSymCap;					//分组密码算法标识
//        long		AlgAsymCap;					//非对称密码算法标识
//        long		AlgHashCap;					//密码杂凑算法标识
//        long		DevAuthAlgId;				//设备认证使用的分组密码算法标识
//        long		TotalSpace;					//设备总空间大小
//        long		FreeSpace;					//用户可用空间大小
//        long		MaxECCBufferSize;			// 能够处理的 ECC 加密数据大小
//        long		MaxBufferSize;				//能够处理的分组运算和杂凑运算的数据大小
//        byte[]  	Reserved;				//保留扩展

        /* get ulWordsize */
        fieldID = env->GetFieldID(jDevInfoClass, "VersionMajor", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->Version.major);

        fieldID = env->GetFieldID(jDevInfoClass, "VersionMinor", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->Version.minor);

        fieldID = env->GetFieldID(jDevInfoClass, "Manufacturer", "[B");
        jbyteArray = env->NewByteArray(sizeof(devinfo->Manufacturer));
        env->SetByteArrayRegion(jbyteArray, 0, sizeof(devinfo->Manufacturer),
                                (jbyte *) devinfo->Manufacturer);
        env->SetObjectField(obj, fieldID, jbyteArray);

        fieldID = env->GetFieldID(jDevInfoClass, "Issuer", "[B");
        jbyteArray = env->NewByteArray(sizeof(devinfo->Issuer));
        env->SetByteArrayRegion(jbyteArray, 0, sizeof(devinfo->Issuer), (jbyte *) devinfo->Issuer);
        env->SetObjectField(obj, fieldID, jbyteArray);

        fieldID = env->GetFieldID(jDevInfoClass, "Label", "[B");
        jbyteArray = env->NewByteArray(sizeof(devinfo->Label));
        env->SetByteArrayRegion(jbyteArray, 0, sizeof(devinfo->Label), (jbyte *) devinfo->Label);
        env->SetObjectField(obj, fieldID, jbyteArray);

        fieldID = env->GetFieldID(jDevInfoClass, "SerialNumber", "[B");
        jbyteArray = env->NewByteArray(sizeof(devinfo->SerialNumber));
        env->SetByteArrayRegion(jbyteArray, 0, sizeof(devinfo->SerialNumber),
                                (jbyte *) devinfo->SerialNumber);
        env->SetObjectField(obj, fieldID, jbyteArray);
        fieldID = env->GetFieldID(jDevInfoClass, "HWVersionMajor", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->HWVersion.major);

        fieldID = env->GetFieldID(jDevInfoClass, "HWVersionMinor", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->HWVersion.minor);
        fieldID = env->GetFieldID(jDevInfoClass, "FirmwareVersionMajor", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->FirmwareVersion.major);

        fieldID = env->GetFieldID(jDevInfoClass, "FirmwareVersionMinor", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->FirmwareVersion.minor);
        fieldID = env->GetFieldID(jDevInfoClass, "AlgSymCap", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->AlgSymCap);

        fieldID = env->GetFieldID(jDevInfoClass, "AlgAsymCap", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->AlgAsymCap);

        fieldID = env->GetFieldID(jDevInfoClass, "AlgHashCap", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->AlgHashCap);

        fieldID = env->GetFieldID(jDevInfoClass, "DevAuthAlgId", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->DevAuthAlgId);

        fieldID = env->GetFieldID(jDevInfoClass, "TotalSpace", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->TotalSpace);

        fieldID = env->GetFieldID(jDevInfoClass, "FreeSpace", "J");
        assert(fieldID != 0);
        env->SetLongField(obj, fieldID, devinfo->FreeSpace);
    }

    return;
}

void ckDataFromObject(JNIEnv *env, void *ckValue, size_t *ckLen, jobject obj) {
    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "value", "B");

    jbyteArray jbyteArrayOutput = (jbyteArray) env->GetObjectField(obj, ID_value);

    jlong jBufferInputLength = env->GetArrayLength(jbyteArrayOutput);
    jbyte *jBufferInput = env->GetByteArrayElements(jbyteArrayOutput, NULL);

    *ckLen = jBufferInputLength;

    if (ckValue) {
        memcpy(ckValue, jBufferInput, jBufferInputLength);
    }

    env->ReleaseByteArrayElements(jbyteArrayOutput, jBufferInput, 0);

    return;
}


CK_FUNCTION_LIST_PTR getFunctionList(JNIEnv *env, jobject obj) {
    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "ckpFunctions", "J");

    return (CK_FUNCTION_LIST_PTR) env->GetLongField(obj, ID_value);
}


JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, initializeLibraryNative
        (JNIEnv * env, jobject
        obj, jbyteArray
        jbyteArrayInput)) {
    CK_FUNCTION_LIST_PTR ckpFunctions = new CK_FUNCTION_LIST;

    jclass cls = env->GetObjectClass(obj);

    jbyte *jBufferInput = 0;
    jlong jBufferInputLength = 0;

    jfieldID ID_value = env->GetFieldID(cls, "ckpFunctions", "J");

    // add code here for strSFKLibrary load init functions;
    void *hHandle = NULL;

    if( 0 != env->GetLongField(obj, ID_value))
    {
        goto end;
    }

    jBufferInputLength = env->GetArrayLength(jbyteArrayInput);
    jBufferInput = env->GetByteArrayElements(jbyteArrayInput, NULL);

    hHandle = dlopen(std::string(jBufferInput, jBufferInput + jBufferInputLength).c_str(),
                     RTLD_NOW);
    if (NULL == hHandle) {
        goto end;
    }

    ckpFunctions->hHandle = hHandle;

    // load
    ckpFunctions->SKF_SetPackageName = (typeof(ckpFunctions->SKF_SetPackageName)) dlsym(hHandle,
                                                                                        "SKF_SetPackageName");
    ckpFunctions->SKF_WaitForDevEvent = (typeof(ckpFunctions->SKF_WaitForDevEvent)) dlsym(hHandle,
                                                                                          "SKF_WaitForDevEvent");
    ckpFunctions->SKF_CancelWaitForDevEvent = (typeof(ckpFunctions->SKF_CancelWaitForDevEvent)) dlsym(
            hHandle, "SKF_CancelWaitForDevEvent");
    ckpFunctions->SKF_EnumDev = (typeof(ckpFunctions->SKF_EnumDev)) dlsym(hHandle, "SKF_EnumDev");
    ckpFunctions->SKF_ConnectDev = (typeof(ckpFunctions->SKF_ConnectDev)) dlsym(hHandle,
                                                                                "SKF_ConnectDev");
    ckpFunctions->SKF_DisConnectDev = (typeof(ckpFunctions->SKF_DisConnectDev)) dlsym(hHandle,
                                                                                      "SKF_DisConnectDev");
    ckpFunctions->SKF_GetDevState = (typeof(ckpFunctions->SKF_GetDevState)) dlsym(hHandle,
                                                                                  "SKF_GetDevState");
    ckpFunctions->SKF_SetLabel = (typeof(ckpFunctions->SKF_SetLabel)) dlsym(hHandle,
                                                                            "SKF_SetLabel");
    ckpFunctions->SKF_GetDevInfo = (typeof(ckpFunctions->SKF_GetDevInfo)) dlsym(hHandle,
                                                                                "SKF_GetDevInfo");
    ckpFunctions->SKF_LockDev = (typeof(ckpFunctions->SKF_LockDev)) dlsym(hHandle, "SKF_LockDev");
    ckpFunctions->SKF_UnlockDev = (typeof(ckpFunctions->SKF_UnlockDev)) dlsym(hHandle,
                                                                              "SKF_UnlockDev");
    ckpFunctions->SKF_Transmit = (typeof(ckpFunctions->SKF_Transmit)) dlsym(hHandle,
                                                                            "SKF_Transmit");
    ckpFunctions->SKF_ChangeDevAuthKey = (typeof(ckpFunctions->SKF_ChangeDevAuthKey)) dlsym(hHandle,
                                                                                            "SKF_ChangeDevAuthKey");
    ckpFunctions->SKF_DevAuth = (typeof(ckpFunctions->SKF_DevAuth)) dlsym(hHandle, "SKF_DevAuth");
    ckpFunctions->SKF_ChangePIN = (typeof(ckpFunctions->SKF_ChangePIN)) dlsym(hHandle,
                                                                              "SKF_ChangePIN");
    ckpFunctions->SKF_GetPINInfo = (typeof(ckpFunctions->SKF_GetPINInfo)) dlsym(hHandle,
                                                                                "SKF_GetPINInfo");
    ckpFunctions->SKF_VerifyPIN = (typeof(ckpFunctions->SKF_VerifyPIN)) dlsym(hHandle,
                                                                              "SKF_VerifyPIN");
    ckpFunctions->SKF_UnblockPIN = (typeof(ckpFunctions->SKF_UnblockPIN)) dlsym(hHandle,
                                                                                "SKF_UnblockPIN");
    ckpFunctions->SKF_ClearSecureState = (typeof(ckpFunctions->SKF_ClearSecureState)) dlsym(hHandle,
                                                                                            "SKF_ClearSecureState");
    ckpFunctions->SKF_CreateApplication = (typeof(ckpFunctions->SKF_CreateApplication)) dlsym(
            hHandle, "SKF_CreateApplication");
    ckpFunctions->SKF_EnumApplication = (typeof(ckpFunctions->SKF_EnumApplication)) dlsym(hHandle,
                                                                                          "SKF_EnumApplication");
    ckpFunctions->SKF_DeleteApplication = (typeof(ckpFunctions->SKF_DeleteApplication)) dlsym(
            hHandle, "SKF_DeleteApplication");
    ckpFunctions->SKF_OpenApplication = (typeof(ckpFunctions->SKF_OpenApplication)) dlsym(hHandle,
                                                                                          "SKF_OpenApplication");
    ckpFunctions->SKF_CloseApplication = (typeof(ckpFunctions->SKF_CloseApplication)) dlsym(hHandle,
                                                                                            "SKF_CloseApplication");
    ckpFunctions->SKF_CreateFile = (typeof(ckpFunctions->SKF_CreateFile)) dlsym(hHandle,
                                                                                "SKF_CreateFile");
    ckpFunctions->SKF_DeleteFile = (typeof(ckpFunctions->SKF_DeleteFile)) dlsym(hHandle,
                                                                                "SKF_DeleteFile");
    ckpFunctions->SKF_EnumFiles = (typeof(ckpFunctions->SKF_EnumFiles)) dlsym(hHandle,
                                                                              "SKF_EnumFiles");
    ckpFunctions->SKF_GetFileInfo = (typeof(ckpFunctions->SKF_GetFileInfo)) dlsym(hHandle,
                                                                                  "SKF_GetFileInfo");
    ckpFunctions->SKF_ReadFile = (typeof(ckpFunctions->SKF_ReadFile)) dlsym(hHandle,
                                                                            "SKF_ReadFile");
    ckpFunctions->SKF_WriteFile = (typeof(ckpFunctions->SKF_WriteFile)) dlsym(hHandle,
                                                                              "SKF_WriteFile");
    ckpFunctions->SKF_CreateContainer = (typeof(ckpFunctions->SKF_CreateContainer)) dlsym(hHandle,
                                                                                          "SKF_CreateContainer");
    ckpFunctions->SKF_DeleteContainer = (typeof(ckpFunctions->SKF_DeleteContainer)) dlsym(hHandle,
                                                                                          "SKF_DeleteContainer");
    ckpFunctions->SKF_OpenContainer = (typeof(ckpFunctions->SKF_OpenContainer)) dlsym(hHandle,
                                                                                      "SKF_OpenContainer");
    ckpFunctions->SKF_CloseContainer = (typeof(ckpFunctions->SKF_CloseContainer)) dlsym(hHandle,
                                                                                        "SKF_CloseContainer");
    ckpFunctions->SKF_EnumContainer = (typeof(ckpFunctions->SKF_EnumContainer)) dlsym(hHandle,
                                                                                      "SKF_EnumContainer");
    ckpFunctions->SKF_GetContainerType = (typeof(ckpFunctions->SKF_GetContainerType)) dlsym(hHandle,
                                                                                            "SKF_GetContainerType");
    ckpFunctions->SKF_ImportCertificate = (typeof(ckpFunctions->SKF_ImportCertificate)) dlsym(
            hHandle, "SKF_ImportCertificate");
    ckpFunctions->SKF_ExportCertificate = (typeof(ckpFunctions->SKF_ExportCertificate)) dlsym(
            hHandle, "SKF_ExportCertificate");
    ckpFunctions->SKF_GenRandom = (typeof(ckpFunctions->SKF_GenRandom)) dlsym(hHandle,
                                                                              "SKF_GenRandom");
    ckpFunctions->SKF_GenExtRSAKey = (typeof(ckpFunctions->SKF_GenExtRSAKey)) dlsym(hHandle,
                                                                                    "SKF_GenExtRSAKey");
    ckpFunctions->SKF_GenRSAKeyPair = (typeof(ckpFunctions->SKF_GenRSAKeyPair)) dlsym(hHandle,
                                                                                      "SKF_GenRSAKeyPair");
    ckpFunctions->SKF_ImportRSAKeyPair = (typeof(ckpFunctions->SKF_ImportRSAKeyPair)) dlsym(hHandle,
                                                                                            "SKF_ImportRSAKeyPair");
    ckpFunctions->SKF_RSASignData = (typeof(ckpFunctions->SKF_RSASignData)) dlsym(hHandle,
                                                                                  "SKF_RSASignData");
    ckpFunctions->SKF_RSAVerify = (typeof(ckpFunctions->SKF_RSAVerify)) dlsym(hHandle,
                                                                              "SKF_RSAVerify");
    ckpFunctions->SKF_RSAExportSessionKey = (typeof(ckpFunctions->SKF_RSAExportSessionKey)) dlsym(
            hHandle, "SKF_RSAExportSessionKey");
    ckpFunctions->SKF_ExtRSAPubKeyOperation = (typeof(ckpFunctions->SKF_ExtRSAPubKeyOperation)) dlsym(
            hHandle, "SKF_ExtRSAPubKeyOperation");
    ckpFunctions->SKF_ExtRSAPriKeyOperation = (typeof(ckpFunctions->SKF_ExtRSAPriKeyOperation)) dlsym(
            hHandle, "SKF_ExtRSAPriKeyOperation");
    ckpFunctions->SKF_GenECCKeyPair = (typeof(ckpFunctions->SKF_GenECCKeyPair)) dlsym(hHandle,
                                                                                      "SKF_GenECCKeyPair");
    ckpFunctions->SKF_ImportECCKeyPair = (typeof(ckpFunctions->SKF_ImportECCKeyPair)) dlsym(hHandle,
                                                                                            "SKF_ImportECCKeyPair");
    ckpFunctions->SKF_ECCSignData = (typeof(ckpFunctions->SKF_ECCSignData)) dlsym(hHandle,
                                                                                  "SKF_ECCSignData");
    ckpFunctions->SKF_ECCVerify = (typeof(ckpFunctions->SKF_ECCVerify)) dlsym(hHandle,
                                                                              "SKF_ECCVerify");
    ckpFunctions->SKF_ECCExportSessionKey = (typeof(ckpFunctions->SKF_ECCExportSessionKey)) dlsym(
            hHandle, "SKF_ECCExportSessionKey");
    ckpFunctions->SKF_ExtECCEncrypt = (typeof(ckpFunctions->SKF_ExtECCEncrypt)) dlsym(hHandle,
                                                                                      "SKF_ExtECCEncrypt");
    ckpFunctions->SKF_ExtECCDecrypt = (typeof(ckpFunctions->SKF_ExtECCDecrypt)) dlsym(hHandle,
                                                                                      "SKF_ExtECCDecrypt");
    ckpFunctions->SKF_ExtECCSign = (typeof(ckpFunctions->SKF_ExtECCSign)) dlsym(hHandle,
                                                                                "SKF_ExtECCSign");
    ckpFunctions->SKF_ExtECCVerify = (typeof(ckpFunctions->SKF_ExtECCVerify)) dlsym(hHandle,
                                                                                    "SKF_ExtECCVerify");
    ckpFunctions->SKF_GenerateAgreementDataWithECC = (typeof(ckpFunctions->SKF_GenerateAgreementDataWithECC)) dlsym(
            hHandle, "SKF_GenerateAgreementDataWithECC");
    ckpFunctions->SKF_GenerateAgreementDataAndKeyWithECC = (typeof(ckpFunctions->SKF_GenerateAgreementDataAndKeyWithECC)) dlsym(
            hHandle, "SKF_GenerateAgreementDataAndKeyWithECC");
    ckpFunctions->SKF_GenerateKeyWithECC = (typeof(ckpFunctions->SKF_GenerateKeyWithECC)) dlsym(
            hHandle, "SKF_GenerateKeyWithECC");
    ckpFunctions->SKF_ExportPublicKey = (typeof(ckpFunctions->SKF_ExportPublicKey)) dlsym(hHandle,
                                                                                          "SKF_ExportPublicKey");
    ckpFunctions->SKF_ImportSessionKey = (typeof(ckpFunctions->SKF_ImportSessionKey)) dlsym(hHandle,
                                                                                            "SKF_ImportSessionKey");
    ckpFunctions->SKF_SetSymmKey = (typeof(ckpFunctions->SKF_SetSymmKey)) dlsym(hHandle,
                                                                                "SKF_SetSymmKey");
    ckpFunctions->SKF_EncryptInit = (typeof(ckpFunctions->SKF_EncryptInit)) dlsym(hHandle,
                                                                                  "SKF_EncryptInit");
    ckpFunctions->SKF_Encrypt = (typeof(ckpFunctions->SKF_Encrypt)) dlsym(hHandle, "SKF_Encrypt");
    ckpFunctions->SKF_EncryptUpdate = (typeof(ckpFunctions->SKF_EncryptUpdate)) dlsym(hHandle,
                                                                                      "SKF_EncryptUpdate");
    ckpFunctions->SKF_EncryptFinal = (typeof(ckpFunctions->SKF_EncryptFinal)) dlsym(hHandle,
                                                                                    "SKF_EncryptFinal");
    ckpFunctions->SKF_DecryptInit = (typeof(ckpFunctions->SKF_DecryptInit)) dlsym(hHandle,
                                                                                  "SKF_DecryptInit");
    ckpFunctions->SKF_Decrypt = (typeof(ckpFunctions->SKF_Decrypt)) dlsym(hHandle, "SKF_Decrypt");
    ckpFunctions->SKF_DecryptUpdate = (typeof(ckpFunctions->SKF_DecryptUpdate)) dlsym(hHandle,
                                                                                      "SKF_DecryptUpdate");
    ckpFunctions->SKF_DecryptFinal = (typeof(ckpFunctions->SKF_DecryptFinal)) dlsym(hHandle,
                                                                                    "SKF_DecryptFinal");
    ckpFunctions->SKF_DigestInit = (typeof(ckpFunctions->SKF_DigestInit)) dlsym(hHandle,
                                                                                "SKF_DigestInit");
    ckpFunctions->SKF_Digest = (typeof(ckpFunctions->SKF_Digest)) dlsym(hHandle, "SKF_Digest");
    ckpFunctions->SKF_DigestUpdate = (typeof(ckpFunctions->SKF_DigestUpdate)) dlsym(hHandle,
                                                                                    "SKF_DigestUpdate");
    ckpFunctions->SKF_DigestFinal = (typeof(ckpFunctions->SKF_DigestFinal)) dlsym(hHandle,
                                                                                  "SKF_DigestFinal");
    ckpFunctions->SKF_MacInit = (typeof(ckpFunctions->SKF_MacInit)) dlsym(hHandle, "SKF_MacInit");
    ckpFunctions->SKF_Mac = (typeof(ckpFunctions->SKF_Mac)) dlsym(hHandle, "SKF_Mac");
    ckpFunctions->SKF_MacUpdate = (typeof(ckpFunctions->SKF_MacUpdate)) dlsym(hHandle,
                                                                              "SKF_MacUpdate");
    ckpFunctions->SKF_MacFinal = (typeof(ckpFunctions->SKF_MacFinal)) dlsym(hHandle,
                                                                            "SKF_MacFinal");
    ckpFunctions->SKF_CloseHandle = (typeof(ckpFunctions->SKF_CloseHandle)) dlsym(hHandle,
                                                                                  "SKF_CloseHandle");

    env->SetLongField(obj, ID_value, (long) ckpFunctions);
    end:
    if (jBufferInput) {
        env->ReleaseByteArrayElements(jbyteArrayInput, jBufferInput, 0);
    }

    return;
}

JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, finalizeLibraryNative
        (JNIEnv * env, jobject
        obj, jbyteArray
        jbyteArrayInput)) {
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    jclass cls = env->GetObjectClass(obj);

    jfieldID ID_value = env->GetFieldID(cls, "ckpFunctions", "J");

    ckpFunctions = (CK_FUNCTION_LIST_PTR) env->GetLongField(obj, ID_value);

    if (ckpFunctions) {
        // add code here
        dlclose(ckpFunctions->hHandle);
        ckpFunctions->hHandle = NULL;

        delete (ckpFunctions);
    }

    // reset to null
    env->SetLongField(obj, ID_value, 0);

    return;
}


/*
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_WaitForDevEvent
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFUlong;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_WaitForDevEvent
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFUlong;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ConnectDev
 * Signature: ([BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DisConnectDev
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_SetLabel
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GetSKFDevInfo
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFDevInfo;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_LockDev
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;J)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_UnlockDev
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_Transmit
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ChangeDevAuthKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DevAuth
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ChangePIN
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;J[B[BLcom/wtsecure/safecard/skf/wrapper/SKFUlong;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GetPINInfo
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFPinInfo;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_VerifyPIN
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;J[BLcom/wtsecure/safecard/skf/wrapper/SKFUlong;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_UnblockPIN
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B[BLcom/wtsecure/safecard/skf/wrapper/SKFUlong;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ClearSecureState
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_CreateApplication
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B[BJ[BJJLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_EnumApplication
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DeleteApplication
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_OpenApplication
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_CloseApplication
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_CreateFile
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BJJ)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DeleteFile
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_EnumFiles
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GetFileInfo
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BLcom/wtsecure/safecard/skf/wrapper/SKFFileAttribute;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ReadFile
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BJJ)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_WriteFile
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BJ[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_CreateContainer
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DeleteContainer
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_OpenContainer
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_CloseContainer
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_EnumContainer
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GetContainerType
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)J
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ImportCertificate
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Z[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExportCertificate
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Z)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenRandom
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenExtRSAKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFRsaPrivateKeyBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenRSAKeyPair
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFRsaPublicKeyBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ImportRSAKeyPair
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;J[B[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_RSASignData
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_RSAVerify
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFRsaPublicKeyBlob;[B[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_RSAExportSessionKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFRsaPublicKeyBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExtRSAPubKeyOperation
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFRsaPublicKeyBlob;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExtRSAPriKeyOperation
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFRsaPrivateKeyBlob;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenECCKeyPair
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ImportECCKeyPair
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEnvelopedKeyBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ECCSignData
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BLcom/wtsecure/safecard/skf/wrapper/SKFEccSignatureBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ECCVerify
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFEccSignatureBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ECCExportSessionKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFEccCipherBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExtECCEncrypt
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFEccCipherBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExtECCDecrypt
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPrivateKeyBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFEccCipherBlob;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExtECCSign
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPrivateKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFEccSignatureBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExtECCVerify
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFEccSignatureBlob;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenerateAgreementDataWithECC
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenerateAgreementDataAndKeyWithECC
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[B[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_GenerateKeyWithECC
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;Lcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ExportPublicKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Z)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_ImportSessionKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;J[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_SetSymmKey
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[BJLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_EncryptInit
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFBlockCipherParam;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_Encrypt
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_EncryptUpdate
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_EncryptFinal
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DecryptInit
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFBlockCipherParam;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_Decrypt
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DecryptUpdate
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DecryptFinal
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DigestInit
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;JLcom/wtsecure/safecard/skf/wrapper/SKFEccPublicKeyBlob;[BLcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_Digest
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DigestUpdate
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_DigestFinal
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_MacInit
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;Lcom/wtsecure/safecard/skf/wrapper/SKFBlockCipherParam;Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_Mac
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_MacUpdate
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;[B)V
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_MacFinal
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)[B
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
 * Class:     com_wtsecure_safecard_skf_wrapper_SKFImplementation
 * Method:    SKF_CloseHandle
 * Signature: (Lcom/wtsecure/safecard/skf/wrapper/SKFHandle;)V
 */
JNIEXPORT void JNICALL __MIX_PREFIX_FUNC_PASTE(MIX_PREFIX_UPAPI_FUNC, SKF_1CloseHandle
        (JNIEnv * env, jobject
        obj, jobject
        hHandle)) {
    ULONG rv = 0;
    CK_FUNCTION_LIST_PTR ckpFunctions = 0;

    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

    ckpFunctions = getFunctionList(env, obj);

    if (ckpFunctions == NULL) { return; }

    rv = (*ckpFunctions->SKF_CloseHandle)(ckHandleFromObject(env, hHandle));

    ckAssertReturnValueOK(env, rv, __FUNCTION__);
    if (0 != rv) { goto end; }

    end:
    FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

    return;
}

#ifdef __cplusplus
}
#endif
