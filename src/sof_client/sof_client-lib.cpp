#include <string>
#include "sof_client.h"
#include "sof_client-tools.h"
#include "assert.h"
#include "FILE_LOG.h"
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include "certificate_items_parse.h"
#include "smb_cs.h"
#include "smcert.h"
#include "openssl_func_def.h"
#include <iostream>
#include <fstream>
#include <iostream>
#include <fstream>
#include <sm2_boringssl.h>
#include <openssl/mem.h>


typedef CK_SOF_CLIENT_FUNCTION_LIST *CK_SOF_CLIENT_FUNCTION_LIST_PTR;
typedef CK_SKF_FUNCTION_LIST *CK_SKF_FUNCTION_LIST_PTR;


//  RFC定义的oid如下：
//  数据类型data                                           1 2 840 113549 1 7 1
//	签名数据类型signedData                                 1 2 840 113549 1 7 2
//	数字信封数据类型envelopedData                          1 2 840 113549 1 7 3
//	签名及数字信封数据类型signedAndEnvelopedData           1 2 840 113549 1 7 4
//	摘要数据类型digestData                                 1 2 840 113549 1 7 5
//	加密数据类型encryptedData                              1 2 840 113549 1 7 6

//	国密标准GM / T 0010定义的oid如下：
//	数据类型data                                           1.2.156.10197.6.1.4.2.1
//	签名数据类型signedData                                 1.2.156.10197.6.1.4.2.2
//	数字信封数据类型envelopedData                          1.2.156.10197.6.1.4.2.3
//	签名及数字信封数据类型signedAndEnvelopedData           1.2.156.10197.6.1.4.2.4
//	加密数据类型encryptedData                              1.2.156.10197.6.1.4.2.5
//	密钥协商类型keyAgreementInfo                           1.2.156.10197.6.1.4.2.6

// 1.2.840.113549.1.7.1
static const uint8_t kPKCS7DataRFC[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,0x0d, 0x01, 0x07, 0x01 };

// 1.2.840.113549.1.7.2
static const uint8_t kPKCS7SignedDataRFC[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,0x0d, 0x01, 0x07, 0x02 };

// 1.2.840.113549.1.7.3
static const uint8_t kPKCS7EnvelopedDataRFC[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7,0x0d, 0x01, 0x07, 0x03 };

// 1.2.156.10197.6.1.4.2.1
static const uint8_t kPKCS7DataSM2[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x06, 0x01, 0x04, 0x02, 0x01 };

// 1.2.156.10197.6.1.4.2.2
static const uint8_t kPKCS7SignedDataSM2[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x06, 0x01, 0x04, 0x02, 0x02 };

// 1.2.156.10197.6.1.4.2.3
static const uint8_t kPKCS7EnvelopedDataDataSM2[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x06, 0x01, 0x04, 0x02, 0x03 };

// 1.2.156.10197.1.401
static const uint8_t kDataSM3[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x01, 0x83, 0x11 };

// 1.2.156.10197.1.301
static const uint8_t kDataSM2[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x01, 0x82, 0x2d };

// 2.16.840.1.101.3.4.2.1 
static const uint8_t kDataSHA256[] = { 0x60, 0x86 , 0x48 , 0x01 , 0x65 , 0x03, 0x04, 0x02, 0x01 };
// 1.3.14.3.2.26
static const uint8_t kDataSHA1[] = { 0x2B, 0x0E , 0x03 , 0x02 , 0x1A };

// 1.2.840.113549.1.1.1
static const uint8_t kDataRSA[]{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,0x01, 0x01,0x01 };



#ifdef __cplusplus
extern "C" {
#endif

	typedef struct _ST_GlobalData
	{
		void * hDevHandle;
		void * hAppHandle;
		ULONG sign_method;
		ULONG encrypt_method;
		ULONG last_error;
		ULONG retry;

	}ST_GlobalData;

	static ST_GlobalData global_data = { 0 };


	unsigned int CAPI_GetMulStringCount(char * pszMulString, int * pulCount)
	{
		int i = 0;

		int ulCount = 0;

		char * ptr = pszMulString;

		for (ptr = pszMulString; *ptr;)
		{
			ptr += strlen(ptr);
			ptr++;
			ulCount++;
		}

		*pulCount = ulCount;

		return 0;
	}

	ULONG ErrorCodeConvert(ULONG errCode)
	{
		if (errCode >= SAR_FAIL || errCode <= SAR_REACH_MAX_CONTAINER_COUNT)
		{
			//return errCode;
		}
		global_data.last_error = errCode;
		return errCode;
	}


	ULONG CALL_CONVENTION SOF_GetVersion(void * p_ckpFunctions, VERSION *pVersion)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;
		DEVINFO devinfo;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GetDevInfo(global_data.hDevHandle,&devinfo);
		if (ulResult)
		{
			goto end;
		}

		memcpy(pVersion, &(devinfo.Version), sizeof(VERSION));

	end:
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_SetSignMethod(void * p_ckpFunctions, ULONG ulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		global_data.sign_method = ulMethod;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_GetSignMethod(void * p_ckpFunctions, ULONG *pulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulMethod = global_data.sign_method;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_SetEncryptMethod(void * p_ckpFunctions, ULONG ulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		global_data.encrypt_method = ulMethod;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_GetEncryptMethod(void * p_ckpFunctions, ULONG *pulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulMethod = global_data.encrypt_method;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_GetUserList(void * p_ckpFunctions, BYTE *pbUserList, ULONG *pulUserListLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		char * ptr = NULL;
		std::string strUserList;

		char buffer_containers[1024] = { 0 };
		char data_info_value[1024] = { 0 };
		ULONG buffer_containers_len = sizeof(buffer_containers);

		unsigned char buffer_cert[1024 *4] = { 0 };
		ULONG buffer_cert_len = sizeof(buffer_cert);

		int data_info_len = sizeof(data_info_value);

		HANDLE hContainer = NULL;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_EnumContainer(global_data.hAppHandle, buffer_containers, &buffer_containers_len);
		if (ulResult)
		{
			goto end;
		}

		for (ptr = buffer_containers; *ptr !=0 && (ptr < buffer_containers + buffer_containers_len); )
		{
			ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, ptr, &hContainer);
			if (ulResult)
			{
				goto end;
			}


			buffer_cert_len = sizeof(buffer_cert);

			ulResult = ckpFunctions->SKF_ExportCertificate(hContainer,TRUE, buffer_cert, &buffer_cert_len);
			if (ulResult)
			{
				goto end;
			}

			WT_SetMyCert(buffer_cert, buffer_cert_len);
			memset(data_info_value, 0, 1024);
			WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
			WT_ClearCert();

			if (strUserList.size() > 0)
			{
				strUserList.append("&&&");
			}
			else
			{

			}

			strUserList.append(strstr(data_info_value, "=") == NULL ? "" : strstr(data_info_value, "=")+1);
			strUserList.append("||");
			strUserList.append(ptr);
			ckpFunctions->SKF_CloseContainer(hContainer);
			hContainer = 0;

			ptr += strlen(ptr);
			ptr += 1;
		}


		if (NULL == pbUserList)
		{
			*pulUserListLen = strUserList.size();
			ulResult = SOR_OK;
		}
		else if (strUserList.size() >  *pulUserListLen)
		{
			*pulUserListLen = strUserList.size();
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulUserListLen = strUserList.size();
			memcpy(pbUserList, strUserList.c_str(), strUserList.size());
			ulResult = SOR_OK;
		}

	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_ExportUserCert(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_ExportCertificate(hContainer, TRUE, pbCert, pulCertLen);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_CloseContainer(hContainer);
		hContainer = 0;
	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_Login(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPIN)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_VerifyPIN(global_data.hAppHandle, USER_TYPE, pPIN, &global_data.retry);
		if (ulResult)
		{
			goto end;
		}

	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetPinRetryCount(void * p_ckpFunctions, LPSTR pContainerName, ULONG *pulRetryCount)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulRetryCount = global_data.retry;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_ChangePassWd(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPINOld, LPSTR pPINNew)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_ChangePIN(global_data.hAppHandle, USER_TYPE, pPINOld, pPINNew, &global_data.retry);
		if (ulResult)
		{
			goto end;
		}

	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_ExportExChangeUserCert(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_ExportCertificate(hContainer, FALSE, pbCert, pulCertLen);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_CloseContainer(hContainer);
		hContainer = 0;
	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetCertInfo(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, UINT16 u16Type, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		ULONG ulResult = 0;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		CertificateItemParse certParse;

		certParse.setCertificate(pbCert, ulCertLen);
		
		if ( 0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}

		switch (u16Type)
		{
		case  SGD_CERT_VERSION:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_VERSION, 0, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_SERIAL:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_ISSUER:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_ISSUER_DN, -1, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_VALID_TIME:
		{
			memcpy(data_info_value, certParse.m_strNotBefore.c_str(), certParse.m_strNotBefore.size());
			memcpy(data_info_value + certParse.m_strNotBefore.size(), "~", 1);
			memcpy(data_info_value + certParse.m_strNotBefore.size() +1, certParse.m_strNotAfter.c_str(), certParse.m_strNotAfter.size());
			data_info_len = certParse.m_strNotBefore.size()+1+certParse.m_strNotAfter.size();
		}
		break;

		case  SGD_CERT_SUBJECT:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SUBJECT_DN, -1, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_DER_PUBLIC_KEY:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SUBJECTPUBLICKEYINFO, 0, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		
		case  SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO:
		{
			memcpy(data_info_value, certParse.m_strIssueKeyID.c_str(), certParse.m_strIssueKeyID.size());
			data_info_len = certParse.m_strIssueKeyID.size();
		}
		break;

		case  SGD_EXT_SUBJECTKEYIDENTIFIER_INFO:
		{
			memcpy(data_info_value, certParse.m_strSubjectKeyID.c_str(), certParse.m_strSubjectKeyID.size());
			data_info_len = certParse.m_strSubjectKeyID.size();
		}
		break;

		case  SGD_EXT_KEYUSAGE_INFO:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_KEYUSAGE, 0, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_ISSUER_CN:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_ISSUER_DN, NID_COMMONNAME, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;

		case  SGD_CERT_ISSUER_O:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_ISSUER_DN, NID_ORGANIZATIONNAME, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_ISSUER_OU:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_ISSUER_DN, NID_ORGANIZATIONALUNITNAME, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;

		case  SGD_CERT_SUBJECT_CN:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		
		case  SGD_CERT_SUBJECT_O:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SUBJECT_DN, NID_ORGANIZATIONNAME, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_SUBJECT_OU:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SUBJECT_DN, NID_ORGANIZATIONALUNITNAME, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;
		case  SGD_CERT_SUBJECT_EMAIL:
		{
			WT_SetMyCert(pbCert, ulCertLen);
			memset(data_info_value, 0, 1024);
			data_info_len = sizeof(data_info_value);
			WT_GetCertInfo(CERT_SUBJECT_DN, NID_PKCS9_EMAILADDRESS, data_info_value, &data_info_len);
			WT_ClearCert();
		}
		break;


		case  SGD_CERT_EXTENSIONS:
		case  SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO:
		case  SGD_EXT_CERTIFICATEPOLICIES_INFO:
		case  SGD_EXT_POLICYMAPPINGS_INFO:
		case  SGD_EXT_BASICCONSTRAINTS_INFO:
		case  SGD_EXT_PROLICYCONSTRAINS_INFO:
		case  SGD_EXT_EXTKEYUSAGE_INFO:
		case  SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO:
		case  SGD_EXT_NETSCAPE_CERT_TYPE_INFO:
		case  SGD_EXT_SELFDEFINED_EXTENSION_INFO:
		default:
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
			break;

		}

		if (NULL == pbInfo)
		{
			*pulInfoLen = data_info_len;
			ulResult = SOR_OK;
		}
		else if (data_info_len >  *pulInfoLen)
		{
			*pulInfoLen = data_info_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulInfoLen = data_info_len;
			memcpy(pbInfo, data_info_value, data_info_len);
			ulResult = SOR_OK;
		}

	end:
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_GetCertInfoByOid(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pOidString, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_NOTSUPPORTYETERR);

		return SOR_NOTSUPPORTYETERR;
	}

	ULONG CALL_CONVENTION SOF_GetDeviceInfo(void * p_ckpFunctions, LPSTR pContainerName, ULONG ulType, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;
		DEVINFO devinfo;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GetDevInfo(global_data.hDevHandle, &devinfo);
		if (ulResult)
		{
			goto end;
		}

		switch (ulType)
		{
		case SGD_DEVICE_SORT:
		{
			memcpy(data_info_value, "crypto card", strlen("crypto card"));
			data_info_len = strlen("crypto card");
		}
		break;
		case SGD_DEVICE_TYPE:
		{
			memcpy(data_info_value, "null", strlen("null"));
			data_info_len = strlen("null");
		}
		break;
		case SGD_DEVICE_DESCRIPTION:
		case SGD_DEVICE_NAME:
		{
			memcpy(data_info_value, devinfo.Label, strlen((const char *)devinfo.Label));
			data_info_len = strlen((const char *)devinfo.Label);
		}
		break;
		case SGD_DEVICE_MANUFACTURER:
		{
			memcpy(data_info_value, devinfo.Manufacturer, strlen((const char *)devinfo.Manufacturer));
			data_info_len = strlen((const char *)devinfo.Manufacturer);
		}
		break;
		case SGD_DEVICE_HARDWARE_VERSION:
		{
			sprintf(data_info_value, "%d.%d", devinfo.HWVersion.major, devinfo.HWVersion.minor);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SOFTWARE_VERSION:
		{
			sprintf(data_info_value, "%d.%d", devinfo.FirmwareVersion.major, devinfo.FirmwareVersion.minor);
			data_info_len = strlen(data_info_value);
		}
		break;

		case SGD_DEVICE_STANDARD_VERSION:
		{
			sprintf(data_info_value, "%d.%d", devinfo.Version.major, devinfo.Version.minor);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SERIAL_NUMBER:
		{
			memcpy(data_info_value, devinfo.SerialNumber, strlen((const char *)devinfo.SerialNumber));
			data_info_len = strlen((const char *)devinfo.SerialNumber);
		}
		break;
		case SGD_DEVICE_SUPPORT_ALG_ASYM:
		{
			sprintf(data_info_value, "%08x", devinfo.AlgAsymCap);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_ALG_SYM:
		{
			sprintf(data_info_value, "%08x", devinfo.AlgSymCap);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_HASH_ALG:
		{
			sprintf(data_info_value, "%08x", devinfo.AlgHashCap);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_STORAGE_SPACE:
		{
			sprintf(data_info_value, "%08x", devinfo.TotalSpace);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_FREE_SPACE:
		{
			sprintf(data_info_value, "%08x", devinfo.FreeSpace);
			data_info_len = strlen(data_info_value);
		}
		break;
		
		case SGD_DEVICE_MANAGER_INFO:
		{
			sprintf(data_info_value, "%08x", devinfo.Issuer);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_MAX_DATA_SIZE:
		{
			sprintf(data_info_value, "%08x", devinfo.TotalSpace);
			data_info_len = strlen(data_info_value);
		}
		break;

		case SGD_DEVICE_RUNTIME:
		case SGD_DEVICE_USED_TIMES:
		case SGD_DEVICE_LOCATION:

		default:
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
			break;
		}


		if (NULL == pbInfo)
		{
			*pulInfoLen = data_info_len;
			ulResult = SOR_OK;
		}
		else if (data_info_len >  *pulInfoLen)
		{
			*pulInfoLen = data_info_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulInfoLen = data_info_len;
			memcpy(pbInfo, data_info_value, data_info_len);
			ulResult = SOR_OK;
		}

	end:
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_ValidateCert(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, ULONG *pulValidate)
	{
		ULONG ulResult = 0;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		CertificateItemParse certParse;

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg)
		{
			int res = SMB_CS_VerifyCert(SMB_CERT_VERIFY_FLAG_TIME | SMB_CERT_VERIFY_FLAG_CHAIN | SMB_CERT_VERIFY_FLAG_CRL, pbCert, ulCertLen);
			*pulValidate = 0;

			switch (res) {
			case 0:
				*pulValidate = SMB_CERT_VERIFY_RESULT_FLAG_OK;
				break;
			case EErr_SMB_VERIFY_TIME:
				*pulValidate = -2;
				break;
			case EErr_SMB_NO_CERT_CHAIN:
				*pulValidate = -6;
				break;
			case EErr_SMB_VERIFY_CERT:
				*pulValidate = -1;
				break;
			default:
				*pulValidate = -6;
				break;
			} 
			
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

	end:
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_SignData(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;
		ULONG ulResult = 0;
		ULONG ulContainerType = 0;
		HANDLE hHash = 0;

		ECCSIGNATUREBLOB blob = { 0 };

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		BYTE hash_value[1024] = { 0 };
		ULONG hash_len = sizeof(data_info_value);


		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}
		//1表示为RSA容器，为2表示为ECC容器
		ulResult = ckpFunctions->SKF_GetContainerType(hContainer, &ulContainerType);
		if (ulResult)
		{
			goto end;
		}


		if (ulContainerType == 1)
		{
			if (global_data.sign_method == SGD_SM3_RSA)
			{
				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, 0, 0, 0, &hHash);
			}
			else if (global_data.sign_method == SGD_SHA1_RSA)
			{
				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA1, 0, 0, 0, &hHash);
			}
			else if (global_data.sign_method == SGD_SHA256_RSA)
			{
				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA256, 0, 0, 0, &hHash);
			}
			else
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_RSASignData(hContainer, hash_value, hash_len, (unsigned char *)data_info_value, (ULONG *)&data_info_len);
			if (ulResult)
			{
				goto end;
			}

		}
		else if (ulContainerType == 2)
		{
			ECCPUBLICKEYBLOB pubkeyBlob = { 0 };
			ULONG ulBlobLen = sizeof(pubkeyBlob);

			if (global_data.sign_method == SGD_SM3_SM2)
			{
				ulResult = ckpFunctions->SKF_ExportPublicKey(hContainer, TRUE, (BYTE*)&pubkeyBlob, &ulBlobLen);
				if (ulResult)
				{
					goto end;
				}

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, &pubkeyBlob, (unsigned char *)"1234567812345678", 16, &hHash);
				if (ulResult)
				{
					goto end;
				}

				ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
				if (ulResult)
				{
					goto end;
				}

			}
			else
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			ulResult = ckpFunctions->SKF_ECCSignData(hContainer, hash_value, hash_len, &blob);
			if (ulResult)
			{
				goto end;
			}

			ulResult = SM2SignAsn1Convert(blob.r + 32, 32, blob.s + 32, 32, (unsigned char *)data_info_value, &data_info_len);
			if (ulResult)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

		if (NULL == pbDataOut)
		{
			*pulDataOutLen = data_info_len;
			ulResult = SOR_OK;
		}
		else if (data_info_len >  *pulDataOutLen)
		{
			*pulDataOutLen = data_info_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulDataOutLen = data_info_len;
			memcpy(pbDataOut, data_info_value,data_info_len);
			ulResult = SOR_OK;
		}

	end:

		if (hHash)
		{
			ckpFunctions->SKF_CloseHandle(hHash);
		}

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_VerifySignedData(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG ulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		RSA *rsa = NULL;

		HANDLE hHash = 0;

		RSAPUBLICKEYBLOB rsaPublicKeyBlob = { 0 };
		ECCPUBLICKEYBLOB eccPublicKeyBlob = { 0 };


		BYTE hash_value[1024] = { 0 };
		ULONG hash_len = sizeof(hash_value);


		CertificateItemParse certParse;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg)
		{
			X509 * x509 = NULL;
			unsigned char pbModulus[256];
			int ulModulusLen = 0;
			const unsigned char *ptr = NULL;
			ptr = pbCert;

			x509 = d2i_X509(NULL, &ptr, ulCertLen);

			if (x509)
			{
				RSA *rsa = EVP_PKEY_get1_RSA(X509_get_pubkey(x509));
				
				if (rsa != NULL)
				{
					ulModulusLen = BN_bn2bin(rsa->n, pbModulus);
				}
				
				rsaPublicKeyBlob.BitLen = ulModulusLen * 8;

				memcpy(rsaPublicKeyBlob.PublicExponent, "\x00\x01\x00\x01", 4);

				memcpy(rsaPublicKeyBlob.Modulus + 256 - ulModulusLen, pbModulus, ulModulusLen);
				X509_free(x509);
			}


			if (global_data.sign_method == SGD_SM3_RSA)
			{
				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, 0, 0, 0, &hHash);
			}
			else if (global_data.sign_method == SGD_SHA1_RSA)
			{
				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA1, 0, 0, 0, &hHash);
			}
			else if (global_data.sign_method == SGD_SHA256_RSA)
			{
				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA256, 0, 0, 0, &hHash);
			}
			else
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_RSAVerify(global_data.hDevHandle, &rsaPublicKeyBlob, hash_value, hash_len, pbDataOut, ulDataOutLen);
		}
		else if (ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
		{
			unsigned char tmp_data[32 * 2 + 1] = { 0 };
			unsigned int tmp_len = 65;

			ECCSIGNATUREBLOB blob = {0};
			
			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(pbCert, ulCertLen, tmp_data, &tmp_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, tmp_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, tmp_data + 1 +32, 32);


			ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, &eccPublicKeyBlob, (unsigned char *)"1234567812345678", 16, &hHash);
			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
			if (ulResult)
			{
				goto end;
			}

			ulResult = SM2SignD2i(pbDataOut, ulDataOutLen, tmp_data, (int *)&tmp_len);
			if (ulResult)
			{
				ulResult = SOR_INDATAERR;
				goto end;
			}

			memcpy(blob.r + 32, tmp_data, 32);
			memcpy(blob.s + 32, tmp_data+32, 32);

			ulResult = ckpFunctions->SKF_ECCVerify(global_data.hDevHandle, &eccPublicKeyBlob, hash_value, hash_len, &blob);
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

	end:

		if (hHash)
		{
			ckpFunctions->SKF_CloseHandle(hHash);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_SignFile(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pFileIn, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		std::fstream _fileIn;
		ULONG ulResult = 0;
		std::ios::pos_type ulFileInDataLen;
		char * pbFileInData = NULL;
		size_t pos = 0;
		size_t i = 0;
		int block = 1024;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		_fileIn.open(pFileIn, std::ios::binary | std::ios::in);

		if (_fileIn)
		{
			
		}
		else
		{
			ulResult = SOR_READFILEERR;
			goto end;
		}

		// get length of file:
		_fileIn.seekg(0, std::ios::end);
		ulFileInDataLen = _fileIn.tellg();
		_fileIn.seekg(0, std::ios::beg);

		pbFileInData = new char[ulFileInDataLen];

		// read data as a block:
		for (pos = 0; pos < ulFileInDataLen; )
		{
			if (pos + 1024 < ulFileInDataLen)
			{
				block = 1024;
			}
			else
			{
				block = (size_t)ulFileInDataLen - pos;
			}

			_fileIn.read(pbFileInData + pos, block);
			pos += block;
		}

		ulResult = SOF_SignData(p_ckpFunctions, pContainerName, (BYTE *)pbFileInData, (ULONG)ulFileInDataLen, (BYTE *)pbDataOut, pulDataOutLen);

		if (ulResult)
		{
			goto end;
		}

	end:

		if (_fileIn)
		{
			_fileIn.close();
		}

		if (pbFileInData)
		{
			delete[] pbFileInData;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_VerifySignedFile(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pFileIn, BYTE *pbDataOut, ULONG ulDataOutLen)
	{
		std::fstream _fileIn; 
		ULONG ulResult = 0;
		std::ios::pos_type ulFileInDataLen;
		char * pbFileInData = NULL;
		size_t pos = 0;
		size_t i = 0;
		int block = 1024;
		ULONG ulFileOutDataLen = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		_fileIn.open(pFileIn, std::ios::binary | std::ios::in);

		if (_fileIn)
		{

		}
		else
		{
			ulResult = SOR_READFILEERR;
			goto end;
		}

		
		// get length of file:
		_fileIn.seekg(0, std::ios::end);
		ulFileInDataLen = _fileIn.tellg();
		_fileIn.seekg(0, std::ios::beg);

		pbFileInData = new char[ulFileInDataLen];

		// read data as a block:
		for (pos = 0; pos < ulFileInDataLen; )
		{
			if (pos + 1024 < ulFileInDataLen)
			{
				block = 1024;
			}
			else
			{
				block = (size_t)ulFileInDataLen - pos;
			}

			_fileIn.read(pbFileInData + pos, block);
			pos += block;
		}

		ulResult = SOF_VerifySignedData(p_ckpFunctions, pbCert, ulCertLen,(BYTE *)pbFileInData, (ULONG)ulFileInDataLen, pbDataOut, ulDataOutLen);

		if (ulResult)
		{
			goto end;
		}

	end:

		if (_fileIn)
		{
			_fileIn.close();
		}

		if (pbFileInData)
		{
			delete[] pbFileInData;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_EncryptData(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		ECCCIPHERBLOB blob;

		RSA *rsa = NULL;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		RSAPUBLICKEYBLOB rsaPublicKeyBlob = { 0 };
		ECCPUBLICKEYBLOB eccPublicKeyBlob = { 0 };

		CertificateItemParse certParse;

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg)
		{
			X509 * x509 = NULL;
			unsigned char pbModulus[256];
			int ulModulusLen = 0;
			const unsigned char *ptr = NULL;
			ptr = pbCert;

			x509 = d2i_X509(NULL, &ptr, ulCertLen);

			if (x509)
			{
				RSA *rsa = EVP_PKEY_get1_RSA(X509_get_pubkey(x509));

				if (rsa != NULL)
				{
					ulModulusLen = BN_bn2bin(rsa->n, pbModulus);
				}

				rsaPublicKeyBlob.BitLen = ulModulusLen * 8;

				memcpy(rsaPublicKeyBlob.PublicExponent, "\x00\x01\x00\x01", 4);

				memcpy(rsaPublicKeyBlob.Modulus + 256 - ulModulusLen, pbModulus, ulModulusLen);
				X509_free(x509);
			}

			ulResult = ckpFunctions->SKF_ExtRSAPubKeyOperation(global_data.hDevHandle, &rsaPublicKeyBlob, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen);
		}
		else if (ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
		{
			unsigned char pk_data[32 * 2 + 1] = { 0 };
			unsigned int pk_len = 65;

			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(pbCert, ulCertLen, pk_data, &pk_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, pk_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, pk_data + 1 + 32, 32);

			ulResult = ckpFunctions->SKF_ExtECCEncrypt(global_data.hDevHandle, &eccPublicKeyBlob, pbDataIn, ulDataInLen, (PECCCIPHERBLOB)&blob);

			if (NULL == pbDataOut)
			{
				*pulDataOutLen = sizeof(blob);
				ulResult = SOR_OK;
			}
			else if (sizeof(blob) >  *pulDataOutLen)
			{
				*pulDataOutLen = sizeof(blob);
				ulResult = SOR_MEMORYERR;
			}
			else
			{
				*pulDataOutLen = sizeof(blob);
				memcpy(pbDataOut, &blob, sizeof(blob));
				ulResult = SOR_OK;
			}
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_DecryptData(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		ECCSIGNATUREBLOB blob;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}
		//1表示为RSA容器，为2表示为ECC容器
		ulResult = ckpFunctions->SKF_GetContainerType(hContainer, &ulContainerType);
		if (ulResult)
		{
			goto end;
		}

		if (ulContainerType == 1)
		{
			ulResult = ckpFunctions->SKF_RSAPriKeyOperation(hContainer, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen, FALSE);

		}
		else if (ulContainerType == 2)
		{
			ulResult = ckpFunctions->SKF_ECCDecrypt(hContainer, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen);

			if (NULL == pbDataOut)
			{
				*pulDataOutLen = sizeof(blob);
				ulResult = SOR_OK;
			}
			else if (sizeof(blob) >  *pulDataOutLen)
			{
				*pulDataOutLen = sizeof(blob);
				ulResult = SOR_MEMORYERR;
			}
			else
			{
				*pulDataOutLen = sizeof(blob);
				memcpy(pbDataOut, &blob, sizeof(blob));
				ulResult = SOR_OK;
			}
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}
	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_EncryptFile(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pFileIn, LPSTR pFileOut)
	{
		std::fstream _fileIn;
		std::fstream _fileOut;
		ULONG ulResult = 0;
		std::ios::pos_type ulFileInDataLen;
		char * pbFileInData = NULL;
		char * pbFileOutData = NULL;
		size_t pos = 0;
		size_t i = 0;
		int block = 1024;
		ULONG ulFileOutDataLen = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		_fileIn.open(pFileIn, std::ios::binary | std::ios::in);
		_fileOut.open(pFileOut, std::ios::binary | std::ios::out);

		if (_fileIn)
		{

		}
		else
		{
			ulResult = SOR_READFILEERR;
			goto end;
		}

		if (_fileOut)
		{

		}
		else
		{
			ulResult = SOR_WRITEFILEERR;
			goto end;
		}

		// get length of file:
		_fileIn.seekg(0, std::ios::end);
		ulFileInDataLen = _fileIn.tellg();
		_fileIn.seekg(0, std::ios::beg);

		pbFileInData = new char[ulFileInDataLen];

		// read data as a block:
		for (pos = 0; pos < ulFileInDataLen; )
		{
			if (pos + 1024 < ulFileInDataLen)
			{
				block = 1024;
			}
			else
			{
				block = (size_t)ulFileInDataLen - pos;
			}

			_fileIn.read(pbFileInData + pos, block);
			pos += block;
		}

		pbFileOutData = new char[(size_t)ulFileInDataLen + 2048];

		ulFileOutDataLen = (ULONG)ulFileInDataLen + 2048;

		ulResult = SOF_EncryptData(p_ckpFunctions, pbCert, ulCertLen, (BYTE *)pbFileInData, (ULONG)ulFileInDataLen, (BYTE *)pbFileOutData, &ulFileOutDataLen);

		if (ulResult)
		{
			goto end;
		}

		_fileOut.write(pbFileOutData, ulFileOutDataLen);

	end:

		if (_fileIn)
		{
			_fileIn.close();
		}

		if (_fileOut)
		{
			_fileOut.close();
		}

		if (pbFileInData)
		{
			delete[] pbFileInData;
		}

		if (pbFileOutData)
		{
			delete[] pbFileOutData;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_DecryptFile(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pFileIn, LPSTR pFileOut)
	{
		std::fstream _fileIn;
		std::fstream _fileOut;
		ULONG ulResult = 0;
		std::ios::pos_type ulFileInDataLen;
		char * pbFileInData = NULL;
		char * pbFileOutData = NULL;
		size_t pos = 0;
		size_t i = 0;
		int block = 1024;
		ULONG ulFileOutDataLen = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		_fileIn.open(pFileIn, std::ios::binary | std::ios::in);
		_fileOut.open(pFileOut, std::ios::binary | std::ios::out);

		if (_fileIn)
		{

		}
		else
		{
			ulResult = SOR_READFILEERR;
			goto end;
		}

		if (_fileOut)
		{

		}
		else
		{
			ulResult = SOR_WRITEFILEERR;
			goto end;
		}

		// get length of file:
		_fileIn.seekg(0, std::ios::end);
		ulFileInDataLen = _fileIn.tellg();
		_fileIn.seekg(0, std::ios::beg);

		pbFileInData = new char[ulFileInDataLen];

		// read data as a block:
		for (pos = 0; pos < ulFileInDataLen; )
		{
			if (pos + 1024 < ulFileInDataLen)
			{
				block = 1024;
			}
			else
			{
				block = (size_t)ulFileInDataLen - pos;
			}

			_fileIn.read(pbFileInData + pos, block);
			pos += block;
		}

		pbFileOutData = new char[(size_t)ulFileInDataLen + 2048];

		ulFileOutDataLen = (ULONG)ulFileInDataLen + 2048;

		ulResult = SOF_DecryptData(p_ckpFunctions, pContainerName, (BYTE *)pbFileInData, (ULONG)ulFileInDataLen, (BYTE *)pbFileOutData, &ulFileOutDataLen);

		if (ulResult)
		{
			goto end;
		}

		_fileOut.write(pbFileOutData, ulFileOutDataLen);

	end:

		if (_fileIn)
		{
			_fileIn.close();
		}

		if (_fileOut)
		{
			_fileOut.close();
		}

		if (pbFileInData)
		{
			delete[] pbFileInData;
		}

		if (pbFileOutData)
		{
			delete[] pbFileOutData;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_SignMessage(void * p_ckpFunctions, LPSTR pContainerName, UINT16 u16Flag, BYTE *pbDataIn,  ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		const unsigned char *ptr = NULL;
		ASN1_INTEGER *serial_number = NULL;
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;
		X509 * x509 = NULL;
		uint8_t *buf;
		X509_NAME *issue_name = NULL;
		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		HANDLE hHash = 0;

		int len = 0;

		CBB out, outer_seq, oid, wrapped_seq, seq, version_bytes, digests_set,
			content_info, plaintext, plaintext_wrap, certificates, digest_alg, digests, null_asn1, signerInfos, signerInfo, version_bytes1, digests1, digest1, encrypt_digest, encrypt_digests, signature;

		size_t result_len = 1024 * 1024 * 1024;

		ECCSIGNATUREBLOB blob = { 0 };

		BYTE pbCert[1024 * 4];
		ULONG ulCertLen = sizeof(pbCert);

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		BYTE hash_value[1024] = { 0 };
		ULONG hash_len = sizeof(hash_value);

		const uint8_t *kHashData = 0;
		size_t kHashLen =0;

		const uint8_t *kPKCS7SignedData = 0;
		size_t kPKCS7SignedLen = 0;

		const uint8_t *kPKCS7Data = 0;
		size_t kPKCS7Len = 0;

		const uint8_t *kEncData = 0;
		size_t kEncLen = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}
		//1表示为RSA容器，为2表示为ECC容器
		ulResult = ckpFunctions->SKF_GetContainerType(hContainer, &ulContainerType);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_ExportCertificate(hContainer, TRUE, pbCert, &ulCertLen);
		if (ulResult)
		{
			goto end;
		}

		ptr = pbCert;

		x509 = d2i_X509(NULL, &ptr, ulCertLen);
		if (!x509)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		issue_name = X509_get_issuer_name(x509);

		if (ulContainerType == 1)
		{
			kPKCS7SignedData = kPKCS7SignedDataRFC;
			kPKCS7SignedLen = sizeof(kPKCS7SignedDataRFC);
			kPKCS7Data = kPKCS7DataRFC;
			kPKCS7Len = sizeof(kPKCS7DataRFC);

			if (global_data.sign_method == SGD_SM3_RSA)
			{
				kEncData = kDataRSA;
				kEncLen = sizeof(kDataRSA);
				kHashData = kDataSM3;
				kHashLen = sizeof(kDataSM3);

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle,SGD_SM3, 0,0,0, &hHash);

			}
			else if (global_data.sign_method == SGD_SHA1_RSA)
			{
				kEncData = kDataRSA;
				kEncLen = sizeof(kDataRSA);
				kHashData = kDataSHA1;
				kHashLen = sizeof(kDataSHA1);

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA1, 0, 0, 0, &hHash);

			}
			else if (global_data.sign_method == SGD_SHA256_RSA)
			{
				kEncData = kDataRSA;
				kEncLen = sizeof(kDataRSA);
				kHashData = kDataSHA256;
				kHashLen = sizeof(kDataSHA256);

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA256, 0, 0, 0, &hHash);
			}
			else
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (ulResult)
			{
				goto end;
			}
			
			ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
			if (ulResult)
			{
				goto end;
			}


			ulResult = ckpFunctions->SKF_RSASignData(hContainer, hash_value, hash_len, (unsigned char *)data_info_value, (ULONG *)&data_info_len);
			if (ulResult)
			{
				goto end;
			}


		}
		else if (ulContainerType == 2)
		{
			ECCPUBLICKEYBLOB pubkeyBlob = {0};
			ULONG ulBlobLen = sizeof(pubkeyBlob);

			kPKCS7SignedData = kPKCS7SignedDataSM2;
			kPKCS7SignedLen = sizeof(kPKCS7SignedDataSM2);
			kPKCS7Data = kPKCS7DataSM2;
			kPKCS7Len = sizeof(kPKCS7DataSM2);

			if (global_data.sign_method == SGD_SM3_SM2)
			{
				kEncData = kDataSM2;
				kEncLen = sizeof(kDataSM2);
				kHashData = kDataSM3;
				kHashLen = sizeof(kDataSM3);

				ulResult = ckpFunctions->SKF_ExportPublicKey(hContainer, TRUE, (BYTE*)&pubkeyBlob, &ulBlobLen);
				if (ulResult)
				{
					goto end;
				}

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, &pubkeyBlob, (unsigned char *)"1234567812345678", 16, &hHash);
				if (ulResult)
				{
					goto end;
				}

				ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
				if (ulResult)
				{
					goto end;
				}
			}
			else
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			ulResult = ckpFunctions->SKF_ECCSignData(hContainer, hash_value, hash_len, &blob);
			if (ulResult)
			{
				goto end;
			}

			ulResult = SM2SignAsn1Convert(blob.r + 32, 32, blob.s + 32, 32, (unsigned char *)data_info_value, &data_info_len);
			if (ulResult)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

		CBB_init(&out, 1024 * 1024 * 1024);

		// See https://tools.ietf.org/html/rfc2315#section-7
		if (!CBB_add_asn1(&out, &outer_seq, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&outer_seq, &oid, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&oid, kPKCS7SignedData, kPKCS7SignedLen) ||                            // P7 类型
			!CBB_add_asn1(&outer_seq, &wrapped_seq,
				CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
			// See https://tools.ietf.org/html/rfc2315#section-9.1
			!CBB_add_asn1(&wrapped_seq, &seq, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&seq, &version_bytes, CBS_ASN1_INTEGER) ||
			!CBB_add_u8(&version_bytes, 1) ||
			!CBB_add_asn1(&seq, &digests_set, CBS_ASN1_SET) ||
			!CBB_add_asn1(&digests_set, &digests, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&digests, &digest_alg, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&digest_alg, kHashData, kHashLen) ||                                     //添加算法
			!CBB_add_asn1(&digests, &null_asn1, CBS_ASN1_NULL) ||
			!CBB_add_asn1(&seq, &content_info, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&content_info, &oid, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&oid, kPKCS7Data, kPKCS7Len))
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (1 == u16Flag)
		{
			if (!CBB_add_asn1(&content_info, &plaintext_wrap, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||  // 原文
				!CBB_add_asn1(&plaintext_wrap, &plaintext, CBS_ASN1_OCTETSTRING) ||                                     // 原文
				!CBB_add_bytes(&plaintext, pbDataIn, ulDataInLen)) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}

		// See https://tools.ietf.org/html/rfc2315#section-9.1
		if (!CBB_add_asn1(&seq, &certificates, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||     // 证书
			!CBB_add_bytes(&certificates, (uint8_t *)pbCert, ulCertLen) ||                                  // 证书 
			!CBB_flush(&seq)) {
			return 0;
		}

		// signerInfos
		if (!CBB_add_asn1(&seq, &signerInfos, CBS_ASN1_SET) ||
			!CBB_add_asn1(&signerInfos, &signerInfo, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&signerInfo, &version_bytes1, CBS_ASN1_INTEGER) ||
			!CBB_add_u8(&version_bytes1, 1)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		len = i2d_X509_NAME(issue_name, NULL);

		if (len < 0 || !CBB_add_space(&signerInfo, &buf, len) ||
			i2d_X509_NAME(issue_name, &buf) < 0 ||
			CBB_flush(&signerInfo)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		// 序列号
		serial_number = X509_get_serialNumber(x509);
		len = i2d_ASN1_INTEGER(serial_number, NULL);
		if (len < 0 || !CBB_add_space(&signerInfo, &buf, len) ||
			i2d_ASN1_INTEGER(serial_number, &buf) < 0 ||
			CBB_flush(&signerInfo)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		if (!CBB_add_asn1(&signerInfo, &digests1, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&digests1, &digest1, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&digest1, kHashData, kHashLen) ||            //添加HASH算法
			!CBB_add_asn1(&digests1, &null_asn1, CBS_ASN1_NULL)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (
			!CBB_add_asn1(&signerInfo, &encrypt_digests, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&encrypt_digests, &encrypt_digest, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&encrypt_digest, kEncData, kEncLen) ||         //添加非对称算法
			!CBB_add_asn1(&encrypt_digests, &null_asn1, CBS_ASN1_NULL)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		if (!CBB_add_asn1(&signerInfo, &signature, CBS_ASN1_OCTETSTRING) ||
			!CBB_add_bytes(&signature, (uint8_t *)data_info_value, data_info_len)       //添加签名值
			) // 签名值
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		// end
		if (!CBB_flush(&out))
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (NULL == pbDataOut)
		{
			*pulDataOutLen = CBB_len(&out);
			ulResult = SOR_OK;
		}
		else if (CBB_len(&out) >  *pulDataOutLen)
		{
			*pulDataOutLen = CBB_len(&out);
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulDataOutLen = CBB_len(&out);
			CBB_finish(&out, &pbDataOut, pulDataOutLen);
			ulResult = SOR_OK;
		}

	end:

		if (hHash)
		{
			ckpFunctions->SKF_CloseHandle(hHash);
		}

		if (x509)
		{
			X509_free(x509);
		}

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	
	extern "C" int CBS_asn1_ber_to_der(CBS *in, uint8_t **out, size_t *out_len);

	ULONG CALL_CONVENTION SOF_VerifySignedMessage(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG ulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		CBS pkcs7;
		RSA *rsa = NULL;

		BYTE pbCert[1024 * 4];
		ULONG ulCertLen = sizeof(pbCert);

		CertificateItemParse certParse;

		HANDLE hHash = 0;

		RSAPUBLICKEYBLOB rsaPublicKeyBlob = { 0 };
		ECCPUBLICKEYBLOB eccPublicKeyBlob = { 0 };
		BYTE hash_value[1024] = { 0 };
		ULONG hash_len = sizeof(hash_value);

		CBS signed_data, certificates;
		uint8_t *der_bytes = NULL;
		STACK_OF(X509) * out_certs = sk_X509_new_null();

		const size_t initial_certs_len = sk_X509_num(out_certs);
		size_t der_len;
		CBS in, content_info, content_type, wrapped_signed_data, digests, digest, content, content_type1, digests_set, wrapped_plain_text, plain_text, signerInfos, signerInfo, signature;
		uint64_t version;

		int hashAlg = 0;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		CBS_init(&pkcs7, pbDataOut, ulDataOutLen);

		der_bytes = NULL;

		if (!CBS_asn1_ber_to_der(&pkcs7, &der_bytes, &der_len)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		if (der_bytes != NULL) {
			CBS_init(&in, der_bytes, der_len);
		}
		else {
			CBS_init(&in, CBS_data(&pkcs7), CBS_len(&pkcs7));
		}

		/* See https://tools.ietf.org/html/rfc2315#section-7 */
		if (!CBS_get_asn1(&in, &content_info, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&content_info, &content_type, CBS_ASN1_OBJECT)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		//if (OBJ_cbs2nid(&content_type) != NID_pkcs7_signed) {
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		/* See https://tools.ietf.org/html/rfc2315#section-9.1 */
		if (!CBS_get_asn1(&content_info, &wrapped_signed_data,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
			!CBS_get_asn1(&wrapped_signed_data, &signed_data, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1_uint64(&signed_data, &version) ||
			!CBS_get_asn1(&signed_data, &digests_set, CBS_ASN1_SET) ||
			!CBS_get_asn1(&signed_data, &content, CBS_ASN1_SEQUENCE)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBS_get_asn1(&signed_data, &signerInfos, CBS_ASN1_SET)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		
		if (!CBS_get_asn1(&signerInfos, &signerInfo, CBS_ASN1_SEQUENCE) || 
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_INTEGER) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, &signature, CBS_ASN1_OCTETSTRING)
			) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		if (!CBS_get_asn1(&digests_set, &digests, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&digests, &digest, CBS_ASN1_OBJECT)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		else
		{
			if (0 == memcmp(CBS_data(&digest), kDataSM3, sizeof(kDataSM3)))
			{
				hashAlg = SGD_SM3;
			}
			else if (0 == memcmp(CBS_data(&digest), kDataSHA1, sizeof(kDataSHA1)))
			{
				hashAlg = SGD_SHA1;
			}
			else if (0 == memcmp(CBS_data(&digest), kDataSHA256, sizeof(kDataSHA256)))
			{
				hashAlg = SGD_SHA256;
			}
			else
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}


		if (!CBS_get_asn1( &content, &content_type1, CBS_ASN1_OBJECT) 
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBS_get_asn1(&content, &wrapped_plain_text, CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC) ||
			!CBS_get_asn1(&wrapped_plain_text, &plain_text, CBS_ASN1_OCTETSTRING) || 
			CBS_len(&plain_text) < 0)
		{
			// 无明文
		}
		else
		{
			pbDataIn = (unsigned char *)CBS_data(&plain_text);
			ulDataInLen = CBS_len(&plain_text);
		}


		if (version < 1) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* See https://tools.ietf.org/html/rfc2315#section-9.1 */
		if (!CBS_get_asn1(&signed_data, &certificates,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		while (CBS_len(&certificates) > 0) {
			CBS cert;
			X509 *x509;
			const uint8_t *inp;

			if (!CBS_get_asn1_element(&certificates, &cert, CBS_ASN1_SEQUENCE)) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (CBS_len(&cert) > LONG_MAX) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
			inp = CBS_data(&cert);
			x509 = d2i_X509(NULL, &inp, (long)CBS_len(&cert));
			if (!x509) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			assert(inp == CBS_data(&cert) + CBS_len(&cert));

			memcpy(pbCert, CBS_data(&cert), CBS_len(&cert));
			ulCertLen = CBS_len(&cert);

			if (sk_X509_push(out_certs, x509) == 0) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg)
		{
			X509 * x509 = NULL;
			unsigned char pbModulus[256];
			int ulModulusLen = 0;
			const unsigned char *ptr = NULL;
			ptr = pbCert;

			x509 = d2i_X509(NULL, &ptr, ulCertLen);

			if (x509)
			{
				RSA *rsa = EVP_PKEY_get1_RSA(X509_get_pubkey(x509));

				if (rsa != NULL)
				{
					ulModulusLen = BN_bn2bin(rsa->n, pbModulus);
				}

				rsaPublicKeyBlob.BitLen = ulModulusLen * 8;

				memcpy(rsaPublicKeyBlob.PublicExponent, "\x00\x01\x00\x01", 4);

				memcpy(rsaPublicKeyBlob.Modulus + 256 - ulModulusLen, pbModulus, ulModulusLen);
				X509_free(x509);
			}

			ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, hashAlg, 0, 0, 0, &hHash);
			
			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_RSAVerify(global_data.hDevHandle, &rsaPublicKeyBlob, hash_value, hash_len, (BYTE *)CBS_data(&signature), CBS_len(&signature));
		}
		else if (ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
		{
			unsigned char tmp_data[32 * 2 + 1] = { 0 };
			unsigned int tmp_len = 65;

			ECCSIGNATUREBLOB blob = { 0 };

			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(pbCert, ulCertLen, tmp_data, &tmp_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, tmp_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, tmp_data + 1 + 32, 32);


			ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, &eccPublicKeyBlob, (unsigned char *)"1234567812345678", 16, &hHash);
			if (ulResult)
			{
				goto end;
			}

			ulResult = ckpFunctions->SKF_Digest(hHash, pbDataIn, ulDataInLen, hash_value, &hash_len);
			if (ulResult)
			{
				goto end;
			}

			ulResult = SM2SignD2i((BYTE *)CBS_data(&signature), CBS_len(&signature), tmp_data, (int *)&tmp_len);
			if (ulResult)
			{
				ulResult = SOR_INDATAERR;
				goto end;
			}

			memcpy(blob.r + 32, tmp_data, 32);
			memcpy(blob.s + 32, tmp_data + 32, 32);

			ulResult = ckpFunctions->SKF_ECCVerify(global_data.hDevHandle, &eccPublicKeyBlob, hash_value, hash_len, &blob);
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}
end:

		if (der_bytes) {
			OPENSSL_free(der_bytes);
		}

		while (sk_X509_num(out_certs) != initial_certs_len) {
			X509 *x509 = sk_X509_pop(out_certs);
			X509_free(x509);
		}

		if (hHash)
		{
			ckpFunctions->SKF_CloseHandle(hHash);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_GetInfoFromSignedMessage(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_SignDataXML(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG CALL_CONVENTION SOF_VerifySignedDataXML(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG CALL_CONVENTION SOF_GetXMLSignatureInfo(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_GenRandom(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		ULONG ulResult = SOR_OK;
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GenRandom(global_data.hDevHandle, pbDataIn, ulDataInLen);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetLastError(void * p_ckpFunctions)
	{
		ULONG ulResult = SOR_OK;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		ulResult = global_data.last_error;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_FinalizeLibraryNative(CK_SKF_FUNCTION_LIST_PTR p_ckpFunctions) {
		ULONG ulResult = SOR_OK;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		if (p_ckpFunctions) {
			// add code here

			if (global_data.hAppHandle)
			{
				p_ckpFunctions->SKF_CloseApplication(global_data.hAppHandle);
				global_data.hAppHandle = 0;
			}

			if (global_data.hDevHandle)
			{
				p_ckpFunctions->SKF_DisConnectDev(global_data.hDevHandle);
				global_data.hDevHandle = 0;
			}

			MYFreeLibrary(p_ckpFunctions->hHandle);
			p_ckpFunctions->hHandle = NULL;

			delete (p_ckpFunctions);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_InitializeLibraryNative(char *pSKFLibraryPath, CK_SKF_FUNCTION_LIST_PTR *pp_ckpFunctions) {
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = new CK_SKF_FUNCTION_LIST;

		void * hHandle = NULL;
		ULONG ulResult = 0;
		char buffer_devs[1024] = { 0 };
		ULONG buffer_devs_len = sizeof(buffer_devs);
		char buffer_apps[1024] = { 0 };
		ULONG buffer_apps_len = sizeof(buffer_apps);

		int mult_string_count = 10;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		
		hHandle = MYLoadLibrary(pSKFLibraryPath);
		if (NULL == hHandle) {
			ulResult = SOR_LOADPROVIDERERR;
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

		ckpFunctions->SKF_ECCDecrypt = (CK_SKF_ECCDecrypt)MYGetProcAddress(hHandle,
			"SKF_ECCDecrypt");

		ckpFunctions->SKF_RSAPriKeyOperation = (CK_SKF_RSAPriKeyOperation)MYGetProcAddress(hHandle,
			"SKF_RSAPriKeyOperation");

		*pp_ckpFunctions = ckpFunctions;

		ulResult = ckpFunctions->SKF_EnumDev(TRUE, buffer_devs, &buffer_devs_len);
		if (ulResult)
		{
			goto end;
		}

		CAPI_GetMulStringCount( buffer_devs, &mult_string_count);
		if (mult_string_count < 1)
		{
			ulResult = SOR_LOADPROVIDERERR;
			goto end;
		}

		ulResult = ckpFunctions->SKF_ConnectDev(buffer_devs, &global_data.hDevHandle);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_EnumApplication(global_data.hDevHandle, buffer_apps, &buffer_apps_len);
		if (ulResult)
		{
			goto end;
		}

		CAPI_GetMulStringCount(buffer_apps, &mult_string_count);
		if (mult_string_count < 1)
		{
			ulResult = SOR_LOADPROVIDERERR;
			goto end;
		}

		ulResult = ckpFunctions->SKF_OpenApplication(global_data.hDevHandle, buffer_apps, &global_data.hAppHandle);
		if (ulResult)
		{
			goto end;
		}
	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		return ulResult;
	}

#ifdef __cplusplus
}
#endif
