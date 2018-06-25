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

#include <libxml/parser.h>



#include <xmlsec/templates.h>
#include <xmlsec/app.h>
#include <xmlsec/xmldsig.h>

#include <xmlsec/keysdata.h>
#include <xmlsec/xmltree.h>

#include <modp_b64.h>

#include <algorithm>

std::wstring CharToWchar(const char* c, size_t m_encode = CP_ACP)
{
	std::wstring str;
	int len = MultiByteToWideChar(m_encode, 0, c, strlen(c), NULL, 0);
	wchar_t*    m_wchar = new wchar_t[len + 1];
	MultiByteToWideChar(m_encode, 0, c, strlen(c), m_wchar, len);
	m_wchar[len] = '\0';
	str = m_wchar;
	delete m_wchar;
	return str;
}

std::string WcharToChar(const wchar_t* wp, size_t m_encode = CP_ACP)
{
	std::string str;
	int len = WideCharToMultiByte(m_encode, 0, wp, wcslen(wp), NULL, 0, NULL, NULL);
	char    *m_char = new char[len + 1];
	WideCharToMultiByte(m_encode, 0, wp, wcslen(wp), m_char, len, NULL, NULL);
	m_char[len] = '\0';
	str = m_char;
	delete m_char;
	return str;
}


extern "C" int CBS_asn1_ber_to_der(CBS *in, uint8_t **out, size_t *out_len);

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
static const uint8_t kPKCS7EnvelopedDataSM2[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x06, 0x01, 0x04, 0x02, 0x03 };

// 1.2.156.10197.1.401
static const uint8_t kDataSM3[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x01, 0x83, 0x11 };

// 1.2.156.10197.1.301.1
static const uint8_t kDataSM2Sign[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x01, 0x82, 0x2d, 0x01 };

// 2.16.840.1.101.3.4.2.1 
static const uint8_t kDataSHA256[] = { 0x60, 0x86 , 0x48 , 0x01 , 0x65 , 0x03, 0x04, 0x02, 0x01 };
// 1.3.14.3.2.26
static const uint8_t kDataSHA1[] = { 0x2B, 0x0E , 0x03 , 0x02 , 0x1A };

// 1.2.840.113549.1.1.1
static const uint8_t kDataRSASign[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,0x01, 0x01,0x01 };

// 1.2.840.113549.1.1.7
static const uint8_t kDataRSAEncrypt[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,0x01, 0x01,0x07 };

// 1.2.156.10197.1.301.3
static const uint8_t kDataSM2Encrypt[] = { 0x2a , 0x81 , 0x1c , 0xcf , 0x55 , 0x01, 0x82, 0x2d, 0x03 };


// 1.2.156.10197.1.102.1
static const uint8_t kDataSM1_ECB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x01 };
// 1.2.156.10197.1.102.2
static const uint8_t kDataSM1_CBC[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x02 };
// 1.2.156.10197.1.102.4
static const uint8_t kDataSM1_CFB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x04 };
// 1.2.156.10197.1.102.3
static const uint8_t kDataSM1_OFB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x66, 0x03 };
// 1.2.156.10197.1.103.1
static const uint8_t kDataSSF33_ECB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x01 };
// 1.2.156.10197.1.103.2
static const uint8_t kDataSSF33_CBC[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x02 };
// 1.2.156.10197.1.103.4
static const uint8_t kDataSSF33_CFB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x04 };
// 1.2.156.10197.1.103.3
static const uint8_t kDataSSF33_OFB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x67, 0x03 };
// 1.2.156.10197.1.104.1
static const uint8_t kDataSMS4_ECB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x01 };
// 1.2.156.10197.1.104.2
static const uint8_t kDataSMS4_CBC[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x02 };
// 1.2.156.10197.1.104.4
static const uint8_t kDataSMS4_CFB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x04 };
// 1.2.156.10197.1.104.3
static const uint8_t kDataSMS4_OFB[] = { 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x68, 0x03 };


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
		void * p_ckpFunctions;
		char * p_contanier;

		BYTE * p_pbCert;
		ULONG ulCertLen;

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
		if (errCode >= SOR_UNKNOWNERR && errCode <= SOR_APPNOTFOUND)
		{
			//return errCode;
		}
		else
		{
			switch (errCode)
			{
			case SAR_FAIL:
			case SAR_UNKNOWNERR:
			case SAR_INVALIDHANDLEERR:
			case SAR_BUFFER_TOO_SMALL:
			case SAR_NOT_EVENTERR:
			case SAR_DEVICE_REMOVED:
			case SAR_PIN_INCORRECT:
			case SAR_PIN_LOCKED:
			case SAR_PIN_INVALID:
			case SAR_APPLICATION_EXISTS:
			case SAR_NO_ROOM:
			case SAR_REACH_MAX_CONTAINER_COUNT:
				errCode = SOR_UNKNOWNERR;
				break;
			case SAR_NOTSUPPORTYETERR:
				errCode = SOR_NOTSUPPORTYETERR;
				break;
			case SAR_FILEERR:
			case SAR_READFILEERR:
			case SAR_WRITEFILEERR:
			case SAR_FILE_ALREADY_EXIST:
			case SAR_FILE_NOT_EXIST:
				errCode = SOR_FILEERR;
				break;
			case SAR_INVALIDPARAMERR:
			case SAR_PIN_LEN_RANGE:
			case SAR_USER_TYPE_INVALID:
				errCode = SOR_PARAMETERNOTSUPPORTEERR;
				break;
			case SAR_NAMELENERR:
				errCode = SOR_NAMELENERR;
				break;
			case SAR_KEYUSAGEERR:
				errCode = SOR_KEYUSAGEERR;
				break;

			case SAR_MODULUSLENERR:
				errCode = SOR_MODULUSLENERR;
				break;
			case SAR_NOTINITIALIZEERR:
			case SAR_USER_PIN_NOT_INITIALIZED:
			case SAR_USER_NOT_LOGGED_IN:
				errCode = SOR_NOTINITIALIZEERR;
				break;
			case SAR_OBJERR:
				errCode = SOR_OBJERR;
				break;
			case SAR_MEMORYERR:
				errCode = SOR_MEMORYERR;
				break;
			case SAR_TIMEOUTERR:
				errCode = SOR_TIMEOUTERR;
				break;
			case SAR_INDATALENERR:
				errCode = SOR_INDATALENERR;
				break;
			case SAR_INDATAERR:
				errCode = SOR_INDATAERR;
				break;
			case SAR_GENRANDERR:
				errCode = SOR_GENRANDERR;
				break;
			case SAR_HASHOBJERR:
				errCode = SOR_HASHOBJERR;
				break;
			case SAR_HASHERR:
				errCode = SOR_HASHERR;
				break;
			case SAR_GENRSAKEYERR:
				errCode = SOR_GENRSAKEYERR;
				break;
			case SAR_RSAMODULUSLENERR:
				errCode = SOR_RSAMODULUSLENERR;
				break;
			case SAR_CSPIMPRTPUBKEYERR:
				errCode = SOR_CSPIMPORTPUBKEYERR;
				break;
			case SAR_RSAENCERR:
				errCode = SOR_RSAENCERR;
				break;
			case SAR_RSADECERR:
				errCode = SOR_RSADECERR;
				break;
			case SAR_HASHNOTEQUALERR:
				errCode = SOR_HASHNOTEQUALERR;
				break;
			case SAR_KEYNOTFOUNTERR:
				errCode = SOR_KEYNOTFOUNDERR;
				break;
			case SAR_CERTNOTFOUNTERR:
				errCode = SOR_CERTNOTFOUNTERR;
				break;
			case SAR_NOTEXPORTERR:
				errCode = SOR_NOTEXPORTERR;
				break;
			case SAR_DECRYPTPADERR:
				errCode = SOR_DECRYPTPADERR;
				break;
			case SAR_MACLENERR:
				errCode = SOR_MACLENERR;
				break;
			case SAR_KEYINFOTYPEERR:
				errCode = SOR_KEYINFOTYPEERR;
				break;

			case SAR_USER_ALREADY_LOGGED_IN:
				errCode = SOR_OK;
				break;
			case SAR_APPLICATION_NAME_INVALID:
			case SAR_APPLICATION_NOT_EXISTS:
				errCode = SOR_APPNOTFOUND;
				break;
			default:
				errCode = errCode;
				break;
			}
		}
		global_data.last_error = errCode;

		FILE_LOG_FMT(file_log_name, "%s %d errCode = %d", __FUNCTION__, __LINE__, errCode);

		return errCode;
	}


	ULONG CALL_CONVENTION SOF_GetVersion(void * p_ckpFunctions, VERSION *pVersion)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;
		DEVINFO devinfo;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GetDevInfo(global_data.hDevHandle, &devinfo);
		FILE_LOG_FMT(file_log_name, "SKF_GetDevInfo ulResult: %d", ulResult);
		if (ulResult)
		{
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%d.%d", devinfo.Version.major, devinfo.Version.minor);

		memcpy(pVersion, &(devinfo.Version), sizeof(VERSION));

	end:
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_SetSignMethod(void * p_ckpFunctions, ULONG ulMethod)
	{
		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		global_data.sign_method = ulMethod;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_GetSignMethod(void * p_ckpFunctions, ULONG *pulMethod)
	{
		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulMethod = global_data.sign_method;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_SetEncryptMethod(void * p_ckpFunctions, ULONG ulMethod)
	{
		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		global_data.encrypt_method = ulMethod;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG CALL_CONVENTION SOF_GetEncryptMethod(void * p_ckpFunctions, ULONG *pulMethod)
	{
		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulMethod = global_data.encrypt_method;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
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

		unsigned char buffer_cert[1024 * 4] = { 0 };
		ULONG buffer_cert_len = sizeof(buffer_cert);

		int data_info_len = sizeof(data_info_value);

		HANDLE hContainer = NULL;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_EnumContainer(global_data.hAppHandle, buffer_containers, &buffer_containers_len);
		if (ulResult)
		{
			goto end;
		}

		for (ptr = buffer_containers; *ptr != 0 && (ptr < buffer_containers + buffer_containers_len); )
		{
			ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, ptr, &hContainer);
			if (ulResult)
			{
				goto end;
			}


			buffer_cert_len = sizeof(buffer_cert);

			ulResult = ckpFunctions->SKF_ExportCertificate(hContainer, TRUE, buffer_cert, &buffer_cert_len);
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

			strUserList.append(strstr(data_info_value, "=") == NULL ? "" : strstr(data_info_value, "=") + 1);
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
		else if (strUserList.size() > *pulUserListLen)
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
		FILE_LOG_FMT(file_log_name, "UserList: %s", strUserList.c_str());

	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_ExportUserCert(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		ULONG ulCertLen;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult != SAR_OK)
		{
			goto end;
		}

		ulCertLen = *pulCertLen;
		ulResult = ckpFunctions->SKF_ExportCertificate(hContainer, TRUE, pbCert, &ulCertLen);
		if (ulResult == SAR_CERTNOTFOUNTERR)
		{
			ulCertLen = *pulCertLen;
			ulResult = ckpFunctions->SKF_ExportCertificate(hContainer, FALSE, pbCert, &ulCertLen);
		}
		if (ulResult)
		{
			if (ulResult == SAR_BUFFER_TOO_SMALL)
				*pulCertLen = ulCertLen;
			goto end;
		}
		*pulCertLen = ulCertLen;

		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);


		ulResult = ckpFunctions->SKF_CloseContainer(hContainer);
		hContainer = 0;
	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_Login(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPIN)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_VerifyPIN(global_data.hAppHandle, USER_TYPE, pPIN, &global_data.retry);
		if (ulResult)
		{
			goto end;
		}

	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetPinRetryCount(void * p_ckpFunctions, LPSTR pContainerName, ULONG *pulRetryCount)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		ULONG ulResult = SOR_OK;
		ULONG ulMaxRetryCount, ulRemainRetryCount;
		BOOL bDefaultPin;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		//		*pulRetryCount = global_data.retry;
		ulResult = ckpFunctions->SKF_GetPINInfo(global_data.hAppHandle, USER_TYPE, &ulMaxRetryCount, &ulRemainRetryCount, &bDefaultPin);
		if (ulResult)
		{
			goto end;
		}
		*pulRetryCount = ulRemainRetryCount;

	end:
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_ChangePassWd(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPINOld, LPSTR pPINNew)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_ChangePIN(global_data.hAppHandle, USER_TYPE, pPINOld, pPINNew, &global_data.retry);
		if (ulResult)
		{
			goto end;
		}

	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_ExportExChangeUserCert(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetCertInfo(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, UINT16 u16Type, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		ULONG ulResult = 0;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_NUMBER(file_log_name, u16Type);
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);

		CertificateItemParse certParse;

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
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
			memcpy(data_info_value + certParse.m_strNotBefore.size() + 1, certParse.m_strNotAfter.c_str(), certParse.m_strNotAfter.size());
			data_info_len = certParse.m_strNotBefore.size() + 1 + certParse.m_strNotAfter.size();
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
		case  160://证书算法标识
		{
			memcpy(data_info_value, certParse.m_strOID.c_str(), certParse.m_strOID.size());
			data_info_len = certParse.m_strOID.size();
		}
		break;
		case  54://证书有效期截止日期(是否有格式)
		{
			memcpy(data_info_value, certParse.m_strNotAfter.c_str(), certParse.m_strNotAfter.size());
			data_info_len = certParse.m_strNotAfter.size();
		}
		break;
		case  53: //证书有效期起始日期(是否有格式):
		{
			memcpy(data_info_value, certParse.m_strNotBefore.c_str(), certParse.m_strNotBefore.size());
			data_info_len = certParse.m_strNotBefore.size();
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
		else if (data_info_len > *pulInfoLen)
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
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_GetCertInfoByOid(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pOidString, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);
		FILE_LOG_FMT(file_log_name, "pOidString: %s", pOidString);

		unsigned char buf[256] = { 0 };
		char szTmp[5] = { 0 };
		int len = 0;
		int ext_count;
		int k;
		BIO *bio = NULL;
		char *pszUserID = pOidString;//(char*)"2.16.840.1.113732.2";		

		const unsigned char *p = NULL;
		X509 *pX509 = NULL;

		p = pbCert;
		pX509 = d2i_X509(NULL, &p, ulCertLen);
		if (NULL == pX509)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		ext_count = X509_get_ext_count(pX509);
		FILE_LOG_FMT(file_log_name, "ext_count: %d", ext_count);
		for (k = 0; k < ext_count; k++)
		{
			X509_EXTENSION* ex = X509_get_ext(pX509, k);
			if (ex == NULL)
				continue;
			memset(buf, 0, sizeof(buf));
			OBJ_obj2txt((char *)buf, sizeof(buf), ex->object, 0);

			FILE_LOG_FMT(file_log_name, "ext name: %s", (char*)buf);

			if (0 == memcmp(buf, pszUserID, strlen(pszUserID))) {
				bio = BIO_new(BIO_s_mem());
				if (!X509V3_EXT_print(bio, ex, 0, 0)) // read the text of this      extention
					M_ASN1_OCTET_STRING_print(bio, ex->value);

				memset(buf, 0, sizeof(buf));
				len = BIO_read(bio, buf, sizeof(buf));// here buffer contain          the text, len the lenght of it.
				buf[len] = '\0'; // add the eot sign, buffer contain a readable text.
				BIO_free(bio);

				memset(pbInfo, 0x00, *pulInfoLen);
				memcpy(pbInfo, buf + 2, buf[1]);
				*pulInfoLen = buf[1];

				break;
			}
		}
		if (k == ext_count)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
	end:
		if (NULL != pX509)
			X509_free(pX509);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetDeviceInfo(void * p_ckpFunctions, LPSTR pContainerName, ULONG ulType, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		ULONG ulResult = 0;
		DEVINFO devinfo;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GetDevInfo(global_data.hDevHandle, &devinfo);
		if (ulResult)
		{
			goto end;
		}

		switch (ulType)
		{
		case SGD_DEVICE_SORT: // 设备类别：密码机、密码卡、智能密码钥匙等
		{
			sprintf(data_info_value, "%08x", 0x04000000); // SGD_DEVICE_SORT_SM(0x04000000)
			data_info_len = strlen(data_info_value); //strlen("crypto card")
		}
		break;
		case SGD_DEVICE_TYPE: // 设备型号
		{
			memcpy(data_info_value, "null", strlen("null"));
			data_info_len = strlen("null");
		}
		break;
		case SGD_DEVICE_DESCRIPTION: // 设备描述
		case SGD_DEVICE_NAME: // 设备名称
		{
			memcpy(data_info_value, devinfo.Label, strlen((const char *)devinfo.Label));
			data_info_len = strlen((const char *)devinfo.Label);
		}
		break;
		case SGD_DEVICE_MANUFACTURER:// 设备厂商
		{
			memcpy(data_info_value, devinfo.Manufacturer, strlen((const char *)devinfo.Manufacturer));
			data_info_len = strlen((const char *)devinfo.Manufacturer);
		}
		break;
		case SGD_DEVICE_HARDWARE_VERSION: // 硬件版本
		{
			sprintf(data_info_value, "%d.%d", devinfo.HWVersion.major, devinfo.HWVersion.minor);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SOFTWARE_VERSION: // 软件版本
		{
			sprintf(data_info_value, "%d.%d", devinfo.FirmwareVersion.major, devinfo.FirmwareVersion.minor);
			data_info_len = strlen(data_info_value);
		}
		break;

		case SGD_DEVICE_STANDARD_VERSION: // 符合标准版本
		{
			sprintf(data_info_value, "%d.%d", devinfo.Version.major, devinfo.Version.minor);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SERIAL_NUMBER: // 序列号
		{
			memcpy(data_info_value, devinfo.SerialNumber, strlen((const char *)devinfo.SerialNumber));
			data_info_len = strlen((const char *)devinfo.SerialNumber);
		}
		break;
		case SGD_DEVICE_SUPPORT_ALG_ASYM: // 支持的非对称算法
		{
			sprintf(data_info_value, "%08x", devinfo.AlgAsymCap);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_ALG_SYM: // 支持的对称算法
		{
			sprintf(data_info_value, "%08x", devinfo.AlgSymCap);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_HASH_ALG: // 支持的哈希算法
		{
			sprintf(data_info_value, "%08x", devinfo.AlgHashCap);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_STORAGE_SPACE: // 最大空间
		{
			sprintf(data_info_value, "%08x", devinfo.TotalSpace);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_SUPPORT_FREE_SPACE: // 剩余空间
		{
			sprintf(data_info_value, "%08x", devinfo.FreeSpace);
			data_info_len = strlen(data_info_value);
		}
		break;

		case SGD_DEVICE_MANAGER_INFO:// 设备管理者信息
		{
			sprintf(data_info_value, "%s", devinfo.Issuer);
			data_info_len = strlen(data_info_value);
		}
		break;
		case SGD_DEVICE_MAX_DATA_SIZE: // 一次处理最大数据量
		{
			sprintf(data_info_value, "%08x", 2000);//devinfo.TotalSpace);
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
		else if (data_info_len > *pulInfoLen)
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
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	//????? SM2证书
	ULONG CALL_CONVENTION SOF_ValidateCert(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, ULONG *pulValidate)
	{
		ULONG ulResult = 0;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s", "Cert:");
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);

		CertificateItemParse certParse;

		*pulValidate = -6;

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg || ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
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
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
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


		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "ContainerName: %s", pContainerName);
		FILE_LOG_FMT(file_log_name, "%s", "DataIn: ");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%s", "Open container ok");

		//1表示为RSA容器，为2表示为ECC容器
		ulResult = ckpFunctions->SKF_GetContainerType(hContainer, &ulContainerType);
		if (ulResult)
		{
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "ContainerType: %d", ulContainerType);
		FILE_LOG_FMT(file_log_name, "sign_method: %d", global_data.sign_method);


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
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
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
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
				goto end;
			}

			ulResult = ckpFunctions->SKF_ECCSignData(hContainer, hash_value, hash_len, &blob);
			if (ulResult)
			{
				FILE_LOG_FMT(file_log_name, "SignData ulResult: %d", ulResult);
				goto end;
			}
			FILE_LOG_HEX(file_log_name, blob.r + 32, 32);
			FILE_LOG_HEX(file_log_name, blob.s + 32, 32);

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
		else if (data_info_len > *pulDataOutLen)
		{
			*pulDataOutLen = data_info_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulDataOutLen = data_info_len;
			memcpy(pbDataOut, data_info_value, data_info_len);
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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_GetContainerType(void * p_ckpFunctions, LPSTR pContainerName, ULONG *pulContainerType)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;
		ULONG ulResult = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%s", "Open container ok");

		//1表示为RSA容器，为2表示为ECC容器
		ulResult = ckpFunctions->SKF_GetContainerType(hContainer, pulContainerType);
		if (ulResult)
		{
			goto end;
		}
	end:
		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_DigestData(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;
		ULONG ulResult = 0;
		ULONG ulContainerType = 0;
		HANDLE hHash = 0;
		BYTE hash_value[1024] = { 0 };
		ULONG hash_len = sizeof(hash_value);


		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "ContainerName: %s", pContainerName);
		FILE_LOG_FMT(file_log_name, "%s", "DataIn: ");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, pContainerName, &hContainer);
		if (ulResult)
		{
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%s", "Open container ok");

		//1表示为RSA容器，为2表示为ECC容器
		ulResult = ckpFunctions->SKF_GetContainerType(hContainer, &ulContainerType);
		if (ulResult)
		{
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "ContainerType: %d", ulContainerType);
		FILE_LOG_FMT(file_log_name, "sign_method: %d", global_data.sign_method);


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
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
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
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
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
			*pulDataOutLen = hash_len;
			ulResult = SOR_OK;
		}
		else if (hash_len > *pulDataOutLen)
		{
			*pulDataOutLen = hash_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulDataOutLen = hash_len;
			memcpy(pbDataOut, hash_value, hash_len);
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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s", "Cert: ");
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);
		FILE_LOG_FMT(file_log_name, "%s", "DataIn: ");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "KeyAlg: %d", certParse.m_iKeyAlg);

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
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
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

			ECCSIGNATUREBLOB blob = { 0 };

			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(pbCert, ulCertLen, tmp_data, &tmp_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, tmp_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, tmp_data + 1 + 32, 32);

			FILE_LOG_HEX(file_log_name, eccPublicKeyBlob.XCoordinate + 32, 32);
			FILE_LOG_HEX(file_log_name, eccPublicKeyBlob.YCoordinate + 32, 32);

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

			FILE_LOG_HEX(file_log_name, pbDataOut, ulDataOutLen);
			ulResult = SM2SignD2i(pbDataOut, ulDataOutLen, tmp_data, (int *)&tmp_len);
			if (ulResult)
			{
				ulResult = SOR_INDATAERR;
				goto end;
			}

			memcpy(blob.r + 32, tmp_data, 32);
			memcpy(blob.s + 32, tmp_data + 32, 32);
			FILE_LOG_HEX(file_log_name, blob.r + 32, 32);
			FILE_LOG_HEX(file_log_name, blob.s + 32, 32);

			ulResult = ckpFunctions->SKF_ECCVerify(global_data.hDevHandle, &eccPublicKeyBlob, hash_value, hash_len, &blob);
			FILE_LOG_FMT(file_log_name, "Verify ulResult = %d", ulResult);
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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_DigestDataCert(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s", "Cert: ");
		FILE_LOG_FMT(file_log_name, "%s", "DataIn: ");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

		certParse.setCertificate(global_data.p_pbCert, global_data.ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "KeyAlg: %d", certParse.m_iKeyAlg);

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg)
		{
			X509 * x509 = NULL;
			unsigned char pbModulus[256];
			int ulModulusLen = 0;
			const unsigned char *ptr = NULL;
			ptr = global_data.p_pbCert;

			x509 = d2i_X509(NULL, &ptr, global_data.ulCertLen);

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
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
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
		}
		else if (ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
		{
			unsigned char tmp_data[32 * 2 + 1] = { 0 };
			unsigned int tmp_len = 65;

			ECCSIGNATUREBLOB blob = { 0 };

			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(global_data.p_pbCert, global_data.ulCertLen, tmp_data, &tmp_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, tmp_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, tmp_data + 1 + 32, 32);

			FILE_LOG_HEX(file_log_name, eccPublicKeyBlob.XCoordinate + 32, 32);
			FILE_LOG_HEX(file_log_name, eccPublicKeyBlob.YCoordinate + 32, 32);

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
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

		if (NULL == pbDataOut)
		{
			*pulDataOutLen = hash_len;
			ulResult = SOR_OK;
		}
		else if (hash_len > *pulDataOutLen)
		{
			*pulDataOutLen = hash_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulDataOutLen = hash_len;
			memcpy(pbDataOut, hash_value, hash_len);
			ulResult = SOR_OK;
		}

	end:

		if (hHash)
		{
			ckpFunctions->SKF_CloseHandle(hHash);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

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

		ulResult = SOF_VerifySignedData(p_ckpFunctions, pbCert, ulCertLen, (BYTE *)pbFileInData, (ULONG)ulFileInDataLen, pbDataOut, ulDataOutLen);

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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_EncryptData(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		const unsigned char *ptr = NULL;
		ASN1_INTEGER *serial_number = NULL;
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;
		X509 * x509 = NULL;
		uint8_t *buf;
		X509_NAME *issue_name = NULL;
		ULONG ulResult = 0;

		HANDLE hKey = 0;

		//BYTE sym_key_plain[1024] = { 0 };

		size_t require_len = 0;

		int len = 0;

		CBB out, outer_seq, oid, data_oid, sym_seq, sym_iv, ciphertext, wrapped_seq, seq, version_bytes, asym_oid, content_info, wrap_key, asym_alg, issue_and_sn, null_asn1, recipInfo, recipInfos, version_bytes1;

		size_t result_len = 1024 * 1024 * 1024;

		ECCCIPHERBLOB blob = { 0 };

		uint8_t *out_buf = NULL;

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		BYTE *cipher_value = NULL;
		ULONG cipher_len = 0;

		const uint8_t *kASymData = 0;
		size_t kASymLen = 0;

		const uint8_t *kPKCS7EnvelopedData = 0;
		size_t kPKCS7EnvelopedLen = 0;

		CertificateItemParse certParse;

		BLOCKCIPHERPARAM blockCipherParam = { 0 };

		RSAPUBLICKEYBLOB rsaPublicKeyBlob = { 0 };
		ECCPUBLICKEYBLOB eccPublicKeyBlob = { 0 };

		const uint8_t *kPKCS7Data = 0;
		size_t kPKCS7Len = 0;


		BYTE *wrapper_key_value = NULL;
		ULONG wrapper_key_len = 0;

		BYTE *wrapper_key_value_fmt = NULL;
		ULONG wrapper_key_len_fmt = 0;

		char buffer_containers[1024] = { 0 };
		ULONG buffer_containers_len = sizeof(buffer_containers);

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s", "DataIn:");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

		FILE_LOG_FMT(file_log_name, "%s", "Cert:");
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);

		ulResult = ckpFunctions->SKF_EnumContainer(global_data.hAppHandle, buffer_containers, &buffer_containers_len);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_OpenContainer(global_data.hAppHandle, buffer_containers, &hContainer);
		if (ulResult)
		{
			goto end;
		}

		certParse.setCertificate(pbCert, ulCertLen);

		if (0 != certParse.parse())
		{
			ulResult = SOR_INDATAERR;
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

		if (ECertificate_KEY_ALG_RSA == certParse.m_iKeyAlg)
		{
			unsigned char pbModulus[256];
			int ulModulusLen = 0;

			RSA *rsa = EVP_PKEY_get1_RSA(X509_get_pubkey(x509));

			kPKCS7EnvelopedData = kPKCS7EnvelopedDataRFC;
			kPKCS7EnvelopedLen = sizeof(kPKCS7EnvelopedDataRFC);
			kPKCS7Data = kPKCS7DataRFC;
			kPKCS7Len = sizeof(kPKCS7DataRFC);
			kASymData = kDataRSAEncrypt;
			kASymLen = sizeof(kDataRSAEncrypt);

			if (rsa != NULL)
			{
				ulModulusLen = BN_bn2bin(rsa->n, pbModulus);
			}

			rsaPublicKeyBlob.BitLen = ulModulusLen * 8;

			memcpy(rsaPublicKeyBlob.PublicExponent, "\x00\x01\x00\x01", 4);

			memcpy(rsaPublicKeyBlob.Modulus + 256 - ulModulusLen, pbModulus, ulModulusLen);

			ulResult = ckpFunctions->SKF_RSAExportSessionKey(hContainer, global_data.encrypt_method, &rsaPublicKeyBlob, wrapper_key_value, &wrapper_key_len, &hKey);
			if (ulResult && SAR_BUFFER_TOO_SMALL != ulResult)
			{
				goto end;
			}
			wrapper_key_value = new BYTE[wrapper_key_len];
			ulResult = ckpFunctions->SKF_RSAExportSessionKey(hContainer, global_data.encrypt_method, &rsaPublicKeyBlob, wrapper_key_value, &wrapper_key_len, &hKey);
			if (ulResult)
			{
				goto end;
			}
			wrapper_key_len_fmt = wrapper_key_len;
			wrapper_key_value_fmt = new BYTE[wrapper_key_len_fmt];
			memcpy(wrapper_key_value_fmt, wrapper_key_value, wrapper_key_len_fmt);
		}
		else if (ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
		{
			ECCPUBLICKEYBLOB pubkeyBlob = { 0 };
			ULONG ulBlobLen = sizeof(pubkeyBlob);

			unsigned char pk_data[32 * 2 + 1] = { 0 };
			unsigned int pk_len = 65;

			kPKCS7EnvelopedData = kPKCS7EnvelopedDataSM2;
			kPKCS7EnvelopedLen = sizeof(kPKCS7EnvelopedDataSM2);

			kPKCS7Data = kPKCS7DataSM2;
			kPKCS7Len = sizeof(kPKCS7DataSM2);

			kASymData = kDataSM2Encrypt;
			kASymLen = sizeof(kDataSM2Encrypt);

			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(pbCert, ulCertLen, pk_data, &pk_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, pk_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, pk_data + 1 + 32, 32);

			wrapper_key_value = new BYTE[32 + sizeof(ECCCIPHERBLOB)];

			memset(wrapper_key_value, 0x00, 32 + sizeof(ECCCIPHERBLOB));

			ulResult = ckpFunctions->SKF_ECCExportSessionKey(
				hContainer,
				global_data.encrypt_method,
				&eccPublicKeyBlob,
				(PECCCIPHERBLOB)wrapper_key_value,
				&hKey
			);

			if (ulResult)
			{
				goto end;
			}

			wrapper_key_len = ((PECCCIPHERBLOB)wrapper_key_value)->CipherLen + sizeof(ECCCIPHERBLOB) - 1;


			wrapper_key_len_fmt = wrapper_key_len + 1024;
			wrapper_key_value_fmt = new BYTE[wrapper_key_len_fmt];

			SM2EncryptAsn1Convert(((PECCCIPHERBLOB)wrapper_key_value)->XCoordinate + 32, 32,
				((PECCCIPHERBLOB)wrapper_key_value)->YCoordinate + 32, 32,
				((PECCCIPHERBLOB)wrapper_key_value)->HASH, 32,
				((PECCCIPHERBLOB)wrapper_key_value)->Cipher, ((PECCCIPHERBLOB)wrapper_key_value)->CipherLen,
				wrapper_key_value_fmt, (int *)&wrapper_key_len_fmt
			);
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

		if (ulResult)
		{
			goto end;
		}

		switch (global_data.encrypt_method)
		{
		case SGD_SM1_ECB:
		{
			blockCipherParam.IVLen = 0;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SM1_CBC:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SM1_CFB:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SM1_OFB:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SSF33_ECB:
		{
			blockCipherParam.IVLen = 0;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case 	SGD_SSF33_CBC:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SSF33_CFB:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SSF33_OFB:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;

		break;
		case SGD_SMS4_ECB:
		{
			blockCipherParam.IVLen = 0;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SMS4_CBC:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SMS4_CFB:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case 	SGD_SMS4_OFB:
		{
			blockCipherParam.IVLen = 16;
			memset(blockCipherParam.IV, 0, 32);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;

		default:
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}
		break;
		}

		ulResult = ckpFunctions->SKF_EncryptInit(hKey, blockCipherParam);

		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_Encrypt(hKey, pbDataIn, ulDataInLen, cipher_value, &cipher_len);

		if (ulResult)
		{
			goto end;
		}

		cipher_value = new BYTE[cipher_len];

		ulResult = ckpFunctions->SKF_Encrypt(hKey, pbDataIn, ulDataInLen, cipher_value, &cipher_len);

		if (ulResult)
		{
			goto end;
		}

		CBB_init(&out, 1024 * 1024 * 10);

		// See https://tools.ietf.org/html/rfc2315#section-7
		if (!CBB_add_asn1(&out, &outer_seq, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&outer_seq, &oid, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&oid, kPKCS7EnvelopedData, kPKCS7EnvelopedLen) ||                            // P7 类型
			!CBB_add_asn1(&outer_seq, &wrapped_seq,
				CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
			// See https://tools.ietf.org/html/rfc2315#section-9.1
			!CBB_add_asn1(&wrapped_seq, &seq, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&seq, &version_bytes, CBS_ASN1_INTEGER) ||
			!CBB_add_u8(&version_bytes, 1) ||
			!CBB_add_asn1(&seq, &recipInfos, CBS_ASN1_SET)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}



		// recipInfos
		if (
			!CBB_add_asn1(&recipInfos, &recipInfo, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&recipInfo, &version_bytes1, CBS_ASN1_INTEGER) ||
			!CBB_add_u8(&version_bytes1, 0) ||
			!CBB_add_asn1(&recipInfo, &issue_and_sn, CBS_ASN1_SEQUENCE)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		len = i2d_X509_NAME(issue_name, NULL);

		if (len < 0 || !CBB_add_space(&issue_and_sn, &buf, len) ||
			i2d_X509_NAME(issue_name, &buf) < 0
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		// 序列号
		serial_number = X509_get_serialNumber(x509);
		len = i2d_ASN1_INTEGER(serial_number, NULL);
		if (len < 0 || !CBB_add_space(&issue_and_sn, &buf, len) ||
			i2d_ASN1_INTEGER(serial_number, &buf) < 0
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		if (
			!CBB_add_asn1(&recipInfo, &asym_alg, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&asym_alg, &asym_oid, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&asym_oid, kASymData, kASymLen) ||
			!CBB_add_asn1(&asym_alg, &null_asn1, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&recipInfo, &wrap_key, CBS_ASN1_OCTETSTRING) ||
			!CBB_add_bytes(&wrap_key, wrapper_key_value_fmt, wrapper_key_len_fmt)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBB_add_asn1(&seq, &content_info, CBS_ASN1_SEQUENCE)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBB_add_asn1(&content_info, &data_oid, CBS_ASN1_OBJECT) ||
			!CBB_add_bytes(&data_oid, kPKCS7Data, kPKCS7Len) ||
			!CBB_add_asn1(&content_info, &sym_seq, CBS_ASN1_SEQUENCE)
			) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		switch (global_data.encrypt_method)
		{
		case SGD_SM1_ECB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.102.1", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SM1_CBC:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.102.2", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SM1_CFB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.102.4", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SM1_OFB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.102.3", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SSF33_ECB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.103.1", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

		}
		break;
		case 	SGD_SSF33_CBC:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.103.2", 1);
			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SSF33_CFB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.103.4", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SSF33_OFB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.103.3", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;

		break;
		case SGD_SMS4_ECB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.104.1", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

		}
		break;
		case SGD_SMS4_CBC:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.104.2", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case SGD_SMS4_CFB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.104.4", 1);
			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;
		case 	SGD_SMS4_OFB:
		{
			ASN1_OBJECT *object = OBJ_txt2obj("1.2.156.10197.1.104.3", 1);

			len = i2d_ASN1_OBJECT(object, NULL);
			if (len < 0 || !CBB_add_space(&sym_seq, &buf, len) ||
				i2d_ASN1_OBJECT(object, &buf) < 0
				)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}


			if (
				!CBB_add_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (!CBB_add_bytes(&sym_iv, blockCipherParam.IV, 16))
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		break;

		default:
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}
		break;
		}

		if (!CBB_add_asn1(&content_info, &ciphertext, CBS_ASN1_CONTEXT_SPECIFIC) ||
			!CBB_add_bytes(&ciphertext, cipher_value, cipher_len))
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

		if (!CBB_finish(&out, &out_buf, &require_len))
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "require_len: %d", require_len);

		FILE_LOG_FMT(file_log_name, "%s", "out_buf:");
		FILE_LOG_HEX(file_log_name, out_buf, require_len);


		if (NULL == pbDataOut)
		{
			*pulDataOutLen = require_len;
			ulResult = SOR_OK;
			goto end;
		}
		else if (require_len > *pulDataOutLen)
		{
			*pulDataOutLen = require_len;
			ulResult = SOR_MEMORYERR;
			goto end;
		}
		else
		{
			*pulDataOutLen = require_len;
			memcpy(pbDataOut, out_buf, require_len);
			ulResult = SOR_OK;
		}
		FILE_LOG_FMT(file_log_name, "%s", "pbDataOut:");
		FILE_LOG_HEX(file_log_name, pbDataOut, *pulDataOutLen);


	end:

		if (hKey)
		{
			ckpFunctions->SKF_CloseHandle(hKey);
		}

		if (x509)
		{
			X509_free(x509);
		}

		if (wrapper_key_value)
		{
			delete[]wrapper_key_value;
		}
		if (wrapper_key_value_fmt)
		{
			delete[]wrapper_key_value_fmt;
		}

		if (cipher_value)
		{
			delete[]cipher_value;
		}

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_DecryptData(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;
		ULONG ulResult = 0;
		ULONG ulContainerType = 0;
		CBS pkcs7;
		RSA *rsa = NULL;
		HANDLE hKey = 0;
		BLOCKCIPHERPARAM blockCipherParam = { 0 };
		uint8_t *der_bytes = NULL;
		size_t der_len;
		CBS in, content_info, content, sym_seq, sym_iv, sym_alg, content_type, oid, ciphertext, wrapped_seq, seq, wrap_key, recipInfo, recipInfos;
		uint64_t version;

		ECCCIPHERBLOB *cipherBlob = (ECCCIPHERBLOB*)malloc(sizeof(ECCCIPHERBLOB) + 1024);
		BYTE wrapper_key_value[97 + 32] = { 0 };
		int	wrapper_key_len = 97 + 32;

		ULONG ulSymAlg = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "ContainerName: %s", pContainerName);

		FILE_LOG_FMT(file_log_name, "%s", "DataIn:");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);


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

		CBS_init(&pkcs7, pbDataIn, ulDataInLen);

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
		if (!CBS_get_asn1(&content_info, &wrapped_seq,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
			!CBS_get_asn1(&wrapped_seq, &seq, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1_uint64(&seq, &version) ||
			!CBS_get_asn1(&seq, &recipInfos, CBS_ASN1_SET) ||
			!CBS_get_asn1(&seq, &content, CBS_ASN1_SEQUENCE)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBS_get_asn1(&recipInfos, &recipInfo, CBS_ASN1_SEQUENCE)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		if (
			!CBS_get_asn1(&recipInfo, NULL, CBS_ASN1_INTEGER) ||
			!CBS_get_asn1(&recipInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&recipInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&recipInfo, &wrap_key, CBS_ASN1_OCTETSTRING)
			) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (
			!CBS_get_asn1(&content, NULL, CBS_ASN1_OBJECT) ||
			!CBS_get_asn1(&content, &sym_seq, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&content, &ciphertext, CBS_ASN1_CONTEXT_SPECIFIC)
			) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBS_get_asn1(&sym_seq, &sym_alg, CBS_ASN1_OBJECT) ||
			!CBS_get_asn1(&sym_seq, &sym_iv, CBS_ASN1_OCTETSTRING)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (0 == memcmp(CBS_data(&sym_alg), kDataSM1_ECB, sizeof(kDataSM1_ECB)))
		{
			ulSymAlg = SGD_SM1_ECB;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSM1_CBC, sizeof(kDataSM1_CBC)))
		{
			ulSymAlg = SGD_SM1_CBC;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSM1_CFB, sizeof(kDataSM1_CFB)))
		{
			ulSymAlg = SGD_SM1_CFB;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSM1_OFB, sizeof(kDataSM1_OFB)))
		{
			ulSymAlg = SGD_SM1_OFB;
		}

		else if (0 == memcmp(CBS_data(&sym_alg), kDataSSF33_ECB, sizeof(kDataSSF33_ECB)))
		{
			ulSymAlg = SGD_SSF33_ECB;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSSF33_CBC, sizeof(kDataSSF33_CBC)))
		{
			ulSymAlg = SGD_SSF33_CBC;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSSF33_CFB, sizeof(kDataSSF33_CFB)))
		{
			ulSymAlg = SGD_SSF33_CFB;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSSF33_OFB, sizeof(kDataSSF33_OFB)))
		{
			ulSymAlg = SGD_SSF33_OFB;
		}

		else if (0 == memcmp(CBS_data(&sym_alg), kDataSMS4_ECB, sizeof(kDataSMS4_ECB)))
		{
			ulSymAlg = SGD_SMS4_ECB;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSMS4_CBC, sizeof(kDataSMS4_CBC)))
		{
			ulSymAlg = SGD_SMS4_CBC;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSMS4_CFB, sizeof(kDataSMS4_CFB)))
		{
			ulSymAlg = SGD_SMS4_CFB;
		}
		else if (0 == memcmp(CBS_data(&sym_alg), kDataSMS4_OFB, sizeof(kDataSMS4_OFB)))
		{
			ulSymAlg = SGD_SMS4_OFB;
		}

		else
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}


		if (ulContainerType == 1)
		{
			ulResult = ckpFunctions->SKF_ImportSessionKey(hContainer, ulSymAlg, (BYTE *)CBS_data(&wrap_key), CBS_len(&wrap_key), &hKey);

			if (ulResult)
			{
				goto end;
			}
		}
		else
		{
			SM2CryptD2i((BYTE *)CBS_data(&wrap_key), CBS_len(&wrap_key), wrapper_key_value, &wrapper_key_len);

			memset(cipherBlob, 0, sizeof(ECCCIPHERBLOB) - 1);

			cipherBlob->CipherLen = wrapper_key_len - 97;
			memcpy(cipherBlob->HASH, wrapper_key_value + wrapper_key_len - 32, 32);
			memcpy(cipherBlob->XCoordinate + 32, wrapper_key_value + 1, 32);
			memcpy(cipherBlob->YCoordinate + 32, wrapper_key_value + 32 + 1, 32);
			memcpy(cipherBlob->Cipher, wrapper_key_value + 64 + 1, wrapper_key_len - 97);

			ulResult = ckpFunctions->SKF_ImportSessionKey(hContainer, ulSymAlg, (BYTE*)cipherBlob, sizeof(ECCCIPHERBLOB) - 1 + cipherBlob->CipherLen, &hKey);

			if (ulResult)
			{
				goto end;
			}

		}



		switch (ulSymAlg)
		{
		case SGD_SM1_ECB:
		{
			blockCipherParam.IVLen = 0;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SM1_CBC:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SM1_CFB:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SM1_OFB:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SSF33_ECB:
		{
			blockCipherParam.IVLen = 0;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case 	SGD_SSF33_CBC:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SSF33_CFB:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SSF33_OFB:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;

		break;
		case SGD_SMS4_ECB:
		{
			blockCipherParam.IVLen = 0;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SMS4_CBC:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case SGD_SMS4_CFB:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;
		case 	SGD_SMS4_OFB:
		{
			blockCipherParam.IVLen = 16;
			memcpy(blockCipherParam.IV, (BYTE *)CBS_data(&sym_iv), 16);
			blockCipherParam.FeedBitLen = 0;
			blockCipherParam.PaddingType = 1;
		}
		break;

		default:
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}
		break;
		}

		ulResult = ckpFunctions->SKF_DecryptInit(hKey, blockCipherParam);
		if (ulResult)
		{
			goto end;
		}

		ulResult = ckpFunctions->SKF_Decrypt(hKey, (BYTE *)CBS_data(&ciphertext), CBS_len(&ciphertext), pbDataOut, pulDataOutLen);
		if (ulResult)
		{
			goto end;
		}

	end:

		if (der_bytes) {
			OPENSSL_free(der_bytes);
		}

		if (cipherBlob)
		{
			free(cipherBlob);
		}

		if (hKey)
		{
			ckpFunctions->SKF_CloseHandle(hKey);
		}

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_SignMessage(void * p_ckpFunctions, LPSTR pContainerName, UINT16 u16Flag, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbSignedMessage, ULONG *pulSignedMessageLen)
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

		size_t require_len = 0;

		int len = 0;

		CBB out, outer_seq, oid, wrapped_seq, seq, version_bytes, digests_set,
			content_info, plaintext, plaintext_wrap, certificates, digest_alg, issue_and_sn, digests, null_asn1, signerInfos, signerInfo, version_bytes1, digests1, digest1, encrypt_digest, encrypt_digests, signature;

		size_t result_len = 1024 * 1024 * 1024;

		ECCSIGNATUREBLOB blob = { 0 };

		uint8_t *out_buf = NULL;

		BYTE pbCert[8192];
		ULONG ulCertLen = sizeof(pbCert);

		char data_info_value[1024] = { 0 };
		int data_info_len = sizeof(data_info_value);

		BYTE hash_value[1024] = { 0 };
		ULONG hash_len = sizeof(hash_value);

		const uint8_t *kHashData = 0;
		size_t kHashLen = 0;

		const uint8_t *kPKCS7SignedData = 0;
		size_t kPKCS7SignedLen = 0;

		const uint8_t *kPKCS7Data = 0;
		size_t kPKCS7Len = 0;

		const uint8_t *kEncData = 0;
		size_t kEncLen = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "ContainerName: %s", pContainerName);
		FILE_LOG_FMT(file_log_name, "u16Flag: %d", u16Flag);
		FILE_LOG_FMT(file_log_name, "%s", "DataIn:");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

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
		FILE_LOG_FMT(file_log_name, "%s", "Cert:");
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);

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
				kEncData = kDataRSASign;
				kEncLen = sizeof(kDataRSASign);
				kHashData = kDataSM3;
				kHashLen = sizeof(kDataSM3);

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SM3, 0, 0, 0, &hHash);

			}
			else if (global_data.sign_method == SGD_SHA1_RSA)
			{
				kEncData = kDataRSASign;
				kEncLen = sizeof(kDataRSASign);
				kHashData = kDataSHA1;
				kHashLen = sizeof(kDataSHA1);

				ulResult = ckpFunctions->SKF_DigestInit(global_data.hDevHandle, SGD_SHA1, 0, 0, 0, &hHash);

			}
			else if (global_data.sign_method == SGD_SHA256_RSA)
			{
				kEncData = kDataRSASign;
				kEncLen = sizeof(kDataRSASign);
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
			ECCPUBLICKEYBLOB pubkeyBlob = { 0 };
			ULONG ulBlobLen = sizeof(pubkeyBlob);

			kPKCS7SignedData = kPKCS7SignedDataSM2;
			kPKCS7SignedLen = sizeof(kPKCS7SignedDataSM2);
			kPKCS7Data = kPKCS7DataSM2;
			kPKCS7Len = sizeof(kPKCS7DataSM2);

			if (global_data.sign_method == SGD_SM3_SM2)
			{
				kEncData = kDataSM2Sign;
				kEncLen = sizeof(kDataSM2Sign);
				kHashData = kDataSM3;
				kHashLen = sizeof(kDataSM3);

				ulResult = ckpFunctions->SKF_ExportPublicKey(hContainer, TRUE, (BYTE*)&pubkeyBlob, &ulBlobLen);
				if (ulResult)
				{
					goto end;
				}
				FILE_LOG_FMT(file_log_name, "%s", "PublicKey:");
				FILE_LOG_HEX(file_log_name, pubkeyBlob.XCoordinate + 32, 32);
				FILE_LOG_HEX(file_log_name, pubkeyBlob.YCoordinate + 32, 32);

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
			FILE_LOG_FMT(file_log_name, "%s", "SignData:");
			FILE_LOG_HEX(file_log_name, blob.r + 32, 32);
			FILE_LOG_HEX(file_log_name, blob.s + 32, 32);

			ulResult = SM2SignAsn1Convert(blob.r + 32, 32, blob.s + 32, 32, (unsigned char *)data_info_value, &data_info_len);
			if (ulResult)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
			FILE_LOG_FMT(file_log_name, "%s", "Asn1Convert:");
			FILE_LOG_HEX(file_log_name, (unsigned char *)data_info_value, data_info_len);
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

		CBB_init(&out, 1024 * 1024 * 10);

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

		if (0 == u16Flag)
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
			!CBB_add_bytes(&certificates, (uint8_t *)pbCert, ulCertLen)

			) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
			//			return 0;
		}

		// signerInfos
		if (!CBB_add_asn1(&seq, &signerInfos, CBS_ASN1_SET) ||
			!CBB_add_asn1(&signerInfos, &signerInfo, CBS_ASN1_SEQUENCE) ||
			!CBB_add_asn1(&signerInfo, &version_bytes1, CBS_ASN1_INTEGER) ||
			!CBB_add_u8(&version_bytes1, 1) ||
			!CBB_add_asn1(&signerInfo, &issue_and_sn, CBS_ASN1_SEQUENCE)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		len = i2d_X509_NAME(issue_name, NULL);

		if (len < 0 || !CBB_add_space(&issue_and_sn, &buf, len) ||
			i2d_X509_NAME(issue_name, &buf) < 0
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		// 序列号
		serial_number = X509_get_serialNumber(x509);
		len = i2d_ASN1_INTEGER(serial_number, NULL);
		if (len < 0 || !CBB_add_space(&issue_and_sn, &buf, len) ||
			i2d_ASN1_INTEGER(serial_number, &buf) < 0
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

		if (!CBB_finish(&out, &out_buf, &require_len))
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "require_len: %d", require_len);

		FILE_LOG_FMT(file_log_name, "%s", "out_buf:");
		FILE_LOG_HEX(file_log_name, out_buf, require_len);


		if (NULL == pbSignedMessage)
		{
			*pulSignedMessageLen = require_len;
			ulResult = SOR_OK;
			goto end;
		}
		else if (require_len > *pulSignedMessageLen)
		{
			*pulSignedMessageLen = require_len;
			ulResult = SOR_MEMORYERR;
			goto end;
		}
		else
		{
			*pulSignedMessageLen = require_len;
			memcpy(pbSignedMessage, out_buf, require_len);
			ulResult = SOR_OK;
		}
		FILE_LOG_FMT(file_log_name, "%s", "SignedMessage:");
		FILE_LOG_HEX(file_log_name, pbSignedMessage, *pulSignedMessageLen);


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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}



	ULONG CALL_CONVENTION SOF_VerifySignedMessage(void * p_ckpFunctions, BYTE *pbMessageData, ULONG ulMessageDataLen, BYTE *pbPlaintext, ULONG ulPlaintextLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		CBS pkcs7;
		RSA *rsa = NULL;

		BYTE pbCert[8192];
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

		BYTE *pbDataIn = NULL;
		ULONG ulDataInLen;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s", "MessageData:");
		FILE_LOG_HEX(file_log_name, pbMessageData, ulMessageDataLen);

		CBS_init(&pkcs7, pbMessageData, ulMessageDataLen);

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
			FILE_LOG_FMT(file_log_name, "%s", "Cert:");
			FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);


			if (sk_X509_push(out_certs, x509) == 0) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		FILE_LOG_FMT(file_log_name, "%s", "111");

		if (!CBS_get_asn1(&signed_data, &signerInfos, CBS_ASN1_SET)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%s", "222");

		if (!CBS_get_asn1(&signerInfos, &signerInfo, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_INTEGER) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, &signature, CBS_ASN1_OCTETSTRING)
			) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%s", "333");


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
		FILE_LOG_FMT(file_log_name, "%s", "555");


		if (!CBS_get_asn1(&content, &content_type1, CBS_ASN1_OBJECT)
			)
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
		FILE_LOG_FMT(file_log_name, "%s", "666");

		if (!CBS_get_asn1(&content, &wrapped_plain_text, CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC) ||
			!CBS_get_asn1(&wrapped_plain_text, &plain_text, CBS_ASN1_OCTETSTRING) ||
			CBS_len(&plain_text) < 0)
		{
			// 无明文
			if (pbPlaintext == NULL || ulPlaintextLen == 0)
			{
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;
				goto end;
			}
			pbDataIn = pbPlaintext;
			ulDataInLen = ulPlaintextLen;
		}
		else
		{
			pbDataIn = (unsigned char *)CBS_data(&plain_text);
			ulDataInLen = CBS_len(&plain_text);
		}
		FILE_LOG_FMT(file_log_name, "%s", "Plaintext:");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);


		if (version < 1) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_GetInfoFromSignedMessage(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbMessageData, ULONG ulMessageDataLen, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		ULONG ulResult = 0;
		CBS pkcs7;
		BYTE pbCert[1024 * 4];
		ULONG ulCertLen = sizeof(pbCert);
		CBS signed_data, certificates;
		uint8_t *der_bytes = NULL;
		STACK_OF(X509) * out_certs = sk_X509_new_null();

		unsigned char *data_info_value = NULL;
		int data_info_len = 0;

		const size_t initial_certs_len = sk_X509_num(out_certs);
		size_t der_len;
		CBS in, content_info, content_type, wrapped_signed_data, digests, digest, content, content_type1, digests_set, wrapped_plain_text, plain_text, signerInfos, signerInfo, signature;
		uint64_t version;

		int hashAlg = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		CBS_init(&pkcs7, pbMessageData, ulMessageDataLen);

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

		if (!CBS_get_asn1(&signed_data, &signerInfos, CBS_ASN1_SET)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (!CBS_get_asn1(&signerInfos, &signerInfo, CBS_ASN1_SEQUENCE) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_INTEGER) ||
			!CBS_get_asn1(&signerInfo, NULL, CBS_ASN1_SEQUENCE) ||
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


		if (!CBS_get_asn1(&content, &content_type1, CBS_ASN1_OBJECT)
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
			if (u16Type == 1)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
		}
		else
		{

		}

		if (version < 1) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (u16Type == 1) // plain
		{
			data_info_value = (unsigned char *)CBS_data(&plain_text);
			data_info_len = CBS_len(&plain_text);
		}
		else if (u16Type == 2) // cert
		{
			data_info_value = pbCert;
			data_info_len = ulCertLen;
		}
		else if (u16Type == 3) // signature
		{
			data_info_value = (BYTE *)CBS_data(&signature);
			data_info_len = CBS_len(&signature);
		}
		else
		{
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (NULL == pbInfo)
		{
			*pulInfoLen = data_info_len;
			ulResult = SOR_OK;
		}
		else if (data_info_len > *pulInfoLen)
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

		if (der_bytes) {
			OPENSSL_free(der_bytes);
		}

		while (sk_X509_num(out_certs) != initial_certs_len) {
			X509 *x509 = sk_X509_pop(out_certs);
			X509_free(x509);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	int cb_digest_simple(void *args, unsigned char *in, int in_len, unsigned char *out, int *out_len)
	{
		FILE_WRITE("D:/digest_ori.o", "", in, in_len);

		return SOF_DigestData(global_data.p_ckpFunctions, global_data.p_contanier, in, in_len, out, (ULONG *)out_len);
	}

	int cb_sign_simple(void *args, unsigned char *in, int in_len, unsigned char *out, int *out_len)
	{
		FILE_WRITE("D:/sign_ori.o", "", in, in_len);

		return SOF_SignData(global_data.p_ckpFunctions, global_data.p_contanier, in, in_len, out, (ULONG *)out_len);
	}

	int cb_digest_vfy(void *args, unsigned char *in, int in_len, unsigned char *out, int *out_len)
	{
		FILE_WRITE("D:/digest_ori.o", "", in, in_len);

		return SOF_DigestDataCert(global_data.p_ckpFunctions, in, in_len, out, (ULONG *)out_len);
	}

	int cb_sign_vfy(void *args, unsigned char *in, int in_len, unsigned char *out, int *out_len)
	{
		FILE_WRITE("D:/sign_ori.o", "", in, in_len);

		return SOF_VerifySignedData(global_data.p_ckpFunctions, global_data.p_pbCert, global_data.ulCertLen, in, in_len, out, *out_len);
	}

	ULONG CALL_CONVENTION SOF_SignDataXML(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		BYTE * data_info_cert = NULL;
		ULONG data_info_cert_len = 0;

		xmlDocPtr doc = NULL;
		xmlNodePtr signNode = NULL;
		xmlSecDSigCtxPtr dsigCtx = NULL;
		xmlNodePtr refNode = NULL;
		xmlNodePtr keyInfoNode = NULL;

		xmlSecTransformId xmlSecTransformId_sign;
		xmlSecTransformId xmlSecTransformId_digest;
		xmlNodePtr x509DataNode = NULL;

		int xml_len = 0;
		xmlChar *xml_ptr_ = NULL;
		xmlChar **xml_ptr = &xml_ptr_;

		const char * kRSAKeyTmp = "-----BEGIN RSA PRIVATE KEY-----\n" \
			"MIIBPAIBAAJBANPQbQ92nlbeg1Q5JNHSO1Yey46nZ7GJltLWw1ccSvp7pnvmfUm+\n" \
			"M521CpFpfr4EAE3UVBMoU9j/hqq3dFAc2H0CAwEAAQJBALFVCjmsAZyQ5jqZLO5N\n" \
			"qEfNuHZSSUol+xPBogFIOq3BWa269eNNcAK5or5g0XWWon7EPdyGT4qyDVH9KzXK\n" \
			"RLECIQDzm/Nj0epUGN51/rKJgRXWkXW/nfSCMO9fvQR6Ujoq3wIhAN6WeHK9vgWg\n" \
			"wBWqMdq5sR211+LlDH7rOUQ6rBpbsoQjAiEA7jzpfglgPPZFOOfo+oh/LuP6X3a+\n" \
			"FER/FQXpRyb7M8kCIETUrwZ8WkiPPxbz/Fqw1W5kjw/g2I5e2uSYaCP2eyuVAiEA\n" \
			"mOI6RhRyMqgxQyy0plJVjG1s4fdu92AWYy9AwYeyd/8=\n" \
			"-----END RSA PRIVATE KEY-----";

		const char * kRSACertTmp = "-----BEGIN CERTIFICATE-----\n" \
			"MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD\n" \
			"VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3Vy\n" \
			"aXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQG\n" \
			"A1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtz\n" \
			"ZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkG\n" \
			"A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1\n" \
			"cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAn\n" \
			"BgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQD\n" \
			"Ew1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5j\n" \
			"b20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7Ljqdn\n" \
			"sYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQAB\n" \
			"o4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH\n" \
			"ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTM\n" \
			"QygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGu\n" \
			"MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1M\n" \
			"IFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2Vj\n" \
			"KTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8G\n" \
			"CSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZI\n" \
			"hvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJ\n" \
			"fBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga\n" \
			"-----END CERTIFICATE-----";

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "ContainerName: %s", pContainerName);
		FILE_LOG_FMT(file_log_name, "%s", "DataIn: ");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

#ifndef XMLSEC_NO_XSLT
		xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

		/* Init libxml and libxslt libraries */
		xmlInitParser();
		LIBXML_TEST_VERSION
			xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
		xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
		xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

		ulResult = SOF_GetContainerType(p_ckpFunctions, pContainerName, &ulContainerType);

		if (ulResult)
		{
			goto end;
		}

		global_data.p_ckpFunctions = p_ckpFunctions;
		global_data.p_contanier = pContainerName;




		ulResult = SOF_ExportUserCert(p_ckpFunctions, pContainerName, data_info_cert, &data_info_cert_len);
		if (ulResult)
		{
			goto end;
		}

		data_info_cert = new BYTE[data_info_cert_len];
		ulResult = SOF_ExportUserCert(p_ckpFunctions, pContainerName, data_info_cert, &data_info_cert_len);
		if (ulResult)
		{
			goto end;
		}

		/* Init libxslt */
#ifndef XMLSEC_NO_XSLT
		/* disable everything */
		xsltSecPrefs = xsltNewSecurityPrefs();
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_READ_FILE, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_WRITE_FILE, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_READ_NETWORK, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_WRITE_NETWORK, xsltSecurityForbid);
		xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

		/* Init xmlsec library */
		if (xmlSecInit() < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Check loaded library version */
		if (xmlSecCheckVersion() != 1) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Load default crypto engine if we are supporting dynamic
		* loading for xmlsec-crypto libraries. Use the crypto library
		* name ("openssl", "nss", etc.) to load corresponding
		* xmlsec-crypto library.
		*/
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
		if (xmlSecCryptoDLLoadLibrary((const xmlChar*)"openssl") < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

		/* Init crypto library */
		if (xmlSecCryptoAppInit(NULL) < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Init xmlsec-crypto library */
		if (xmlSecCryptoInit() < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (ulContainerType == 1)
		{
			if (global_data.sign_method == SGD_SM3_RSA)
			{
				xmlSecTransformId_digest = xmlSecTransformSM3Id;
				xmlSecTransformId_sign = xmlSecTransformRsaSM3Id;
			}
			else if (global_data.sign_method == SGD_SHA1_RSA)
			{
				xmlSecTransformId_digest = xmlSecTransformSha1Id;
				xmlSecTransformId_sign = xmlSecTransformRsaSha1Id;
			}
			else if (global_data.sign_method == SGD_SHA256_RSA)
			{
				xmlSecTransformId_digest = xmlSecTransformSha256Id;
				xmlSecTransformId_sign = xmlSecTransformRsaSha256Id;
			}
			else
			{
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
				goto end;
			}
		}
		else if (ulContainerType == 2)
		{
			if (global_data.sign_method == SGD_SM3_SM2)
			{
				xmlSecTransformId_digest = xmlSecTransformSM3Id;
				xmlSecTransformId_sign = xmlSecTransformSM2SM3Id;
			}
			else
			{
				ulResult = SOR_PARAMETERNOTSUPPORTEERR;//SOR_UNKNOWNERR;
				goto end;
			}
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

		doc = xmlParseMemory((char *)pbDataIn, ulDataInLen);

		if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
			ulResult = SOR_XMLENCODEERR;
			goto end;
		}

		/* create signature template for RSA-SHA1 enveloped signature */
		signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
			xmlSecTransformId_sign, NULL);
		if (signNode == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}



		/* add <dsig:Signature/> node to the doc */
		xmlAddChild(xmlDocGetRootElement(doc), signNode);

		/* add reference */
		refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformId_digest,
			NULL, NULL, NULL);
		if (refNode == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* add enveloped transform */
		if (xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* add <dsig:KeyInfo/> and <dsig:X509Data/> */
		keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
		if (keyInfoNode == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		x509DataNode = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);
		if (x509DataNode == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (xmlSecTmplX509DataAddSubjectName(x509DataNode) == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (xmlSecTmplX509DataAddCertificate(x509DataNode) == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* create signature context, we don't need keys manager in this example */
		dsigCtx = xmlSecDSigCtxCreate(NULL);
		if (dsigCtx == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* load private key, assuming that there is not password */
		dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory((unsigned char *)kRSAKeyTmp, strlen(kRSAKeyTmp), xmlSecKeyDataFormatPem, NULL, NULL, NULL);
		if (dsigCtx->signKey == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* load certificate and add to the key */
		//if (xmlSecCryptoAppKeyCertLoadMemory(dsigCtx->signKey, (unsigned char *)kRSACertTmp, strlen(kRSACertTmp), xmlSecKeyDataFormatPem) < 0) {
		if (xmlSecCryptoAppKeyCertLoadMemory(dsigCtx->signKey, data_info_cert, data_info_cert_len, xmlSecKeyDataFormatDer) < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* set key name to the file name, this is just an example! */
		//if (xmlSecKeySetName(dsigCtx->signKey, (const xmlChar *)"null.key") < 0) {
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		/* sign the template */
		if (xmlSecDSigCtxSign(dsigCtx, signNode, cb_digest_simple, cb_sign_simple) < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* print signed document to stdout */
		//xmlDocDump(stdout, doc);


		xmlDocDumpMemory(doc, xml_ptr, &xml_len);

		if (NULL == pbDataOut)
		{
			*pulDataOutLen = xml_len;
			ulResult = SOR_OK;
		}
		else if (xml_len > *pulDataOutLen)
		{
			*pulDataOutLen = xml_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulDataOutLen = xml_len;
			memcpy(pbDataOut, *xml_ptr, xml_len);
			ulResult = SOR_OK;
		}



	end:

		if (xml_ptr_)
		{
			xmlFree(xml_ptr_);
			xml_ptr_ = NULL;
		}

		/* cleanup */
		if (dsigCtx != NULL) {
			xmlSecDSigCtxDestroy(dsigCtx);
		}

		if (doc != NULL) {
			xmlFreeDoc(doc);
		}

		/* Shutdown xmlsec-crypto library */
		xmlSecCryptoShutdown();

		/* Shutdown crypto library */
		xmlSecCryptoAppShutdown();

		/* Shutdown xmlsec library */
		xmlSecShutdown();

		/* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
		xsltFreeSecurityPrefs(xsltSecPrefs);
		xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
		xmlCleanupParser();

		if (data_info_cert)
		{
			delete data_info_cert;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}



	ULONG CALL_CONVENTION SOF_VerifySignedDataXML(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		ULONG ulResult = SOR_OK;
		char * pbCert = NULL;
		char *pSignMethod = NULL;
		ULONG  info_len = 0;
		char * pbInfo = NULL;

		xmlNodePtr node = NULL;

		std::string str_cert;

		ULONG sign_method = global_data.sign_method;

		const char * kRSAKeyTmp = "-----BEGIN PUBLIC KEY-----\n" \
			"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANPQbQ92nlbeg1Q5JNHSO1Yey46nZ7GJ\n" \
			"ltLWw1ccSvp7pnvmfUm+M521CpFpfr4EAE3UVBMoU9j/hqq3dFAc2H0CAwEAAQ==\n" \
			"-----END PUBLIC KEY-----";

		int i = 0;

#ifndef XMLSEC_NO_XSLT
		xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

		xmlDocPtr doc = NULL;
		xmlSecDSigCtxPtr dsigCtx = NULL;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		for (i = 1; i < 7; i++)
		{
			if (4 == i || 6 == i)
			{
				pbInfo = NULL;
				info_len = 0;

				ulResult = SOF_GetXMLSignatureInfo(p_ckpFunctions, i, pbDataIn, ulDataInLen, (BYTE*)pbInfo, &info_len);
				if (ulResult)
				{
					ulResult = SOR_UNKNOWNERR;
					goto end;
				}

				pbInfo = new char[info_len + 1];
				memset(pbInfo, 0, info_len + 1);

				ulResult = SOF_GetXMLSignatureInfo(p_ckpFunctions, i, pbDataIn, ulDataInLen, (BYTE*)pbInfo, &info_len);
				if (ulResult)
				{
					ulResult = SOR_UNKNOWNERR;
					goto end;
				}

				if (4 == i)
				{
					pbCert = pbInfo;
				}

				if (6 == i)
				{
					pSignMethod = pbInfo;
				}
			}
		}

		/* Init libxml and libxslt libraries */
		xmlInitParser();
		LIBXML_TEST_VERSION
			xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
		xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
		xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

		/* Init libxslt */
#ifndef XMLSEC_NO_XSLT
		/* disable everything */
		xsltSecPrefs = xsltNewSecurityPrefs();
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_READ_FILE, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_WRITE_FILE, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_READ_NETWORK, xsltSecurityForbid);
		xsltSetSecurityPrefs(xsltSecPrefs, XSLT_SECPREF_WRITE_NETWORK, xsltSecurityForbid);
		xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

		/* Init xmlsec library */
		if (xmlSecInit() < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Check loaded library version */
		if (xmlSecCheckVersion() != 1) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Load default crypto engine if we are supporting dynamic
		* loading for xmlsec-crypto libraries. Use the crypto library
		* name ("openssl", "nss", etc.) to load corresponding
		* xmlsec-crypto library.
		*/
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
		if (xmlSecCryptoDLLoadLibrary((xmlChar *)"openssl") < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

		/* Init crypto library */
		if (xmlSecCryptoAppInit(NULL) < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Init xmlsec-crypto library */
		if (xmlSecCryptoInit() < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		doc = xmlParseMemory((const char *)pbDataIn, ulDataInLen);
		if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (0 == memcmp(pSignMethod, xmlSecHrefSM2SM3, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SM3_SM2;
		}
		else if (0 == memcmp(pSignMethod, xmlSecHrefRsaSM3, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SM3_RSA;
		}
		else if (0 == memcmp(pSignMethod, xmlSecHrefRsaSha1, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SHA1_RSA;
		}
		else if (0 == memcmp(pSignMethod, xmlSecHrefRsaSha256, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SHA256_RSA;
		}

		str_cert = pbCert;

		str_cert.erase(std::remove(str_cert.begin(), str_cert.end(), '\r'), str_cert.end());
		str_cert.erase(std::remove(str_cert.begin(), str_cert.end(), '\n'), str_cert.end());

		str_cert = modp_b64_decode(str_cert);

		global_data.p_pbCert = (BYTE*)str_cert.c_str();
		global_data.ulCertLen = str_cert.size();

		/* find start node */
		node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
		if (node == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* create signature context, we don't need keys manager in this example */
		dsigCtx = xmlSecDSigCtxCreate(NULL);
		if (dsigCtx == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* load public key */
		dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory((unsigned char *)kRSAKeyTmp, strlen(kRSAKeyTmp), xmlSecKeyDataFormatPem, NULL, NULL, NULL);
		if (dsigCtx->signKey == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* Verify signature */
		if (xmlSecDSigCtxVerify(dsigCtx, node, cb_digest_vfy, cb_sign_vfy) < 0) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		/* print verification result to stdout */
		if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
			ulResult = SOR_OK;
			goto end;
		}
		else {
			ulResult = SOR_VERIFYSIGNDATAERR;
			goto end;
		}
	end:
		if (pbCert)
		{
			delete pbCert;
		}

		if (pSignMethod)
		{
			delete pSignMethod;
		}

		/* Shutdown xmlsec-crypto library */
		xmlSecCryptoShutdown();

		/* Shutdown crypto library */
		xmlSecCryptoAppShutdown();

		/* Shutdown xmlsec library */
		xmlSecShutdown();

		/* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
		xsltFreeSecurityPrefs(xsltSecPrefs);
		xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
		xmlCleanupParser();

		global_data.sign_method = sign_method;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}





	ULONG CALL_CONVENTION SOF_VerifySignedDataXML2(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		ULONG ulResult = SOR_OK;

		xmlDocPtr doc_digest_plain = NULL;
		xmlDocPtr doc_sign_plain = NULL;

		char * pDigest = NULL;
		char * pSignature = NULL;
		char * pbCert = NULL;

		char *pPlain = NULL;
		char *pDigestMethod = NULL;
		char *pSignMethod = NULL;
		ULONG  info_len = 0;
		char * pbInfo = NULL;

		int xml_len = 0;
		xmlChar *xml_ptr_ = NULL;
		xmlChar **xml_ptr = &xml_ptr_;

		xmlNodePtr node = NULL;

		std::string str_digest;
		std::string str_signature;

		unsigned char *pbDigest = NULL;
		unsigned char *pbSignature = NULL;

		std::string str_cert;

		ULONG sign_method = global_data.sign_method;

		int i = 0;

		unsigned char template_digest_plain[] = {
			0x3C,0x45,0x6E,0x76,0x65,0x6C,0x6F,0x70,0x65,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x22,0x75,0x72,0x6E,0x3A,0x65,0x6E,0x76,0x65,0x6C,0x6F,0x70,0x65,0x22,0x3E,0x0A,0x20,0x20,0x3C,0x44,0x61,0x74,0x61,0x3E,0x0A,0x09,0x48,0x65,0x6C,0x6C,0x6F,0x2C,0x20,0x57,0x6F,0x72,0x6C,0x64,0x21,0x0A,0x20,0x20,0x3C,0x2F,0x44,0x61,0x74,0x61,0x3E,0x0A,0x3C,0x2F,0x45,0x6E,0x76,0x65,0x6C,0x6F,0x70,0x65,0x3E };

		unsigned char template_sign_plain[] = { 0x3C,0x53,0x69,0x67,0x6E,0x65,0x64,0x49,0x6E,0x66,0x6F,0x20,0x78,0x6D,0x6C,0x6E,0x73,0x3D,0x22,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x77,0x33,0x2E,0x6F,0x72,0x67,0x2F,0x32,0x30,0x30,0x30,0x2F,0x30,0x39,0x2F,0x78,0x6D,0x6C,0x64,0x73,0x69,0x67,0x23,0x22,0x3E,0x0A,0x3C,0x43,0x61,0x6E,0x6F,0x6E,0x69,0x63,0x61,0x6C,0x69,0x7A,0x61,0x74,0x69,0x6F,0x6E,0x4D,0x65,0x74,0x68,0x6F,0x64,0x20,0x41,0x6C,0x67,0x6F,0x72,0x69,0x74,0x68,0x6D,0x3D,0x22,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x77,0x33,0x2E,0x6F,0x72,0x67,0x2F,0x32,0x30,0x30,0x31,0x2F,0x31,0x30,0x2F,0x78,0x6D,0x6C,0x2D,0x65,0x78,0x63,0x2D,0x63,0x31,0x34,0x6E,0x23,0x22,0x3E,0x3C,0x2F,0x43,0x61,0x6E,0x6F,0x6E,0x69,0x63,0x61,0x6C,0x69,0x7A,0x61,0x74,0x69,0x6F,0x6E,0x4D,0x65,0x74,0x68,0x6F,0x64,0x3E,0x0A,0x3C,0x53,0x69,0x67,0x6E,0x61,0x74,0x75,0x72,0x65,0x4D,0x65,0x74,0x68,0x6F,0x64,0x20,0x41,0x6C,0x67,0x6F,0x72,0x69,0x74,0x68,0x6D,0x3D,0x22,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x77,0x33,0x2E,0x6F,0x72,0x67,0x2F,0x32,0x30,0x30,0x30,0x2F,0x30,0x39,0x2F,0x78,0x6D,0x6C,0x64,0x73,0x69,0x67,0x23,0x73,0x6D,0x32,0x2D,0x73,0x6D,0x33,0x22,0x3E,0x3C,0x2F,0x53,0x69,0x67,0x6E,0x61,0x74,0x75,0x72,0x65,0x4D,0x65,0x74,0x68,0x6F,0x64,0x3E,0x0A,0x3C,0x52,0x65,0x66,0x65,0x72,0x65,0x6E,0x63,0x65,0x3E,0x0A,0x3C,0x54,0x72,0x61,0x6E,0x73,0x66,0x6F,0x72,0x6D,0x73,0x3E,0x0A,0x3C,0x54,0x72,0x61,0x6E,0x73,0x66,0x6F,0x72,0x6D,0x20,0x41,0x6C,0x67,0x6F,0x72,0x69,0x74,0x68,0x6D,0x3D,0x22,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x77,0x33,0x2E,0x6F,0x72,0x67,0x2F,0x32,0x30,0x30,0x30,0x2F,0x30,0x39,0x2F,0x78,0x6D,0x6C,0x64,0x73,0x69,0x67,0x23,0x65,0x6E,0x76,0x65,0x6C,0x6F,0x70,0x65,0x64,0x2D,0x73,0x69,0x67,0x6E,0x61,0x74,0x75,0x72,0x65,0x22,0x3E,0x3C,0x2F,0x54,0x72,0x61,0x6E,0x73,0x66,0x6F,0x72,0x6D,0x3E,0x0A,0x3C,0x2F,0x54,0x72,0x61,0x6E,0x73,0x66,0x6F,0x72,0x6D,0x73,0x3E,0x0A,0x3C,0x44,0x69,0x67,0x65,0x73,0x74,0x4D,0x65,0x74,0x68,0x6F,0x64,0x20,0x41,0x6C,0x67,0x6F,0x72,0x69,0x74,0x68,0x6D,0x3D,0x22,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x77,0x33,0x2E,0x6F,0x72,0x67,0x2F,0x32,0x30,0x30,0x30,0x2F,0x30,0x39,0x2F,0x78,0x6D,0x6C,0x64,0x73,0x69,0x67,0x23,0x73,0x6D,0x33,0x22,0x3E,0x3C,0x2F,0x44,0x69,0x67,0x65,0x73,0x74,0x4D,0x65,0x74,0x68,0x6F,0x64,0x3E,0x0A,0x3C,0x44,0x69,0x67,0x65,0x73,0x74,0x56,0x61,0x6C,0x75,0x65,0x3E,0x30,0x2B,0x76,0x4C,0x58,0x61,0x42,0x6D,0x65,0x65,0x2B,0x54,0x66,0x43,0x57,0x68,0x42,0x65,0x65,0x63,0x41,0x4D,0x51,0x69,0x6B,0x58,0x79,0x4E,0x43,0x70,0x69,0x50,0x70,0x56,0x54,0x42,0x30,0x74,0x48,0x49,0x42,0x52,0x41,0x3D,0x3C,0x2F,0x44,0x69,0x67,0x65,0x73,0x74,0x56,0x61,0x6C,0x75,0x65,0x3E,0x0A,0x3C,0x2F,0x52,0x65,0x66,0x65,0x72,0x65,0x6E,0x63,0x65,0x3E,0x0A,0x3C,0x2F,0x53,0x69,0x67,0x6E,0x65,0x64,0x49,0x6E,0x66,0x6F,0x3E };

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		for (i = 1; i < 7; i++)
		{
			pbInfo = NULL;
			info_len = 0;

			ulResult = SOF_GetXMLSignatureInfo(p_ckpFunctions, i, pbDataIn, ulDataInLen, (BYTE*)pbInfo, &info_len);
			if (ulResult)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			pbInfo = new char[info_len + 1];
			memset(pbInfo, 0, info_len + 1);

			ulResult = SOF_GetXMLSignatureInfo(p_ckpFunctions, i, pbDataIn, ulDataInLen, (BYTE*)pbInfo, &info_len);
			if (ulResult)
			{
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			if (1 == i)
			{
				pPlain = pbInfo;
			}


			if (2 == i)
			{
				pDigest = pbInfo;
			}

			if (3 == i)
			{
				pSignature = pbInfo;
			}

			if (4 == i)
			{
				pbCert = pbInfo;
			}

			if (5 == i)
			{
				pDigestMethod = pbInfo;
			}

			if (6 == i)
			{
				pSignMethod = pbInfo;
			}
		}

		/* Init libxml and libxslt libraries */
		xmlInitParser();
		LIBXML_TEST_VERSION
			xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
		xmlSubstituteEntitiesDefault(1);

		doc_digest_plain = xmlParseMemory((const char *)template_digest_plain, sizeof(template_digest_plain));
		if ((doc_digest_plain == NULL) || (xmlDocGetRootElement(doc_digest_plain) == NULL)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		doc_sign_plain = xmlParseMemory((const char *)template_sign_plain, sizeof(template_sign_plain));
		if ((doc_sign_plain == NULL) || (xmlDocGetRootElement(doc_sign_plain) == NULL)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		if (0 == memcmp(pSignMethod, xmlSecHrefSM2SM3, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SM3_SM2;
		}
		else if (0 == memcmp(pSignMethod, xmlSecHrefRsaSM3, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SM3_RSA;
		}
		else if (0 == memcmp(pSignMethod, xmlSecHrefRsaSha1, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SHA1_RSA;
		}
		else if (0 == memcmp(pSignMethod, xmlSecHrefRsaSha256, strlen(pSignMethod)))
		{
			global_data.sign_method = SGD_SHA256_RSA;
		}

		node = xmlSecFindNode(xmlDocGetRootElement(doc_digest_plain), (xmlChar *)"Data", (xmlChar *)"urn:envelope");
		if (node == NULL) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		xmlNodeSetContent(node, (xmlChar*)pPlain);

		xmlDocDumpFormatMemory(doc_digest_plain, xml_ptr, &xml_len, 0);

		str_cert = pbCert;

		str_cert.erase(std::remove(str_cert.begin(), str_cert.end(), '\r'), str_cert.end());
		str_cert.erase(std::remove(str_cert.begin(), str_cert.end(), '\n'), str_cert.end());

		str_cert = modp_b64_decode(str_cert);

		global_data.p_pbCert = (BYTE*)str_cert.c_str();
		global_data.ulCertLen = str_cert.size();

#if 0
		//info_len = 0;
		//ulResult = SOF_DigestDataCert(p_ckpFunctions, *xml_ptr, xml_len, pbDigest, &info_len);
		//if (ulResult)
		//{
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		//pbDigest = new unsigned char[info_len];

		//ulResult = SOF_DigestDataCert(p_ckpFunctions,  (*xml_ptr) + 0x16, xml_len - 0x16 -1, pbDigest, &info_len);
		//if (ulResult)
		//{
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		//if (xml_ptr_)
		//{
		//	xmlFree(xml_ptr_);
		//	xml_ptr_ = NULL;
		//}

		//str_digest = pDigest;
		//str_digest.erase(std::remove(str_digest.begin(), str_digest.end(), '\r'), str_digest.end());
		//str_digest.erase(std::remove(str_digest.begin(), str_digest.end(), '\n'), str_digest.end());

		//str_digest = modp_b64_decode(str_digest);

		//if (0 != memcmp(str_digest.c_str(), pbDigest, info_len))
		//{
		//	ulResult = SOR_HASHNOTEQUALERR;
		//	goto end;
		//}

		////XML_SAVE_NO_DECL, 

		//// 2. SignatureMethod
		//node = xmlSecFindNode(xmlDocGetRootElement(doc_sign_plain), xmlSecNodeSignatureMethod, xmlSecDSigNs);
		//if (node == NULL) {
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		//xmlSetProp(node, xmlSecAttrAlgorithm, (xmlChar*)pSignMethod);

		//// 3. DigestMethod
		//node = xmlSecFindNode(xmlDocGetRootElement(doc_sign_plain), xmlSecNodeDigestMethod, xmlSecDSigNs);
		//if (node == NULL) {
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		//xmlSetProp(node, xmlSecAttrAlgorithm, (xmlChar*)pDigestMethod);

		//// 4. DigestValue
		//node = xmlSecFindNode(xmlDocGetRootElement(doc_sign_plain), xmlSecNodeDigestValue, xmlSecDSigNs);
		//if (node == NULL) {
		//	ulResult = SOR_UNKNOWNERR;
		//	goto end;
		//}

		//xmlNodeSetContent(node, (xmlChar*)pDigest);

		//str_signature = pSignature;

		//str_signature.erase(std::remove(str_signature.begin(), str_signature.end(), '\r'), str_signature.end());
		//str_signature.erase(std::remove(str_signature.begin(), str_signature.end(), '\n'), str_signature.end());

		//str_signature = modp_b64_decode(str_signature);


		//xmlDocDumpFormatMemory(doc_sign_plain, xml_ptr, &xml_len, 2);


		//ulResult = SOF_VerifySignedData(p_ckpFunctions, (BYTE*)str_cert.c_str(), str_cert.size(), (*xml_ptr) + 0x16, xml_len - 0x16 - 1, (BYTE*)str_signature.c_str(), str_signature.size());
		//if (ulResult)
		//{
		//	goto end;
		//}

#endif

	end:


		if (pPlain)
		{
			delete pPlain;
		}


		if (pbDigest)
		{
			delete pbDigest;
		}


		if (pDigest)
		{
			delete pDigest;
		}

		if (pSignature)
		{
			delete pSignature;
		}

		if (pbCert)
		{
			delete pbCert;
		}

		if (pDigestMethod)
		{
			delete pDigestMethod;
		}

		if (pSignMethod)
		{
			delete pSignMethod;
		}

		if (doc_sign_plain != NULL) {
			xmlFreeDoc(doc_sign_plain);
		}

		if (doc_digest_plain != NULL) {
			xmlFreeDoc(doc_digest_plain);
		}

		xmlCleanupParser();

		global_data.sign_method = sign_method;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_GetXMLSignatureInfo(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		ULONG ulResult = SOR_OK;

		/* Init libxml and libxslt libraries */
		xmlInitParser();
		LIBXML_TEST_VERSION
			xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
		xmlSubstituteEntitiesDefault(1);

		xmlDocPtr doc = NULL;
		xmlNodePtr node = NULL;
		char *ptr = NULL;

		/* load file */
		doc = xmlParseMemory((const char *)pbDataIn, ulDataInLen);
		if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
			ulResult = SOR_UNKNOWNERR;
			goto end;
		}

		switch (u16Type)
		{
		case 1:
		{
			node = xmlSecFindNode(xmlDocGetRootElement(doc), (xmlChar *)"Data", (xmlChar *)"urn:envelope");
			if (node == NULL) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
			ptr = (char *)xmlNodeGetContent(node);
		}
		break;
		case 2:
		{

			/* find start node */
			node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeDigestValue, xmlSecDSigNs);
			if (node == NULL) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
			ptr = (char *)xmlNodeGetContent(node);
		}


		break;
		case 3:
		{
			/* find start node */
			node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignatureValue, xmlSecDSigNs);
			if (node == NULL) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}
			ptr = (char *)xmlNodeGetContent(node);
		}
		break;
		case 4:
		{
			/* find start node */
			node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeX509Certificate, xmlSecDSigNs);
			if (node == NULL) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			ptr = (char *)xmlNodeGetContent(node);
		}
		break;
		case 5:
		{
			/* find start node */
			node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeDigestMethod, xmlSecDSigNs);
			if (node == NULL) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			ptr = (char *)xmlGetProp(node, xmlSecAttrAlgorithm);
		}
		break;
		case 6:
		{
			/* find start node */
			node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignatureMethod, xmlSecDSigNs);
			if (node == NULL) {
				ulResult = SOR_UNKNOWNERR;
				goto end;
			}

			ptr = (char *)xmlGetProp(node, xmlSecAttrAlgorithm);
		}
		break;
		default:
			break;
		}


		if (NULL == pbInfo)
		{
			*pulInfoLen = strlen(ptr);
			ulResult = SOR_OK;
		}
		else if (strlen(ptr) > *pulInfoLen)
		{
			*pulInfoLen = strlen(ptr);
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulInfoLen = strlen(ptr);
			memcpy(pbInfo, ptr, strlen(ptr));
			ulResult = SOR_OK;
		}

	end:


		if (doc != NULL) {
			xmlFreeDoc(doc);
		}

		xmlCleanupParser();

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GenRandom(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		ULONG ulResult = SOR_OK;
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GenRandom(global_data.hDevHandle, pbDataIn, ulDataInLen);
		if (ulResult != SAR_OK)
			ulResult = SOR_GENRANDERR;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_GetLastError(void * p_ckpFunctions)
	{
		ULONG ulResult = SOR_OK;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		ulResult = global_data.last_error;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_FinalizeLibraryNative(CK_SKF_FUNCTION_LIST_PTR *pp_ckpFunctions) {
		ULONG ulResult = SOR_OK;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		if (*pp_ckpFunctions) {
			// add code here

			if (global_data.hAppHandle)
			{
				(*pp_ckpFunctions)->SKF_CloseApplication(global_data.hAppHandle);
				global_data.hAppHandle = 0;
			}

			if (global_data.hDevHandle)
			{
				(*pp_ckpFunctions)->SKF_DisConnectDev(global_data.hDevHandle);
				global_data.hDevHandle = 0;
			}

			MYFreeLibrary((*pp_ckpFunctions)->hHandle);
			(*pp_ckpFunctions)->hHandle = NULL;

			delete (*pp_ckpFunctions);

			*pp_ckpFunctions = NULL;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
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

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");



		hHandle = MYLoadLibrary(pSKFLibraryPath);
		if (NULL == hHandle) {
			ulResult = SOR_LOADPROVIDERERR;
			goto end;
		}

#if defined(SKF_SUPPORT_WT)
		if (!IsFileDigitallySigned(CharToWchar(pSKFLibraryPath).c_str()) || !MYValidWTFile(CharToWchar(pSKFLibraryPath).c_str(), CharToWchar("Tianjin Win-Trust Co., Ltd.").c_str()))
		{
			ulResult = SOR_LOADPROVIDERERR;
			goto end;
		}
#else

#endif

		memset(ckpFunctions, 0, sizeof(CK_SKF_FUNCTION_LIST));

		ckpFunctions->hHandle = hHandle;

		// load
		ckpFunctions->SKF_SetPackageName = (CK_SKF_SetPackageName)MYGetProcAddress(hHandle,
			"SKF_SetPackageName");
		ckpFunctions->SKF_WaitForDevEvent = (CK_SKF_WaitForDevEvent)MYGetProcAddress(hHandle,
			"SKF_WaitForDevEvent");
		ckpFunctions->SKF_CancelWaitForDevEvent = (CK_SKF_CancelWaitForDevEvent)MYGetProcAddress(
			hHandle, "SKF_CancelWaitForDevEvent");
		ckpFunctions->SKF_EnumDev = (CK_SKF_EnumDev)MYGetProcAddress(hHandle, "SKF_EnumDev");
		ckpFunctions->SKF_ConnectDev = (CK_SKF_ConnectDev)MYGetProcAddress(hHandle,
			"SKF_ConnectDev");
		ckpFunctions->SKF_DisConnectDev = (CK_SKF_DisConnectDev)MYGetProcAddress(hHandle,
			"SKF_DisConnectDev");
		ckpFunctions->SKF_GetDevState = (CK_SKF_GetDevState)MYGetProcAddress(hHandle,
			"SKF_GetDevState");
		ckpFunctions->SKF_SetLabel = (CK_SKF_SetLabel)MYGetProcAddress(hHandle,
			"SKF_SetLabel");
		ckpFunctions->SKF_GetDevInfo = (CK_SKF_GetDevInfo)MYGetProcAddress(hHandle,
			"SKF_GetDevInfo");
		ckpFunctions->SKF_LockDev = (CK_SKF_LockDev)MYGetProcAddress(hHandle, "SKF_LockDev");
		ckpFunctions->SKF_UnlockDev = (CK_SKF_UnlockDev)MYGetProcAddress(hHandle,
			"SKF_UnlockDev");
		ckpFunctions->SKF_Transmit = (CK_SKF_Transmit)MYGetProcAddress(hHandle,
			"SKF_Transmit");
		ckpFunctions->SKF_ChangeDevAuthKey = (CK_SKF_ChangeDevAuthKey)MYGetProcAddress(hHandle,
			"SKF_ChangeDevAuthKey");
		ckpFunctions->SKF_DevAuth = (CK_SKF_DevAuth)MYGetProcAddress(hHandle, "SKF_DevAuth");
		ckpFunctions->SKF_ChangePIN = (CK_SKF_ChangePIN)MYGetProcAddress(hHandle,
			"SKF_ChangePIN");
		ckpFunctions->SKF_GetPINInfo = (CK_SKF_GetPINInfo)MYGetProcAddress(hHandle,
			"SKF_GetPINInfo");
		ckpFunctions->SKF_VerifyPIN = (CK_SKF_VerifyPIN)MYGetProcAddress(hHandle,
			"SKF_VerifyPIN");
		ckpFunctions->SKF_UnblockPIN = (CK_SKF_UnblockPIN)MYGetProcAddress(hHandle,
			"SKF_UnblockPIN");
		ckpFunctions->SKF_ClearSecureState = (CK_SKF_ClearSecureState)MYGetProcAddress(hHandle,
			"SKF_ClearSecureState");
		ckpFunctions->SKF_CreateApplication = (CK_SKF_CreateApplication)MYGetProcAddress(
			hHandle, "SKF_CreateApplication");
		ckpFunctions->SKF_EnumApplication = (CK_SKF_EnumApplication)MYGetProcAddress(hHandle,
			"SKF_EnumApplication");
		ckpFunctions->SKF_DeleteApplication = (CK_SKF_DeleteApplication)MYGetProcAddress(
			hHandle, "SKF_DeleteApplication");
		ckpFunctions->SKF_OpenApplication = (CK_SKF_OpenApplication)MYGetProcAddress(hHandle,
			"SKF_OpenApplication");
		ckpFunctions->SKF_CloseApplication = (CK_SKF_CloseApplication)MYGetProcAddress(hHandle,
			"SKF_CloseApplication");
		ckpFunctions->SKF_CreateFile = (CK_SKF_CreateFile)MYGetProcAddress(hHandle,
			"SKF_CreateFile");
		ckpFunctions->SKF_DeleteFile = (CK_SKF_DeleteFile)MYGetProcAddress(hHandle,
			"SKF_DeleteFile");
		ckpFunctions->SKF_EnumFiles = (CK_SKF_EnumFiles)MYGetProcAddress(hHandle,
			"SKF_EnumFiles");
		ckpFunctions->SKF_GetFileInfo = (CK_SKF_GetFileInfo)MYGetProcAddress(hHandle,
			"SKF_GetFileInfo");
		ckpFunctions->SKF_ReadFile = (CK_SKF_ReadFile)MYGetProcAddress(hHandle,
			"SKF_ReadFile");
		ckpFunctions->SKF_WriteFile = (CK_SKF_WriteFile)MYGetProcAddress(hHandle,
			"SKF_WriteFile");
		ckpFunctions->SKF_CreateContainer = (CK_SKF_CreateContainer)MYGetProcAddress(hHandle,
			"SKF_CreateContainer");
		ckpFunctions->SKF_DeleteContainer = (CK_SKF_DeleteContainer)MYGetProcAddress(hHandle,
			"SKF_DeleteContainer");
		ckpFunctions->SKF_OpenContainer = (CK_SKF_OpenContainer)MYGetProcAddress(hHandle,
			"SKF_OpenContainer");
		ckpFunctions->SKF_CloseContainer = (CK_SKF_CloseContainer)MYGetProcAddress(hHandle,
			"SKF_CloseContainer");
		ckpFunctions->SKF_EnumContainer = (CK_SKF_EnumContainer)MYGetProcAddress(hHandle,
			"SKF_EnumContainer");
		ckpFunctions->SKF_GetContainerType = (CK_SKF_GetContainerType)MYGetProcAddress(hHandle,
			"SKF_GetContainerType");
		ckpFunctions->SKF_ImportCertificate = (CK_SKF_ImportCertificate)MYGetProcAddress(
			hHandle, "SKF_ImportCertificate");
		ckpFunctions->SKF_ExportCertificate = (CK_SKF_ExportCertificate)MYGetProcAddress(
			hHandle, "SKF_ExportCertificate");
		ckpFunctions->SKF_GenRandom = (CK_SKF_GenRandom)MYGetProcAddress(hHandle,
			"SKF_GenRandom");
		ckpFunctions->SKF_GenExtRSAKey = (CK_SKF_GenExtRSAKey)MYGetProcAddress(hHandle,
			"SKF_GenExtRSAKey");
		ckpFunctions->SKF_GenRSAKeyPair = (CK_SKF_GenRSAKeyPair)MYGetProcAddress(hHandle,
			"SKF_GenRSAKeyPair");
		ckpFunctions->SKF_ImportRSAKeyPair = (CK_SKF_ImportRSAKeyPair)MYGetProcAddress(hHandle,
			"SKF_ImportRSAKeyPair");
		ckpFunctions->SKF_RSASignData = (CK_SKF_RSASignData)MYGetProcAddress(hHandle,
			"SKF_RSASignData");
		ckpFunctions->SKF_RSAVerify = (CK_SKF_RSAVerify)MYGetProcAddress(hHandle,
			"SKF_RSAVerify");
		ckpFunctions->SKF_RSAExportSessionKey = (CK_SKF_RSAExportSessionKey)MYGetProcAddress(
			hHandle, "SKF_RSAExportSessionKey");
		ckpFunctions->SKF_ExtRSAPubKeyOperation = (CK_SKF_ExtRSAPubKeyOperation)MYGetProcAddress(
			hHandle, "SKF_ExtRSAPubKeyOperation");
		ckpFunctions->SKF_ExtRSAPriKeyOperation = (CK_SKF_ExtRSAPriKeyOperation)MYGetProcAddress(
			hHandle, "SKF_ExtRSAPriKeyOperation");
		ckpFunctions->SKF_GenECCKeyPair = (CK_SKF_GenECCKeyPair)MYGetProcAddress(hHandle,
			"SKF_GenECCKeyPair");
		ckpFunctions->SKF_ImportECCKeyPair = (CK_SKF_ImportECCKeyPair)MYGetProcAddress(hHandle,
			"SKF_ImportECCKeyPair");
		ckpFunctions->SKF_ECCSignData = (CK_SKF_ECCSignData)MYGetProcAddress(hHandle,
			"SKF_ECCSignData");
		ckpFunctions->SKF_ECCVerify = (CK_SKF_ECCVerify)MYGetProcAddress(hHandle,
			"SKF_ECCVerify");
		ckpFunctions->SKF_ECCExportSessionKey = (CK_SKF_ECCExportSessionKey)MYGetProcAddress(
			hHandle, "SKF_ECCExportSessionKey");
		ckpFunctions->SKF_ExtECCEncrypt = (CK_SKF_ExtECCEncrypt)MYGetProcAddress(hHandle,
			"SKF_ExtECCEncrypt");
		ckpFunctions->SKF_ExtECCDecrypt = (CK_SKF_ExtECCDecrypt)MYGetProcAddress(hHandle,
			"SKF_ExtECCDecrypt");
		ckpFunctions->SKF_ExtECCSign = (CK_SKF_ExtECCSign)MYGetProcAddress(hHandle,
			"SKF_ExtECCSign");
		ckpFunctions->SKF_ExtECCVerify = (CK_SKF_ExtECCVerify)MYGetProcAddress(hHandle,
			"SKF_ExtECCVerify");
		ckpFunctions->SKF_GenerateAgreementDataWithECC = (CK_SKF_GenerateAgreementDataWithECC)MYGetProcAddress(
			hHandle, "SKF_GenerateAgreementDataWithECC");
		ckpFunctions->SKF_GenerateAgreementDataAndKeyWithECC = (CK_SKF_GenerateAgreementDataAndKeyWithECC)MYGetProcAddress(
			hHandle, "SKF_GenerateAgreementDataAndKeyWithECC");
		ckpFunctions->SKF_GenerateKeyWithECC = (CK_SKF_GenerateKeyWithECC)MYGetProcAddress(
			hHandle, "SKF_GenerateKeyWithECC");
		ckpFunctions->SKF_ExportPublicKey = (CK_SKF_ExportPublicKey)MYGetProcAddress(hHandle,
			"SKF_ExportPublicKey");
		ckpFunctions->SKF_ImportSessionKey = (CK_SKF_ImportSessionKey)MYGetProcAddress(hHandle,
			"SKF_ImportSessionKey");
		ckpFunctions->SKF_SetSymmKey = (CK_SKF_SetSymmKey)MYGetProcAddress(hHandle,
			"SKF_SetSymmKey");
		ckpFunctions->SKF_EncryptInit = (CK_SKF_EncryptInit)MYGetProcAddress(hHandle,
			"SKF_EncryptInit");
		ckpFunctions->SKF_Encrypt = (CK_SKF_Encrypt)MYGetProcAddress(hHandle, "SKF_Encrypt");
		ckpFunctions->SKF_EncryptUpdate = (CK_SKF_EncryptUpdate)MYGetProcAddress(hHandle,
			"SKF_EncryptUpdate");
		ckpFunctions->SKF_EncryptFinal = (CK_SKF_EncryptFinal)MYGetProcAddress(hHandle,
			"SKF_EncryptFinal");
		ckpFunctions->SKF_DecryptInit = (CK_SKF_DecryptInit)MYGetProcAddress(hHandle,
			"SKF_DecryptInit");
		ckpFunctions->SKF_Decrypt = (CK_SKF_Decrypt)MYGetProcAddress(hHandle, "SKF_Decrypt");
		ckpFunctions->SKF_DecryptUpdate = (CK_SKF_DecryptUpdate)MYGetProcAddress(hHandle,
			"SKF_DecryptUpdate");
		ckpFunctions->SKF_DecryptFinal = (CK_SKF_DecryptFinal)MYGetProcAddress(hHandle,
			"SKF_DecryptFinal");
		ckpFunctions->SKF_DigestInit = (CK_SKF_DigestInit)MYGetProcAddress(hHandle,
			"SKF_DigestInit");
		ckpFunctions->SKF_Digest = (CK_SKF_Digest)MYGetProcAddress(hHandle, "SKF_Digest");
		ckpFunctions->SKF_DigestUpdate = (CK_SKF_DigestUpdate)MYGetProcAddress(hHandle,
			"SKF_DigestUpdate");
		ckpFunctions->SKF_DigestFinal = (CK_SKF_DigestFinal)MYGetProcAddress(hHandle,
			"SKF_DigestFinal");
		ckpFunctions->SKF_MacInit = (CK_SKF_MacInit)MYGetProcAddress(hHandle, "SKF_MacInit");
		ckpFunctions->SKF_Mac = (CK_SKF_Mac)MYGetProcAddress(hHandle, "SKF_Mac");
		ckpFunctions->SKF_MacUpdate = (CK_SKF_MacUpdate)MYGetProcAddress(hHandle,
			"SKF_MacUpdate");
		ckpFunctions->SKF_MacFinal = (CK_SKF_MacFinal)MYGetProcAddress(hHandle,
			"SKF_MacFinal");
		ckpFunctions->SKF_CloseHandle = (CK_SKF_CloseHandle)MYGetProcAddress(hHandle,
			"SKF_CloseHandle");

		ckpFunctions->SKF_ECCDecrypt = (CK_SKF_ECCDecrypt)MYGetProcAddress(hHandle,
			"SKF_ECCDecrypt");

		ckpFunctions->SKF_RSAPriKeyOperation = (CK_SKF_RSAPriKeyOperation)MYGetProcAddress(hHandle,
			"SKF_RSAPriKeyOperation");

		ckpFunctions->SKF_RSADecrypt = (CK_SKF_RSADecrypt)MYGetProcAddress(hHandle,
			"SKF_RSADecrypt");

		ckpFunctions->SKF_ECCPrvKeyDecryptEx = (CK_SKF_ECCPrvKeyDecryptEx)MYGetProcAddress(hHandle,
			"SKF_ECCPrvKeyDecryptEx");

		*pp_ckpFunctions = ckpFunctions;

		ulResult = ckpFunctions->SKF_EnumDev(TRUE, buffer_devs, &buffer_devs_len);
		if (ulResult)
		{
			goto end;
		}

		CAPI_GetMulStringCount(buffer_devs, &mult_string_count);
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

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG CALL_CONVENTION SOF_Logout(void *p_ckpFunctions)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_ClearSecureState(global_data.hAppHandle);
		if (ulResult)
		{
			goto end;
		}
	end:

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

#if 1

	ULONG CALL_CONVENTION SOF_PubKeyEncrypt(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = SOR_OK;
		ULONG ulContainerType = 0;

		BYTE *pbTmp = NULL;
		ULONG ulTmpLen;

		X509 * x509 = NULL;
		RSA *rsa = NULL;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");

		FILE_LOG_FMT(file_log_name, "%s", "Cert:");
		FILE_LOG_HEX(file_log_name, pbCert, ulCertLen);
		FILE_LOG_FMT(file_log_name, "%s", "DataIn:");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

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

			unsigned char pbModulus[256];
			int ulModulusLen = 0;
			const unsigned char *ptr = NULL;
			ptr = pbCert;

			x509 = d2i_X509(NULL, &ptr, ulCertLen);

			if (x509)
			{
				rsa = EVP_PKEY_get1_RSA(X509_get_pubkey(x509));
				int ulTmpLen = 0;

				if (rsa != NULL)
				{
					ulModulusLen = BN_bn2bin(rsa->n, pbModulus);
				}

				rsaPublicKeyBlob.BitLen = ulModulusLen * 8;

				memcpy(rsaPublicKeyBlob.PublicExponent, "\x00\x01\x00\x01", 4);

				memcpy(rsaPublicKeyBlob.Modulus + 256 - ulModulusLen, pbModulus, ulModulusLen);

				pbTmp = (BYTE*)malloc(ulDataInLen + rsaPublicKeyBlob.BitLen);
				if (pbTmp == NULL)
				{
					ulResult = SOR_MEMORYERR;
					goto end;
				}

				ulTmpLen = RSA_public_encrypt(ulDataInLen, pbDataIn, pbTmp, rsa, RSA_PKCS1_PADDING);

				if (ulTmpLen < 0)
				{
					ulResult = SOR_INDATALENERR;
					goto end;
				}

				if (NULL == pbDataOut)
				{
					*pulDataOutLen = ulTmpLen;
					ulResult = SOR_OK;
					goto end;
				}
				else if (ulTmpLen > *pulDataOutLen)
				{
					*pulDataOutLen = ulTmpLen;
					ulResult = SOR_MEMORYERR;
					goto end;
				}
				else
				{
					*pulDataOutLen = ulTmpLen;
					memcpy(pbDataOut, pbTmp, ulTmpLen);
				}
			}

			//if (ckpFunctions->SKF_RSAEncrypt != NULL)
			//{
			//	//ulResult = ckpFunctions->SKF_RSAEncrypt(global_data.hDevHandle,FALSE, &rsaPublicKeyBlob, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen);
			//}
			//else
			//{
			//	ulResult = ckpFunctions->SKF_ExtRSAPubKeyOperation(global_data.hDevHandle, &rsaPublicKeyBlob, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen);
			//}
		}
		else if (ECertificate_KEY_ALG_EC == certParse.m_iKeyAlg)
		{
			unsigned char pk_data[32 * 2 + 1] = { 0 };
			unsigned int pk_len = 65;

			eccPublicKeyBlob.BitLen = 256;

			OpenSSL_CertGetPubkey(pbCert, ulCertLen, pk_data, &pk_len);

			memcpy(eccPublicKeyBlob.XCoordinate + 32, pk_data + 1, 32);
			memcpy(eccPublicKeyBlob.YCoordinate + 32, pk_data + 1 + 32, 32);

			ulTmpLen = ulDataInLen + sizeof(ECCCIPHERBLOB);
			pbTmp = (BYTE*)malloc(ulTmpLen);
			if (pbTmp == NULL)
			{
				ulResult = SOR_MEMORYERR;
				goto end;
			}
			memset(pbTmp, 0x00, ulDataInLen + sizeof(ECCCIPHERBLOB));
			ulResult = ckpFunctions->SKF_ExtECCEncrypt(global_data.hDevHandle, &eccPublicKeyBlob, pbDataIn, ulDataInLen, (PECCCIPHERBLOB)pbTmp);

			if (NULL == pbDataOut)
			{
				*pulDataOutLen = ulTmpLen;
				ulResult = SOR_OK;
				goto end;
			}
			else if (ulTmpLen > *pulDataOutLen)
			{
				*pulDataOutLen = ulTmpLen;
				ulResult = SOR_MEMORYERR;
				goto end;
			}
			else
			{
				*pulDataOutLen = ulTmpLen;
				memcpy(pbDataOut, pbTmp, ulTmpLen);
			}
			FILE_LOG_FMT(file_log_name, "%s", "DataOut:");
			FILE_LOG_HEX(file_log_name, pbDataOut, ulTmpLen);
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}

	end:

		if (rsa)
		{
			RSA_free(rsa);
		}

		if (x509)
		{
			X509_free(x509);
		}


		if (pbTmp != NULL)
			free(pbTmp);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG CALL_CONVENTION SOF_PriKeyDecrypt(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

		ULONG ulResult = 0;
		ULONG ulContainerType = 0;

		FILE_LOG_FMT(file_log_name, "\n%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "ContainerName: %s", pContainerName);

		FILE_LOG_FMT(file_log_name, "%s", "DataIn:");
		FILE_LOG_HEX(file_log_name, pbDataIn, ulDataInLen);

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
			if (NULL != ckpFunctions->SKF_RSAPriKeyOperation)
			{
				ulResult = ckpFunctions->SKF_RSAPriKeyOperation(hContainer, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen, FALSE);
			}
			else if (NULL != ckpFunctions->SKF_RSADecrypt)
			{
				ulResult = ckpFunctions->SKF_RSADecrypt(hContainer, FALSE, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen);
			}

		}
		else if (ulContainerType == 2)
		{
			if (NULL != ckpFunctions->SKF_ECCDecrypt)
			{
				ulResult = ckpFunctions->SKF_ECCDecrypt(hContainer, pbDataIn, ulDataInLen, pbDataOut, pulDataOutLen);
			}
			else if (NULL != ckpFunctions->SKF_ECCPrvKeyDecryptEx)
			{
				ulResult = ckpFunctions->SKF_ECCPrvKeyDecryptEx(hContainer, FALSE, (PECCCIPHERBLOB)pbDataIn, pbDataOut, pulDataOutLen);
			}
			FILE_LOG_FMT(file_log_name, "ulResult: %d", ulResult);
		}
		else
		{
			ulResult = SOR_NOTSUPPORTYETERR;
			goto end;
		}
		if (pbDataOut == NULL)
			FILE_LOG_FMT(file_log_name, "ulDataOutLen: %d", *pulDataOutLen);
		else
		{
			FILE_LOG_FMT(file_log_name, "%s", "DataOut:");
			FILE_LOG_HEX(file_log_name, pbDataOut, *pulDataOutLen);
		}
	end:

		if (hContainer)
		{
			ckpFunctions->SKF_CloseContainer(hContainer);
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting\n");

		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

#endif








#ifdef __cplusplus
}
#endif
