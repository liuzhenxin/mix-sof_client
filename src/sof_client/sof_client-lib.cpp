#include <string>
#include "sof_client.h"
#include "sof_client-tools.h"
#include "skf.h"
#include "assert.h"
#include "FILE_LOG.h"
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include "certificate_items_parse.h"
#include "smb_cs.h"
#include "smcert.h"

typedef CK_SOF_CLIENT_FUNCTION_LIST *CK_SOF_CLIENT_FUNCTION_LIST_PTR;
typedef CK_SKF_FUNCTION_LIST *CK_SKF_FUNCTION_LIST_PTR;




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

	ST_GlobalData global_data = { 0 };


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


	ULONG SOF_GetVersion(void * p_ckpFunctions, VERSION *pVersion)
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

	ULONG SOF_SetSignMethod(void * p_ckpFunctions, ULONG ulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		global_data.sign_method = ulMethod;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_GetSignMethod(void * p_ckpFunctions, ULONG *pulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulMethod = global_data.sign_method;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_SetEncryptMethod(void * p_ckpFunctions, ULONG ulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		global_data.encrypt_method = ulMethod;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_GetEncryptMethod(void * p_ckpFunctions, ULONG *pulMethod)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulMethod = global_data.encrypt_method;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_GetUserList(void * p_ckpFunctions, BYTE *pbUserList, ULONG *pulUserListLen)
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

			strUserList.append(data_info_value);
			strUserList.append("||");
			strUserList.append(ptr);
			ckpFunctions->SKF_CloseContainer(hContainer);
			hContainer = 0;

			ptr += strlen(ptr);
			ptr += 1;
		}


		if (NULL == pbUserList)
		{
			*pulUserListLen = data_info_len;
			ulResult = SOR_OK;
		}
		if (data_info_len >  *pulUserListLen)
		{
			*pulUserListLen = data_info_len;
			ulResult = SOR_MEMORYERR;
		}
		else
		{
			*pulUserListLen = data_info_len;
			memcpy(pbUserList, data_info_value, data_info_len);
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

	ULONG SOF_ExportUserCert(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen)
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

	ULONG SOF_Login(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPIN)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

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

	ULONG SOF_GetPinRetryCount(void * p_ckpFunctions, LPSTR pContainerName, ULONG *pulRetryCount)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		*pulRetryCount = global_data.retry;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_ChangePassWd(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pPINOld, LPSTR pPINNew)
	{
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;
		HANDLE hContainer = NULL;

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

	ULONG SOF_ExportExChangeUserCert(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbCert, ULONG *pulCertLen)
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

	ULONG SOF_GetCertInfo(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, UINT16 u16Type, BYTE *pbInfo, ULONG *pulInfoLen)
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
		if (data_info_len >  *pulInfoLen)
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


	ULONG SOF_GetCertInfoByOid(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pOidString, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_NOTSUPPORTYETERR);

		return SOR_NOTSUPPORTYETERR;
	}

	ULONG SOF_GetDeviceInfo(void * p_ckpFunctions, LPSTR pContainerName, ULONG ulType, BYTE *pbInfo, ULONG *pulInfoLen)
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
		if (data_info_len >  *pulInfoLen)
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

	ULONG SOF_ValidateCert(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, ULONG *pulValidate)
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

	ULONG SOF_SignData(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_VerifySignedData(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG ulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_SignFile(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pFileIn, LPSTR pFileOut)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_VerifySignedFile(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pFileIn, LPSTR pFileOut)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_EncryptData(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_DecryptData(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_EncryptFile(void * p_ckpFunctions, BYTE *pbCert, ULONG ulCertLen, LPSTR pFileIn, LPSTR pFileOut)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_DecryptFile(void * p_ckpFunctions, LPSTR pContainerName, LPSTR pFileIn, LPSTR pFileOut)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_SignMessage(void * p_ckpFunctions, LPSTR pContainerName, UINT16 u16Flag, BYTE *pbDataIn,  ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_VerifySignedMessage(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG ulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_GetInfoFromSignedMessage(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_SignDataXML(void * p_ckpFunctions, LPSTR pContainerName, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbDataOut, ULONG *pulDataOutLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_VerifySignedDataXML(void * p_ckpFunctions, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}


	ULONG SOF_GetXMLSignatureInfo(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen, BYTE *pbInfo, ULONG *pulInfoLen)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(SOR_OK);

		return SOR_OK;
	}

	ULONG SOF_GenRandom(void * p_ckpFunctions, UINT16 u16Type, BYTE *pbDataIn, ULONG ulDataInLen)
	{
		ULONG ulResult = SOR_OK;
		CK_SKF_FUNCTION_LIST_PTR ckpFunctions = (CK_SKF_FUNCTION_LIST_PTR)p_ckpFunctions;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");

		ulResult = ckpFunctions->SKF_GenRandom(global_data.hDevHandle, pbDataIn, ulDataInLen);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ulResult = ErrorCodeConvert(ulResult);

		return ulResult;
	}

	ULONG SOF_GetLastError(void * p_ckpFunctions)
	{
		ULONG ulResult = SOR_OK;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "entering");
		ulResult = global_data.last_error;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "exiting");
		ErrorCodeConvert(ulResult);

		return ulResult;
	}


	ULONG SOF_FinalizeLibraryNative(CK_SKF_FUNCTION_LIST_PTR p_ckpFunctions) {
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

	ULONG SOF_InitializeLibraryNative(char *pSKFLibraryPath, CK_SKF_FUNCTION_LIST_PTR *pp_ckpFunctions) {
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
