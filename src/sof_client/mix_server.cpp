

#include "mix_server.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <Json/Json.h>
#include "FBWTSofPluginAPI.h"

int http_server_command_exec(std::string pfmtCommandIn, std::string &pfmtCommandOut, FBWTSofPluginAPI *pFBWTSofPluginAPI)
{
	unsigned int json_request_len = 0;
	unsigned int json_response_len = 0;

	Json::Value json_value_common_call;
	Json::Reader json_reader;
	Json::Value values;
	Json::Value items;
	bool bFlag = false;

	bFlag = json_reader.parse((const char*)pfmtCommandIn.c_str(), json_value_common_call);

	// exec_type exec_name exec_result exec_error
	if (bFlag)
	{
		Json::Value exec_arg_real_list = json_value_common_call["exec_arg_real_list"];

		Json::Value exec_result;

		if (exec_arg_real_list.type() == Json::nullValue)
		{
			//printf("exec_arg_real_list=%s\n","NULL");
		}
		else
		{
			//printf("exec_arg_real_list=%s\n",exec_arg_real_list.toStyledString().c_str());
		}

		if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_FinalizeLibraryNative"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_FinalizeLibraryNative();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_InitializeLibraryNative"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_InitializeLibraryNative(exec_arg_real_list[0].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetLastError"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_GetLastError();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_Logout"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_Logout();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_PriKeyDecryptLongData"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_PriKeyDecryptLongData(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_PubKeyEncryptLongData"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_PubKeyEncryptLongData(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_PriKeyDecrypt"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_PriKeyDecrypt(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_PubKeyEncrypt"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_PubKeyEncrypt(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GenRandom"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GenRandom(exec_arg_real_list[0].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetXMLSignatureInfo"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetXMLSignatureInfo(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_VerifySignedDataXML"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_VerifySignedDataXML(exec_arg_real_list[0].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_SignDataXML"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_SignDataXML(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetInfoFromSignedMessage"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetInfoFromSignedMessage(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_VerifySignedMessage"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_VerifySignedMessage(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_SignMessage"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_SignMessage(exec_arg_real_list[0].asInt(), exec_arg_real_list[1].asCString(), exec_arg_real_list[2].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_DecryptFile"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_DecryptFile(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString(), exec_arg_real_list[2].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_EncryptFile"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_EncryptFile(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString(), exec_arg_real_list[2].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_DecryptData"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_DecryptData(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_EncryptData"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_EncryptData(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_VerifySignedFile"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_VerifySignedFile(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString(), exec_arg_real_list[2].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_SignFile"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_SignFile(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_VerifySignedData"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_VerifySignedData(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString(), exec_arg_real_list[2].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_SignData"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_SignData(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_ValidateCert"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_ValidateCert(exec_arg_real_list[0].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetDeviceInfo"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetDeviceInfo(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetCertInfoByOid"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetCertInfoByOid(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetCertInfo"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetCertInfo(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_ExportExChangeUserCert"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_ExportExChangeUserCert(exec_arg_real_list[0].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_ChangePassWd"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_ChangePassWd(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString(), exec_arg_real_list[2].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetPinRetryCount"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_GetPinRetryCount(exec_arg_real_list[0].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_Login"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_Login(exec_arg_real_list[0].asCString(), exec_arg_real_list[1].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_ExportUserCert"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_ExportUserCert(exec_arg_real_list[0].asCString());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetUserList"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetUserList();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetEncryptMethod"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_GetEncryptMethod();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_SetEncryptMethod"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_SetEncryptMethod(exec_arg_real_list[0].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetSignMethod"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_GetSignMethod();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_SetSignMethod"))
		{
			exec_result = (int)pFBWTSofPluginAPI->SOF_SetSignMethod(exec_arg_real_list[0].asInt());
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SOF_GetVersion"))
		{
			exec_result = pFBWTSofPluginAPI->SOF_GetVersion();
			values["exec_status"] = (int)pFBWTSofPluginAPI->SOF_GetLastError();
		}
		else
		{
			values["exec_status"] = SOR_UNKNOWNERR;
			values["exec_error"] = "Invalid command";
		}
		

		values["exec_result"] = exec_result;
		values["exec_name"] = json_value_common_call["exec_name"];
	}
	else
	{
		values["exec_status"] = -1;
		values["exec_error"] = "Invalid command";
	}

	// return values
	pfmtCommandOut = values.toStyledString();

	return 0;
}



