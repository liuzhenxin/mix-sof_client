
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <stdio.h>
#include <vector>
#include "sof_client.h"

#include "FILE_LOG.h"


int main(int argc, char * argv[])
{

	unsigned char szUserList[1024] = { 0 };

	ULONG ulUserListLen = 1024;

	unsigned char plain[32] = { 0 };
	unsigned char signature[2048] = { 0 };
	unsigned char sign_cert[2048] = { 0 };
	unsigned char crypt_cert[2048] = { 0 };

	ULONG plain_len = sizeof(plain);
	ULONG sign_cert_len = sizeof(sign_cert);
	ULONG crypt_cert_len = sizeof(crypt_cert);
	ULONG signature_len = sizeof(signature);
	int i = 0;

	unsigned char info[2048] = { 0 };
	ULONG info_len  = sizeof(info);
	

	CK_SKF_FUNCTION_LIST *ckpFunctions = NULL;

	ULONG ulResult = 0;

	ulResult = SOF_InitializeLibraryNative("WTSKFInterface.dll", &ckpFunctions);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_GetUserList(ckpFunctions, szUserList, &ulUserListLen);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_Login(ckpFunctions, "RT_SM_CON", "88888888");
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_ExportUserCert(ckpFunctions, "RT_SM_CON", sign_cert, &sign_cert_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_ExportExChangeUserCert(ckpFunctions, "RT_SM_CON", crypt_cert, &crypt_cert_len);
	if (ulResult)
	{
		goto end;
	}

	//ulResult = SOF_SetSignMethod(ckpFunctions, SGD_SM3_SM2);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_SignData(ckpFunctions, "RT_SM_CON", plain, plain_len, signature, &signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_VerifySignedData(ckpFunctions, sign_cert, sign_cert_len, plain, plain_len, signature, signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}
	//signature_len = sizeof(signature);
	//ulResult = SOF_SignMessage(ckpFunctions, "RT_SM_CON",0, plain, plain_len, signature, &signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_VerifySignedMessage(ckpFunctions,signature, signature_len, NULL, 0);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//for (i = 1; i < 4; i++)
	//{
	//	info_len = sizeof(info);
	//	ulResult = SOF_GetInfoFromSignedMessage(ckpFunctions, i, signature, signature_len, info, &info_len);
	//	if (ulResult)
	//	{
	//		goto end;
	//	}
	//}
	//


	//signature_len = sizeof(signature);
	//ulResult = SOF_SignMessage(ckpFunctions, "RT_SM_CON", 1, plain, plain_len, signature, &signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_VerifySignedMessage(ckpFunctions, signature, signature_len, plain, plain_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//signature_len = sizeof(signature);
	//ulResult = SOF_SignFile(ckpFunctions, "RT_SM_CON", "D:/test.txt", signature, &signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_VerifySignedFile(ckpFunctions, sign_cert, sign_cert_len, "D:/test.txt", signature, signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}


	ulResult = SOF_SetEncryptMethod(ckpFunctions, SGD_SM1_ECB);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_EncryptFile(ckpFunctions, crypt_cert, crypt_cert_len, "D:/test.txt", "D:/cipher.txt");
	if (ulResult)
	{
		goto end;
	}


	ulResult = SOF_DecryptFile(ckpFunctions, "RT_SM_CON", "D:/cipher.txt", "D:/plain.txt" );
	if (ulResult)
	{
		goto end;
	}


end:
	

	return getchar();
}