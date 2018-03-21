
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
	unsigned char * signature = new unsigned char[1024 * 8];
	unsigned char * sign_cert = new unsigned char[1024 * 8];
	unsigned char * crypt_cert = new unsigned char[1024 * 8];

	ULONG plain_len = sizeof(plain);
	ULONG sign_cert_len = 1024 * 8;
	ULONG crypt_cert_len = 1024 * 8;
	ULONG signature_len = 1024 * 8;
	int i = 0;

	unsigned char info[2048] = { 0 };
	ULONG info_len  = sizeof(info);
	

	CK_SKF_FUNCTION_LIST *ckpFunctions = NULL;

	ULONG ulResult = 0;

	const char * xmlData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
		"<!-- \n" \
		"XML Security Library example: Original XML doc file for sign3 example. \n" \
		"-->\n" \
		"<Envelope xmlns=\"urn:envelope\">\n" \
		"  <Data>\n" \
		"	Hello,ABCDEFG World!\n" \
		"  </Data>\n" \
		"</Envelope>\n";


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

	ulResult = SOF_Login(ckpFunctions, "11-rsa", "88888888");
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_ExportUserCert(ckpFunctions, "11-rsa", sign_cert, &sign_cert_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_ExportExChangeUserCert(ckpFunctions, "11-rsa", crypt_cert, &crypt_cert_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_SetSignMethod(ckpFunctions, SGD_SM3_RSA);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_SignDataXML(ckpFunctions, "11-rsa", (BYTE*)xmlData, strlen(xmlData), signature, &signature_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_VerifySignedDataXML(ckpFunctions, signature, signature_len);
	if (ulResult)
	{
		goto end;
	}

	for (i = 1; i < 7; i++)
	{
		info_len = sizeof(info);
		memset(info, 0, info_len);
		ulResult = SOF_GetXMLSignatureInfo(ckpFunctions, i, signature, signature_len, info, &info_len);
		if (ulResult)
		{
			goto end;
		}
		printf("%s\n", info);
	}
	

	signature_len = 1024 * 8;
	ulResult = SOF_SignMessage(ckpFunctions, "11-rsa", 0, plain, plain_len, signature, &signature_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_VerifySignedMessage(ckpFunctions, signature, signature_len, NULL, 0);
	if (ulResult)
	{
		goto end;
	}

	for (i = 1; i < 4; i++)
	{
		info_len = sizeof(info);
		ulResult = SOF_GetInfoFromSignedMessage(ckpFunctions, i, signature, signature_len, info, &info_len);
		if (ulResult)
		{
			goto end;
		}
	}
	


	signature_len = 1024 * 8;
	ulResult = SOF_SignMessage(ckpFunctions, "11-rsa", 1, plain, plain_len, signature, &signature_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_VerifySignedMessage(ckpFunctions, signature, signature_len, plain, plain_len);
	if (ulResult)
	{
		goto end;
	}

	//ulResult = SOF_SignData(ckpFunctions, "11-rsa", plain, plain_len, signature, &signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_VerifySignedData(ckpFunctions, sign_cert, sign_cert_len, plain, plain_len, signature, signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	

	//signature_len = 1024 * 8;
	//ulResult = SOF_SignFile(ckpFunctions, "11-rsa", "D:/test.txt", signature, &signature_len);
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


	ulResult = SOF_DecryptFile(ckpFunctions, "11-rsa", "D:/cipher.txt", "D:/plain.txt" );
	if (ulResult)
	{
		goto end;
	}


end:
	

	return getchar();
}