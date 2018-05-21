
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <stdio.h>
#include <vector>
#include "sof_client.h"

#include "FILE_LOG.h"

#include "modp_b64.h"

#define DEFAULT_CON_RSA "d249e49c-340e-446a-8adb-4e3d1ac1c129"
//#define DEFAULT_CON_SM2 "RT_SM_CON"
#define DEFAULT_CON_SM2  "d249e49c-340e-446a-8adb-4e3d1ac1c129"

int main(int argc, char * argv[])
{

	unsigned char szUserList[1024] = { 0 };

	ULONG ulUserListLen = 1024;

	unsigned char plain[4096] = { 0 };
	unsigned char * signature = new unsigned char[1024 * 8];
	unsigned char * sign_cert = new unsigned char[1024 * 8];
	unsigned char * crypt_cert = new unsigned char[1024 * 8];
	unsigned char * crypt_data = new unsigned char[1024 * 8];
	unsigned char * plain_data = new unsigned char[1024 * 8];

	ULONG plain_len = sizeof(plain);
	ULONG sign_cert_len = 1024 * 8;
	ULONG crypt_cert_len = 1024 * 8;
	ULONG crypt_data_len = 1024 * 8;
	ULONG plain_data_len = 1024 * 8;
	ULONG signature_len = 1024 * 8;
	int i = 0;

	unsigned char info[2048] = { 0 };
	ULONG info_len  = sizeof(info);
	
	char * container_used = DEFAULT_CON_RSA;

	CK_SKF_FUNCTION_LIST *ckpFunctions = NULL;

	ULONG ulResult = 0;

	std::string strcert = "MEYCIQCgJSKu8nRnMXSVgdZYoBRF6S1sM8SA7d8VFuKR8Vz2fgIhANL1t74+6FsN0mWw6ZijogxK9JAC3vZeFoOhGwgC135J";

	std::string strcert2 = strcert;

	strcert2 = modp_b64_decode(strcert2);

	strcert2 = modp_b64_encode(strcert2);

	if (0 == strcmp(strcert2.c_str(), strcert.c_str()))
	{
		printf("success!");
	}


	const char * xmlData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
		"<!-- \n" \
		"XML Security Library example: Original XML doc file for sign3 example. \n" \
		"-->\n" \
		"<Envelope xmlns=\"urn:envelope\">\n" \
		"  <Data>\n" \
		"	Hello,ABCDEFG World!\n" \
		"  </Data>\n" \
		"</Envelope>\n";


	ulResult = SOF_InitializeLibraryNative("mtoken_gm3000.dll", &ckpFunctions);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_GetUserList(ckpFunctions, szUserList, &ulUserListLen);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_Login(ckpFunctions, container_used, "88888888");
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_ExportUserCert(ckpFunctions, container_used, sign_cert, &sign_cert_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_ExportExChangeUserCert(ckpFunctions, container_used, crypt_cert, &crypt_cert_len);
	if (ulResult)
	{
		goto end;
	}


	ulResult = SOF_PubKeyEncrypt(ckpFunctions, crypt_cert, crypt_cert_len, (BYTE*)sign_cert, 256, crypt_data, & crypt_data_len);
	if (ulResult)
	{
		goto end;
	}


	//ulResult = SOF_PriKeyDecrypt(ckpFunctions, container_used, crypt_data, crypt_data_len, plain_data, & plain_len);
	if (ulResult)
	{
		goto end;
	}


	ulResult = SOF_SetSignMethod(ckpFunctions, SGD_SHA1_RSA);
	if (ulResult)
	{
		goto end;
	}

	plain_len = 4;
	signature_len = 1024 * 8;
	ulResult = SOF_SignMessage(ckpFunctions, container_used, 0, plain, plain_len, signature, &signature_len);
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
	plain_len = 4;
	signature_len = 1024 * 8;
	ulResult = SOF_SignMessage(ckpFunctions, container_used, 1, plain, plain_len, signature, &signature_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_VerifySignedMessage(ckpFunctions, signature, signature_len, plain, plain_len);
	if (ulResult)
	{
		goto end;
	}
	signature_len = 1024 * 8;
	ulResult = SOF_SignDataXML(ckpFunctions, container_used, (BYTE*)xmlData, strlen(xmlData), signature, &signature_len);
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
	


	//ulResult = SOF_SignData(ckpFunctions, container_used, plain, plain_len, signature, &signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	//ulResult = SOF_VerifySignedData(ckpFunctions, sign_cert, sign_cert_len, plain, plain_len, signature, signature_len);
	//if (ulResult)
	//{
	//	goto end;
	//}

	

	signature_len = 1024 * 8;
	ulResult = SOF_SignFile(ckpFunctions, container_used, "D:/test.txt", signature, &signature_len);
	if (ulResult)
	{
		goto end;
	}

	ulResult = SOF_VerifySignedFile(ckpFunctions, sign_cert, sign_cert_len, "D:/test.txt", signature, signature_len);
	if (ulResult)
	{
		goto end;
	}


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


	ulResult = SOF_DecryptFile(ckpFunctions, container_used, "D:/cipher.txt", "D:/plain.txt" );
	if (ulResult)
	{
		goto end;
	}


end:
	

	return getchar();
}