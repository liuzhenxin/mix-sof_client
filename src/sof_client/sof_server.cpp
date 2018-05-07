

#include "mix_server.h"
#include <sys/types.h>


#if defined(WINDOWS) || defined(WIN32)
#include <io.h>
#pragma warning(push, 3)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
typedef int ssize_t;
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <Json/Json.h>

#include "modp_b64.h"

static std::string mix_b64_encode(std::string s)
{
	std::string x(modp_b64_encode_len(s.size()), '\0');
	size_t d = modp_b64_encode(const_cast<char*>(x.data()), s.data(), (int)s.size());
	x.erase(d, std::string::npos);
	s.swap(x);
	return s;
}

/**
* base 64 decode a string (self-modifing)
* On failure, the string is empty.
*
* This function is for C++ only (duh)
*
* \param[in,out] s the string to be decoded
* \return a reference to the input string
*/
static std::string mix_b64_decode(std::string s)
{
	std::string x(modp_b64_decode_len(s.size()), '\0');
	size_t d = modp_b64_decode(const_cast<char*>(x.data()), s.data(), (int)s.size());
	if (d == MODP_B64_ERROR) {
		x.clear();
	}
	else {
		x.erase(d, std::string::npos);
	}
	s.swap(x);
	return s;
}


#define LISTEN_PORT 8484
#if defined(WINDOWS) || defined(WIN32)
DWORD WINAPI run(void *arg)
#else
void *run(void *arg)//thread execute function
#endif
{
	int sockfd = (long)arg;
	int n = 0;
	int i = 0;
	unsigned int json_request_len = 0;
	int ifmtCommandInLen = 0;
	int readlen = 0;
	unsigned char line[512];
	unsigned char *pfmtCommandOut = NULL;
	int ifmtCommandOutLen = 0;
	unsigned char * pfmtCommandIn = NULL;

	printf("ready to read\n");

	while ((n = read(sockfd, line, 512))>0)
	{
		readlen = n;

		// read header until disconnect
		while (readlen < SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE && (n = read(sockfd, line + readlen, 512 - readlen) > 0))
		{
			readlen += n;
		}

		// length not valid
		if (readlen < SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE)
		{
			break;
		}
		printf("readlen=%d\n", readlen);
		// get length
		GET_ULONG_BE(json_request_len, line, SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE);
		printf("json_request_len=%d\n", json_request_len);
		ifmtCommandInLen = json_request_len + SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE;
		printf("ifmtCommandInLen=%d\n", ifmtCommandInLen);
		pfmtCommandIn = (unsigned char *)malloc(ifmtCommandInLen);

		memset(pfmtCommandIn, 0, ifmtCommandInLen);

		memcpy(pfmtCommandIn, line, readlen);

		for (i = 0; i<readlen; i++)
		{
			if (i>32 && i < 37)
			{
				printf("\n%d\n", pfmtCommandIn[i]);
			}
			else
			{
				printf("%c", pfmtCommandIn[i]);
			}
		}

		// read left buffers
		while (readlen < ifmtCommandInLen && (n = read(sockfd, line, 512))>0)
		{
			memcpy(pfmtCommandIn + readlen, line, n);
			readlen += n;
		}

		// length not valid
		if (readlen < ifmtCommandInLen)
		{
			free(pfmtCommandIn);
			break;
		}

		if (mix_server_command_valid(pfmtCommandIn))
		{
			free(pfmtCommandIn);
			break;
		}

		pfmtCommandOut = NULL;
		//ifmtCommandOutLen = 1024*1024;

		mix_server_command_exec(pfmtCommandIn, ifmtCommandInLen, pfmtCommandOut, &ifmtCommandOutLen);
		pfmtCommandOut = (unsigned char *)malloc(ifmtCommandOutLen);
		mix_server_command_exec(pfmtCommandIn, ifmtCommandInLen, pfmtCommandOut, &ifmtCommandOutLen);

		write(sockfd, pfmtCommandOut, ifmtCommandOutLen);

		free(pfmtCommandIn);
		free(pfmtCommandOut);
	}

	printf("end read\n");
	close(sockfd);
	return NULL;
}

void *run_mix_server_thread(void *)
{
	int listenfd, connfd;
	//pid_t childpid;
	socklen_t chilen;
	struct sockaddr_in chiaddr, servaddr;

#if defined(WINDOWS) || defined(WIN32)

	WSADATA wsaData;

	DWORD ulThreadID = 0;

	HANDLE hThrd = 0;

	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error %d\n", err);
		//return false;
	}

#else
	pthread_t tid;

#endif

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
	{
		printf("socket established error: %s\n", (char*)strerror(errno)); return NULL;
	}
#if defined(WINDOWS) || defined(WIN32)
	memset(&servaddr, 0, sizeof(servaddr));
#else
	bzero(&servaddr, sizeof(servaddr));
#endif

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(LISTEN_PORT);

	while (-1 == bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)))
	{
		printf("bind error: %s\n", strerror(errno));


#if defined(WINDOWS) || defined(WIN32)
		Sleep(1000);
#else
		sleep(1);
#endif
	}

	listen(listenfd, 2000);
	for (;;)
	{
		chilen = sizeof(chiaddr);

		connfd = accept(listenfd, (struct sockaddr*)&chiaddr, &chilen);
		if (connfd == -1)
		{
			printf("accept client error: %s\n", strerror(errno)); return NULL;
		}
		else
			printf("client connected\n");
		/*
		if((childpid=fork())==0)
		{
		close(listenfd);
		printf("client from %s\n",inet_ntoa(chiaddr.sin_addr));
		str_echo(connfd);
		exit(0);
		}
		else if (childpid<0)
		printf("fork error: %s\n",strerror(errno));
		*/
		printf("client from %s\n", inet_ntoa(chiaddr.sin_addr));
		//create new thread handle client

#if defined(WINDOWS) || defined(WIN32)
		hThrd = CreateThread(NULL, 0, run, NULL, 0, &ulThreadID);
#else
		pthread_create(&tid, NULL, run, (void *)connfd);
		pthread_detach(tid);
#endif
		//close(connfd);
	}
}



int mix_server_command_valid(unsigned char * pfmtCommandIn)
{
	if (pfmtCommandIn[SERVICE_COMMAND_HEAD_SIZE] != SERVICE_COMMAND_TAG_DATA)
	{
		return -1;
	}

	return 0;
}


Json::Value SFTKSign(Json::Value &parameters, Json::Value &exec_result)
{
	int uiRet = 0;
	/*
	std::string usr_pwd;
	int i_cert_id;
	std::string str_msg;
	int i_hash_alg;
	int i_sign_type;
	unsigned char * pbDataOut = NULL;
	int uiDataOutLen = 0;
	int certIDs[20];
	int certCnt = 20;

	Json::Value paramItem;
	char filepathDB[255] = { 0 };

	memset(filepathDB, 0, 255);
	memcpy(filepathDB, [NSHomeDirectory() UTF8String], [NSHomeDirectory() length]);
	strcat(filepathDB, "/Documents");


	paramItem = parameters[0];
	i_cert_id = paramItem.asInt();

	paramItem = parameters[1];
	str_msg = mix_b64_decode(paramItem.asString());

	paramItem = parameters[2];
	i_hash_alg = paramItem.asInt();

	paramItem = parameters[3];
	i_sign_type = paramItem.asInt();

	paramItem = parameters[4];
	usr_pwd = paramItem.asString();

	// uiRet = SFTK_SetSystemDBDir(filepathDB);
	if (uiRet) {
		goto err;
	}

	uiRet = SFTK_EnumCertIDs(certIDs, &certCnt);
	if (uiRet) {
		goto err;
	}

	uiRet = SFTK_VerifyPIN(usr_pwd.c_str());
	if (uiRet) {
		goto err;
	}

	uiRet = SFTK_Sign(i_cert_id, (unsigned char *)str_msg.c_str(), (int)str_msg.size(), (EHashAlgEnum)i_hash_alg, (ESignTypeEnum)i_sign_type, pbDataOut, &uiDataOutLen);
	if (uiRet) {
		goto err;
	}

	pbDataOut = (unsigned char *)malloc(uiDataOutLen);

	uiRet = SFTK_Sign(i_cert_id, (unsigned char *)str_msg.c_str(), (int)str_msg.size(), (EHashAlgEnum)i_hash_alg, (ESignTypeEnum)i_sign_type, pbDataOut, &uiDataOutLen);
	if (uiRet) {
		goto err;
	}

	exec_result = std::string(mix_b64_encode(std::string((char *)pbDataOut, (char *)pbDataOut + uiDataOutLen)));

err:

	if (pbDataOut)
	{
		free(pbDataOut);
		pbDataOut = NULL;
	}
	*/

	return uiRet;
}

int mix_server_command_exec(unsigned char * pfmtCommandIn, int ifmtCommandInLen, unsigned char *pfmtCommandOut, int *pifmtCommandOutLen)
{
	unsigned int json_request_len = 0;
	unsigned int json_response_len = 0;

	Json::Value json_value_common_call;
	Json::Reader json_reader;
	Json::Value values;
	Json::Value items;
	bool bFlag = false;

	GET_ULONG_BE(json_request_len, pfmtCommandIn, SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE);

	bFlag = json_reader.parse((const char*)pfmtCommandIn + SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE, json_value_common_call);

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

		/*
		if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKVerifyPIN"))
		{
			values["exec_status"] = SFTKVerifyPIN(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKChangePIN"))
		{
			values["exec_status"] = SFTKChangePIN(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKUnlockUserPIN"))
		{
			values["exec_status"] = SFTKUnlockUserPIN(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKImportPfx"))
		{
			values["exec_status"] = SFTKImportPfx(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKEnumCertIDs"))
		{
			values["exec_status"] = SFTKEnumCertIDs(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKGetCertAttribute"))
		{
			values["exec_status"] = SFTKGetCertAttribute(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKGetCertBuf"))
		{
			values["exec_status"] = SFTKGetCert(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKSign"))
		{
			values["exec_status"] = SFTKSign(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKVerify"))
		{
			values["exec_status"] = SFTKVerify(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKEncryptMsg"))
		{
			values["exec_status"] = SFTKEncryptMsg(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKDecryptMsg"))
		{
			values["exec_status"] = SFTKDecryptMsg(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKPubkeyEncrypt"))
		{
			values["exec_status"] = SFTKPubkeyEncrypt(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKPrikeyDecrypt"))
		{
			values["exec_status"] = SFTKPrikeyDecrypt(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKDeleteCert"))
		{
			values["exec_status"] = SFTKDeleteCert(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKEncryptMsgInner"))
		{
			values["exec_status"] = SFTKEncryptMsgInner(exec_arg_real_list, exec_result);
		}
		else if (0 == strcmp(json_value_common_call["exec_name"].asCString(), "SFTKPubkeyEncryptInner"))
		{
			values["exec_status"] = SFTKPubkeyEncryptInner(exec_arg_real_list, exec_result);
		}
		else
		{
			values["exec_status"] = EStateFailure;
			values["exec_error"] = "Invalid command";
		}
		*/

		values["exec_result"] = exec_result;
		values["exec_name"] = json_value_common_call["exec_name"];
	}
	else
	{
		values["exec_status"] = -1;
		values["exec_error"] = "Invalid command";
	}

	// return values
	json_response_len = values.toStyledString().length();

	printf("values=%s", values.toStyledString().c_str());

	if (*pifmtCommandOutLen < SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE + json_response_len)
	{
		*pifmtCommandOutLen = SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE + json_response_len;
	}
	else
	{
		*pifmtCommandOutLen = SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE + json_response_len;
		memset(pfmtCommandOut, 'H', SERVICE_COMMAND_HEAD_SIZE);
		pfmtCommandOut[SERVICE_COMMAND_HEAD_SIZE] = SERVICE_COMMAND_TAG_DATA;
		PUT_ULONG_BE(json_response_len, pfmtCommandOut, SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE);
		memcpy(pfmtCommandOut + SERVICE_COMMAND_HEAD_SIZE + SERVICE_COMMAND_TAG_SIZE + SERVICE_COMMAND_LEN_SIZE, values.toStyledString().c_str(), json_response_len);
	}

	return 0;
}

int main(int argc,char *argv[])
{
	run_mix_server_thread(NULL);

	return 0;
}