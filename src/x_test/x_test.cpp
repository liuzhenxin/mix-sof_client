
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <stdio.h>
#include <vector>
#include "sof_client.h"




int main(int argc, char * argv[])
{

	unsigned char szUserList[1024] = { 0 };

	ULONG ulUserListLen = 1024;

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



end:
	

	return getchar();
}