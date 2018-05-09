/*******************************************************
 *
 * 使用此JS脚本之前请先仔细阅读YDXToken KEY帮助文档
 * 
 * @author		Longmai
 * @version		3.0
 * @date		2015/9/25
 * @explanation	 YDXToken Plugin 支持各浏览器
 *
**********************************************************/
	
	var token = new YDXToken("YDXTokenPlugin");
	
	//动态添加option选项
	function addOption(optionStr, selectID)
	{	
		selectID.options.add(new Option(optionStr, optionStr));
	}
	
	function InitializeLibraryNative()
	{	
		var slectType = document.getElementById("SKFInterface").value;
		var ret = 0;
		
		if(slectType == "WTSKFInterface.dll")
		{
			ret = token.SOF_InitializeLibraryNative("WTSKFInterface.dll");
		}	
		
		if(token.TRUE == ret)
		{
			alert("加载控件成功!");
		}
		else
		{
			alert("加载控件失败,错误码:" + token.SOF_GetLastError());
			return ;
		}
		
	}
	
	//获取证书列表
	function GetUserList()
	{
		var cerlistID = document.getElementById("sele_contentList");
		cerlistID.options.length = 0;
		
		var userList = token.SOF_GetUserList();
		
		if(userList != null && userList.length > 0)
		{
			var arrList = userList.split("&&&");
			
			for(var i = 0; i < arrList.length; ++i)
			{
				addOption(arrList[i].split("||")[1], cerlistID);
			}
		}
						
		else if(userList == null)
			alert("设备中无证书");
		else
			alert("获取证书列表失败,错误码:" + token.SOF_GetLastError());
	}
	
	//验证用户密码
	function Login()
	{
		var pin = document.getElementById("txt_pwd").value;	
		var ret = token.SOF_Login(document.getElementById("sele_contentList").value, pin);			
		if(token.TRUE != ret)
		{	
	
			alert("验证用户密码失败,错误码:" + token.SOF_GetLastError());
			
			var retryCount = token.SOF_GetPinRetryCount(document.getElementById("sele_contentList").value);	
			
			document.getElementById("tryCount").innerText = "剩余次数：" + retryCount;
			
			return;
		}
		else
		{
			document.getElementById("tryCount").innerText = "";
			alert("验证用户密码通过");
		}
				
	}
	
	//修改密码
	function ChangePassWd()
	{
		var pin = document.getElementById("txt_pwd").value;	
		var resetPin = document.getElementById("txt_Changepwd").value;
		var ret = token.SOF_ChangePassWd("", pin, resetPin);
		if(token.TRUE != ret)
		{
			alert("密码修改失败,错误码:" + token.SOF_GetLastError());
		}
		else
		{
			alert("密码修改成功");
		}	
	}
	
	//控件版本信息
	 function GetVersion()
    {
        var version = token.SOF_GetVersion();
		document.getElementById("contorlInfo").value = version;			
    }	
	
	//导出证书信息
	function ExportUserCert()
	{
		document.getElementById("cerInfo").value = "";	
		
		var container = document.getElementById("sele_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var selectType = document.getElementById("sele_cerType");
		
		
		var cerType = selectType.options[selectType.selectedIndex].value;
		
		var cert = null;
		
		if(cerType == 0)
		{
			cert = token.SOF_ExportExChangeUserCert(containerName);
		}
		else if(cerType == 1)
		{
			cert = token.SOF_ExportUserCert(containerName);
		}
		
		if(cert != null && cert != "")
		{
			document.getElementById("cerInfo").value = cert;	
		}
		else
			alert("获取证书信息失败,错误码:" + token.SOF_GetLastError());
	}
	
	//获取证书信息
	function GetCertInfo()
	{
		signCert = document.getElementById("cerInfo").value;
		if(signCert == "")
			{
				alert("请先导出证书");
				return;	
			}
		var showCer = document.getElementById("showcerInfo");
		
		showCer.value = "";
		var cerInfo = "";
		var str = token.SOF_GetCertInfo(signCert, token.SGD_CERT_ISSUER_CN);
		cerInfo += "Issuer: " + str + "\r";
		
		str = token.SOF_GetCertInfo(signCert, token.SGD_CERT_SUBJECT);
		cerInfo += "Subject: " + str + "\r";
		str = token.SOF_GetCertInfo(signCert, token.SGD_CERT_SUBJECT_CN);
		cerInfo += "Subject_CN: " + str + "\r";
		str = token.SOF_GetCertInfo(signCert, token.SGD_CERT_SUBJECT_EMALL);
		cerInfo += "Subject_EMail: " + str + "\r";
		str = token.SOF_GetCertInfo(signCert, token.SGD_CERT_SERIAL);
		cerInfo += "Serial: " + str + "\r";
		str = token.SOF_GetCertInfo(signCert, token.SGD_CERT_CRL);
		cerInfo += "cRLDistributionPoints: " + str + "\r";
		
		//cerInfo += "如需获取更多信息请查看帮助文档";
		
		showCer.value = cerInfo;
	}
	
	//获取设备信息
	function GetDeviceInfo()
	{
		var container = document.getElementById("sele_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var deviceInfo = document.getElementById("deviceInfo");
		deviceInfo.value = "";
		var strInfo;
		var str = token.SOF_GetDeviceInfo(containerName, token.SGD_DEVICE_NAME);
		strInfo = "Device name: " + str + "\r";
		
		var str = token.SOF_GetDeviceInfo(containerName, token.SGD_DEVICE_SUPPORT_STORANGE_SPACE);
		strInfo += "Device total space: " + str + "\r";
		
		var str = token.SOF_GetDeviceInfo(containerName, token.SGD_DEVICE_SUPPORT_FREE_SAPCE);
		strInfo += "Device free space: " + str + "\r";
		
		var str = token.SOF_GetDeviceInfo(containerName, token.SGD_DEVICE_HARDWARE_VERSION);
		strInfo += "Hardware version: " + str + "\r";
		
		var str = token.SOF_GetDeviceInfo(containerName, token.SGD_DEVICE_SERIAL_NUMBER);
		strInfo += "Device serial number: " + str + "\r";
		
		var str = token.SOF_GetDeviceInfo(containerName, token.SGD_DEVICE_MANUFACTURER);
		strInfo += "Device manufacturer: " + str + "\r";
		
		//strInfo += "如需获取更多信息请查看帮助文档";
		
		deviceInfo.value = strInfo;
	}
	
	function SetSignMethod()
	{
		var mech = document.getElementById("signMech").value;
		var ret = token.SOF_SetSignMethod(Number(mech));
		if(token.SAR_OK != ret)
		{
			alert("操作失败,错误码:" + token.SOF_GetLastError());
		}
		else
		{
			alert("操作成功");
		}	
	}
	
	function GetSignMethod()
	{
		var ret = token.SOF_GetSignMethod();
		
		if(token.SGD_SM3_RSA == ret){
			alert("SGD_SM3_RSA");
		}
		else if(token.SGD_SHA1_RSA == ret){
			alert("SGD_SHA1_RSA");
		}
		else if(token.SGD_SHA256_RSA == ret){
			alert("SGD_SHA256_RSA");
		}
		else if(token.SGD_SM3_SM2 == ret){
			alert("SGD_SM3_SM2");
		}
		else{
			alert("操作失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	function SetEncryptMethod()
	{
		var mech = document.getElementById("encMech").value;
		var ret = token.SOF_SetEncryptMethod(Number(mech));
		if(token.SAR_OK != ret)
		{
			alert("操作失败,错误码:" + token.SOF_GetLastError());
		}
		else
		{
			alert("操作成功");
		}	
	}
	
	function GetEncryptMethod()
	{
		var ret = token.SOF_GetEncryptMethod();
		
		if(token.SGD_SM1_ECB == ret){
			alert("SGD_SM1_ECB");
		}
		else if(token.SGD_SM1_CBC == ret){
			alert("SGD_SM1_CBC");
		}
		else if(token.SGD_SM1_CFB == ret){
			alert("SGD_SM1_CFB");
		}
		else if(token.SGD_SM1_OFB == ret){
			alert("SGD_SM1_OFB");
		}
		
		else if(token.SGD_SSF33_ECB == ret){
			alert("SGD_SSF33_ECB");
		}
		else if(token.SGD_SSF33_CBC == ret){
			alert("SGD_SSF33_CBC");
		}
		else if(token.SGD_SSF33_CFB == ret){
			alert("SGD_SSF33_CFB");
		}
		else if(token.SGD_SSF33_OFB == ret){
			alert("SGD_SSF33_OFB");
		}
		else if(token.SGD_SM4_ECB == ret){
			alert("SGD_SM4_ECB");
		}
		else if(token.SGD_SM4_CBC == ret){
			alert("SGD_SM4_CBC");
		}
		else if(token.SGD_SM4_CFB == ret){
			alert("SGD_SM4_CFB");
		}
		else if(token.SGD_SM4_OFB == ret){
			alert("SGD_SM4_OFB");
		}
		else{
			alert("操作失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	
	

	//数据签名
	function signData()
	{
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 0)
		{
			alert("请选择签名密钥进行签名");
			return ;
		}
		var DigestMethod = document.getElementById("mech").value;
		var inData = document.getElementById("originalData").value;
		var ret = token.SOF_SetDigestMethod(Number(DigestMethod));
			
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请先枚举容器后操作");
			return;
		}
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		var signed = token.SOF_SignDataEx(containerName, cerType, inData, inData.length);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	
	var signed;
	//数据签名
	function signData_P7()
	{
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 0)
		{
			alert("请选择签名密钥进行签名");
			return ;
		}
		var DigestMethod = document.getElementById("mech").value;
		var userID = document.getElementById("userID").value;
		var inData = document.getElementById("originalData").value;
		var ret = token.SOF_SetDigestMethod(Number(DigestMethod));
			ret = token.SOF_SetUserID(userID);
			
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请先枚举容器后操作");
			return;
		}
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		

		signed = token.SOF_SignDataToPKCS7(containerName, cerType, inData, inData.length, 0);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	//文件签名
	function signFile()
	{	
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 0)
		{
			alert("请选择签名密钥进行签名");
			return ;
		}
		var DigestMethod = document.getElementById("mech").value;
		var userID = document.getElementById("userID").value;
		var inFile = document.getElementById("signFile").value;
		var ret = token.SOF_SetDigestMethod(Number(DigestMethod));
			ret = token.SOF_SetUserID(userID);
			
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请先枚举容器后操作");
			return;
		}
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		

		var signed = token.SOF_SignFileToPKCS7(containerName, cerType, inFile, 1);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	//数据验签
	function verifySignFile()
	{
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 0)
		{
			alert("请选择签名密钥进行签名");
			return ;
		}
		var DigestMethod = document.getElementById("mech").value;
		var userID = document.getElementById("userID").value;
		var inFile = document.getElementById("signFile").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var selectType = document.getElementById("sele_cerType");
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		var ret = token.SOF_SetDigestMethod(Number(DigestMethod));
			ret = token.SOF_SetUserID(userID);
			ret = token.SOF_VerifyFileToPKCS7(signed, inFile, 1);
		if(ret != 0)
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		else
			alert("验签成功");
	}
	
	//数据验签
	function verifySign()
	{
		var DigestMethod = document.getElementById("mech").value;
		var userID = document.getElementById("userID").value;
		var inData = document.getElementById("originalData").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var selectType = document.getElementById("sele_cerType");
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		var cerType = selectType.options[selectType.selectedIndex].value;
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		var ret = token.SOF_SetDigestMethod(Number(DigestMethod));
			ret = token.SOF_SetUserID(userID);
			ret = token.SOF_VerifySignedDataEx(cert, inData, signed);
		if(ret != 0)
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		else
			alert("验签成功");
	}
	
	//数据验签
	function verifySign_P7()
	{
		var DigestMethod = document.getElementById("mech").value;
		var userID = document.getElementById("userID").value;
		var inData = document.getElementById("originalData").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var selectType = document.getElementById("sele_cerType");
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		var cerType = selectType.options[selectType.selectedIndex].value;
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		var ret = token.SOF_SetDigestMethod(Number(DigestMethod));
			ret = token.SOF_SetUserID(userID);
			ret = token.SOF_VerifyDataToPKCS7(signed, inData, 0);
		if(ret != 0)
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		else
			alert("验签成功");
	}
	//数据加密
	function encryptData()
	{
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 1)
		{
			alert("请选择加密证书进行加密");
			return ;
		}
		var DigestMethod = document.getElementById("encrymech").value;
		var iv = document.getElementById("iv").value;
		var inData = document.getElementById("enData").value;
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		token.SOF_SetEncryptMethodAndIV(DigestMethod, iv);
		var encrypedData = token.SOF_EncryptData(cert, inData, inData.length);
		if(encrypedData != null || encrypedData == "")
			document.getElementById("enedData").value = encrypedData;
		else
			alert("加密失败,错误码:" + token.SOF_GetLastError());
	}
	
	function encryptData_P7()
	{
	var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 1)
		{
			alert("请选择加密证书进行加密");
			return ;
		}
		var DigestMethod = document.getElementById("encrymech").value;
		var iv = document.getElementById("iv").value;
		var inData = document.getElementById("enData").value;
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		token.SOF_SetEncryptMethodAndIV(DigestMethod, iv);
		var encrypedData = token.SOF_SignDataToPKCS7(containerName, cerType, inData, inData.length, 0);
		if(encrypedData != null || encrypedData == "")
			document.getElementById("enedData").value = encrypedData;
		else
			alert("加密失败,错误码:" + token.SOF_GetLastError());	
	}
	
	//数据加密
	function encryptFile()
	{
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		if(cerType == 1)
		{
			alert("请选择加密证书进行加密");
			return ;
		}
		var DigestMethod = document.getElementById("encrymech").value;
		var iv = document.getElementById("iv").value;
		var inData = document.getElementById("enFile").value;
		var OutData = document.getElementById("enDstFile").value;
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
				
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		
		
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		token.SOF_SetEncryptMethodAndIV(DigestMethod, iv);
		var envelopData = token.SOF_EncryptFileToPKCS7(cert, inData, OutData, 1);
		if(envelopData != null)
			document.getElementById("enedData").value = envelopData;
		else
			alert("加密失败,错误码:" + token.SOF_GetLastError());
	}
	
	function decryptFile()
	{
		var DigestMethod = document.getElementById("encrymech").value;
		var iv = document.getElementById("iv").value;
		var outFile = document.getElementById("enFile").value;
		var inData = document.getElementById("enDstFile").value;
		var encrypedData = document.getElementById("enedData").value;
		if(encrypedData == null || encrypedData.length <= 0)
		{
			alert("请先加密后操作");
			return;
		}
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		token.SOF_SetEncryptMethodAndIV(DigestMethod, iv);
		
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		
		outFile = outFile + ".plainText";
		decryptedData = token.SOF_DecryptFileToPKCS7(containerName, cerType, encrypedData, inData, outFile, 1);
		if(decryptedData != 0)
			alert("解密失败,错误码:" + token.SOF_GetLastError());
		else
		{
			document.getElementById("deData").value = outFile;
			alert("解密文件成功，目标文件:" + outFile);
		}
	}
		
	//数据解密
	function decryptData()
	{
		var DigestMethod = document.getElementById("encrymech").value;
		var iv = document.getElementById("iv").value;
		var encrypedData = document.getElementById("enedData").value;
		if(encrypedData == null || encrypedData.length <= 0)
		{
			alert("请先加密后操作");
			return;
		}
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		token.SOF_SetEncryptMethodAndIV(DigestMethod, iv);
		
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		
		decryptedData = token.SOF_DecryptData(containerName, cerType, encrypedData);
		if(decryptedData != null && decryptedData != "")
			document.getElementById("deData").value = decryptedData;
		else
			alert("解密失败,错误码:" + token.SOF_GetLastError());
	}
	
	
	
	//对数据做摘要
	function digestData()
	{
		var DigestMethod = document.getElementById("digestmech").value;
		var inData = document.getElementById("digestData").value;	
		var userID = document.getElementById("userID").value;		
		token.SOF_SetDigestMethod(DigestMethod);
		ret = token.SOF_SetUserID(userID);
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}

		digest = token.SOF_DigestData(containerName, inData, inData.length);
		if(digest != null)
			document.getElementById("digestedData").value = digest;
		else
			alert("数据摘要失败,错误码:" + token.SOF_GetLastError());
	}
	
	
	function GenRemoteUnlockPin()
	{
		var request = token.SOF_GenRemoteUnblockRequest();
		if(request == null || request == "")
		{
			alert("生成解锁请求失败");
			return;
		}
		
		document.getElementById("remoteUnlockPin").value = request;
	}
	
	function GenUnlockPinResponse()
	{
		var encrypedData = document.getElementById("remoteUnlockPin").value;
		var SoPinData = document.getElementById("SoPinData").value;
		var UserData = document.getElementById("newPinData").value;
		var request = token.SOF_GenResetpwdResponse(encrypedData, SoPinData, UserData);
		if(request == null || request == "")
		{
			alert("生成解锁请求失败");
			return;
		}
		
		document.getElementById("remoteUnlockPin").value = request;
	}
	
	
	function RemoteUnlockPin()
	{
		var encrypedData = document.getElementById("remoteUnlockPin").value;
		var request = token.SOF_RemoteUnblockPIN(encrypedData);
		if(request != 0)
		{
			alert("解锁失败");
			return;
		}
		else
		{
			alert("解锁成功");
		}
	}
	
	function exportPubKey()
	{
		document.getElementById("PubKey").value = "";	
		
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var selectType = document.getElementById("sele_cerType");
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		var cerType = selectType.options[selectType.selectedIndex].value;
		var strPubKey  = token.SOF_ExportPubKey(containerName, cerType);
		if(strPubKey != null && strPubKey != "")
		{
			document.getElementById("PubKey").value = strPubKey;	
		}
		else
			alert("获取公钥失败,错误码:" + token.SOF_GetLastError());
	}
	
	function encryptbyPubKey()
	{
		var strPubKey = document.getElementById("PubKey").value;
		var strInput = document.getElementById("AsymPlain").value;
		
		var selectType = document.getElementById("sele_cerType");
		var cerType = selectType.options[selectType.selectedIndex].value;
		
		var strAsymCipher = token.SOF_EncryptbyPubKey(strPubKey, strInput, cerType);
		if(strAsymCipher != null && strAsymCipher != "")
		{
			document.getElementById("AsymCipher").value = strAsymCipher;	
		}
		else
			alert("公钥加密失败,错误码:" + token.SOF_GetLastError());
	}
	
	function decryptbyPrvKey()
	{
		var container = document.getElementById("sele_contentList");
		if(container.selectedIndex < 0)
		{
			alert("请选择容器操作");
			return;
		}
		
		var selectType = document.getElementById("sele_cerType");
		var containerName = container.options[container.selectedIndex].text;
		if(containerName == null || containerName == "")
		{
			alert("请选择容器操作");
			return;
		}
		
		var cerType = selectType.options[selectType.selectedIndex].value;
		
		var strAsymCipher = document.getElementById("AsymCipher").value;
		
		var strAsymPlain = token.SOF_DecryptbyPrvKey(containerName, cerType, strAsymCipher);
		if(strAsymPlain != null && strAsymPlain != "")
		{
			document.getElementById("AsymPlain").value = strAsymPlain;	
		}
		else
			alert("私钥解密失败,错误码:" + token.SOF_GetLastError());
	}
	
	
	
	
	
	
	
	
	
	
	
	