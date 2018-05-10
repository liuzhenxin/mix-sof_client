
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
		var cerlistID = document.getElementById("select_contentList");
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
		{
			alert("设备中无证书");
		}
		else
		{
			alert("获取证书列表失败,错误码:" + token.SOF_GetLastError());
		}
			
	}
	
	//验证用户密码
	function Login()
	{
		var pin = document.getElementById("txt_pwd").value;	
		var ret = token.SOF_Login(document.getElementById("select_contentList").value, pin);			
		if(token.TRUE != ret)
		{	
	
			alert("验证用户密码失败,错误码:" + token.SOF_GetLastError());
			
			var retryCount = token.SOF_GetPinRetryCount(document.getElementById("select_contentList").value);	
			
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
	
	//导出证书
	function ExportUserCert()
	{
		document.getElementById("certData").value = "";	
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}

		var cert = token.SOF_ExportUserCert(containerName);
		
		if(cert != null && cert != "")
		{
			document.getElementById("certData").value = cert;	
		}
		else
		{
			alert("获取证书信息失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	function ExportExChangeUserCert()
	{
		document.getElementById("certData").value = "";	
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}

		var cert = token.SOF_ExportExChangeUserCert(containerName);
		
		if(cert != null && cert != "")
		{
			document.getElementById("certData").value = cert;	
		}
		else
		{
			alert("获取证书信息失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	//获取证书信息
	function GetCertInfo()
	{
		signCert = document.getElementById("certData").value;
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
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
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
		
		if(token.SGD_SM3_RSA == ret)
		{
			alert("SGD_SM3_RSA");
		}
		else if(token.SGD_SHA1_RSA == ret)
		{
			alert("SGD_SHA1_RSA");
		}
		else if(token.SGD_SHA256_RSA == ret)
		{
			alert("SGD_SHA256_RSA");
		}
		else if(token.SGD_SM3_SM2 == ret)
		{
			alert("SGD_SM3_SM2");
		}
		else
		{
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
		
		if(token.SGD_SM1_ECB == ret)
		{
			alert("SGD_SM1_ECB");
		}
		else if(token.SGD_SM1_CBC == ret)
		{
			alert("SGD_SM1_CBC");
		}
		else if(token.SGD_SM1_CFB == ret)
		{
			alert("SGD_SM1_CFB");
		}
		else if(token.SGD_SM1_OFB == ret)
		{
			alert("SGD_SM1_OFB");
		}
		
		else if(token.SGD_SSF33_ECB == ret)
		{
			alert("SGD_SSF33_ECB");
		}
		else if(token.SGD_SSF33_CBC == ret)
		{
			alert("SGD_SSF33_CBC");
		}
		else if(token.SGD_SSF33_CFB == ret)
		{
			alert("SGD_SSF33_CFB");
		}
		else if(token.SGD_SSF33_OFB == ret)
		{
			alert("SGD_SSF33_OFB");
		}
		else if(token.SGD_SM4_ECB == ret)
		{
			alert("SGD_SM4_ECB");
		}
		else if(token.SGD_SM4_CBC == ret)
		{
			alert("SGD_SM4_CBC");
		}
		else if(token.SGD_SM4_CFB == ret)
		{
			alert("SGD_SM4_CFB");
		}
		else if(token.SGD_SM4_OFB == ret)
		{
			alert("SGD_SM4_OFB");
		}
		else
		{
			alert("操作失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	function VerifySignedFile()
	{
		var inData = document.getElementById("originalData").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = token.SOF_ExportUserCert(containerName);
		
		var ret = token.SOF_VerifySignedFile(cert, inData, signed);
		if(token.TRUE != ret)
		{
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}

	function VerifySignedMessage()
	{
		var inData = document.getElementById("originalData").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = token.SOF_ExportUserCert(containerName);
		
		var ret = token.SOF_VerifySignedMessage(signed, inData);
		if(token.TRUE != ret)
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		else
			alert("验签成功");
	}
				
	function VerifySignedDataXML()
	{
		var inData = document.getElementById("originalData").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var ret = token.SOF_VerifySignedDataXML(signed);
		if(token.TRUE != ret)
		{
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}
				
	//数据验签
	function VerifySignedData()
	{
		var inData = document.getElementById("originalData").value;
		var signed = document.getElementById("signedData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = token.SOF_ExportUserCert(containerName);
		
		var ret = token.SOF_VerifySignedData(cert, inData, signed);
		if(token.TRUE != ret)
			alert("验签失败,错误码:" + token.SOF_GetLastError());
		else
			alert("验签成功");
	}
	
	function SignFile()
	{
		var inData = document.getElementById("originalData").value;
			
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var signed = token.SOF_SignFile(containerName, inData);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	function SignMessage()
	{
		var selectSignType = document.getElementById("select_signType");
		var signType = selectSignType.options[selectSignType.selectedIndex].value;
		var inData = document.getElementById("originalData").value;
			
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}

		var signed = token.SOF_SignMessage(Number(signType), containerName, inData);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	function SignDataXML()
	{
		var inData = document.getElementById("originalDataXML").value;
		
		if(signed != null && signed != "")
		{

		}
		else
		{
			indata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- \nXML Security Library example: Original XML doc file for sign3 example. \n-->\n<Envelope xmlns=\"urn:envelope\">\n  <Data>\n	Hello,ABCDEFG World!\n  </Data>\n</Envelope>\n";
				
			document.getElementById("originalDataXML").value = indata;
		}
			
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var signed = token.SOF_SignDataXML(containerName, inData);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	//数据签名
	function SignData()
	{
		var inData = document.getElementById("originalData").value;
			
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var signed = token.SOF_SignData(containerName, inData);
		if(signed != null && signed != "")
			document.getElementById("signedData").value = signed;
		else
			alert("签名失败,错误码:" + token.SOF_GetLastError());
	}
	
	//数据加密
	function EncryptData()
	{
		var inData = document.getElementById("enData").value;
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = token.SOF_ExportUserCert(containerName);
		
		var encrypedData = token.SOF_EncryptData(cert, inData);
		if(encrypedData != null || encrypedData == "")
		{
			document.getElementById("enedData").value = encrypedData;
		}	
		else
		{
			alert("加密失败,错误码:" + token.SOF_GetLastError());
		}
			
	}
	
	//数据加密
	function EncryptFile()
	{
		var inData = document.getElementById("enData").value;
		var OutData = document.getElementById("enedData").value;
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = token.SOF_ExportUserCert(containerName, cerType);
		
		var envelopData = token.SOF_EncryptFile(cert, inData, OutData);
		if(envelopData != null)
		{
			document.getElementById("enedData").value = envelopData;
		}
		else
		{
			alert("加密失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	function DecryptFile()
	{
		var outFile = document.getElementById("enData").value;
		var inData = document.getElementById("enedData").value;
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		decryptedData = token.SOF_DecryptFile(containerName, inData, outFile);
		if(decryptedData != 0)
		{
			alert("解密失败,错误码:" + token.SOF_GetLastError());
		}
		else
		{
			document.getElementById("deData").value = outFile;
			alert("解密文件成功，目标文件:" + outFile);
		}
	}
		
	//数据解密
	function DecryptData()
	{
		var encrypedData = document.getElementById("enedData").value;
		if(encrypedData == null || encrypedData.length <= 0)
		{
			alert("请先加密后操作");
			return;
		}
		
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		decryptedData = token.SOF_DecryptData(containerName, encrypedData);
		if(decryptedData != null && decryptedData != "")
		{
			document.getElementById("deData").value = decryptedData;
		}
		else
		{
			alert("解密失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	function encryptbyPubKey()
	{
		var strPubKey = document.getElementById("PubKey").value;
		var strInput = document.getElementById("AsymPlain").value;
		
		var strAsymCipher = token.SOF_EncryptbyPubKey(strPubKey, strInput, cerType);
		if(strAsymCipher != null && strAsymCipher != "")
		{
			document.getElementById("AsymCipher").value = strAsymCipher;	
		}
		else
		{
			alert("公钥加密失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	function decryptbyPrvKey()
	{
		var container = document.getElementById("select_contentList");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var strAsymCipher = document.getElementById("AsymCipher").value;
		
		var strAsymPlain = token.SOF_DecryptbyPrvKey(containerName, cerType, strAsymCipher);
		if(strAsymPlain != null && strAsymPlain != "")
		{
			document.getElementById("AsymPlain").value = strAsymPlain;	
		}
		else
		{
			alert("私钥解密失败,错误码:" + token.SOF_GetLastError());
		}
	}
	
	
	