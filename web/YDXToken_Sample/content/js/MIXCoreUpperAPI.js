
	var mixCore = new MIXCore("MIXCorePlugin");
	
	function addSelectOption(val, elementId)
	{	
		elementId.options.add(new Option(val, val));
	}
	
	function InitializeLibraryNative()
	{	
		var slectType = document.getElementById("SKFInterface").value;
		var ret = 0;
		
		if(slectType == "WTSKFInterface.dll")
		{
			ret = mixCore.SOF_InitializeLibraryNative("WTSKFInterface.dll");
		}	
		
		if(mixCore.TRUE == ret)
		{
			alert("加载控件成功!");
		}
		else
		{
			alert("加载控件失败,错误码:" + mixCore.SOF_GetLastError());
			return ;
		}
	}
	
	function FinalizeLibraryNative()
	{	
		var slectType = document.getElementById("SKFInterface").value;
		var ret = 0;
		
		ret = mixCore.SOF_FinalizeLibraryNative();
		
		if(mixCore.TRUE == ret)
		{
			alert("卸载控件成功!");
		}
		else
		{
			alert("卸载控件失败,错误码:" + mixCore.SOF_GetLastError());
			return ;
		}
	}
	
	function GetUserList()
	{
		var containerID = document.getElementById("select_container");
		containerID.options.length = 0;
		
		var userList = mixCore.SOF_GetUserList();
		
		if(userList != null && userList.length > 0)
		{
			var arrList = userList.split("&&&");
			
			for(var i = 0; i < arrList.length; ++i)
			{
				addSelectOption(arrList[i].split("||")[1], containerID);
			}
		}		
		else if(userList == null)
		{
			alert("未发现证书！");
		}
		else
		{
			alert("获取证书列表失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	//验证用户密码
	function Login()
	{
		var pin = document.getElementById("txt_pwd").value;	
		var ret = mixCore.SOF_Login(document.getElementById("select_container").value, pin);			
		if(mixCore.TRUE != ret)
		{	
	
			alert("验证用户密码失败,错误码:" + mixCore.SOF_GetLastError());
			
			var retryCount = mixCore.SOF_GetPinRetryCount(document.getElementById("select_container").value);	
			
			document.getElementById("tryCount").innerText = "剩余次数：" + retryCount;
			
			return;
		}
		else
		{
			document.getElementById("tryCount").innerText = "";
			alert("验证用户密码通过");
		}
				
	}
	
	function Logout()
	{
		var ret = mixCore.SOF_Logout();
		if(mixCore.TRUE != ret)
		{	
			alert("退出失败,错误码:" + mixCore.SOF_GetLastError());
			
			return;
		}
		else
		{
			alert("退出成功");
		}	
	}
	
	function GenRandom()
	{
		var ret = mixCore.SOF_GenRandom(10);
		if(ret != null && ret != "")
		{
			document.getElementById("txt_random").value = ret;	
		}
		else
		{
			alert("生成随机数失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	
	//修改密码
	function ChangePassWd()
	{
		var pin = document.getElementById("txt_pwd").value;	
		var resetPin = document.getElementById("txt_Changepwd").value;
		var ret = mixCore.SOF_ChangePassWd("", pin, resetPin);
		if(mixCore.TRUE != ret)
		{
			alert("密码修改失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("密码修改成功");
		}	
	}
	
	function ValidateCert()
	{
		var cert = document.getElementById("certData").value;	
		
		var ret = mixCore.SOF_ValidateCert(cert);
		
		if(0 != ret)
		{
			alert("校验证书失败,验证失败码:" + ret);
		}
		else
		{
			alert("校验证书成功");
		}	
	}
	
	
	
	//控件版本信息
	 function GetVersion()
    {
        var version = mixCore.SOF_GetVersion();
		document.getElementById("contorlInfo").value = version;			
    }	
	
	//导出证书
	function ExportUserCert()
	{
		document.getElementById("certData").value = "";	
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}

		var cert = mixCore.SOF_ExportUserCert(containerName);
		
		if(cert != null && cert != "")
		{
			document.getElementById("certData").value = cert;	
		}
		else
		{
			alert("获取证书失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function ExportExChangeUserCert()
	{
		document.getElementById("certData").value = "";	
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}

		var cert = mixCore.SOF_ExportExChangeUserCert(containerName);
		
		if(cert != null && cert != "")
		{
			document.getElementById("certData").value = cert;	
		}
		else
		{
			alert("获取证书失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	//获取证书信息
	function GetCertInfo()
	{
		var certData = document.getElementById("certData").value;
		
		if(certData == "")
		{
			alert("数据错误！");
			return;	
		}

		var itemsInfo = "";
		var str = mixCore.SOF_GetCertInfo(certData, mixCore.SGD_CERT_ISSUER_CN);
		itemsInfo += "Issuer: " + str + "\r";
		
		str = mixCore.SOF_GetCertInfo(certData, mixCore.SGD_CERT_SUBJECT);
		itemsInfo += "Subject: " + str + "\r";
		str = mixCore.SOF_GetCertInfo(certData, mixCore.SGD_CERT_SUBJECT_CN);
		itemsInfo += "Subject_CN: " + str + "\r";
		str = mixCore.SOF_GetCertInfo(certData, mixCore.SGD_CERT_SUBJECT_EMALL);
		itemsInfo += "Subject_EMail: " + str + "\r";
		str = mixCore.SOF_GetCertInfo(certData, mixCore.SGD_CERT_SERIAL);
		itemsInfo += "Serial: " + str + "\r";
		str = mixCore.SOF_GetCertInfo(certData, mixCore.SGD_CERT_CRL);
		itemsInfo += "cRLDistributionPoints: " + str + "\r";
		
		document.getElementById("certInfo").value = itemsInfo;
	}
	
	
	function GetXMLSignatureInfo()
	{
		var inData = document.getElementById("inputData").value;
		
		if(inData == "")
		{
			alert("请先填充XML签名值数据");
			return;	
		}
		
		var itemsInfo = "";
		var str = mixCore.SOF_GetXMLSignatureInfo(inData, 1);
		itemsInfo += "Data: " + str + "\r";
		
		str = mixCore.SOF_GetXMLSignatureInfo(inData, 2);
		itemsInfo += "DigestValue: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inData, 3);
		itemsInfo += "SignatureValue: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inData, 4);
		itemsInfo += "X509Certificate: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inData, 5);
		itemsInfo += "DigestMethod: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inData, 6);
		itemsInfo += "SignatureMethod: " + str + "\r";
		
		document.getElementById("outputData").value = itemsInfo;
	}
	
	function GetInfoFromSignedMessage()
	{
		var inData = document.getElementById("inputData").value;
		
		if(inData == "")
		{
			alert("请先填充消息签名值数据");
			return;	
		}
		
		var itemsInfo = "";
		var str = mixCore.SOF_GetInfoFromSignedMessage(inData, 1);
		itemsInfo += "Data: " + str + "\r";
		str = mixCore.SOF_GetInfoFromSignedMessage(inData, 2);
		itemsInfo += "X509Certificate: " + str + "\r";
		str = mixCore.SOF_GetInfoFromSignedMessage(inData, 3);
		itemsInfo += "SignatureValue: " + str + "\r";
		
		document.getElementById("outputData").value = itemsInfo;
	}
	
	function GetCertInfoByOid()
	{
		var certData = "MIICuTCCAl6gAwIBAgIKFBEAAAAAAAAIOTAKBggqgRzPVQGDdTBNMQswCQYDVQQGEwJDTjERMA8GA1UECgwIQ0hJTkFNU0ExETAPBgNVBAsMCENISU5BTVNBMRgwFgYDVQQDDA9DSElOQU1TQSBTTTIgQ0EwHhcNMTUwOTEwMTYwMDAwWhcNMTgwOTExMTU1OTU5WjBTMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5YyX5LqsMQ8wDQYDVQQHDAbmtbfmt4AxIjAgBgNVBAMMGea1t+S6i+S4quS6uua1i+ivlVRG5Y2hMDgwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQ/Y3m7wMvU7B1HEaseF9CsM2gbHEq8CIgJLbedoBw0HACDy0F/t4karfGJoEtDbzIC/EZMZaPG4LHHsVzzKA5co4IBHjCCARowHwYDVR0jBBgwFoAUcWzpmZA0N7fJ6ciCy5fLmv72uF0wHQYDVR0OBBYEFOUdCXJkB9N9gUbP7Hjo+gJvcbabMAsGA1UdDwQEAwIGwDCBpgYDVR0fBIGeMIGbMGigZqBkpGIwYDELMAkGA1UEBhMCQ04xETAPBgNVBAoMCENISU5BTVNBMREwDwYDVQQLDAhDSElOQU1TQTEYMBYGA1UEAwwPQ0hJTkFNU0EgU00yIENBMREwDwYDVQQDEwhjYTExY3JsMTAvoC2gK4YpaHR0cDovLzE5OC4zMi4yMjcuMTo4MDAwL2NybC9jYTExY3JsMS5jcmwwIgYIYIZIAYb4RAIEFgwUU0YxMzAxODUxOTgzMDEyNDM0MTUwCgYIKoEcz1UBg3UDSQAwRgIhAJ+XDG1T2eNyE/Yp7Vm4IK7S+M9NH+61BjPQHXZ9D6dFAiEAgyEcAnn+0avFRtF+wFtkiRQv80iFORQ7QexOAoNw1ug=";

		var showCer = document.getElementById("certInfo");
		
		showCer.value = "";
		var certInfo = "";
		var str = mixCore.SOF_GetCertInfoByOid(certData, "2.16.840.1.113732.2");
		certInfo += "2.16.840.1.113732.2: " + str;
		
		showCer.value = certInfo;
	}
	
	//获取设备信息
	function GetDeviceInfo()
	{
		var container = document.getElementById("select_container");
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
		var str = mixCore.SOF_GetDeviceInfo(containerName, mixCore.SGD_DEVICE_NAME);
		strInfo = "Device name: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(containerName, mixCore.SGD_DEVICE_SUPPORT_STORANGE_SPACE);
		strInfo += "Device total space: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(containerName, mixCore.SGD_DEVICE_SUPPORT_FREE_SAPCE);
		strInfo += "Device free space: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(containerName, mixCore.SGD_DEVICE_HARDWARE_VERSION);
		strInfo += "Hardware version: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(containerName, mixCore.SGD_DEVICE_SERIAL_NUMBER);
		strInfo += "Device serial number: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(containerName, mixCore.SGD_DEVICE_MANUFACTURER);
		strInfo += "Device manufacturer: " + str + "\r";
		
		//strInfo += "如需获取更多信息请查看帮助文档";
		
		deviceInfo.value = strInfo;
	}
	
	function SetSignMethod()
	{
		var mech = document.getElementById("signMech").value;
		var ret = mixCore.SOF_SetSignMethod(Number(mech));
		if(mixCore.SAR_OK != ret)
		{
			alert("操作失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("操作成功");
		}	
	}
	
	function GetSignMethod()
	{
		var ret = mixCore.SOF_GetSignMethod();
		
		if(mixCore.SGD_SM3_RSA == ret)
		{
			alert("SGD_SM3_RSA");
		}
		else if(mixCore.SGD_SHA1_RSA == ret)
		{
			alert("SGD_SHA1_RSA");
		}
		else if(mixCore.SGD_SHA256_RSA == ret)
		{
			alert("SGD_SHA256_RSA");
		}
		else if(mixCore.SGD_SM3_SM2 == ret)
		{
			alert("SGD_SM3_SM2");
		}
		else
		{
			alert("操作失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function SetEncryptMethod()
	{
		var mech = document.getElementById("encMech").value;
		var ret = mixCore.SOF_SetEncryptMethod(Number(mech));
		if(mixCore.SAR_OK != ret)
		{
			alert("操作失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("操作成功");
		}	
	}
	
	function GetEncryptMethod()
	{
		var ret = mixCore.SOF_GetEncryptMethod();
		
		if(mixCore.SGD_SM1_ECB == ret)
		{
			alert("SGD_SM1_ECB");
		}
		else if(mixCore.SGD_SM1_CBC == ret)
		{
			alert("SGD_SM1_CBC");
		}
		else if(mixCore.SGD_SM1_CFB == ret)
		{
			alert("SGD_SM1_CFB");
		}
		else if(mixCore.SGD_SM1_OFB == ret)
		{
			alert("SGD_SM1_OFB");
		}
		
		else if(mixCore.SGD_SSF33_ECB == ret)
		{
			alert("SGD_SSF33_ECB");
		}
		else if(mixCore.SGD_SSF33_CBC == ret)
		{
			alert("SGD_SSF33_CBC");
		}
		else if(mixCore.SGD_SSF33_CFB == ret)
		{
			alert("SGD_SSF33_CFB");
		}
		else if(mixCore.SGD_SSF33_OFB == ret)
		{
			alert("SGD_SSF33_OFB");
		}
		else if(mixCore.SGD_SM4_ECB == ret)
		{
			alert("SGD_SM4_ECB");
		}
		else if(mixCore.SGD_SM4_CBC == ret)
		{
			alert("SGD_SM4_CBC");
		}
		else if(mixCore.SGD_SM4_CFB == ret)
		{
			alert("SGD_SM4_CFB");
		}
		else if(mixCore.SGD_SM4_OFB == ret)
		{
			alert("SGD_SM4_OFB");
		}
		else
		{
			alert("操作失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function VerifySignedFile()
	{
		var inData = document.getElementById("inputData").value;
		var signed = document.getElementById("outputData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportUserCert(containerName);
		
		var ret = mixCore.SOF_VerifySignedFile(cert, inData, signed);
		if(mixCore.TRUE != ret)
		{
			alert("验签失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}

	function VerifySignedMessage()
	{
		var inData = document.getElementById("inputData").value;
		var signed = document.getElementById("outputData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportUserCert(containerName);
		
		var ret = mixCore.SOF_VerifySignedMessage(signed, inData);
		if(mixCore.TRUE != ret)
		{
			alert("验签失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}
				
	function VerifySignedDataXML()
	{
		var inData = document.getElementById("inputData").value;
		var signed = document.getElementById("outputData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var ret = mixCore.SOF_VerifySignedDataXML(signed);
		if(mixCore.TRUE != ret)
		{
			alert("验签失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}
				
	//数据验签
	function VerifySignedData()
	{
		var inData = document.getElementById("inputData").value;
		var signed = document.getElementById("outputData").value;
		if(signed == null || signed.length <= 0)
		{
			alert("请先签名后操作");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportUserCert(containerName);
		
		var ret = mixCore.SOF_VerifySignedData(cert, inData, signed);
		if(mixCore.TRUE != ret)
		{
			alert("验签失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}
	
	function SignFile()
	{
		var inData = document.getElementById("inputData").value;
			
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var signed = mixCore.SOF_SignFile(containerName, inData);
		if(signed != null && signed != "")
		{
			document.getElementById("outputData").value = signed;	
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());	
		}
	}
	
	function SignMessage()
	{
		var selectSignType = document.getElementById("select_signType");
		var signType = selectSignType.options[selectSignType.selectedIndex].value;
		var inData = document.getElementById("inputData").value;
			
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}

		var signed = mixCore.SOF_SignMessage(Number(signType), containerName, inData);
		if(signed != null && signed != "")
		{
			document.getElementById("outputData").value = signed;
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function SetDataXMLTemplate()
	{
		var indata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- \nXML Security Library example: Original XML doc file for sign3 example. \n-->\n<Envelope xmlns=\"urn:envelope\">\n  <Data>\n	Hello,ABCDEFG World!\n  </Data>\n</Envelope>\n";
			
		document.getElementById("inputData").value = indata;
	}
	
	function ExchangeData()
	{
		var indata = document.getElementById("inputData").value;
		var outdata = document.getElementById("outputData").value;
			
		document.getElementById("inputData").value = outdata;
		document.getElementById("outputData").value = indata;
	}
	
	
	function SignDataXML()
	{
		var inData = document.getElementById("inputData").value;
		
		if(inData != null && inData != "")
		{

		}
		else
		{
			alert("请设置XML输入数据");
			return;
		}
			
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var signed = mixCore.SOF_SignDataXML(containerName, inData);
		if(signed != null && signed != "")
		{
			document.getElementById("outputData").value = signed;
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	//数据签名
	function SignData()
	{
		var inData = document.getElementById("inputData").value;
			
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var signed = mixCore.SOF_SignData(containerName, inData);
		if(signed != null && signed != "")
		{
			document.getElementById("outputData").value = signed;
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	//数据加密
	function EncryptData()
	{
		var inData = document.getElementById("inputData").value;
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(containerName);
		
		var outData = mixCore.SOF_EncryptData(cert, inData);
		if(outData != null && outData != "")
		{
			document.getElementById("outputData").value = outData;
		}	
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	function PubKeyEncrypt()
	{
		var inData = document.getElementById("inputData").value;
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(containerName);
		
		var outData = mixCore.SOF_PubKeyEncrypt(cert, inData);
		if(outData != null && outData != "")
		{
			document.getElementById("outputData").value = outData;
		}	
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	function PubKeyEncryptLongData()
	{
		var inData = document.getElementById("inputData").value;
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(containerName);
		
		var outData = mixCore.SOF_PubKeyEncryptLongData(cert, inData);
		if(outData != null && outData != "")
		{
			document.getElementById("outputData").value = outData;
		}	
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	//数据加密
	function EncryptFile()
	{
		var inData = document.getElementById("inputData").value;
		var outData = document.getElementById("outputData").value;
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(containerName);
		
		var ret = mixCore.SOF_EncryptFile(cert, inData, outData);
		if(mixCore.TRUE == ret)
		{
			alert("加密成功！");
		}
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function DecryptFile()
	{
		var inData = document.getElementById("inputData").value;
		var outData = document.getElementById("outputData").value;
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		var ret = mixCore.SOF_DecryptFile(containerName, inData, outData);
		
		if(mixCore.TRUE == ret)
		{
			alert("解密成功！");
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
		
	//数据解密
	function DecryptData()
	{
		var inData = document.getElementById("inputData").value;
		if(inData == null || inData.length <= 0)
		{
			alert("数据错误！");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		decryptedData = mixCore.SOF_DecryptData(containerName, inData);
		if(decryptedData != null && decryptedData != "")
		{
			document.getElementById("outputData").value = decryptedData;
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	
	function PriKeyDecryptLongData()
	{
		var inData = document.getElementById("inputData").value;
		if(inData == null || inData.length <= 0)
		{
			alert("数据错误！");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		decryptedData = mixCore.SOF_PriKeyDecryptLongData(containerName, inData);
		if(decryptedData != null && decryptedData != "")
		{
			document.getElementById("outputData").value = decryptedData;
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	
	function PriKeyDecrypt()
	{
		var inData = document.getElementById("inputData").value;
		if(inData == null || inData.length <= 0)
		{
			alert("数据错误！");
			return;
		}
		
		var container = document.getElementById("select_container");
		var containerName = "";
		
		if(container.selectedIndex < 0)
		{

		}
		else
		{
			containerName = container.options[container.selectedIndex].text;
		}
		
		decryptedData = mixCore.SOF_PriKeyDecrypt(containerName, inData);
		if(decryptedData != null && decryptedData != "")
		{
			document.getElementById("outputData").value = decryptedData;
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	
	
	