
	var mixCore = new MIXCore("MIXCorePlugin");
	
	function addSelectOption(elementId, name, val)
	{	
		elementId.options.add(new Option(name, val));
	}
	
	function InitializeLibraryNative()
	{	
		var slectType = document.getElementById("SKFInterface").value;
		var result = 0;
		
		if(slectType == "WTSKFInterface.dll")
		{
			result = mixCore.SOF_InitializeLibraryNative("WTSKFInterface.dll");
		}	
		
		if(mixCore.TRUE == result)
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
		var result = 0;
		
		result = mixCore.SOF_FinalizeLibraryNative();
		
		if(mixCore.TRUE == result)
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
		var select_container = document.getElementById("select_container");
		select_container.options.length = 0;
		
		var userList = mixCore.SOF_GetUserList();
		
		if(null != userList && 0 < userList.length)
		{
			var arrList = userList.split("&&&");
			
			for(var i = 0; i < arrList.length; ++i)
			{
				addSelectOption(select_container, arrList[i].split("||")[1], arrList[i].split("||")[1]);
			}
		}		
		else if(null == userList)
		{
			alert("未发现证书！");
		}
		else
		{
			alert("获取用户列表失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function Login()
	{
		var pin = document.getElementById("input_password").value;	
		var result = mixCore.SOF_Login(document.getElementById("select_container").value, pin);	
		
		if(mixCore.TRUE != result)
		{	
	
			alert("验证用户密码失败,错误码:" + mixCore.SOF_GetLastError());
			
			var relabel_retryCount = mixCore.SOF_GetPinRelabel_retryCount(document.getElementById("select_container").value);	
			
			document.getElementById("label_retryCount").innerText = "剩余次数：" + relabel_retryCount;
			
			return;
		}
		else
		{
			document.getElementById("label_retryCount").innerText = "";
			alert("验证用户密码成功");
		}
				
	}
	
	function Logout()
	{
		var result = mixCore.SOF_Logout();
		
		if(mixCore.TRUE != result)
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
		var result = mixCore.SOF_GenRandom(10);
		
		if(null !=result && "" != result)
		{
			document.getElementById("input_random").value = result;	
		}
		else
		{
			alert("生成随机数失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function ChangePassWd()
	{
		var pin = document.getElementById("input_password").value;	
		var resetPin = document.getElementById("input_password_new").value;
		var result = mixCore.SOF_ChangePassWd("", pin, resetPin);
		
		if(mixCore.TRUE != result)
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
		var result = mixCore.SOF_ValidateCert(cert);
		
		if(0 != result)
		{
			alert("校验证书失败,验证失败码:" + result);
		}
		else
		{
			alert("校验证书成功");
		}	
	}
	
	function GetVersion()
    {
        var versionInfo = mixCore.SOF_GetVersion();
		document.getElementById("versionInfo").value = versionInfo;			
    }	
	
	function ExportUserCert()
	{
		document.getElementById("certData").value = "";	
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}

		var certData = mixCore.SOF_ExportUserCert(default_container_name);
		
		if(null != certData && "" != certData)
		{
			document.getElementById("certData").value = certData;	
		}
		else
		{
			alert("获取证书失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function ExportExChangeUserCert()
	{
		document.getElementById("certData").value = "";	
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}

		var cert = mixCore.SOF_ExportExChangeUserCert(default_container_name);
		
		if(null != certData && "" != certData)
		{
			document.getElementById("certData").value = certData;	
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
		
		if("" == certData)
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
		var inputData = document.getElementById("inputData").value;
		
		if("" == inputData)
		{
			alert("请先填充XML签名值数据");
			return;	
		}
		
		var itemsInfo = "";
		var str = mixCore.SOF_GetXMLSignatureInfo(inputData, 1);
		itemsInfo += "Data: " + str + "\r";
		
		str = mixCore.SOF_GetXMLSignatureInfo(inputData, 2);
		itemsInfo += "DigestValue: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inputData, 3);
		itemsInfo += "SignatureValue: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inputData, 4);
		itemsInfo += "X509Certificate: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inputData, 5);
		itemsInfo += "DigestMethod: " + str + "\r";
		str = mixCore.SOF_GetXMLSignatureInfo(inputData, 6);
		itemsInfo += "SignatureMethod: " + str + "\r";
		
		document.getElementById("outputData").value = itemsInfo;
	}
	
	function GetInfoFromSignedMessage()
	{
		var inputData = document.getElementById("inputData").value;
		
		if("" == inputData)
		{
			alert("请先填充消息签名值数据");
			return;	
		}
		
		var itemsInfo = "";
		var str = mixCore.SOF_GetInfoFromSignedMessage(inputData, 1);
		itemsInfo += "Data: " + str + "\r";
		str = mixCore.SOF_GetInfoFromSignedMessage(inputData, 2);
		itemsInfo += "X509Certificate: " + str + "\r";
		str = mixCore.SOF_GetInfoFromSignedMessage(inputData, 3);
		itemsInfo += "SignatureValue: " + str + "\r";
		
		document.getElementById("outputData").value = itemsInfo;
	}
	
	function GetCertInfoByOid()
	{
		var certData = "MIICuTCCAl6gAwIBAgIKFBEAAAAAAAAIOTAKBggqgRzPVQGDdTBNMQswCQYDVQQGEwJDTjERMA8GA1UECgwIQ0hJTkFNU0ExETAPBgNVBAsMCENISU5BTVNBMRgwFgYDVQQDDA9DSElOQU1TQSBTTTIgQ0EwHhcNMTUwOTEwMTYwMDAwWhcNMTgwOTExMTU1OTU5WjBTMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5YyX5LqsMQ8wDQYDVQQHDAbmtbfmt4AxIjAgBgNVBAMMGea1t+S6i+S4quS6uua1i+ivlVRG5Y2hMDgwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQ/Y3m7wMvU7B1HEaseF9CsM2gbHEq8CIgJLbedoBw0HACDy0F/t4karfGJoEtDbzIC/EZMZaPG4LHHsVzzKA5co4IBHjCCARowHwYDVR0jBBgwFoAUcWzpmZA0N7fJ6ciCy5fLmv72uF0wHQYDVR0OBBYEFOUdCXJkB9N9gUbP7Hjo+gJvcbabMAsGA1UdDwQEAwIGwDCBpgYDVR0fBIGeMIGbMGigZqBkpGIwYDELMAkGA1UEBhMCQ04xETAPBgNVBAoMCENISU5BTVNBMREwDwYDVQQLDAhDSElOQU1TQTEYMBYGA1UEAwwPQ0hJTkFNU0EgU00yIENBMREwDwYDVQQDEwhjYTExY3JsMTAvoC2gK4YpaHR0cDovLzE5OC4zMi4yMjcuMTo4MDAwL2NybC9jYTExY3JsMS5jcmwwIgYIYIZIAYb4RAIEFgwUU0YxMzAxODUxOTgzMDEyNDM0MTUwCgYIKoEcz1UBg3UDSQAwRgIhAJ+XDG1T2eNyE/Yp7Vm4IK7S+M9NH+61BjPQHXZ9D6dFAiEAgyEcAnn+0avFRtF+wFtkiRQv80iFORQ7QexOAoNw1ug=";
		var itemsInfo = "";
		
		var str = mixCore.SOF_GetCertInfoByOid(certData, "2.16.840.1.113732.2");
		itemsInfo += "2.16.840.1.113732.2: " + str;
		
		document.getElementById("certInfo").value = itemsInfo;
	}
	
	function GetDeviceInfo()
	{
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var itemsInfo = "";
		
		var str = mixCore.SOF_GetDeviceInfo(default_container_name, mixCore.SGD_DEVICE_NAME);
		itemsInfo = "Device name: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(default_container_name, mixCore.SGD_DEVICE_SUPPORT_STORANGE_SPACE);
		itemsInfo += "Device total space: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(default_container_name, mixCore.SGD_DEVICE_SUPPORT_FREE_SAPCE);
		itemsInfo += "Device free space: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(default_container_name, mixCore.SGD_DEVICE_HARDWARE_VERSION);
		itemsInfo += "Hardware version: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(default_container_name, mixCore.SGD_DEVICE_SERIAL_NUMBER);
		itemsInfo += "Device serial number: " + str + "\r";
		
		var str = mixCore.SOF_GetDeviceInfo(default_container_name, mixCore.SGD_DEVICE_MANUFACTURER);
		itemsInfo += "Device manufacturer: " + str + "\r";
		
		document.getElementById("deviceInfo").value = itemsInfo;
	}
	
	function SetSignMethod()
	{
		var mech = document.getElementById("signMech").value;
		var result = mixCore.SOF_SetSignMethod(Number(mech));
		if(mixCore.SAR_OK != result)
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
		var result = mixCore.SOF_GetSignMethod();
		
		if(mixCore.SGD_SM3_RSA == result)
		{
			alert("SGD_SM3_RSA");
		}
		else if(mixCore.SGD_SHA1_RSA == result)
		{
			alert("SGD_SHA1_RSA");
		}
		else if(mixCore.SGD_SHA256_RSA == result)
		{
			alert("SGD_SHA256_RSA");
		}
		else if(mixCore.SGD_SM3_SM2 == result)
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
		var result = mixCore.SOF_SetEncryptMethod(Number(mech));
		if(mixCore.SAR_OK != result)
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
		var result = mixCore.SOF_GetEncryptMethod();
		
		if(mixCore.SGD_SM1_ECB == result)
		{
			alert("SGD_SM1_ECB");
		}
		else if(mixCore.SGD_SM1_CBC == result)
		{
			alert("SGD_SM1_CBC");
		}
		else if(mixCore.SGD_SM1_CFB == result)
		{
			alert("SGD_SM1_CFB");
		}
		else if(mixCore.SGD_SM1_OFB == result)
		{
			alert("SGD_SM1_OFB");
		}
		
		else if(mixCore.SGD_SSF33_ECB == result)
		{
			alert("SGD_SSF33_ECB");
		}
		else if(mixCore.SGD_SSF33_CBC == result)
		{
			alert("SGD_SSF33_CBC");
		}
		else if(mixCore.SGD_SSF33_CFB == result)
		{
			alert("SGD_SSF33_CFB");
		}
		else if(mixCore.SGD_SSF33_OFB == result)
		{
			alert("SGD_SSF33_OFB");
		}
		else if(mixCore.SGD_SM4_ECB == result)
		{
			alert("SGD_SM4_ECB");
		}
		else if(mixCore.SGD_SM4_CBC == result)
		{
			alert("SGD_SM4_CBC");
		}
		else if(mixCore.SGD_SM4_CFB == result)
		{
			alert("SGD_SM4_CFB");
		}
		else if(mixCore.SGD_SM4_OFB == result)
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
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
		if(null == outputData || 0 >= outputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportUserCert(default_container_name);
		
		var result = mixCore.SOF_VerifySignedFile(cert, inputData, outputData);
		if(mixCore.TRUE != result)
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
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
		if(null == outputData || 0 >= outputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportUserCert(default_container_name);
		
		var result = mixCore.SOF_VerifySignedMessage(outputData, inputData);
		if(mixCore.TRUE != result)
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
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
		if(null == outputData || 0 >= outputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var result = mixCore.SOF_VerifySignedDataXML(outputData);
		if(mixCore.TRUE != result)
		{
			alert("验签失败,错误码:" + mixCore.SOF_GetLastError());
		}
		else
		{
			alert("验签成功");
		}
	}

	function VerifySignedData()
	{
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
		if(null == outputData || 0 >= outputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportUserCert(default_container_name);
		
		var result = mixCore.SOF_VerifySignedData(cert, inputData, outputData);
		if(mixCore.TRUE != result)
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
		var inputData = document.getElementById("inputData").value;
			
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var outputData = mixCore.SOF_SignFile(default_container_name, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;	
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
		var inputData = document.getElementById("inputData").value;
			
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}

		var outputData = mixCore.SOF_SignMessage(Number(signType), default_container_name, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function SetDataXMLTemplate()
	{
		var inputData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- \nXML Security Library example: Original XML doc file for sign3 example. \n-->\n<Envelope xmlns=\"urn:envelope\">\n  <Data>\n	Hello,ABCDEFG World!\n  </Data>\n</Envelope>\n";
			
		document.getElementById("inputData").value = inputData;
	}
	
	function ExchangeData()
	{
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
			
		document.getElementById("inputData").value = outputData;
		document.getElementById("outputData").value = inputData;
	}
	
	function SignDataXML()
	{
		var inputData = document.getElementById("inputData").value;
		
		if(null != inputData && "" != inputData)
		{

		}
		else
		{
			alert("请设置XML输入数据");
			return;
		}
			
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var outputData = mixCore.SOF_SignDataXML(default_container_name, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function SignData()
	{
		var inputData = document.getElementById("inputData").value;
			
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var outputData = mixCore.SOF_SignData(default_container_name, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}
		else
		{
			alert("签名失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function EncryptData()
	{
		var inputData = document.getElementById("inputData").value;
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(default_container_name);
		
		var outputData = mixCore.SOF_EncryptData(cert, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}	
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	function PubKeyEncrypt()
	{
		var inputData = document.getElementById("inputData").value;
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(default_container_name);
		
		var outputData = mixCore.SOF_PubKeyEncrypt(cert, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}	
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	function PubKeyEncryptLongData()
	{
		var inputData = document.getElementById("inputData").value;
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(default_container_name);
		
		var outputData = mixCore.SOF_PubKeyEncryptLongData(cert, inputData);
		if(null != outputData &&  "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}	
		else
		{
			alert("加密失败,错误码:" + mixCore.SOF_GetLastError());
		}
			
	}
	
	function EncryptFile()
	{
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var cert  = mixCore.SOF_ExportExChangeUserCert(default_container_name);
		
		var result = mixCore.SOF_EncryptFile(cert, inputData, outputData);
		if(mixCore.TRUE == result)
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
		var inputData = document.getElementById("inputData").value;
		var outputData = document.getElementById("outputData").value;
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		var result = mixCore.SOF_DecryptFile(default_container_name, inputData, outputData);
		
		if(mixCore.TRUE == result)
		{
			alert("解密成功！");
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function DecryptData()
	{
		var inputData = document.getElementById("inputData").value;
		if(null == inputData || 0 >= inputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		outputData = mixCore.SOF_DecryptData(default_container_name, inputData);
		if(null != outputData && "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function PriKeyDecryptLongData()
	{
		var inputData = document.getElementById("inputData").value;
		if(null == inputData || 0 >= inputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		outputData = mixCore.SOF_PriKeyDecryptLongData(default_container_name, inputData);
		if(null != outputData && "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	function PriKeyDecrypt()
	{
		var inputData = document.getElementById("inputData").value;
		if(null == inputData || 0 >= inputData.length)
		{
			alert("数据错误！");
			return;
		}
		
		var select_container = document.getElementById("select_container");
		var default_container_name = "";
		
		if(0 > select_container.selectedIndex)
		{

		}
		else
		{
			default_container_name = select_container.options[select_container.selectedIndex].text;
		}
		
		outputData = mixCore.SOF_PriKeyDecrypt(default_container_name, inputData);
		if(null != outputData && "" != outputData)
		{
			document.getElementById("outputData").value = outputData;
		}
		else
		{
			alert("解密失败,错误码:" + mixCore.SOF_GetLastError());
		}
	}
	
	
	
	