
function MIXCore(object){
	this.object = object;	
	
	this.SAR_OK										=	0;
	this.SAR_FALSE									= 	1;
	
	this.SGD_SM1_ECB								=	0x00000101;
	this.SGD_SM1_CBC								=	0x00000102;
	this.SGD_SM1_CFB								=	0x00000104;
	this.SGD_SM1_OFB								=	0x00000108;
	this.SGD_SM1_MAC								=	0x00000110;
	this.SGD_SSF33_ECB								=	0x00000201;
	this.SGD_SSF33_CBC								=	0x00000202;
	this.SGD_SSF33_CFB								=	0x00000204;
	this.SGD_SSF33_OFB								=	0x00000208;
	this.SGD_SSF33_MAC								=	0x00000210;
	this.SGD_SM4_ECB								=	0x00000401;
	this.SGD_SM4_CBC								=	0x00000402;
	this.SGD_SM4_CFB								=	0x00000404;
	this.SGD_SM4_OFB								=	0x00000408;
	this.SGD_SM4_MAC								=	0x00000410;
	
	this.SGD_RSA									=	0x00010000;
	this.SGD_SM2_1									=	0x00020100; //ECC签名
	this.SGD_SM2_2									=	0x00020200; //ECC密钥交换
	this.SGD_SM2_3									=	0x00020400; //ECC加密
	
	this.SGD_SM3									=	0x00000001;
	this.SGD_SHA1									=	0x00000002;
	this.SGD_SHA256									=	0x00000004;
	
	this.SGD_SM3_RSA                                = 	0x00010001; 
	this.SGD_SHA1_RSA                               = 	0x00010002;
	this.SGD_SHA256_RSA                             = 	0x00010004;
	this.SGD_SM3_SM2                                = 	0x00020201; 

	
	this.SGD_CERT_VERSION							=	0x00000001;
	this.SGD_CERT_SERIAL							= 	0x00000002;
	this.SGD_CERT_ISSUE								= 	0x00000005;
	this.SGD_CERT_VALID_TIME						= 	0x00000006;
	this.SGD_CERT_SUBJECT							= 	0x00000007;
	this.SGD_CERT_DER_PUBLIC_KEY					= 	0x00000008;
	this.SGD_CERT_DER_EXTENSIONS					= 	0x00000009;
	this.SGD_CERT_ISSUER_CN							= 	0x00000021;
	this.SGD_CERT_ISSUER_O							= 	0x00000022;
	this.SGD_CERT_ISSUER_OU							= 	0x00000023;
	this.SGD_CERT_SUBJECT_CN						= 	0x00000031;
	this.SGD_CERT_SUBJECT_O							= 	0x00000032;
	this.SGD_CERT_SUBJECT_OU						= 	0x00000033;
	this.SGD_CERT_SUBJECT_EMALL						= 	0x00000034;
	
	this.SGD_CERT_CRL								= 	0x00000041;
                                            

	this.SGD_DEVICE_SORT							= 	0x00000201;
	this.SGD_DEVICE_TYPE							= 	0x00000202;
	this.SGD_DEVICE_NAME							= 	0x00000203;
	this.SGD_DEVICE_MANUFACTURER					= 	0x00000204;
	this.SGD_DEVICE_HARDWARE_VERSION				= 	0x00000205;
	this.SGD_DEVICE_SOFTWARE_VERSION				= 	0x00000206;
	this.SGD_DEVICE_STANDARD_VERSION				= 	0x00000207;
	this.SGD_DEVICE_SERIAL_NUMBER					= 	0x00000208;
	this.SGD_DEVICE_SUPPORT_SYM_ALG					= 	0x00000209;
	this.SGD_DEVICE_SUPPORT_ASYM_ALG				= 	0x0000020A;
	this.SGD_DEVICE_SUPPORT_HASH_ALG				= 	0x0000020B;
	this.SGD_DEVICE_SUPPORT_STORANGE_SPACE			= 	0x0000020C;
	this.SGD_DEVICE_SUPPORT_FREE_SAPCE				= 	0x0000020D;
	this.SGD_DEVICE_RUNTIME							= 	0x0000020E;
	this.SGD_DEVICE_USED_TIMES						= 	0x0000020F;
	this.SGD_DEVICE_LOCATION						= 	0x00000210;
	this.SGD_DEVICE_DESCRIPTION						= 	0x00000211;
	this.SGD_DEVICE_MANAGER_INFO					= 	0x00000212;
	this.SGD_DEVICE_MAX_DATA_SIZE					= 	0x00000213;
	
	this.TRUE										=	1;
	this.FALSE										=	0;
	
	
	var g_MIXPlugin = null;
	
	
	this.SOF_GetLastError = function()
	{
		if(null == g_MIXPlugin)
		{
			return -1;
		}
		
		return g_MIXPlugin.SOF_GetLastError();
	}
	
	this.SOF_GetVersion = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetVersion();
	}

	this.SOF_SetSignMethod = function(ulMethod)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_SetSignMethod(ulMethod);
	}

	this.SOF_GetSignMethod = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetSignMethod();
	}

	this.SOF_SetEncryptMethod = function(ulMethod)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_SetEncryptMethod(ulMethod);
	}

	this.SOF_GetEncryptMethod = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetEncryptMethod();
	}

	this.SOF_GetUserList = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetUserList();
	}

	this.SOF_ExportUserCert = function(strContainerName)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_ExportUserCert(strContainerName);
	}

	this.SOF_Login = function(strContainerName,strPIN)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_Login(strContainerName,strPIN);
	}

	this.SOF_GetPinRetryCount = function(strContainerName)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetPinRetryCount(strContainerName);
	}

	this.SOF_ChangePassWd = function(strContainerName, strPINOld, strPINNew)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_ChangePassWd(strContainerName, strPINOld, strPINNew);
	}

	this.SOF_ExportExChangeUserCert = function(strContainerName)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_ExportExChangeUserCert(strContainerName);
	}

	this.SOF_GetCertInfo = function(strCert, u16Type)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetCertInfo(strCert, u16Type);
	}

	this.SOF_GetCertInfoByOid = function(strCert, strOidString)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetCertInfoByOid(strCert, strOidString);
	}

	this.SOF_GetDeviceInfo = function(strContainerName, ulType)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetDeviceInfo(strContainerName, ulType);
	}

	this.SOF_ValidateCert = function(strCert)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_ValidateCert(strCert);
	}

	this.SOF_SignData = function(strContainerName, strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_SignData(strContainerName, strDataIn);
	}

	this.SOF_VerifySignedData = function(strCert, strDataIn, strDataOut)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_VerifySignedData(strCert, strDataIn, strDataOut);
	}

	this.SOF_SignFile = function(strContainerName, strFileIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_SignFile(strContainerName, strFileIn);
	}

	this.SOF_VerifySignedFile = function(strCert, strFileIn, strDataOut)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_VerifySignedFile(strCert, strFileIn, strDataOut);
	}

	this.SOF_EncryptData = function(strCert,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_EncryptData(strCert,strDataIn);
	}

	this.SOF_DecryptData = function(strContainerName,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_DecryptData(strContainerName,strDataIn);
	}

	this.SOF_EncryptFile = function(strCert, strFileIn, strFileOut)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_EncryptFile(strCert, strFileIn, strFileOut);
	}

	this.SOF_DecryptFile = function(strContainerName, strFileIn, strFileOut)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_DecryptFile(strContainerName, strFileIn, strFileOut);
	}

	this.SOF_SignMessage = function(u16Flag,strContainerName, strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_SignMessage(u16Flag,strContainerName, strDataIn);
	}

	this.SOF_VerifySignedMessage = function(strDataOut, strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_VerifySignedMessage(strDataOut, strDataIn);
	}

	this.SOF_GetInfoFromSignedMessage = function(strMessageData, u16Type)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetInfoFromSignedMessage(strMessageData, u16Type);
	}

	this.SOF_SignDataXML = function(strContainerName,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_SignDataXML(strContainerName,strDataIn);
	}

	this.SOF_VerifySignedDataXML = function(strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_VerifySignedDataXML(strDataIn);
	}

	this.SOF_GetXMLSignatureInfo = function(strDataIn, u16Type)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetXMLSignatureInfo(strDataIn, u16Type);
	}

	this.SOF_GenRandom = function(u16Type)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GenRandom(u16Type);
	}

	this.SOF_PubKeyEncrypt = function(strCert,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_PubKeyEncrypt(strCert,strDataIn);
	}

	this.SOF_PriKeyDecrypt = function(strContainerName,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_PriKeyDecrypt(strContainerName,strDataIn);
	}

	this.SOF_PubKeyEncryptLongData = function(strCert,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_PubKeyEncryptLongData(strCert,strDataIn);
	}

	this.SOF_PriKeyDecryptLongData = function(strContainerName,strDataIn)
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_PriKeyDecryptLongData(strContainerName,strDataIn);
	}

	this.SOF_Logout = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_Logout();
	}

	this.SOF_GetLastError = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_GetLastError();
	}

	this.SOF_InitializeLibraryNative = function(strLibrary)
	{
		var ret;
		if(null == g_MIXPlugin)
		{
			g_MIXPlugin = document.getElementById(object);
			g_MIXPlugin.setAttribute("type", "application/x-fbwtsofplugin");
			
			if("1.0.0.0" == g_MIXPlugin.version)
			{
				//console.log(g_MIXPlugin.version);
				//alert(g_MIXPlugin.version);
			}
			else
			{
				g_MIXPlugin = new MIXCorePlugin();
			}
		}
		
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_InitializeLibraryNative(strLibrary);
	}

	this.SOF_FinalizeLibraryNative = function()
	{
		if(null == g_MIXPlugin)
		{
			return null;
		}
		return g_MIXPlugin.SOF_FinalizeLibraryNative();
	}
}


function MIXCorePlugin(){

	var url = "http://localhost:50000/npfbwtsof_plugin";
	
	var xhr ;
	
	function MixProcess(json) {
		if(null == xhr) {
			if (window.XMLHttpRequest) {
				xhr = new XMLHttpRequest();
			} else {
				xhr = new ActiveXObject("Microsoft.XMLHTTP");
			}
		}
		xhr.open("POST", url, false);
		xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
		xhr.send(json);
	}

	this.SOF_GetVersion = function()
	{
		var json = {
			exec_name:"SOF_GetVersion",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	
	this.SOF_SetSignMethod = function(ulMethod)
	{
		var json = {
			exec_name:"SOF_SetSignMethod",
			exec_arg_real_list:[ulMethod]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_GetSignMethod = function()
	{
		var json = {
			exec_name:"SOF_GetSignMethod",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_SetEncryptMethod = function(ulMethod)
	{
		var json = {
			exec_name:"SOF_SetEncryptMethod",
			exec_arg_real_list:[ulMethod]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_GetEncryptMethod = function()
	{
		var json = {
			exec_name:"SOF_GetEncryptMethod",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_GetUserList = function()
	{
		var json = {
			exec_name:"SOF_GetUserList",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_ExportUserCert = function(strContainerName)
	{
		var json = {
			exec_name:"SOF_ExportUserCert",
			exec_arg_real_list:[strContainerName]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_Login = function(strContainerName, strPIN)
	{
		var json = {
			exec_name:"SOF_Login",
			exec_arg_real_list:[strContainerName, strPIN]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_GetPinRetryCount = function(strContainerName)
	{
		var json = {
			exec_name:"SOF_GetPinRetryCount",
			exec_arg_real_list:[strContainerName]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_ChangePassWd = function(strContainerName, strPINOld, strPINNew)
	{
		var json = {
			exec_name:"SOF_ChangePassWd",
			exec_arg_real_list:[strContainerName, strPINOld, strPINNew]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_ExportExChangeUserCert = function(strContainerName)
	{
		var json = {
			exec_name:"SOF_ExportExChangeUserCert",
			exec_arg_real_list:[strContainerName]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_GetCertInfo = function(strCert, u16Type)
	{
		var json = {
			exec_name:"SOF_GetCertInfo",
			exec_arg_real_list:[strCert, u16Type]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_GetCertInfoByOid = function(strCert, strOidString)
	{
		var json = {
			exec_name:"SOF_GetCertInfoByOid",
			exec_arg_real_list:[strCert, strOidString]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_GetDeviceInfo = function(strContainerName, ulType)
	{
		var json = {
			exec_name:"SOF_GetDeviceInfo",
			exec_arg_real_list:[strContainerName, ulType]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_ValidateCert = function(strCert)
	{
		var json = {
			exec_name:"SOF_ValidateCert",
			exec_arg_real_list:[strCert]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_SignData = function(strContainerName, strDataIn)
	{
		var json = {
			exec_name:"SOF_SignData",
			exec_arg_real_list:[strContainerName, strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_VerifySignedData = function( strCert, strDataIn, strDataOut)
	{
		var json = {
			exec_name:"SOF_VerifySignedData",
			exec_arg_real_list:[ strCert, strDataIn, strDataOut]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_SignFile = function(  strContainerName, strFileIn)
	{
		var json = {
			exec_name:"SOF_SignFile",
			exec_arg_real_list:[ strContainerName, strFileIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_VerifySignedFile = function(  strCert, strFileIn, strDataOut)
	{
		var json = {
			exec_name:"SOF_VerifySignedFile",
			exec_arg_real_list:[ strCert, strFileIn, strDataOut]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_EncryptData = function( strCert,  strDataIn)
	{
		var json = {
			exec_name:"SOF_EncryptData",
			exec_arg_real_list:[ strCert,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_DecryptData = function( strContainerName,  strDataIn)
	{
		var json = {
			exec_name:"SOF_DecryptData",
			exec_arg_real_list:[ strContainerName,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_EncryptFile = function( strCert, strFileIn, strFileOut)
	{
		var json = {
			exec_name:"SOF_EncryptFile",
			exec_arg_real_list:[ strCert, strFileIn, strFileOut]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_DecryptFile = function( strContainerName, strFileIn, strFileOut)
	{
		var json = {
			exec_name:"SOF_DecryptFile",
			exec_arg_real_list:[ strContainerName, strFileIn, strFileOut]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_SignMessage = function( u16Flag,  strContainerName, strDataIn)
	{
		var json = {
			exec_name:"SOF_SignMessage",
			exec_arg_real_list:[ u16Flag,  strContainerName, strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_VerifySignedMessage = function(strDataOut, strDataIn)
	{
		var json = {
			exec_name:"SOF_VerifySignedMessage",
			exec_arg_real_list:[ strDataOut, strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_GetInfoFromSignedMessage = function( strMessageData, u16Type)
	{
		var json = {
			exec_name:"SOF_GetInfoFromSignedMessage",
			exec_arg_real_list:[ strMessageData, u16Type]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_SignDataXML = function( strContainerName,  strDataIn)
	{
		var json = {
			exec_name:"SOF_SignDataXML",
			exec_arg_real_list:[ strContainerName,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_VerifySignedDataXML = function( strDataIn)
	{
		var json = {
			exec_name:"SOF_VerifySignedDataXML",
			exec_arg_real_list:[ strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_GetXMLSignatureInfo = function( strDataIn, u16Type)
	{
		var json = {
			exec_name:"SOF_GetXMLSignatureInfo",
			exec_arg_real_list:[ strDataIn, u16Type]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_GenRandom = function( u16Type)
	{
		var json = {
			exec_name:"SOF_GenRandom",
			exec_arg_real_list:[ u16Type]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_PubKeyEncrypt = function( strCert,  strDataIn)
	{
		var json = {
			exec_name:"SOF_PubKeyEncrypt",
			exec_arg_real_list:[ strCert,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	
	this.SOF_PriKeyDecrypt = function( strContainerName,  strDataIn)
	{
		var json = {
			exec_name:"SOF_PriKeyDecrypt",
			exec_arg_real_list:[ strContainerName,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_PubKeyEncryptLongData = function( strCert,  strDataIn)
	{
		var json = {
			exec_name:"SOF_PubKeyEncryptLongData",
			exec_arg_real_list:[ strCert,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_PriKeyDecryptLongData = function(strContainerName,  strDataIn)
	{
		var json = {
			exec_name:"SOF_PriKeyDecryptLongData",
			exec_arg_real_list:[ strContainerName,  strDataIn]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_Logout = function()
	{
		var json = {
			exec_name:"SOF_Logout",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}

	this.SOF_GetLastError = function()
	{
		var json = {
			exec_name:"SOF_GetLastError",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
	this.SOF_InitializeLibraryNative = function(strLibrary)
	{
		var json = {
			exec_name:"SOF_InitializeLibraryNative",
			exec_arg_real_list:[strLibrary]
		};
			
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}

		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;

		}else{
			return -2;
		}
	};
	

	
	this.SOF_FinalizeLibraryNative = function()
	{
		var json = {
			exec_name:"SOF_FinalizeLibraryNative",
			exec_arg_real_list:[]
		};
		
		try
		{
			MixProcess(JSON.stringify(json));
		}
		catch (e)
		{
			return -3;
		}
		
		if(4 == xhr.readyState && 200 == xhr.status) {
			var object = eval("(" + xhr.responseText + ")");
			return object.exec_result;
		}else{
			return -2;
		}
	}
	
}
