/**********************************************************\

  Auto-generated FBWTSofPluginAPI.h

\**********************************************************/

#include <string>
#include <sstream>

#include "sof_client.h"

#ifndef H_FBWTSofPluginAPI
#define H_FBWTSofPluginAPI

class FBWTSofPluginAPI
{
public:
    ////////////////////////////////////////////////////////////////////////////
    /// @fn FBWTSofPluginAPI::FBWTSofPluginAPI(const FBWTSofPluginPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ////////////////////////////////////////////////////////////////////////////
    FBWTSofPluginAPI()
    {
		ckpFunctions = NULL;

		//if (NULL == ckpFunctions)
		//{
		//	ulResult = SOF_InitializeLibraryNative("WTSKFInterface.dll", &ckpFunctions);
		//	if (SOR_OK != ulResult)
		//	{
		//		//MessageBox()
		//	}
		//}
	}

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn FBWTSofPluginAPI::~FBWTSofPluginAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////////
    virtual ~FBWTSofPluginAPI() {
		::SOF_FinalizeLibraryNative(ckpFunctions);
	};

    // Read/Write property ${PROPERTY.ident}
    std::string get_testString();
    void set_testString(const std::string& val);

	std::string FunTestString();

	std::string SOF_GetVersion();

	ULONG SOF_SetSignMethod(ULONG ulMethod);

	ULONG SOF_GetSignMethod();

	ULONG SOF_SetEncryptMethod(ULONG ulMethod);

	ULONG SOF_GetEncryptMethod();

	std::string SOF_GetUserList();

	std::string SOF_ExportUserCert(std::string strContainerName);

	BOOL SOF_Login(std::string strContainerName,std::string strPIN);

	ULONG SOF_GetPinRetryCount(std::string strContainerName);

	BOOL SOF_ChangePassWd( std::string strContainerName, std::string strPINOld, std::string strPINNew);

	std::string SOF_ExportExChangeUserCert( std::string strContainerName);

	std::string SOF_GetCertInfo(std::string strCert, UINT16 u16Type);

	std::string SOF_GetCertInfoByOid(std::string strCert, std::string strOidString);

	std::string SOF_GetDeviceInfo( std::string strContainerName, ULONG ulType);

	ULONG SOF_ValidateCert(std::string strCert);

	std::string SOF_SignData( std::string strContainerName, std::string strDataIn);

	BOOL SOF_VerifySignedData(std::string strCert, std::string strDataIn, std::string strDataOut);

	std::string SOF_SignFile( std::string strContainerName, std::string strFileIn);

	BOOL SOF_VerifySignedFile(std::string strCert, std::string strFileIn, std::string strDataOut);

	std::string SOF_EncryptData(std::string strCert,  std::string strDataIn);

	std::string SOF_DecryptData( std::string strContainerName,  std::string strDataIn);

	BOOL SOF_EncryptFile(std::string strCert, std::string strFileIn, std::string strFileOut);

	BOOL SOF_DecryptFile( std::string strContainerName, std::string strFileIn, std::string strFileOut);

	std::string SOF_SignMessage( UINT16 u16Flag,  std::string strContainerName, std::string strDataIn);

	BOOL SOF_VerifySignedMessage(  std::string strDataIn, std::string strDataOut);

	std::string SOF_GetInfoFromSignedMessage(std::string strMessageData, UINT16 u16Type);

	std::string SOF_SignDataXML( std::string strContainerName,  std::string strDataIn);

	BOOL SOF_VerifySignedDataXML(std::string strDataIn);

	std::string SOF_GetXMLSignatureInfo(std::string strDataIn, UINT16 u16Type);

	std::string SOF_GenRandom( UINT16 u16Type);


	std::string SOF_PubKeyEncrypt(std::string strCert,  std::string strDataIn);

	std::string SOF_PriKeyDecrypt( std::string strContainerName,  std::string strDataIn);

	std::string SOF_PubKeyEncryptLongData(std::string strCert,  std::string strDataIn);

	std::string SOF_PriKeyDecryptLongData( std::string strContainerName,  std::string strDataIn);

	BOOL SOF_Logout();


	ULONG SOF_GetLastError();

	BOOL SOF_InitializeLibraryNative(std::string strLibrary);

	BOOL SOF_FinalizeLibraryNative();

	void SOF_GetDefaultContainer();

private:

	CK_SKF_FUNCTION_LIST *ckpFunctions;
    std::string m_testString;
	ULONG ulResult;
	std::string m_default_container;
};

#endif // H_FBWTSofPluginAPI

