/**
 * Created by LQQ on 2017/11/13.
 */

#ifndef _SOF_CLIENTN_H_
#define _SOF_CLIENTN_H_

#define	SOR_OK							0x00000000		//成功
#define	SOR_UNKNOWNERR					0x0B000001		//异常错误
#define	SOR_NOTSUPPORTYETERR			0x0B000002		//不支持的服务
#define	SOR_FILEERR						0x0B000003		//文件操作错误
#define SOR_PROVIDERTYPEERR             0x0B000004      //服务提供者参数类型错误
#define SOR_LOADPROVIDERERR             0x0B000005      //导入服务提供者接口错误
#define SOR_LOADDEVMNGAPIERR            0x0B000006      //导入设备管理接口错误
#define SOR_ALGTYPEERR                  0x0B000007      //算法类型错误
#define	SOR_NAMELENERR                  0x0B000008		//名称长度错误
#define	SOR_KEYUSAGEERR                 0x0B000009		//密钥用途错误
#define	SOR_MODULUSLENERR               0x0B000010		//模的长度错误
#define	SOR_NOTINITIALIZEERR            0x0B000011      //未初始化
#define	SOR_OBJERR                  	0x0B000012      //对象错误
#define	SOR_MEMORYERR                  	0x0B000100      //内存错误
#define	SOR_TIMEOUTERR                  0x0B000101      //服务超时
#define	SOR_INDATALENERR                0x0B000200		//输入数据长度错误
#define	SOR_INDATAERR                  	0x0B000201		//输入数据错误
#define	SOR_GENRANDERR                  0x0B000300		//生成随机数错误
#define	SOR_HASHOBJERR                  0x0B000301      //HASH对象错误
#define	SOR_HASHERR                  	0x0B000302      //HASH运算错误
#define	SOR_GENRSAKEYERR                0x0B000303      //产生RSA密钥错误
#define	SOR_RSAMODULUSLENERR            0x0B000304		//RSA密钥模长错误
#define	SOR_CSPIMPORTPUBKEYERR          0x0B000305      //CSP导入公钥错误
#define	SOR_RSAENCERR                  	0x0B000306      //RSA加密错误
#define	SOR_RSADECERR                  	0x0B000307      //RSA解密错误
#define	SOR_HASHNOTEQUALERR             0x0B000308		//HASH值不相等     
#define	SOR_KEYNOTFOUNDERR              0x0B000309      //密钥未发现    
#define	SOR_CERTNOTFOUNTERR             0x0B000310      //证书未发现     
#define	SOR_NOTEXPORTERR                0x0B000311      //对象未导出  
#define	SOR_VERIFYPOLICYERR             0x0B000312      //未能完全按照策略验证成功
#define	SOR_DECRYPTPADERR               0x0B000400      //解密时做补丁错误   
#define	SOR_MACLENERR                   0x0B000401      //MAC长度错误
#define	SOR_KEYINFOTYPEERR              0x0B000402      //密钥类型错误    
#define	SOR_NULLPOINTERERR              0x0B000403      //某一个参数为空指针   
#define	SOR_APPNOTFOUNDERR              0x0B000404		//没有找到该应用  
#define	SOR_CERTENCODEERR               0x0B000405      //证书编码格式错误   
#define	SOR_CERTINVALIDERR              0x0B000406      //证书无效，不是可信CA颁发的证书    
#define	SOR_CERTHASHEXPIREDERR          0x0B000407      //证书已过期        
#define	SOR_CERTREVOKEDERR              0x0B000408		//证书已经被吊销         
#define	SOR_SIGNDATAERR                 0x0B000409      //签名失败     
#define	SOR_VERIFYSIGNDATAERR           0x0B000410      //验证签名失败            
#define	SOR_READFILEERR                 0x0B000411      //读文件异常，可能文件不存在或没有读取权限等   
#define	SOR_WRITEFILEERR                0x0B000412      //写文件异常，可能文件不存在或没有写权限等
#define	SOR_SECRETSEGMENTERR            0x0B000413      //门限算法密钥分割失败          
#define	SOR_SECRETRECOVERYERR           0x0B000414		//门限恢复失败      
#define	SOR_ENCRYPTDATAERR              0x0B000415      //对数据的对策加密失败       
#define	SOR_DECYPTDATAERR               0x0B000416      //对称算法的数据解密失败       
#define	SOR_PKCS7ENCODEERR              0x0B000417      //PKCS7编码格式错误            
#define	SOR_XMLENCODEERR                0x0B000418		//不是合法的XML编码数据         
#define	SOR_PARAMETERNOTSUPPORTEERR     0x0B000419      //不支持的参数                  
#define	SOR_CTLNOTFOUND                 0x0B000420      //没有发现信任链表   
#define	SOR_APPNOTFOUND                 0x0B000421      //设置的应用名称没发现   



#endif /* _SOF_CLIENTN_H_ */
