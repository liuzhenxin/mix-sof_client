/**
 * Created by LQQ on 2017/11/13.
 */


#ifndef _SKFT_H_
#define _SKFT_H_ 1

#include "common.h"

#define CK_DECLARE_FUNCTION(rtype,func) extern rtype CALL_CONVENTION func
#define CK_DECLARE_FUNCTION_POINTER(rtype,func) rtype (CALL_CONVENTION* func)



//errorCode
#include "skfn.h"

#define	SGD_SM1_ECB		0x00000101		//SM1算法ECB加密模式
#define	SGD_SM1_CBC		0x00000102		//SM1算法CBC加密模式
#define	SGD_SM1_CFB		0x00000104		//SM1算法CFB加密模式
#define	SGD_SM1_OFB		0x00000108		//SM1算法OFB加密模式
#define	SGD_SM1_MAC		0x00000110		//SM1算法MAC运算
#define	SGD_SSF33_ECB	0x00000201		//SSF33算法ECB加密模式
#define	SGD_SSF33_CBC	0x00000202		//SSF33算法CBC加密模式
#define	SGD_SSF33_CFB	0x00000204		//SSF33算法CFB加密模式
#define	SGD_SSF33_OFB	0x00000208		//SSF33算法OFB加密模式
#define	SGD_SSF33_MAC	0x00000210		//SSF33算法MAC运算
#define	SGD_SMS4_ECB	0x00000401		//SMS4算法ECB加密模式
#define	SGD_SMS4_CBC	0x00000402		//SMS4算法CBC加密模式
#define	SGD_SMS4_CFB	0x00000404		//SMS4算法CFB加密模式
#define	SGD_SMS4_OFB	0x00000408		//SMS4算法OFB加密模式
#define	SGD_SMS4_MAC	0x00000410		//SMS4算法MAC运算

#define SGD_3DES_ECB	0x00000001  //3DES算法ECB加密模式

#define	SGD_RSA			0x00010000		//RSA算法
#define	SGD_SM2_1		0x00020100		//椭圆曲线签名算法
#define	SGD_SM2_2		0x00020200		//椭圆曲线密钥交换协议
#define	SGD_SM2_3		0x00020400		//椭圆曲线加密算法

#define	SGD_SM3			0x00000001		//SM3密码杂凑算法
#define	SGD_SHA1		0x00000002		//SHA1密码杂凑算法
#define	SGD_SHA256		0x00000004		//SHA256密码杂凑算法

typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;

#if defined(WINDOWS) || defined(WIN32)
#include <Windows.h>
#else
typedef INT32 BOOL;
//CHAR	字符类型，无符号8位整数
typedef UINT8 CHAR;
//LONG 	长整数，有符号32位整数
typedef INT32 LONG;
//ULONG	长整数，无符号32位整数
typedef UINT32 ULONG;
//DWORD	双字类型，无符号32位整数
typedef UINT32 DWORD;
#endif

typedef UINT8 BYTE;
//SHORT	短整数，有符号16位
typedef INT16 SHORT;
//USHORT	无符号16位整数
typedef UINT16 USHORT;
//UINT	无符号32位整数
typedef UINT32 UINT;
//WORD	字类型，无符号16位整数
typedef UINT16 WORD;
//FLAGS	标志类型，无符号32位整数
typedef UINT32 FLAGS;
//LPSTR	8位字符串指针，按照UTF8格式存储及交换
typedef char * LPSTR;
//HANDLE 	句柄，指向任意数据对象的起始地址
typedef  void* HANDLE;
//DEVHANDLE	设备句柄
typedef HANDLE DEVHANDLE;
//HAPPLICATION	应用句柄
typedef HANDLE HAPPLICATION;
//HCONTAINER	容器句柄
typedef HANDLE HCONTAINER;

//6.3	常量定义
#ifndef TRUE
#define	TRUE	0x00000001		//布尔值为真
#endif

#ifndef FALSE
#define	FALSE	0x00000000		//布尔值为假
#endif

#ifndef DEVAPI
#define	DEVAPI
#endif

#ifndef ADMIN_TYPE
#define	ADMIN_TYPE	0			//管理员PIN类型
#endif

#ifndef USER_TYPE
#define	USER_TYPE	1			//用户PIN类型
#endif


//6.4.12	权限类型
#define SECURE_NEVER_ACCOUNT	0x00000000	//不允许
#define SECURE_ADM_ACCOUNT		0x00000001	//管理员权限
#define SECURE_USER_ACCOUNT		0x00000010	//用户权限
#define SECURE_ANYONE_ACCOUNT	0x000000FF	//任何人

//6.4.13	设备状态
#define DEV_ABSENT_STATE		0x00000000	//设备不存在
#define DEV_PRESENT_STATE		0x00000001	//设备存在
#define DEV_UNKNOW_STATE		0x00000002	//设备状态未知



/* packing defines */
#include "skfp.h"


//6.4	复合数据类型
//6.4.1	版本
typedef struct Struct_Version{
    BYTE major;		//主版本号
    BYTE minor;		//次版本号
}VERSION;
//主版本号和次版本号以"."分隔，例如 Version 1.0，主版本号为1，次版本号为0；Version 2.10，主版本号为2，次版本号为10。

//6.4.2	设备信息
typedef struct Struct_DEVINFO{
    VERSION		Version;					//版本号	数据结构版本号，本结构的版本号为1.0
    CHAR		Manufacturer[64];			//设备厂商信息	以 '\0'为结束符的ASCII字符串
    CHAR		Issuer[64];					//发行厂商信息	以 '\0'为结束符的ASCII字符串
    CHAR		Label[32];					//设备标签	以 '\0'为结束符的ASCII字符串
    CHAR		SerialNumber[32];			//序列号	以 '\0'为结束符的ASCII字符串
    VERSION		HWVersion;					//设备硬件版本
    VERSION		FirmwareVersion;			//设备本身固件版本
    ULONG		AlgSymCap;					//分组密码算法标识
    ULONG		AlgAsymCap;					//非对称密码算法标识
    ULONG		AlgHashCap;					//密码杂凑算法标识
    ULONG		DevAuthAlgId;				//设备认证使用的分组密码算法标识
    ULONG		TotalSpace;					//设备总空间大小
    ULONG		FreeSpace;					//用户可用空间大小
    //ULONG		MaxECCBufferSize;			// 能够处理的 ECC 加密数据大小
    //ULONG		MaxBufferSize;				//能够处理的分组运算和杂凑运算的数据大小
    BYTE  		Reserved[64];				//保留扩展
}DEVINFO,*PDEVINFO;

//6.4.3	RSA公钥数据结构
#define MAX_RSA_MODULUS_LEN 256			//算法模数的最大长度
#define MAX_RSA_EXPONENT_LEN 4			//算法指数的最大长度
typedef struct Struct_RSAPUBLICKEYBLOB{
    ULONG	AlgID;									//算法标识号
    ULONG	BitLen;									//模数的实际位长度	必须是8的倍数
    BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//模数n = p * q	实际长度为BitLen/8字节
    BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//公开密钥e	一般为0x00010001
}RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

//6.4.4	RSA私钥数据结构
typedef struct Struct_RSAPRIVATEKEYBLOB{
    ULONG	AlgID;									//算法标识号
    ULONG	BitLen;									//模数的实际位长度	必须是8的倍数
    BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//模数n = p * q	实际长度为BitLen/8字节
    BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//公开密钥e	一般为00010001
    BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];	//私有密钥d	实际长度为BitLen/8字节
    BYTE	Prime1[MAX_RSA_MODULUS_LEN/2];			//素数p	实际长度为BitLen/16字节
    BYTE	Prime2[MAX_RSA_MODULUS_LEN/2];			//素数q	实际长度为BitLen/16字节
    BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (p-1)的值	实际长度为BitLen/16字节
    BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (q -1)的值	实际长度为BitLen/16字节
    BYTE	Coefficient[MAX_RSA_MODULUS_LEN/2];		//q模p的乘法逆元	实际长度为BitLen/16字节
}RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

//6.4.5	ECC公钥数据结构
#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC算法X坐标的最大长度
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC算法Y坐标的最大长度
typedef struct Struct_ECCPUBLICKEYBLOB{
    ULONG	BitLen;											//模数的实际位长度	必须是8的倍数
    BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//曲线上点的X坐标	有限域上的整数
    BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];	//曲线上点的Y坐标	有限域上的整数
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

//6.4.6	ECC私钥数据结构
#define ECC_MAX_MODULUS_BITS_LEN 512 //ECC算法模数的最大长度。
typedef struct Struct_ECCPRIVATEKEYBLOB{
    ULONG	BitLen;											//模数的实际位长度	必须是8的倍数
    BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];			//私有密钥	有限域上的整数
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

//6.4.7	ECC密文数据结构
typedef struct Struct_ECCCIPHERBLOB{
    BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//与y组成椭圆曲线上的点（x，y）
    BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//与x组成椭圆曲线上的点（x，y）
    BYTE  HASH[32];											//明文的杂凑值
    ULONG	CipherLen;										//密文数据长度
    BYTE  Cipher[1];										//密文数据	实际长度为CipherLen
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

//6.4.8	ECC签名数据结构
//ECC算法模数的最大长度
typedef struct Struct_ECCSIGNATUREBLOB{
    BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];			//签名结果的r部分
    BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];			//签名结果的s部分
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

//6.4.9	分组密码参数
#define MAX_IV_LEN 32
typedef struct Struct_BLOCKCIPHERPARAM{
    BYTE	IV[MAX_IV_LEN];							//初始向量，MAX_IV_LEN为初始化向量的最大长度
    ULONG	IVLen;									//初始向量实际长度（按字节计算）
    ULONG	PaddingType;							//填充方式，0表示不填充，1表示按照PKCS#5方式进行填充
    ULONG	FeedBitLen;								//反馈值的位长度（按位计算）	只针对OFB、CFB模式
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

//6.4.10	ECC加密密钥对保护结构
typedef struct SKF_ENVELOPEDKEYBLOB{
    ULONG Version;							// 当前版本为 1
    ULONG ulSymmAlgID;						// 对称算法标识，限定ECB模式
    ULONG ulBits;							// 加密密钥对的密钥位长度
    BYTE cbEncryptedPriKey[64];				// 对称算法加密的加密私钥,加密私钥的原文为ECCPRIVATEKEYBLOB结构中的PrivateKey。
    // 其有效长度为原文的（ulBits + 7）/8
    ECCPUBLICKEYBLOB PubKey;				// 加密密钥对的公钥
    ECCCIPHERBLOB ECCCipherBlob;			// 用保护公钥加密的对称密钥密文。
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

//6.4.11	文件属性
typedef struct Struct_FILEATTRIBUTE{
    CHAR	FileName[32];					//文件名	以'\0'结束的ASCII字符串，最大长度为32
    ULONG	FileSize;						//文件大小	创建文件时定义的文件大小
    ULONG	ReadRights;						//读取权限	读取文件需要的权限
    ULONG	WriteRights;					//写入权限	写入文件需要的权限
} FILEATTRIBUTE, *PFILEATTRIBUTE;

/* undo packing */
#include "skfu.h"

#endif
