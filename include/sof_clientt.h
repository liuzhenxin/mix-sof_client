/**
 * Created by LQQ on 2017/11/13.
 */


#ifndef _SOF_CLIENTT_H_
#define _SOF_CLIENTT_H_ 1

#define SGD_CERT_VERSION                         0x00000001      //证书版本
#define SGD_CERT_SERIAL                          0x00000002      //证书序列号
#define SGD_CERT_ISSUER							 0x00000005      //证书颁发者信息
#define SGD_CERT_VALID_TIME						 0x00000006      //证书有效期
#define SGD_CERT_SUBJECT						 0x00000007      //证书拥有者信息
#define SGD_CERT_DER_PUBLIC_KEY					 0x00000008      //证书公钥信息
#define SGD_CERT_EXTENSIONS						 0x00000009      //证书扩展项信息
#define SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO		 0x00000011      //颁发者密钥标示符
#define SGD_EXT_SUBJECTKEYIDENTIFIER_INFO		 0x00000012      //证书持有者密钥标示符
#define SGD_EXT_KEYUSAGE_INFO					 0x00000013      //密钥用途
#define SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO		 0x00000014      //私钥有效期
#define SGD_EXT_CERTIFICATEPOLICIES_INFO		 0x00000015      //证书策略
#define SGD_EXT_POLICYMAPPINGS_INFO				 0x00000016      //策略映射
#define SGD_EXT_BASICCONSTRAINTS_INFO			 0x00000017      //基本限制
#define SGD_EXT_PROLICYCONSTRAINS_INFO			 0x00000018      //策略限制
#define SGD_EXT_EXTKEYUSAGE_INFO				 0x00000019      //扩展密钥用途
#define SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO		 0x0000001A      //CRL发布点
#define SGD_EXT_NETSCAPE_CERT_TYPE_INFO			 0x0000001B      //Netscape属性
#define SGD_EXT_SELFDEFINED_EXTENSION_INFO		 0x0000001C      //私有的自定义扩展项
#define SGD_CERT_ISSUER_CN						 0x00000021      //证书颁发者CN
#define SGD_CERT_ISSUER_O						 0x00000022      //证书颁发者O
#define SGD_CERT_ISSUER_OU						 0x00000023      //证书颁发者OU
#define SGD_CERT_SUBJECT_CN						 0x00000031      //证书持有者信息CN
#define SGD_CERT_SUBJECT_O						 0x00000032      //证书持有者信息O
#define SGD_CERT_SUBJECT_OU						 0x00000033      //证书持有者信息OU
#define SGD_CERT_SUBJECT_EMAIL					 0x00000034      //证书持有者信息EMAIL
/*0x00000080~0x000000FF 为其他证书解析项预留*/



#define SGD_DEVICE_SORT                          0x00000201       //设备类型
#define SGD_DEVICE_TYPE                          0x00000202       //设备型号
#define SGD_DEVICE_NAME							 0x00000203		  //设备名称
#define SGD_DEVICE_MANUFACTURER					 0x00000204		  //生成厂商
#define SGD_DEVICE_HARDWARE_VERSION				 0x00000205		  //硬件版本
#define SGD_DEVICE_SOFTWARE_VERSION				 0x00000206		  //软件版本
#define SGD_DEVICE_STANDARD_VERSION				 0x00000207		  //符合标准版本
#define SGD_DEVICE_SERIAL_NUMBER				 0x00000208		  //设备编号
#define SGD_DEVICE_SUPPORT_ALG_ASYM			     0x00000209		  //设备能力非对称
#define SGD_DEVICE_SUPPORT_ALG_SYM				 0x0000020A		  //设备能力对称
#define SGD_DEVICE_SUPPORT_HASH_ALG				 0x0000020B		  //设备能力杂凑
#define SGD_DEVICE_SUPPORT_STORAGE_SPACE		 0x0000020C		  //设备能力最大文件存储空间
#define SGD_DEVICE_SUPPORT_FREE_SPACE			 0x0000020D		  //设备能力空闲文件存储空间
#define SGD_DEVICE_RUNTIME						 0x0000020E		  //已运行时间
#define SGD_DEVICE_USED_TIMES					 0x0000020F		  //设备被调用次数
#define SGD_DEVICE_LOCATION						 0x00000210		  //设备物理位置
#define SGD_DEVICE_DESCRIPTION					 0x00000211		  //设备描述
#define SGD_DEVICE_MANAGER_INFO					 0x00000212		  //设备管理者描述信息
#define SGD_DEVICE_MAX_DATA_SIZE				 0x00000213		  //设备一次能处理的数据容量


//errorCode
#include "sof_clientn.h"


/* packing defines */
#include "skfp.h"


/* undo packing */
#include "skfu.h"

#endif
