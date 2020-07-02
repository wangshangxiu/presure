/********************************************
//文件名:tx_define.h

//功能:  

//作者: 

//创建时间: 

//修改记录:

//修改者
*********************************************/
#ifndef __TX_DEFINE_H__
#define __TX_DEFINE_H__

//宏定义
#define MAX_LEN 				24 * 1024		//最大数据包32k
#define HEAD_LEN 				12			//固定包头长度20字节
#define MAX_MSG_LEN				24 * 1024		//消息内容最大长度

//服务器类型定义
 

//终端类型定义
#define C_IOS					1
#define C_ANDROID				2


typedef long long 		int64;
typedef unsigned long long 	uint64;
typedef int			int32;
typedef unsigned int		uint32;	
typedef unsigned char		uint8;
typedef unsigned short		uint16;
 





#endif //__TX_DEFINE_H__

