#ifndef _COMM_H_
#define _COMM_H_

#include <string>
#include <vector>
#include <uv.h>
#include "log4cplus/fileappender.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "CJsonObject.hpp"

//框架日志都使用本系列日志接口
#define LOG4_FATAL(...) LOG4CPLUS_FATAL_FMT(Logger::GetInstance()->GetLogger(), ##__VA_ARGS__)
#define LOG4_ERROR(...) LOG4CPLUS_ERROR_FMT(Logger::GetInstance()->GetLogger(), ##__VA_ARGS__)
#define LOG4_WARN(...) LOG4CPLUS_WARN_FMT(Logger::GetInstance()->GetLogger(), ##__VA_ARGS__)
#define LOG4_INFO(...) LOG4CPLUS_INFO_FMT(Logger::GetInstance()->GetLogger(), ##__VA_ARGS__)
#define LOG4_DEBUG(...) LOG4CPLUS_DEBUG_FMT(Logger::GetInstance()->GetLogger(), ##__VA_ARGS__)
#ifdef _DEBUG
#define LOG4_TRACE(...) LOG4CPLUS_TRACE_FMT(Logger::GetInstance()->GetLogger(), ##__VA_ARGS__)
#else
#define LOG4_TRACE(...)
#endif

#define RB_SIZE 1024*16 
#define TASK_THREAD_NUM 1
#define USE_HEAD_LEN
#define USE_MUTI_THREAD
#define TCP_BUFFER_LEN 1024
#define AESKEY_LEN 256
#define CONNECTS_BACTH_PERIO 100
#define HEARBEAT_PERIO (3.5*60*1000)

#pragma pack(1)
#if 0
struct clientMsgHead
{
    unsigned short body_len;                ///< 长度（2字节）
    unsigned int seq;                       ///< 序列号（4字节）
    clientMsgHead() :body_len(0), seq(0)
    { 
    }
                
};
#endif
struct tagAppMsgHead
{
	unsigned int len = 0;                  ///< 消息体长度（4字节）
	unsigned int cmd = 0;                     ///< 命令字/功能号（4字节）
	unsigned int seq = 0;                       ///< 序列号（4字节）
	unsigned char version = 0;                  ///< 协议版本号（1字节）
    unsigned char reserve = 0;                  ///< 保留（1字节）  黄色 01 aes 10 rsa  绿色 01 gzip压缩
    unsigned short status = 0;                ///< 校验码（2字节）
    tagAppMsgHead() = default;
};

#pragma pack()

typedef struct {
    std::string ip;
    int port = 0;
    int connects = 0;
} ConnInfo;

//32字节一个包
typedef struct {
    const void* stream = nullptr; //uv_stream_t*
    void* UserInfoPtr = nullptr; //UserInfo
    char *packBuf = nullptr;
    int len = 0;
}ImPack;

//32字节一个包
typedef struct 
{
    enum {
        EVENT_DEFAULT,
        EVENT_LOGIN_SUCCESSE,
        EVENT_LOGIN_FAILED,
    };
    int ieventType = EVENT_DEFAULT;
    const void *handle = nullptr;
    const void *userInfo = nullptr;
    int istatus = 0;
}CustomEvent;

//常常忘记在枚举的'}'后加';'
enum
{
    E_TCP_CONNECTING = 0,
    E_TCP_ESHTABLISHED = 1,
    E_TCP_TIMEOUT = 2,     //TCP超时
    E_TCP_LOGINING = 3, //登录已经返回
    E_TCP_LOGINED = 4, //登录已经返回
};
typedef struct 
{
    long long startConnectTime = 0; //开始连接时间
    long long finConnectedTime = 0; //建立连接时间
    long long loginTime = 0;        //登录时间
    long long loginRspTime = 0;     //登录返回时间
    int loginStatus = -1;           //0成功， 非0失败，主要是和登录协议的status一致
    int state = 0;             //登录的状态， 包括发起tcp, 建立tcp, tcp超时
}LoginInfo;

typedef struct {
    long long userId = 0;               //db有
    long long loginSeq = 0;             //程序产生
    int  seq = 0;                       //

    std::string  devId;                 //设备ID，db有
    std::string  authToken;             //验证token，db有
    std::string ecdhKey[2];             //signal key pair，协商密钥对,index=0, pub; index=1, pri
    std::string aesKey;                 //开始是自己，成功换成服务器生成的
    std::string sessionId;              //

    ConnInfo info;                      //连接信息
    LoginInfo  loginInfo;               //登录事务信息

    uv_timer_t *timeOutTimer = nullptr; //超时定时器
    uv_timer_t *timer = nullptr;        //用户心跳定时器
    uv_timer_t *msgTimer = nullptr;     //消息定时器
    const uv_tcp_t *conn = nullptr;     //此用户使用的连接，这里不用负责内存回收

    void reCycleSource()
    {
        if(timeOutTimer)
        {
            uv_timer_stop((uv_timer_t*)timeOutTimer);
            uv_close((uv_handle_t*)timeOutTimer,[](uv_handle_t* handle){
                if(handle){
                    delete (uv_timer_t*)handle;
                }
            });
            timeOutTimer = nullptr;
        }
        if(timer)
        {
            uv_timer_stop((uv_timer_t*)timer);
            uv_close((uv_handle_t*)timer,[](uv_handle_t* handle){
                if(handle){
                    delete (uv_timer_t*)handle;
                }
            });
            timer = nullptr;
        }
        if(msgTimer)
        {
            uv_timer_stop((uv_timer_t*)msgTimer);
            uv_close((uv_handle_t*)msgTimer,[](uv_handle_t* handle){
                if(handle){
                    delete (uv_timer_t*)handle;
                }
            });
            msgTimer = nullptr;
        }
        if(conn)
        {
            conn == nullptr; //uv_tcp_t*,这里不用del,
        }
    }
}UserInfo;

//定时器函数的handle.data
typedef struct 
{
    std::vector<UserInfo> *vUserInfo; //用户列表
    int iBatch;                   //周期内发起的并发数
    int iPerio;                  //定时发起TCP的周期
    int connTimeout;             //连接超时的周期
    uv_loop_t* uvLoop = nullptr; //事件循环指针
    int processNum = 0;         //创建的子进程数
    std::string strQPSLog;      //qps结果文件输出目录
    int loginQps = 0;           //每秒qps
    int loginQpsPerio = 0;      //loginqps发出间隔, 1/毫秒，把一秒的qps拆成多次
    int loginSeq = 0;          //登录seq，每次启动需要从配置读，++回写，免得每次都要重置redis缓冲
}UTimerData;

namespace globalFuncation
{
long long GetMicrosecond();
//加载配置，顺便需要回写配置的一起操作
bool LoadConfig(util::CJsonObject& oConf, const char* strConfFile);
//解析CSV比JSON要快多了
bool LoadUserInfoFromJsonFile(std::vector<UserInfo>& userInfo, const std::string& strPath);
#if 0
bool LoadUserInfoFromCVSFile(std::vector<std::vector<UserInfo>>& vvUserInfo, const std::string& strPath, int smpleSize);
#endif
bool LoadUserInfoFromCVSFile(std::vector<UserInfo>& userInfo, const std::string& strPath, int offset = 0, int smpleSize = 200000);
void StringSplit(const std::string& strSrc, std::vector<std::string>& vec, char c= ':');
};
#endif//_COMM_H
