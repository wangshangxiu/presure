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
#define TASK_THREAD_NUM 5
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

typedef struct {
    const void* stream = nullptr; //uv_stream_t*
    void* UserInfoPtr = nullptr; //UserInfo
    char *packBuf = nullptr;
    int len = 0;
}ImPack;

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

typedef struct 
{
    long long startConnectTime = 0;
    long long loginTime = 0;
    long long loginRspTime = 0;
    int loginStatus = -1;//0成功， 非0失败，主要是和登录协议的status一致
}LoginInfo;

typedef struct {
    long long userId = 0;//db有
    long long loginSeq = 0;//程序产生
    int  seq = 0;
    std::string  devId; //设备ID，db有
    std::string  authToken;//验证token，db有
    std::string ecdhKey[2];//signal key pair，协商密钥对,index=0, pub; index=1, pri
    std::string aesKey;//开始是自己，成功换成服务器生成的
    std::string sessionId;//
    ConnInfo info;//连接信息
    LoginInfo  loginInfo;//登录事务信息
    uv_timer_t *timer = nullptr;//用户心跳定时器
    uv_timer_t *msgTimer = nullptr;//消息定时器
    const uv_tcp_t *conn = nullptr;//此用户使用的连接

    void reCycleSource()
    {
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

typedef struct 
{
    std::vector<UserInfo> *vUserInfo;
    int iBatch;//周期内发起的并发数
    int iPerio;//周期
}UTimerData;

namespace globalFuncation
{
long long GetMicrosecond();
bool LoadConfig(util::CJsonObject& oConf, const char* strConfFile);
bool LoadUserInfoFromFile(std::vector<UserInfo>& userInfo, const std::string& strPath);
void StringSplit(const std::string& strSrc, std::vector<std::string>& vec, char c= ':');
};
#endif//_COMM_H
