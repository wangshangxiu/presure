/***
 * 不同的业务接口回调（命令字）可以通过继承这个类，具体参考子类
 ***/
#ifndef _PACK_H_
#define _PACK_H_
#include <map>
#include <uv.h>
#include "logger.h"
#include "comm.h"
#include "ring_buffer.h"
#include "msg.pb.h"
class Pack
{
public:
    Pack(RingBuffer* recvRb, void *recvMem, RingBuffer* sendRb, void* sendMem, uv_async_t* uvAsyn, int index);
    Pack();//
    ~Pack();
    static void StartThread(void *p);                           //线程函数入口
    typedef void (Pack::*MemberFuntionPointer)(const ImPack& pack);

    static void SendMsg(uv_tcp_t* handle, int icmd , const std::string& msgBody, bool bEncryt = true);//作为服务器时的发送函数
protected:
    virtual void OnThread();                                    //线程函数
    void DoTask(const ImPack& pack);                            //在线程函数里根据处理业务回调
    void ConnectMemberFun(int cmd , MemberFuntionPointer fun);  //建立命令字和函数的回调映射
    MemberFuntionPointer GetMemberFun(int icmd);                //根据命令字获取相应的回调函数
    
protected:
    std::map<int, MemberFuntionPointer> m_mapMemberFun;
    RingBuffer *m_recvRb;                                       //业务线程处理数据包的无锁缓冲对象
    void *m_recvMem;                                            //业务线程处理数据包的无锁缓冲内存区
    RingBuffer *m_sendRb;                                       //业务线程发送数据包投递的无锁缓冲
    void *m_sendMem;                                            //业务线程发送数据包投递的无锁缓冲内存区
    uv_async_t  *m_asyn_send;                                   //异步通知socket线程
    int m_index;                                                //线程号
};




#endif
