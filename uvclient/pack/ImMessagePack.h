#ifndef _TEST_IM_MESSAGE_H
#define _TEST_IM_MESSAGE_H
#include "pack.h"
#include "msg.pb.h"
#include "login.pb.h"
#include "ImError.h"
#include "client.pb.h"
#define USER_CONCURRENT_QUEUE
class ImMessagePack: public Pack
{
public:
    ImMessagePack(RingBuffer* recvRb, void *recvMem, RingBuffer* sendRb, void* sendMem, uv_async_t* uvAsyn, int index);
    ImMessagePack(moodycamel::ConcurrentQueue<ImPack>* recvCQ, moodycamel::ConcurrentQueue<CustomEvent>* sendCQ, uv_async_t* uvAsyn, int index);
    ImMessagePack();
    ~ImMessagePack();
public:
    virtual void OnThread();
    //主动请求
    static void LoginReq(UserInfo& userInfo, MsgBody& msgBody);
    static void HeatBeatReq(const UserInfo& userInfo, MsgBody& msgBody);
    static void MsgChatReq(const UserInfo& userInfo, MsgBody& msgBody);
    static void GroupChatReq(const UserInfo& userInfo, MsgBody& msgBody);

    void CallDoTask(const ImPack& pack);
private:
    //被动接收回复
    void LoginRsp(const ImPack& pack);
    void HearBeatRsp(const ImPack& pack);
    void MsgChatRsp(const ImPack& pack);
    void GroupChatRsp(const ImPack& pack);
};


#endif //_TEST_IM_MESSAGE_H