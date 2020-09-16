#include <unistd.h>
#include "encrypt_crypto.h"
#include "pack.h"
#include "connect.h"
// extern std::map<uv_tcp_t*, void*> g_mapConnCache;
const unsigned char g_Aes_ReserveBit  = 0x04;          ///< 采用256位aes
Pack::Pack(RingBuffer* recvRb, void *recvMem, RingBuffer* sendRb, void* sendMem, uv_async_t* uvAsyn, int index) :
    m_recvRb(recvRb),
    m_recvMem(recvMem),
    m_sendRb(sendRb),
    m_sendMem(sendMem),
    m_asyn_send(uvAsyn),
    m_index(index)
{
}
Pack::Pack():
    m_recvRb(nullptr),
    m_recvMem(nullptr),
    m_sendRb(nullptr),
    m_sendMem(nullptr),
    m_asyn_send(nullptr),
    m_index(0)
{
}

Pack::~Pack()
{
    m_recvRb = nullptr;
    m_recvMem = nullptr;
    m_sendRb = nullptr;
    m_sendMem = nullptr;
    m_asyn_send = nullptr;
    m_index = 0;

    m_mapMemberFun.clear();
}


void Pack::ConnectMemberFun(int cmd , MemberFuntionPointer fun)
{
    if (m_mapMemberFun.find(cmd) == m_mapMemberFun.end())
    {
        m_mapMemberFun.insert(std::make_pair(cmd, fun));
    }
}

Pack::MemberFuntionPointer Pack::GetMemberFun(int icmd)
{
    const auto& iter = m_mapMemberFun.find(icmd);
    if (iter != m_mapMemberFun.end())
    {
        return iter->second;
    }
    return nullptr;
}

void Pack::StartThread(void* p)
{
    if(p)
    {
        Pack* pPack = (Pack*)p;
        pPack->OnThread();
    }
}

void Pack::OnThread()
{
    for(;;)
    {
        ImPack pack; 
        unsigned int len = sizeof(ImPack);
        int ret = m_recvRb->pop(&pack , &len, m_recvMem);
        if(ret == 0)
        {
            LOG4_INFO("pop pack of  stream(%p) from ringbuffer, pack->packBuf(%p), pack->len(%d), rb_recv(%p), p_recv_mem(%p)",pack.stream, pack.packBuf, pack.len, m_recvRb, m_recvMem);
            DoTask(pack);
            if(pack.packBuf)
            {
                delete pack.packBuf;//回收在socket线程分配出来的包内存
            } 
            uv_async_send(m_asyn_send);
        }
        else if(ret == -2)
        { 
            LOG4_ERROR("m_recvRb->pop(&pack , &len, m_recvMem) error");
        }
        else
        {
            usleep(1000);//缓冲为空，业务线程可以休眠1ms
        }
    }
}

void Pack::DoTask(const ImPack& pack)
{
    int icmd = ntohl(*(unsigned int*)(pack.packBuf + 4));//移动4个字节就是cmd
    MemberFuntionPointer fun = GetMemberFun(icmd);
    if(fun)
    {
        (this->*fun)(pack);
    }
}


void Pack::SendMsg(uv_tcp_t* handle, int icmd , const std::string& msgBody, bool bEncryt)
{
    LOG4_INFO("-------SendMsg on stream(%p), strMsgBody len(%d), bEncrypt(%d)---------",handle, msgBody.size(), bEncryt);
    uv_write_t *wReq = new uv_write_t;
    wReq->data = handle;
    uv_buf_t bufArray[2] = {{0, 0},{0, 0}};
    auto iter = uvconn::g_mapConnCache.find((uv_tcp_t*)handle);//判断连接是否还在
    if(iter == uvconn::g_mapConnCache.end())
    {
        LOG4_ERROR("stream(%p) no exist, maybe have recycle", handle);
        //需要再用时，连接不在了需要回收资源吗
        return;
    }
    UserInfo *pUserInfo = (UserInfo*)handle->data;
    tagAppMsgHead head;
    std::string data;
    if(bEncryt)//msgBody被加密
    {
        if(pUserInfo)
        {
            std::string& strAesKey = pUserInfo->aesKey;
            if(strAesKey.size() > 0)
            {
                if(!Aes256Encrypt(msgBody, data, strAesKey))
                {
                    LOG4_ERROR("aes encrypt error, data(%s)", data.c_str());
                }
            }
            else
            {
                LOG4_ERROR("strAesKey error, strAesKey(%s) size = %d", strAesKey.c_str(), (int)strAesKey.size());    
            }
        }
        else
        {
            LOG4_ERROR("there is no userInfo, pUserInfo (%p)", pUserInfo);
        }
#ifdef USE_HEAD_LEN
        head.len = data.size() + sizeof(tagAppMsgHead);
#else
        head.len = data.size();
#endif
        head.reserve |= g_Aes_ReserveBit;//aes 加密
    }
    else
    {
#ifdef USE_HEAD_LEN
        head.len = msgBody.size() + sizeof(tagAppMsgHead);
#else
        head.len = msgBody.size();
#endif
    }
    head.cmd = icmd;
    if(pUserInfo) {head.seq = pUserInfo->seq++;}
    head.len = htonl(head.len);
    head.cmd = htonl(head.cmd);
    head.seq = htonl(head.seq);
    bufArray[0].base = (char*)&head;
    bufArray[0].len = sizeof(tagAppMsgHead);
    if(bEncryt)//msgBody被加密
    {
        bufArray[1].base = (char*)data.c_str();
        bufArray[1].len = data.size(); 
    }
    else
    {
        bufArray[1].base = (char*)msgBody.c_str();
        bufArray[1].len = msgBody.size(); 
    }
    uv_write(wReq, (uv_stream_t*)handle, bufArray, 2, [](uv_write_t* req, int status){
        if(status ==0) 
        {
            LOG4_INFO("write successfully on stream(%p), req=%p",req->data, req);
        }
        else
        {
            LOG4_INFO("write error on stream(%p), status= %d",req->data, status);
        }

        if(req)
        {
            delete req;
            req =nullptr;
        }
    });
}
