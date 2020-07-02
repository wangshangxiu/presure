#include <unistd.h>
#include "encrypt_crypto.h"
#include "pack.h"
extern int autoSeq;      
extern std::map<uv_tcp_t*, uv_connect_t*> g_mapSocketConn;
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
    LOG4_INFO("-------SendMsg---------");
    uv_write_t *wReq = new uv_write_t;
    uv_buf_t bufArray[2] = {{0, 0},{0, 0}};

    uv_connect_t *conn = nullptr;
    const auto& iter = g_mapSocketConn.find(handle);
    if(iter != g_mapSocketConn.end())
    {
        conn = iter->second;
    }
    UserInfo *pUserInfo = (UserInfo*)conn->data;

    tagAppMsgHead head;
    std::string data;

    if(bEncryt)
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
    bufArray[1].base = (char*)data.c_str();
    bufArray[1].len = data.size(); 
    uv_write(wReq, (uv_stream_t*)handle, bufArray, 2, [](uv_write_t* req, int status){
        if(status ==0) 
        {
            LOG4_INFO("write successfully, req=%p",req);
        }
        else
        {
            LOG4_INFO("write error, status= %d",status);
        }

        if(req)
        {
            delete req;
            req =nullptr;
        }
    });
}

void Pack::SendMsg(uv_connect_t* conn, int icmd , const MsgBody& msgBody, bool bEncryt)
{
    LOG4_INFO("-------SendMsg---------");
    uv_write_t *wReq = new uv_write_t;
    uv_buf_t bufArray[2] = {{0, 0},{0, 0}};
    
    tagAppMsgHead head;
    std::string data;
    UserInfo* pUserInfo = (UserInfo*)conn->data;
    if(bEncryt)
    {
        if(pUserInfo)
        {
            std::string& strAesKey = pUserInfo->aesKey;
            if(strAesKey.size()  > 0)
            {
                if(!Aes256Encrypt(msgBody.SerializeAsString(), data, strAesKey))
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
        data = msgBody.SerializeAsString();
#ifdef USE_HEAD_LEN
        head.len = data.size() + sizeof(tagAppMsgHead);
#else
        head.len = data.size();
#endif
    }
    head.cmd = icmd;
    if(pUserInfo) {head.seq = pUserInfo->seq++;}
    head.len = htonl(head.len);
    head.cmd = htonl(head.cmd);
    head.seq = htonl(head.seq);
    bufArray[0].base = (char*)&head;
    bufArray[0].len = sizeof(tagAppMsgHead);
    bufArray[1].base = (char*)data.c_str();
    bufArray[1].len = data.size(); 
    uv_write(wReq, (uv_stream_t*)conn->handle, bufArray, 2, [](uv_write_t* req, int status){
        if(status ==0) 
        {
            LOG4_INFO("write successfully, req=%p", req);
        }
        else
        {
            LOG4_INFO("write error, status= %d", status);
        }

        if(req)
        {
            delete req;
            req =nullptr;
        }
    });
}
void Pack::AsynSendMsg(const ImPack& pack)
{

}