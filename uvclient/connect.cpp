#include "connect.h"
#include "logger.h"
#include "CircleBuffer.hpp"
#include "ImMessagePack.h"
#include "client.pb.h"
namespace uvconn
{
void *p_recv_mem = malloc(RB_SIZE);                     //writer:sockect线程；reader:业务线程  
RingBuffer rb_recv(RB_SIZE, false, false);              //存放接收到的业务pack的lock-free缓冲
void *p_send_mem[TASK_THREAD_NUM];                      //writer:业务线程, reader:sockect线程
RingBuffer *rb_send[TASK_THREAD_NUM];                   //(RB_SIZE, false, false),多线程处理业务后要发包入缓冲，通知socket线程发送,有几个业务线程就有几个这样的rb
std::map<uv_tcp_t*, void*> g_mapConnCache;              //socket映射连接，连接与缓冲区关联，目的是不去占用uv_tcp_t.data

//void (*uv_connect_cb)(uv_connect_t* req, int status);
void on_connect(uv_connect_t* req, int status)
{
    LOG4_INFO("-------on_connect callback , stream=%p--------",req->handle);
    //req里包含了连接、用户信息
    UserInfo* pUserInfo = (UserInfo*)req->data;
    uv_tcp_t *handle = (uv_tcp_t*)req->handle;
    if(status == 0)
    {
        //为新建立的连接配一个固定环形缓冲
        auto iter = g_mapConnCache.find((uv_tcp_t*)handle);
        if(iter == g_mapConnCache.end())
        {
            g_mapConnCache.insert(std::make_pair(handle, new CircleBuffer<char>(TCP_BUFFER_LEN)));
        }
        uv_read_start((uv_stream_t*)handle , alloc_buffer, echo_read);
        //登录
        MsgBody msgBody;
        ImMessagePack::LoginReq(*pUserInfo, msgBody);
        Pack::SendMsg(handle, 1001, msgBody.SerializeAsString(), false);
    }
    else 
    {
        uv_close((uv_handle_t*)handle, close_cb);
        LOG4_ERROR("status = %d, errorName(%s) , errorString(%s)" ,status, uv_err_name(status), uv_strerror(status));
    }

    if(req) free(req);//无论成功与否，把过程量uv_connect_t回收了，但如果成功连接已经保存起来
    return;
}


//void (*uv_alloc_cb)(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) 
{
    static char cacheBuf[TCP_BUFFER_LEN * 4]={0};
    if(handle)
    {
        auto iter = g_mapConnCache.find((uv_tcp_t*)handle);
        if(iter == g_mapConnCache.end())
        {
            LOG4_ERROR("stream(%p)'s buf no exist", handle);
            return;
        }
        CircleBuffer<char>* pBuf = (CircleBuffer<char>*)iter->second;
        if(pBuf)
        {
            if(pBuf->isEmpty())
            {
                LOG4_INFO("pBuf is empty, uv_buf.len is %d ", sizeof(cacheBuf));
                buf->len = TCP_BUFFER_LEN *4;
            }
            else if(pBuf->isFull())
            {
                LOG4_INFO("pBuf is full");
                buf->len = 0;
            }
            else
            {
                LOG4_INFO("pBuf has free space");
                buf->len = (TCP_BUFFER_LEN - pBuf->GetLength());//传入环形缓冲的最大空闲长度,环形缓冲是固定长非线程安全
            }
            buf->base = (char*)&cacheBuf[0];//根据环形缓冲区的剩余空间，决定取多长的socket数据
        }
    }
}

//void (*uv_read_cb)(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void echo_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    if(nread == UV_EOF)
    {
        uv_close((uv_handle_t*)stream, close_cb);
        return;
    }
    else
    {
        //这里先解析buf，最后残余数据再放缓冲
        auto iter = g_mapConnCache.find((uv_tcp_t*)stream);
        if(iter == g_mapConnCache.end())
        {
            LOG4_ERROR("stream(%p)'s buf no exist", stream);
            return;
        }
        CircleBuffer<char>* pBuf = (CircleBuffer<char>*)iter->second;
        if(pBuf)
        {
            if(pBuf->isEmpty())
            {
                int leftLen = nread;//开始的剩余长度为这次从sockert读回来的数据
                int offset = 0;
                for(;;)
                {
                    if(leftLen >= (int)sizeof(tagAppMsgHead))
                    {
                        int packLen = ntohl(*(unsigned int*)(buf->base + offset)); 
                        if(leftLen >= packLen)
                        {
                            char *cbuf = new char[packLen];
                            memcpy(cbuf, buf->base + offset, packLen);
                            LOG4_INFO("recive pack cmd = %ld len = %ld, seq = %ld", ntohl(*(unsigned int*)(cbuf+4)), ntohl(*(unsigned int*)(cbuf)), ntohl(*(unsigned int*)(cbuf+8)));
                            ImPack pack;
                            pack.stream = stream; 
                            pack.UserInfoPtr = stream->data; //uv_tcp_t.data :UserInfo
                            pack.packBuf = cbuf;
                            pack.len = packLen;
                            if(rb_recv.push(&pack, sizeof(pack), p_recv_mem) == 0)
                            {
                                LOG4_INFO("push pack of stream(%p) to ringbuffer, pack.packBuf(%p), pack.len(%d), rb_recv(%p), p_recv_mem(%p)",pack.stream,  pack.packBuf, pack.len, &rb_recv, p_recv_mem);
                            }
                            else
                            {
                                delete []cbuf;//rb_recv满了，pack被扔掉了,后期可以考虑peek,但要配上remove,不可能在这里处理业务吧
                                return;
                            }

                            leftLen -= packLen;
                            offset += packLen;
                        }
                        else
                        {
                            pBuf->Write(buf->base + offset, leftLen);
                            break;
                        }
                    }
                    else
                    {
                        pBuf->Write(buf->base + offset, leftLen);
                        break;
                    }
                }
            }
            else
            {
                pBuf->Write(buf->base, nread);//从缓socket实际拿回来的数据长度为nread
                on_parse_pack(stream);//在这个函数里分析服务器下发的数据
            }
        }
        LOG4_INFO("data in CircleBuffer<char> pBuf , len:%d", pBuf->GetLength());
    }
}
//对环形缓冲进行业务包分析
void on_parse_pack(const uv_stream_t* stream)
{
    if(stream)
    {
        auto iter = g_mapConnCache.find((uv_tcp_t*)stream);
        if(iter == g_mapConnCache.end())
        {
            LOG4_ERROR("stream(%p)'s buf no exist", stream);
            return;
        }
        CircleBuffer<char>* pBuf = (CircleBuffer<char>*)iter->second;
        for(;;)
        {
            int iReadyReadLen = pBuf->GetLength();
            tagAppMsgHead head;
            if(iReadyReadLen >= (int)sizeof(tagAppMsgHead))
            {
                //预览头数据
                pBuf->Peak((char*)&head, sizeof(tagAppMsgHead));
                int packLen = ntohl(head.len);//包括头部的长度在内
                if(iReadyReadLen >= packLen)
                {
                    char *buf = new char[packLen];
                    pBuf->Read(buf, packLen);
                    LOG4_INFO("recive pack cmd = %ld len = %ld, seq = %ld", ntohl(head.cmd), ntohl(head.len), ntohl(head.seq));
                    //业务数据包投递到无锁队列，由业务线程处理
                    ImPack pack;
                    pack.stream = stream; 
                    pack.UserInfoPtr = stream->data; //uv_tcp_t.data :UserInfo
                    pack.packBuf = buf;
                    pack.len = packLen;
                    if(rb_recv.push(&pack, sizeof(pack), p_recv_mem) == 0)//pack放到rb_recv, 能放下则放下
                    {
                        LOG4_INFO("push pack of stream(%p) to ringbuffer, pack.packBuf(%p), pack.len(%d), rb_recv(%p), p_recv_mem(%p)",pack.stream,  pack.packBuf, pack.len, &rb_recv, p_recv_mem);
                    }
                    else
                    {
                        delete []buf;
                        return;//rb_recv满了，pack被扔掉了,后期可以考虑peek,但要配上remove,不可能在这里处理业务吧
                    }
                }
                else
                {
                    break;
                    LOG4_INFO("pack is not complete");
                }
            }
            else
            {
                break;
                LOG4_INFO("pack head is not complete");
            }
        }
    }
    else
    {
        LOG4_ERROR("stream %x error", stream);
    }

}

//int uv_write(uv_write_t* req, uv_stream_t* handle, const uv_buf_t bufs[], unsigned int nbufs, uv_write_cb cb);
void write_cb(uv_write_t* req, int status)
{
    if(status ==0) 
    {

        LOG4_INFO("write successfully, req=%p",req);
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
}

//void (*uv_close_cb)(uv_handle_t* handle);
//目前只用于close连接
void close_cb(uv_handle_t* handle)
{
    if(handle)
    {
        auto iter = g_mapConnCache.find((uv_tcp_t*)handle);
        if((iter != g_mapConnCache.end()) && iter->second)//<uv_tcp*, void*>,连接回收时，要回收接收缓冲区
        {
            //连接的接收缓冲区
            delete (CircleBuffer<char>*)iter->second;
        }
        g_mapConnCache.erase((uv_tcp_t*)handle);
        //连接绑定的用户的资源：心跳定时器，消息定时器...
        UserInfo* pUserInfo = (UserInfo*)handle->data;
        if(pUserInfo) //UserInfo*
        {
            pUserInfo->reCycleSource();
        }
        free(handle);
    }
    LOG4_INFO("close callback");
}

void uv_async_call(uv_async_t* handle)
{
    LOG4_INFO("-------uv_async_all---------");
    for(int i = 0; i < TASK_THREAD_NUM; i++)
    {
        for(;;)
        {
            unsigned int len = sizeof(CustomEvent);
            CustomEvent *p_ctx = (CustomEvent*)rb_send[i]->peek(&len, 0, p_send_mem[i]);
            if(p_ctx)
            {
                LOG4_INFO("uv_async_call pop CustomEvent from ringbuffer, event.handle(%p) event->ieventType(%d) event->istatus(%d), rb_send(%p), p_send_mem(%p)",
                    ((UserInfo*)p_ctx->userInfo)->conn, p_ctx->ieventType,  p_ctx->istatus , rb_send[i], p_send_mem[i]);
                switch (p_ctx->ieventType) 
                {
                case CustomEvent::EVENT_LOGIN_SUCCESSE:
                    {
                        if(p_ctx->userInfo)
                        {
                            UserInfo* pUserInfo = (UserInfo*)p_ctx->userInfo;
                            if(pUserInfo)
                            {
                                //心跳定时器
                                {
                                    uv_timer_t*  heatBeatTimer= new uv_timer_t; 
                                    heatBeatTimer->data = (void*)p_ctx->userInfo;
                                    uv_timer_init(uv_default_loop(), heatBeatTimer);
                                    uv_timer_start(heatBeatTimer, uv_personal_heatBeat_timer_callback, HEARBEAT_PERIO, HEARBEAT_PERIO);//3.5min执行第一次，周期3.5min,心跳发送定时器
                                    pUserInfo->timer = heatBeatTimer;
                                }
                                //单聊消息定时器
                                {
                                    uv_timer_t*  msgTimer= new uv_timer_t; 
                                    msgTimer->data = (void*)p_ctx->userInfo;
                                    uv_timer_init(uv_default_loop(), msgTimer);
                                    uv_timer_start(msgTimer, uv_msg_timer_callback, 0, 1000);//next loop 执行第一次，周期1s,心跳发送定时器s
                                    pUserInfo->msgTimer = msgTimer;
                                }
                            }
                        }
                    }
                    break;
                case CustomEvent::EVENT_LOGIN_FAILED:
                
                default:
                    break;
                }               
                rb_send[i]->remove(p_send_mem[i]);
            }
            else
            {
                LOG4_INFO("rb_send[%d] is empty, p_ctx(%p)", i, p_ctx);
                break;
            }
        }
    }
}
//void (*uv_timer_cb)(uv_timer_t* handle);
void uv_personal_heatBeat_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("---------uv_personal_heatBeat_timer_callback-------");
    UserInfo* pUserInfo = (UserInfo*)handle->data;
    const uv_stream_t* stream = (uv_stream_t*)pUserInfo->conn;
    auto iter = g_mapConnCache.find((uv_tcp_t*)stream);
    if(iter == g_mapConnCache.end())
    {
        LOG4_ERROR("stream(%p) no exist, maybe have recycle", stream);
        //需要再用时，连接不在了需要回收资源吗
        return;
    }
    else
    {
        tagAppMsgHead head;
        head.cmd = 1101;
        head.seq = pUserInfo->seq++;
        head.len = htonl(sizeof(tagAppMsgHead));
        head.cmd = htonl(head.cmd);
        head.seq = htonl(head.seq);

        uv_buf_t buf;
        buf.base = (char*)&head;
        buf.len = sizeof(tagAppMsgHead); 
        uv_write_t *wReq = new uv_write_t;
        uv_write(wReq, (uv_stream_t*)stream, &buf, 1, write_cb);
    }
}

/*TODO**/
void uv_msg_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("-------uv_msg_timer_callback-------");
    UserInfo* pUserInfo = (UserInfo*)handle->data;
    const uv_stream_t* stream = (uv_stream_t*)pUserInfo->conn;
    auto iter = g_mapConnCache.find((uv_tcp_t*)stream);
    if(iter == g_mapConnCache.end())
    {
        LOG4_ERROR("stream(%p) no exist, maybe have recycle", stream);
        //需要再用时，连接不在了需要回收资源吗
        return;
    }
    else
    {
        //发单聊消息
        MsgBody msgBody;
        ImMessagePack::MsgChatReq(*pUserInfo, msgBody);
        Pack::SendMsg((uv_tcp_t*)stream, 4001, msgBody.SerializeAsString());
    }
}

};