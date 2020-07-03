#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <set>
#include<list>
#include <map>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <uv.h>

#include "msg.pb.h"
#include "login.pb.h"
#include "ImError.h"
#include "client.pb.h"

#include "encrypt_crypto.h"

#include "CircleBuffer.hpp"
#include "atomic_ops.h"
#include "ring_buffer.h"

#include "ImMessagePack.h"
#include "logger.h"
#include "CJsonObject.hpp"
#include "comm.h"

util::CJsonObject g_cfg;
std::vector<UserInfo> listUserInfo;                     //模拟用户列表
std::list<uv_tcp_t*> socketList;                         //连接套接字的set
std::map<uv_tcp_t*, uv_connect_t*> g_mapSocketConn;     //socket映射连接，用于回收连接的内存
void *p_recv_mem = malloc(RB_SIZE);                     //writer:sockect线程；reader:业务线程  
RingBuffer rb_recv(RB_SIZE, false, false);              //存放接收到的业务pack的lock-free缓冲
void *p_send_mem[TASK_THREAD_NUM];                      //writer:业务线程, reader:sockect线程
RingBuffer *rb_send[TASK_THREAD_NUM];                   //(RB_SIZE, false, false),多线程处理业务后要发包入缓冲，通知socket线程发送,有几个业务线程就有几个这样的rb
const std::string& rsaKeyPath = "./conf/rsakey/public_key.pem";
RSA* rsaPublicKey = readRsaPublicKeyFromFile(const_cast<char*>(rsaKeyPath.c_str())); 
std::string dstIp;
int dstPort = 0;

//void (*uv_close_cb)(uv_handle_t* handle);
void close_cb(uv_handle_t* handle)
{
    //连接回收时，要处理资源回收
    if(handle)
    {
        if(handle->data)
        {
            //连接的应用缓冲区
            delete (CircleBuffer<char>*)handle->data;
            handle->data = nullptr;
        }
        //连接及连接上的用户的心跳定时器
        const auto& iter = g_mapSocketConn.find((uv_tcp_t*)handle);
        if(iter->second)
        {
            uv_connect_t* conn = (uv_connect_t*)iter->second;
            UserInfo* pUserInfo = (UserInfo*)conn->data;
            if(pUserInfo->timer)
            {
                uv_timer_stop((uv_timer_t*)pUserInfo->timer);
                uv_close((uv_handle_t*)pUserInfo->timer,[](uv_handle_t* handle){
                    if(handle){
                        delete (uv_timer_t*)handle;
                    }
                });
                pUserInfo->timer = nullptr;
            }
            free(iter->second);
        }

        g_mapSocketConn.erase((uv_tcp_t*)handle);
        socketList.remove((uv_tcp_t*)handle);

        free(handle);
    }
    LOG4_INFO("close callback");
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
//void (*uv_alloc_cb)(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    static char cacheBuf[TCP_BUFFER_LEN * 4]={0};
    if(handle)
    {
        CircleBuffer<char>* pBuf = (CircleBuffer<char>*)handle->data;
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
//void (*uv_async_cb)(uv_async_t* handle);
void uv_personal_heatBeat_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("---------uv_personal_heatBeat_timer_callback-------");
    uv_tcp_t* stream = (uv_tcp_t*)handle->data;
    if(stream)
    {
        const auto& iter = g_mapSocketConn.find((uv_tcp_t*)stream);
        if(iter != g_mapSocketConn.end())
        {
            uv_connect_t* conn = (uv_connect_t*)iter->second;
            if(conn)
            {
                UserInfo* pUserInfo = (UserInfo*)conn->data;
                if(pUserInfo)
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
        }
    }
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
                    p_ctx->handle, p_ctx->ieventType,  p_ctx->istatus , rb_send[i], p_send_mem[i]);
                switch (p_ctx->ieventType) 
                {
                case CustomEvent::EVENT_LOGIN_SUCCESSE:
                    {
                        if(p_ctx->handle)
                        {
                            uv_connect_t* conn = nullptr;
                            const auto& iter = g_mapSocketConn.find((uv_tcp_t*)p_ctx->handle);
                            if(iter != g_mapSocketConn.end())
                            {
                                conn = (uv_connect_t*)iter->second;
                            }
                            if(conn)
                            {
                                UserInfo* pUserInfo = (UserInfo*)conn->data;
                                if(pUserInfo)
                                {
                                    uv_timer_t*  heatBeatTimer= new uv_timer_t; 
                                    heatBeatTimer->data = (void*)p_ctx->handle;
                                    uv_timer_init(uv_default_loop(), heatBeatTimer);
                                    uv_timer_start(heatBeatTimer, uv_personal_heatBeat_timer_callback, HEARBEAT_PERIO, HEARBEAT_PERIO);//next loop 执行第一次，周期3.5min,心跳发送定时器
                                    pUserInfo->timer = heatBeatTimer;
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

//对环形缓冲进行业务包分析
void on_parse_pack(const uv_stream_t* stream)
{
    if(stream)
    {
        CircleBuffer<char>* pBuf = (CircleBuffer<char>*)stream->data;
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
        //这里其实应该先解析buf，最后残余数据再放缓冲，目前为了简单一律先放缓冲
        CircleBuffer<char>* pBuf = (CircleBuffer<char>*)stream->data;
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

//void (*uv_connect_cb)(uv_connect_t* req, int status);
void on_connect(uv_connect_t* req, int status)
{
    LOG4_INFO("-------on_connect callback , stream=%p--------",req->handle);
    void *handle = req->handle;
    if(status == 0)
    {
        uv_read_start((uv_stream_t*)handle , alloc_buffer, echo_read);
        //为新建立的连接配一个固定环形缓冲
        ((uv_tcp_t*)handle)->data = new CircleBuffer<char>(TCP_BUFFER_LEN);
        //把新建连接放到集合里
        socketList.push_back((uv_tcp_t*)handle);
        //socket关联新连接
        g_mapSocketConn.insert(std::make_pair((uv_tcp_t*)handle, req));
        //登录
        MsgBody msgBody;
        ImMessagePack::LoginReq((uv_connect_t* )req, msgBody);
        Pack::SendMsg((uv_connect_t*)req, 1001, msgBody, false);
    }
    else 
    {
        free(req);
        uv_close((uv_handle_t*)handle, close_cb);
        LOG4_ERROR("status = %d, errorName(%s) , errorString(%s)" ,status, uv_err_name(status), uv_strerror(status));
        return;
    }
}

//int uv_timer_start(uv_timer_t* handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat);
//void (*uv_timer_cb)(uv_timer_t* handle);
void uv_creatconn_timer_callback(uv_timer_t* handle){
    LOG4_INFO("-------uv_creatconn_timer_callback-------");
    static int userInfoListCounter = 0;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)handle->data;
    
    int batch = CONNECTS_BACTH_PERIO;
    if(!g_cfg.Get("create_conn_nums_pertime", batch))
    {
        batch = CONNECTS_BACTH_PERIO;
    }
    for(int i = 0;  userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
    {
        uv_tcp_t* socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
        uv_tcp_init(uv_default_loop(), socket);
        uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
        connect->handle = (uv_stream_t*)socket;
        connect->data = &listUserInfo[userInfoListCounter++];//为连接绑定一个用户
        struct sockaddr_in dest;
        uv_ip4_addr(dstIp.c_str(), dstPort, &dest);
        LOG4_DEBUG("user(%ld) devid(%s) token(%s) start connect ...",
            listUserInfo[userInfoListCounter].userId, listUserInfo[userInfoListCounter].devId.c_str(), listUserInfo[userInfoListCounter].authToken.c_str());
        uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);
    }

    if(userInfoListCounter >= (int)listUserInfo.size())
    {
        LOG4_INFO("create connect timer completed, close timer...");
        uv_timer_stop(handle);
        userInfoListCounter = 0;
        uv_close((uv_handle_t*)handle, [](uv_handle_t* handle){
            if(handle){
                delete (uv_timer_t*)handle;
            }
        });
    }
}

void uv_msg_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("-------uv_msg_timer_callback-------");
    static int ibatch = 100;
    std::list<uv_tcp_t*>& pSocketList = *(std::list<uv_tcp_t*>*)handle->data;
    if(pSocketList.size() > 0)
    {
        LOG4_INFO("uv_msg_timer_callback() pSocketList = %d",pSocketList.size());
        for(const auto & stream:pSocketList)
        {
            const auto& iter = g_mapSocketConn.find((uv_tcp_t*)stream);
            if(iter != g_mapSocketConn.end())
            {
                uv_connect_t* conn = (uv_connect_t*)iter->second;
                if(conn)
                {
                    //发单聊消息
                    MsgBody msgBody;
                    ImMessagePack::MsgChatReq((uv_connect_t* )conn, msgBody);
                    Pack::SendMsg((uv_connect_t*)conn, 4001, msgBody);
                }
            }
        }
    }
}

void uv_heatBeat_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("---------uv_heatBeat_timer_callback-------");
    std::list<uv_tcp_t*>& pSocketList = *(std::list<uv_tcp_t*>*)handle->data;
    if(pSocketList.size() > 0)
    {
        LOG4_INFO("uv_heatBeat_timer_callback() pSocketList = %d", pSocketList.size());
        for(const auto & stream:pSocketList)
        {
            const auto& iter = g_mapSocketConn.find((uv_tcp_t*)stream);
            if(iter != g_mapSocketConn.end())
            {
                uv_connect_t* conn = (uv_connect_t*)iter->second;
                if(conn)
                {
                    UserInfo* pUserInfo = (UserInfo*)conn->data;
                    if(pUserInfo)
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
            }
        }
    }
}

bool LoadConfig(util::CJsonObject& oConf, const char* strConfFile)
{
    std::ifstream fin(strConfFile);
	//配置信息输入流
	if (fin.good())
	{
		//解析配置信息 JSON格式
		std::stringstream ssContent;
		ssContent << fin.rdbuf();
		if (!oConf.Parse(ssContent.str()))
		{
			//配置文件解析失败
			printf("Read conf (%s) error,it's maybe not a json file!\n",strConfFile);
			ssContent.str("");
			fin.close();
			return false;
		}
		ssContent.str("");
		fin.close();
		return true;
	}
	else
	{
		//配置信息流读取失败
		printf("Open conf (%s) error!\n",strConfFile);
		return false;
	}
}

bool LoadUserInfoFromFile(std::vector<UserInfo>& userInfo, const std::string& strPath)
{
    util::CJsonObject jsonIds;
    if(!LoadConfig(jsonIds, strPath.c_str()))
    {
        LOG4_ERROR("load user data error");
        return false;
    }
    int arraySize = jsonIds["RECORDS"].GetArraySize();
    LOG4_DEBUG("userInfo arraySize(%d)", arraySize);
    for(int i = 0; i < arraySize; i++)
    {
        UserInfo info;
        info.userId = atoll(jsonIds["RECORDS"][i]("id").c_str());//db有
        info.loginSeq = 0;//程序产生
        info.devId = jsonIds["RECORDS"][i]("dev_id"); //设备ID，db有
        info.authToken = jsonIds["RECORDS"][i]("token");//验证token，db有
        info.aesKey;//开始是自己，成功换成服务器生成的
        userInfo.push_back(info);
    }
    return true;
}

int main(int argc, char* argv[])
{
    if(argc < 3) 
    {
        printf("Usage: %s hostAddress port  cfgfile\n", argv[0]);
        return 0;
    }
    dstIp.assign(argv[1]);
    dstPort = std::atoi(argv[2]);

    //加载配置文件
    if(!LoadConfig(g_cfg, argv[3]))
    {
        printf("Init failed, Load config error\n");
        return 0;
    }

    //初始化日志打印库
    if(!Logger::GetInstance()->InitLogger(g_cfg))
    {
        printf("Init logger failed\n");
        return 0;
    }

    //读取用户数据文件
    std::string strSampleDataPath;
    std::string strSampleDataSize;
    g_cfg.Get("user_data_path", strSampleDataPath);
    g_cfg.Get("sample_data_size", strSampleDataSize);
    strSampleDataPath += "id_test_";
    strSampleDataPath += strSampleDataSize;
    strSampleDataPath +=".json";
    if(!LoadUserInfoFromFile(listUserInfo, strSampleDataPath))
    {
        LOG4_ERROR("load user.json error");
        return 0;
    }
    LOG4_DEBUG("listUserInfo size(%d)", listUserInfo.size());

    //启动多线程结构
    uv_async_t* async = new uv_async_t;
    uv_async_init(uv_default_loop(), async, uv_async_call);//用于woker线程异步通知主线程
    int worker_thread_num = 1; 
    if(!g_cfg.Get("worker_thread_num", worker_thread_num))
    {
        worker_thread_num = 1;
    }
    for(int i = 0; i < worker_thread_num; i++)
    {
        p_send_mem[i] = malloc(RB_SIZE);
        rb_send[i] = new RingBuffer(RB_SIZE, false, false);
        ImMessagePack* objTestImMsg = new ImMessagePack(&rb_recv, p_recv_mem, rb_send[i], p_send_mem[i], async, i);
        std::thread th(&Pack::StartThread, objTestImMsg);
        th.detach();
    }

    //创建连接定时器
    int perio = 1;
    if(!g_cfg.Get("create_conn_timer_perio", perio))
    {
        perio = 1;
    }
    uv_timer_t*  creatConnTimer= new uv_timer_t; 
    creatConnTimer->data = &listUserInfo;//挂接用户信息列表
    uv_timer_init(uv_default_loop(), creatConnTimer);
    uv_timer_start(creatConnTimer, uv_creatconn_timer_callback, 0, perio*1000);//next loop 执行第一次, 并周期为perio秒

    // uv_timer_t*  msgTimer= new uv_timer_t; 
    // msgTimer->data = &socketList;
    // uv_timer_init(uv_default_loop(), msgTimer);
    // uv_timer_start(msgTimer, uv_msg_timer_callback, 1*1000, 1*1000);//1s后启动, 并周期为1s,消息发送定时器

    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

