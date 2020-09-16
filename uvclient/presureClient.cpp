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
#include <time.h>
#include <uv.h>
#include "connect.h"
#include "msg.pb.h"
#include "login.pb.h"
#include "ImError.h"
#include "client.pb.h"
#include "encrypt_crypto.h"
#include "ImMessagePack.h"
#include "logger.h"
#include "CJsonObject.hpp"
#include "comm.h"

util::CJsonObject g_cfg;                                //配置
std::vector<UserInfo> listUserInfo;                     //模拟用户列表
std::vector<std::string>  dstIpList;                    //IP列表
std::string dstIp;                                      //单个IP
int dstPort = 0;                                        //端口

//void (*uv_timer_cb)(uv_timer_t* handle);
void uv_creatconn_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("-------uv_creatconn_timer_callback-------");
    static int userInfoListCounter = 0;
    UTimerData* pUTimerData = (UTimerData*)handle->data;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    int batch = pUTimerData->iBatch;
    for(int i = 0;  userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
    {
        uv_tcp_t* utcp = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
        uv_tcp_init(uv_default_loop(), utcp);
        utcp->data = &listUserInfo[userInfoListCounter];//全局的<连接，用户>映射
        listUserInfo[userInfoListCounter].conn = utcp;//业务层的用户架构关联网络层的连接，指针

        uv_connect_t* uconn = (uv_connect_t*)malloc(sizeof(uv_connect_t));
        uconn->handle = (uv_stream_t*)utcp;
        uconn->data = &listUserInfo[userInfoListCounter];//为连接绑定一个用户

        struct sockaddr_in dest;
        int index = rand()%dstIpList.size();
        // uv_ip4_addr(dstIp.c_str(), dstPort, &dest);
        uv_ip4_addr(dstIpList[index].c_str(), dstPort, &dest);
        LOG4_DEBUG("user(%ld) devid(%s) token(%s) on stream(%p) start connect ...",
            listUserInfo[userInfoListCounter].userId, listUserInfo[userInfoListCounter].devId.c_str(), listUserInfo[userInfoListCounter].authToken.c_str(), utcp);
        listUserInfo[userInfoListCounter].loginInfo.startConnectTime = globalFuncation::GetMicrosecond();
        userInfoListCounter++;
        uv_tcp_connect(uconn, utcp, (const struct sockaddr*)&dest, uvconn::on_connect);
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

void uv_logintask_statistics_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("---------uv_logintask_statistics_timer_callback-------");
    UTimerData* pUTimerData = (UTimerData*)handle->data;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    int perio = pUTimerData->iPerio;//周期
    int batch = pUTimerData->iBatch;//并发数
    static int userInfoListCounter = 0;
    long long tatolCostTime = 0;

    //计算周期内指定并发数的QPS
    // for(const auto& userInfo:listUserInfo)
    int i = 0;
    for(;userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
    {
        tatolCostTime += (listUserInfo[userInfoListCounter].loginInfo.loginRspTime - listUserInfo[userInfoListCounter].loginInfo.loginTime);
        userInfoListCounter++;
    }
    if(userInfoListCounter && (userInfoListCounter%(int)listUserInfo.size() == 0))
    {
        batch = i;
    }
    LOG4_INFO("-----------Time:%ld Login Tps (conroutin(%d) , perio (%d), tatolCostTime(%ld), QPS(%f))-----------",globalFuncation::GetMicrosecond(),  batch, perio, tatolCostTime, ((tatolCostTime/(batch*1.0))/perio));
    printf("-----------Time:%ld Login Tps (conroutin(%d) , perio (%d), tatolCostTime(%ld), QPS(%f))-----------\n",globalFuncation::GetMicrosecond(),  batch, perio, tatolCostTime, ((tatolCostTime/(batch*1.0))/perio));
    tatolCostTime = 0;
    if(userInfoListCounter >= (int)listUserInfo.size())
    {
        userInfoListCounter = 0;
    }
}

int main(int argc, char* argv[])
{
    if(argc < 4) 
    {
        printf("Usage: %s hostAddress port  cfgfile\n", argv[0]);
        return 0;
    }
    //从命令行参数获取目标IP列表、端口
    globalFuncation::StringSplit(argv[1], dstIpList);
    if(dstIpList.size() == 0 )
    {
        printf("ip list error , ips = %s\n", argv[1]);
        return 0;
    }
    dstPort = std::atoi(argv[2]);
    srand(time(nullptr));
    //加载配置文件
    if(!globalFuncation::LoadConfig(g_cfg, argv[3]))
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

    //从文件加载用户数据
    std::string strSampleDataPath;
    std::string strSampleDataSize;
    int sampleDataSize = 0;
    g_cfg.Get("user_data_path", strSampleDataPath);
    g_cfg.Get("sample_data_size", strSampleDataSize);
    g_cfg.Get("sample_data_total_size", sampleDataSize);
    // strSampleDataPath += "id_test_";
    // strSampleDataPath += strSampleDataSize;
    // strSampleDataPath +=".json";
    // if(!globalFuncation::LoadUserInfoFromJsonFile(listUserInfo, strSampleDataPath))
    // {
    //     LOG4_ERROR("load user.json error");
    //     return 0;
    // }
    strSampleDataPath += "id.csv";
    if(!globalFuncation::LoadUserInfoFromCVSFile(listUserInfo, strSampleDataPath, 0, sampleDataSize))
    {
        LOG4_ERROR("load id.cvs error");
        return 0;
    }
    LOG4_DEBUG("listUserInfo size(%d)", listUserInfo.size());

    //启动woker线程
    uv_async_t* async = new uv_async_t;
    uv_async_init(uv_default_loop(), async, uvconn::uv_async_call);//用于woker线程异步通知主线程
    int worker_thread_num = 1; 
    if(!g_cfg.Get("worker_thread_num", worker_thread_num) || (worker_thread_num > TASK_THREAD_NUM))
    {
        worker_thread_num = TASK_THREAD_NUM; //限定业务线程数最大值
    }
    for(int i = 0; i < worker_thread_num; i++)//要注意防止数组越界
    {
        uvconn::p_send_mem[i] = malloc(RB_SIZE);
        uvconn::rb_send[i] = new RingBuffer(RB_SIZE, false, false);
        ImMessagePack* objTestImMsg = new ImMessagePack(&uvconn::rb_recv, uvconn::p_recv_mem, uvconn::rb_send[i], uvconn::p_send_mem[i], async, i);
        std::thread th(&Pack::StartThread, objTestImMsg);
        th.detach();
    }

    //创建定时器
    UTimerData uvTimerData;
    int perio = 1;
    if(!g_cfg.Get("create_conn_timer_perio", perio))
    {
        perio = 1;
    }
    uvTimerData.iPerio = perio;
    int batch = CONNECTS_BACTH_PERIO;
    if(!g_cfg.Get("create_conn_nums_pertime", batch))
    {
        batch = CONNECTS_BACTH_PERIO;
    }
    uvTimerData.iBatch = batch;
    uvTimerData.vUserInfo = &listUserInfo;//用户容器

    uv_timer_t*  creatConnTimer= new uv_timer_t; 
    creatConnTimer->data = &uvTimerData;//挂接定时器用到的数据
    uv_timer_init(uv_default_loop(), creatConnTimer);
    uv_timer_start(creatConnTimer, uv_creatconn_timer_callback, 0, perio*1000);//next loop 执行第一次, 并周期为perio秒

    uv_timer_t*  loginTaskStatisticsTimer= new uv_timer_t; 
    loginTaskStatisticsTimer->data = &uvTimerData;//挂接定时器用到的数据
    uv_timer_init(uv_default_loop(), loginTaskStatisticsTimer);
    uv_timer_start(loginTaskStatisticsTimer, uv_logintask_statistics_timer_callback, perio*1000*5, perio*1000);//5倍perio*1000 执行第一次, 并周期为perio秒

    // uv_timer_t*  msgTimer= new uv_timer_t; 
    // msgTimer->data = &uvTimerData;
    // uv_timer_init(uv_default_loop(), msgTimer);
    // uv_timer_start(msgTimer, uv_msg_timer_callback, 1*1000, 1*1000);//1s后启动, 并周期为1s,消息发送定时器

    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

