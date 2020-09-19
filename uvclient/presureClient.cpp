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

#define TCP_CONNNECT_TIME_OVER 10                       //3s
util::CJsonObject g_cfg;                                //配置
std::vector<UserInfo> listUserInfo;                     //模拟用户列表
std::vector<std::string>  dstIpList;                    //IP列表
std::string dstIp;                                      //单个IP
int dstPort = 0;                                        //端口

void uv_personal_conn_timeout_timer_callback(uv_timer_t* handle)
{
    UserInfo* pUserInfo = (UserInfo*)handle->data;
    if(pUserInfo->loginInfo.state == E_TCP_CONNECTING)//5s后定时器触发时还是连接中，则认为连接超时
    {
        pUserInfo->loginInfo.state = E_TCP_TIMEOUT;
        if(pUserInfo->conn)//tcp超时，关闭连接，用户的定时器在关闭连接的回调中被关闭
        {
            uv_close((uv_handle_t*)pUserInfo->conn, uvconn::close_cb);
            LOG4_ERROR("user(%ld) devid(%s) token(%s) on stream(%p) connect timeout...",
                pUserInfo->userId, pUserInfo->devId.c_str(), 
                pUserInfo->authToken.c_str(), pUserInfo->conn);
        } 
    }
    else
    {
        uv_timer_stop((uv_timer_t*)handle);
        uv_close((uv_handle_t*)handle,[](uv_handle_t* handle){
            if(handle){
                delete (uv_timer_t*)handle;
            }
        });
    }
}

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
        uv_tcp_connect(uconn, utcp, (const struct sockaddr*)&dest, uvconn::on_connect);
        listUserInfo[userInfoListCounter].loginInfo.startConnectTime = globalFuncation::GetMicrosecond(); //设置发起tcp连接的时间， TaskTime

        //超时定时器
        {
            uv_timer_t*  checkTimeOutTimer = new uv_timer_t; 
            checkTimeOutTimer->data = &listUserInfo[userInfoListCounter];
            uv_timer_init(uv_default_loop(), checkTimeOutTimer);
            uv_timer_start(checkTimeOutTimer, uv_personal_conn_timeout_timer_callback, 
                TCP_CONNNECT_TIME_OVER, TCP_CONNNECT_TIME_OVER);//5s后执行第一次，周期5s,看TCP连接是否返回
            listUserInfo[userInfoListCounter].timeOutTimer = checkTimeOutTimer; //方便后续回收
        }

        userInfoListCounter++;
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
    static int regionIndex = 0;     //同1s区间内第一个发出的请求
    //计算周期内指定并发数的QPS
    std::vector<UserInfo*> vUserLoginInOneSecond;
    for(int i = 0; userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
    {
        long long regionIndexTime = listUserInfo[userInfoListCounter].loginInfo.startConnectTime -  listUserInfo[regionIndex].loginInfo.startConnectTime;
        LOG4_ERROR("=========userId(%ld) cost time(%ld)", listUserInfo[userInfoListCounter].userId, regionIndexTime);
        //把同1s内发出请求的用户作为一个区间来统计，客户端发出QPS是可以调节的，这个比较方式也总能准确的把一个个区间的QPS分离出来
        //其实batch就有这个效果，但比较方式能避免1s内客户端产生QPS的上限导致的问题
        if(regionIndexTime <= 1*000*000) 
        {
            vUserLoginInOneSecond.push_back(&listUserInfo[userInfoListCounter]);
            userInfoListCounter++;
        }
        else
        {
            LOG4_ERROR("=========userId(%ld) cost time(%ld)", listUserInfo[userInfoListCounter].userId, regionIndexTime);
            regionIndex = userInfoListCounter; //下一区间的开始
            // break; //最多一次循环batch次(客户端一个秒区间模拟的QPS值)，但如果遇到生产高QPS，耗时超出1s
        }
    }

    std::set<long long> loginTimeCostSet;
    long long tatolCostTime = 0;
    int loginSuccessfulCount = 0;
    int loginTimeOverCount = 0;
    int restError = 0;
    for(const auto& pUserInfo:vUserLoginInOneSecond) //遍历单位时间制造的QPS,分析其中的 sample, duration(持续压测时间), min, max, average, successful, error, timeout,
    {
        if(pUserInfo->loginInfo.loginStatus == 0) //登录成功
        {
            loginSuccessfulCount++;
            long long costTime = pUserInfo->loginInfo.loginRspTime - pUserInfo->loginInfo.startConnectTime;
            loginTimeCostSet.insert(costTime); //目的是想得到最大最小值
            tatolCostTime += costTime;
        }
        else if(pUserInfo->loginInfo.state == E_TCP_TIMEOUT)
        {
            loginTimeOverCount++;
        }
        else
        {
            restError++;
        }
    }

    // LOG4_WARN("-----------Time:%ld Login Tps (conroutin(%d) , perio (%d), tatolCostTime(%ld), QPS(%f))-----------",globalFuncation::GetMicrosecond(),  batch, perio, tatolCostTime, ((tatolCostTime/(batch*1.0))/perio));
    float average = tatolCostTime/(loginSuccessfulCount*1.0);
    LOG4_WARN("-----------Time:%ld Login Tps (sample(%d) , tatolCostTime(%ld), min(%ld), max(%ld), average(%f), QPS(%f), error(%f), timeout(%d))-----------",
        globalFuncation::GetMicrosecond(),  vUserLoginInOneSecond.size(), tatolCostTime, *loginTimeCostSet.begin(), 
        *loginTimeCostSet.rbegin(),  average, perio*1000*1000.0/average, restError/(loginSuccessfulCount*1.0) , loginTimeOverCount);
}

//每个周期检查同一时间发起连接的一批用户，如果状态处于连接中，（5s内登录态没改变），那么认为建连接超时
void uv_check_conn_timeout_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("---------uv_check_conn_timeout_timer_callback-------");
    UTimerData* pUTimerData = (UTimerData*)handle->data;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    // int perio = pUTimerData->iPerio;//周期,这里不用
    int batch = pUTimerData->iBatch;//每周期发起的QPS数
    static int userInfoListCounter = 0;
    static int tcpTimeOverNums = 0;
    for(int i = 0; userInfoListCounter < (int)listUserInfo.size() && i < batch; i++)
    {
        if((listUserInfo[userInfoListCounter].loginInfo.state == E_TCP_CONNECTING) && 
            (globalFuncation::GetMicrosecond() - listUserInfo[userInfoListCounter].loginInfo.startConnectTime > TCP_CONNNECT_TIME_OVER))
        {
            listUserInfo[userInfoListCounter].loginInfo.state = E_TCP_TIMEOUT;
            if(listUserInfo[userInfoListCounter].conn)//tcp超时，关闭连接
            {
                uv_close((uv_handle_t*)listUserInfo[userInfoListCounter].conn, uvconn::close_cb);
                LOG4_ERROR("user(%ld) devid(%s) token(%s) on stream(%p) connect timeout...",
                    listUserInfo[userInfoListCounter].userId, listUserInfo[userInfoListCounter].devId.c_str(), 
                    listUserInfo[userInfoListCounter].authToken.c_str(), listUserInfo[userInfoListCounter].conn);
                tcpTimeOverNums++;
            }   
        }
        userInfoListCounter++;
    }

    if(userInfoListCounter >= (int)listUserInfo.size())
    {
        LOG4_ERROR("check_conn_timeout_timer completed, timeover user num(%d), rate(%f)", tcpTimeOverNums, tcpTimeOverNums/userInfoListCounter*1.0);
        uv_timer_stop(handle);
        userInfoListCounter = 0;
        tcpTimeOverNums = 0;
        uv_close((uv_handle_t*)handle, [](uv_handle_t* handle){
            if(handle){
                delete (uv_timer_t*)handle;
            }
        });
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
        uvconn::p_send_mem.push_back(malloc(RB_SIZE));
        uvconn::rb_send.push_back(new RingBuffer(RB_SIZE, false, false));
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
    uv_timer_start(loginTaskStatisticsTimer, uv_logintask_statistics_timer_callback, TCP_CONNNECT_TIME_OVER*2*1000, 1*1000);//10s后执行第一次, 目的是充分等到每条TCP的超时定时器已经触发，周期为1秒

    // uv_timer_t*  checkTcpConnectTimeOutTimer= new uv_timer_t; 
    // checkTcpConnectTimeOutTimer->data = &uvTimerData;//挂接定时器用到的数据
    // uv_timer_init(uv_default_loop(), checkTcpConnectTimeOutTimer);
    // uv_timer_start(checkTcpConnectTimeOutTimer, uv_check_conn_timeout_timer_callback, 5*1000, TCP_CONNNECT_TIME_OVER*1000);//程序启动5s后执行第一次, 并周期为3s

    // uv_timer_t*  msgTimer= new uv_timer_t; 
    // msgTimer->data = &uvTimerData;
    // uv_timer_init(uv_default_loop(), msgTimer);
    // uv_timer_start(msgTimer, uv_msg_timer_callback, 1*1000, 1*1000);//1s后启动, 并周期为1s,消息发送定时器

    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

