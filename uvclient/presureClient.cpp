#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <set>
#include<list>
#include <map>
#include <fstream>
#include <thread>
#include <atomic> 
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uv.h>
#include "proctitle_helper.h"
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

// #define USE_CUSTOM_TIMEOUT_TIMER
#define TCP_CONNNECT_TIME_OVER   48                     //3+15+20s
util::CJsonObject g_cfg;                                //配置
// std::vector<UserInfo> listUserInfo;                     //模拟用户列表
std::vector<std::string>  dstIpList;                    //IP列表
std::string dstIp;                                      //单个IP
int dstPort = 0;                                        //端口
void uv_personal_conn_timeout_timer_callback(uv_timer_t* handle)
{
    UserInfo* pUserInfo = (UserInfo*)handle->data;
    if(pUserInfo->loginInfo.state != E_TCP_ESHTABLISHED)//TCP_CONNNECT_TIME_OVER秒后定时器触发时还没进入连接完成，则认为连接超时
    {
        pUserInfo->loginInfo.state = E_TCP_TIMEOUT;
        if(pUserInfo->conn)//tcp超时，关闭连接，用户的定时器资源回收在关闭连接的回调中被关闭
        {
            uv_close((uv_handle_t*)pUserInfo->conn, uvconn::close_cb);
            long long nowTime = globalFuncation::GetMicrosecond();
            LOG4_ERROR("user(%ld) devid(%s) token(%s) on stream(%p) connect timeout,start connect at(%ld),finished time(%ld) and now(%ld), duration(%ld)...",
                pUserInfo->userId, pUserInfo->devId.c_str(), 
                pUserInfo->authToken.c_str(), pUserInfo->conn,
                pUserInfo->loginInfo.startConnectTime, pUserInfo->loginInfo.finConnectedTime,
                nowTime, nowTime - pUserInfo->loginInfo.startConnectTime);
        } 
    }
    else //(state == E_TCP_ESHTABLISHED)， 连接可能还在或者不在了，中途连接是可能被事件触发回收的
    {
        if(pUserInfo->timeOutTimer)
        {
            uv_timer_stop((uv_timer_t*)handle);
            uv_close((uv_handle_t*)handle,[](uv_handle_t* handle){
                if(handle){
                    delete (uv_timer_t*)handle;
                }
            });
            pUserInfo->timeOutTimer = nullptr;
        }
    }
}

//void (*uv_timer_cb)(uv_timer_t* handle);
void uv_creatconn_timer_callback(uv_timer_t* handle) //周期为perio
{
    static int creatconn_timer_counter = 1;
    static int t=0;
    int t1=time(NULL);
    if( t1 -t >= 1 )
    {
        t= t1;
        LOG4_WARN("-------uv_creatconn_timer_callback, time(%ld), %d-------", globalFuncation::GetMicrosecond()/1000, creatconn_timer_counter);
    }

    static int userInfoListCounter = 0;
    UTimerData* pUTimerData = (UTimerData*)handle->data;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    int batch = pUTimerData->iBatch;
    int timeout = pUTimerData->connTimeout;
    uv_loop_t* uvLoop = (uv_loop_t*)pUTimerData->uvLoop;
    for(int i = 0;  userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
    {
        uv_tcp_t* utcp = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
        uv_tcp_init(uvLoop, utcp);
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
            listUserInfo[userInfoListCounter].userId, listUserInfo[userInfoListCounter].devId.c_str(), 
            listUserInfo[userInfoListCounter].authToken.c_str(), utcp);
        uv_tcp_connect(uconn, utcp, (const struct sockaddr*)&dest, uvconn::on_connect);
        listUserInfo[userInfoListCounter].loginInfo.startConnectTime = globalFuncation::GetMicrosecond(); //设置发起tcp连接的时间， [startConnectTime,-]

#ifdef USE_CUSTOM_TIMEOUT_TIMER
        //超时定时器
        {
            uv_timer_t*  checkTimeOutTimer = new uv_timer_t; 
            checkTimeOutTimer->data = &listUserInfo[userInfoListCounter];
            uv_timer_init(uvLoop, checkTimeOutTimer);
            uv_timer_start(checkTimeOutTimer, uv_personal_conn_timeout_timer_callback, 
                timeout*1000, 1*1000);//TCP_CONNNECT_TIME_OVER s后执行第一次,看TCP连接是否返回
            listUserInfo[userInfoListCounter].timeOutTimer = checkTimeOutTimer; //方便后续回收
        }
#endif 
        userInfoListCounter++;
    }

    creatconn_timer_counter++;

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

//void (*uv_timer_cb)(uv_timer_t* handle);
void uv_login_timer_callback(uv_timer_t* handle) //周期为perio
{
    LOG4_INFO("-------uv_creatconn_timer_callback-------");
    static int loginCounter = 0;
    UTimerData* pUTimerData = (UTimerData*)handle->data;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    int batch = pUTimerData->iBatch;
    int timeout = pUTimerData->connTimeout;
    uv_loop_t* uvLoop = (uv_loop_t*)pUTimerData->uvLoop;
    int processNum = pUTimerData->processNum;
    for(auto iter = listUserInfo.begin(); iter != listUserInfo.end(); iter++)
    {
        if(iter->loginInfo.state == E_TCP_ESHTABLISHED)
        {
            long long now = globalFuncation::GetMicrosecond();
            MsgBody msgBody;
            ImMessagePack::LoginReq(*iter, msgBody);
            if(!Pack::SendMsg((uv_tcp_t*)iter->conn, 1001, msgBody.SerializeAsString(), false))
            {
                LOG4_ERROR("userid(%ld) send cmd[%d] error on stream(%p)",iter->userId, 1001, iter->conn);
                continue;
            }
            iter->loginInfo.state = E_TCP_LOGINING;
            iter->loginInfo.loginTime = globalFuncation::GetMicrosecond();//设置用户登录时间， [finConnectedTime, loginTime]
            LOG4_WARN("===userId(%ld) ready for login cost time (%ld)", iter->userId, iter->loginInfo.loginTime - now);
        }
        else if(iter->loginInfo.state == E_TCP_LOGINED)
        {
            loginCounter++;
        }
    }

    if(loginCounter == listUserInfo.size())
    {
        LOG4_INFO("create connect timer completed, close timer...");
        uv_timer_stop(handle);
        loginCounter = 0;
        uv_close((uv_handle_t*)handle, [](uv_handle_t* handle){
            if(handle){
                delete (uv_timer_t*)handle;
            }
        });
    }
}

//统计的样本总是慢于发出请求的样本，并保证被统计的样本是已经等待了足够超时时间的
void uv_logintask_statistics_timer_callback(uv_timer_t* handle)
{
    LOG4_INFO("---------uv_logintask_statistics_timer_callback-------");
    UTimerData* pUTimerData = (UTimerData*)handle->data;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    int perio = pUTimerData->iPerio;//周期,ms
    int batch = pUTimerData->iBatch*(1000/perio);//并发数, 但batch很大时,可能并不能在一秒内全部发出,所以在下边统计时需要判断batch批次内同1s发出的
    static int userInfoListCounter = 0;
    static int regionIndex = 0;     //同1s区间内第一个发出的请求
    //计算周期内指定并发数的QPS
    std::vector<UserInfo*> vUserLoginInOneSecond;
    for(int i = 0; userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
    {
        long long regionIndexTime = listUserInfo[userInfoListCounter].loginInfo.startConnectTime -  listUserInfo[regionIndex].loginInfo.startConnectTime;
        // long long regionIndexTime = listUserInfo[userInfoListCounter].loginInfo.loginTime -  listUserInfo[regionIndex].loginInfo.loginTime;
        //把同1s内发出请求的用户作为一个区间来统计，客户端发出QPS是可以调节的，这个比较方式也总能准确的把一个个区间的QPS分离出来
        //其实batch就有这个效果，但比较方式能避免1s内客户端产生QPS的上限导致的问题
        if(regionIndexTime <= 1*1000*1000) 
        {
            LOG4_INFO("userId(%ld) start connect wait time(%ld)", listUserInfo[userInfoListCounter].userId, regionIndexTime);
            vUserLoginInOneSecond.push_back(&listUserInfo[userInfoListCounter]);
            userInfoListCounter++;
        }
        else
        {
            LOG4_INFO("userId(%ld) start connect wait time(%ld)", listUserInfo[userInfoListCounter].userId, regionIndexTime);
            regionIndex = userInfoListCounter; //下一区间的开始
            break; //最多一次循环batch次(客户端一个秒区间模拟的QPS值)，但如果遇到生产高QPS，耗时超出1s
        }
    }
    if(vUserLoginInOneSecond.size() == batch) //如果这batch样本都在1s内，主动移到下个区间
    {
        regionIndex = userInfoListCounter; 
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
            long long loginCostTime = pUserInfo->loginInfo.loginRspTime - pUserInfo->loginInfo.startConnectTime;
            loginTimeCostSet.insert(loginCostTime); //目的是想得到最大最小值
            tatolCostTime += loginCostTime;
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

    float average = tatolCostTime/(loginSuccessfulCount*1.0);
    LOG4_WARN("Time:%ld Login Tps (QPS(%d/s) , tatolCostTime(%ld), min(%ld), max(%ld), average(%f), error(%f), timeout(%d))-----------",
        globalFuncation::GetMicrosecond(),  vUserLoginInOneSecond.size(), tatolCostTime, loginTimeCostSet.size()?*loginTimeCostSet.begin():0, 
        loginTimeCostSet.size()?*loginTimeCostSet.rbegin():0,  average, restError/(vUserLoginInOneSecond.size()*1.0) , loginTimeOverCount);

    if(userInfoListCounter >= (int)listUserInfo.size())
    {
        //本来还想算一次总样本的
        LOG4_WARN("uv_logintask_statistics_timer completed, user0 loginTime(%ld), user%ld loginTime(%ld), past(%ld)...",
            listUserInfo[0].loginInfo.startConnectTime, listUserInfo.size(), listUserInfo[userInfoListCounter-1].loginInfo.startConnectTime, 
            listUserInfo[userInfoListCounter-1].loginInfo.startConnectTime - listUserInfo[0].loginInfo.startConnectTime);
        uv_timer_stop(handle);
        userInfoListCounter = 0;
        regionIndex = 0;
        uv_close((uv_handle_t*)handle, [](uv_handle_t* handle){
            if(handle){
                delete (uv_timer_t*)handle;
            }
        });
    }
}

void uv_logintask_statistics_independent_thread(UTimerData* uvTimerData)
{
    LOG4_INFO("---------uv_logintask_statistics_independent_thread-------");
    UTimerData* pUTimerData = uvTimerData;
    std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
    int perio = pUTimerData->iPerio;//周期,ms
    int batch = pUTimerData->iBatch*(1000/perio);//并发数, 但batch很大时,可能并不能在一秒内全部发出,所以在下边统计时需要判断batch批次内同1s发出的
    int timeout = pUTimerData->connTimeout;
    static int userInfoListCounter = 0;
    static int regionIndex = 0;     //同1s区间内第一个发出的请求
    //qps统计结果输入到一个独立文件
    FILE *m_fp = fopen(pUTimerData->strQPSLog.c_str(), "a+" );
    if(!m_fp)
    {
        LOG4_ERROR("open file error, path=%s", pUTimerData->strQPSLog.c_str());
        return;
    }
    //计算周期内指定并发数的QPS
    sleep(timeout); //这个线程延时timeout才真正开始工作
    while(true)
    {
        std::vector<UserInfo*> vUserLoginInOneSecond;
        for(int i = 0; userInfoListCounter < (int)listUserInfo.size() && i < batch ; i++)
        {
            long long regionIndexTime = listUserInfo[userInfoListCounter].loginInfo.startConnectTime -  listUserInfo[regionIndex].loginInfo.startConnectTime;
            // long long regionIndexTime = listUserInfo[userInfoListCounter].loginInfo.loginTime -  listUserInfo[regionIndex].loginInfo.loginTime;
            //把同1s内发出(连接)请求的用户作为一个区间来统计，客户端发出QPS是可以调节的，这个比较方式也总能准确的把一个个区间的QPS分离出来
            //其实batch就有这个效果，但比较方式能避免1s内客户端产生QPS的上限导致的问题
            if(regionIndexTime <= 1*1000*1000) 
            {
                LOG4_ERROR("userId(%ld) start connect wait time(%ld)", listUserInfo[userInfoListCounter].userId, regionIndexTime);
                vUserLoginInOneSecond.push_back(&listUserInfo[userInfoListCounter]);
                userInfoListCounter++;
            }
            else
            {
                LOG4_ERROR("userId(%ld) start connect wait time(%ld)", listUserInfo[userInfoListCounter].userId, regionIndexTime);
                regionIndex = userInfoListCounter; //下一区间的开始
                break; //最多一次循环batch次(客户端一个秒区间模拟的QPS值)，但如果遇到生产高QPS，耗时超出1s
            }
        }
        if(vUserLoginInOneSecond.size() == batch) //如果这batch样本都在1s内，主动移到下个区间
        {
            regionIndex = userInfoListCounter; 
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
                long long loginCostTime = pUserInfo->loginInfo.loginRspTime - pUserInfo->loginInfo.startConnectTime;
                // long long loginCostTime = pUserInfo->loginInfo.loginRspTime - pUserInfo->loginInfo.loginTime;
                loginTimeCostSet.insert(loginCostTime); //目的是想得到最大最小值
                tatolCostTime += loginCostTime;
            }
            else if(pUserInfo->loginInfo.state == E_TCP_TIMEOUT)
            {
                loginTimeOverCount++;
            }
            else
            {
                restError++; //这里的error包括登录有返回但logical失败，也包括没返回tcp被断开；logical失败可以是业务超时（能返回到客户端）和其它
            }
        }

        static int round = 0;
        float average = tatolCostTime/(loginSuccessfulCount*1.0);
        LOG4_WARN("Time(%ld) Login Tps (QPS(%d/s) , tatolCostTime(%ld), min(%ld), max(%ld), average(%f), error(%d), timeout(%d))",
            globalFuncation::GetMicrosecond()/(1000*1000),  vUserLoginInOneSecond.size(), tatolCostTime, loginTimeCostSet.size()?*loginTimeCostSet.begin():0, 
            loginTimeCostSet.size()?*loginTimeCostSet.rbegin():0,  average, restError/*restError/(vUserLoginInOneSecond.size()*1.0)*/ , loginTimeOverCount);
        //统计信息刷到独立文件 ./qps/presureClient_0.log
        fprintf(m_fp,"%d: Time(%ld) Login Tps (QPS(%d/s) , tatolCostTime(%ld), min(%ld), max(%ld), average(%f), error(%d), timeout(%d))\n",
            round++, globalFuncation::GetMicrosecond()/(1000*1000),  vUserLoginInOneSecond.size(), tatolCostTime, loginTimeCostSet.size()?*loginTimeCostSet.begin():0, 
            loginTimeCostSet.size()?*loginTimeCostSet.rbegin():0,  average, restError/*restError/(vUserLoginInOneSecond.size()*1.0)*/ , loginTimeOverCount);
        fflush(m_fp);

        if(userInfoListCounter >= (int)listUserInfo.size())
        {
            userInfoListCounter = 0;
            regionIndex = 0;
            LOG4_WARN("%lld uv_logintask_statistics_timer completed, user0 loginTime(%ld), user%ld loginTime(%ld), past(%ld)...",
                listUserInfo[0].loginInfo.startConnectTime/(1000*1000), listUserInfo[0].loginInfo.startConnectTime, listUserInfo.size(), 
                listUserInfo[userInfoListCounter-1].loginInfo.startConnectTime, 
                listUserInfo[userInfoListCounter-1].loginInfo.startConnectTime - listUserInfo[0].loginInfo.startConnectTime);
            // uv_timer_stop(handle);

            // uv_close((uv_handle_t*)handle, [](uv_handle_t* handle){
            //     if(handle){
            //         delete (uv_timer_t*)handle;
            //     }
            // });
            fclose(m_fp);//关闭文件
            return;
        }
        sleep(1); // 定时一秒
    }
}
// //每个周期检查同一时间发起连接的一批用户，暂时不用这个函数
// void uv_check_conn_timeout_timer_callback(uv_timer_t* handle)
// {
//     LOG4_INFO("---------uv_check_conn_timeout_timer_callback-------");
//     UTimerData* pUTimerData = (UTimerData*)handle->data;
//     std::vector<UserInfo>& listUserInfo = *(std::vector<UserInfo>*)pUTimerData->vUserInfo;
//     // int perio = pUTimerData->iPerio;//周期,这里不用
//     int batch = pUTimerData->iBatch;//每周期发起的QPS数
//     static int userInfoListCounter = 0;
//     static int tcpTimeOverNums = 0;
//     for(int i = 0; userInfoListCounter < (int)listUserInfo.size() && i < batch; i++)
//     {
//         if((listUserInfo[userInfoListCounter].loginInfo.state == E_TCP_CONNECTING) && 
//             (globalFuncation::GetMicrosecond() - listUserInfo[userInfoListCounter].loginInfo.startConnectTime > TCP_CONNNECT_TIME_OVER))
//         {
//             listUserInfo[userInfoListCounter].loginInfo.state = E_TCP_TIMEOUT;
//             if(listUserInfo[userInfoListCounter].conn)//tcp超时，关闭连接
//             {
//                 uv_close((uv_handle_t*)listUserInfo[userInfoListCounter].conn, uvconn::close_cb);
//                 LOG4_ERROR("user(%ld) devid(%s) token(%s) on stream(%p) connect timeout...",
//                     listUserInfo[userInfoListCounter].userId, listUserInfo[userInfoListCounter].devId.c_str(), 
//                     listUserInfo[userInfoListCounter].authToken.c_str(), listUserInfo[userInfoListCounter].conn);
//                 tcpTimeOverNums++;
//             }   
//         }
//         userInfoListCounter++;
//     }

//     if(userInfoListCounter >= (int)listUserInfo.size())
//     {
//         LOG4_ERROR("check_conn_timeout_timer completed, timeover user num(%d), rate(%f)", tcpTimeOverNums, tcpTimeOverNums/userInfoListCounter*1.0);
//         uv_timer_stop(handle);
//         userInfoListCounter = 0;
//         tcpTimeOverNums = 0;
//         uv_close((uv_handle_t*)handle, [](uv_handle_t* handle){
//             if(handle){
//                 delete (uv_timer_t*)handle;
//             }
//         });
//     }
// }

int main(int argc, char* argv[])
{
    if(argc < 3) 
    {
        printf("Usage: %s  cfgfile processNum\n", argv[0]);
        return 0;
    }
    long long proceStartTime = globalFuncation::GetMicrosecond();
    ngx_init_setproctitle(argc, argv);
    //加载配置文件
    if(!globalFuncation::LoadConfig(g_cfg, argv[1]))
    {
        printf("Init failed, Load config error\n");
        return 0;
    }
    //从配置文件获取目标IP列表、端口
    std::string strIpList;
    g_cfg.Get("server_ip_list", strIpList);
    g_cfg.Get("server_dst_port", dstPort);
    globalFuncation::StringSplit(strIpList, dstIpList);
    if(dstIpList.size() == 0 )
    {
        printf("ip list error , ips = %s\n", strIpList.c_str());
        return 0;
    }
    //准备开启多进程，每个子进程是一个独立的事件循环
    int processNum =  std::atoi(argv[2]);
    int pid[processNum];
    uv_loop_t* uvLoop = new uv_loop_t[processNum];
    for(int i = 0; i < processNum; i++)
    {
        if(uvLoop && uv_loop_init(&uvLoop[i]) < 0)
        {
            printf("init array uvLoop[%d] error!\n", processNum);
            return 0;
        }
    }
    int chileId = 0;
    int i = 0;
    for(; i <processNum; i++)
    {
        if((chileId = fork()) == -1)
        {
            printf("fork error!");
            exit(EXIT_FAILURE);
        }
        else if(chileId == 0)
        {
            srand(time(nullptr));
            pid[i] = getpid();
            char szProcessName[64] = {0};
            snprintf(szProcessName, sizeof(szProcessName), "%s_%d", argv[0], i);
            ngx_setproctitle(szProcessName);
            //初始化日志打印库
            if(!Logger::GetInstance()->InitLogger(g_cfg))
            {
                printf("Init logger failed\n");
                return 0;
            }
            std::vector<UserInfo> listUserInfo; //模拟用户列表                     
            //从文件加载用户数据,每个进程从样本不同的位置偏移开始加载指定大小的用户数据
            std::string strSampleDataPath;
            int sampleDataSize = 0;
            int totalSampleDataSize = 0;
            g_cfg.Get("user_data_path", strSampleDataPath);
            g_cfg.Get("sample_data_size", sampleDataSize); //每个进程从同一个样本数据加载部分数据的大小
            g_cfg.Get("sample_data_total_size", totalSampleDataSize); //同一份样本数据的总大小，暂时不用
            strSampleDataPath += "id.csv";
	        long long now = globalFuncation::GetMicrosecond();
            if(!globalFuncation::LoadUserInfoFromCVSFile(listUserInfo, strSampleDataPath, i, sampleDataSize)) //i为进程号
            {
                LOG4_ERROR("load id.cvs error");
                return 0;
            }
            long long curr = globalFuncation::GetMicrosecond();
            LOG4_INFO("listUserInfo size(%d) load from file cost time(%ld)", listUserInfo.size(), curr - now);
            
            while(globalFuncation::GetMicrosecond() - proceStartTime < 5*1000*1000 && processNum > 1)
            {
                sleep(1);
            }
            //准备在每个独立子进程里启动自己的woker线程
            uv_async_t* async = new uv_async_t;
            async->data = &uvLoop[i];
            uv_async_init(&uvLoop[i], async, uvconn::uv_async_call);//用于woker线程异步通知主线程
            int worker_thread_num = 1; 
            if(!g_cfg.Get("worker_thread_num", worker_thread_num) || (worker_thread_num > TASK_THREAD_NUM))
            {
                worker_thread_num = TASK_THREAD_NUM; //限定业务线程数最大值
                LOG4_WARN("worker_thread_num error");
            }
#if 0
            for(int i = 0; i < worker_thread_num; i++)//要注意防止数组越界
            {
                uvconn::p_send_mem.push_back(malloc(RB_SIZE));
                uvconn::rb_send.push_back(new RingBuffer(RB_SIZE, false, false));
                ImMessagePack* objTestImMsg = new ImMessagePack(&uvconn::rb_recv, uvconn::p_recv_mem, uvconn::rb_send[i], uvconn::p_send_mem[i], async, i);
                std::thread th(&Pack::StartThread, objTestImMsg);
                th.detach();
            }
#endif
            for(int i = 0; i < worker_thread_num; i++)//要注意防止数组越界
            {
                // uvconn::p_send_mem.push_back(malloc(RB_SIZE));
                // uvconn::rb_send.push_back(new RingBuffer(RB_SIZE, false, false));
                // ImMessagePack* objTestImMsg = new ImMessagePack(&uvconn::rb_recv, uvconn::p_recv_mem, uvconn::rb_send[i], uvconn::p_send_mem[i], async, i);
                ImMessagePack* objTestImMsg = new ImMessagePack(&uvconn::recv_cq, &uvconn::send_cq, async, i);
                std::thread th(&Pack::StartThread, objTestImMsg);
                th.detach();
            }
            //创建定时器
            UTimerData uvTimerData;
            uvTimerData.processNum = processNum; //进程数
            int perio = 5;                       //这里默认为5ms，意思是认为请求发出的循环周期为50us, 5ms内可以完成100个请求发出
            if(!g_cfg.Get("create_conn_timer_perio", perio))
            {
                perio = 5;
            }
            uvTimerData.iPerio = perio;
            int batch = CONNECTS_BACTH_PERIO;
            if(!g_cfg.Get("create_conn_nums_pertime", batch))
            {
                batch = CONNECTS_BACTH_PERIO;
            }
            int iConnTimeOut = TCP_CONNNECT_TIME_OVER;
            if(!g_cfg.Get("connet_timeout", iConnTimeOut))
            {
                iConnTimeOut = TCP_CONNNECT_TIME_OVER;
            }
            uvTimerData.connTimeout = iConnTimeOut;
            uvTimerData.iBatch = batch;
            uvTimerData.vUserInfo = &listUserInfo;//用户容器
            uvTimerData.uvLoop = &uvLoop[i];
            uvTimerData.strQPSLog = g_cfg("qps_log_path") + std::string("/") + getproctitle() + std::string(".log");

            //启动定时器，这个定时器用于发起连接
            uv_timer_t*  creatConnTimer= new uv_timer_t; 
            creatConnTimer->data = &uvTimerData;//挂接定时器用到的数据
            uv_timer_init(&uvLoop[i], creatConnTimer);
            uv_timer_start(creatConnTimer, uv_creatconn_timer_callback, 0, perio);//next loop 执行第一次, 并周期为perio ms
#if 0
            //登录定时器
            uv_timer_t*  loginTimer= new uv_timer_t; 
            loginTimer->data = &uvTimerData;//挂接定时器用到的数据
            uv_timer_init(&uvLoop[i], loginTimer);
            uv_timer_start(loginTimer, uv_login_timer_callback, 2*1000, 50);//2s后执行第一次, 并周期为50ms；这时起码一个客户端上有50k连接了,50ms重复一次是为了校时，让客户端时钟走到同一秒
#endif 
#if 0
            //关于统计也可以开启一个独立线程定时统计，这样就不影响主线程了
            uv_timer_t*  loginTaskStatisticsTimer= new uv_timer_t; 
            loginTaskStatisticsTimer->data = &uvTimerData;//挂接定时器用到的数据
            uv_timer_init(&uvLoop[i], loginTaskStatisticsTimer);
            uv_timer_start(loginTaskStatisticsTimer, uv_logintask_statistics_timer_callback, iConnTimeOut*2*1000, 1*1000);//2倍TCP_CONNNECT_TIME_OVER后执行第一次, 目的是充分等到每条TCP的超时定时器已经触发
#endif
            //统计线程
            std::thread th(uv_logintask_statistics_independent_thread, &uvTimerData); 
            th.detach();

            // uv_timer_t*  checkTcpConnectTimeOutTimer= new uv_timer_t; 
            // checkTcpConnectTimeOutTimer->data = &uvTimerData;//挂接定时器用到的数据
            // uv_timer_init(&uvLoop[i], checkTcpConnectTimeOutTimer);
            // uv_timer_start(checkTcpConnectTimeOutTimer, uv_check_conn_timeout_timer_callback, 5*1000, TCP_CONNNECT_TIME_OVER*1000);//程序启动5s后执行第一次, 并周期为3s

            // uv_timer_t*  msgTimer= new uv_timer_t; 
            // msgTimer->data = &uvTimerData;
            // uv_timer_init(&uvLoop[i], msgTimer);
            // uv_timer_start(msgTimer, uv_msg_timer_callback, 1*1000, 1*1000);//1s后启动, 并周期为1s,消息发送定时器

            //事件循环
            return uv_run(&uvLoop[i], UV_RUN_DEFAULT);
        }
        else //父进程
        {

        }
    }

    for(int i=0;i< processNum ;i++)
	{
		waitpid(pid[i],NULL,0);
	}
}

