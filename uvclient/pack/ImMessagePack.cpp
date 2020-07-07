#include "ImMessagePack.h"
#include "encrypt_crypto.h"
extern std::map<uv_tcp_t*, uv_connect_t*> g_mapSocketConn;
extern RSA* rsaPublicKey;

ImMessagePack::ImMessagePack(RingBuffer* recvRb, void *recvMem, RingBuffer* sendRb, void* sendMem, uv_async_t* uvAsyn, int index):
    Pack(recvRb, recvMem, sendRb, sendMem, uvAsyn, index)
{
    //ConnectMemberFun(1002, &ImMessagePack::LoginRsp);//这种写法会报编译错误，提示找不到类型
    ConnectMemberFun(1002, MemberFuntionPointer(&ImMessagePack::LoginRsp));
    ConnectMemberFun(1102, MemberFuntionPointer(&ImMessagePack::HearBeatRsp));
    ConnectMemberFun(4002, MemberFuntionPointer(&ImMessagePack::MsgChatRsp));
    ConnectMemberFun(4502, MemberFuntionPointer(&ImMessagePack::GroupChatRsp));
}

ImMessagePack::~ImMessagePack()
{
}


void ImMessagePack::LoginReq(uv_connect_t* conn, MsgBody& msgBody)
{

    UserInfo* pUserInfo = (UserInfo*)conn->data;
    if(pUserInfo)
    {
        pUserInfo->loginInfo.loginTime = GetMicrosecond();//设置登录时间
        LOG4_TRACE("userId(%ld) devId(%s) token(%s) logining at %ld ...", pUserInfo->userId, pUserInfo->devId.c_str(), pUserInfo->authToken.c_str(), pUserInfo->loginInfo.loginTime);
        printf("userId(%ld) devId(%s) token(%s) logining at %ld ...\n", pUserInfo->userId, pUserInfo->devId.c_str(), pUserInfo->authToken.c_str(), pUserInfo->loginInfo.loginTime);
        im_login::Login loginReq;
        im_login::RsaData rsaData;
        pUserInfo->aesKey = GetPassword(32);//临时aeskey
        GenerateEcdhKeyPair(pUserInfo->ecdhKey[0], pUserInfo->ecdhKey[1]);//ecdh key pair
        rsaData.set_userid(pUserInfo->userId);
        rsaData.set_ecdhpubkey(pUserInfo->ecdhKey[0]);
        rsaData.set_aeskey(pUserInfo->aesKey);

        im_login::AESData aesData;
        aesData.set_token(pUserInfo->authToken); // 用户token
        aesData.set_clienttime(0); // 时间戳，秒，4个字节
        aesData.set_devid(pUserInfo->devId); // 设备id
        aesData.set_loginseq(pUserInfo->loginSeq); // 登录序列号，每次自增，8个字节
        aesData.set_other("");    // 其余数据待定

        std::string strRsaEncryptDest;
        std::string strAesEncryptDest;
        if(Rsa2048Encrypt(rsaData.SerializeAsString(), strRsaEncryptDest, rsaPublicKey, false))
        {
            if(Aes256Encrypt(aesData.SerializeAsString(), strAesEncryptDest, pUserInfo->aesKey))
            {
                loginReq.set_rsadata(strRsaEncryptDest);
                loginReq.set_aesdata(strAesEncryptDest);
                loginReq.set_rasversion(1.0);
                msgBody.set_body(loginReq.SerializeAsString());
                msgBody.set_targetid("");
            }
            else
            {
                LOG4_ERROR("Aes256Encrypt faild!");
            }
        }
        else
        {
            LOG4_ERROR("Rsa2048Encrypt faild!");
        }
    }
    else
    {
        LOG4_ERROR("userInfo faild!");
    }
}

void ImMessagePack::LoginRsp(const ImPack& pack)
{
    //登录最外层都不加密，但成功登录，LoginRsp会加密
    MsgBody msgbody;
    if(!msgbody.ParseFromArray(pack.packBuf + sizeof(tagAppMsgHead), pack.len - sizeof(tagAppMsgHead)))//移动相应的位置就是数据包了
    {
        LOG4_ERROR("pb parse error , msgbody(%s)", msgbody.DebugString().c_str());
        return;
    }

    //uv_connect_t* conn = (uv_connect_t*)pack.stream;//这样强转不起效
    uv_connect_t* conn = nullptr;
    UserInfo* pUserInfo = nullptr;
    const auto& iter = g_mapSocketConn.find((uv_tcp_t*)pack.stream);
    if(iter != g_mapSocketConn.end())
    {
        conn = (uv_connect_t*)iter->second;
        if(conn)
        {
            pUserInfo = (UserInfo*)conn->data;
        }
        else
        {
            LOG4_ERROR("conn (%p) from stream(%p) is not a uv_connect_t", conn, pack.stream);
            return;
        }
    }

    int status = ntohl(*(unsigned short*)(pack.packBuf + 14));//移动14个字节就是status
    pUserInfo->loginInfo.loginStatus = status;
    if(status == 0)//成功的情况
    {
        if(pUserInfo)
        {
            std::string strLoginRsp;
            LOG4_INFO("pUserInfo->aesKey = %s", pUserInfo->aesKey.c_str());
            if(Aes256Decrypt(msgbody.body(), strLoginRsp, pUserInfo->aesKey))//aes256, key 256 bits
            {
                im_login::LoginRsp loginRsp;
                loginRsp.ParseFromString(strLoginRsp);
                pUserInfo->seq = loginRsp.startseq();
                pUserInfo->sessionId = loginRsp.sessionid();
                std::string sharedKey;
                CacllateShareKey(loginRsp.ecdhserverpubkey(), pUserInfo->ecdhKey[1], sharedKey);
                if(!Aes256Decrypt(loginRsp.sessionkey(), pUserInfo->aesKey, sharedKey))
                {
                    LOG4_ERROR("decrypt sessionKey error, sharedKey(%s)", sharedKey.c_str());
                    return;
                }
                pUserInfo->loginInfo.loginRspTime = GetMicrosecond();//登录返回并处理完的时间
                LOG4_INFO("userId(%lld) devId(%s) token(%s) loginRsp successfully at %ld", 
                    pUserInfo->userId, pUserInfo->devId.c_str(), pUserInfo->authToken.c_str(), pUserInfo->loginInfo.loginRspTime);
                long long costTime = pUserInfo->loginInfo.loginRspTime - pUserInfo->loginInfo.loginTime;
                printf("userId(%lld) devId(%s) token(%s) loginRsp successfully at %ld, cost time %ld\n", 
                    pUserInfo->userId, pUserInfo->devId.c_str(), pUserInfo->authToken.c_str(), pUserInfo->loginInfo.loginRspTime, costTime);
                //登录成功后需要为当前用户开启心跳定时器，这个步骤要回到socket线程
    #if 1
                CustomEvent event;
                event.handle = pack.stream; 
                event.istatus = 0;
                event.ieventType = CustomEvent::EVENT_LOGIN_SUCCESSE;
                if(m_sendRb->push(&event, sizeof(event), m_sendMem) == 0)//pack放到rb_recv, 能放下则放下
                {
                    LOG4_INFO("push CustomEvent of event.handle(%p) to ringbuffer, event.ieventType(%d), event.istatus(%d), rb_send(%p), p_send_mem(%p)",event.handle, event.ieventType, event.istatus ,  m_sendRb, m_sendMem);
                }
                else
                {
                    return;//m_sendRb满了，pack被扔掉了,后期可以考虑peek,但要配上remove,不可能在这里处理业务吧
                }
    #endif
            }
            else
            {
                LOG4_ERROR("decrypt LoginRsp error");
            }
        }
        else
        {
            LOG4_ERROR("there is no userInfo(%p)", pUserInfo);
        }
    }
    else 
    {
        im_login::LoginRsp loginRsp;
        loginRsp.ParseFromString(msgbody.body());
        LOG4_ERROR("loginRsp failed: (%s)", loginRsp.DebugString().c_str());
        pUserInfo->loginInfo.loginRspTime = GetMicrosecond();//登录返回并处理完的时间
        LOG4_ERROR("userId(%lld) devId(%s) token(%s) loginRsp failed at %ld", 
            pUserInfo->userId, pUserInfo->devId.c_str(), pUserInfo->authToken.c_str(), pUserInfo->loginInfo.loginRspTime);
        printf("userId(%lld) devId(%s) token(%s) loginRsp failed at %ld\n", 
            pUserInfo->userId, pUserInfo->devId.c_str(), pUserInfo->authToken.c_str(), pUserInfo->loginInfo.loginRspTime);
        switch (status)//不同情况的登录返回处理
        {
            case 0:
                /* code */
                break;
            
            default:
                break;
        }
    }
}

void ImMessagePack::HeatBeatReq(uv_connect_t* conn, MsgBody& msgBody)
{
    

}
void ImMessagePack::HearBeatRsp(const ImPack& pack)
{
    LOG4_INFO("HearBeatRsp from stream(%p), cmdId(%d), pack->len(%d)",pack.stream, ntohl(*((unsigned int*)(pack.packBuf + 4))), pack.len);
}

void ImMessagePack::MsgChatReq(uv_connect_t* conn, MsgBody& msgBody)
{/*
    message SendMsgReq
    {
        int64 fromId = 1;
        string fromNickName = 2;
        string fromHeadImg = 3;
        int64 dstId = 4;
        int32 dstType = 5;//
        int64 msgId = 6;//服务端生成的消息ID，客户端发起消息时不用填
        int64 sendTime = 7;//客户端发起消息的时间， 如果是派发消息4003， 则为服务端收到消息的时间
        int32 isTransmit = 8;//0:默认 0x00000001:转发类型信息 0x00000002:回复类型信息，按位表示消息的类型
        int32 msgType = 9;
        Msg msg = 10;
        int64 clientMsgId = 11;
        int32 createSession =12;
        int32 nodeStartTime=13;//服务端产生，客户端本地保存
        string nodeId=14;//服务端产生，客户端本地保存(单聊消息,状态消息: nodeId = "min(userId)_max(userId)", 比如“123456789_123456790”；群聊，群状态消息:nodeId = "groupId", 比如“66388374839230585”, 后边的nodeId如同)
        int32 msgSeq=15;//服务端产生，客户端本地保存
        int32 isTrySend =16;//重发消息，0:否 1：重发
        repeated int64 notifyUserId =17;//群聊@功能用到
        int64 notifyMsgId  =18;//单聊、群聊回复引用的消息ID
        int64 keyVersion = 19;//端到端密钥版本号,snowId，以服务器本地时间比较判断是否超过7天。默认0， 不加密通讯；>0 ,加密通讯

    }
*/
    UserInfo* pUserInfo = (UserInfo*)conn->data;
    if(pUserInfo)
    {
        im_client::SendMsgReq msgchat;
        msgchat.set_fromid(pUserInfo->userId);
        msgBody.set_body(msgchat.SerializeAsString());
        msgBody.set_targetid("");
    }
}



void ImMessagePack::MsgChatRsp(const ImPack& pack)
{
    LOG4_INFO("MsgChatRsp from stream(%p), cmdId(%d), pack->len(%d)",pack.stream, ntohl(*((unsigned int*)(pack.packBuf + 4))), pack.len);
}
void ImMessagePack::GroupChatReq(uv_connect_t* conn, MsgBody& msgBody)
{

}

void ImMessagePack::GroupChatRsp(const ImPack& pack)
{

}




