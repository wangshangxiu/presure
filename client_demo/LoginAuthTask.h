#ifndef LOGINAUTHTASK_H_
#define LOGINAUTHTASK_H_


#include"public/tx_define.h"
#include "LoginAuthMessage.pb.h"
#include"rsa_encrypt.h"
#include "aes_crypt.h"
#include <arpa/inet.h> 
#include"public/client_cmd.h"
#include"LoginAuthMessage.pb.h"
using namespace std;


#pragma pack(1)
typedef struct  Head
{
	uint32_t len;
	uint32_t cmd;
	uint32_t seq;
	uint8_t version;
	uint8_t reserve;
	uint16_t status;


}THead;

typedef struct  COUNT
{
	std::atomic<int>       sendCount;
	std::atomic<int> recvCount;
	std::atomic<int> lastSendCount;
	std::atomic<int> lastRecvCount;
	std::atomic<int> connectTotal;//l连接总数

}TCount;

typedef struct TPARAM
{
	enum { LOGIN_TEST = 1, SEND_MSG };
	int aTestType;//1 login ;2 send msg p2p
	int cConcurrentNumber;//并发数
	int sQps;//每秒请求/发送数
	int nTotalNumber;//总共发送数
	int tStopTime;//j截至时间
	int bStartUserId;//测试用户号段，开始id
	int eEndUserId;//测试用户号段，结束用户id
	string iIP;
	short pPort;
	int dThreadNumber;//线程数

}TParam;
#pragma pack()
void ntoh_head(THead& tHead);
//function
//head to network 
void hton_head(THead& tHead);
class LoginAuthTask  
{
public:
	//设置rsa公钥
	static void setRsaPublickKey(RSA* pRsa);
public:
 
	string		m_strUserName;
	string		m_strPwd;
 


	//init(uint32 uUserId, string token, uint32 uLoginSeq);
	int makePacket(string& body)
	{
		//init
		GenPwd();
 
		//ecdh

		GenAesKey();

		//
		RsaData *rsaData = new RsaData();
		rsaData->set_aeskey(m_strAesKey.c_str());
		rsaData->set_userid(m_uUserID);
		rsaData->set_ecdhpubkey(m_strLocalEcdhPubKey.c_str());

		//rsa encrypt
		string *req = new string();
		 rsaData->SerializeToString(req);
		 unsigned char*pEncryptData = new unsigned char[2048];
		 short rsaLen =publicEncrypt((unsigned char*)req->c_str(),req->length(), m_pRsaPubKey,   pEncryptData, RSA_PKCS1_PADDING);

		 
		 //aes encrypt

		 AESData *aesData = new AESData();
		 string tmp = "deviceid";
		 char szUserId[20] = "";
		 sprintf(szUserId, "%d", m_uUserID);
		 string sUserid = szUserId;
		 aesData->set_devid(tmp+ sUserid +"001");
		 aesData->set_token(string("token")+ sUserid +"001");
		 aesData->set_clienttime(time(NULL));
		 aesData->set_loginseq(m_ulLoginSeq++);
		 aesData->set_other(string("other:")+ sUserid);

		 string *req1 = new string();
		 aesData->SerializeToString(req1);

		 uint8* paesData = new uint8[req1->length()+17];
		 short aesEncryptLen=aes_encrypt((uint8*)req1->c_str(), req1->length(), (uint8*)m_strAesKey.c_str(), (uint8*)m_strAesKey.substr(0,16).c_str(), paesData);

		 
		 short netrsaLen = htons( rsaLen);
		 body.append((const char *)&netrsaLen, 2);
		   

		 short netaesLen = htons(aesEncryptLen);
		 body.append((const char *)&netaesLen, 2);

		 char rsaVersion = 1;
		 body.append((const char *)&rsaVersion, 1);
 
		 body.append((const char *)pEncryptData, rsaLen);
		 body.append((const char *)paesData, aesEncryptLen);

 
		 delete rsaData;
		 delete req;
		 delete pEncryptData;
		 delete aesData;
		 delete req1;
		 delete paesData;


		 return body.length();

	}
	string makeHead(string& body)
	{
		uint32 len = htonl(sizeof(THead) + body.length());
		uint32 cmd = CL_LOGIN_REQ;
		uint32 seq = 0;
		uint8 version = 1;
		uint8 reserve = 0;
		uint16 status = 0;
		string head;
		head.append((const char *)&len, sizeof(len));
		head.append((const char *)&cmd, sizeof(cmd));
		head.append((const char *)&seq, sizeof(seq));
		head.append((const char *)&version, sizeof(version));
		head.append((const char *)&reserve, sizeof(reserve));
		head.append((const char *)&status, sizeof(status));
		return head;
	}
	/*string unpackHead(char* head)
	{
		THead tHead;
		memset(&tHead, 0, sizeof(tHead));
		memcpy(&tHead, head, sizeof(tHead));

	}*/
	string unpackLogin(string& pack)
	{
		THead tHead;
		memset(&tHead, 0, sizeof(tHead));
		memcpy(&tHead, pack.c_str(), sizeof(tHead));

		ntoh_head(tHead);


		uint8* paesData = new uint8[tHead.len + 16];
		short aesDecryptLen = aes_decrypt((uint8*)pack.c_str()+sizeof(tHead),  tHead.len-sizeof(tHead), (uint8*)m_strAesKey.c_str(), (uint8*)m_strAesKey.c_str() + 16, (uint8*)paesData);

		LoginRsp *pRsp = new LoginRsp();
		bool bRet = pRsp->ParsePartialFromArray(paesData, aesDecryptLen);
		if (bRet)
		{
			int code = pRsp->code();
			string codeMsg = pRsp->codemsg();
			m_strRemoteEcdhPubKey =pRsp->ecdhserverpubkey();
			string skey=pRsp->sessionkey();
			m_sessionID = pRsp->sessionid();

			m_seq = pRsp->startseq();

			printf("recv unpackLogin\n");
		}
		else
		{
			printf("parse login rsp data err\n");
		}
	}
	//loadFromFileUserList();
	//1.init user info  2.packet loginreq to serize 3.send 4.recv rsp 5.heart 
public:
	void GenPwd();				//密码Md5
	void GenAesKey();			//握手包aes(仅用于本次通讯,后续通讯使用ECDH协商出的session key)
	void GenEcdh();				//生成本地DH
 
	   
	uint32      m_uUserID;
	string		m_strToken;
	string		m_strAesKey;
	int			m_nAesKeyLen = 16;
	string		m_strLocalEcdhPubKey;
	string		m_strLocalEcdhPriKey;
	string		m_strRemoteEcdhPubKey;
	static RSA * m_pRsaPubKey;
 
	int			m_nid = 0;
	string		m_strDeviceID;
	uint64		m_ulLoginSeq;
	string		m_strOthers;
	string      m_sessionID;
	string      m_sessionKey;
	uint32      m_seq;

 

};

#endif  
