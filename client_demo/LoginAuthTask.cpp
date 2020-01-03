 
#include "LoginAuthTask.h"


RSA* LoginAuthTask::m_pRsaPubKey = NULL;
void ntoh_head(THead& tHead)
{
	tHead.len = ntohl(tHead.len);
	tHead.cmd = ntohl(tHead.cmd);
	tHead.seq = ntohl(tHead.seq);
	tHead.status = ntohs(tHead.status);

}

//head to network 
void hton_head(THead& tHead)
{
	tHead.len = htonl(tHead.len);
	tHead.cmd = htonl(tHead.cmd);
	tHead.seq = htonl(tHead.seq);
	tHead.status = htons(tHead.status);

}
//…Ë÷√rsaπ´‘ø
 void LoginAuthTask::setRsaPublickKey(RSA* pRsa)
{


	 m_pRsaPubKey = pRsa;

}
 
void LoginAuthTask::GenPwd()
{
	//m_strPwd = GetMd5_32(m_strPwd);
}

void LoginAuthTask::GenAesKey()
{
	m_strAesKey.resize(32);
	for (int i = 0; i < 32; i++)
	{
		m_strAesKey[i] = rand() % 0xff;
	}
}

void LoginAuthTask::GenEcdh()
{
	///m_nid = ECDH_NID;
	//::GenEcdh(m_nid, m_strLocalEcdhPubKey, m_strLocalEcdhPriKey);
}
 

