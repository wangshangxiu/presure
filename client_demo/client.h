

#ifndef CLIENT_H_
#define CLIENT_H_


//libgo
#include <boost/thread.hpp>
#include <boost/progress.hpp>
//#include "coroutine.h"
#include "win_exit.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include<unistd.h>
#include<getopt.h>
#include <stdlib.h>
#include <stdint.h>
#include<string>
#include <check.h>
//#include <ctype.h>
//#include "../src/signal_protocol.h"
//#include "../src/signal_protocol_internal.h"
//#include "../src/curve.h"
//extern "C"
#include "test_common.h"
#include"LoginAuthMessage.pb.h"
#include"public/client_cmd.h"
#include"public/tx_define.h"
#include<string>
#include <arpa/inet.h> 

#include"LoginAuthTask.h"

#include "my_config.h"
/* 
#ifdef __cplusplus
extern "C" {
#endif*/

	typedef struct TFLAG
	{

		bool isNormal;
		bool isExitSendTask;
	}TFlag;


// global var
	extern TParam g_cmdParam;
	extern TCount g_count;//ͳ�Ƽ�¼����
	extern signal_context *global_context;//signal ʹ��
	void generate_key_pair_public_private_ecdh_string(string& publicKey, string &privateKey);
	//head to host 

	void initContext();
	void  destroyContext();
	//�������ԣ���Կ˽Կ��16���ƴ�����Կǰ�����5��������Э����Կһ����;��Կ33�ֽڣ�66��16�����ַ�����˽Կ32���ֽڣ�64��16�����ַ���
	void test_curve25519_inputkey_agreements(char* alicePubKey, char* alicePriKey, char*bobPubKey, char* bobPriKey);
	//�Լ����ɲ��Թ�Կ��˽Կ��Э������ecdh
	void test_curve25519_random_agreements();
	void generate_key_pair_public_private_ecdh_string(string& publicKey, string &privateKey);
	


	 
	void showStats();
	//void maintainConnect();
	 
	void client(char* ip, short sport, LoginAuthTask*pUserTask);
 
 


	/*
#ifdef __cplusplus
}
#endif*/

#endif  
