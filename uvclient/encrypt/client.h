

#ifndef CLIENT_H_
#define CLIENT_H_


 
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
 
 
#include "test_common.h"
 
 
#include"tx_define.h"
#include<string>
#include <arpa/inet.h> 
 
using namespace std;
 
 

// global var
	 
	extern signal_context *global_context;//signal ʹ��
 
	//head to host 

	void initContext();
	void  destroyContext();
	//�������ԣ���Կ˽Կ��16���ƴ�����Կǰ�����5��������Э����Կһ����;��Կ33�ֽڣ�66��16�����ַ�����˽Կ32���ֽڣ�64��16�����ַ���
	void test_curve25519_inputkey_agreements(char* alicePubKey, char* alicePriKey, char*bobPubKey, char* bobPriKey);
	//�Լ����ɲ��Թ�Կ��˽Կ��Э������ecdh
	void test_curve25519_random_agreements();
	void generate_key_pair_public_private_ecdh_string(string& publicKey, string &privateKey);
	
	// �������ԣ���Կ˽Կ��16���ƴ�����Կǰ�����5��������Э����Կһ����; ��Կ33�ֽ� ��˽Կ32���ֽ� 
	void test_curve25519_inpu_bindata_agreements(char* alicePubKey, char* alicePriKey, char*bobPubKey, char* bobPriKey);
	uint8_t* calculate_ecdh_share_key(const char* alicePubKey, const char* alicePriKey);
	void print_private_key(const char *prefix, ec_private_key *key);
 
 


	/*
#ifdef __cplusplus
}
#endif*/

#endif  
