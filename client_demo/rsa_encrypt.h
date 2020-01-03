/*
* rsa_encrypt.h
*
*  Created on: 2019-12-26
*      Author: frank
*/
#ifndef RSA_ENCRYPT_H_
#define RSA_ENCRYPT_H_
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include<string>
#include<memory.h>
#include<iostream>
#include "openssl/err.h"
using namespace std;
#ifdef __cplusplus
extern "C" {
#endif

#define PUBLICKEY "publicKey.pem"
#define PRIVATEKEY "privateKey.pem"
#define KEY_LENGTH  2048 
//int iPadding = RSA_PKCS1_PADDING;
//int i_encrypt_len = 0;
#define PUB_EXP     3 

 
//读取公钥文件中公钥到 内存rsa 结构中
RSA *readRsaPublicKeyFromFile(char* filePathPem);
 
RSA *readRsaPrivateKeyFromFile(char* filePathPem, char* passwd);
 

/**
* @summary 生成公钥对到内存
* @param data strKey：strKey[0] 公钥； strKey[1] 私钥
* @return 是否处理成功 -1 失败； 0 成功
*/
int GenerateRsaKeyToMem(string strKey[]);
 

/**
* @summary 从字符串密钥转换为 rsa结构体
* @param key 密钥字符串
* @param flag  1 publickey ;0 privatekey
* @return NUll 失败，否则返回rsa 结构的密钥
*/
RSA* createRsaFromKeyStr(unsigned char* key, int flag);
 



/**
* @summary 公钥加密数据
* @param data 待加密数据
* @param data_len 待加密数据长度
* @param rsa 密钥
* @param encrypted 加密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  加密后数据长度
*/
int publicEncrypt(unsigned char* pData, int iDataLen, RSA *pRsa, unsigned char* pEncryptData, int iPadding);
 
/**
* @summary 私钥解密数据
* @param pEncryptData 待解密数据
* @param iEncryptDataLen  待解密数长度
* @param rsa 密钥
* @param pDecryptData  解密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  解密后数据长度
*/
int privateDecrypt(unsigned char* pEncryptData, int iEncryptDataLen, RSA *pRsa, unsigned char* pDecryptData, int iPadding);
 


/**
* @summary 私钥加密数据
* @param pEncryptData 待解密数据
* @param iEncryptDataLen  待解密数长度
* @param rsa 密钥
* @param pDecryptData  解密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  解密后数据长度
*/
int privateEncrypt(unsigned char* pData, int iDataLen, RSA *pRsa, unsigned char* pEncryptData, int iPadding);
 
/**
* @summary 公钥解密数据
* @param pEncryptData 待解密数据
* @param iEncryptDataLen  待解密数长度
* @param rsa 密钥
* @param pDecryptData  解密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  解密后数据长度
*/
int publicDecrypt(unsigned char* pEncryptData, int iEncryptDataLen, RSA *pRsa, unsigned char* pDecryptData, int iPadding);
 

void printLastError(char *msg);
 

#ifdef __cplusplus
}
#endif

#endif /* RSA_ENCRYPT_H_ */
