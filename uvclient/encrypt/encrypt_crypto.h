#ifndef ENCRYPT_CRYPTO
#define ENCRYPT_CRYPTO
#include <string>
#include "aes_crypt.h"
#include "rsa_encrypt.h"

const int LOGINTOKENAUTHKEY_LEN 		= 512;
const int LOGINUSERDEVICEINFOKEY_LEN 	= 256;
const int AES_BLOCK_SIZE        		= 16;
const int AES_IV_LEN            		= 16;
const int	SESSIONKEY_LEN		  		= 32;
const int	ECDHKEY_LEN		  		    = 32;
const int RSA2048_ENCRYPTE_LEN		= 256;


std::string GetPassword(unsigned int size);
bool Rsa2048Decrypt(const std::string& strSrc, std::string& strDest, RSA* rsaKey, bool bRsaPrivateKey = true);
bool Rsa2048Encrypt(const std::string& strSrc, std::string& strDest, RSA* rsaKey, bool bRsaPrivateKey = true);
bool Aes256Encrypt(const std::string& strSrc, std::string& strDest,const std::string & aes_key);
bool Aes256Decrypt(const std::string& strSrc, std::string& strDest,const std::string & aes_key);
void GenerateEcdhKeyPair(std::string& pubKey, std::string& priKey);
void CacllateShareKey(const std::string& pubKey, const std::string& priKey, std::string& sharedKey);
void Base64Decode(const std::string& strSrc, std::string& strDest);
void Base64Encode(const std::string& strSrc, std::string& strDest);
#endif
