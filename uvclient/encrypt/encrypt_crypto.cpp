#include "encrypt_crypto.h"
#include "aes_crypt.h"
#include "rsa_encrypt.h"
#include "client.h"
#include "comm.h"
#include <stdlib.h>
#include <stdio.h>
bool Rsa2048Decrypt(const std::string& strSrc, std::string& strDest, RSA* rsaKey, bool bRsaPrivateKey)
{
    if(!rsaKey)
    {
        printf("rsaKey null!\n");
        return false;
    } 
    if (strSrc.size() > RSA2048_ENCRYPTE_LEN) 
    {
        printf("strSrc too length!!!\n");
        return false;
    }
    strDest.resize(RSA2048_ENCRYPTE_LEN, 0);
    int decrypted_length = -1;
    if(bRsaPrivateKey)
    {
        decrypted_length = privateDecrypt((unsigned char*)strSrc.c_str(), strSrc.size(), rsaKey, (unsigned char*)strDest.c_str(), RSA_PKCS1_PADDING);
    }
    else
    {
        decrypted_length = publicDecrypt((unsigned char*)strSrc.c_str(), strSrc.size(), rsaKey, (unsigned char*)strDest.c_str(), RSA_PKCS1_PADDING);
    }
    // printf("rsaKey = %p, privatekey decrypted length =%d,encypt:%s\n", rsaKey,  decrypted_length, base64Encode((const char*)strDest.c_str(), decrypted_length));
    if (decrypted_length < 0) 
    {
        printf("rsa Private Decrypt failed\n");
        return false;
    }
    strDest.resize(decrypted_length);
    return true;
}

bool Rsa2048Encrypt(const std::string& strSrc, std::string& strDest, RSA* rsaKey, bool bRsaPrivateKey)
{
    if(!rsaKey)
    {
        printf("rsaKey null!\n");
        return false;
    } 
    if (strSrc.size() > RSA2048_ENCRYPTE_LEN) 
    {
        printf("strSrc too length!!!\n");
        return false;
    }
    strDest.resize(RSA2048_ENCRYPTE_LEN, 0);
    int decrypted_length = -1;
    if(bRsaPrivateKey)
    {
        decrypted_length = privateEncrypt((unsigned char*)strSrc.c_str(), strSrc.size(), rsaKey, (unsigned char*)strDest.c_str(), RSA_PKCS1_PADDING);
    }
    else
    {
        decrypted_length = publicEncrypt((unsigned char*)strSrc.c_str(), strSrc.size(), rsaKey, (unsigned char*)strDest.c_str(), RSA_PKCS1_PADDING);
    }
    // printf("rsaKey = %p, privatekey decrypted length =%d,encypt:%s\n", rsaKey,  decrypted_length, base64Encode((const char*)strDest.c_str(), decrypted_length));
    if (decrypted_length < 0) 
    {
        printf("rsa Private Decrypt failed\n");
        return false;
    }
    strDest.resize(decrypted_length);
    return true;
}

bool Aes256Encrypt(const std::string& strSrc, std::string& strDest,const std::string & aes_key)
{
    strDest.resize(AES_BLOCK_SIZE * (strSrc.size() / AES_BLOCK_SIZE + 1), 0);
    int encrypted_len = aes_encrypt( (unsigned char*) strSrc.c_str(), strSrc.size(),
            (unsigned char*) aes_key.c_str(), (unsigned char*) aes_key.substr(0, AES_IV_LEN).c_str(),  (unsigned char*) strDest.c_str());
    if (encrypted_len < 0)
    {
        printf("aes aes_encrypt encrypted_len == %d\n",encrypted_len);
        return false;
    }
    strDest.resize(encrypted_len);
    return true;
}

bool Aes256Decrypt(const std::string& strSrc, std::string& strDest,const std::string & aes_key)
{
    strDest.resize(strSrc.size(),0);
    // printf("aes original text : %s, size :%d\n", base64Encode((const char*)strSrc.c_str(), strSrc.size()), strSrc.size());
    int decrypted_length = aes_decrypt( (unsigned char*)  strSrc.c_str(), strSrc.size(),
            (unsigned char*) aes_key.c_str(),  (unsigned char*) aes_key.substr(0, AES_IV_LEN).c_str(),  (unsigned char*) strDest.c_str()); //对称解密
    // printf("aes decrypted length =%d,encypt:%s\n", decrypted_length, base64Encode((const char*)strDest.c_str(), decrypted_length));
    if (decrypted_length < 0)
    {
        printf("aes decrypted decrypted_length == %d\n",decrypted_length);
        return false;
    }
    strDest.resize(decrypted_length);
    return true;
}

void GenerateEcdhKeyPair(std::string& pubKey, std::string& priKey)
{
    generate_key_pair_public_private_ecdh_string(pubKey, priKey);//生成协商密钥对,index=0, pub; index=1, pri
}

void CacllateShareKey(const std::string& pubKey, const std::string& priKey, std::string& sharedKey)
{
    uint8_t *signalKey = calculate_ecdh_share_key(pubKey.c_str(), priKey.c_str());
    sharedKey.resize(ECDHKEY_LEN);
    sharedKey.assign((char*)signalKey, ECDHKEY_LEN);
}

std::string GetPassword(unsigned int size)
{
    srand(time(nullptr));
    if (size > 128) size = 128;//限制最大长度
    std::string s;
    for(unsigned int i= 0; i< size; i++)
    {
        char ch(0);
        int num = rand()%3;
        if(num == 0)
            ch = static_cast<char>('0' + rand()%('9'-'0'+1));//getDigit
        else if(num == 1)
            ch = static_cast<char>('a' + rand()%('z'-'a'+1));//getLower
        else
            ch = static_cast<char>('A' + rand()%('Z'-'A'+1));//getUpper
        s.push_back(ch);

    }
    return s;

}
