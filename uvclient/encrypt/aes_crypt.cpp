#include <stdlib.h>
#include <stdio.h>
#include "aes_crypt.h"
#include <openssl/evp.h>
#include <string.h>
#include"comm.h"
 
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -2;
	}
 
  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  {
	  EVP_CIPHER_CTX_free(ctx);
	  return -3;
  }
  ciphertext_len = len;
 
  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
  {
	  EVP_CIPHER_CTX_free(ctx);
	  return -4;
  }
  ciphertext_len += len;
 
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
 
  return ciphertext_len;
}
 
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
 
  int len;
 
  int plaintext_len;
 
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
 
  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
	  EVP_CIPHER_CTX_free(ctx);
	  return -2;
  }
 
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
	  EVP_CIPHER_CTX_free(ctx);
	  return -3;
  }
  plaintext_len = len;
 
  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
  {
	  EVP_CIPHER_CTX_free(ctx);
	  return -4;
  }
  plaintext_len += len;
 
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
 
  return plaintext_len;
}


void aesDemoTest()
{
 
	//待加密测试数据
	unsigned char *plaintext = (unsigned char *)"123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456";

	int plaintext_len = strlen((const char*)plaintext);

	unsigned char *key = (unsigned char *)"12345678901234561234567890123456";//encrypt key 加密key
	unsigned char *iv = (unsigned char *)"1234567890123456";//iv向量 取加密key 前16字节
	int outLen = 16 * (plaintext_len / 16 + 1);
	unsigned char *ciphertext = new unsigned char[outLen];

	int len = aes_encrypt(plaintext, plaintext_len, key, iv, ciphertext);
	//hex2Str(char *sSrc, int nSrcLen, char *sDest)

	char *sDest = new   char[outLen * 2+1];
	memset(sDest, 0, outLen * 2+1);
	//转换加密后数据为16进制字符串
	hex2Str((char*)ciphertext, len, sDest);
	//加密后的16进制字符串

	printf("aes plaintext:%s\n", plaintext);
	printf("aes encrypt value:%s\n", sDest);

	unsigned char decrpyttext[1024*8] = {0};
	aes_decrypt(ciphertext, outLen, key, iv, &decrpyttext[0]);
	printf("aes decrypt value:%s\n", decrpyttext);
	
	if(ciphertext)
		delete ciphertext;
	if (sDest)
		delete sDest;

}
