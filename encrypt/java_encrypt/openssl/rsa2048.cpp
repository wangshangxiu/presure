#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/engine.h>


 

int main(int argc, char* argv[])
{
	printf("openssl_test begin\n");
	RSA* rsa = NULL;
	unsigned char originstr[] = "hello\n";   //这是我们需要加密的原始数据
									//allocate RSA structure，首先需要申请一个RSA结构题用于存放生成的公私钥，这里rsa就是这个结构体的指针
	rsa = RSA_new();
	if (rsa == NULL)
	{
		printf("RSA_new failed\n");
		return -1;
	}

	//generate RSA keys
	BIGNUM* exponent;
	exponent = BN_new();        //生成RSA公私钥之前需要选择一个奇数（odd number）来用于生成公私钥
	if (exponent == NULL)
	{
		printf("BN_new failed\n");


		BN_free(exponent);
 
		RSA_free(rsa);
		return 0;
	}
	if (0 == BN_set_word(exponent, 65537))    //这里选择奇数65537
	{
		printf("BN_set_word failed\n");
		BN_free(exponent);

		RSA_free(rsa);
		return 0;
	}


	//这里modulus的长度选择2048，小于1024的modulus长度都是不安全的，容易被破解
	if (0 == RSA_generate_key_ex(rsa, 2048, exponent, NULL))
	{
		printf("RSA_generate_key_ex failed\n");
		RSA_free(rsa);
		return 0;
	}
	unsigned char* cipherstr = NULL;
	//分配一段空间用于存储加密后的数据，这个空间的大小由RSA_size函数根据rsa算出
	cipherstr = (unsigned char*)malloc(RSA_size(rsa));
	if (cipherstr == NULL)
	{
		printf("malloc cipherstr buf failed\n");

		BN_free(exponent);

		RSA_free(rsa);
		return 0;
	}
	prfinf("public")
	//下面是实际的加密过程，最后一个参数padding type，有以下几种。    
	/*
	RSA_PKCS1_PADDINGPKCS #1 v1.5 padding. This currently is the most widely used mode.
	RSA_PKCS1_OAEP_PADDING
	EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter. This mode is recommended for all new applications.
	RSA_SSLV23_PADDING
	PKCS #1 v1.5 padding with an SSL-specific modification that denotes that the server is SSL3 capable.
	RSA_NO_PADDING
	Raw RSA encryption. This mode should only be used to implement cryptographically sound padding modes in the application code. Encrypting user data directly with RSA is insecure.
	*/
	//这里首先用公钥进行加密，选择了RSA_PKCS1_PADDING

	if (RSA_size(rsa) != RSA_public_encrypt(strlen((const   char *)originstr) + 1, (const unsigned char *)originstr, cipherstr, rsa, RSA_PKCS1_PADDING))
	{
		printf("encryption failure\n");

		free(cipherstr);

		BN_free(exponent);

		RSA_free(rsa);
		return 0;
	}
	printf("the original string is %s\n", originstr);
	printf("the encrypted string is %s\n", cipherstr);


	//Now, let's decrypt the string with private key
	//下面来用私钥解密，首先需要一个buffer用于存储解密后的数据，这个buffer的长度要足够（小于RSA_size(rsa)）
	//这里分配一个长度为250的字符数组，应该是够用的。
	unsigned char decrypted_str[250];
	int decrypted_len;
	if (-1 == (decrypted_len = RSA_private_decrypt(256, (const unsigned char *)cipherstr, decrypted_str, rsa, RSA_PKCS1_PADDING)))
	{
		printf("decryption failure\n");
		free(cipherstr);
 
		BN_free(exponent);
 
		RSA_free(rsa);
		return 0;
	}
	printf("decrypted string length is %d,decryped_str is %s\n", decrypted_len, decrypted_str);

	return 0;
}