#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/engine.h>


 

int main(int argc, char* argv[])
{
	printf("openssl_test begin\n");
	RSA* rsa = NULL;
	unsigned char originstr[] = "hello\n";   //����������Ҫ���ܵ�ԭʼ����
									//allocate RSA structure��������Ҫ����һ��RSA�ṹ�����ڴ�����ɵĹ�˽Կ������rsa��������ṹ���ָ��
	rsa = RSA_new();
	if (rsa == NULL)
	{
		printf("RSA_new failed\n");
		return -1;
	}

	//generate RSA keys
	BIGNUM* exponent;
	exponent = BN_new();        //����RSA��˽Կ֮ǰ��Ҫѡ��һ��������odd number�����������ɹ�˽Կ
	if (exponent == NULL)
	{
		printf("BN_new failed\n");


		BN_free(exponent);
 
		RSA_free(rsa);
		return 0;
	}
	if (0 == BN_set_word(exponent, 65537))    //����ѡ������65537
	{
		printf("BN_set_word failed\n");
		BN_free(exponent);

		RSA_free(rsa);
		return 0;
	}


	//����modulus�ĳ���ѡ��2048��С��1024��modulus���ȶ��ǲ���ȫ�ģ����ױ��ƽ�
	if (0 == RSA_generate_key_ex(rsa, 2048, exponent, NULL))
	{
		printf("RSA_generate_key_ex failed\n");
		RSA_free(rsa);
		return 0;
	}
	unsigned char* cipherstr = NULL;
	//����һ�οռ����ڴ洢���ܺ�����ݣ�����ռ�Ĵ�С��RSA_size��������rsa���
	cipherstr = (unsigned char*)malloc(RSA_size(rsa));
	if (cipherstr == NULL)
	{
		printf("malloc cipherstr buf failed\n");

		BN_free(exponent);

		RSA_free(rsa);
		return 0;
	}
	prfinf("public")
	//������ʵ�ʵļ��ܹ��̣����һ������padding type�������¼��֡�    
	/*
	RSA_PKCS1_PADDINGPKCS #1 v1.5 padding. This currently is the most widely used mode.
	RSA_PKCS1_OAEP_PADDING
	EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter. This mode is recommended for all new applications.
	RSA_SSLV23_PADDING
	PKCS #1 v1.5 padding with an SSL-specific modification that denotes that the server is SSL3 capable.
	RSA_NO_PADDING
	Raw RSA encryption. This mode should only be used to implement cryptographically sound padding modes in the application code. Encrypting user data directly with RSA is insecure.
	*/
	//���������ù�Կ���м��ܣ�ѡ����RSA_PKCS1_PADDING

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
	//��������˽Կ���ܣ�������Ҫһ��buffer���ڴ洢���ܺ�����ݣ����buffer�ĳ���Ҫ�㹻��С��RSA_size(rsa)��
	//�������һ������Ϊ250���ַ����飬Ӧ���ǹ��õġ�
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