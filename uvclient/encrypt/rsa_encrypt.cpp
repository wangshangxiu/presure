#include "rsa_encrypt.h"
#include "comm.h"


//读取公钥文件中公钥到 内存rsa 结构中
RSA *readRsaPublicKeyFromFile(char* filePathPem)
{
	FILE *fp = NULL;
	RSA *publicRsa = NULL;
	if ((fp = fopen(filePathPem, "r")) == NULL)
	{
		printf("public key path error\n");
		return publicRsa;
	}
	if ((publicRsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL)
	{
		printf("PEM_read_RSA_PUBKEY error\n");
		return publicRsa;
	}
	fclose(fp);
	return publicRsa;
}
RSA *readRsaPrivateKeyFromFile(char* filePathPem, char* passwd)
{
	FILE *fp = NULL;
	RSA *privateRsa = NULL;
	if ((fp = fopen(filePathPem, "r")) == NULL)
	{
		printf("private key path error\n");
		return NULL;
	}
	if (passwd != NULL)
		OpenSSL_add_all_algorithms();//密钥有经过口令加密需要这个函数
	if ((privateRsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, (char *)passwd)) == NULL)
	{
		printf("PEM_read_RSAPrivateKey error\n");
		return NULL;
	}
	fclose(fp);
	return privateRsa;
}

/**
* @summary 生成公钥对到内存
* @param data strKey：strKey[0] 公钥； strKey[1] 私钥
* @return 是否处理成功 -1 失败； 0 成功
*/
int GenerateRsaKeyToMem(string strKey[])
{
	size_t pri_len;          // Length of private key
	size_t pub_len;          // Length of public key
	char *pri_key = NULL;           // Private key
	char *pub_key = NULL;           // Public key

	RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	pri_key = new char[pri_len + 1];
	pub_key = new char[pub_len + 1];

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	strKey[0] = pub_key;
	strKey[1] = pri_key;

	//printf("\n%s\n%s\n", pri_key, pub_key);

	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);
	delete[] pri_key;
	delete[] pub_key;

	return 0;
}

/**
* @summary 从字符串密钥转换为 rsa结构体
* @param key 密钥字符串
* @param flag  1 publickey ;0 privatekey
* @return NUll 失败，否则返回rsa 结构的密钥
*/
RSA* createRsaFromKeyStr(unsigned char* key, int flag)
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);

	if (keybio == NULL) {
		printf("Failed to create key BIO");
		return 0;
	}

	if (flag)
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	else
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	if (rsa == NULL)
		printf("Failed to create RSA");

	return rsa;
}



/**
* @summary 公钥加密数据
* @param data 待加密数据
* @param data_len 待加密数据长度
* @param rsa 密钥
* @param encrypted 加密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  加密后数据长度
*/
int publicEncrypt(unsigned char* pData, int iDataLen, RSA *pRsa, unsigned char* pEncryptData, int iPadding)
{
	//RSA * rsa = createRSA(key, 1);
	int result = RSA_public_encrypt(iDataLen, pData, pEncryptData, pRsa, iPadding);
	return result;
}
/**
* @summary 私钥解密数据
* @param pEncryptData 待解密数据
* @param iEncryptDataLen  待解密数长度
* @param rsa 密钥
* @param pDecryptData  解密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  解密后数据长度
*/
int privateDecrypt(unsigned char* pEncryptData, int iEncryptDataLen, RSA *pRsa, unsigned char* pDecryptData, int iPadding)
{
	//RSA * rsa = createRSA(key, 0);
	int  result = RSA_private_decrypt(iEncryptDataLen, pEncryptData, pDecryptData, pRsa, iPadding);
	return result;

}


/**
* @summary 私钥加密数据
* @param pEncryptData 待解密数据
* @param iEncryptDataLen  待解密数长度
* @param rsa 密钥
* @param pDecryptData  解密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  解密后数据长度
*/
int privateEncrypt(unsigned char* pData, int iDataLen, RSA *pRsa, unsigned char* pEncryptData, int iPadding)
{
	//RSA * rsa = createRSA(key, 0);
	int result = RSA_private_encrypt(iDataLen, pData, pEncryptData, pRsa, iPadding);
	return result;
}
/**
* @summary 公钥解密数据
* @param pEncryptData 待解密数据
* @param iEncryptDataLen  待解密数长度
* @param rsa 密钥
* @param pDecryptData  解密后数据
* @param iPadding  对齐方式
* @return 是否处理成功 -1 失败； >0  解密后数据长度
*/
int publicDecrypt(unsigned char* pEncryptData, int iEncryptDataLen, RSA *pRsa, unsigned char* pDecryptData, int iPadding)
{
	//RSA * rsa = createRSA(key, 1);
	int  result = RSA_public_decrypt(iEncryptDataLen, pEncryptData, pDecryptData, pRsa, iPadding);
	return result;
}

void printLastError(char *msg)
{
	char * err = (char*)malloc(130);;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}


// -ldl   -lssl -lcrypto -lcryptopp
void demoTest()
{

	printf("rsa2048/RSA_PKCS1_PADDING test");
		string cleartext = "1中国北京12345$abcde%ABCDE@！！！!2中国北京12345$abcde%ABCDE@！！！!3中国北京12345$abcde%ABCDE@！！！!4中国北京12345$abcde%ABCDE@！！！!";
	int padding = RSA_PKCS1_PADDING;
	if (cleartext.length() > 256) {
		cout << "cleartext too length!!!" << endl;
		return;
	}
	string plainText = cleartext;

	/*
	-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY
ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+
vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp
fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68
i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV
PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy
wQIDAQAB
-----END PUBLIC KEY-----
*/
	string publicKey = "-----BEGIN PUBLIC KEY-----\n" \
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n" \
		"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n" \
		"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n" \
		"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n" \
		"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n" \
		"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n" \
		"wQIDAQAB\n" \
		"-----END PUBLIC KEY-----\n";

	//char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"
	string privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"\
		"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
		"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
		"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
		"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
		"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
		"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
		"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
		"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
		"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
		"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
		"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
		"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
		"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
		"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
		"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
		"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
		"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
		"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
		"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
		"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
		"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
		"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
		"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
		"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
		"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
		"-----END RSA PRIVATE KEY-----\n";

	/*-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy
vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9
Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9
yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l
WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q
gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8
omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e
N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG
X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd
gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl
vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF
1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu
m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ
uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D
JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D
4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV
WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5
nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG
PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA
SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1
I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96
ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF
yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5
w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX
uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw
-----END RSA PRIVATE KEY-----*/

	unsigned char  encrypted[4098] = "";
	unsigned char decrypted[4098] = "";


	//int encrypted_length= public_encrypt((unsigned char*)plainText,strlen(plainText),(unsigned char*)publicKey,encrypted);
	int encrypted_length = publicEncrypt((unsigned char*)plainText.c_str(), plainText.length(), createRsaFromKeyStr((unsigned char*)publicKey.c_str(), 1), encrypted, padding);
	if (encrypted_length == -1) {
		printLastError("Public Encrypt failed ");
		exit(0);
	}
	//公钥加密
	printf("publickey Encrypted： length =%d,encypt:%s\n", encrypted_length, base64Encode((const char*)encrypted, encrypted_length));
	//string tmp = "oAuMn6IgnrwKEKDQapI5s1X0QZ7LUJmksFuOOcZIy7stfLnwtoIoqsxqPP4yr2WJgS3iwcvg/LNYuZn3z9n9CUrsBrkfhNIZkW81tr0ri4ab9VZJFC6ALWXtSmjKzy5Ei9COLtcJOKNNcOF7zOhjLFWCXny6pBIdIGP44jBgJ0eqeZqenmWKT9qYNbPRUuoKxvQjtB4hSZgq2YwmWOwBRrlsOHX4wOu5KKihZ0b9HFD2YwOAKjN7qDZouMbHBpKKxsFUyOwjGrSczm9+JiWtzTKPLob29wY30lj4pjySVMVTFvGS5PA0LRi+/XjSeqQYHXN20Om2r0pSX98mHI2KZA==";
	//memcpy(encrypted, base64Decode((  char*)tmp.c_str(), tmp.length()), encrypted_length);
	//int decrypted_length = privateDecrypt(encrypted, encrypted_length, createRsaFromKeyStr((unsigned char*)privateKey.c_str(), 0), decrypted, padding);
	//私钥解密
	int decrypted_length = privateDecrypt(encrypted, encrypted_length, createRsaFromKeyStr((unsigned char*)privateKey.c_str(), 0), decrypted, padding);
	if (decrypted_length == -1) {
		printLastError("Private Decrypt failed ");
		exit(0);
	}
	printf("privatekey Decrypted： Text =%s\n", decrypted);
	printf("Decrypted Length =%d\n", decrypted_length);
	//私钥加密
	encrypted_length = privateEncrypt((unsigned char*)plainText.c_str(), plainText.length(), createRsaFromKeyStr((unsigned char*)privateKey.c_str(), 0), encrypted, padding);
	if (encrypted_length == -1) {
		printLastError("Private Encrypt failed");
		exit(0);
	}
	printf("Encrypted length =%d,encypt:%s\n", encrypted_length, base64Encode((const char*)encrypted, encrypted_length));
	//公钥解密
	decrypted_length = publicDecrypt(encrypted, encrypted_length, createRsaFromKeyStr((unsigned char*)publicKey.c_str(), 1), decrypted, padding);
	if (decrypted_length == -1) {
		printLastError("Public Decrypt failed");
		exit(0);
	}
	printf("Decrypted Text =%s\n", decrypted);
	printf("Decrypted Length =%d\n", decrypted_length);



}
