#ifndef __MY_UTILITY_H__
#define __MY_UTILITY_H__

#include <string>
#include <map>
#include <vector>

using namespace std;

namespace MYU
{
	unsigned int GetTime(char * tt);

	int GetCurDatetime(char* szDTime);

	string GetTimeSpace(unsigned int tt);
	
	short GetStateNum(char * str);

	string GetStateStr(int num);

	unsigned int GetYYYYMMDD(unsigned int currtime);

	unsigned int GetNextDay(unsigned int currtime);

	//查看文件十分存在0--存在-1不存在
	int IsExsitFile(char *filePath);

	//获取文件大小0--文件不存在
	unsigned int GetFileSize(char* filePath);
	
	//清除左边空格
	void trimLeft(char *p);
	
	//清除由边空格
	void trimRight(char *p);

	void trimAll(char *p);

	//记录进程id
	void LogPid(const char *filename, unsigned int pid);

	//线程安全的sleep函数
	int mySleep(unsigned int sec, unsigned int usec);

	string MakeSalt();

	//分解key-value子串
	int parserKeyValue(const char *str, vector<string> &vec);
	
	//解析请求串
	int parserHttpReq(const char *str, map<string, string> & param);

	string HexPrintf(unsigned char *src, int len);

	//解析主key 和子key 返回 0--成功
	int parserKey(const char* str, int &ernterid, int &key, int &subkey);

	string codeTrans(char *srccode, char *dstcode, const char *in);

	int decode(const unsigned char * bytes ,unsigned long bytes_len ,wchar_t *buffer,bool decode_force=true); 

	int code_convert(char *from_charset,char *to_charset,char *inbuf,int inlen,char *outbuf,int outlen);

	int Mchar(unsigned char *str, char *out);

	size_t BKDRHash(const char *str);  

	string MD532(const char *p);
	
	int SplitStrByChar( const string Str, const char ch, vector<string> &StrList );

	int commStr(vector<string> vec, string &str);

	//压缩返回压缩的长度
	int Commpress(unsigned char *dest, unsigned long dest_len, const unsigned char *src, unsigned long src_len);
	
	//解压
	int UnCommpress(unsigned char *dest, unsigned long dest_len, const unsigned char *src, unsigned long src_len);

	//AES加密解密加密处理长度一样
	int AES_EnCode(const char *src, int len, char* dest, char *key, int key_len);
	int AES_Length(int len);
	int AES_DeCode(const char *src, int len, char* dest, char *key, int key_len);

	//3DES加密解密
	/*//返回加密后长度8的倍数最前面2字节为源字符串长度
	int DES3_EnCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);
	int DES3_DeCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);

	//des加密解密
	int DES_EnCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);
	int DES_DeCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);*/

	bool IsNum(string str);

	///////////////////////////////////////////////////////////////////////////////////////////////////////////
	//add by xkj 2017-9-18
	//写文件
	int WriteFile(char* filename, char* content, int len);

	//读文件,返回文件长度
	int ReadFile(char* filename, string& str);

	string encrypt(string plainText, unsigned char* key);
	string decrypt(string cipherTextHex, unsigned char* key);
};


#endif


