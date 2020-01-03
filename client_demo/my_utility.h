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

	//�鿴�ļ�ʮ�ִ���0--����-1������
	int IsExsitFile(char *filePath);

	//��ȡ�ļ���С0--�ļ�������
	unsigned int GetFileSize(char* filePath);
	
	//�����߿ո�
	void trimLeft(char *p);
	
	//����ɱ߿ո�
	void trimRight(char *p);

	void trimAll(char *p);

	//��¼����id
	void LogPid(const char *filename, unsigned int pid);

	//�̰߳�ȫ��sleep����
	int mySleep(unsigned int sec, unsigned int usec);

	string MakeSalt();

	//�ֽ�key-value�Ӵ�
	int parserKeyValue(const char *str, vector<string> &vec);
	
	//��������
	int parserHttpReq(const char *str, map<string, string> & param);

	string HexPrintf(unsigned char *src, int len);

	//������key ����key ���� 0--�ɹ�
	int parserKey(const char* str, int &ernterid, int &key, int &subkey);

	string codeTrans(char *srccode, char *dstcode, const char *in);

	int decode(const unsigned char * bytes ,unsigned long bytes_len ,wchar_t *buffer,bool decode_force=true); 

	int code_convert(char *from_charset,char *to_charset,char *inbuf,int inlen,char *outbuf,int outlen);

	int Mchar(unsigned char *str, char *out);

	size_t BKDRHash(const char *str);  

	string MD532(const char *p);
	
	int SplitStrByChar( const string Str, const char ch, vector<string> &StrList );

	int commStr(vector<string> vec, string &str);

	//ѹ������ѹ���ĳ���
	int Commpress(unsigned char *dest, unsigned long dest_len, const unsigned char *src, unsigned long src_len);
	
	//��ѹ
	int UnCommpress(unsigned char *dest, unsigned long dest_len, const unsigned char *src, unsigned long src_len);

	//AES���ܽ��ܼ��ܴ�����һ��
	int AES_EnCode(const char *src, int len, char* dest, char *key, int key_len);
	int AES_Length(int len);
	int AES_DeCode(const char *src, int len, char* dest, char *key, int key_len);

	//3DES���ܽ���
	/*//���ؼ��ܺ󳤶�8�ı�����ǰ��2�ֽ�ΪԴ�ַ�������
	int DES3_EnCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);
	int DES3_DeCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);

	//des���ܽ���
	int DES_EnCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);
	int DES_DeCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len);*/

	bool IsNum(string str);

	///////////////////////////////////////////////////////////////////////////////////////////////////////////
	//add by xkj 2017-9-18
	//д�ļ�
	int WriteFile(char* filename, char* content, int len);

	//���ļ�,�����ļ�����
	int ReadFile(char* filename, string& str);

	string encrypt(string plainText, unsigned char* key);
	string decrypt(string cipherTextHex, unsigned char* key);
};


#endif


