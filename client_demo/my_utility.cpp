#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "my_utility.h"
#include <string.h>
#include <iconv.h>
#include <errno.h>
//#include "md5.h"
//#include "zlib.h"
#include "openssl/aes.h"
#include "openssl/objects.h"
#include "openssl/evp.h"
//#include <openssl/des.h>
#include <string>
#include <sstream>
//#include <cryptopp/aes.h>
//#include <cryptopp/filters.h>
//#include <cryptopp/modes.h>
//#include <cryptopp/cryptlib.h>

namespace MYU
{
	unsigned int GetTime(char * tt)
	{
        tm t = {0};
        sscanf(tt, "%04d-%02d-%02d %02d:%02d:%02d", &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec);
        t.tm_year -= 1900;
        t.tm_mon -= 1;

        time_t x = mktime(&t);

		return (unsigned int)x;
	}

	int GetCurDatetime(char* szDTime)
	{
		time_t tm1;
		struct tm tb1;
		struct tm *re_tb;
		time(&tm1);
		re_tb = localtime_r(&tm1, &tb1); 
		
		if(NULL == re_tb)
		{
			return -1;
		}
		
		sprintf(szDTime,"%04d-%02d-%02d::%02d:%02d:%02d",
				tb1.tm_year+1900,tb1.tm_mon+1,tb1.tm_mday,
				tb1.tm_hour,tb1.tm_min,tb1.tm_sec);

		return 1;
	}

	string GetTimeSpace(unsigned int tt)
	{
		time_t tm1 = tt;
		struct tm tb1;
		struct tm *re_tb;
		
		re_tb = localtime_r(&tm1, &tb1); 
		
		if(NULL == re_tb)
		{
			return string("0");
		}

		char szDTtime[32] = {0};
		sprintf(szDTtime,"%04d-%02d-%02d",
				tb1.tm_year+1900,tb1.tm_mon+1,tb1.tm_mday);

		return string(szDTtime);
	}

	unsigned int GetYYYYMMDD(unsigned int currtime)
	{
		time_t tm1 = currtime;
		struct tm tb1;
		struct tm *re_tb;
		
		re_tb = localtime_r(&tm1, &tb1); 
		
		if(NULL == re_tb)
		{
			return -1;
		}

		unsigned int x = (tb1.tm_year+1900) * 10000 + (tb1.tm_mon+1) * 100 + tb1.tm_mday;

		/*
		char szDTime[32] = {0};
		sprintf(szDTime,"%04d-%02d-%02d",
				tb1.tm_year+1900,tb1.tm_mon+1,tb1.tm_mday);

		tm t = {0};
		sscanf(szDTime, "%04d-%02d-%02d", &t.tm_year, &t.tm_mon, &t.tm_mday);
		t.tm_year -= 1900;
		t.tm_mon -= 1;

		time_t x = mktime(&t); */

		return x;
	}

	unsigned int GetNextDay(unsigned int currtime)
	{
		time_t tm1 = currtime;
		struct tm tb1;
		struct tm *re_tb;
		
		re_tb = localtime_r(&tm1, &tb1); 
		
		if(NULL == re_tb)
		{
			return -1;
		}

		char szDTime[32] = {0};
		sprintf(szDTime,"%04d-%02d-%02d",
				tb1.tm_year+1900,tb1.tm_mon+1,tb1.tm_mday + 1);

		tm t = {0};
		sscanf(szDTime, "%04d-%02d-%02d", &t.tm_year, &t.tm_mon, &t.tm_mday);
		t.tm_year -= 1900;
		t.tm_mon -= 1;

		time_t x = mktime(&t); 

		return x;
	}

	short GetStateNum(char * str)
	{
		return 0;
	}

	string GetStateStr(int num)
	{
		string str = ""; 
		return str;
	}

	int IsExsitFile(char *filePath)
	{
		int fd = open(filePath, O_RDONLY);
		if(fd > 0)
		{
			close(fd);

			return 0;
		}

		return -1;
	}

	//获取文件大小0--文件不存在
	unsigned int GetFileSize(char* filePath)
	{
		struct stat buf;
		if(stat(filePath, &buf)<0)
		{
			return 0;
		}

		return (unsigned int)buf.st_size;
	}
		
	//清除左边空格
	void trimLeft(char *str)
	{
		char *p = str;

		if(' ' != *p)
		{
			return ;
		}
		
		while(*p == ' ')
		{
			p ++;	
		}

		strcpy(str, p);
	}
	
	//清除由边空格
	void trimRight(char *str)
	{
		int len = strlen(str);
		char *p = str + len - 1;

		while(*p == ' ')
		{
			p --;
		}

		*(p + 1) = '\0';
	}

	void trimAll(char *str)
	{
		char *p = str;

		while(*p)
		{
			if(*p == ' ')
			{
				strcpy(p, p + 1);
			}
			else
			{
				p ++;
			}
		}
	}

	void LogPid(const char *filename, unsigned int pid)
	{
		FILE * fp = fopen(filename, "w+");
		char buf[64] = {0};
		snprintf(buf, sizeof(buf), "%u", pid);
		fwrite(buf, strlen(buf), 1, fp);
		fclose(fp);
	}

	int mySleep(unsigned int sec, unsigned int usec)
	{
	    timeval t_timeval;
	    t_timeval.tv_sec = sec;
	    t_timeval.tv_usec = usec;
	    select( 0, NULL, NULL, NULL, &t_timeval );
	    return 0;
	}

	string MakeSalt()
	{
		string code = "123456789abcdefghijkhlmopqrstvuwxzy";
	    string str;
	    for(int i=0;i<6;i++)
	    {
	        int k = 1;
	        time_t curr_time;
	        time(&curr_time);

	        int x = curr_time % (k * 10);

	        int s = x % 25;
	        str[i] = code[s + i];

	        k *= 10;
	    }

		return str;
	}


	int parserKeyValue(const char *str, vector<string> &vec)
	{
		if(NULL == str)
		{
			return -1;
		}

		const char *bg = str;
		const char *end = str;
		while(*end)
		{
			if('&' == *end)
			{
				string v;
				v.append(bg, end-bg);

				vec.push_back(v);
				end ++;
				bg = end;
			}
			else
			{
				end ++;
			}
		}

		//加入最后一个
		vec.push_back(string(bg));

		return 0;
	}
		
	int parserHttpReq(const char *str, map<string, string> & param)
	{
		if(NULL == str)
		{
			return -1;
		}

		const char *pos = strstr(str, "cmd");
		if(NULL == pos)
		{
			return -1;
		}

		vector<string> vec;
		vec.clear();

		if(-1 == parserKeyValue(pos, vec))
		{
			return -1;
		}

		for(vector<string>::iterator it=vec.begin(); it!=vec.end(); it++)
		{
			const char *k = it->c_str();

			const char *find = strchr(k, '=');
			if(NULL == find)
			{
				break;
			}

			string key;
			key.append(k, find - k);
			
			find ++;
			param[key] = string(find);
		}
		
		return 0;
	}

	string HexPrintf(unsigned char *src, int len)
	{
		string str;
		str.clear();
		
		for(int i=0;i<len;i++)
		{
			char tmp[16] = {0};
			snprintf(tmp, sizeof(tmp), "%02x ", src[i]);

			str += string(tmp);
		}

		return str;
	}

	int parserKey(const char* str, int &ernterid, int &key, int &subkey)
	{
		//*129*01*95533*1*2*3#
		if(NULL == str)
		{
			return -1;
		}

		const char *p = str;
		char sernter[32] = {0};
		char skey[32] = {0};
		char ssubkey[32] = {0};

		//由于前面8个字节长度固定*129*01* 
		int count = 8;
		int i=0;
		while(*p && *p != '#' && count)
		{
			if('*' != *p)
			{
				sernter[i++] = *p ++;
				count --;
			}
			else
			{
				p ++;
				count --;
			}
		}
		
		i=0;
		//取主key
		while(*p && *p != '#' && i < 32)
		{
			if('*' == *p)
			{
				p ++;
				break;
			}
			else
			{
				skey[i++] = *p ++;
			}
		}

		//取子key
		i=1;
		ssubkey[0] = '1';
		while(*p && *p != '#' &&  i < 32)
		{
			if('*' == *p)
			{
				p ++;
			}
			else
			{
				ssubkey[i++] = *p ++;
			}
		}

		ernterid = atoi(sernter);
		key = atoi(skey);
		subkey = atoi(ssubkey);
		
		return 0;
	}

	string codeTrans(char *srccode, char *dstcode, const char *in)
	{
        char  bufout[1024], *sin, *sout;
        int  lenin, lenout, ret;
        iconv_t c_pt;

        if ((c_pt = iconv_open(srccode, dstcode)) == (iconv_t)-1)
        {
        	return "1111";
        }

        lenin  = strlen(in);
        lenout = 1024;
        sin    = (char *)in;
        sout   = bufout;
        ret = iconv(c_pt, &sin, (size_t *)&lenin, &sout, (size_t *)&lenout);
        if (ret == -1)
        {
        	printf("%s\n", strerror(errno));
        	return "2222";
        }
        iconv_close(c_pt);

		return string(bufout);
	}

	int decode(const unsigned char * bytes ,unsigned long bytes_len ,wchar_t *buffer, bool decode_force)
	{
		int decode_size = 0;
		while( bytes_len > 0 )
		{
			if( *bytes < 0x80 ) //0xxxxxxx
			{
				*buffer = *bytes;

				bytes++;
				bytes_len --;
				
			}
			else if ( ((*bytes) >> 5) ==6 ) //110xxxxx 10xxxxxx
			{
				if( bytes_len >1 && bytes[1]>>6 == 2 )
				{
					*buffer = ((*bytes  & 0x1f ) << 6) | (bytes[1] & 0x3f);

					bytes+=2;
					bytes_len -=2;
				}
			}
			else if ( ((*bytes) >> 4) == 14 ) //1110xxxx 10xxxxxx 10xxxxxx
			{
				if(bytes_len >2 &&   bytes[1]>>6==2 && bytes[2]>>6==2 )
				{
					*buffer = ((*bytes  & 0x0f ) << 12 ) |
						((bytes[1] & 0x3f) << 6 ) |(bytes[2] & 0x3f);

					bytes+=3;
					bytes_len -=3;
				}
			}
			else if ( ((*bytes) >> 3) == 30 ) //11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
			{
				if(  bytes_len >3 && bytes[1]>>6==2 && bytes[2]>>6==2 && bytes[3]>>6==2 )
				{
					*buffer = ((*bytes  & 0x07 ) << 18 ) | 
						((bytes[1] & 0x3f) << 12 ) | ((bytes[2] & 0x3f) << 6 ) |(bytes[3] & 0x3f);

					bytes+=4;
					bytes_len -=4;
				}
			}
			else if (  ((*bytes) >> 2) == 62 ) //111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
			{
				if( bytes_len >4 && bytes[1]>>6==2 && bytes[2]>>6==2 && bytes[3]>>6==2 && bytes[4]>>6==2 )
				{
					*buffer = ((*bytes  & 0x03 ) << 24 ) | 
						((bytes[1] & 0x3f) << 18 ) | ((bytes[2] & 0x3f) << 12 ) | ((bytes[3] & 0x3f) << 6 ) |(bytes[4] & 0x3f);

					bytes+=5;
					bytes_len -=5;
				}
			}
			else if (   ((*bytes) >> 1) == 126 ) //1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
			{
				if( bytes_len >5 &&bytes[1]>>6==2 && bytes[2]>>6==2 && bytes[3]>>6==2 && bytes[4]>>6==2 && bytes[5]>>6==2 )
				{
					*buffer = ((*bytes  & 0x03 ) << 30 ) | 
						((bytes[1] & 0x3f) << 24 ) | ((bytes[2] & 0x3f) << 18 ) | ((bytes[3] & 0x3f) << 12 ) |((bytes[3] & 0x3f) << 6 ) |(bytes[5] & 0x3f);

					bytes+=6;
					bytes_len -=6;
				}
			}
			else  //非正常的字节
			{
				if( decode_force ) //强制解码，将该字节直接提升为宽字符
				{
					*buffer = *bytes;

					bytes++;
					bytes_len --;
				}
				else
				{
					return 0;
				}
			}
			buffer++;
			decode_size++;
		}
		return decode_size;
	}

	int code_convert(char *from_charset,char *to_charset,char *inbuf,int inlen,char *outbuf,int outlen)
	{
	  iconv_t cd;
	  char **pin = &inbuf;
	  char **pout = &outbuf;
	  cd = iconv_open(to_charset,from_charset);
	  if (cd==0)
	  {
	           return -1;
	  }

	   memset(outbuf,0,outlen);
	  if ((int)iconv(cd,pin,(size_t *)&inlen,pout,(size_t *)&outlen)==-1)
	  {
	        printf("%s\n", strerror(errno));
	        return outlen;   
	  }
	  
	   iconv_close(cd);    
	   return outlen;    
	} 

	int Mchar(unsigned char *str, char *out)
	{
        int len = 0;
        unsigned char *p = str;
        int i=0;
        while(*p)
        {
            if(*p> 0x81 && *p < 0xFE)
            {
                out[i] = *p;
                out[i + 1] = *(p + 1);

                p += 2;
                len += 2;
                i += 2;
            }
            else
            {
                out[i] = 0x00;
                out[i + 1] = *p;

                p ++;
                len += 2;
                i += 2;
            }
        }

        return len;
	}		

	size_t BKDRHash(const char *str)  
	{  
	    register size_t hash = 0;  
	    while (size_t ch = (size_t)*str++)  
	    {         
	        hash = hash * 131 + ch;   // 也可以乘以31、131、1313、13131、131313..      
	    }  
		
	    return hash;  
	}  

	string MD532(const char *p)
	{
		//MD5 md5;
		//md5.update(p);

		//string str = md5.toString();

		//return str;
		string x;
		return x;
	}
	
	int SplitStrByChar( const string Str, const char ch, vector<string> &StrList)
	{
		if(Str.length() > 4096 * 2)
		{
			return 0;
		}
		
		
    		char*temp = strtok(const_cast<char*>(Str.c_str()),",");
    		while(temp)
    		{
			StrList.push_back(temp);
        		temp = strtok(NULL,",");
    		}
		return StrList.size();
	}

	int commStr(vector<string> vec, string &str)
	{
		string r = "";

		for(vector<string>::iterator it = vec.begin(); it != vec.end(); it ++)
		{
			r += *it;
			r += string(",");
		}
		
		str =r.substr(0, r.length()-1);

		return 0;
	}
	
	//压缩
	/*int Commpress(unsigned char *dest, unsigned long dest_len, const unsigned char *src, unsigned long src_len)
	{
		if(NULL == dest || src == NULL)
		{
			return -1;
		}
		
		int ret = compress(dest, &dest_len, src, src_len);
		if(Z_OK == ret)
		{
			return 0;
		}

		return ret;
	}
	
	//解压
	int UnCommpress(unsigned char *dest, unsigned long dest_len, const unsigned char *src, unsigned long src_len)
	{
		if(NULL == dest || src == NULL)
		{
			return -1;
		}
		
		int ret = uncompress(dest, &dest_len, src, src_len);
		if(Z_OK == ret)
		{
			return 0;
		}
		
		return ret;
	}*/

	int AES_EnCode(const char *src, int len, char* dest, char *key, int key_len)
	{
		if(NULL == src || dest == NULL || NULL == key || key_len != 16)
		{
			return -1;
		}
		
		AES_KEY aes;

		unsigned char iv[16];
		memset(iv,0, sizeof(iv));
		memcpy(iv, "1111111111111111", 16);

		if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
		{
			return -1;
		}

		AES_cbc_encrypt((unsigned char*)src, (unsigned char*)dest, len, &aes, iv, AES_ENCRYPT);

		return 0;
	}

	int AES_Length(int len)
	{
		if(len % 16 == 0)
		{
			return len;
		}
		
		return ((len / 16 + 1) * 16); 
	}	

	int AES_DeCode(const char *src, int len, char* dest, char *key, int key_len)
	{
		if(NULL == src || dest == NULL || NULL == key || key_len != 16)
		{
			return -1;
		}
		
		AES_KEY aes;

		unsigned char iv[16];
		memset(iv,0, sizeof(iv));
		memcpy(iv, "1111111111111111", 16);

		if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
		{
			return -1;
		}

		AES_cbc_encrypt((unsigned char*)src, (unsigned char*)dest, len, &aes, iv, AES_DECRYPT);

		return 0;
	}

	/*//返回加密后长度8的倍数
	int DES3_EnCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len)
	{
		if(src == NULL || dest == NULL || key == NULL || key_len != 24)
		{
			return -1;
		}

		int data_len = len;
		unsigned char iv[8]; 
		memset(iv, 0, sizeof(iv));

		int ulAppend = 0;

		DES_key_schedule ks1;
		DES_key_schedule ks2;
		DES_key_schedule ks3;

		ulAppend = data_len % 8;

		if(ulAppend > 0)
		{
			data_len += (8- ulAppend);  //des加密不够8字节要补够
		}

		DES_set_key((DES_cblock *)key, &ks1);
		DES_set_key((DES_cblock *)(key+8), &ks2);
		DES_set_key((DES_cblock *)(key+16), &ks3);

		DES_ede3_cbc_encrypt(src, dest, data_len, &ks1, &ks2, &ks3, (DES_cblock *)iv, DES_ENCRYPT);

		return data_len;
	}
	
	int DES3_DeCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len)
	{
		if(src == NULL || dest == NULL || key == NULL || key_len != 24)
		{
			return -1;
		}
		
		unsigned char iv[8]; 
		memset(iv, 0, sizeof(iv));

        DES_key_schedule ks1;
        DES_key_schedule ks2;
        DES_key_schedule ks3;

        DES_set_key((DES_cblock *)key, &ks1);
        DES_set_key((DES_cblock *)(key+8), &ks2);
        DES_set_key((DES_cblock *)(key+16), &ks3);

        DES_ede3_cbc_encrypt(src, dest, len, &ks1, &ks2, &ks3, (DES_cblock *)iv, DES_DECRYPT);

		return 0;
	}

	//des加密解密
	int DES_EnCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len)
	{
		if(src == NULL || dest == NULL || key == NULL || key_len != 8)
		{
			return -1;
		}

		DES_key_schedule ks;
        const_DES_cblock deskey;
        DES_cblock  ivec;
        memset(&ivec, 0, sizeof(ivec));

        memcpy((char *)deskey, key, 8);

        DES_set_key_unchecked( &deskey, &ks );

        DES_ncbc_encrypt(src, dest, len, &ks, &ivec, DES_ENCRYPT );

		return 0;
	}
	
	int DES_DeCode(const unsigned char *src, int len, unsigned char* dest, char *key, int key_len)
	{
		if(src == NULL || dest == NULL || key == NULL || key_len != 8)
		{
			return -1;
		}

		DES_key_schedule ks;
        const_DES_cblock deskey;
        DES_cblock  ivec;
        memset(&ivec, 0, sizeof(ivec));

        memcpy((char *)deskey, key, 8);

        DES_set_key_unchecked( &deskey, &ks );

        DES_ncbc_encrypt(src, dest, len, &ks, &ivec, DES_DECRYPT );

		return 0;
	}

	*/

	bool IsNum(std::string str)
	{
		stringstream stream(str);  
    		double d;  
    		char c;  
    		if(!(stream >> d))  
        		return false;  
    		if (stream >> c)  
        		return false;  
    		return true;  
	}  		

	////////////////////////////////////////////////////////////////////////////////////////////////////
	//写文件
	int WriteFile(char* filename, char* content, int len)
	{
		int fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		if(fd < 0)
		{
			return -1;
		}

		int ret = write(fd, content, len);
		if(ret < 0)
		{
			return -1;
		}

		return len;
	}
	
	//读文件,返回文件长度
	int ReadFile(char* filename, string& str)
	{
		struct stat ss;
		if(stat(filename, &ss)<0)
		{
			return 0;
		}

		int file_len = (int)ss.st_size;
		
		int fd = open(filename, O_RDONLY);
		if(fd < 0)
		{
			return -1;
		}

		char *buf = new char[file_len + 1];
		if(buf == NULL)
		{
			return -1;
		}

		memset(buf, 0, file_len + 1);

		int ret = read(fd, buf, file_len);
		if(ret < 0)
		{
			return -1;
		}

		str.assign(buf, file_len);

		delete [] buf;
		buf = NULL;
		
		return file_len;
	}

	string encrypt(string plainText, unsigned char* key)
	{
        	/*unsigned char iv[16];
        	memcpy(iv, "1122abcd3344abcd", 16);

        	string cipherText;
        	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );
        	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( cipherText ));
        	stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length());

        	//stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length() + 1 );
        	stfEncryptor.MessageEnd();

        	return cipherText;
*/
        	/*string cipherTextHex;
          	for( int i = 0; i < (int)cipherText.length(); i++ )
               	{
                                  char ch[3] = {0};
                                                  sprintf(ch, "%02x",  static_cast<unsigned char>(cipherText[i]));
                                                                  cipherTextHex += ch;
                                                                          }
 
                                                                                  return cipherTextHex; */
		string s;
		return s;
	}

	string decrypt(string cipherTextHex, unsigned char* key)
	{
		unsigned char iv[16];
        	memcpy(iv, "1122abcd3344abcd", 16);
		
		//string cipherText;
		string decryptedText;
/*
		CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );
        	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedText ));
		stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cipherTextHex.c_str() ), cipherTextHex.size());
        	stfDecryptor.MessageEnd();
*/
        	return decryptedText;
	}

}



