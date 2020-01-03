#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>  
#include <stdlib.h>
#include "my_config.h"
#include "my_utility.h"
#include <string.h>


  TQueue<LoginAuthTask*> g_queueIdle;//空闲人员队列

CMyConfig::CMyConfig()
{
	m_map.clear();
}

int CMyConfig::ReadConfig(const char *root_dir_filename)
{
	FILE *pstFile;	
	char szBuffer[4096] = {0};	
	char* pszTemp;	

	string path_conf = string(root_dir_filename)  ;
	
	if((pstFile = fopen(path_conf.c_str(), "r")) == NULL)	
	{		
		return -1;	
	}
	
	while(fgets(szBuffer, sizeof(szBuffer), pstFile) != NULL)	
	{		
		szBuffer[strlen(szBuffer)-1] = '\0'; 		
		pszTemp = strstr(szBuffer, "=");		
		if(pszTemp == NULL)
		{			
			memset(szBuffer, 0, sizeof(szBuffer));			
			continue;		
		}		
		*pszTemp='\0';		
		pszTemp ++;
		
		//清除空格
		MYU::trimLeft(szBuffer);
		MYU::trimRight(szBuffer);
		MYU::trimLeft(pszTemp);
		MYU::trimRight(pszTemp);

		//printf("key=%s, value=%s, %d\n", szBuffer, pszTemp, (int)strlen(pszTemp));
		m_map[szBuffer] = pszTemp;		
		memset(szBuffer, 0, sizeof(szBuffer));	
	}	

	fclose(pstFile);

	return 0;
}//userid,token,deviceid
int CMyConfig::ReadUserList(const char* path_file)
{
	FILE *pstFile;
	char szBuffer[512] = { 0 };
	char* pszTemp;

	if ((pstFile = fopen(path_file, "r")) == NULL)
	{
		return -1;
	}

	while (fgets(szBuffer, sizeof(szBuffer), pstFile) != NULL)
	{
		szBuffer[strlen(szBuffer) - 1] = '\0';
		 
		 
		pszTemp++;
		char*pLineBuf = (char*)szBuffer;

		char*pNext = strsep(&pLineBuf, ",");
		LoginAuthTask *pTask = new LoginAuthTask();
		int i = 0;
		//userid,token,deviceid
		while (pNext != NULL)
		{
			switch (i )
			{
				case 0://userid
					pTask->m_uUserID = atol(pNext);
					break;
				case 1:
					pTask->m_strToken =  pNext ;
					break;
				case 2:
					pTask->m_strDeviceID = pNext;
					break;
			default:
				break;
			}
			i++;
			 
			printf("%s\n", pNext);
			pNext = strsep(&pLineBuf, ",");
		}
		//清除空格
		 
 
		g_queueIdle.push(pTask);

		//printf("key=%s, value=%s, %d\n", szBuffer, pszTemp, (int)strlen(pszTemp));
		m_map[szBuffer] = pszTemp;
		memset(szBuffer, 0, sizeof(szBuffer));
	}

	fclose(pstFile);

	return 0;



}
int CMyConfig::ReadConfigFile(const char *filename)
{
	FILE *pstFile;	
	char szBuffer[512] = {0};	
	char* pszTemp;	
	
	if((pstFile = fopen(filename, "r")) == NULL)	
	{		
		return -1;	
	}
	
	while(fgets(szBuffer, sizeof(szBuffer), pstFile) != NULL)	
	{		
		szBuffer[strlen(szBuffer)-1] = '\0'; 		
		pszTemp = strstr(szBuffer, "=");		
		if(pszTemp == NULL)
		{			
			memset(szBuffer, 0, sizeof(szBuffer));			
			continue;		
		}		
		*pszTemp='\0';		
		pszTemp ++;
		
		//清除空格
		MYU::trimLeft(szBuffer);
		MYU::trimRight(szBuffer);
		MYU::trimLeft(pszTemp);
		MYU::trimRight(pszTemp);

		//printf("key=%s, value=%s, %d\n", szBuffer, pszTemp, (int)strlen(pszTemp));
		m_map[szBuffer] = pszTemp;		
		memset(szBuffer, 0, sizeof(szBuffer));	
	}	

	fclose(pstFile);

	return 0;
}

string CMyConfig::GetValueByKey(const char *key)
{
	map<string, string>::iterator it;
	it = m_map.find(string(key));

	if(it == m_map.end())
	{
		return string("");
	}

	return it->second;
}


void CMyConfig::SetValueByKey(const char *root_dir, const char *key, const char* value)
{
	string path_conf = string(root_dir)  ;
	
	//replace	
	FILE *pstFile;
	
	struct stat tbuf;
    	stat(path_conf.c_str(), &tbuf);
	
    	long file_size = tbuf.st_size;
	
	char* buf = new char[file_size + 1];
	if(buf == NULL)
	{
		return ;
	}

	memset(buf, 0, file_size);	

        if((pstFile = fopen(path_conf.c_str(), "r")) == NULL)
        {
		delete [] buf;
		buf = NULL;
                return ;
        }

	int result = fread(buf, 1, file_size, pstFile);	
	if(result != file_size)
	{
		delete [] buf;
                buf = NULL;
		return ;
	}

	fclose(pstFile);
	//replace
	char *p = strstr(buf, key);
	if(p == NULL)
	{
		delete [] buf;
                buf = NULL;
		return ;
	}

	p += strlen(key);
	p ++;
	*p = *value;

	//write
	if((pstFile = fopen(path_conf.c_str(), "w")) == NULL)
        {
		delete [] buf;
                buf = NULL;
	
                return ;
        }

	fwrite(buf, 1, file_size, pstFile);

	fclose(pstFile);
	
	delete [] buf;
        buf = NULL;
}

