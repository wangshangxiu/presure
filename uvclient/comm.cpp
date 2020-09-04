#include "comm.h"
#include <chrono>
#include <fstream>
namespace globalFuncation
{
long long GetMicrosecond()
{
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

bool LoadConfig(util::CJsonObject& oConf, const char* strConfFile)
{
    std::ifstream fin(strConfFile);
	//配置信息输入流
	if (fin.good())
	{
		//解析配置信息 JSON格式
		std::stringstream ssContent;
		ssContent << fin.rdbuf();
		if (!oConf.Parse(ssContent.str()))
		{
			//配置文件解析失败
			printf("Read conf (%s) error,it's maybe not a json file!\n",strConfFile);
			ssContent.str("");
			fin.close();
			return false;
		}
		ssContent.str("");
		fin.close();
		return true;
	}
	else
	{
		//配置信息流读取失败
		printf("Open conf (%s) error!\n",strConfFile);
		return false;
	}
}

bool LoadUserInfoFromFile(std::vector<UserInfo>& userInfo, const std::string& strPath)
{
    util::CJsonObject jsonIds;
    if(!LoadConfig(jsonIds, strPath.c_str()))
    {
        printf("load user data error");
        return false;
    }
    int arraySize = jsonIds["RECORDS"].GetArraySize();
    printf("userInfo arraySize(%d)", arraySize);
    for(int i = 0; i < arraySize; i++)
    {
        UserInfo info;
        info.userId = atoll(jsonIds["RECORDS"][i]("id").c_str());//db有
        info.loginSeq = 0;//程序产生
        info.devId = jsonIds["RECORDS"][i]("dev_id"); //设备ID，db有
        info.authToken = jsonIds["RECORDS"][i]("token");//验证token，db有
        info.aesKey;//开始是自己，成功换成服务器生成的
        userInfo.push_back(info);
    }
    return true;
}

void StringSplit(const std::string& strSrc, std::vector<std::string>& vec, char c)
{
	if (strSrc.size() > 0)
	{
		int iPosBegin = 0;
		int iPosEnd = 0;
		for (;;)
		{
			iPosEnd = strSrc.find(c, iPosBegin);
			if (iPosEnd > 0)
			{
				vec.push_back(strSrc.substr(iPosBegin, iPosEnd - iPosBegin));
			}
			else
			{
                vec.push_back(strSrc.substr(iPosBegin, strSrc.size() - iPosBegin));
				break;
			}
			iPosBegin = iPosEnd + 1;
		}
	}
}
};