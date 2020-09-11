#include "comm.h"
#include <chrono>
#include <iostream>
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

bool LoadUserInfoFromJsonFile(std::vector<UserInfo>& userInfo, const std::string& strPath)
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

//@param offset 需要根据本进程smpleSize样本大小，以及开启的io thread所分配到的线程序号，以及多少个客户端在协同工作计算所得；
//offset = smpleSize*clientNo + threadIndex*(smpleSize/threadNum), 样本数据是从offset开始的，包含offset位置那条
bool LoadUserInfoFromCVSFile(std::vector<UserInfo>& userInfo, const std::string& strPath, int offset, int smpleSize)
{
	//ios_base
	//	ios
	// 		istream				
	//			ifstream
	// 			istringstream
	//		ostream				
	//			ofstream
	//			ostringstream
	//		[istream, ostream]	
	// 			iostream
	//				stringstream
	// 				fstream
    // 读文件  
    std::ifstream inFile(strPath.c_str(), std::ios::in); //./data/id.cvs
    std::string lineStr;  
    // std::vector<std::vector<std::string>> strArray;  
	// istream& getline (istream& is, string& str, char delim);
	// istream& getline (istream& is, string& str);
	int lineCounter = 0;
    while (std::getline(inFile, lineStr) && ((offset + smpleSize) > lineCounter))  
    {  
		lineCounter++;
		if(offset > lineCounter)
		{
			continue;
		}
        // 打印整行字符串  
        std::cout << lineStr << " " << lineCounter << std::endl;  
        // 存成二维表结构  
        std::stringstream ss(lineStr);  
        std::string str;  
        std::vector<std::string> lineArray; //cvs读出来的三个字段
        // 按照逗号分隔  
        while (std::getline(ss, str, ','))
		{
			lineArray.push_back(str); 
		}  

		UserInfo info;
        info.userId = atoll(lineArray[0].c_str());//db有
        info.loginSeq = 0;//程序产生
        info.devId = lineArray[1]; //设备ID，db有
        info.authToken = lineArray[2];//验证token，db有
        info.aesKey;//开始是自己，成功换成服务器生成的
        userInfo.push_back(info);
		
        // strArray.push_back(lineArray);  
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