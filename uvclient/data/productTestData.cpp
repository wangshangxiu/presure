#include<fstream>
#include <iostream>
#include <chrono>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
//#define RUNTIMES (256*1000)
#define RUNTIMES (10*1000)
//毫秒级时间戳id
inline unsigned long long GetUniqueId_MS(unsigned short uiNodeId, unsigned char ucWorkerIndex)
{
    //1bit未使用（可以兼容64位整形）  41bit作为毫秒数，14bit作为机器的ID（8个bit是节点，6个bit的工作者id），8bit作为流水号
    const unsigned long long ullSequenceBit =              0x00FF;//8bit 256 ullSequenceBit
    const unsigned long long ullWorkerIndexBit =         0x003F00;//6bit 64 ucWorkerIndex
    const unsigned long long ullNodeIndexBit =         0x003FC000;//8bit 256 uiNodeId
    const unsigned long long ullTimeIndexBit = 0x7FFFFFFFFFC00000;//41bit 2199023255552 ullTime

    static unsigned int uiSequence = 0;
    std::chrono::microseconds timeNow = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());
    unsigned long long ullTime = timeNow.count();
    //1579155560156
    //2199023255552
    ++uiSequence;
    uiSequence &= ullSequenceBit;
    //1bit  41 bit   8 bit 6 bit 8bit
    //1   2199023255552    256   128   256(0xFFFF)
    unsigned long long ullUniqueId = ((unsigned long long)(ullTime << 22) & ullTimeIndexBit) | \
                         ((unsigned long long)(uiNodeId << 14) & ullNodeIndexBit) | ((unsigned long long)(ucWorkerIndex << 8) & ullWorkerIndexBit) | \
                         ((unsigned long long)(uiSequence) & ullSequenceBit);
    return ullUniqueId;
}

std::string GetRandStr(unsigned int size, bool format = false)                                                                                                           
{       
    if (size > 128) size = 128;//限制最大长度
    std::string s;
    for(unsigned int i= 0; i< size; i++)
    {   
             char ch(0);
             int num = rand()%3;
             if(num == 0)
                     ch = static_cast<char>('0' + rand()%('9'-'0'+1));//getDigit
             else if(num == 1)
                     ch = static_cast<char>('a' + rand()%('z'-'a'+1));//getLower
             else
                     ch = static_cast<char>('A' + rand()%('Z'-'A'+1));//getUpper
             s.push_back(ch);
        
             if(format && (s.size()%7 >= 6) && i%2 != 0)
             {
                s.push_back('-');
             }
         
             
    }       
    return s;
}  

#if 1
int main(int argc, char* argv[])
{
    if(argc < 2) 
    {
        printf("parameters too few..., usage: %s smpleNums(10000)\n", argv[0]);
        return 0;   

    }
    srand(time(nullptr));
    unsigned long long timeNow = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    struct stat buf;
    bool bcsvExist = false;
    if(stat("./ id.csv", &buf) ==0)
    {
        bcsvExist = true;
        printf("file  id.csv exist\n");
    }
    std::ofstream csvFile("./ id.csv" , std::ios::out| std::ios::app);
    std::ofstream insRedisDataFile("./ins_redis_data.txt", std::ios::out | std::ios::app);
    std::ofstream set0RedisDataFile("./set_0_redis_data.txt", std::ios::out | std::ios::app);
    if(!bcsvExist)
    {
        csvFile << "id, dev_id, token" << "\n";
    }
#if 1
    for(int i = 0 ; i < atoi(argv[1]); i++)
    {
       unsigned long long id =  GetUniqueId_MS(254, 64);
       std::string stRand = GetRandStr(32, true);
    
       char csvBuf[128] = {0};
       snprintf(csvBuf, sizeof(csvBuf), "%ld, %s, %s", id, stRand.c_str(), stRand.c_str());

       //hset 1:1:im:token::deviceid:5EDF8352-7BB2-4A8A-9BE4-812F1F053C2B  1275006717478846466 5EDF8352-7BB2-4A8A-9BE4-812F1F053C2B //设置登录token ,hash结构
       char insRedisBuf[256] ={0};
       snprintf(insRedisBuf, sizeof(insRedisBuf), "hset 1:1:im:token:deviceid:%s %ld %s", stRand.c_str(), id,  stRand.c_str());
       

       //hset 1:2:im:status:userid:1275006717478846466 loginseq:5EDF8352-7BB2-4A8A-9BE4-812F1F053C2B 0 //把登录态的loginSeq归零
       char set0Buf[256] ={0};
       snprintf(set0Buf, sizeof(set0Buf), "hset 1:2:im:status:userid:%ld loginseq:%s 0", id, stRand.c_str());

       std::cout << csvBuf << std::endl;
       std::cout << insRedisBuf << std::endl;
       std::cout <<set0Buf << std::endl; 
       
       csvFile << csvBuf << "\n";
       insRedisDataFile << insRedisBuf << "\r\n";
       set0RedisDataFile << set0Buf<< "\r\n";

       memset(csvBuf, 0 ,sizeof(csvBuf));
       memset(set0Buf, 0 ,sizeof(set0Buf));
       memset(insRedisBuf, 0 ,sizeof(insRedisBuf));
    }
#endif
    csvFile.close();
    insRedisDataFile.close();
    set0RedisDataFile.close();

    unsigned long long timeEnd= std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::cout << "Hello world" << std::endl;
    std::cout << "Run cost time: ("<< (timeEnd - timeNow) << ")" << std::endl;
    
    return 0;
}
#endif
