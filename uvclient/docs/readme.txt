----压测客户端目录结构----
1.include 第三方库头文件目录
2.lib      第三方库 .so文件目录
3.conf     配置文件目录, 密钥文件或压测用户表
4.pb       protobuf 通讯协议源码子目录 
5.encrypt  加解密 二次封装源码目录
6.CMakeList.txt 主目录的CMake构建文件
7.*.h *.hpp *.cc *.cpp *c  源码
8.cmake-build-debug cmake  集中构建临时目录
9.buffer  环形队列github代码
10.unix   linux下的一些特征函数
11.logger log4cplus封装
12.json   json解析库
13.pack   业务请求、应答函数
14.log    程序日志
15.docs   文档目录

-----工程构建步骤-------
1、cd /app/uvclient  进到压测客户端目录
2、mkdir cmake-build-debug && cd cmake-build-debug
3、cmake ..
4、cd -
5、make -C cmake-build-debug
最后会在工程目录下产生可执行的presureClient
如果要重新构建可以删除cmake-build-debug ,重新从步骤<2>开始

cmake构建多目录源码工程参考
http://blog.chinaunix.net/uid-30512847-id-5775284.html

---------------生产数据-------
生产数据程序编译
g++ productTestData.cpp -o productTestData -std=c++11
生成可执行程序后运行
[root@im-msg-test-32 data]# ./productTestData 450000(样本数据量)
生成对应的文件
id.csv ：id, dev_id, token（用户登录的基本信息)
id.csv会被导导数据库，然后再以JSON方式导出来给程序当样本数据
//
ins_redis_data.txt: //hset 1:1:im:token::deviceid:5EDF8352-7BB2-4A8A-9BE4-812F1F053C2B  1275006717478846466 5EDF8352-7BB2-4A8A-9BE4-812F1F053C2B //设置登录token ,hash结构到redis
set_0_redis_data.txt://hset 1:2:im:status:userid:1275006717478846466 loginseq:5EDF8352-7BB2-4A8A-9BE4-812F1F053C2B 0 //把登录态的loginSeq归零,方便下次登录，应对程序没对loginseq++的情况
//通过这种方式使用上边两个和redis数据相关的文件
cat set_0_redis_data.txt | redis-cli -h 10.3.0.65 -p 19000 -a rxLt2bdQAyf9E  --pipe  （这回管道操作redis)

--------运行工具--------
在工程目录下运行程序，即可建立多连接, 并且能登录，保持在线
[root@im2 uvclient]# ./presureClient iplist port cfgfile (示例：./presureClient 192.168.11.70:192.168.11.72:192.168.11.73:192.168.11.74:192.168.11.75 27010 ./conf/client.conf)

-----------------在多个文件种分组求和QPS---------
awk -F"|" '{a[$2]+=$3;b[$2]+=$8;c[$2]+=$9}END{for(i in a)print i, a[i],b[i],c[i]}' qps/presureClient_* | sort -k1n




