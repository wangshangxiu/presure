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
2、mkdir cmake_build_debug && cd cmake_build_debug
3、cmake ..
4、cd -
5、make -C cmake_build_debug
最后会在工程目录下产生可执行的presureClient
如果要重新构建可以删除cmake_build_debug,重新从步骤<2>开始

cmake构建多目录源码工程参考
http://blog.chinaunix.net/uid-30512847-id-5775284.html

--------运行工具--------
在工程目录下运行程序，即可建立多连接, 并且能登录，保持在线
[root@im2 uvclient]# ./presureClient iplist port cfgfile (示例：./presureClient 192.168.11.70:192.168.11.72:192.168.11.73:192.168.11.74:192.168.11.75 27010 ./conf/client.conf)





