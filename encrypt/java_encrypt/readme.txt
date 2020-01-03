
1.AES256加密：
1)环境配置
此处加密的key是smkldospdosldaaa，如果修改为32位或者更高位的的将会报java.security.InvalidKeyException: Illegal key size
解决办法：
下载对应的jar文件替换原有的，
jdk1.8的http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html。
其他版本的与之类似，下载好后解压，主要用到local_policy.jar和US_export_policy.jar，将其复制到JAVA_HOME下的\jre\lib\security中替换，即可

2)加密验证：aes256/cbc/pad5
验证网址：
http://www.ssleye.com/aes_cipher.html
目前在整理java的加密组件，ecdh选择的是 libsignal，做了部分测试； 到目前刚整好aes256，这个碰到点问题来，java默认支持的是128的；正在整rsa2048的。

2.RSA2048位：RSA/ECB/PKCS1Padding
参照代码例子可以加密/解密/签名/生成公钥对

3.libsignal签名ecdh库
安卓使用:

dependencies {
  compile 'org.whispersystems:signal-protocol-android:(latest version number)'
}
java程序：

<dependency>
  <groupId>org.whispersystems</groupId>
  <artifactId>signal-protocol-java</artifactId>
  <version>2.3.0</version>
</dependency>

rsa加密解密
http://tool.chacuo.net/cryptrsaprikey