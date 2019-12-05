package com.im.secure;

/*
 --------------------------------------------**********--------------------------------------------
 该算法于1977年由美国麻省理工学院MIT(Massachusetts Institute of Technology)的Ronal Rivest，Adi Shamir和Len Adleman三位年轻教授提出，并以三人的姓氏Rivest，Shamir和Adlernan命名为RSA算法，是一个支持变长密钥的公共密钥算法，需要加密的文件快的长度也是可变的!
 所谓RSA加密算法，是世界上第一个非对称加密算法，也是数论的第一个实际应用。它的算法如下：
 1.找两个非常大的质数p和q（通常p和q都有155十进制位或都有512十进制位）并计算n=pq，k=(p-1)(q-1)。
 2.将明文编码成整数M，保证M不小于0但是小于n。
 3.任取一个整数e，保证e和k互质，而且e不小于0但是小于k。加密钥匙（称作公钥）是(e, n)。
 4.找到一个整数d，使得ed除以k的余数是1（只要e和n满足上面条件，d肯定存在）。解密钥匙（称作密钥）是(d, n)。
 加密过程： 加密后的编码C等于M的e次方除以n所得的余数。
 解密过程： 解密后的编码N等于C的d次方除以n所得的余数。
 只要e、d和n满足上面给定的条件。M等于N。
 --------------------------------------------**********--------------------------------------------
 */
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


public class RSAUtil {
    public static final String CHAR_ENCODING = "UTF-8";
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
     /** 指定key的大小 2048位 */
    private static int KEYSIZE = 2048;

    /**
     * 生成密钥对
     * @param
     * @return map 公钥私钥信息
     */
    public static Map<String, String> generateKeyPair() throws Exception {
        /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom sr = new SecureRandom();
        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        kpg.initialize(KEYSIZE, sr);
        /** 生成密匙对 */
        KeyPair kp = kpg.generateKeyPair();
        /** 得到公钥 */
        Key publicKey = kp.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String pub = new String(Base64.encodeBase64(publicKeyBytes),
                 CHAR_ENCODING);
        /** 得到私钥 */
        Key privateKey = kp.getPrivate();
        byte[] privateKeyBytes = privateKey.getEncoded();
        String pri = new String(Base64.encodeBase64(privateKeyBytes),
                 CHAR_ENCODING);
        Map<String, String> map = new HashMap<String, String>();
        map.put("publicKey", pub);
        map.put("privateKey", pri);
        RSAPublicKey rsp = (RSAPublicKey) kp.getPublic();
        BigInteger bint = rsp.getModulus();
        byte[] b = bint.toByteArray();
        byte[] deBase64Value = Base64.encodeBase64(b);
        String retValue = new String(deBase64Value);
        map.put("modulus", retValue);
        return map;
    }

    /**
     * 用公钥加密数据
     * @param source 待加密数据
     * @param publicKey 公钥
     * @return result  加密后的base64数据
     */
    public static String encrypt(String source, String publicKey)
            throws Exception {
        Key key = getPublicKey(publicKey);
        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance( RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] b = source.getBytes(CHAR_ENCODING);
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(b);
        return new String(Base64.encodeBase64(b1),
                 CHAR_ENCODING);
    }


    /**
     * 用私钥解密加密数据
     * @param cryptograph 密文
     * @param privateKey 私钥
     * @return
     */
    /**
     * 用私钥解密数据
     * @param cryptograph 待解密数据base64格式
     * @param privateKey 公钥
     * @return result  解密后的数据
     */
    public static String decrypt(String cryptograph, String privateKey)
            throws Exception {
        Key key = getPrivateKey(privateKey);
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance( RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] b1 = Base64.decodeBase64(cryptograph.getBytes());
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(b1);
        return new String(b);
    }

    /**
     * 得到公钥
     * @param key 密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                Base64.decodeBase64(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 得到私钥
     * @param key  密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                Base64.decodeBase64(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 私钥对数据进行签名
     * @param content 待签名数据
     * @param privateKey 私钥
     * @return result  签名后的base64数据
     */
    public static String sign(String content, String privateKey) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(
                    Base64.decodeBase64(privateKey.getBytes()));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initSign(priKey);
            signature.update(content.getBytes(CHAR_ENCODING));
            byte[] signed = signature.sign();
            return new String(Base64.encodeBase64(signed));
        } catch (Exception e) {

        }
        return null;
    }
    /**
     * 检查签名是否一致
     * @param content 解密前的byte数组
     * @param sign    签名
     * @param publicKey 公钥
     * @return result  解密后的byte数组
     * @throws Exception
     */
    public static boolean checkSign(String content, String sign, String publicKey)
    {
        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.decodeBase64(publicKey);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            java.security.Signature signature = java.security.Signature
                    .getInstance("SHA256WithRSA");

            signature.initVerify(pubKey);
            signature.update( content.getBytes(CHAR_ENCODING) );

            boolean bverify = signature.verify( Base64.decodeBase64(sign) );
            return bverify;

        }
        catch (Exception e)
        {
           // log.error(e.getMessage(), e);
        }

        return false;
    }
    // 简单测试例子
    public static void main(String[] args) throws Exception {
        {
            //1.产生公私钥测试
            Map<String, String> keyMap = RSAUtil.generateKeyPair();
            String publicKey = keyMap.get("publicKey");
            String privateKey = keyMap.get("privateKey");
            System.out.println("公钥: \n\r" + publicKey);
            System.out.println("私钥： \n\r" + privateKey);
        }
        {
            //2.加密解密测试2048位
            String publicKey = "";
            String privateKey = "";
            System.out.println("公钥加密——私钥解密1");
            String str = "rsajiami解密测试";
            System.out.println("\r明文：\r\n" + str);
            System.out.println("\r明文大小：\r\n" + str.getBytes().length);
            //公钥
            publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtldiH/7SNqlNB3jbKOHM" +
                    "CEWDWpJtWJUckPqifFX9GVH0t5Qz+s/ivCr0ceJhOcz0VNcVWfLdYQJIblqqJXMt" +
                    "9NN/9AXnHE8OKfVQFG/XKC5jsf1L+oISZdHTaGRCX/M2poIe8rDn7b2GLQHXSPze" +
                    "1RE76EtpYZdWzVQ6y3nW31w+mcERKl4mks+4vvEKX1dGoY1OOL39NT21cimhGP2I" +
                    "sV+ybLzkg+Jus7ewoJSUr+M9fskGvmSXaQs9Hm/9KuOQgCFm2Z9EtwXu69/hlNkf" +
                    "0oNidteioTCGps0D5+A9CRv21S4ivuw6QJ5EE9UAr2O2TC8zVlFwtGffNP5gVZkB" +
                    "QwIDAQAB";
            String encodedData = RSAUtil.encrypt(str, publicKey);  //传入明文和公钥加密,得到密文
            System.out.println("密文：\r\n" + encodedData);
            //私钥
            privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2V2If/tI2qU0H" +
                    "eNso4cwIRYNakm1YlRyQ+qJ8Vf0ZUfS3lDP6z+K8KvRx4mE5zPRU1xVZ8t1hAkhu" +
                    "Wqolcy3003/0BeccTw4p9VAUb9coLmOx/Uv6ghJl0dNoZEJf8zamgh7ysOftvYYt" +
                    "AddI/N7VETvoS2lhl1bNVDrLedbfXD6ZwREqXiaSz7i+8QpfV0ahjU44vf01PbVy" +
                    "KaEY/YixX7JsvOSD4m6zt7CglJSv4z1+yQa+ZJdpCz0eb/0q45CAIWbZn0S3Be7r" +
                    "3+GU2R/Sg2J216KhMIamzQPn4D0JG/bVLiK+7DpAnkQT1QCvY7ZMLzNWUXC0Z980" +
                    "/mBVmQFDAgMBAAECggEBALIicjlhv8oo4ZjwJ+MrnCFkj6u3K14D5nF4ea7QbsAC" +
                    "wflqrtFTsGU17bMofuVx5izQJwrF6iJwkYRFzL1jZb0ttm4WKi8MyICTKJWeoWqe" +
                    "z0S+eTCVTBXuxALTF8kXGQfYTRW5YAtxQRjNGJ40dBlhic4phh0SNXnI1Nud/x4b" +
                    "HzES0KnqilzeymvTzZBDEEj9wZddbBavsQnPr+FLKyO/aRKrGvd2agaWa/fqrnmp" +
                    "h+f0KYYlgBCUk2wkREQq8YFGYS1g/aV8bXHi4FuCYp4WFXPqnwzFQv4TGcLVIRU7" +
                    "jI1zlX/Mzz7snwnx1pcKVU52BrkJSAKp8XiY7V3CGYECgYEA7FLqJrtGQPLtic7t" +
                    "aCJXqQEOzyAjHOVmv/TY1v5TXLEqLOGbZfXIoNAA9tVHgK33Y2btguso9RAttcSt" +
                    "iTm/bky+c2e6/zUghaFjp1Ysl9+yC7sFGWCYMMRCSdi0b0b9P//1W6WRjE/PFuKV" +
                    "QJuArstlgTiLFlpOYnXvxPMLQQMCgYEAxYXd6wbceqQEbcZIFuV9e//17nXK4z0B" +
                    "AO1SKH3KMZIre3eT6Dk5dDViUxKqpuu1vy2CPWpXgaXH3oF2GNsVvZM91ezmInqr" +
                    "sKt5Xh8LF/Zdk+8LzUnGM9hKHuVpb54bhjhKYQmRMKJ59kN5chSkkX1wmhHHjFxS" +
                    "qAsR3KH7qsECgYBKvLYcZaGELM9+g5iFFEdQxWrfijRQkSP7lP12kJvgdo71/qtc" +
                    "hWxbnyyO40hno5zXLNf0TVZ4mhM6puaSvVaTFWYtrSJwT2bnm/CeHRyhMzdlilHE" +
                    "gs3erlKgdA4sGvFAajw4LZZoH11IyYOWGReLL/v779vcx9Z+QPoA+TQX7QKBgQCW" +
                    "tfbGvnx6Iy2x6MnWlpIxi/LFWSFOU5yxbWLzvE8LlcERuwKi/Q7GiXkVc7e8Fzuc" +
                    "vIeUftB3/ttK/jLy8i9bb76NvO03v6vC6IN5emxHg1aRaqLxp2nQ4yZi/p59aQEN" +
                    "X2P5OIiMuFwguAkxL2kGDdVd6VT91u/GgnPFid7xwQKBgGl0Ax2XyDv8kr8oVAd1" +
                    "a53oAXvwFxCbIhBnMVD5BR/YAe7CAGZVMvohrpZ+AiaaU/9apMkvMF/fdMWWidOC" +
                    "L0UyojHWy+sDy6Ph3fJh+aS8jE62bmCsl0IRzcWxrEjObkzFIHHedd0EzeFNNs9S" +
                    "1gOc1ovEomiZn4G6WSLaBmIe";
            String decodedData = RSAUtil.decrypt(encodedData, privateKey); //传入密文和私钥,得到明文
            System.out.println("解密后文字: \r\n" + decodedData);
        }

    }
}