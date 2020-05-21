package com.im.tg;

import com.google.protobuf.ByteString;
//import com.im.secure.HexUtil;
//import com.im.secure.SinglePreKeyMessageProtobuf;
//import com.im.single.*;
//import org.bouncycastle.util.encoders.Base64;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
//import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;
//import org.whispersystems.libsignal.protocol.CiphertextMessage;
//import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.KeyHelper;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;




//1.模式一，一个用户对一个用户（每个用户多个设备，能够获取同样消息；
//1）创建会话和密钥
//2）收发加密消息
//3)更新密钥： 发送100条或密钥时间超过7天则 发起密钥更新
//4）并发更新密钥问题：发起的时间小的为准

public class tg_chattest_one_user_to_one_user {
    private static final SignalProtocolAddress BOB_ADDRESS = new SignalProtocolAddress("userid:1" + "+14151231234", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("userid:2" + "+14159998888", 1);
    private static final SignalProtocolAddress BOB_ADDRESS_2 = new SignalProtocolAddress("userid:1" + "+14151231234", 2);
    private static final SignalProtocolAddress ALICE_ADDRESS_2 = new SignalProtocolAddress("userid:2" + "+14159998888", 2);


    public static void main(String[] args) throws InvalidKeyIdException, InvalidKeyException, LegacyMessageException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, NoSessionException, IOException, ParseException {
        testA_To_B_Demo();

    }


    static void testA_To_B_Demo() throws InvalidKeyIdException, InvalidKeyException, LegacyMessageException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, NoSessionException, IOException, ParseException {

//以A用户和B用户为例：
// 发送创建会话消息 userid，deviceid， 接收者userid， 身份公钥版本，身份公钥，
        //服务端收到后，判断是否会话已存在，已存在则返回相关信息；不存在则产生相关消息进行通知，只通知B用户一个在线设备即可。
        byte recv_encrydata[]=null;
        byte sendEncryptMsg[]=null;
        //1.
        SinglePreKeyMessageProtobuf.SinglePreKeyMessage.Builder sendTopreMsg=null;
        //构造A用户 alice密钥信息
        ECKeyPair ourEinitiatorKeyPair = Curve.generateKeyPair();//临时key
        int registrationId = KeyHelper.generateSenderKeyId();
        int signedPreKeyId = KeyHelper.generateSenderKeyId();
        ECKeyPair ourIdentityKeyPair = Curve.generateKeyPair();//自己的身份密钥和id
        ECKeyPair ourSignedPreKeyPair = Curve.generateKeyPair();//自己的预签名共享密钥和id
        IdentityKey ourIdentityKey = new IdentityKey(ourIdentityKeyPair.getPublicKey());
        UserKey aliceUser = new UserKey((long) 100, registrationId, signedPreKeyId, ourIdentityKeyPair, ourSignedPreKeyPair);
        //B用户bobUser信息：
        //从服务器获取到好友的公共 key相关信息，这里为了测试自造
        ECKeyPair theirSignedPreKeyPair = Curve.generateKeyPair();
        ECKeyPair theirIdentityKeyPair = Curve.generateKeyPair();
        int theirRegistrationId = KeyHelper.generateSenderKeyId();
        int theriSignedPreKeyId = KeyHelper.generateSenderKeyId();
        UserKey bobUser = new UserKey((long) 101, theirRegistrationId, theriSignedPreKeyId, theirIdentityKeyPair, theirSignedPreKeyPair);

        ConcurrentHashMap<Long, UserKey> userKeyMap = new ConcurrentHashMap<Long, UserKey>();
        userKeyMap.put(100L, aliceUser);
        userKeyMap.put(101L, bobUser);
        byte encrydataToB[] = null;
        //2.产生加密密钥
        // master_secret = ECDH ( Iinitiator, Srecipient ) || ECDH ( Einitiator, Irecipient ) || ECDH ( Einitiator, Srecipient )
        //发起者使用 HKDF 算法从 master_secret 创建一个根密钥（Root Key）和链密钥（Chain Keys）
        //A---》B
        {
            theirRegistrationId = registrationId;
            theriSignedPreKeyId = signedPreKeyId;

            byte iv[] = null;
            byte key[] = null;
            byte macKey[]=null;
            byte[][] derivedSecrets = getEncryptKeyIv(ourIdentityKeyPair, ourEinitiatorKeyPair, theirIdentityKeyPair.getPublicKey(), theirSignedPreKeyPair.getPublicKey());
            //协商的加密key
            key = derivedSecrets[0];
            iv = derivedSecrets[1];
            macKey = derivedSecrets[2];

           // System.out.println("src:")

            //加密生成随机key32字节
            byte randKey[] = makeRandom32();
            long oldver=-1;
            long newver=System.currentTimeMillis()/1000;


            SinglePreKeyMessageProtobuf.ShareKeyMessage.Builder shareMsgToB=SinglePreKeyMessageProtobuf.ShareKeyMessage.newBuilder().setSrcUserId(aliceUser.getUserId()).setDstUserId(bobUser.getUserId())
                    .setSrcDeviceId(ByteString.copyFrom("devicetest".getBytes())).setShareKey(ByteString.copyFrom(randKey)).setOldKeyVersion(oldver).setNewKeyVersion(newver) ;


            byte data[] = shareMsgToB.build().toByteArray();

            //加密key和其他数据
            System.out.println("send    text sharekey data:" + HexUtil.encode(randKey));

            encrydataToB = getCipherText(iv, key, data);

           // byte mac[]=HKDF.createFor(3).deriveSecrets(macKey,encrydataToB,32);
            byte mac[]=shaHmacSHA256(macKey,encrydataToB);

            SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS.Builder sharekeyToS=SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS.newBuilder().setVersion(3)
                    .setShareKeyMsgToB(ByteString.copyFrom(encrydataToB) ).setMacKeyToB(ByteString.copyFrom(mac))
                    .setEinitiatorKey(ByteString.copyFrom(ourEinitiatorKeyPair.getPublicKey().serialize()))
                    .setIdentityKey(ByteString.copyFrom(ourIdentityKeyPair.getPublicKey().serialize()))
                    .setOldKeyVersion(oldver).setNewKeyVersion( newver);
            //加入现有协议的消息体中,发送服务端
            // --------------------------------用密钥发送个消息例子：
            String  user_msg="user's messages";
            byte msgs[]=user_msg.getBytes();


            //byte macKeyMsg[]=HKDF.createFor(3).deriveSecrets(randKey,msgs,16);
            System.out.println("randkey:" + HexUtil.encode(randKey)+" msg:"+ HexUtil.encode(msgs));
            byte macKeyMsg[]=shaHmacSHA256(randKey,msgs);

            byte ivMsg[]=new byte[16];
            byte keyMsg[]=new byte[32];

            byte msgMackey16[ ]=new byte[16];
            System.arraycopy(macKeyMsg, 0, msgMackey16, 0, 16);

            byte keyAndIv[]=HKDF.createFor(3).deriveSecrets(randKey,msgMackey16,48);
            System.arraycopy(keyAndIv, 32, ivMsg, 0, 16);
            System.arraycopy(keyAndIv, 0, keyMsg, 0, 32);

            byte aes_datamsg[]   = getCipherText(ivMsg, keyMsg, msgs);

             sendTopreMsg =SinglePreKeyMessageProtobuf.SinglePreKeyMessage.newBuilder().setVersion(3)
                    .setKeyVersion(newver).setSeq(99).setBody(ByteString.copyFrom(aes_datamsg)).setMacKey(ByteString.copyFrom(msgMackey16));
               sendEncryptMsg= sendTopreMsg.build().toByteArray();
//---------------用密钥发送个消息例子 end



 //服务端处理----- //发送给服务端   服务端拆解成发送到A的其他设备  和发送给B的消息
            //服务端进行解析拆分成发送到客户端B的消息包
            SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS sharekeyToS_server=SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS.parseFrom(sharekeyToS.build().toByteArray());
           //产生分发给客户端B用户的数据消息内容
            SinglePreKeyMessageProtobuf.SinglePreKeyMessageTC shareKeyToC__B=SinglePreKeyMessageProtobuf.SinglePreKeyMessageTC.newBuilder().setVersion(sharekeyToS_server.getVersion())
                    .setChainKey(sharekeyToS_server.getShareKeyMsgToB()).setMacKey(sharekeyToS_server.getMacKeyToB()).setOldKeyVersion(sharekeyToS_server.getOldKeyVersion())
                    .setNewKeyVersion(sharekeyToS_server.getNewKeyVersion()).setEinitiatorKey(sharekeyToS_server.getEinitiatorKey()).setIdentityKey(sharekeyToS_server.getIdentityKey()).build();

//B端收到后进行的处理
              recv_encrydata = shareKeyToC__B.toByteArray();
        }
            //产生解密密钥
            //目的用户端
            {
                SinglePreKeyMessageProtobuf.SinglePreKeyMessageTC recv_ToB_Msg= SinglePreKeyMessageProtobuf.SinglePreKeyMessageTC.parseFrom(recv_encrydata);

                byte iv[] = null;
                byte key[] = null;
                byte macKey[]=null;
                //计算加密密钥
                ECPublicKey theirIdentityPublicKey=Curve.decodePoint(recv_ToB_Msg.getIdentityKey().toByteArray(),0);
                 ECPublicKey theirBaseTmpPublicKey=Curve.decodePoint(recv_ToB_Msg.getEinitiatorKey().toByteArray(),0);

                byte key_iv_mac[][]= getDecryptKeyIv(bobUser,theirIdentityPublicKey,theirBaseTmpPublicKey);


                //校验
                macKey=key_iv_mac[2];
                byte mac[]= shaHmacSHA256(macKey,recv_ToB_Msg.getChainKey().toByteArray());//HKDF.createFor(3).deriveSecrets(macKey,recv_ToB_Msg.getChainKey().toByteArray(),32);

               if( Arrays.equals(mac, recv_ToB_Msg.getMacKey().toByteArray()))
               {
                   System.out.println("check mac ok:"+HexUtil.encode(mac)+" a:"+ HexUtil.encode(recv_ToB_Msg.getMacKey().toByteArray()));
               }


                //解密
                byte text[]= getPlainText(key_iv_mac[1],key_iv_mac[0],recv_ToB_Msg.getChainKey().toByteArray());
                SinglePreKeyMessageProtobuf.ShareKeyMessage shareKeyMsg= SinglePreKeyMessageProtobuf.ShareKeyMessage.parseFrom(text);

                byte shareKey[]=shareKeyMsg.getShareKey().toByteArray();
                System.out.println("send    text data:" + HexUtil.encode(shareKeyMsg.getShareKey().toByteArray()));

                //sharekey msg 解析
                System.out.println("send    msg data:sharekey:" + HexUtil.encode(shareKeyMsg.getShareKey().toByteArray())+"oldversion:"+ recv_ToB_Msg.getOldKeyVersion() +" newversion:"+ recv_ToB_Msg.getNewKeyVersion());


                recv_ToB_Msg.getVersion();
                recv_ToB_Msg.getOldKeyVersion();
                recv_ToB_Msg.getNewKeyVersion();
                recv_ToB_Msg.getEinitiatorKey();
                recv_ToB_Msg.getChainKey();
                recv_ToB_Msg.getIdentityKey();
                recv_ToB_Msg.getMacKey();
//解密收到的消息------------------
                //解密 A 用 共享密钥 加密的  消息
                SinglePreKeyMessageProtobuf.SinglePreKeyMessage recvmsg=SinglePreKeyMessageProtobuf.SinglePreKeyMessage.parseFrom(sendEncryptMsg);


                byte ivMsg[]=new byte[16];
                byte keyMsg[]=new byte[32];



                byte keyAndIv[]=HKDF.createFor(3).deriveSecrets(shareKey,recvmsg.getMacKey().toByteArray(),48);
                System.arraycopy(keyAndIv, 32, ivMsg, 0, 16);
                System.arraycopy(keyAndIv, 0, keyMsg, 0, 32);



               // byte ivMsg[]=new byte[16];
               // System.arraycopy(shareKey, 0, ivMsg, 0, 16);
                byte recvtext[]= getPlainText(ivMsg,keyMsg,recvmsg.getBody().toByteArray());


                byte macKeyMsg[]=shaHmacSHA256(shareKey,recvtext);
                byte localMacKey[]=new byte[16];
                System.arraycopy(macKeyMsg, 0, localMacKey, 0, 16);
                System.out.println("randkey:" + HexUtil.encode(shareKey)+" msg:"+ HexUtil.encode(recvtext));
                System.out.println("send mac:"+HexUtil.encode(recvmsg.getMacKey().toByteArray())+" \n   local:"+ HexUtil.encode(localMacKey) );
                System.out.println("recv    msg data::"+new String(recvtext));


            }

    }
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static byte[] makeRandom32( ) {
        try {
            byte[] key = new byte[32];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(key);

            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
       static private int randomInt() {
            try {
                return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError(e);
            }
        }
        //获取端对端协商密钥key
       static  byte[][] getDecryptKeyIv(UserKey user, ECPublicKey theirIdentityPublicKey, ECPublicKey theirBaseTmpPublicKey) throws InvalidKeyException, IOException, ParseException {

            ByteArrayOutputStream secretsRecv = new ByteArrayOutputStream();
            secretsRecv.write(Curve.calculateAgreement(theirIdentityPublicKey, user.signedPreKeyPair.getPrivateKey()
            ));
            secretsRecv.write(Curve.calculateAgreement(theirBaseTmpPublicKey ,
                    user.identityKeyPair.getPrivateKey() ));
            secretsRecv.write(Curve.calculateAgreement(theirBaseTmpPublicKey,
                    user.signedPreKeyPair.getPrivateKey() ));

            HKDF kdf = new HKDFv3();
            byte[] derivedSecretBytes = kdf.deriveSecrets(secretsRecv.toByteArray(), "WhisperText".getBytes(), 80);
            byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16,32);
            //协商的加密key
           // byte[] shareEncryptKeyRecv = derivedSecrets[0];
            return derivedSecrets;
        }


        static byte[] shaHmacSHA256(byte[] key, byte[] inputKeyMaterial)
        {

            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
                return mac.doFinal(inputKeyMaterial);
            } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
                throw new AssertionError(e);
            }


        }
    //获取端对端协商密钥key
   static byte[][] getEncryptKeyIv(  ECKeyPair ourIdentityKeyPair,  ECKeyPair ourEinitiatorKeyPair, ECPublicKey theirIdentityKeyPublic, ECPublicKey theirSignedPreKeyPublic ) throws InvalidKeyException, IOException, ParseException {
        //产生加密本次消息的密钥
        ByteArrayOutputStream secrets = new ByteArrayOutputStream();
        //secrets.write(getDiscontinuityBytes());
        secrets.write(Curve.calculateAgreement(theirSignedPreKeyPublic, ourIdentityKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPublic , ourEinitiatorKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirSignedPreKeyPublic , ourEinitiatorKeyPair.getPrivateKey()));


        HKDF kdf = new HKDFv3();
        byte[] derivedSecretBytes = kdf.deriveSecrets(secrets.toByteArray(), "WhisperText".getBytes(), 80);
        byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16,32);

        return derivedSecrets;
    }

        //aes解密函数
       static private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
                throws InvalidMessageException
        {
            try {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                Cipher cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);

                return cipher.doFinal(ciphertext);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
                    InvalidAlgorithmParameterException e)
            {
                throw new AssertionError(e);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new InvalidMessageException(e);
            }
        }

        //aes加密
       public   static  byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
            try {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                Cipher cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);
                return cipher.doFinal(plaintext);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                    IllegalBlockSizeException | BadPaddingException | java.security.InvalidKeyException e)
            {
                throw new AssertionError(e);
            }
        }










}
