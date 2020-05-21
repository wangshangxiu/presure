package com.im.single;

import com.google.protobuf.ByteString;
import com.im.secure.HexUtil;
import com.im.secure.SinglePreKeyMessageProtobuf;
import org.bouncycastle.util.encoders.Base64;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.Hex;
import org.whispersystems.libsignal.util.KeyHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.rmi.CORBA.Util;
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
private static int PROTOCOL_VERSION=3;

    public static void main(String[] args) throws InvalidKeyIdException, InvalidKeyException, LegacyMessageException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, NoSessionException, IOException, ParseException {


        testA_To_B_Demo();

    }


    static void testA_To_B_Demo() throws InvalidKeyIdException, InvalidKeyException, LegacyMessageException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, NoSessionException, IOException, ParseException {

//以A用户和B用户为例： 创建会话密钥协商； 发送端对端加密消息； 更新密钥

        //服务端收到后，判断是否会话已存在，已存在则返回相关信息；不存在则产生相关消息进行通知，只通知B用户一个在线设备即可。
        byte recv_encrydata[]=null;
        byte sendEncryptMsg[]=null;
        //1.
        SinglePreKeyMessageProtobuf.SinglePreKeyMessage.Builder sendTopreMsg=null;//发送给b的消息
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
            byte iv[] = null;
            byte key[] = null;
            byte macKey[]=null;
            //根据双方密钥key和自己生成临时密钥对 和 dh 算法产生协商密钥加密key
            byte[][] derivedSecrets = getShareEcdhKeyIvMac(ourIdentityKeyPair, ourEinitiatorKeyPair, theirIdentityKeyPair.getPublicKey(), theirSignedPreKeyPair.getPublicKey());
            //协商的加密key
            key = derivedSecrets[0];
            iv = derivedSecrets[1];
            macKey = derivedSecrets[2];

            //加密生成随机key32字节 作为端对端消息加密的种子
            byte randKey[] = makeRandom32();
            long oldver=-1;
            long newver=System.currentTimeMillis()/1000;


            SinglePreKeyMessageProtobuf.ShareKeyMessage.Builder shareMsgToB=SinglePreKeyMessageProtobuf.ShareKeyMessage.newBuilder().setSrcUserId(aliceUser.getUserId()).setDstUserId(bobUser.getUserId())
                    .setSrcDeviceId(ByteString.copyFrom("devicetest".getBytes())).setShareKey(ByteString.copyFrom(randKey)).setOldKeyVersion(oldver).setNewKeyVersion(newver) ;

            //传送密钥消息
            byte data[] = shareMsgToB.build().toByteArray();

            //加密key和其他数据
            System.out.println("send    text sharekey data:" + HexUtil.encode(randKey));

            encrydataToB = getCipherText(iv, key, data);//用ecdh 共享密钥进行aes加密数据： 端对端消息密钥

            byte mac[]=HKDF.createFor(PROTOCOL_VERSION).deriveSecrets(macKey,encrydataToB,32);//把加密数据生成 mac 验证码
            //打包产生给服务器的加密密钥，进行更新密钥
            SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS.Builder sharekeyToS=SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS.newBuilder().setVersion(PROTOCOL_VERSION)
                    .setShareKeyMsgToB(ByteString.copyFrom(encrydataToB) ).setMacKeyToB(ByteString.copyFrom(mac))
                    .setEinitiatorKey(ByteString.copyFrom(ourEinitiatorKeyPair.getPublicKey().serialize()))
                    .setIdentityKey(ByteString.copyFrom(ourIdentityKeyPair.getPublicKey().serialize()))
                    .setOldKeyVersion(oldver).setNewKeyVersion( newver);
            //加入现有协议的消息体中,发送服务端
//用密钥发送个消息
            //用密钥发送个消息例子：
            String  user_msg="user's messages";
            byte msgs[]=user_msg.getBytes();
            byte macKeyMsg[]=HKDF.createFor(3).deriveSecrets(randKey,msgs,32);
            byte ivMsg[]=new byte[16];
            System.arraycopy(randKey, 0, ivMsg, 0, 16);
            byte datamsg[]   = getCipherText(ivMsg, randKey, msgs);

             sendTopreMsg =SinglePreKeyMessageProtobuf.SinglePreKeyMessage.newBuilder().setVersion(3)
                    .setKeyVersion(newver).setSeq(99).setBody(ByteString.copyFrom(datamsg)).setMacKey(ByteString.copyFrom(macKeyMsg));
               sendEncryptMsg= sendTopreMsg.build().toByteArray();

 //服务端处理----- //1.发送给服务端   服务端拆解成发送到A的其他设备  和发送给B的消息
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
                byte mac[]=HKDF.createFor(3).deriveSecrets(macKey,recv_ToB_Msg.getChainKey().toByteArray(),32);

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

                //解密 A 用 共享密钥 加密的  消息
                SinglePreKeyMessageProtobuf.SinglePreKeyMessage recvmsg=SinglePreKeyMessageProtobuf.SinglePreKeyMessage.parseFrom(sendEncryptMsg);
                byte ivMsg[]=new byte[16];
                System.arraycopy(shareKey, 0, ivMsg, 0, 16);
                byte recvtext[]= getPlainText(ivMsg,shareKey,recvmsg.getBody().toByteArray());
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
                    user.identityKeyPair.getPrivateKey() ));

            HKDF kdf = new HKDFv3();
            byte[] derivedSecretBytes = kdf.deriveSecrets(secretsRecv.toByteArray(), "WhisperText".getBytes(), 80);
            byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16,32);
            //协商的加密key
           // byte[] shareEncryptKeyRecv = derivedSecrets[0];
            return derivedSecrets;
        }
    //获取端对端协商密钥key
   static byte[][] getShareEcdhKeyIvMac(  ECKeyPair ourIdentityKeyPair,  ECKeyPair ourEinitiatorKeyPair, ECPublicKey theirIdentityKeyPublic, ECPublicKey theirSignedPreKeyPublic ) throws InvalidKeyException, IOException, ParseException {
        //产生加密本次消息的密钥
        ByteArrayOutputStream secrets = new ByteArrayOutputStream();
        //secrets.write(getDiscontinuityBytes());
        secrets.write(Curve.calculateAgreement(theirSignedPreKeyPublic, ourIdentityKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPublic , ourEinitiatorKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPublic , ourEinitiatorKeyPair.getPrivateKey()));
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

        //测试用户
        private static final SignalProtocolAddress SENDER_ADDRESS = new SignalProtocolAddress("+13266838001", 1);
        private static final SenderKeyName SENDER_1   = new SenderKeyName("sessionid1001_1002" , SENDER_ADDRESS);
        //同一用户的其他设备
        private static final SignalProtocolAddress SENDER_ADDRESS1 = new SignalProtocolAddress("+13266838001", 2);
        private static final SenderKeyName SENDER_1_1   = new SenderKeyName("sessionid1001_1002" , SENDER_ADDRESS1);
        //群成员数
        private static final int  GroupMaxNum =2;
        public void testGroupEncryptOneDeviceOneKeyAll() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException, InvalidKeyException, IOException, InvalidVersionException, InvalidKeyIdException {
            //1.
            //构造测试数据
        //发起端密钥数据
            ECKeyPair ourEinitiatorKeyPair = Curve.generateKeyPair();//临时key
            int registrationId = KeyHelper.generateSenderKeyId();
            int signedPreKeyId = KeyHelper.generateSenderKeyId();
            ECKeyPair ourIdentityKeyPair = Curve.generateKeyPair();//自己的身份密钥和id
            ECKeyPair ourSignedPreKeyPair = Curve.generateKeyPair();//自己的预签名共享密钥和id
            IdentityKey ourIdentityKey=new IdentityKey(ourIdentityKeyPair.getPublicKey());


            //SingleChatSession( String name , int deviceId,UserKey self, UserKey their)；

            UserKey aliceUser= new UserKey((long) 100, registrationId,   signedPreKeyId, ourIdentityKeyPair,    ourSignedPreKeyPair);


            //从服务器获取到好友的key相关信息，这里为了测试自造
            ECKeyPair theirSignedPreKeyPair = Curve.generateKeyPair();
            ECKeyPair theirIdentityKeyPair = Curve.generateKeyPair();
            int theirRegistrationId = KeyHelper.generateSenderKeyId();
            int theriSignedPreKeyId = KeyHelper.generateSenderKeyId();


            UserKey bobUser= new UserKey((long) 101, theirRegistrationId,   theriSignedPreKeyId, theirIdentityKeyPair,    theirSignedPreKeyPair);



            ConcurrentHashMap<Long,  UserKey> userKeyMap =new ConcurrentHashMap<Long,  UserKey>();
            userKeyMap.put(100L,aliceUser);
            userKeyMap.put(101L,bobUser);


            /*
             *创建2个用户例子 alice和bob 和他们的密钥
             */

//            UserEntity alice = new UserEntity(  "userid:1:alice",1);
//            UserEntity alice1 = new UserEntity(  alice.getOtherKeyBundle().getRegistrationId(), alice.getStore().getIdentityKeyPair(),
//                    alice.getOtherKeyBundle().getPreKeyId(),alice.getStore().loadPreKey(alice.getOtherKeyBundle().getPreKeyId()).getKeyPair(),
//                    alice.getOtherKeyBundle().getSignedPreKeyId(), alice.getStore().loadSignedPreKey(alice.getOtherKeyBundle().getSignedPreKeyId() ).getKeyPair(),
//                    "userid:1:alice", 2);
//            UserEntity bob = new UserEntity(  "userid:2:bob",1);
//            UserEntity bob1 = new UserEntity(  bob.getOtherKeyBundle().getRegistrationId(), bob.getStore().getIdentityKeyPair(),
//                    bob.getOtherKeyBundle().getPreKeyId(),bob.getStore().loadPreKey(bob.getOtherKeyBundle().getPreKeyId()).getKeyPair(),
//                    bob.getOtherKeyBundle().getSignedPreKeyId(), bob.getStore().loadSignedPreKey(bob.getOtherKeyBundle().getSignedPreKeyId() ).getKeyPair(),
//                    "userid:2:bob", 2);

            // 2.发送加密密钥 给服务器  长连接或短链接都可以

//            InMemorySenderKeyStore aliceStore = new   InMemorySenderKeyStore();
//            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
//            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, SENDER_1);

            SingleChatSession aliceSession1 = new SingleChatSession( "13266838001", 1001, aliceUser,bobUser);
            SenderKeyDistributionMessage aliceSentDistributionMessage=aliceSession1.createOrLoad();//aliceSession1.getSelfSenderKeyName()
            //测试自己的另外一个设备 可删
            SingleChatSession aliceSession11 = new SingleChatSession( "13266838001", 10011, aliceUser,bobUser);
//             InMemorySenderKeyStore aliceStore1 = new  InMemorySenderKeyStore();
//            GroupSessionBuilder aliceSessionBuilder1 = new GroupSessionBuilder(aliceStore1);
//            GroupCipher aliceGroupCipher1 = new GroupCipher(aliceStore1, SENDER_1_1);
//            SenderKeyDistributionMessage sentAliceDistributionMessage1     = aliceSessionBuilder1.create(SENDER_1_1);//产生群发送消息密钥



            byte[][] arraySendData1=new byte[2005][];
            for(int z=0; z<2005; z++) {
                arraySendData1[z] = aliceSession1.encrypt(("devic1 msg:"+z+"test group smert ze smert").getBytes());//aliceGroupCipher1.encrypt(("devic1 msg:"+z+"test group smert ze smert").getBytes());

            }

            //3.本地是否有加密信息，没有则产生；//Alice 产生 发消息密钥 给服务端，服务端如果已经有了，则需要返回，且替换掉本地。
            //SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(SENDER_1);//产生群发送消息密钥
            GroupSenderKeyDistributionMessage selfGroupSenderKeyDistributionMessage=new GroupSenderKeyDistributionMessage(aliceSentDistributionMessage.getId(),
                    aliceSentDistributionMessage.getIteration(),aliceSentDistributionMessage.getChainKey(), aliceSentDistributionMessage.getSignatureKey(),
                    aliceSession1.getSenderKeyStore().loadSenderKey( aliceSession1.getSelfSenderKeyName()).getSenderKeyState( aliceSentDistributionMessage.getId()).getSigningKeyPrivate());

            System.out.println("group key id:"+ aliceSentDistributionMessage.getId()+" key:"+ Base64.toBase64String(aliceSentDistributionMessage.getChainKey()));

//--------------------发送端发送消息------------
//发送/收取消息
            //Alice 发送群消息
            byte[][] arraySendData=new byte[20][];
            for(int z=0; z<20; z++) {
                arraySendData[z] = aliceSession1.encrypt(("msg:"+z+"test group smert ze smert").getBytes());

            }
//---------------------end
            //4.打包后发送给服务端；服务端如果有了，则返回已有的key消息;解密后使用，且保存本地。
            //5.加密发送给服务端 所有现有 成员密钥

            GroupPreKeySignalMessageToServer groupPretypeMsgsToServer = new GroupPreKeySignalMessageToServer(CiphertextMessage.CURRENT_VERSION,
                    0, 0, 0,
                    ourEinitiatorKeyPair.getPublicKey() , ourIdentityKeyPair.getPublicKey()  );

            //自己的另一端
            {
                theirSignedPreKeyPair =  ourSignedPreKeyPair;
                theirIdentityKeyPair = ourIdentityKeyPair;
                theirRegistrationId = registrationId;
                theriSignedPreKeyId=signedPreKeyId;
                byte groupKeyEncrypt[] = null;
                byte iv[] = null;
                byte key[] = null;

              /*  byte[][] derivedSecrets = getEncryptKeyIv(ourIdentityKeyPair, ourEinitiatorKeyPair, theirIdentityKeyPair.getPublicKey(), theirSignedPreKeyPair.getPublicKey());
                //协商的加密key
                key = derivedSecrets[0];
                iv = derivedSecrets[1];
                groupKeyEncrypt = getCipherText(iv, key, selfGroupSenderKeyDistributionMessage.serialize());
                groupPretypeMsgsToServer.AddGroupPretypeMsg(aliceUser.getUserId(), groupKeyEncrypt);*/
            }
            //目的用户端
            {
                theirSignedPreKeyPair =  bobUser.getSignedPreKeyPair();
                theirIdentityKeyPair = bobUser.getIdentityKeyPair();
                theirRegistrationId = bobUser.getIdentityId();
                theriSignedPreKeyId=bobUser.getSignedPreId();
                byte groupKeyEncrypt[]=null;
                byte iv[] =null;
                byte key[]=null;

               /* byte[][] derivedSecrets = getEncryptKeyIv(ourIdentityKeyPair, ourEinitiatorKeyPair, theirIdentityKeyPair.getPublicKey(),  theirSignedPreKeyPair.getPublicKey());
                //协商的加密key
                key = derivedSecrets[0];
                iv = derivedSecrets[1];

                    groupKeyEncrypt = getCipherText(iv, key, aliceSentDistributionMessage.serialize());
                groupPretypeMsgsToServer.AddGroupPretypeMsg(bobUser.getUserId(), groupKeyEncrypt);*/

            }

//整体报文序列化，然后发送给服务端
            groupPretypeMsgsToServer.getPacketGroupPretypeMsgSerialized();
            System.out.println("pack data: len:"+ groupPretypeMsgsToServer.serialize().length);

//-----------------------------服务端处理逻辑---------------：这里服务端收到后进行拆分： 服务端拆解成2份；一份自己的其他设备；一份目的端的 其他设备
            GroupPreKeySignalMessageToServer groupRecvPreKeySignalMessageToServer = new GroupPreKeySignalMessageToServer(groupPretypeMsgsToServer.serialize(),userKeyMap);
            //for(int k=0; k< groupRecvPreKeySignalMessageToServer.getClientMsgLst().size(); k++) {

//产生 各个各个接收客户端的消息报文

                //GroupPreKeySignalMessageToClient groupPreKeySignalMessageToClient=groupRecvPreKeySignalMessageToServer.getClientMsgLst().get(0);

//------------------------------客户端收到后的处理：解密获取密码； 解密消息------------------------------------
//以下是客户端收到的加密报文报：解密获取该用户的发送  消息密码


                //接收端为自己的其他设备端
                {
                    GroupPreKeySignalMessageToClient groupPreKeySignalMessageToClient=groupRecvPreKeySignalMessageToServer.getClientMsgLst().get(0);

//------------------------------客户端收到后的处理：解密获取密码； 解密消息------------------------------------
//以下是客户端收到的加密报文报：解密获取该用户的发送  消息密码
                    UserKey obj=userKeyMap.get(groupPreKeySignalMessageToClient.getUserId());
                   /* byte[][] keyAndIv= getDecryptKeyIv(obj,groupPreKeySignalMessageToClient.getIdentityKey(), groupPreKeySignalMessageToClient.getBaseKey()  );
                    byte[] msgSerialize= getPlainText(keyAndIv[1],   keyAndIv[0],  groupPreKeySignalMessageToClient.getMessage());
                    GroupSenderKeyDistributionMessage selfReceiveGroupSenderKeyDistributionMessage=null;
                    SenderKeyDistributionMessage receivedAliceDistributionMessage=null;
                    selfReceiveGroupSenderKeyDistributionMessage = new GroupSenderKeyDistributionMessage(msgSerialize);
                    receivedAliceDistributionMessage = new SenderKeyDistributionMessage(selfReceiveGroupSenderKeyDistributionMessage.getId(),selfReceiveGroupSenderKeyDistributionMessage.getIteration(),selfReceiveGroupSenderKeyDistributionMessage.getChainKey(),selfReceiveGroupSenderKeyDistributionMessage.getSignatureKey());

//aliceSession1.getSelfSenderKeyName() 要加入协议

                        //aliceSession11.processFromSelf(aliceSession1.getSelfSenderKeyName(), selfReceiveGroupSenderKeyDistributionMessage );
                        // 接收加密的消息，解密

                        for (int j = 0; j < 20; j++) {
                            if (j % 5 == 0) {
                                      //byte[] plaintextFromAlice = aliceSession11.decrypt(arraySendData[j],aliceSession1.getSelfSenderKeyName());
                                //      System.out.println("解密自己的其他设备： userid:" + obj.userId + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + org.bouncycastle.util.encoders.Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                            }
                        }

                        //自己的其他设备加密下，然后解密*/

                }
//接收端为目的端
                { GroupPreKeySignalMessageToClient groupPreKeySignalMessageToClient=groupRecvPreKeySignalMessageToServer.getClientMsgLst().get(1);
                    SingleChatSession bobSession1= new SingleChatSession( "13266838002", 10011, aliceUser,bobUser);
                    UserKey obj=userKeyMap.get(groupPreKeySignalMessageToClient.getUserId());
                    /*byte[][] keyAndIv= getDecryptKeyIv(obj,groupPreKeySignalMessageToClient.getIdentityKey(), groupPreKeySignalMessageToClient.getBaseKey()  );
                    byte[] msgSerialize= getPlainText(keyAndIv[1],   keyAndIv[0],  groupPreKeySignalMessageToClient.getMessage());

                    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(msgSerialize);
                    //bobSession1.process( aliceSession1.getSelfSenderKeyName(), receivedAliceDistributionMessage);



                    // 接收加密的消息，解密

                    for(int j=0; j< 20; j++) {
                        if(j%5==0) {
                            //byte[] plaintextFromAlice = bobSession1.decrypt(arraySendData[j], aliceSession1.getSelfSenderKeyName() );
                           // System.out.println("userid:" + obj.userId + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                        }
                    }*/
                }





//设备id一样，就是本身 1)使用原来密钥  2）重新生成密钥


        //}



        }







}
