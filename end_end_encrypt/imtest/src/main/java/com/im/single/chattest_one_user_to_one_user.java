package com.im.single;

import org.bouncycastle.util.encoders.Base64;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.*;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.protocol.*;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Medium;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import org.whispersystems.libsignal.protocol.PreKeySignalMessage;

import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Medium;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Random;



//1.模式一，一个用户对一个用户（每个用户多个设备，能够获取同样消息
//放案1：群组实现放方式方案。   这里按照群聊实现多设备端对端聊天加密：
//      每个发送者设备一条加密密钥，自己的其他设备只能用该密钥解密，不能加密；
//      服务端对消息进行分发到各个设备；接收者根据规则解密。
//方案2：一条消息按设备来，2个密钥，一个自己；一个对方；每次2条消息
public class chattest_one_user_to_one_user {
    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("userid:1"+"+14151231234", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("userid:2"+"+14159998888", 1);
    private static final SignalProtocolAddress BOB_ADDRESS_2  = new SignalProtocolAddress("userid:1"+"+14151231234", 2);
    private static final SignalProtocolAddress ALICE_ADDRESS_2 = new SignalProtocolAddress("userid:2"+"+14159998888", 2);

        private int randomInt() {
            try {
                return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError(e);
            }
        }
        //获取端对端协商密钥key
        byte[][] getDecryptKeyIv(UserKey user, ECPublicKey theirIdentityPublicKey, ECPublicKey theirBaseTmpPublicKey) throws InvalidKeyException, IOException {

            ByteArrayOutputStream secretsRecv = new ByteArrayOutputStream();
            secretsRecv.write(Curve.calculateAgreement(theirIdentityPublicKey, user.signedPreKeyPair.getPrivateKey()
            ));
            secretsRecv.write(Curve.calculateAgreement(theirBaseTmpPublicKey ,
                    user.identityKeyPair.getPrivateKey() ));
            secretsRecv.write(Curve.calculateAgreement(theirBaseTmpPublicKey,
                    user.identityKeyPair.getPrivateKey() ));

            HKDF kdf = new HKDFv3();
            byte[] derivedSecretBytes = kdf.deriveSecrets(secretsRecv.toByteArray(), "WhisperText".getBytes(), 48);
            byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16);
            //协商的加密key
            byte[] shareEncryptKeyRecv = derivedSecrets[0];
            return derivedSecrets;
        }
    //获取端对端协商密钥key
    byte[][] getEncryptKeyIv(  ECKeyPair ourIdentityKeyPair,  ECKeyPair ourEinitiatorKeyPair, ECPublicKey theirIdentityKeyPublic, ECPublicKey theirSignedPreKeyPublic ) throws InvalidKeyException, IOException {
        //产生加密本次消息的密钥
        ByteArrayOutputStream secrets = new ByteArrayOutputStream();
        //secrets.write(getDiscontinuityBytes());
        secrets.write(Curve.calculateAgreement(theirSignedPreKeyPublic, ourIdentityKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPublic , ourEinitiatorKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPublic , ourEinitiatorKeyPair.getPrivateKey()));


        HKDF kdf = new HKDFv3();
        byte[] derivedSecretBytes = kdf.deriveSecrets(secrets.toByteArray(), "WhisperText".getBytes(), 48);
        byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16);
        //协商的加密key
        //key = derivedSecrets[0];
        //iv = derivedSecrets[1];
        return derivedSecrets;
    }

        //aes解密函数
        private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
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
        private byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
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

            System.out.println("group key id:"+ aliceSentDistributionMessage.getId()+" key:"+ org.bouncycastle.util.encoders.Base64.toBase64String(aliceSentDistributionMessage.getChainKey()));

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

                byte[][] derivedSecrets = getEncryptKeyIv(ourIdentityKeyPair, ourEinitiatorKeyPair, theirIdentityKeyPair.getPublicKey(), theirSignedPreKeyPair.getPublicKey());
                //协商的加密key
                key = derivedSecrets[0];
                iv = derivedSecrets[1];
                groupKeyEncrypt = getCipherText(iv, key, selfGroupSenderKeyDistributionMessage.serialize());
                groupPretypeMsgsToServer.AddGroupPretypeMsg(aliceUser.getUserId(), groupKeyEncrypt);
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

                byte[][] derivedSecrets = getEncryptKeyIv(ourIdentityKeyPair, ourEinitiatorKeyPair, theirIdentityKeyPair.getPublicKey(),  theirSignedPreKeyPair.getPublicKey());
                //协商的加密key
                key = derivedSecrets[0];
                iv = derivedSecrets[1];

                    groupKeyEncrypt = getCipherText(iv, key, aliceSentDistributionMessage.serialize());
                groupPretypeMsgsToServer.AddGroupPretypeMsg(bobUser.getUserId(), groupKeyEncrypt);

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
                    byte[][] keyAndIv= getDecryptKeyIv(obj,groupPreKeySignalMessageToClient.getIdentityKey(), groupPreKeySignalMessageToClient.getBaseKey()  );
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

                        //自己的其他设备加密下，然后解密

                }
//接收端为目的端
                { GroupPreKeySignalMessageToClient groupPreKeySignalMessageToClient=groupRecvPreKeySignalMessageToServer.getClientMsgLst().get(1);
                    SingleChatSession bobSession1= new SingleChatSession( "13266838002", 10011, aliceUser,bobUser);
                    UserKey obj=userKeyMap.get(groupPreKeySignalMessageToClient.getUserId());
                    byte[][] keyAndIv= getDecryptKeyIv(obj,groupPreKeySignalMessageToClient.getIdentityKey(), groupPreKeySignalMessageToClient.getBaseKey()  );
                    byte[] msgSerialize= getPlainText(keyAndIv[1],   keyAndIv[0],  groupPreKeySignalMessageToClient.getMessage());

                    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(msgSerialize);
                    //bobSession1.process( aliceSession1.getSelfSenderKeyName(), receivedAliceDistributionMessage);



                    // 接收加密的消息，解密

                    for(int j=0; j< 20; j++) {
                        if(j%5==0) {
                            //byte[] plaintextFromAlice = bobSession1.decrypt(arraySendData[j], aliceSession1.getSelfSenderKeyName() );
                           // System.out.println("userid:" + obj.userId + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                        }
                    }
                }





//设备id一样，就是本身 1)使用原来密钥  2）重新生成密钥


        //}



        }



        public static void main(String[] args) throws InvalidKeyIdException, InvalidKeyException, LegacyMessageException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, NoSessionException, IOException {
            com.im.group.GroupCipherDemo obj =new com.im.group.GroupCipherDemo();
            obj.testGroupEncryptOneDeviceOneKeyAll();
        }




}
