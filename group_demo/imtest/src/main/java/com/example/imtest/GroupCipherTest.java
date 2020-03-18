package com.example.imtest;






import com.im.secure.GroupPreKeySignalMessageToClient;
import com.im.secure.GroupPreKeySignalMessageToServer;
import com.im.secure.GroupSenderKeyDistributionMessage;

import com.im.secure.UserKey;
import junit.framework.TestCase;

import org.bouncycastle.util.encoders.Base64;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.protocol.*;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.KeyHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

//存储密钥
class InMemorySenderKeyStore implements SenderKeyStore {

    private final Map<SenderKeyName, SenderKeyRecord> store = new HashMap<>();

    @Override
    public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record) {
        store.put(senderKeyName, record);
    }

    @Override
    public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName) {
        try {
            SenderKeyRecord record = store.get(senderKeyName);

            if (record == null) {
                return new SenderKeyRecord();
            } else {
                return new SenderKeyRecord(record.serialize());
            }
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}




//}
public class GroupCipherTest extends TestCase {

//获取端对端协商密钥key
byte[][] getDecryptKeyIv(UserKey user, ECPublicKey theirIdentityPublicKey, ECPublicKey theirBaseTmpPublicKey) throws InvalidKeyException, IOException {

    ByteArrayOutputStream secretsRecv = new ByteArrayOutputStream();
                secretsRecv.write(Curve.calculateAgreement(theirIdentityPublicKey, user.getSignedPreKeyPair().getPrivateKey()
                        ));
                secretsRecv.write(Curve.calculateAgreement(theirBaseTmpPublicKey ,
            user.getIdentityKeyPair().getPrivateKey() ));
                secretsRecv.write(Curve.calculateAgreement(theirBaseTmpPublicKey,
            user.getIdentityKeyPair().getPrivateKey() ));

        HKDF kdf = new HKDFv3();
        byte[] derivedSecretBytes = kdf.deriveSecrets(secretsRecv.toByteArray(), "WhisperText".getBytes(), 48);
        byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16);
        //协商的加密key
        byte[] shareEncryptKeyRecv = derivedSecrets[0];
        return derivedSecrets;
        //byte[] data = getPlainText(derivedSecrets[1], derivedSecrets[0], t.getOneMsg().toByteArray());
        //SenderKeyDistributionMessage tmsg = new SenderKeyDistributionMessage(data);

}


    //aes解密
private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
        throws InvalidMessageException
{
    try {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher          cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");
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

    //加密
  static   byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
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
    private static final SignalProtocolAddress SENDER_ADDRESS = new SignalProtocolAddress("+13266838001", 1);
    private static final SenderKeyName GROUP_SENDER   = new SenderKeyName("groupId1001" , SENDER_ADDRESS);
    //同一用户的其他设备
    private static final SignalProtocolAddress SENDER_ADDRESS1 = new SignalProtocolAddress("+13266838001", 2);
    private static final SenderKeyName GROUP_SENDER1   = new SenderKeyName("groupId1001" , SENDER_ADDRESS1);

    private static final int  GroupMaxNum =20;
public void testGroupEncryptOneDeviceOneKeyAll() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException, InvalidKeyException, IOException, InvalidVersionException, InvalidKeyIdException {
    //1.建立群
    // 2.发送加密密钥 给服务器  长连接或短链接都可以
    InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);


    //发送者自己的key信息
    ECKeyPair ourEinitiatorKeyPair = Curve.generateKeyPair();//临时key
    int registrationId =KeyHelper.generateSenderKeyId();
    int signedPreKeyId = KeyHelper.generateSenderKeyId();
    ECKeyPair ourIdentityKeyPair = Curve.generateKeyPair();//自己的身份密钥和id
    ECKeyPair ourSignedPreKeyPair = Curve.generateKeyPair();//自己的预签名共享密钥和id
    IdentityKey ourIdentityKey=new IdentityKey(ourIdentityKeyPair.getPublicKey());



    //测试自己的另外一个设备 可删
    InMemorySenderKeyStore aliceStore1 = new InMemorySenderKeyStore();
    GroupSessionBuilder aliceSessionBuilder1 = new GroupSessionBuilder(aliceStore1);
    GroupCipher aliceGroupCipher1 = new GroupCipher(aliceStore1, GROUP_SENDER1);
    SenderKeyDistributionMessage sentAliceDistributionMessage1     = aliceSessionBuilder1.create(GROUP_SENDER1);//产生群发送消息密钥

    byte[][] arraySendData1=new byte[2005][];
    for(int z=0; z<2005; z++) {
        arraySendData1[z] = aliceGroupCipher1.encrypt(("devic1 msg:"+z+"test group smert ze smert").getBytes());

    }


    //3.本地是否有加密信息，没有则产生；//Alice 产生 发消息密钥 给服务端，服务端如果已经有了，则需要返回，且替换掉本地。
    SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(GROUP_SENDER);//产生群发送消息密钥
    GroupSenderKeyDistributionMessage selfGroupSenderKeyDistributionMessage=new GroupSenderKeyDistributionMessage(sentAliceDistributionMessage.getId(),
            sentAliceDistributionMessage.getIteration(),sentAliceDistributionMessage.getChainKey(), sentAliceDistributionMessage.getSignatureKey(),
            aliceStore.loadSenderKey(GROUP_SENDER ).getSenderKeyState( sentAliceDistributionMessage.getId()).getSigningKeyPrivate());
    System.out.println("group key id:"+ sentAliceDistributionMessage.getId()+" key:"+ Base64.toBase64String(sentAliceDistributionMessage.getChainKey()));





    //4.打包后发送给服务端；服务端如果有了，则返回已有的key消息;解密后使用，且保存本地。

    //5.加密发送给服务端 所有现有群成员密钥






//--------------------发送端发送消息------------
//发送/收取消息
    //Alice 发送群消息
    byte[][] arraySendData=new byte[20][];
    for(int z=0; z<20; z++) {
        arraySendData[z] = aliceGroupCipher.encrypt(("msg:"+z+"test group smert ze smert").getBytes());

    }
//---------------------end

//打包对所有现有群成员的加密密钥
    GroupPreKeySignalMessageToServer groupPretypeMsgsToServer = new GroupPreKeySignalMessageToServer(CiphertextMessage.CURRENT_VERSION, 0, 0, 0,
            ourEinitiatorKeyPair.getPublicKey() , ourIdentityKeyPair.getPublicKey()  );
    //所有群成员用户的加密key信息
    ConcurrentHashMap<Long, UserKey> userKeyMap =new ConcurrentHashMap<Long, UserKey>();
    for(int i=0; i < GroupMaxNum; i++)
    {
    //产生成员 i的 加密信息
        //获取成员id的 个人信息 实际代码中，要从服务端获取，这里临时生成取代
        ECKeyPair theirSignedPreKeyPair = Curve.generateKeyPair();
        ECKeyPair theirIdentityKeyPair = Curve.generateKeyPair();
        int theirRegistrationId =KeyHelper.generateSenderKeyId();
        int theriSignedPreKeyId = KeyHelper.generateSenderKeyId();
        if(i==0)//self
        {
            theirSignedPreKeyPair =  ourSignedPreKeyPair;
            theirIdentityKeyPair = ourIdentityKeyPair;
            theirRegistrationId = registrationId;
            theriSignedPreKeyId=signedPreKeyId;
        }
        UserKey obj=new UserKey(5000000000L+i,theirRegistrationId,theriSignedPreKeyId, theirIdentityKeyPair, theirSignedPreKeyPair);
        userKeyMap.put(5000000000L+i, obj);

    //产生加密本次消息的密钥
        ByteArrayOutputStream secrets = new ByteArrayOutputStream();
        //secrets.write(getDiscontinuityBytes());
        secrets.write(Curve.calculateAgreement(theirSignedPreKeyPair.getPublicKey(), ourIdentityKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorKeyPair.getPrivateKey()));
        secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorKeyPair.getPrivateKey()));

        byte groupKeyEncrypt[]=null;
        byte iv[] =null;
        byte key[]=null;

        HKDF kdf = new HKDFv3();
        byte[] derivedSecretBytes = kdf.deriveSecrets(secrets.toByteArray(), "WhisperText".getBytes(), 48);
        byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16);
        //协商的加密key
        key = derivedSecrets[0];
        iv = derivedSecrets[1];

        if(i==0)//自己的其他终端，则多一个密钥
        {
            groupKeyEncrypt = getCipherText(iv, key, selfGroupSenderKeyDistributionMessage.serialize());

        }else {
            groupKeyEncrypt = getCipherText(iv, key, sentAliceDistributionMessage.serialize());

        }
        //TArray t = new TArray();
        //t.setData( groupKeyEncrypt);
        //t.setUserId(5000000000L+i );
        //groupPretypeMsgsToServer.AddMsg(t);
        groupPretypeMsgsToServer.AddGroupPretypeMsg(5000000000L+i, groupKeyEncrypt);
        //打包该成员信息到 消息
    }
//整体报文序列化，然后发送给服务端
    groupPretypeMsgsToServer.getPacketGroupPretypeMsgSerialized();
System.out.println("pack data: len:"+ groupPretypeMsgsToServer.serialize().length);

//这里服务端收到后进行拆分： 服务端拆解成N份；分别发送给各个客户端
    GroupPreKeySignalMessageToServer groupRecvPreKeySignalMessageToServer = new GroupPreKeySignalMessageToServer(groupPretypeMsgsToServer.serialize(),userKeyMap);
    for(int k=0; k< groupRecvPreKeySignalMessageToServer.getClientMsgLst().size(); k++) {

//产生 各个各个接收客户端的消息报文
        //各个接收客户端收取到后解密
        GroupPreKeySignalMessageToClient groupPreKeySignalMessageToClient=groupRecvPreKeySignalMessageToServer.getClientMsgLst().get(k);
//------------------------------客户端收到后的处理：解密获取密码； 解密消息------------------------------------
//以下是客户端收到的加密报文报：解密获取该用户的发送 群消息密码
        UserKey obj=userKeyMap.get(groupPreKeySignalMessageToClient.getUserId());
        byte[][] keyAndIv= getDecryptKeyIv(obj,groupPreKeySignalMessageToClient.getIdentityKey(), groupPreKeySignalMessageToClient.getBaseKey()  );
        byte[] msgSerialize= getPlainText(keyAndIv[1],   keyAndIv[0],  groupPreKeySignalMessageToClient.getMessage());
        //这是群发送者发来的的群消息加密密钥信息
        //
        {
            GroupSenderKeyDistributionMessage selfReceiveGroupSenderKeyDistributionMessage=null;
            SenderKeyDistributionMessage receivedAliceDistributionMessage=null;
            //例子以这个id为自己,且设备id一样
            if( groupPreKeySignalMessageToClient.getUserId() == 5000000000L) {
                selfReceiveGroupSenderKeyDistributionMessage = new GroupSenderKeyDistributionMessage(msgSerialize);
                receivedAliceDistributionMessage = new SenderKeyDistributionMessage(selfReceiveGroupSenderKeyDistributionMessage.getId(),selfReceiveGroupSenderKeyDistributionMessage.getIteration(),selfReceiveGroupSenderKeyDistributionMessage.getChainKey(),selfReceiveGroupSenderKeyDistributionMessage.getSignatureKey());

//设备id 不一样
                {
                    aliceSessionBuilder1.process(GROUP_SENDER, receivedAliceDistributionMessage);
                    GroupCipher aliceGroupCipher01 = new GroupCipher(aliceStore1, GROUP_SENDER);

                    // 接收加密的消息，解密

                    for (int j = 0; j < 20; j++) {
                        if (j % 5 == 0) {
                            byte[] plaintextFromAlice = aliceGroupCipher01.decrypt(arraySendData[j]);
                            System.out.println("解密自己的其他设备： userid:" + obj.getUserId() + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                        }
                    }

                    //自己的其他设备加密下，然后解密
                    aliceSessionBuilder.process(GROUP_SENDER1,sentAliceDistributionMessage1);
                    GroupCipher aliceGroupCipher11 = new GroupCipher(aliceStore, GROUP_SENDER1);
                    byte[] plaintextFromAlice = aliceGroupCipher11.decrypt(arraySendData1[1999]);
                    System.out.println("a1 解密自己的其他设备： userid:" + obj.getUserId() + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + sentAliceDistributionMessage1.getId() + " key:" + Base64.toBase64String(sentAliceDistributionMessage1.getChainKey()));

                }


//设备id一样，就是本身 1)使用原来密钥  2）重新生成密钥

                {
                  /*  InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
                    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

                    ECKeyPair signatureKey = new ECKeyPair(selfReceiveGroupSenderKeyDistributionMessage.getSignatureKey(), selfReceiveGroupSenderKeyDistributionMessage.getSignatureKeyPrivate());

                    bobStore.loadSenderKey(GROUP_SENDER).setSenderKeyState(selfReceiveGroupSenderKeyDistributionMessage.getId(), selfReceiveGroupSenderKeyDistributionMessage.getIteration(),
                            selfReceiveGroupSenderKeyDistributionMessage.getChainKey(), signatureKey);

                    // 接收加密的消息，解密
                    GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);
                    for (int j = 0; j < 20; j++) {
                        if (j % 5 == 0) {
                            byte[] plaintextFromAlice = bobGroupCipher.decrypt(arraySendData[j]);
                            System.out.println("self userid:" + obj.userId + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                        }
                    }*/
                }
            }else {
                  receivedAliceDistributionMessage = new SenderKeyDistributionMessage(msgSerialize);
                InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
                GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
                bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

                // 接收加密的消息，解密
                GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);
                for(int j=0; j< 20; j++) {
                    if(j%5==0) {
                        byte[] plaintextFromAlice = bobGroupCipher.decrypt(arraySendData[j]);
                        System.out.println("userid:" + obj.getUserId() + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                    }
                }
            }
        //根据加密密码产生群会话信息，为收取消息解密准备


        }

    }



}

    public void testNoSession() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, GROUP_SENDER);

        SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(GROUP_SENDER);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

//    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert".getBytes());
        try {
            byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice);
            throw new AssertionError("Should be no session!");
        } catch (NoSessionException e) {
            // good
        }
    }

    public void testBasicEncryptDecrypt()
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
    {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, GROUP_SENDER);

        SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(GROUP_SENDER);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
        bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert".getBytes());
        byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice);

        assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
    }

    public void testLargeMessages() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, GROUP_SENDER);

        SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(GROUP_SENDER);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
        bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        byte[] plaintext = new byte[1024 * 1024];
        new Random().nextBytes(plaintext);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(plaintext);
        byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice);

        assertTrue(Arrays.equals(plaintext, plaintextFromAlice));
    }

    public void testBasicRatchet()
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
    {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage sentAliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);
        SenderKeyDistributionMessage receivedAliceDistributionMessage =
                new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

        bobSessionBuilder.process(aliceName, receivedAliceDistributionMessage);

        byte[] ciphertextFromAlice  = aliceGroupCipher.encrypt("smert ze smert".getBytes());
        byte[] ciphertextFromAlice2 = aliceGroupCipher.encrypt("smert ze smert2".getBytes());
        byte[] ciphertextFromAlice3 = aliceGroupCipher.encrypt("smert ze smert3".getBytes());

        byte[] plaintextFromAlice   = bobGroupCipher.decrypt(ciphertextFromAlice);

        try {
            bobGroupCipher.decrypt(ciphertextFromAlice);
            throw new AssertionError("Should have ratcheted forward!");
        } catch (DuplicateMessageException dme) {
            // good
        }

        byte[] plaintextFromAlice2  = bobGroupCipher.decrypt(ciphertextFromAlice2);
        byte[] plaintextFromAlice3  = bobGroupCipher.decrypt(ciphertextFromAlice3);

        assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
        assertTrue(new String(plaintextFromAlice2).equals("smert ze smert2"));
        assertTrue(new String(plaintextFromAlice3).equals("smert ze smert3"));
    }

    public void testLateJoin() throws NoSessionException, InvalidMessageException, LegacyMessageException, DuplicateMessageException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);


        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);


        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);
        // Send off to some people.

        for (int i=0;i<100;i++) {
            aliceGroupCipher.encrypt("up the punks up the punks up the punks".getBytes());
        }

        // Now Bob Joins.
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
        GroupCipher         bobGroupCipher    = new GroupCipher(bobStore, aliceName);


        SenderKeyDistributionMessage distributionMessageToBob = aliceSessionBuilder.create(aliceName);
        bobSessionBuilder.process(aliceName, new SenderKeyDistributionMessage(distributionMessageToBob.serialize()));

        byte[] ciphertext = aliceGroupCipher.encrypt("welcome to the group".getBytes());
        byte[] plaintext  = bobGroupCipher.decrypt(ciphertext);

        assertEquals(new String(plaintext), "welcome to the group");
    }


    public void testOutOfOrder()
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
    {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        ArrayList<byte[]> ciphertexts = new ArrayList<>(100);

        for (int i=0;i<100;i++) {
            ciphertexts.add(aliceGroupCipher.encrypt("up the punks".getBytes()));
        }

        while (ciphertexts.size() > 0) {
            int    index      = randomInt() % ciphertexts.size();
            byte[] ciphertext = ciphertexts.remove(index);
            byte[] plaintext  = bobGroupCipher.decrypt(ciphertext);

            assertTrue(new String(plaintext).equals("up the punks"));
        }
    }

    public void testEncryptNoSession() {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, new SenderKeyName("coolio groupio", new SignalProtocolAddress("+10002223333", 1)));
        try {
            aliceGroupCipher.encrypt("up the punks".getBytes());
            throw new AssertionError("Should have failed!");
        } catch (NoSessionException nse) {
            // good
        }
    }


    public void testTooFarInFuture() throws DuplicateMessageException, InvalidMessageException, LegacyMessageException, NoSessionException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        for (int i=0;i<2001;i++) {
            aliceGroupCipher.encrypt("up the punks".getBytes());
        }

        byte[] tooFarCiphertext = aliceGroupCipher.encrypt("notta gonna worka".getBytes());
        try {
            bobGroupCipher.decrypt(tooFarCiphertext);
            throw new AssertionError("Should have failed!");
        } catch (InvalidMessageException e) {
            // good
        }
    }

    public void testMessageKeyLimit() throws Exception {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher   = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        List<byte[]> inflight = new LinkedList<>();

        for (int i=0;i<2010;i++) {
            inflight.add(aliceGroupCipher.encrypt("up the punks".getBytes()));
        }

        bobGroupCipher.decrypt(inflight.get(1000));
        bobGroupCipher.decrypt(inflight.get(inflight.size()-1));

        try {
            bobGroupCipher.decrypt(inflight.get(0));
            throw new AssertionError("Should have failed!");
        } catch (DuplicateMessageException e) {
            // good
        }
    }


    private int randomInt() {
        try {
            return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    public static void main(String[] args) {

    }

    public void groupEncryptAllOneUserOneKeyTest() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException, InvalidKeyException, IOException, InvalidVersionException, InvalidKeyIdException {
        //1.建立群
        // 2.发送加密密钥 给服务器  长连接或短链接都可以
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);


        //3.本地是否有加密信息，没有则产生；//Alice 产生 发消息密钥 给服务端，服务端如果已经有了，则需要返回，且替换掉本地。
        SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(GROUP_SENDER);//产生群发送消息密钥
        GroupSenderKeyDistributionMessage selfGroupSenderKeyDistributionMessage=new GroupSenderKeyDistributionMessage(sentAliceDistributionMessage.getId(),
                sentAliceDistributionMessage.getIteration(),sentAliceDistributionMessage.getChainKey(), sentAliceDistributionMessage.getSignatureKey(),
                aliceStore.loadSenderKey(GROUP_SENDER ).getSenderKeyState( sentAliceDistributionMessage.getId()).getSigningKeyPrivate());
        System.out.println("group key id:"+ sentAliceDistributionMessage.getId()+" key:"+ Base64.toBase64String(sentAliceDistributionMessage.getChainKey()));

        //4.打包后发送给服务端；服务端如果有了，则返回已有的key消息;解密后使用，且保存本地。

        //5.加密发送给服务端 所有现有群成员密钥
        //发送者自己的key信息
        ECKeyPair ourEinitiatorKeyPair = Curve.generateKeyPair();//临时key
        int registrationId =KeyHelper.generateSenderKeyId();
        int signedPreKeyId = KeyHelper.generateSenderKeyId();
        ECKeyPair ourIdentityKeyPair = Curve.generateKeyPair();//自己的身份密钥和id
        ECKeyPair ourSignedPreKeyPair = Curve.generateKeyPair();//自己的预签名共享密钥和id
        IdentityKey ourIdentityKey=new IdentityKey(ourIdentityKeyPair.getPublicKey());


//--------------------发送端发送消息------------
//发送/收取消息
        //Alice 发送群消息
        byte[][] arraySendData=new byte[20][];
        for(int z=0; z<20; z++) {
            arraySendData[z] = aliceGroupCipher.encrypt(("msg:"+z+"test group smert ze smert").getBytes());

        }
//---------------------end

//打包对所有现有群成员的加密密钥
        GroupPreKeySignalMessageToServer groupPretypeMsgsToServer = new GroupPreKeySignalMessageToServer(CiphertextMessage.CURRENT_VERSION, 0, 0, 0,
                ourEinitiatorKeyPair.getPublicKey() , ourIdentityKeyPair.getPublicKey()  );
        //所有群成员用户的加密key信息
        ConcurrentHashMap<Long, UserKey> userKeyMap =new ConcurrentHashMap<Long, UserKey>();
        for(int i=0; i < GroupMaxNum; i++)
        {
            //产生成员 i的 加密信息
            //获取成员id的 个人信息 实际代码中，要从服务端获取，这里临时生成取代
            ECKeyPair theirSignedPreKeyPair = Curve.generateKeyPair();
            ECKeyPair theirIdentityKeyPair = Curve.generateKeyPair();
            int theirRegistrationId =KeyHelper.generateSenderKeyId();
            int theriSignedPreKeyId = KeyHelper.generateSenderKeyId();
            if(i==0)//self
            {
                theirSignedPreKeyPair =  ourSignedPreKeyPair;
                theirIdentityKeyPair = ourIdentityKeyPair;
                theirRegistrationId = registrationId;
                theriSignedPreKeyId=signedPreKeyId;
            }
            UserKey obj=new UserKey(5000000000L+i,theirRegistrationId,theriSignedPreKeyId, theirIdentityKeyPair, theirSignedPreKeyPair);
            userKeyMap.put(5000000000L+i, obj);

            //产生加密本次消息的密钥
            ByteArrayOutputStream secrets = new ByteArrayOutputStream();
            //secrets.write(getDiscontinuityBytes());
            secrets.write(Curve.calculateAgreement(theirSignedPreKeyPair.getPublicKey(), ourIdentityKeyPair.getPrivateKey()));
            secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorKeyPair.getPrivateKey()));
            secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorKeyPair.getPrivateKey()));

            byte groupKeyEncrypt[]=null;
            byte iv[] =null;
            byte key[]=null;

            HKDF kdf = new HKDFv3();
            byte[] derivedSecretBytes = kdf.deriveSecrets(secrets.toByteArray(), "WhisperText".getBytes(), 48);
            byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 16);
            //协商的加密key
            key = derivedSecrets[0];
            iv = derivedSecrets[1];

            if(i==0)//自己的其他终端，则多一个密钥
            {
                groupKeyEncrypt = getCipherText(iv, key, selfGroupSenderKeyDistributionMessage.serialize());

            }else {
                groupKeyEncrypt = getCipherText(iv, key, sentAliceDistributionMessage.serialize());

            }
            //TArray t = new TArray();
            //t.setData( groupKeyEncrypt);
            //t.setUserId(5000000000L+i );
            //groupPretypeMsgsToServer.AddMsg(t);
            groupPretypeMsgsToServer.AddGroupPretypeMsg(5000000000L+i, groupKeyEncrypt);
            //打包该成员信息到 消息
        }
//整体报文序列化，然后发送给服务端
        groupPretypeMsgsToServer.getPacketGroupPretypeMsgSerialized();
        System.out.println("pack data: len:"+ groupPretypeMsgsToServer.serialize().length);

//这里服务端收到后进行拆分： 服务端拆解成N份；分别发送给各个客户端
        GroupPreKeySignalMessageToServer groupRecvPreKeySignalMessageToServer = new GroupPreKeySignalMessageToServer(groupPretypeMsgsToServer.serialize(),
                userKeyMap);
        for(int k=0; k< groupRecvPreKeySignalMessageToServer.getClientMsgLst().size(); k++) {

//产生 各个各个接收客户端的消息报文
            //各个接收客户端收取到后解密
            GroupPreKeySignalMessageToClient groupPreKeySignalMessageToClient=groupRecvPreKeySignalMessageToServer.getClientMsgLst().get(k);
//------------------------------客户端收到后的处理：解密获取密码； 解密消息------------------------------------
//以下是客户端收到的加密报文报：解密获取该用户的发送 群消息密码
            UserKey obj=userKeyMap.get(groupPreKeySignalMessageToClient.getUserId());
            byte[][] keyAndIv= getDecryptKeyIv(obj,groupPreKeySignalMessageToClient.getIdentityKey(), groupPreKeySignalMessageToClient.getBaseKey()  );
            byte[] msgSerialize= getPlainText(keyAndIv[1],   keyAndIv[0],  groupPreKeySignalMessageToClient.getMessage());
            //这是群发送者发来的的群消息加密密钥信息
            //
            {
                GroupSenderKeyDistributionMessage selfReceiveGroupSenderKeyDistributionMessage=null;
                SenderKeyDistributionMessage receivedAliceDistributionMessage=null;
                //例子以这个id为自己
                if( groupPreKeySignalMessageToClient.getUserId() == 5000000000L) {
                    selfReceiveGroupSenderKeyDistributionMessage = new GroupSenderKeyDistributionMessage(msgSerialize);


                    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
                    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

                    ECKeyPair signatureKey= new ECKeyPair(selfReceiveGroupSenderKeyDistributionMessage.getSignatureKey(),selfReceiveGroupSenderKeyDistributionMessage.getSignatureKeyPrivate());

                    bobStore.loadSenderKey( GROUP_SENDER).setSenderKeyState(selfReceiveGroupSenderKeyDistributionMessage.getId(),selfReceiveGroupSenderKeyDistributionMessage.getIteration(),
                            selfReceiveGroupSenderKeyDistributionMessage.getChainKey(),signatureKey );

                    // 接收加密的消息，解密
                    GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);
                    for(int j=0; j< 20; j++) {
                        if(j%5==0) {
                            byte[] plaintextFromAlice = bobGroupCipher.decrypt(arraySendData[j]);
                            System.out.println("self userid:" + obj.getUserId() + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                        }
                    }

                }else {
                    receivedAliceDistributionMessage = new SenderKeyDistributionMessage(msgSerialize);
                    InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
                    GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
                    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

                    // 接收加密的消息，解密
                    GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);
                    for(int j=0; j< 20; j++) {
                        if(j%5==0) {
                            byte[] plaintextFromAlice = bobGroupCipher.decrypt(arraySendData[j]);
                            System.out.println("userid:" + obj.getUserId() + "msg:[" + new String(plaintextFromAlice) + "] group key id:" + receivedAliceDistributionMessage.getId() + " key:" + Base64.toBase64String(receivedAliceDistributionMessage.getChainKey()));
                        }
                    }
                }
                //根据加密密码产生群会话信息，为收取消息解密准备


            }

        }



/*
//这里需要加密待发送的消息
    byte[] data=null;
    byte iv[] ={0,1,2,3,4,5,6,7,8,9,1,1,1,1,1,1};
    byte key[]={0,1,2,3,4,5,6,7,8,9,1,1,1,1,1,1,0,1,2,3,4,5,6,7,8,9,1,1,1,1,1,1};
    {
        System.out.println("send data:"+ Base64.toBase64String(sentAliceDistributionMessage.serialize()));
        data=getCipherText(iv, key, sentAliceDistributionMessage.serialize());
       // getCipherText(byte[] iv, byte[] key, byte[] plaintext);

    }
    //解密
    {

       byte[] msgserial= getPlainText(iv,   key,  data);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(msgserial);
        System.out.println("recv data:"+ Base64.toBase64String(msgserial));
        receivedAliceDistributionMessage.getChainKey();
    }

    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

    //其他客户端接收 Alice 的加密密钥，如Bob
    InMemorySenderKeyStore bobStore   = new InMemorySenderKeyStore();
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);
    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);
//发送/收取消息
    //Alice 发送群消息
   // byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("smert ze smert".getBytes());


    //群其他成员接收消息，解密
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, GROUP_SENDER);
    byte[] plaintextFromAlice  = bobGroupCipher.decrypt(ciphertextFromAlice);

   // assertTrue(new String(plaintextFromAlice).equals("smert ze smert"));
*/
    }

    }


//{

/*
    //1.生成key和id generateIdentityKeyPair(), generateRegistrationId()
    SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
    //2.alice端产生alice和bob的会话
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

    //3.bob生成 生成key和id generateIdentityKeyPair(), generateRegistrationId()
    final SignalProtocolStore bobStore                 = new TestInMemorySignalProtocolStore();
    ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
    ECKeyPair    bobSignedPreKeyPair      = Curve.generateKeyPair();
    byte[]       bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
            bobSignedPreKeyPair.getPublicKey().serialize());
//alice 客户端本地从服务端获取bob的这些信息
    PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
            31337, bobPreKeyPair.getPublicKey(),
            22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
            bobStore.getIdentityKeyPair().getPublicKey());
//alice 根据从服务端获取bob的相关key信息，产生会话对象
    aliceSessionBuilder.process(bobPreKey);

    assertTrue(aliceStore.containsSession(BOB_ADDRESS));
    assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);

    final String            originalMessage    = "L'homme est condamné à être libre";
    SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
    CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

    assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

    PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
    bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
    bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

    SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
    byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new DecryptionCallback() {
        @Override
        public void handlePlaintext(byte[] plaintext) {
            assertTrue(originalMessage.equals(new String(plaintext)));
            assertFalse(bobStore.containsSession(ALICE_ADDRESS));
        }
    });

    assertTrue(bobStore.containsSession(ALICE_ADDRESS));
    assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);
    assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey() != null);
    assertTrue(originalMessage.equals(new String(plaintext)));

*/