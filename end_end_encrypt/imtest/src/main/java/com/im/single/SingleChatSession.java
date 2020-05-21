package com.im.single;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.groups.ratchet.SenderChainKey;
import org.whispersystems.libsignal.groups.ratchet.SenderMessageKey;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyState;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.protocol.SenderKeyMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

//一个用户userid+每次设备产生的加密id 作为一个设备会话；
public class SingleChatSession {


    final Object LOCK = new Object();

    private   SenderKeyStore senderKeyStore;//存储解密密码的 缓存；自己的其他设备发送来的或会话另一方发来的密钥
    private   SenderKeyStore selfKeyStore;//存储自己作为发送方的加密密钥相关信息
    public SenderKeyName getSelfSenderKeyName() {
        return selfSenderKeyName;
    }
    public void setSelfSenderKeyName(SenderKeyName selfSenderKeyName) {
        this.selfSenderKeyName = selfSenderKeyName;
    }

    private   SenderKeyName selfSenderKeyName;//发送方自己的信息
    UserKey self;
    UserKey their;
    SignalProtocolAddress selfAddress;
    //name uid
    public SingleChatSession( String name , int deviceId,UserKey self, UserKey their) {
         InMemorySenderKeyStore selfStore = new   InMemorySenderKeyStore();
        InMemorySenderKeyStore senderStore = new   InMemorySenderKeyStore();
         this.self = self;
         this.their=their;
         this.selfAddress= new SignalProtocolAddress(name ,deviceId);
         //1001_1002
         String sessionId=(self.getUserId() > their.getUserId() ? their.getUserId(): self.getUserId())+"_"+(self.getUserId()< their.getUserId() ? their.getUserId(): self.getUserId());
        selfSenderKeyName= new SenderKeyName(sessionId, selfAddress);


        this.selfKeyStore = selfStore;
        this.senderKeyStore = senderStore;
        this.selfSenderKeyName    = selfSenderKeyName;
    }

    public SenderKeyStore getSenderKeyStore() {
        return senderKeyStore;
    }

    public void setSenderKeyStore(SenderKeyStore senderKeyStore) {
        this.senderKeyStore = senderKeyStore;
    }

//    /**
//     * 根据接收的自己 产生的消息构造一个加密会话
//     *
//     * @param senderKeyName The (groupId, senderId, deviceId) tuple associated with the SenderKeyDistributionMessage.
//     * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
//     */
//    public void processFromSelf(SenderKeyName senderKeyName, GroupSenderKeyDistributionMessage senderKeyDistributionMessage) {
//        synchronized (  LOCK) {
//            SenderKeyRecord senderKeyRecord = selfKeyStore.loadSenderKey(senderKeyName);
//            ECKeyPair signatureKey =new ECKeyPair(senderKeyDistributionMessage.getSignatureKey(), senderKeyDistributionMessage.getSignatureKeyPrivate());
//
//            senderKeyRecord.setSenderKeyState(senderKeyDistributionMessage.getId(),
//                    senderKeyDistributionMessage.getIteration(),
//                    senderKeyDistributionMessage.getChainKey(),
//                    signatureKey);
//
//            selfKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
//        }
//    }
    /**
     * 根据接收的消息构造一个加密会话 key: userid1_userid2,userid,deviceid=keyid
     *
     * @param   senderId  userid
     * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
     */
    public void process(String senderId, SenderKeyDistributionMessage senderKeyDistributionMessage) {
        synchronized (  LOCK) {
            SenderKeyName senderKeyName = new SenderKeyName(selfSenderKeyName.getGroupId(),//会话id,
                    new SignalProtocolAddress(senderId,senderKeyDistributionMessage.getId()));

            SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
            senderKeyRecord.addSenderKeyState(senderKeyDistributionMessage.getId(),
                    senderKeyDistributionMessage.getIteration(),
                    senderKeyDistributionMessage.getChainKey(),
                    senderKeyDistributionMessage.getSignatureKey());
            senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
        }
    }
//设置且加载 加密密码；例如从本地数据库加载的时候
//    public SenderKeyDistributionMessage setAndLoad( int keyId, int iteration,  byte[] chainKey, ECKeyPair signatureKey) {
//        synchronized (  LOCK) {
//            try {
//                SenderKeyName senderKeyName=selfSenderKeyName;
//                SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
//
//                if (senderKeyRecord.isEmpty()) {
//                    senderKeyRecord.setSenderKeyState( keyId,
//                            iteration,
//                            chainKey,
//                            signatureKey);
//                    senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
//                }
//
//                SenderKeyState state = senderKeyRecord.getSenderKeyState();
//
//                return new SenderKeyDistributionMessage(state.getKeyId(),
//                        state.getSenderChainKey().getIteration(),
//                        state.getSenderChainKey().getSeed(),
//                        state.getSigningKeyPublic());
//
//            } catch (InvalidKeyIdException | InvalidKeyException e) {
//                throw new AssertionError(e);
//            }
//        }
//    }

    /**
     * 发送端构造加密会话密码
     *
     // @param   The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
     * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
     */
    public SenderKeyDistributionMessage createOrLoad( ) {
        synchronized (  LOCK) {
            try {
                SenderKeyName senderKeyName=selfSenderKeyName;
                SenderKeyRecord senderKeyRecord = selfKeyStore.loadSenderKey(senderKeyName);

               if (senderKeyRecord.isEmpty()) {
                    senderKeyRecord.setSenderKeyState(KeyHelper.generateSenderKeyId(),
                            0,
                            KeyHelper.generateSenderKey(),
                            KeyHelper.generateSenderSigningKey());
                    selfKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
                }

                SenderKeyState state = senderKeyRecord.getSenderKeyState();

                return new SenderKeyDistributionMessage(state.getKeyId(),
                        state.getSenderChainKey().getIteration(),
                        state.getSenderChainKey().getSeed(),
                        state.getSigningKeyPublic());

            } catch (InvalidKeyIdException | InvalidKeyException e) {
                throw new AssertionError(e);
            }
        }
    }
//    /**
//     * 发送端构造加密会话密码 给自己的其他端
//     *
//     * @param senderKeyName The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
//     * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
//     */
//    public GroupSenderKeyDistributionMessage createOrLoadSelf(SenderKeyName senderKeyName) {
//        synchronized (  LOCK) {
//            try {
//                SenderKeyRecord senderKeyRecord = selfKeyStore.loadSenderKey(senderKeyName);
//
//                if (senderKeyRecord.isEmpty()) {
//                    senderKeyRecord.setSenderKeyState(KeyHelper.generateSenderKeyId(),
//                            0,
//                            KeyHelper.generateSenderKey(),
//                            KeyHelper.generateSenderSigningKey());
//                    selfKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
//                }
//
//                SenderKeyState state = senderKeyRecord.getSenderKeyState();
//
//                return new GroupSenderKeyDistributionMessage(state.getKeyId(),
//                        state.getSenderChainKey().getIteration(),
//                        state.getSenderChainKey().getSeed(),
//                        state.getSigningKeyPublic(),state.getSigningKeyPrivate());
//
//
//            } catch (InvalidKeyIdException | InvalidKeyException e) {
//                throw new AssertionError(e);
//            }
//        }
//    }




    /**
     * Encrypt a message.
     *
     * @param paddedPlaintext The plaintext message bytes, optionally padded.
     * @return Ciphertext.
     * @throws NoSessionException
     */
    public byte[] encrypt(byte[] paddedPlaintext) throws NoSessionException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord  record         = selfKeyStore.loadSenderKey(selfSenderKeyName);
                SenderKeyState senderKeyState = record.getSenderKeyState();
                SenderMessageKey senderKey      = senderKeyState.getSenderChainKey().getSenderMessageKey();
                byte[]           ciphertext     = getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext);

                SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyState.getKeyId(),
                        senderKey.getIteration(),
                        ciphertext,
                        senderKeyState.getSigningKeyPrivate());

                senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());

                selfKeyStore.storeSenderKey(selfSenderKeyName, record);

                return senderKeyMessage.serialize();
            } catch (InvalidKeyIdException e) {
                throw new NoSessionException(e);
            }
        }
    }

    /**
     * Decrypt a SenderKey group message.
     *
     * @param senderKeyMessageBytes The received ciphertext.
     * @return Plaintext
     * @throws LegacyMessageException
     * @throws InvalidMessageException
     * @throws DuplicateMessageException
     */
    public byte[] decrypt(byte[] senderKeyMessageBytes,String senderId)
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
    {
        return decrypt(senderKeyMessageBytes, senderId, new  NullDecryptionCallback());
    }

    /**
     * Decrypt a SenderKey group message.
     *
     * @param senderKeyMessageBytes The received ciphertext.
     * @param callback   A callback that is triggered after decryption is complete,
     *                    but before the updated session state has been committed to the session
     *                    DB.  This allows some implementations to store the committed plaintext
     *                    to a DB first, in case they are concerned with a crash happening between
     *                    the time the session state is updated but before they're able to store
     *                    the plaintext to disk.
     * @return Plaintext
     * @throws LegacyMessageException
     * @throws InvalidMessageException
     * @throws DuplicateMessageException
     */
    public byte[] decrypt(byte[] senderKeyMessageBytes,String senderId, DecryptionCallback callback)
            throws LegacyMessageException, InvalidMessageException, DuplicateMessageException,
            NoSessionException
    {
        synchronized (LOCK) {
            try {

                SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyMessageBytes);

                SignalProtocolAddress sender=new SignalProtocolAddress(senderId ,senderKeyMessage.getKeyId());
                SenderKeyName senderKeyName = new SenderKeyName(selfSenderKeyName.getGroupId(),sender);
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyName);

                if (record.isEmpty()) {
                    throw new NoSessionException("No sender key for: " + senderKeyName);
                }
                SenderKeyState   senderKeyState   = record.getSenderKeyState(senderKeyMessage.getKeyId());

                senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());

                SenderMessageKey senderKey = getSenderKey(senderKeyState, senderKeyMessage.getIteration());

                byte[] plaintext = getPlainText(senderKey.getIv(), senderKey.getCipherKey(), senderKeyMessage.getCipherText());

                callback.handlePlaintext(plaintext);

                senderKeyStore.storeSenderKey(senderKeyName, record);

                return plaintext;
            } catch (org.whispersystems.libsignal.InvalidKeyException | InvalidKeyIdException e) {
                throw new InvalidMessageException(e);
            }
        }
    }

    private SenderMessageKey getSenderKey(SenderKeyState senderKeyState, int iteration)
            throws DuplicateMessageException, InvalidMessageException
    {
        SenderChainKey senderChainKey = senderKeyState.getSenderChainKey();

        if (senderChainKey.getIteration() > iteration) {
            if (senderKeyState.hasSenderMessageKey(iteration)) {
                return senderKeyState.removeSenderMessageKey(iteration);
            } else {
                throw new DuplicateMessageException("Received message with old counter: " +
                        senderChainKey.getIteration() + " , " + iteration);
            }
        }

        /*if (iteration - senderChainKey.getIteration() > 2000) {
            throw new InvalidMessageException("Over 2000 messages into the future!");
        }*/

        while (senderChainKey.getIteration() < iteration) {
            senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
            senderChainKey = senderChainKey.getNext();
        }

        senderKeyState.setSenderChainKey(senderChainKey.getNext());
        return senderChainKey.getSenderMessageKey();
    }

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

    private byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher          cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);

            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException | java.security.InvalidKeyException e)
        {
            throw new AssertionError(e);
        }
    }

    private static class NullDecryptionCallback implements DecryptionCallback {
        @Override
        public void handlePlaintext(byte[] plaintext) {}
    }





}
