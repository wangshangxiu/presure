package com.im.secure;

import junit.framework.TestCase;

import org.bouncycastle.util.encoders.Base64;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.*;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Pair;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
  class GroupTestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
    public GroupTestInMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
        //super(generateIdentityKeyPair(), generateRegistrationId());
        super( identityKeyPair, registrationId);
    }

    public static IdentityKeyPair generateIdentityKeyPair() {
        ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

        return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                identityKeyPairKeys.getPrivateKey());
    }

    public  static int generateRegistrationId() {
        return KeyHelper.generateRegistrationId(false);
    }
}
    class DerivedKeys {
    private final RootKey   rootKey;
    private final ChainKey  chainKey;

    private DerivedKeys(RootKey rootKey, ChainKey chainKey) {
        this.rootKey   = rootKey;
        this.chainKey  = chainKey;
    }

    public RootKey getRootKey() {
        return rootKey;
    }

    public ChainKey getChainKey() {
        return chainKey;
    }
}


class GroupMessageKeys extends MessageKeys {

    public GroupMessageKeys(SecretKeySpec cipherKey, SecretKeySpec macKey, IvParameterSpec iv, int counter) {
        super(cipherKey, macKey, iv, counter);
    }
}


public class SessionBuilderTest extends TestCase {

    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14152222222", 1);

    public void testBasicPreKeyV2()
            throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore      = new TestInMemorySignalProtocolStore();
        ECKeyPair    bobPreKeyPair = Curve.generateKeyPair();
        PreKeyBundle bobPreKey     = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                0, null, null,
                bobStore.getIdentityKeyPair().getPublicKey());

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new AssertionError("Should fail with missing unsigned prekey!");
        } catch (InvalidKeyException e) {
            // Good!
            return;
        }
    }
//
private static byte[] getDiscontinuityBytes() {
    byte[] discontinuity = new byte[32];
    Arrays.fill(discontinuity, (byte) 0xFF);
    return discontinuity;
}


    public void testBasicPreKeyV3group()
            throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
        //1.生成key和id generateIdentityKeyPair(), generateRegistrationId()
        /*SignalProtocolStore aliceStore          = new GroupTestInMemorySignalProtocolStore(
                GroupTestInMemorySignalProtocolStore.generateIdentityKeyPair(),
                GroupTestInMemorySignalProtocolStore.generateRegistrationId());
        //2.alice端产生alice和bob的会话
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        //3.bob生成 生成key和id generateIdentityKeyPair(), generateRegistrationId()
        final SignalProtocolStore bobStore                 =  new GroupTestInMemorySignalProtocolStore(
                GroupTestInMemorySignalProtocolStore.generateIdentityKeyPair(),
                GroupTestInMemorySignalProtocolStore.generateRegistrationId());
        ECKeyPair    bobPreKeyPair            = Curve.generateKeyPair();
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

        CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
*/


        try {
//发送端角度
            ECKeyPair ourEinitiatorBaseKey = Curve.generateKeyPair();//Einitiator

            ECKeyPair ourIdentityKeyPair = Curve.generateKeyPair();
            IdentityKeyPair ourIdentityKeyPairKeys = new IdentityKeyPair(new IdentityKey(ourIdentityKeyPair.getPublicKey()),
                    ourIdentityKeyPair.getPrivateKey());


            ECKeyPair theirSignedPreKeyPair = Curve.generateKeyPair();
            ECKeyPair theirIdentityKeyPair = Curve.generateKeyPair();

//发送者
            {



                ByteArrayOutputStream secrets = new ByteArrayOutputStream();

                 //secrets.write(getDiscontinuityBytes());

                secrets.write(Curve.calculateAgreement(theirSignedPreKeyPair.getPublicKey(), ourIdentityKeyPair.getPrivateKey()));
                secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorBaseKey.getPrivateKey()));
                secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorBaseKey.getPrivateKey()));

                {
                    HKDF kdf = new HKDFv3();
                    byte[] derivedSecretBytes = kdf.deriveSecrets(secrets.toByteArray(), "WhisperText".getBytes(), 64);
                    byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);
                    //协商的加密key
                    byte[] shareEncryptKey = derivedSecrets[0];
                    //System.out.println("send sharekey:"+HexUtil.encode(secrets.toByteArray()));
                    System.out.println("send sharekey kdf:"+Base64.toBase64String(shareEncryptKey));
                }

            }
//接收端解密
            {

                ECKeyPair theirEmpBaseKey2 =ourEinitiatorBaseKey;//Einitiator

                ECKeyPair theirIdentityKeyPair2=ourIdentityKeyPair;




                ECKeyPair ourSignedPreKeyPair2 = theirSignedPreKeyPair;
                ECKeyPair ourIdentityKeyPair2 = theirIdentityKeyPair;


                ByteArrayOutputStream secretsRecv = new ByteArrayOutputStream();

                //secretsRecv.write(getDiscontinuityBytes());

                secretsRecv.write(Curve.calculateAgreement(theirIdentityKeyPair2.getPublicKey(),
                        ourSignedPreKeyPair2.getPrivateKey()));
                secretsRecv.write(Curve.calculateAgreement(theirEmpBaseKey2.getPublicKey(),
                        ourIdentityKeyPair2.getPrivateKey()));
                secretsRecv.write(Curve.calculateAgreement(theirEmpBaseKey2.getPublicKey(),
                        ourIdentityKeyPair2.getPrivateKey()));


                {


                    HKDF kdf = new HKDFv3();
                    byte[] derivedSecretBytes = kdf.deriveSecrets(secretsRecv.toByteArray(), "WhisperText".getBytes(), 64);
                    byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);
                    //协商的加密key
                    byte[] shareEncryptKeyRecv = derivedSecrets[0];
                    //System.out.println("recv sharekey:"+HexUtil.encode(secretsRecv.toByteArray()));
                    System.out.println("recv sharekey kdf:"+Base64.toBase64String(shareEncryptKeyRecv));


                }
            }

        } catch (IOException e) {
            throw new AssertionError(e);
        }

//自己对自己 测试

        try {
//发送端角度
            ECKeyPair ourEinitiatorBaseKey = Curve.generateKeyPair();//Einitiator

            ECKeyPair ourIdentityKeyPair = Curve.generateKeyPair();
            ECKeyPair ourSignedPreKeyPair = Curve.generateKeyPair();


            ECKeyPair theirSignedPreKeyPair = ourSignedPreKeyPair;
            ECKeyPair theirIdentityKeyPair = ourIdentityKeyPair;

//发送者
            {



                ByteArrayOutputStream secrets = new ByteArrayOutputStream();

                //secrets.write(getDiscontinuityBytes());

                secrets.write(Curve.calculateAgreement(theirSignedPreKeyPair.getPublicKey(), ourIdentityKeyPair.getPrivateKey()));
                secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorBaseKey.getPrivateKey()));
                secrets.write(Curve.calculateAgreement(theirIdentityKeyPair.getPublicKey(), ourEinitiatorBaseKey.getPrivateKey()));

                {
                    HKDF kdf = new HKDFv3();
                    byte[] derivedSecretBytes = kdf.deriveSecrets(secrets.toByteArray(), "WhisperText".getBytes(), 64);
                    byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);
                    //协商的加密key
                    byte[] shareEncryptKey = derivedSecrets[1];
                    //System.out.println("send sharekey:"+HexUtil.encode(secrets.toByteArray()));
                    System.out.println("2 send sharekey kdf:"+Base64.toBase64String(shareEncryptKey));
                }

            }
//接收端解密
            {

                ECKeyPair theirEmpBaseKey2 =ourEinitiatorBaseKey;//Einitiator

                ECKeyPair theirIdentityKeyPair2=ourIdentityKeyPair;




                ECKeyPair ourSignedPreKeyPair2 = theirSignedPreKeyPair;
                ECKeyPair ourIdentityKeyPair2 = theirIdentityKeyPair;


                ByteArrayOutputStream secretsRecv = new ByteArrayOutputStream();

                //secretsRecv.write(getDiscontinuityBytes());

                secretsRecv.write(Curve.calculateAgreement(theirIdentityKeyPair2.getPublicKey(),
                        ourSignedPreKeyPair2.getPrivateKey()));
                secretsRecv.write(Curve.calculateAgreement(theirEmpBaseKey2.getPublicKey(),
                        ourIdentityKeyPair2.getPrivateKey()));
                secretsRecv.write(Curve.calculateAgreement(theirEmpBaseKey2.getPublicKey(),
                        ourIdentityKeyPair2.getPrivateKey()));


                {


                    HKDF kdf = new HKDFv3();
                    byte[] derivedSecretBytes = kdf.deriveSecrets(secretsRecv.toByteArray(), "WhisperText".getBytes(), 64);
                    byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);
                    //协商的加密key
                    byte[] shareEncryptKeyRecv = derivedSecrets[1];
                    //System.out.println("recv sharekey:"+HexUtil.encode(secretsRecv.toByteArray()));
                    System.out.println("2 recv sharekey kdf:"+Base64.toBase64String(shareEncryptKeyRecv));


                }
            }

        } catch (IOException e) {
            throw new AssertionError(e);
        }



    }

    public void testBasicPreKeyV3()
            throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
        //1.生成key和id generateIdentityKeyPair(), generateRegistrationId()
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        //2.alice端产生alice和bob的会话
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        //3.bob生成 生成key和id generateIdentityKeyPair(), generateRegistrationId()
        final SignalProtocolStore bobStore                 = new TestInMemorySignalProtocolStore();
        ECKeyPair    bobPreKeyPair            = Curve.generateKeyPair();
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

        CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
        assertTrue(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
        assertTrue(new String(alicePlaintext).equals(originalMessage));

        runInteraction(aliceStore, bobStore);

        aliceStore          = new TestInMemorySignalProtocolStore();
        aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
        aliceSessionCipher  = new SessionCipher(aliceStore, BOB_ADDRESS);

        bobPreKeyPair            = Curve.generateKeyPair();
        bobSignedPreKeyPair      = Curve.generateKeyPair();
        bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(), bobSignedPreKeyPair.getPublicKey().serialize());
        bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(),
                1, 31338, bobPreKeyPair.getPublicKey(),
                23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(23, new SignedPreKeyRecord(23, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
        aliceSessionBuilder.process(bobPreKey);

        outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        try {
            plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
            throw new AssertionError("shouldn't be trusted!");
        } catch (UntrustedIdentityException uie) {
            bobStore.saveIdentity(ALICE_ADDRESS, new PreKeySignalMessage(outgoingMessage.serialize()).getIdentityKey());
        }

        plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(outgoingMessage.serialize()));
        assertTrue(new String(plaintext).equals(originalMessage));

        bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, Curve.generateKeyPair().getPublicKey(),
                23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                aliceStore.getIdentityKeyPair().getPublicKey());

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new AssertionError("shoulnd't be trusted!");
        } catch (UntrustedIdentityException uie) {
            // good
        }
    }

    public void testBadSignedPreKeySignature() throws InvalidKeyException, UntrustedIdentityException {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        IdentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

        ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
        byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobIdentityKeyStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().serialize());


        for (int i=0;i<bobSignedPreKeySignature.length * 8;i++) {
            byte[] modifiedSignature = new byte[bobSignedPreKeySignature.length];
            System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

            modifiedSignature[i/8] ^= (0x01 << (i % 8));

            PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
                    31337, bobPreKeyPair.getPublicKey(),
                    22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
                    bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

            try {
                aliceSessionBuilder.process(bobPreKey);
                throw new AssertionError("Accepted modified device key signature!");
            } catch (InvalidKeyException ike) {
                // good
            }
        }

        PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);
    }

    public void testRepeatBundleMessageV2() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
        byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().serialize());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                0, null, null,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new AssertionError("Should fail with missing signed prekey!");
        } catch (InvalidKeyException e) {
            // Good!
            return;
        }
    }

    public void testRepeatBundleMessageV3() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, NoSessionException {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
        byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().serialize());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        aliceSessionBuilder.process(bobPreKey);

        String            originalMessage    = "L'homme est condamné à être libre";
        SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
        CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);
        assertTrue(outgoingMessageTwo.getType() == CiphertextMessage.PREKEY_TYPE);

        PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.serialize());

        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);
        assertTrue(originalMessage.equals(new String(plaintext)));

        CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
        assertTrue(originalMessage.equals(new String(alicePlaintext)));

        // The test

        PreKeySignalMessage incomingMessageTwo = new PreKeySignalMessage(outgoingMessageTwo.serialize());

        plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(incomingMessageTwo.serialize()));
        assertTrue(originalMessage.equals(new String(plaintext)));

        bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
        alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
        assertTrue(originalMessage.equals(new String(alicePlaintext)));

    }

    public void testBadMessageBundle() throws InvalidKeyException, UntrustedIdentityException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
        byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().serialize());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        aliceSessionBuilder.process(bobPreKey);

        String            originalMessage    = "L'homme est condamné à être libre";
        SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

        byte[] goodMessage = outgoingMessageOne.serialize();
        byte[] badMessage  = new byte[goodMessage.length];
        System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

        badMessage[badMessage.length-10] ^= 0x01;

        PreKeySignalMessage incomingMessage  = new PreKeySignalMessage(badMessage);
        SessionCipher        bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        byte[] plaintext = new byte[0];

        try {
            plaintext = bobSessionCipher.decrypt(incomingMessage);
            throw new AssertionError("Decrypt should have failed!");
        } catch (InvalidMessageException e) {
            // good.
        }

        assertTrue(bobStore.containsPreKey(31337));

        plaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(goodMessage));

        assertTrue(originalMessage.equals(new String(plaintext)));
        assertTrue(!bobStore.containsPreKey(31337));
    }

    public void testOptionalOneTimePreKey() throws Exception {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair      = Curve.generateKeyPair();
        byte[]    bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().serialize());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                0, null,
                22, bobSignedPreKeyPair.getPublicKey(),
                bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);

        assertTrue(aliceStore.containsSession(BOB_ADDRESS));
        assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);

        String            originalMessage    = "L'homme est condamné à être libre";
        SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

        PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
        assertTrue(!incomingMessage.getPreKeyId().isPresent());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
        byte[]        plaintext        = bobSessionCipher.decrypt(incomingMessage);

        assertTrue(bobStore.containsSession(ALICE_ADDRESS));
        assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);
        assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey() != null);
        assertTrue(originalMessage.equals(new String(plaintext)));
    }


    private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
            throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException
    {
        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher   = new SessionCipher(bobStore, ALICE_ADDRESS);

        String originalMessage = "smert ze smert";
        CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(aliceMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));
        assertTrue(new String(plaintext).equals(originalMessage));

        CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(bobMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
        assertTrue(new String(plaintext).equals(originalMessage));

        for (int i=0;i<10;i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (int i=0;i<10;i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        Set<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

        for (int i=0;i<10;i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
        }

        for (int i=0;i<10;i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (int i=0;i<10;i++) {
            String loopingMessage = ("You can only desire based on what you know: " + i);
            CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
            byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
            assertTrue(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
        }
    }


}