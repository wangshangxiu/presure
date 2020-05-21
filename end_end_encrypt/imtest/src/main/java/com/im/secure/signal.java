package com.im.secure;

import junit.framework.TestCase;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Pair;

import java.util.HashSet;
import java.util.Set;

import static com.im.secure.signal.test11;

public class signal {


    public static  void  test11(){

        System.out.println(2 * Integer.MAX_VALUE);
        System.out.println(2*Integer.MIN_VALUE) ;

    }
   // public static  int  test11( ){ System.out.println(1);}
    //public int static test11(){ System.out.println(1);}
    public static void main(String[] args)  {

        try {
            test11();



          //  testBasicPreKeyV3();


          //  IdentityKeyPair    identityKeyPair = KeyHelper.generateIdentityKeyPair();
           // int                registrationId  = KeyHelper.generateRegistrationId();
           // List<PreKeyRecord> preKeys         = KeyHelper.generatePreKeys(startId, 100);
           // SignedPreKeyRecord signedPreKey    = KeyHelper.generateSignedPreKey(identityKeyPair, 5);

// Store identityKeyPair somewhere durable and safe.
// Store registrationId somewhere durable and safe.

// Store preKeys in PreKeyStore.
// Store signed prekey in SignedPreKeyStore.
//Curve25519 产生公司密钥对例子：

            /*
            private:e0df8409f502d9077964b6812310040d0852b20255306b4e2c2d3f0067be4654
publi:05fdcb579adbc60ccba1471aa9f91114a3720da3013754b4df0e21ac0224f3b212
presignedkey:
private:6050afcf88e8d946342eafe2374ac7c029f8fa5a002d35f69af12801fbe85c60
publi:0595d8a98a6a0212277e6e9db95b520273496d0d7eb6c8e6e1dc7f11a195efd908
             */
            //产生身份id公钥私钥
            IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
            System.out.println( "private:"+ HexUtil.encode(identityKeyPair.getPrivateKey().serialize()));
            System.out.println( "publi:"+ HexUtil.encode(identityKeyPair.getPublicKey().serialize()));

//
// a 用户
            String strPubtype5A="05fdcb579adbc60ccba1471aa9f91114a3720da3013754b4df0e21ac0224f3b212";
            String strPrivateA="e0df8409f502d9077964b6812310040d0852b20255306b4e2c2d3f0067be4654";

           // strPubtype5A="056F78C81974614171B0DF6CD3F66E529A73E0EC9076E2BB47D78B0C9BD1ABA22B";
           // strPrivateA="D0A721B338EAF0E6D8CCC47D4F8A934C680EC33A223A059117EE4783289B3D69";


             IdentityKey publicKeyA=new IdentityKey(HexUtil.decode(strPubtype5A), 0);
             ECPrivateKey privateKeyA= Curve.decodePrivatePoint(HexUtil.decode(strPrivateA));
//b 用户
            String strPubtype5B="0527af1839f1f245dc50cbe84814fbc63891ba61037681623b1fb35de00b394d21";
            String strPrivateB="70a9c351d39983b08466adfd56e47bbf323a27420b95985fe7b12183c98fec56";

            //       strPubtype5B="0529B09B9794AF91F8AB5D19B3BBA4CFF283FCFB4CB704F43060654D16F014EE78";
           // strPrivateB="C0AF56015D4A5C1CD00CA7FDEE56E64D08582A655025FA95E9CD26076AAE6268";
            IdentityKey publicKeyB=new IdentityKey(HexUtil.decode(strPubtype5B), 0);
            ECPrivateKey privateKeyB= Curve.decodePrivatePoint(HexUtil.decode(strPrivateB));

//a & b  协商密钥对比：share key calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)

            //byte [] out=Curve.calculateAgreement(publicKeyA.getPublicKey(),privateKeyB);

            String sharekey1=HexUtil.encode(Curve.calculateAgreement(publicKeyA.getPublicKey(),privateKeyB));
            String sharekey2=HexUtil.encode(Curve.calculateAgreement(publicKeyB.getPublicKey(),privateKeyA));

            System.out.println("sharkey compare result:"+sharekey1.equals(sharekey2)+"\nsharekey b:["+sharekey1+"] \nsharekey a:["+sharekey2+"]");

           // int registrationId = KeyHelper.generateRegistrationId(true);
          //  int startId = 0;
           // List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 100);
            SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, 5);
            System.out.println( "private:"+ HexUtil.encode(signedPreKey.getKeyPair().getPrivateKey().serialize()));
            System.out.println( "publi:"+ HexUtil.encode(signedPreKey.getKeyPair().getPublicKey().serialize()));
//加密key 的hex：22dcb09b5c98da75397d47d003cddcc9b2b37702e5715c02c28751d94ed65519

            String testStr="hello world!";
            String encrypt=HexUtil.encode( Aes256.encryptData(sharekey1.substring(0,32).getBytes(),testStr.getBytes()));
           System.out.println("aes encrypt:"+encrypt);
           byte[] decrypt =  Aes256.decryptData(sharekey1.substring(0,32).getBytes(), HexUtil.decode(encrypt));
            System.out.println("aes decrypt:"+new String(decrypt) );



//消息如何使用
           /* {
            SessionStore sessionStore = new MySessionStore();
            PreKeyStore preKeyStore = new MyPreKeyStore();
            SignedPreKeyStore signedPreKeyStore = new MySignedPreKeyStore();
            IdentityKeyStore identityStore = new MyIdentityKeyStore();
//Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
            SessionBuilder sessionBuilder = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                    identityStore, recipientId, deviceId);
//Build a session with a PreKey retrieved from the server.
            sessionBuilder.process(retrievedPreKey);
            SessionCipher sessionCipher = new SessionCipher(sessionStore, recipientId, deviceId);
            CiphertextMessage message = sessionCipher.encrypt("Hello world!".getBytes("UTF-8"));
            deliver(message.serialize());}*/
           // System.out.println("test");
        }
        catch (Exception e)
        {

        }
    }
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14152222222", 1);
   static public void testBasicPreKeyV3()
            throws InvalidKeyException, InvalidVersionException, InvalidMessageException, InvalidKeyIdException, DuplicateMessageException, LegacyMessageException, UntrustedIdentityException, NoSessionException {
        SignalProtocolStore aliceStore          = new TestInMemorySignalProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);

        final SignalProtocolStore bobStore                 = new TestInMemorySignalProtocolStore();
        ECKeyPair bobPreKeyPair            = Curve.generateKeyPair();
        ECKeyPair    bobSignedPreKeyPair      = Curve.generateKeyPair();
        byte[]       bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().serialize());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(),
                bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);

        TestCase.assertTrue(aliceStore.containsSession(BOB_ADDRESS));
       TestCase.assertTrue(aliceStore.loadSession(BOB_ADDRESS).getSessionState().getSessionVersion() == 3);

        final String            originalMessage    = "L'homme est condamné à être libre";
        SessionCipher     aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        CiphertextMessage outgoingMessage    = aliceSessionCipher.encrypt(originalMessage.getBytes());

       TestCase.assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

        PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.serialize());
        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
        byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new DecryptionCallback() {
            @Override
            public void handlePlaintext(byte[] plaintext) {
                TestCase.assertTrue(originalMessage.equals(new String(plaintext)));
               // TestCase.assertTrue(bobStore.containsSession(ALICE_ADDRESS));
            }
        });

       TestCase.assertTrue(bobStore.containsSession(ALICE_ADDRESS));
       TestCase.assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getSessionVersion() == 3);
       TestCase.assertTrue(bobStore.loadSession(ALICE_ADDRESS).getSessionState().getAliceBaseKey() != null);
       TestCase.assertTrue(originalMessage.equals(new String(plaintext)));

        CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
       TestCase.assertTrue(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobOutgoingMessage.serialize()));
       TestCase.assertTrue(new String(alicePlaintext).equals(originalMessage));

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
       TestCase.assertTrue(new String(plaintext).equals(originalMessage));

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
    static private void runInteraction(SignalProtocolStore aliceStore, SignalProtocolStore bobStore)
            throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException
    {
        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        SessionCipher bobSessionCipher   = new SessionCipher(bobStore, ALICE_ADDRESS);

        String originalMessage = "smert ze smert";
        CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        TestCase.assertTrue(aliceMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        byte[] plaintext = bobSessionCipher.decrypt(new SignalMessage(aliceMessage.serialize()));

        TestCase.assertTrue(new String(plaintext).equals(originalMessage));

        CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        TestCase.assertTrue(bobMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        plaintext = aliceSessionCipher.decrypt(new SignalMessage(bobMessage.serialize()));
        TestCase.assertTrue(new String(plaintext).equals(originalMessage));

        for (int i=0;i<10;i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceLoopingMessage.serialize()));
            TestCase.assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (int i=0;i<10;i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
            TestCase.assertTrue(new String(loopingPlaintext).equals(loopingMessage));
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
            TestCase.assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (int i=0;i<10;i++) {
            String loopingMessage = ("You can only desire based on what you know: " + i);
            CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = aliceSessionCipher.decrypt(new SignalMessage(bobLoopingMessage.serialize()));
            TestCase.assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
            byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new SignalMessage(aliceOutOfOrderMessage.second().serialize()));
            TestCase.assertTrue(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
        }
    }



}
