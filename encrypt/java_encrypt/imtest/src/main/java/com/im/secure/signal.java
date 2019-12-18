package com.im.secure;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.KeyHelper;

public class signal {

    public static void main(String[] args)  {

        try {



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

             IdentityKey publicKeyA=new IdentityKey(HexUtil.decode(strPubtype5A), 0);
             ECPrivateKey privateKeyA= Curve.decodePrivatePoint(HexUtil.decode(strPrivateA));
//b 用户
            String strPubtype5B="0527af1839f1f245dc50cbe84814fbc63891ba61037681623b1fb35de00b394d21";
            String strPrivateB="70a9c351d39983b08466adfd56e47bbf323a27420b95985fe7b12183c98fec56";
            IdentityKey publicKeyB=new IdentityKey(HexUtil.decode(strPubtype5B), 0);
            ECPrivateKey privateKeyB= Curve.decodePrivatePoint(HexUtil.decode(strPrivateB));

//a & b  协商密钥对比：share key calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)

            //byte [] out=Curve.calculateAgreement(publicKeyA.getPublicKey(),privateKeyB);

            String sharekey1=HexUtil.encode(Curve.calculateAgreement(publicKeyA.getPublicKey(),privateKeyB));
            String sharekey2=HexUtil.encode(Curve.calculateAgreement(publicKeyB.getPublicKey(),privateKeyA));

            System.out.println("sharekey b:["+sharekey1+"] sharekey a:"+sharekey2);

           // int registrationId = KeyHelper.generateRegistrationId(true);
          //  int startId = 0;
           // List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 100);
            SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, 5);
            System.out.println( "private:"+ HexUtil.encode(signedPreKey.getKeyPair().getPrivateKey().serialize()));
            System.out.println( "publi:"+ HexUtil.encode(signedPreKey.getKeyPair().getPublicKey().serialize()));
//加密key 的hex：22dcb09b5c98da75397d47d003cddcc9b2b37702e5715c02c28751d94ed65519

            String testStr="hello world";
            String encrypt=HexUtil.encode( Aes256.encryptData(sharekey1.substring(0,32).getBytes(),testStr.getBytes()));
           System.out.println("aes encrypt:"+encrypt);
           byte[] decrypt =  Aes256.decryptData(sharekey1.substring(0,32).getBytes(), HexUtil.decode(encrypt));
            System.out.println("aes decrypt:"+new String(decrypt) );


/*
消息如何使用
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
            deliver(message.serialize());*/
           // System.out.println("test");
        }
        catch (Exception e)
        {

        }
    }


}
