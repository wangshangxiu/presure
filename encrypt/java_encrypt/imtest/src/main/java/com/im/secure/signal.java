package com.im.secure;

import com.example.imtest.ImtestApplication;
import org.springframework.boot.SpringApplication;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.List;

public class signal {

    public static void main(String[] args)  {

        try {
//Curve25519 产生公司密钥对例子：
            IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
            System.out.println( "private:"+ HexUtil.encode(identityKeyPair.getPrivateKey().serialize()));
            System.out.println( "public:"+ HexUtil.encode(identityKeyPair.getPublicKey().serialize()));



           // int registrationId = KeyHelper.generateRegistrationId(true);
          //  int startId = 0;
           // List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 100);
            //SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, 5);

/*
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
            System.out.println("test");
        }
        catch (Exception e)
        {

        }
    }


}
