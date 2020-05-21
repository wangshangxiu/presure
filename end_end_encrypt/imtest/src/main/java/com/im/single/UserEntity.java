package com.im.single;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore;
import org.whispersystems.libsignal.util.KeyHelper;

public class UserEntity {
    private final SignalProtocolStore store;
    private final PreKeyBundle otherKeyBundle;
    private final SignalProtocolAddress address;


    public UserEntity(int registrationId, IdentityKeyPair    identityKeyPair0,int preKeyId,ECKeyPair preKeyPair,
                      int signedPreKeyId,ECKeyPair signedPreKeyPair,  String address,int deviceId)
            throws InvalidKeyException
    {
        IdentityKeyPair identityKeyPair = new IdentityKeyPair(identityKeyPair0.getPublicKey(),identityKeyPair0.getPrivateKey());
        this.address = new SignalProtocolAddress(address, deviceId);
        this.store = new InMemorySignalProtocolStore(
                identityKeyPair,
                registrationId);

        long timestamp = System.currentTimeMillis();

        byte[] signedPreKeySignature = Curve.calculateSignature(
                identityKeyPair.getPrivateKey(),
                signedPreKeyPair.getPublicKey().serialize());

        IdentityKey identityKey = identityKeyPair.getPublicKey();
        ECPublicKey preKeyPublic = preKeyPair.getPublicKey();
        ECPublicKey signedPreKeyPublic = signedPreKeyPair.getPublicKey();

        this.otherKeyBundle = new PreKeyBundle(
                registrationId,
                deviceId,
                preKeyId,
                preKeyPublic,
                signedPreKeyId,
                signedPreKeyPublic,
                signedPreKeySignature,
                identityKey);

        PreKeyRecord preKeyRecord = new PreKeyRecord(otherKeyBundle.getPreKeyId(), preKeyPair);
        SignedPreKeyRecord signedPreKeyRecord = new SignedPreKeyRecord(
                signedPreKeyId, timestamp, signedPreKeyPair, signedPreKeySignature);

        store.storePreKey(preKeyId, preKeyRecord);
        store.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord);
    }

    public UserEntity(String address,int deviceId)
            throws InvalidKeyException
    {

        int preKeyId=KeyHelper.generateRegistrationId(true);
        int signedPreKeyId=KeyHelper.generateRegistrationId(true);
        this.address = new SignalProtocolAddress(address, deviceId);
        this.store = new InMemorySignalProtocolStore(
                KeyHelper.generateIdentityKeyPair(),
                KeyHelper.generateRegistrationId(true));
        IdentityKeyPair identityKeyPair = store.getIdentityKeyPair();
        int registrationId = store.getLocalRegistrationId();

        ECKeyPair preKeyPair = Curve.generateKeyPair();
        ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
       // int deviceId = 1;
        long timestamp = System.currentTimeMillis();

        byte[] signedPreKeySignature = Curve.calculateSignature(
                identityKeyPair.getPrivateKey(),
                signedPreKeyPair.getPublicKey().serialize());

        IdentityKey identityKey = identityKeyPair.getPublicKey();
        ECPublicKey preKeyPublic = preKeyPair.getPublicKey();
        ECPublicKey signedPreKeyPublic = signedPreKeyPair.getPublicKey();

        this.otherKeyBundle = new PreKeyBundle(
                registrationId,
                deviceId,
                preKeyId,
                preKeyPublic,
                signedPreKeyId,
                signedPreKeyPublic,
                signedPreKeySignature,
                identityKey);

        PreKeyRecord preKeyRecord = new PreKeyRecord(otherKeyBundle.getPreKeyId(), preKeyPair);
        SignedPreKeyRecord signedPreKeyRecord = new SignedPreKeyRecord(
                signedPreKeyId, timestamp, signedPreKeyPair, signedPreKeySignature);

        store.storePreKey(preKeyId, preKeyRecord);
        store.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord);
    }

    public UserEntity(  String address  )
            throws InvalidKeyException
    {
        this(   address,1);

    }
    public SignalProtocolStore getStore() {
        return store;
    }

    public PreKeyBundle getOtherKeyBundle() {
        return otherKeyBundle;
    }

    public SignalProtocolAddress getAddress() {
        return address;
    }
}