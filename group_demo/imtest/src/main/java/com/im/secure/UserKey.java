package com.im.secure;

import org.whispersystems.libsignal.ecc.ECKeyPair;

public class UserKey
{
    public ECKeyPair getSignedPreKeyPair() {
        return signedPreKeyPair;
    }

    public void setSignedPreKeyPair(ECKeyPair signedPreKeyPair) {
        this.signedPreKeyPair = signedPreKeyPair;
    }

    public ECKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    public void setIdentityKeyPair(ECKeyPair identityKeyPair) {
        this.identityKeyPair = identityKeyPair;
    }

    public int getSignedPreId() {
        return signedPreId;
    }

    public void setSignedPreId(int signedPreId) {
        this.signedPreId = signedPreId;
    }

    public int getIdentityId() {
        return identityId;
    }

    public void setIdentityId(int identityId) {
        this.identityId = identityId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    ECKeyPair signedPreKeyPair;
    ECKeyPair identityKeyPair;
    int signedPreId;
    int identityId;
    Long  userId;
    public  UserKey( Long uid, int identityId, int signedPreId,ECKeyPair identityKeyPair,ECKeyPair  signedPreKeyPair)
    {
        userId = uid;
        this.identityId= identityId;
        this.signedPreId= signedPreId;
        this.signedPreKeyPair =signedPreKeyPair;
        this.identityKeyPair=identityKeyPair;

    }

}
