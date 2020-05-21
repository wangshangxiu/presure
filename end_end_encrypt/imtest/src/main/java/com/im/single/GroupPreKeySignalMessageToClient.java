package com.im.single;


import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;

class GroupPreKeySignalMessageToClient implements CiphertextMessage {
  private   int               version;
  private   int               registrationId;
  private   int                 preKeyId;
  private   int               signedPreKeyId;
  private ECPublicKey baseKey;
  private   ECPublicKey       identityKey;
  private long                  userId;
  private   byte[]            serialized;
  byte[] message;

  public ECPublicKey getIdentityKey() {
      return identityKey;
  }

  public void setIdentityKey(ECPublicKey identityKey) {
      this.identityKey = identityKey;
  }

  public long getUserId() {
      return userId;
  }

  public void setUserId(long userId) {
      this.userId = userId;
  }

  public int getVersion() {
      return version;
  }

  public void setVersion(int version) {
      this.version = version;
  }

  public int getRegistrationId() {
      return registrationId;
  }

  public void setRegistrationId(int registrationId) {
      this.registrationId = registrationId;
  }

  public int getPreKeyId() {
      return preKeyId;
  }

  public void setPreKeyId(int preKeyId) {
      this.preKeyId = preKeyId;
  }

  public int getSignedPreKeyId() {
      return signedPreKeyId;
  }

  public void setSignedPreKeyId(int signedPreKeyId) {
      this.signedPreKeyId = signedPreKeyId;
  }

  public ECPublicKey getBaseKey() {
      return baseKey;
  }

  public void setBaseKey(ECPublicKey baseKey) {
      this.baseKey = baseKey;
  }





  public byte[] getSerialized() {
      return serialized;
  }

  public void setSerialized(byte[] serialized) {
      this.serialized = serialized;
  }

  public byte[] getMessage() {
      return message;
  }

  public void setMessage(byte[] message) {
      this.message = message;
  }

  @Override
  public byte[] serialize() {
      return new byte[0];
  }

  @Override
  public int getType() {
      return 0;
  }
}
