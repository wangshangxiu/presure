package com.im.single;
/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.im.secure.SinglePreKeyMessageProtobuf;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libsignal.util.ByteUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;


class SinglePreKeySignalMessageToServer implements CiphertextMessage {

  private   int               version;
  private   byte[]      chainKey;//old_keyVersion/new_keyVersion/srcuid/deviceid/encrytypekey////
     private byte[]  macKey;
  private byte[] srcDeviceId;//源设备id
  long  old_keyVersion;//本地加密key版本 t*keyId;
  long  new_keyVersion;//最新生成的key的版本号  t*keyId;
  private   ECPublicKey       baseKeyEinitiator;//l临时key
  private   ECPublicKey       identityKeyIinitiator;//身份key
  private   byte[]            serialized;

//解析成 各个成员的报
  public SinglePreKeySignalMessageToServer(byte[] serialized, ConcurrentHashMap<Long,  UserKey> userHashMap)
          throws InvalidMessageException, InvalidVersionException
  {
      try {
          this.version = ByteUtil.highBitsToInt(serialized[0]);

          if (this.version > CiphertextMessage.CURRENT_VERSION) {
              throw new InvalidVersionException("Unknown version: " + this.version);
          }

          if (this.version < CiphertextMessage.CURRENT_VERSION) {
              throw new LegacyMessageException("Legacy version: " + this.version);
          }



          GroupPretypeMsgProtobuf.SendMsgStateReq preKeyWhisperMessage =GroupPretypeMsgProtobuf.SendMsgStateReq.parseFrom( ByteString.copyFrom(serialized, 1,
                      serialized.length-1));

         /* if (!preKeyWhisperMessage.hasField( ) ||
                  !preKeyWhisperMessage.hasBaseKey()         ||
                  !preKeyWhisperMessage.hasIdentityKey()     ||
                  !preKeyWhisperMessage.hasMessage())
          {
              throw new InvalidMessageException("Incomplete message.");
          }*/

          this.serialized     = serialized;
            this.baseKeyEinitiator        = Curve.decodePoint(preKeyWhisperMessage.getBaseKey().toByteArray(), 0);
          this.identityKeyIinitiator    = Curve.decodePoint(preKeyWhisperMessage.getIdentityKey().toByteArray(), 0);//new IdentityKey(Curve.decodePoint(preKeyWhisperMessage.getIdentityKey().toByteArray(), 0));
          int num =preKeyWhisperMessage.getMessageList().size();



          for(int i=0; i<num; i++ )
          {
              GroupPretypeMsgProtobuf.SentDistributionMessage   t= preKeyWhisperMessage.getMessageList().get(i);


                  GroupPreKeySignalMessageToClient tobj =new GroupPreKeySignalMessageToClient();
                  tobj.setBaseKey(this.baseKeyEinitiator);
                  tobj.setIdentityKey( this.identityKeyIinitiator);

                  tobj.setMessage(t.getOneMsg().toByteArray());
                  tobj.setUserId(t.getUserId());



              }
          } catch (LegacyMessageException ex) {
          ex.printStackTrace();
      } catch (InvalidProtocolBufferException ex) {
          ex.printStackTrace();
      } catch (InvalidKeyException ex) {
          ex.printStackTrace();
      }


  }
/*
  public int AddMsg(TArray t){
      messageList.add(t);
  return messageList.size();
  }*/
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
  public SinglePreKeySignalMessageToServer(int messageVersion, int registrationId, int preKeyId,
                                           int signedPreKeyId, ECPublicKey baseKeyEinitiator, ECPublicKey identityKeyIinitiator
                                  )
  {
      this.version        = messageVersion;

      this.baseKeyEinitiator        = baseKeyEinitiator;
      this.identityKeyIinitiator    = identityKeyIinitiator;
      //messageList = new ArrayList<TArray>();
      //SinglePreKeyMessageProtobuf.SinglePreKeyMessageTS.newBuilder().set


  }


  public int AddGroupPretypeMsg(long userId,byte[]  data){
      //messageList.add(t);
      GroupPretypeMsgProtobuf.SentDistributionMessage.Builder bmsg =
              GroupPretypeMsgProtobuf.SentDistributionMessage.newBuilder().setUserId( userId).setOneMsg(ByteString.copyFrom( data));

      return 0;
  }
  //打包成字节序列
 public  byte[]   getPacketGroupPretypeMsgSerialized()
 {

     byte[] versionBytes = {ByteUtil.intsToByteHighAndLow(this.version, CURRENT_VERSION)};

     //byte[] messageBytes = builderMsgList.build().toByteArray();
      //serialized = ByteUtil.combine(versionBytes, messageBytes);
     return serialized;

 }

  public int getMessageVersion() {
      return version;
  }





  @Override
  public byte[] serialize() {
      return serialized;
  }

  @Override
  public int getType() {
      return CiphertextMessage.PREKEY_TYPE;
  }

}
