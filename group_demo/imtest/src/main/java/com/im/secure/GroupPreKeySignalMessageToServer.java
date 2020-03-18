package com.im.secure;
/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

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


public class GroupPreKeySignalMessageToServer implements CiphertextMessage {

    private   int               version;
    private   int               registrationId;
    private   int               preKeyId;
    private   int               signedPreKeyId;
    private   ECPublicKey       baseKeyEinitiator;
    private   ECPublicKey       identityKeyIinitiator;

    //private   ArrayList<TArray> messageList = null;
     private  ArrayList<SenderKeyDistributionMessage> senderMsgList=null;
    GroupPretypeMsgProtobuf.SendMsgStateReq.Builder builderMsgList=null;


    public ArrayList<GroupPreKeySignalMessageToClient> getClientMsgLst() {
        return clientMsgLst;
    }

    public void setClientMsgLst(ArrayList<GroupPreKeySignalMessageToClient> clientMsgLst) {
        this.clientMsgLst = clientMsgLst;
    }
//接收者消息 列表
    ArrayList<GroupPreKeySignalMessageToClient> clientMsgLst= new ArrayList<GroupPreKeySignalMessageToClient>();
    private   byte[]            serialized;

//解析成 各个成员的报
    public GroupPreKeySignalMessageToServer(byte[] serialized, ConcurrentHashMap<Long,  UserKey> userHashMap)
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
            this.registrationId = preKeyWhisperMessage.getRegistrationId();
            this.preKeyId       = preKeyWhisperMessage.getPreKeyId();  //.hasPreKeyId() ? Optional.of(preKeyWhisperMessage.getPreKeyId()) : Optional.<Integer>absent();
            this.signedPreKeyId = preKeyWhisperMessage.getSignedPreKeyId();//.hasSignedPreKeyId() ? preKeyWhisperMessage.getSignedPreKeyId() : -1;
            this.baseKeyEinitiator        = Curve.decodePoint(preKeyWhisperMessage.getBaseKey().toByteArray(), 0);
            this.identityKeyIinitiator    = Curve.decodePoint(preKeyWhisperMessage.getIdentityKey().toByteArray(), 0);//new IdentityKey(Curve.decodePoint(preKeyWhisperMessage.getIdentityKey().toByteArray(), 0));
            int num =preKeyWhisperMessage.getMessageList().size();
            senderMsgList = new ArrayList<SenderKeyDistributionMessage>();

            for(int i=0; i<num; i++ )
            {
                GroupPretypeMsgProtobuf.SentDistributionMessage   t= preKeyWhisperMessage.getMessageList().get(i);


                    GroupPreKeySignalMessageToClient tobj =new GroupPreKeySignalMessageToClient();
                    tobj.setBaseKey(this.baseKeyEinitiator);
                    tobj.setIdentityKey( this.identityKeyIinitiator);
                    tobj.setSignedPreKeyId(this.signedPreKeyId);
                    tobj.setRegistrationId( this.registrationId);
                    tobj.setMessage(t.getOneMsg().toByteArray());
                    tobj.setUserId(t.getUserId());
                    clientMsgLst.add(tobj);


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
    public GroupPreKeySignalMessageToServer(int messageVersion, int registrationId, int preKeyId,
                                    int signedPreKeyId, ECPublicKey baseKeyEinitiator, ECPublicKey identityKeyIinitiator
                                    )
    {
        this.version        = messageVersion;
        this.registrationId = registrationId;
        this.preKeyId       = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
        this.baseKeyEinitiator        = baseKeyEinitiator;
        this.identityKeyIinitiator    = identityKeyIinitiator;
        //messageList = new ArrayList<TArray>();

        builderMsgList=GroupPretypeMsgProtobuf.SendMsgStateReq.newBuilder().
                setRegistrationId(registrationId)
                .setIdentityKey(ByteString.copyFrom(identityKeyIinitiator.serialize()))
                .setBaseKey(ByteString.copyFrom(baseKeyEinitiator.serialize()))
                .setPreKeyId(0)
                .setSignedPreKeyId( signedPreKeyId);


    }


    public int AddGroupPretypeMsg(long userId,byte[]  data){
        //messageList.add(t);
        com.im.secure.GroupPretypeMsgProtobuf.SentDistributionMessage.Builder bmsg =
                com.im.secure.GroupPretypeMsgProtobuf.SentDistributionMessage.newBuilder().setUserId( userId).setOneMsg(ByteString.copyFrom( data));
        builderMsgList.addMessage(bmsg);
        return 0;
    }
    //打包成字节序列
   public  byte[]   getPacketGroupPretypeMsgSerialized()
   {

       byte[] versionBytes = {ByteUtil.intsToByteHighAndLow(this.version, CURRENT_VERSION)};

       byte[] messageBytes = builderMsgList.build().toByteArray();
        serialized = ByteUtil.combine(versionBytes, messageBytes);
       return serialized;

   }

    public int getMessageVersion() {
        return version;
    }



    public int getRegistrationId() {
        return registrationId;
    }

    public int getPreKeyId() {
        return preKeyId;
    }

    public int getSignedPreKeyId() {
        return signedPreKeyId;
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
