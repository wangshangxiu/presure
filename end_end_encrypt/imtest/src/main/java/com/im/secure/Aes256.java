package com.im.secure;
import org.whispersystems.libsignal.InvalidMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

//aes 256/cbc/PKCS5Padding
public class Aes256 {

    /**
     * 解密
     * @param key    密匙 长度32
     * @param cipherText 需要解密的内容
     * @return 解密后的字节数组
     */
    public   static  byte[] decryptData(byte[]  key, byte[] cipherText)
            throws InvalidMessageException
    {
        try {
            SecretKeySpec    cipherKey = new SecretKeySpec(key, "AES");
            byte[] bytesIv=  new byte[16];
            System.arraycopy(key, 0, bytesIv, 0, 16);
            IvParameterSpec iv = new IvParameterSpec(bytesIv);
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE, cipherKey ,iv);
            return cipher.doFinal(cipherText);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidMessageException(e);
        }
    }

    //aes 256/padding5/cbc encrypt
    /**
     * 加密
     * @param key    密匙 长度32
     * @param plaintext 需要加密的内容
     * @return 加密后的字节数组
     */
    public   static  byte[] encryptData(byte[] key, byte[] plaintext) {
        try {
            SecretKeySpec    cipherKey = new SecretKeySpec(key, "AES");
            byte[] bytesIv=  new byte[16];
            System.arraycopy(key, 0, bytesIv, 0, 16);
            IvParameterSpec iv = new IvParameterSpec(bytesIv);
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, cipherKey, iv);
            return cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }
    private  static  Cipher getCipher(int mode, SecretKeySpec key, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, key, iv);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
                InvalidAlgorithmParameterException e)
        {
            throw new AssertionError(e);
        }
    }
}
