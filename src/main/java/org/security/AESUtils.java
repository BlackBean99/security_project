package org.security;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

public class AESUtils {

    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;
    private static String initVector = "encryptionIntVec";

    public void init() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();
    }

    public String encryptECB(String data) throws Exception {
        System.out.println("data : " + data);
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String encryptCFB(String data)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        System.out.println("data : " + data);
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/CFB/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }
    public String encryptWithIV(String data, String mode) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
//            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance(mode);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

//            String encryptedBytes =
            byte[] bytes1 = data.getBytes();
            byte[] bytes = cipher.doFinal(bytes1);
            String encode = encode(bytes);
            System.out.println(encode);
            return encode;
        } catch (Exception ex) {
            System.out.println("ERRPR : Fuck");
            ex.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    public String decryptECB(String encryptedData) throws Exception {
        //Cipher 객체 인스턴스화(Java에서는 PKCS#5 = PKCS#7이랑 동일)
        Cipher decryptedCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        //Cipher 객체 초기화
        decryptedCipher.init(Cipher.DECRYPT_MODE, key);
        //Decode Hex
        byte[] decodeByte = decode(encryptedData);

        //Decode Base64
//		byte[] decodeByte = Base64.decodeBase64(encodeText);

        return new String(decryptedCipher.doFinal(decodeByte), "UTF-8");
    }
    public String decryptCFB(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/CFB/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, this.key, ivSpec);
        return new String(decryptionCipher.doFinal(dataInBytes), "UTF-8");
    }

    public String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
