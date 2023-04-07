package org.security;

public class Main {
    public static void main(String[] args) {
        try {
            AESUtils aes_encryption = new AESUtils();

            String data = "Hello, welcome to the encryption world";

            // AES/CBC/
            aes_encryption.init();
            String CBCEncryptedData = aes_encryption.encrypt(data);
            String CBCDecryptedData = aes_encryption.decrypt(CBCEncryptedData);
            // AES/ECB/
            aes_encryption.init();
            String ECBEncryptedData = aes_encryption.encryptECB(data);
            String ECBDecryptedData = aes_encryption.decryptECB(ECBEncryptedData);
            //AES/CFB
            String CFBEncryptedData = aes_encryption.encryptCFB(data);
            String CFBDecryptedData = aes_encryption.decryptCFB(CFBEncryptedData);

            // AES/CBC
            System.out.println("[AES/CBC] : Encrypted Data : " + CBCEncryptedData);
            System.out.println("[AES/CBC] Decrypted Data : " + CBCDecryptedData);
            // AES/ECB
            System.out.println("[AES/ECB] : Encrypted Data : " + ECBEncryptedData);
            System.out.println("[AES/ECB] Decrypted Data : " + ECBDecryptedData);
            // AES/CFB
            System.out.println("[AES/CFB] : Encrypted Data : " + CFBEncryptedData);
            System.out.println("[AES/CFB] Decrypted Data : " + CFBDecryptedData);

        } catch (Exception ignored) {
            System.out.println("ERROR : " + ignored);

        }
    }
}