package org.security;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class RSAEncryptionExample {
    private static final String RSA_ALGORITHM = "RSA";

    public static void main(String[] args) throws Exception {
        // Generate a key pair
        KeyPair keyPair = generateKeyPair();

        // Get the public and private keys from the key pair
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // The message to be encrypted
        String message = "Hello, world!";

        // Encrypt the message using the private key
        byte[] encryptedMessage = encrypt(message.getBytes(), privateKey);

        // Decrypt the message using the public key
        byte[] decryptedMessage = decrypt(encryptedMessage, publicKey);

        // Convert the decrypted message back to a string
        String decryptedMessageStr = new String(decryptedMessage);

        // Print the original and decrypted messages
        System.out.println("Original message: " + message);
        System.out.println("Decrypted message: " + decryptedMessageStr);
    }

    /**
     * Generates a new RSA key pair.
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        SecureRandom secureRandom = new SecureRandom();
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypts the given plaintext using the RSA algorithm and the given private key.
     */
    public static byte[] encrypt(byte[] plaintext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypts the given ciphertext using the RSA algorithm and the given public key.
     */
    public static byte[] decrypt(byte[] ciphertext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Converts a byte array containing an encoded private key to a PrivateKey object.
     */
    public static PrivateKey decodePrivateKey(byte[] encodedPrivateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        return KeyFactory.getInstance(RSA_ALGORITHM).generatePrivate(keySpec);
    }

    /**
     * Converts a byte array containing an encoded public key to a PublicKey object.
     */
    public static PublicKey decodePublicKey(byte[] encodedPublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
        return KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(keySpec);
    }
}
