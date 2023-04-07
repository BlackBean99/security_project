//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.Test;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.SecretKey;
//import javax.crypto.spec.IvParameterSpec;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.security.spec.InvalidKeySpecException;
//
//public class EncryptTest {
//    @Test
//    void givenPassword_whenEncrypt_thenSuccess()
//            throws InvalidKeySpecException, NoSuchAlgorithmException,
//            IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
//            InvalidAlgorithmParameterException, NoSuchPaddingException {
//
//        String plainText = "www.baeldung.com";
//        String password = "baeldung";
//        String salt = "12345678";
//        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
//        SecretKey key = AESUtil.getKeyFromPassword(password,salt);
//        String cipherText = AESUtil.encryptPasswordBased(plainText, key, ivParameterSpec);
//        String decryptedCipherText = AESUtil.decryptPasswordBased(
//                cipherText, key, ivParameterSpec);
//        Assertions.assertEquals(plainText, decryptedCipherText);
//    }
//}
