package com.example.springboottest.utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import com.example.springboottest.entity.User;

import javax.crypto.SecretKey;

/**
 * @author 梁富贵
 * @Date 2024/4/6
 **/
public class EncryptionUtil {
//    AES算法
    private static final String AES_ALGORITHM = "AES";

    private static final int AES_KEY_SIZE = 128;

    private static final int KEK_KEY_SIZE = 256;


    /*
     * 密码aes加密
     */
    public static User transformPassword(User user, String password) {
//        生成AES密钥
        SecretKey aesKey = gernerateSecretKey();
//        生成kek主密钥
        SecretKey kek = generateKek();
//    加密密码
        String encryptedData = encrypt(password, aesKey);

//        加密aes的密钥
        String aesKeyStr = encryptAesKey(aesKey, kek);

//        转化kek为字符串
        String kekStr = Base64.getEncoder().encodeToString(kek.getEncoded());

        user.setKek(kekStr);
        user.setAes(aesKeyStr);
        user.setPassword(encryptedData);

        return user;
    }

    /*
     * 密码aes解密
     */
    private static String decryptPassword(String password, String aesStr, String kekStr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] kek = Base64.getDecoder().decode(kekStr);
        SecretKey kekKey = new SecretKeySpec(kek, AES_ALGORITHM);
        SecretKey aesKey = decryptAesKey(aesStr, kekKey);
        return decrypt(password, aesKey);
    }

    /*
     * 生成aes密钥
     */
    private static SecretKey gernerateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGenerator.init(AES_KEY_SIZE);
            return  keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /*
     * aes加密算法
     */

    private static String encrypt(String data, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /*
     * aes解密算法
     */

    private static String decrypt(String encryptedData, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 生成kek主密钥
     * @return
     */
    private static SecretKey generateKek() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGenerator.init(KEK_KEY_SIZE);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用kek主密钥加密AES密钥
     * @param aesKey
     * @param kek
     * @return
     */
    private static String encryptAesKey(SecretKey aesKey, SecretKey kek) {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, kek);
            return Base64.getEncoder().encodeToString(cipher.doFinal(aesKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 使用kek主密钥解密AES密钥
     * @param encryptedAesKey
     * @param kek
     * @return
     */
    private static SecretKey decryptAesKey(String encryptedAesKey, SecretKey kek) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] decryptedAesKey = Base64.getDecoder().decode(encryptedAesKey);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, kek);
        return new SecretKeySpec(decryptedAesKey,0,decryptedAesKey.length,AES_ALGORITHM);

    }
}
