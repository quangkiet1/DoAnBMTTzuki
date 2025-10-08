package com.example.demo.security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class AESUtil {
    private static final String ALGORITHM = "AES";
    private static byte[] SECRET_KEY;

    static {
        try {
            InputStream input = AESUtil.class.getClassLoader().getResourceAsStream("secret.key");
            if (input == null) throw new RuntimeException("Không tìm thấy file secret.key!");
            String keyString = new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
            SECRET_KEY = keyString.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Lỗi khi tải khóa mã hóa", e);
        }
    }

    // 🔒 Mã hóa dữ liệu bằng AES
    public static String encrypt(String data) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Lỗi mã hóa dữ liệu", e);
        }
    }

    // 🔓 Giải mã dữ liệu bằng AES
    public static String decrypt(String encryptedData) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Lỗi giải mã dữ liệu", e);
        }
    }   

    // 🔐 Demo mô hình mã hóa lai AES + RSA
    public static void hybridKeyEncryptionDemo() {
        try {
            KeyPair keyPair = RSAUtil.generateRSAKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Mã hóa khóa AES (dưới dạng Base64 string)
            String aesKeyBase64 = Base64.getEncoder().encodeToString(SECRET_KEY);
            String encryptedAESKey = RSAUtil.encrypt(aesKeyBase64, publicKey);
            System.out.println("🔐 AES Key (encrypted by RSA): " + encryptedAESKey);

            // Giải mã lại khóa AES
            String decryptedAESKeyBase64 = RSAUtil.decrypt(encryptedAESKey, privateKey);
            String decryptedAESKey = new String(Base64.getDecoder().decode(decryptedAESKeyBase64), StandardCharsets.UTF_8);
            System.out.println("✅ AES Key (decrypted): " + decryptedAESKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
