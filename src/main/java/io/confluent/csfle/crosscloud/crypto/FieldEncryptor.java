package io.confluent.csfle.crosscloud.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM field-level encrypt / decrypt.
 *
 * Wire format: base64(iv) + ":" + base64(ciphertext+tag)
 * A fresh 12-byte IV is generated per encrypt call.
 * The DEK is never retained — callers must zero it after use.
 */
public final class FieldEncryptor {

    private static final String ALGORITHM    = "AES/GCM/NoPadding";
    private static final int IV_BYTES        = 12;
    private static final int TAG_BITS        = 128;

    private FieldEncryptor() {}

    public static String encrypt(String plaintext, byte[] dek) {
        try {
            byte[] iv = new byte[IV_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));

            byte[] ct = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(iv) + ":" +
                   Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new RuntimeException("AES-256-GCM encrypt failed", e);
        }
    }

    public static String decrypt(String encryptedValue, byte[] dek) {
        try {
            String[] parts = encryptedValue.split(":", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException(
                        "Invalid ciphertext format — expected base64(iv):base64(ct)");
            }
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ct = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));

            return new String(cipher.doFinal(ct));
        } catch (Exception e) {
            throw new RuntimeException("AES-256-GCM decrypt failed", e);
        }
    }
}
