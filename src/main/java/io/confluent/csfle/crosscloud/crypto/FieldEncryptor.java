package io.confluent.csfle.crosscloud.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM field-level encrypt / decrypt.
 *
 * Wire format (new):  dekVersion + ":" + base64(iv) + ":" + base64(ciphertext+tag)
 * Wire format (old):  base64(iv) + ":" + base64(ciphertext+tag)   ← backward-compat, treated as version 1
 *
 * The DEK version is the Schema Registry schema version of the DEK subject used at encrypt
 * time. Embedding it in the field value lets consumers fetch the exact DEK version needed
 * to decrypt each record, supporting coexistence of multiple DEK generations on the same
 * topic (e.g. after DEK rotation, including rotation during a DR outage).
 *
 * A fresh 12-byte IV is generated per encrypt call.
 * The DEK is never retained — callers must zero it after use.
 */
public final class FieldEncryptor {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_BYTES     = 12;
    private static final int TAG_BITS     = 128;

    private FieldEncryptor() {}

    /**
     * Encrypts plaintext and embeds the DEK version in the wire format.
     *
     * @param plaintext  field value to encrypt
     * @param dek        plaintext DEK bytes (caller must zero after use)
     * @param dekVersion Schema Registry version of the DEK subject used
     * @return           wire-format string:  dekVersion:base64(iv):base64(ct)
     */
    public static String encrypt(String plaintext, byte[] dek, int dekVersion) {
        try {
            byte[] iv = new byte[IV_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));

            byte[] ct = cipher.doFinal(plaintext.getBytes());
            return dekVersion + ":" +
                   Base64.getEncoder().encodeToString(iv) + ":" +
                   Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new RuntimeException("AES-256-GCM encrypt failed", e);
        }
    }

    /**
     * Decrypts a wire-format ciphertext.
     * Handles both old format (base64(iv):base64(ct)) and new format (version:iv:ct).
     * The DEK supplied must correspond to the version embedded in the value.
     *
     * @param encryptedValue wire-format string from the record
     * @param dek            plaintext DEK bytes for the version referenced in the value
     * @return               decrypted plaintext
     */
    public static String decrypt(String encryptedValue, byte[] dek) {
        try {
            String ivPart, ctPart;

            // New format has exactly two colons (version:iv:ct → 3 parts).
            // Old format has exactly one colon (iv:ct → 2 parts).
            String[] parts = encryptedValue.split(":", 3);
            if (parts.length == 3) {
                // New format: parts[0]=version, parts[1]=iv, parts[2]=ct
                ivPart = parts[1];
                ctPart = parts[2];
            } else if (parts.length == 2) {
                // Old format: parts[0]=iv, parts[1]=ct
                ivPart = parts[0];
                ctPart = parts[1];
            } else {
                throw new IllegalArgumentException(
                        "Invalid ciphertext format — expected version:base64(iv):base64(ct) " +
                        "or base64(iv):base64(ct), got: " + encryptedValue);
            }

            byte[] iv = Base64.getDecoder().decode(ivPart);
            byte[] ct = Base64.getDecoder().decode(ctPart);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));

            return new String(cipher.doFinal(ct));
        } catch (Exception e) {
            throw new RuntimeException("AES-256-GCM decrypt failed", e);
        }
    }

    /**
     * Parses the DEK version embedded in a wire-format field value.
     *
     * @return the version number (≥ 1), or 0 if the value uses the old format
     *         (no version prefix) — caller should treat 0 as "fetch latest".
     */
    public static int parseDekVersion(String encryptedValue) {
        String[] parts = encryptedValue.split(":", 3);
        if (parts.length == 3) {
            try {
                return Integer.parseInt(parts[0]);
            } catch (NumberFormatException e) {
                return 0; // not a version prefix — treat as old format
            }
        }
        return 0; // old format (only one colon)
    }
}
