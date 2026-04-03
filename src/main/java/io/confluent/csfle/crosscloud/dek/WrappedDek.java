package io.confluent.csfle.crosscloud.dek;

import io.confluent.csfle.crosscloud.config.KekReference;

/**
 * A DEK that has been wrapped (encrypted) with a specific KEK.
 * The plaintext DEK is never retained in this object.
 */
public record WrappedDek(KekReference kek, byte[] encryptedDek) {

    public WrappedDek {
        if (encryptedDek == null || encryptedDek.length == 0) {
            throw new IllegalArgumentException("encryptedDek must not be empty");
        }
    }
}
