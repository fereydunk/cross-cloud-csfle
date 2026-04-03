package io.confluent.csfle.crosscloud.kms;

/**
 * Abstraction over a KMS for KEK wrap/unwrap operations.
 * Implementations must not retain plaintext key material beyond the scope of each call.
 */
public interface KmsClient extends AutoCloseable {

    /**
     * Wraps (encrypts) the given plaintext DEK using the KEK identified by {@code kekId}.
     *
     * @param kekId     the KEK identifier (ARN, resource path, URI, etc.)
     * @param plaintextDek  the raw DEK bytes to wrap
     * @return the wrapped (encrypted) DEK bytes
     */
    byte[] wrapDek(String kekId, byte[] plaintextDek);

    /**
     * Unwraps (decrypts) the given wrapped DEK using the KEK identified by {@code kekId}.
     *
     * @param kekId      the KEK identifier
     * @param wrappedDek the wrapped DEK bytes to unwrap
     * @return the plaintext DEK bytes — caller is responsible for zeroing after use
     */
    byte[] unwrapDek(String kekId, byte[] wrappedDek);

    @Override
    void close();
}
