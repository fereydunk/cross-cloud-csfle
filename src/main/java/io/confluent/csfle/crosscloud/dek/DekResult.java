package io.confluent.csfle.crosscloud.dek;

/**
 * A plaintext DEK paired with its Schema Registry version number.
 *
 * The version is the schema version of the DEK subject at the time it was fetched.
 * It is embedded in the encrypted field wire format so consumers can resolve the
 * correct DEK version regardless of how many rotations have occurred.
 *
 * Callers MUST zero the plaintext array after use.
 */
public final class DekResult {

    private final int version;
    private final byte[] plaintext;

    public DekResult(int version, byte[] plaintext) {
        this.version   = version;
        this.plaintext = plaintext;
    }

    /** Schema Registry version of this DEK (1-based). */
    public int version() { return version; }

    /** Plaintext DEK bytes — caller must zero after use. */
    public byte[] plaintext() { return plaintext; }
}
