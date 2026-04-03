package io.confluent.csfle.crosscloud.linking;

/**
 * Stores the src-wrapped DEK in the source cluster's Schema Registry.
 *
 * This is a thin facade over the Confluent Schema Registry REST API.
 * The wrapped DEK is stored as a DEKS resource under the given KEK name,
 * keyed by field name — consistent with Confluent's existing CSFLE key registry format.
 */
public interface SrcSchemaRegistryClient {

    /**
     * Persists the src-wrapped DEK for the given field.
     *
     * @param field        the encrypted field name (used as the subject/key)
     * @param kekId        the src KEK identifier
     * @param encryptedDek the DEK bytes wrapped with the src KEK
     */
    void storeDek(String field, String kekId, byte[] encryptedDek);

    /**
     * Writes a temporary transfer subject containing the plaintext DEK for split-mode
     * provisioning. Schema linking replicates this subject to the destination SR over TLS,
     * where {@code provision-dst} reads it, wraps with the dst KEK, and deletes it.
     *
     * <p>The transfer subject ({@code cross-cloud-dek-{field}-transfer}) exists only for
     * the window between phase 1 and phase 2 and must be deleted by the destination side
     * immediately after wrapping.
     *
     * @param field        the encrypted field name
     * @param plaintextDek the plaintext DEK bytes — caller must zero after this call returns
     */
    void writeTransferSubject(String field, byte[] plaintextDek);
}
