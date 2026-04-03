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
     * @param field       the encrypted field name (used as the subject/key)
     * @param kekId       the src KEK identifier
     * @param encryptedDek the DEK bytes wrapped with the src KEK
     */
    void storeDek(String field, String kekId, byte[] encryptedDek);
}
