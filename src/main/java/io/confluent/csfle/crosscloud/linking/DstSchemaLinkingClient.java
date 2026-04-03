package io.confluent.csfle.crosscloud.linking;

/**
 * Publishes the dst-wrapped DEK to the destination cluster's Schema Registry via schema linking.
 *
 * Schema linking replicates subjects (schemas + associated key metadata) from src to dst.
 * The dst-wrapped DEK is published as a DEKS resource in the src Schema Registry under a
 * dedicated subject that schema linking will replicate to the dst Schema Registry.
 *
 * The dst consumer then fetches its wrapped DEK from its local (dst) Schema Registry —
 * no cross-cloud KMS call is required at read time.
 */
public interface DstSchemaLinkingClient {

    /**
     * Publishes the dst-wrapped DEK so that schema linking replicates it to the dst cluster.
     *
     * @param field        the encrypted field name
     * @param dstKekId     the dst KEK identifier
     * @param encryptedDek the DEK bytes wrapped with the dst KEK
     */
    void publishDek(String field, String dstKekId, byte[] encryptedDek);
}
