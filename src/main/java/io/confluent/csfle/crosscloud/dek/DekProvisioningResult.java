package io.confluent.csfle.crosscloud.dek;

/**
 * Result of a successful DEK provisioning.
 *
 * Both wrapped copies have been persisted before this object is returned —
 * the DEK is safe to use for encryption.
 */
public record DekProvisioningResult(
        String field,
        WrappedDek srcWrapped,
        WrappedDek dstWrapped
) {}
