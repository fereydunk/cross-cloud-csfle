package io.confluent.csfle.crosscloud.dek;

/**
 * Result of a DEK provisioning operation.
 *
 * In normal mode (link active): both srcWrapped and dstWrapped are non-null and
 * already persisted before this object is returned — the DEK is safe to use.
 *
 * In DR single-KMS mode (link broken): only one of srcWrapped/dstWrapped is non-null.
 * The null copy is deferred to {@link DekSyncer} at link re-establishment time.
 *
 * Use {@link #isSingleKmsMode()} to detect the DR case.
 */
public record DekProvisioningResult(
        String field,
        WrappedDek srcWrapped,
        WrappedDek dstWrapped
) {
    /** True if only one wrapped copy exists (DR single-KMS provisioning). */
    public boolean isSingleKmsMode() {
        return srcWrapped == null || dstWrapped == null;
    }
}
