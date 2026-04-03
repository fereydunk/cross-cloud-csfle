package io.confluent.csfle.crosscloud.config;

/**
 * Defines CSFLE encryption for a single field, with explicit src and dst KEK references.
 *
 * Both KEK references are required. The src KEK is used to wrap the DEK for local persistence
 * at the source cluster. The dst KEK is used to wrap the DEK for transfer to the destination
 * cluster via schema linking.
 *
 * The DEK is not put into use until both wrapped copies are successfully stored.
 */
public class EncryptionRule {

    private final String field;
    private final KekReference srcKek;
    private final KekReference dstKek;

    public EncryptionRule(String field, KekReference srcKek, KekReference dstKek) {
        if (field == null || field.isBlank()) {
            throw new IllegalArgumentException("Field name must not be blank");
        }
        if (srcKek == null) throw new IllegalArgumentException("srcKek must not be null");
        if (dstKek == null) throw new IllegalArgumentException("dstKek must not be null");

        this.field = field;
        this.srcKek = srcKek;
        this.dstKek = dstKek;

        validate();
    }

    private void validate() {
        // Case 4: both external — each must have an explicit type marker
        boolean srcIsCsp = srcKek.getExplicitType()
                .map(KmsType::isCsp)
                .orElse(KmsTypeInferrer.infer(srcKek.getId()).map(KmsType::isCsp).orElse(false));
        boolean dstIsCsp = dstKek.getExplicitType()
                .map(KmsType::isCsp)
                .orElse(KmsTypeInferrer.infer(dstKek.getId()).map(KmsType::isCsp).orElse(false));

        if (!srcIsCsp && !dstIsCsp) {
            // Both external — explicit types are required on both
            if (srcKek.getExplicitType().isEmpty()) {
                throw new IllegalArgumentException(
                        "Field '" + field + "': srcKek type must be explicit when both KEKs are external (Case 4). " +
                        "Set 'type' to HASHICORP_VAULT or CIPHERTRUST.");
            }
            if (dstKek.getExplicitType().isEmpty()) {
                throw new IllegalArgumentException(
                        "Field '" + field + "': dstKek type must be explicit when both KEKs are external (Case 4). " +
                        "Set 'type' to HASHICORP_VAULT or CIPHERTRUST.");
            }
        }
    }

    public String getField() { return field; }
    public KekReference getSrcKek() { return srcKek; }
    public KekReference getDstKek() { return dstKek; }

    @Override
    public String toString() {
        return "EncryptionRule{field='" + field + "', src=" + srcKek + ", dst=" + dstKek + "}";
    }
}
