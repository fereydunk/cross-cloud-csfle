package io.confluent.csfle.crosscloud.config;

import java.util.Optional;

/**
 * Reference to a Key Encryption Key (KEK) in a KMS.
 *
 * The {@code type} field is optional for CSP-based KEKs whose type can be inferred from
 * the {@code id} URI. It is required when the KEK belongs to an external (non-CSP) KMS
 * and the counterpart KEK is also external (Case 4 — both outside CSPs).
 */
public class KekReference {

    private final String id;
    private final KmsType explicitType;

    public KekReference(String id) {
        this(id, null);
    }

    public KekReference(String id, KmsType explicitType) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("KEK id must not be blank");
        }
        this.id = id;
        this.explicitType = explicitType;
    }

    public String getId() {
        return id;
    }

    /**
     * Returns the resolved KMS type, either from the explicit override or inferred from the id.
     * Throws if the type cannot be determined.
     */
    public KmsType resolveType() {
        if (explicitType != null) {
            return explicitType;
        }
        return KmsTypeInferrer.infer(id)
                .orElseThrow(() -> new IllegalStateException(
                        "Cannot infer KMS type from KEK id '" + id + "'. " +
                        "Set an explicit 'type' when both src and dst KEKs are external (Case 4)."));
    }

    public Optional<KmsType> getExplicitType() {
        return Optional.ofNullable(explicitType);
    }

    @Override
    public String toString() {
        return "KekReference{id='" + id + "', type=" + explicitType + "}";
    }
}
