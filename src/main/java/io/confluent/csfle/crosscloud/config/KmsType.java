package io.confluent.csfle.crosscloud.config;

/**
 * Supported KMS providers.
 *
 * For CSP-based providers (AWS, GCP, AZURE) the type is inferred from the KEK identifier URI.
 * For external providers (HASHICORP_VAULT, CIPHERTRUST) the type must be specified explicitly
 * when both src and dst KEKs are external (Case 4).
 */
public enum KmsType {
    AWS,
    GCP,
    AZURE,
    HASHICORP_VAULT,
    CIPHERTRUST;

    public boolean isCsp() {
        return this == AWS || this == GCP || this == AZURE;
    }
}
