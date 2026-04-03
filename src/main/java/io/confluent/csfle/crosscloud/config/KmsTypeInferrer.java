package io.confluent.csfle.crosscloud.config;

import java.util.Optional;

/**
 * Infers the KMS type from a KEK identifier URI.
 *
 * Inference rules:
 *   AWS   — arn:aws:kms:...
 *   GCP   — projects/.../locations/.../keyRings/.../cryptoKeys/...
 *   AZURE — https://*.vault.azure.net/keys/...
 *
 * HashiCorp Vault and CipherTrust URIs are not uniquely identifiable by pattern alone,
 * so they return empty — the caller must supply an explicit type.
 */
public final class KmsTypeInferrer {

    private KmsTypeInferrer() {}

    public static Optional<KmsType> infer(String kekId) {
        if (kekId == null) {
            return Optional.empty();
        }
        if (kekId.startsWith("arn:aws:kms:")) {
            return Optional.of(KmsType.AWS);
        }
        if (kekId.startsWith("projects/") && kekId.contains("/keyRings/") && kekId.contains("/cryptoKeys/")) {
            return Optional.of(KmsType.GCP);
        }
        if (kekId.matches("https://[^/]+\\.vault\\.azure\\.net/keys/.*")) {
            return Optional.of(KmsType.AZURE);
        }
        return Optional.empty();
    }
}
