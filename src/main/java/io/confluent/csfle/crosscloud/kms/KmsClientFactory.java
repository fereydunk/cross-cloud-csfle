package io.confluent.csfle.crosscloud.kms;

import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.config.KmsType;

/**
 * Resolves a {@link KmsClient} from a {@link KekReference}.
 *
 * The KMS type is resolved via {@link KekReference#resolveType()}, which either reads the
 * explicit type or infers it from the KEK id URI (for CSP-based KEKs).
 */
public final class KmsClientFactory {

    private KmsClientFactory() {}

    public static KmsClient create(KekReference kekRef) {
        KmsType type = kekRef.resolveType();
        return switch (type) {
            case AWS            -> new AwsKmsClient();
            case GCP            -> new GcpKmsClient();
            case AZURE          -> new AzureKmsClient();
            case HASHICORP_VAULT -> new HashiCorpVaultKmsClient();
            case CIPHERTRUST    -> new CipherTrustKmsClient();
        };
    }
}
