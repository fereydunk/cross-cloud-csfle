package io.confluent.csfle.crosscloud.kms;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;

import java.util.Base64;
import java.util.Map;

/**
 * KMS client for HashiCorp Vault Transit secrets engine.
 *
 * The kekId format expected: {@code https://<vault-addr>/v1/transit/keys/<key-name>}
 * Vault address and token are resolved from the kekId URI and environment variables respectively.
 */
public class HashiCorpVaultKmsClient implements KmsClient {

    private static final String VAULT_TOKEN_ENV = "VAULT_TOKEN";

    @Override
    public byte[] wrapDek(String kekId, byte[] plaintextDek) {
        try {
            VaultContext ctx = VaultContext.parse(kekId);
            Vault vault = buildVault(ctx.address());
            String encoded = Base64.getEncoder().encodeToString(plaintextDek);
            LogicalResponse response = vault.logical()
                    .write("transit/encrypt/" + ctx.keyName(), Map.of("plaintext", encoded));
            String ciphertext = response.getData().get("ciphertext");
            return ciphertext.getBytes();
        } catch (VaultException e) {
            throw new RuntimeException("HashiCorp Vault wrap failed for key: " + kekId, e);
        }
    }

    @Override
    public byte[] unwrapDek(String kekId, byte[] wrappedDek) {
        try {
            VaultContext ctx = VaultContext.parse(kekId);
            Vault vault = buildVault(ctx.address());
            String ciphertext = new String(wrappedDek);
            LogicalResponse response = vault.logical()
                    .write("transit/decrypt/" + ctx.keyName(), Map.of("ciphertext", ciphertext));
            String plaintext = response.getData().get("plaintext");
            return Base64.getDecoder().decode(plaintext);
        } catch (VaultException e) {
            throw new RuntimeException("HashiCorp Vault unwrap failed for key: " + kekId, e);
        }
    }

    private Vault buildVault(String address) throws VaultException {
        String token = System.getenv(VAULT_TOKEN_ENV);
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("VAULT_TOKEN environment variable not set");
        }
        VaultConfig config = new VaultConfig()
                .address(address)
                .token(token)
                .build();
        return Vault.create(config);
    }

    @Override
    public void close() {}

    private record VaultContext(String address, String keyName) {
        static VaultContext parse(String kekId) {
            // Expected: https://<host>/v1/transit/keys/<key-name>
            int keysIdx = kekId.indexOf("/transit/keys/");
            if (keysIdx == -1) {
                throw new IllegalArgumentException(
                        "Invalid HashiCorp Vault KEK id format. Expected: " +
                        "https://<vault-addr>/v1/transit/keys/<key-name>, got: " + kekId);
            }
            String address = kekId.substring(0, kekId.indexOf("/v1/"));
            String keyName = kekId.substring(keysIdx + "/transit/keys/".length());
            return new VaultContext(address, keyName);
        }
    }
}
