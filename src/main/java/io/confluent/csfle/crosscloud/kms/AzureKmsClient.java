package io.confluent.csfle.crosscloud.kms;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.DecryptResult;

public class AzureKmsClient implements KmsClient {

    @Override
    public byte[] wrapDek(String kekId, byte[] plaintextDek) {
        CryptographyClient client = buildClient(kekId);
        EncryptResult result = client.encrypt(EncryptionAlgorithm.RSA_OAEP_256, plaintextDek);
        return result.getCipherText();
    }

    @Override
    public byte[] unwrapDek(String kekId, byte[] wrappedDek) {
        CryptographyClient client = buildClient(kekId);
        DecryptResult result = client.decrypt(EncryptionAlgorithm.RSA_OAEP_256, wrappedDek);
        return result.getPlainText();
    }

    private CryptographyClient buildClient(String kekId) {
        return new CryptographyClientBuilder()
                .keyIdentifier(kekId)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
    }

    @Override
    public void close() {
        // CryptographyClient is stateless per call; nothing to close
    }
}
