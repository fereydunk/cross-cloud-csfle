package io.confluent.csfle.crosscloud.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;

public class AwsKmsClient implements io.confluent.csfle.crosscloud.kms.KmsClient {

    private final KmsClient awsClient;

    public AwsKmsClient() {
        this.awsClient = KmsClient.create(); // uses default credential chain
    }

    @Override
    public byte[] wrapDek(String kekId, byte[] plaintextDek) {
        EncryptRequest request = EncryptRequest.builder()
                .keyId(kekId)
                .plaintext(SdkBytes.fromByteArray(plaintextDek))
                .build();
        EncryptResponse response = awsClient.encrypt(request);
        return response.ciphertextBlob().asByteArray();
    }

    @Override
    public byte[] unwrapDek(String kekId, byte[] wrappedDek) {
        DecryptRequest request = DecryptRequest.builder()
                .keyId(kekId)
                .ciphertextBlob(SdkBytes.fromByteArray(wrappedDek))
                .build();
        DecryptResponse response = awsClient.decrypt(request);
        return response.plaintext().asByteArray();
    }

    @Override
    public void close() {
        awsClient.close();
    }
}
