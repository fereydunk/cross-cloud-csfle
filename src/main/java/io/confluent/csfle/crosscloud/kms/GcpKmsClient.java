package io.confluent.csfle.crosscloud.kms;

import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

import java.io.IOException;

public class GcpKmsClient implements KmsClient {

    private final KeyManagementServiceClient gcpClient;

    public GcpKmsClient() {
        try {
            this.gcpClient = KeyManagementServiceClient.create();
        } catch (IOException e) {
            throw new RuntimeException("Failed to create GCP KMS client", e);
        }
    }

    @Override
    public byte[] wrapDek(String kekId, byte[] plaintextDek) {
        EncryptResponse response = gcpClient.encrypt(kekId, ByteString.copyFrom(plaintextDek));
        return response.getCiphertext().toByteArray();
    }

    @Override
    public byte[] unwrapDek(String kekId, byte[] wrappedDek) {
        DecryptResponse response = gcpClient.decrypt(kekId, ByteString.copyFrom(wrappedDek));
        return response.getPlaintext().toByteArray();
    }

    @Override
    public void close() {
        gcpClient.close();
    }
}
