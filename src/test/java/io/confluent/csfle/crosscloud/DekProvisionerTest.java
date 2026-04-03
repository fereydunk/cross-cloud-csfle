package io.confluent.csfle.crosscloud;

import io.confluent.csfle.crosscloud.config.EncryptionRule;
import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.config.KmsType;
import io.confluent.csfle.crosscloud.dek.DekProvisioningResult;
import io.confluent.csfle.crosscloud.dek.DekProvisioner;
import io.confluent.csfle.crosscloud.linking.DstSchemaLinkingClient;
import io.confluent.csfle.crosscloud.linking.SrcSchemaRegistryClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DekProvisionerTest {

    // Minimal stub KMS clients injected via a testable subclass arrangement
    // Real KMS calls are not made in unit tests

    private SrcSchemaRegistryClient srcRegistry;
    private DstSchemaLinkingClient dstRegistry;

    @BeforeEach
    void setUp() {
        srcRegistry = mock(SrcSchemaRegistryClient.class);
        dstRegistry = mock(DstSchemaLinkingClient.class);
    }

    @Test
    void encryptionRule_rejectsBlankField() {
        assertThrows(IllegalArgumentException.class, () ->
                new EncryptionRule("",
                        new KekReference("arn:aws:kms:us-east-1:123:key/abc"),
                        new KekReference("projects/p/locations/l/keyRings/r/cryptoKeys/k")));
    }

    @Test
    void encryptionRule_rejectsNullSrcKek() {
        assertThrows(IllegalArgumentException.class, () ->
                new EncryptionRule("ssn", null,
                        new KekReference("projects/p/locations/l/keyRings/r/cryptoKeys/k")));
    }

    @Test
    void encryptionRule_case4_requiresExplicitTypes() {
        // Both external, no explicit types — should fail at rule construction
        KekReference srcKek = new KekReference("https://vault.example.com/v1/transit/keys/my-key");
        KekReference dstKek = new KekReference("https://ciphertrust.example.com/api/v1/keys/my-key");
        assertThrows(IllegalArgumentException.class, () ->
                new EncryptionRule("ssn", srcKek, dstKek));
    }

    @Test
    void encryptionRule_case4_passesWithExplicitTypes() {
        KekReference srcKek = new KekReference(
                "https://vault.example.com/v1/transit/keys/my-key", KmsType.HASHICORP_VAULT);
        KekReference dstKek = new KekReference(
                "https://ciphertrust.example.com/api/v1/keys/my-key", KmsType.CIPHERTRUST);
        assertDoesNotThrow(() -> new EncryptionRule("ssn", srcKek, dstKek));
    }

    @Test
    void encryptionRule_case3_externalSrcCspDst_noMarkerRequired() {
        // External src (no explicit type), CSP dst — should pass (Case 3)
        KekReference srcKek = new KekReference("https://vault.example.com/v1/transit/keys/my-key");
        KekReference dstKek = new KekReference("projects/p/locations/l/keyRings/r/cryptoKeys/k");
        assertDoesNotThrow(() -> new EncryptionRule("ssn", srcKek, dstKek));
    }

    @Test
    void kmsTypeInferrer_detectsAwsArn() {
        KekReference ref = new KekReference("arn:aws:kms:us-east-1:123456789012:key/abc-def");
        assertEquals(KmsType.AWS, ref.resolveType());
    }

    @Test
    void kmsTypeInferrer_detectsGcpResourcePath() {
        KekReference ref = new KekReference(
                "projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key");
        assertEquals(KmsType.GCP, ref.resolveType());
    }

    @Test
    void kmsTypeInferrer_detectsAzureVaultUri() {
        KekReference ref = new KekReference("https://my-vault.vault.azure.net/keys/my-key/version1");
        assertEquals(KmsType.AZURE, ref.resolveType());
    }

    @Test
    void kmsTypeInferrer_externalWithoutExplicitType_throwsOnResolve() {
        KekReference ref = new KekReference("https://vault.example.com/v1/transit/keys/my-key");
        assertThrows(IllegalStateException.class, ref::resolveType);
    }
}
