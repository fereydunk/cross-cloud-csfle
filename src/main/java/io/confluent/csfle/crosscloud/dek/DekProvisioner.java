package io.confluent.csfle.crosscloud.dek;

import io.confluent.csfle.crosscloud.config.EncryptionRule;
import io.confluent.csfle.crosscloud.kms.KmsClient;
import io.confluent.csfle.crosscloud.kms.KmsClientFactory;
import io.confluent.csfle.crosscloud.linking.DstSchemaLinkingClient;
import io.confluent.csfle.crosscloud.linking.SrcSchemaRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Orchestrates atomic DEK provisioning for a given encryption rule.
 *
 * Flow:
 *   1. Generate a new DEK in memory (AES-256)
 *   2. Wrap DEK with src KEK  → persist to src Schema Registry
 *   3. Wrap DEK with dst KEK  → send to dst Schema Registry via schema linking
 *   4. Zero out the plaintext DEK from memory
 *   5. Return result — DEK is now safe to use
 *
 * If step 2 or 3 fails, the DEK is zeroed and an exception is thrown.
 * The DEK is never activated unless both wraps succeed.
 */
public class DekProvisioner {

    private static final Logger log = LoggerFactory.getLogger(DekProvisioner.class);
    private static final String DEK_ALGORITHM = "AES";
    private static final int DEK_SIZE_BITS = 256;

    private final SrcSchemaRegistryClient srcRegistry;
    private final DstSchemaLinkingClient dstRegistry;

    public DekProvisioner(SrcSchemaRegistryClient srcRegistry, DstSchemaLinkingClient dstRegistry) {
        this.srcRegistry = srcRegistry;
        this.dstRegistry = dstRegistry;
    }

    public DekProvisioningResult provision(EncryptionRule rule) {
        log.info("Provisioning DEK for field '{}' — src: {}, dst: {}",
                rule.getField(), rule.getSrcKek().getId(), rule.getDstKek().getId());

        byte[] plaintextDek = generateDek();
        try {
            return provisionInternal(rule, plaintextDek);
        } finally {
            // Zero the plaintext DEK from memory regardless of outcome
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    private DekProvisioningResult provisionInternal(EncryptionRule rule, byte[] plaintextDek) {
        WrappedDek srcWrapped = wrapWithSrc(rule, plaintextDek);
        WrappedDek dstWrapped = wrapWithDst(rule, plaintextDek);

        // Both wraps succeeded — persist atomically
        persistToSrc(rule, srcWrapped);
        sendToDst(rule, dstWrapped);

        log.info("DEK for field '{}' provisioned successfully", rule.getField());
        return new DekProvisioningResult(rule.getField(), srcWrapped, dstWrapped);
    }

    private WrappedDek wrapWithSrc(EncryptionRule rule, byte[] plaintextDek) {
        try (KmsClient client = KmsClientFactory.create(rule.getSrcKek())) {
            byte[] encrypted = client.wrapDek(rule.getSrcKek().getId(), plaintextDek);
            return new WrappedDek(rule.getSrcKek(), encrypted);
        } catch (Exception e) {
            throw new DekProvisioningException(
                    "Failed to wrap DEK with src KEK for field '" + rule.getField() + "'", e);
        }
    }

    private WrappedDek wrapWithDst(EncryptionRule rule, byte[] plaintextDek) {
        try (KmsClient client = KmsClientFactory.create(rule.getDstKek())) {
            byte[] encrypted = client.wrapDek(rule.getDstKek().getId(), plaintextDek);
            return new WrappedDek(rule.getDstKek(), encrypted);
        } catch (Exception e) {
            throw new DekProvisioningException(
                    "Failed to wrap DEK with dst KEK for field '" + rule.getField() + "'", e);
        }
    }

    private void persistToSrc(EncryptionRule rule, WrappedDek srcWrapped) {
        try {
            srcRegistry.storeDek(rule.getField(), rule.getSrcKek().getId(), srcWrapped.encryptedDek());
        } catch (Exception e) {
            throw new DekProvisioningException(
                    "Failed to persist src-wrapped DEK for field '" + rule.getField() + "'", e);
        }
    }

    private void sendToDst(EncryptionRule rule, WrappedDek dstWrapped) {
        try {
            dstRegistry.publishDek(rule.getField(), rule.getDstKek().getId(), dstWrapped.encryptedDek());
        } catch (Exception e) {
            throw new DekProvisioningException(
                    "Failed to send dst-wrapped DEK via schema linking for field '" + rule.getField() + "'", e);
        }
    }

    private byte[] generateDek() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(DEK_ALGORITHM);
            keyGen.init(DEK_SIZE_BITS, new SecureRandom());
            SecretKey key = keyGen.generateKey();
            return key.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES not available", e);
        }
    }
}
