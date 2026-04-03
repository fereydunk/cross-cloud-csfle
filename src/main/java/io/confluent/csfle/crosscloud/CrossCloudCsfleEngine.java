package io.confluent.csfle.crosscloud;

import io.confluent.csfle.crosscloud.config.DekProvisioningMode;
import io.confluent.csfle.crosscloud.config.EncryptionRule;
import io.confluent.csfle.crosscloud.dek.DekProvisioningResult;
import io.confluent.csfle.crosscloud.dek.DekProvisioner;
import io.confluent.csfle.crosscloud.linking.DstSchemaLinkingClient;
import io.confluent.csfle.crosscloud.linking.SrcSchemaRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Entry point for cross-cloud CSFLE DEK provisioning.
 *
 * <p>Selects the correct provisioning path per rule based on {@link DekProvisioningMode}
 * and KMS type auto-detection:
 *
 * <ul>
 *   <li><strong>Same KMS type</strong> (auto-detected): single wrap — one KMS call, same
 *       ciphertext stored as both src and dst subjects. {@code dek.provisioning.mode} is
 *       ignored for these rules.</li>
 *   <li><strong>Different KMS, {@code dual}</strong> (default): two wrap calls, two subjects.
 *       Schema linking replicates the encrypted dst-wrapped DEK to the destination SR.</li>
 *   <li><strong>Different KMS, {@code split}</strong>: src wraps on source side only.
 *       Plaintext DEK is stored as a temporary transfer subject for schema linking to carry
 *       to the destination SR. Run {@code provision-dst} on the destination side to complete.</li>
 * </ul>
 */
public class CrossCloudCsfleEngine {

    private static final Logger log = LoggerFactory.getLogger(CrossCloudCsfleEngine.class);

    private final DekProvisioner provisioner;

    public CrossCloudCsfleEngine(SrcSchemaRegistryClient srcRegistry,
                                  DstSchemaLinkingClient dstRegistry) {
        this.provisioner = new DekProvisioner(srcRegistry, dstRegistry);
    }

    /**
     * Provisions DEKs for all given encryption rules using the specified mode.
     * Fails fast — if any rule fails, provisioning stops and an exception is thrown.
     */
    public List<DekProvisioningResult> provisionAll(List<EncryptionRule> rules,
                                                    DekProvisioningMode mode) {
        log.info("Provisioning DEKs for {} encryption rule(s)", rules.size());
        List<DekProvisioningResult> results = new ArrayList<>();
        for (EncryptionRule rule : rules) {
            results.add(provisionOne(rule, mode));
        }
        log.info("All DEKs provisioned successfully");
        return results;
    }

    private DekProvisioningResult provisionOne(EncryptionRule rule, DekProvisioningMode mode) {
        boolean sameKms = rule.getSrcKek().resolveType() == rule.getDstKek().resolveType();
        if (sameKms) {
            return provisioner.provisionSingle(rule);
        }
        return switch (mode) {
            case DUAL  -> provisioner.provision(rule);
            case SPLIT -> provisioner.provisionSplitSrc(rule);
        };
    }
}
