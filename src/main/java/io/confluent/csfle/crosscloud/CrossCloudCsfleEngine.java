package io.confluent.csfle.crosscloud;

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
 * Entry point for cross-cloud CSFLE.
 *
 * For each encryption rule, provisions a DEK atomically:
 *   - src-wrapped copy persisted to src Schema Registry
 *   - dst-wrapped copy sent to dst Schema Registry via schema linking
 *
 * No new component is introduced. Data movement uses cluster linking (records)
 * and schema linking (key material).
 *
 * Usage:
 * <pre>
 *   ConfluentSchemaRegistryClient srcClient = new ConfluentSchemaRegistryClient(srcUrl, key, secret);
 *   ConfluentSchemaRegistryClient dstClient = new ConfluentSchemaRegistryClient(srcUrl, key, secret);
 *
 *   CrossCloudCsfleEngine engine = new CrossCloudCsfleEngine(srcClient, dstClient);
 *
 *   List&lt;EncryptionRule&gt; rules = List.of(
 *       new EncryptionRule("ssn",
 *           new KekReference("arn:aws:kms:us-east-1:123:key/abc"),
 *           new KekReference("projects/my-proj/locations/us/keyRings/r/cryptoKeys/k"))
 *   );
 *
 *   engine.provisionAll(rules);
 * </pre>
 */
public class CrossCloudCsfleEngine {

    private static final Logger log = LoggerFactory.getLogger(CrossCloudCsfleEngine.class);

    private final DekProvisioner provisioner;

    public CrossCloudCsfleEngine(SrcSchemaRegistryClient srcRegistry,
                                  DstSchemaLinkingClient dstRegistry) {
        this.provisioner = new DekProvisioner(srcRegistry, dstRegistry);
    }

    /**
     * Provisions DEKs for all given encryption rules.
     * Fails fast — if any rule fails, provisioning stops and an exception is thrown.
     * No DEK is activated until its own provisioning completes fully.
     */
    public List<DekProvisioningResult> provisionAll(List<EncryptionRule> rules) {
        log.info("Provisioning DEKs for {} encryption rule(s)", rules.size());
        List<DekProvisioningResult> results = new ArrayList<>();
        for (EncryptionRule rule : rules) {
            results.add(provisioner.provision(rule));
        }
        log.info("All DEKs provisioned successfully");
        return results;
    }
}
