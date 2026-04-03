package io.confluent.csfle.crosscloud;

import io.confluent.csfle.crosscloud.config.DekProvisioningMode;
import io.confluent.csfle.crosscloud.config.EncryptionRule;
import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.config.KmsType;
import io.confluent.csfle.crosscloud.dek.DekProvisioningResult;
import io.confluent.csfle.crosscloud.linking.ConfluentSchemaRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

/**
 * Deployment runner for cross-cloud CSFLE — phase 1 (source side).
 *
 * Reads deployment.properties, resolves dek.provisioning.mode, and provisions DEKs
 * for all configured encryption rules.
 *
 * For split mode, this is phase 1 only. After this completes, wait for schema linking
 * to replicate the transfer subjects, then run 'provision-dst' on the destination side.
 */
public class CrossCloudCsfleRunner {

    private static final Logger log = LoggerFactory.getLogger(CrossCloudCsfleRunner.class);

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: CrossCloudCsfleRunner <path-to-deployment.properties>");
            System.exit(1);
        }

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(args[0])) {
            props.load(fis);
        }

        DekProvisioningMode mode = DekProvisioningMode.from(
                props.getProperty("dek.provisioning.mode", "dual"));

        log.info("=== Cross-Cloud CSFLE Deployment ===");
        log.info("Source cluster     : {}", props.getProperty("src.bootstrap.servers"));
        log.info("Destination cluster: {}", props.getProperty("dst.bootstrap.servers"));
        log.info("Topic              : {}", props.getProperty("topic"));
        log.info("DEK provisioning   : {}", mode);

        ConfluentSchemaRegistryClient srcSrClient = new ConfluentSchemaRegistryClient(
                props.getProperty("src.sr.url"),
                props.getProperty("src.sr.api.key"),
                props.getProperty("src.sr.api.secret"));

        CrossCloudCsfleEngine engine = new CrossCloudCsfleEngine(srcSrClient, srcSrClient);

        List<EncryptionRule> rules = buildRules(props);
        log.info("Provisioning {} encryption rule(s)...", rules.size());

        List<DekProvisioningResult> results = engine.provisionAll(rules, mode);

        log.info("");
        log.info("=== Provisioning Complete ===");
        for (DekProvisioningResult result : results) {
            log.info("Field  : {}", result.field());
            if (result.srcWrapped() != null) {
                log.info("  src KEK         : {}", result.srcWrapped().kek().getId());
                log.info("  src wrapped DEK : {}",
                        Base64.getEncoder().encodeToString(result.srcWrapped().encryptedDek()));
            }
            if (result.dstWrapped() != null && result.dstWrapped() != result.srcWrapped()) {
                log.info("  dst KEK         : {}", result.dstWrapped().kek().getId());
                log.info("  dst wrapped DEK : {}",
                        Base64.getEncoder().encodeToString(result.dstWrapped().encryptedDek()));
            }
            if (result.dstWrapped() == result.srcWrapped()) {
                log.info("  (single-KMS: same ciphertext stored for both src and dst subjects)");
            }
            log.info("  Status : {}", result.isSingleKmsMode() && mode == DekProvisioningMode.SPLIT
                    ? "PHASE 1 COMPLETE — run 'provision-dst' on destination side to finish"
                    : "ACTIVE — safe to encrypt with this DEK");
        }

        log.info("");
        if (mode == DekProvisioningMode.SPLIT) {
            log.info("Split mode — next step:");
            log.info("  1. Wait for schema linking to replicate the transfer subject(s) to dst SR");
            log.info("  2. Run on the destination side:");
            log.info("       java -jar cross-cloud-csfle.jar provision-dst <deployment.properties>");
        } else {
            log.info("src-wrapped DEK persisted to : {}", props.getProperty("src.sr.url"));
            log.info("dst-wrapped DEK persisted to : {} (schema exporter replicates to dst SR)",
                    props.getProperty("src.sr.url"));
            log.info("Records will flow via cluster linking: {} → {}",
                    props.getProperty("src.bootstrap.servers"),
                    props.getProperty("dst.bootstrap.servers"));
        }
    }

    public static List<EncryptionRule> buildRules(Properties props) {
        List<EncryptionRule> rules = new ArrayList<>();
        props.stringPropertyNames().stream()
                .filter(k -> k.endsWith(".field") && k.startsWith("rule."))
                .forEach(fieldKey -> {
                    String prefix = fieldKey.substring(0, fieldKey.lastIndexOf(".field"));

                    String srcKekId   = props.getProperty(prefix + ".src.kek.id");
                    String srcKekType = props.getProperty(prefix + ".src.kek.type");
                    String dstKekId   = props.getProperty(prefix + ".dst.kek.id");
                    String dstKekType = props.getProperty(prefix + ".dst.kek.type");

                    KekReference srcKek = srcKekType != null
                            ? new KekReference(srcKekId, KmsType.valueOf(srcKekType))
                            : new KekReference(srcKekId);

                    KekReference dstKek = dstKekType != null
                            ? new KekReference(dstKekId, KmsType.valueOf(dstKekType))
                            : new KekReference(dstKekId);

                    String field = props.getProperty(fieldKey);
                    rules.add(new EncryptionRule(field, srcKek, dstKek));
                    log.info("Loaded rule: field='{}' srcKek='{}' dstKek='{}'",
                            field, srcKekId, dstKekId);
                });
        return rules;
    }
}
