package io.confluent.csfle.crosscloud.app;

import io.confluent.csfle.crosscloud.CrossCloudCsfleRunner;
import io.confluent.csfle.crosscloud.config.DekProvisioningMode;
import io.confluent.csfle.crosscloud.config.EncryptionRule;
import io.confluent.csfle.crosscloud.kms.KmsClient;
import io.confluent.csfle.crosscloud.kms.KmsClientFactory;
import io.confluent.csfle.crosscloud.linking.ConfluentSchemaRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Split-mode provisioning — phase 2 (destination side).
 *
 * <p>Reads the plaintext DEK from the transfer subject that schema linking replicated
 * from the source SR, wraps it with the destination KEK, stores the dst-wrapped DEK
 * subject in the destination SR, and deletes the transfer subject.
 *
 * <p>Run this on the destination side after:
 * <ol>
 *   <li>{@code provision} (phase 1) has completed on the source side, and</li>
 *   <li>Schema linking has replicated the transfer subject(s) to the destination SR.</li>
 * </ol>
 *
 * <pre>
 *   java -jar cross-cloud-csfle.jar provision-dst deployment/deployment.properties
 * </pre>
 *
 * <p>Uses subject-level mode overrides (PUT /mode/{subject}) rather than the global SR mode,
 * so the schema exporter continues running without interruption. Each dst-wrapped DEK subject
 * is individually switched to READWRITE, written, then reverted to the global mode.
 */
public class SplitProvisionDstApp {

    private static final Logger log = LoggerFactory.getLogger(SplitProvisionDstApp.class);

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(propsFile)) {
            props.load(fis);
        }

        String modeStr = props.getProperty("dek.provisioning.mode", "dual");
        if (DekProvisioningMode.from(modeStr) != DekProvisioningMode.SPLIT) {
            log.error("provision-dst is only for split mode. " +
                      "Set dek.provisioning.mode=split in deployment.properties.");
            System.exit(1);
        }

        log.info("=== Split-Mode Provisioning — Phase 2 (Destination Side) ===");
        log.info("Destination SR : {}", props.getProperty("dst.sr.url"));

        ConfluentSchemaRegistryClient dstSr = new ConfluentSchemaRegistryClient(
                props.getProperty("dst.sr.url"),
                props.getProperty("dst.sr.api.key"),
                props.getProperty("dst.sr.api.secret"));

        List<EncryptionRule> rules = CrossCloudCsfleRunner.buildRules(props);
        log.info("Processing {} rule(s) using subject-level mode overrides...", rules.size());
        log.info("Global dst SR mode is unchanged — schema exporter continues running.");

        for (EncryptionRule rule : rules) {
            provisionDst(rule, dstSr);
        }

        log.info("");
        log.info("=== Phase 2 Complete ===");
        log.info("All dst-wrapped DEK subjects stored. Transfer subjects deleted.");
        log.info("DEK provisioning is now fully complete — producers may start encrypting.");
    }

    private static void provisionDst(EncryptionRule rule, ConfluentSchemaRegistryClient dstSr) {
        String field = rule.getField();
        String dstSubject = "cross-cloud-dek-" + field + "-dst";

        log.info("Field '{}': reading transfer subject from dst SR...", field);
        byte[] plaintextDek = dstSr.readTransferSubject(field);
        try {
            log.info("Field '{}': wrapping with dst KEK '{}'...",
                    field, rule.getDstKek().getId());

            byte[] wrappedDek;
            try (KmsClient kms = KmsClientFactory.create(rule.getDstKek())) {
                wrappedDek = kms.wrapDek(rule.getDstKek().getId(), plaintextDek);
            } catch (Exception e) {
                throw new RuntimeException(
                        "Failed to wrap DEK with dst KEK for field '" + field + "'", e);
            }

            // Use subject-level mode override so the global SR mode (IMPORT) is unchanged
            // and the schema exporter continues running without interruption.
            log.info("Field '{}': setting subject '{}' to READWRITE for write...", field, dstSubject);
            dstSr.setSubjectMode(dstSubject, "READWRITE");
            try {
                dstSr.storeDekForRole(field, rule.getDstKek().getId(), wrappedDek, "dst");
                log.info("Field '{}': dst-wrapped DEK stored in dst SR ✓", field);
            } finally {
                dstSr.deleteSubjectMode(dstSubject);
                log.info("Field '{}': subject '{}' mode override cleared ✓", field, dstSubject);
            }

            dstSr.deleteTransferSubject(field);
            log.info("Field '{}': transfer subject deleted ✓", field);

        } finally {
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }
}
