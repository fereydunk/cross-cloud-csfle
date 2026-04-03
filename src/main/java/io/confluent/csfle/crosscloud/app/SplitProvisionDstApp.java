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
 * <p>The destination SR is briefly switched to READWRITE to allow the dst-wrapped DEK
 * subject to be written (the SR is normally in IMPORT mode while the schema exporter runs).
 * The original mode is restored immediately after, whether or not the operation succeeds.
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
        log.info("Processing {} rule(s)...", rules.size());

        String originalMode = dstSr.getMode();
        log.info("Destination SR current mode: {} — switching to READWRITE for dst subject writes",
                originalMode);
        dstSr.setMode("READWRITE");

        try {
            for (EncryptionRule rule : rules) {
                provisionDst(rule, dstSr);
            }
        } finally {
            log.info("Restoring destination SR mode to {}", originalMode);
            dstSr.setMode(originalMode);
        }

        log.info("");
        log.info("=== Phase 2 Complete ===");
        log.info("All dst-wrapped DEK subjects stored. Transfer subjects deleted.");
        log.info("DEK provisioning is now fully complete — producers may start encrypting.");
    }

    private static void provisionDst(EncryptionRule rule, ConfluentSchemaRegistryClient dstSr) {
        String field = rule.getField();
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

            dstSr.storeDekForRole(field, rule.getDstKek().getId(), wrappedDek, "dst");
            log.info("Field '{}': dst-wrapped DEK stored in dst SR ✓", field);

            dstSr.deleteTransferSubject(field);
            log.info("Field '{}': transfer subject deleted ✓", field);

        } finally {
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }
}
