package io.confluent.csfle.crosscloud.dek;

import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.kms.KmsClient;
import io.confluent.csfle.crosscloud.kms.KmsClientFactory;
import io.confluent.csfle.crosscloud.linking.ConfluentSchemaRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Synchronises DEK versions from the surviving Schema Registry to the recovering SR.
 *
 * <p>Called at link re-establishment time, after the recovering cluster is back up and
 * its Schema Registry has received all schemas via the reverse schema exporter — but
 * <strong>before</strong> any mirror topic is promoted. This is the only window where:
 * <ul>
 *   <li>Both KMS systems are reachable (the recovering side is up)</li>
 *   <li>Both SRs are current (schema exporter catch-up is complete)</li>
 *   <li>No new records can flow (no topic is promoted yet)</li>
 * </ul>
 *
 * <p>Algorithm: for each DEK field discovered in the surviving SR, compare versions.
 * For any version present in the surviving SR but absent in the recovering SR, re-wrap:
 * <ol>
 *   <li>Fetch the wrapped DEK from the surviving SR and unwrap with the surviving KMS.</li>
 *   <li>Re-wrap the plaintext DEK with the recovering KMS.</li>
 *   <li>Push the re-wrapped DEK to the recovering SR under the recovering role.</li>
 *   <li>Zero the plaintext DEK from memory.</li>
 * </ol>
 *
 * <p>The operation is idempotent: versions already present in the recovering SR are skipped.
 *
 * <p><strong>Mode management:</strong> the recovering SR is briefly switched to READWRITE
 * before the sync and restored to IMPORT after. The original mode is always restored,
 * even if sync fails.
 *
 * <p>Example (GCP survived, AWS recovering):
 * <pre>
 *   DekFetcher gcpFetcher = new DekFetcher(gcpSrUrl, gcpSrKey, gcpSrSecret);
 *   ConfluentSchemaRegistryClient awsSr = new ConfluentSchemaRegistryClient(awsSrUrl, ...);
 *   KekReference awsKek = new KekReference("arn:aws:kms:us-east-2:...:key/...");
 *
 *   DekSyncer syncer = new DekSyncer(gcpFetcher, "dst", awsSr, "src", awsKek);
 *   SyncReport report = syncer.sync();
 *   if (!report.isComplete()) { // abort — do not promote topics }
 * </pre>
 */
public class DekSyncer {

    private static final Logger log = LoggerFactory.getLogger(DekSyncer.class);

    private final DekFetcher survivingFetcher;
    private final String survivingRole;
    private final ConfluentSchemaRegistryClient recoveringSr;
    private final String recoveringRole;
    private final KekReference recoveringKek;

    /**
     * @param survivingFetcher  DekFetcher pointing at the surviving SR (e.g. GCP SR)
     * @param survivingRole     role used on the surviving side ("dst" if GCP survived)
     * @param recoveringSr      client for the recovering SR (e.g. AWS SR)
     * @param recoveringRole    role to write on the recovering side ("src" if AWS is recovering)
     * @param recoveringKek     KEK on the recovering side used to re-wrap DEKs
     */
    public DekSyncer(DekFetcher survivingFetcher,
                     String survivingRole,
                     ConfluentSchemaRegistryClient recoveringSr,
                     String recoveringRole,
                     KekReference recoveringKek) {
        this.survivingFetcher = survivingFetcher;
        this.survivingRole    = survivingRole;
        this.recoveringSr     = recoveringSr;
        this.recoveringRole   = recoveringRole;
        this.recoveringKek    = recoveringKek;
    }

    /**
     * Runs the sync. The recovering SR is switched to READWRITE for the duration
     * and restored to its original mode after (whether sync succeeds or fails).
     *
     * @return a {@link SyncReport} — check {@link SyncReport#isComplete()} before
     *         proceeding to topic promotion.
     */
    public SyncReport sync() {
        log.info("=== DEK Sync: {} (surviving, role={}) → {} (recovering, role={})",
                "survivingSR", survivingRole, "recoveringSR", recoveringRole);

        String originalMode = recoveringSr.getMode();
        log.info("Recovering SR current mode: {} — switching to READWRITE for sync", originalMode);
        recoveringSr.setMode("READWRITE");

        try {
            return runSync();
        } finally {
            log.info("Restoring recovering SR mode to {}", originalMode);
            recoveringSr.setMode(originalMode);
        }
    }

    private SyncReport runSync() {
        List<String> fields  = survivingFetcher.listDekFields(survivingRole);
        List<String> errors  = new ArrayList<>();
        int versionsFound    = 0;
        int versionsSynced   = 0;
        int versionsPresent  = 0;

        log.info("Found {} DEK field(s) in surviving SR for role '{}': {}",
                fields.size(), survivingRole, fields);

        for (String field : fields) {
            List<Integer> versions = survivingFetcher.listVersions(field, survivingRole);
            versionsFound += versions.size();

            log.info("Field '{}': {} version(s) in surviving SR — {}",
                    field, versions.size(), versions);

            for (int version : versions) {
                String recoveringSubject = "cross-cloud-dek-" + field + "-" + recoveringRole;

                if (recoveringSr.hasSubjectVersion(recoveringSubject, version)) {
                    log.info("  v{} — already present in recovering SR, skipping", version);
                    versionsPresent++;
                    continue;
                }

                log.info("  v{} — missing in recovering SR, re-wrapping...", version);
                try {
                    syncVersion(field, version);
                    versionsSynced++;
                    log.info("  v{} — re-wrapped and pushed to recovering SR ✓", version);
                } catch (Exception e) {
                    String msg = "field='" + field + "' v" + version + ": " + e.getMessage();
                    log.error("  v{} — FAILED: {}", version, e.getMessage());
                    errors.add(msg);
                }
            }
        }

        SyncReport report = new SyncReport(fields.size(), versionsFound,
                versionsSynced, versionsPresent, errors);
        log.info("Sync complete: {}", report);

        if (!report.isComplete()) {
            log.error("Sync completed with errors — do NOT proceed to topic promotion until resolved:");
            report.errors().forEach(e -> log.error("  {}", e));
        } else {
            log.info("All DEK versions synced successfully. Safe to promote topics.");
        }
        return report;
    }

    private void syncVersion(String field, int version) {
        // Step 1: fetch and unwrap from surviving SR (uses surviving KMS via KmsClientFactory)
        DekResult dekResult = survivingFetcher.fetchDek(field, survivingRole, version);
        byte[] plaintextDek = dekResult.plaintext();

        try {
            // Step 2: re-wrap with recovering KMS
            byte[] rewrapped;
            try (KmsClient recoveringKmsClient = KmsClientFactory.create(recoveringKek)) {
                rewrapped = recoveringKmsClient.wrapDek(recoveringKek.getId(), plaintextDek);
            } catch (Exception e) {
                throw new RuntimeException(
                        "Failed to re-wrap DEK with recovering KMS '" + recoveringKek.getId() + "'", e);
            }

            // Step 3: push to recovering SR under the recovering role
            recoveringSr.storeDekForRole(field, recoveringKek.getId(), rewrapped, recoveringRole);

        } finally {
            // Step 4: always zero the plaintext DEK
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }
}
