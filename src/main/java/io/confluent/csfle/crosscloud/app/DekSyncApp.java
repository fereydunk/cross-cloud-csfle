package io.confluent.csfle.crosscloud.app;

import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.dek.DekFetcher;
import io.confluent.csfle.crosscloud.dek.DekSyncer;
import io.confluent.csfle.crosscloud.dek.SyncReport;
import io.confluent.csfle.crosscloud.linking.ConfluentSchemaRegistryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Pre-failback DEK sync — re-wraps DEK versions from the surviving SR with the recovering
 * KMS and pushes them to the recovering SR.
 *
 * <p>Run this <strong>before</strong> re-establishing the cluster link. Only after
 * this completes successfully should topics be promoted and the link brought up.
 *
 * <p>Normal usage (GCP survived, AWS recovering):
 * <pre>
 *   java -jar cross-cloud-csfle.jar sync deployment/deployment.properties
 * </pre>
 *
 * <p>The direction is inferred automatically:
 * <ul>
 *   <li>If only the dst SR (GCP) is reachable → surviving=dst, recovering=src (AWS)</li>
 *   <li>If only the src SR (AWS) is reachable → surviving=src, recovering=dst (GCP)</li>
 * </ul>
 * Provide the {@code sync.surviving.role} property to override (default: "dst").
 *
 * <p>Properties used (all already present in deployment.properties):
 * <ul>
 *   <li>{@code src.sr.url}, {@code src.sr.api.key}, {@code src.sr.api.secret}</li>
 *   <li>{@code dst.sr.url}, {@code dst.sr.api.key}, {@code dst.sr.api.secret}</li>
 *   <li>{@code rule.ssn.src.kek.id} — AWS KEK for re-wrapping</li>
 *   <li>{@code rule.ssn.dst.kek.id} — GCP KEK for re-wrapping</li>
 *   <li>{@code sync.surviving.role} — "dst" (default) or "src"</li>
 * </ul>
 */
public class DekSyncApp {

    private static final Logger log = LoggerFactory.getLogger(DekSyncApp.class);

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties cfg   = load(propsFile);

        // Which side survived? Default: GCP (dst) survived, AWS (src) is recovering.
        String survivingRole  = cfg.getProperty("sync.surviving.role", "dst");
        String recoveringRole = survivingRole.equals("dst") ? "src" : "dst";

        log.info("=== DEK Sync (pre-failback) ===");
        log.info("Surviving side  : {} (role={})",
                survivingRole.equals("dst") ? cfg.getProperty("dst.sr.url") : cfg.getProperty("src.sr.url"),
                survivingRole);
        log.info("Recovering side : {} (role={})",
                recoveringRole.equals("src") ? cfg.getProperty("src.sr.url") : cfg.getProperty("dst.sr.url"),
                recoveringRole);
        log.info("");
        log.info("This sync MUST complete before the cluster link is re-established.");
        log.info("The recovering SR will be briefly switched to READWRITE during sync.");

        // Build clients
        DekFetcher survivingFetcher;
        ConfluentSchemaRegistryClient recoveringSr;
        KekReference recoveringKek;

        if (survivingRole.equals("dst")) {
            // GCP survived, AWS recovering
            survivingFetcher = new DekFetcher(
                    cfg.getProperty("dst.sr.url"),
                    cfg.getProperty("dst.sr.api.key"),
                    cfg.getProperty("dst.sr.api.secret"));
            recoveringSr = new ConfluentSchemaRegistryClient(
                    cfg.getProperty("src.sr.url"),
                    cfg.getProperty("src.sr.api.key"),
                    cfg.getProperty("src.sr.api.secret"));
            recoveringKek = new KekReference(cfg.getProperty("rule.ssn.src.kek.id"));
        } else {
            // AWS survived, GCP recovering
            survivingFetcher = new DekFetcher(
                    cfg.getProperty("src.sr.url"),
                    cfg.getProperty("src.sr.api.key"),
                    cfg.getProperty("src.sr.api.secret"));
            recoveringSr = new ConfluentSchemaRegistryClient(
                    cfg.getProperty("dst.sr.url"),
                    cfg.getProperty("dst.sr.api.key"),
                    cfg.getProperty("dst.sr.api.secret"));
            recoveringKek = new KekReference(cfg.getProperty("rule.ssn.dst.kek.id"));
        }

        DekSyncer syncer = new DekSyncer(
                survivingFetcher, survivingRole,
                recoveringSr, recoveringRole,
                recoveringKek);

        log.info("");
        SyncReport report = syncer.sync();
        log.info("");

        if (report.isComplete()) {
            log.info("✓ Sync successful. All DEK versions are present on both sides.");
            log.info("  You may now re-establish the cluster link.");
        } else {
            log.error("✗ Sync completed with {} error(s). DO NOT re-establish the cluster link.",
                    report.errors().size());
            log.error("  Fix the errors above and re-run the sync.");
            System.exit(1);
        }
    }

    private static Properties load(String path) throws IOException {
        Properties p = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) { p.load(fis); }
        return p;
    }
}
