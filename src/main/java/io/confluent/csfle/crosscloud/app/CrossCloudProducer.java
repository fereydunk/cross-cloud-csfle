package io.confluent.csfle.crosscloud.app;

import io.confluent.csfle.crosscloud.CrossCloudCsfleEngine;
import io.confluent.csfle.crosscloud.config.EncryptionRule;
import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.config.KmsType;
import io.confluent.csfle.crosscloud.crypto.FieldEncryptor;
import io.confluent.csfle.crosscloud.dek.DekFetcher;
import io.confluent.csfle.crosscloud.dek.DekResult;
import io.confluent.csfle.crosscloud.linking.ConfluentSchemaRegistryClient;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Cross-cloud CSFLE producer — AWS side.
 *
 * Steps:
 *   1. Provision DEKs via CrossCloudCsfleEngine (idempotent — safe to re-run).
 *   2. Fetch the src-wrapped DEK from the source SR and unwrap it using AWS KMS.
 *   3. Produce records to the source Kafka cluster with the social_security field
 *      AES-256-GCM encrypted in-process.
 *   4. Zero the plaintext DEK on exit.
 *
 * Records flow to the GCP destination cluster via cluster linking.
 * The dst-wrapped DEK is replicated to the GCP SR via schema linking.
 * The CrossCloudConsumer on the GCP side decrypts using GCP Cloud KMS.
 */
public class CrossCloudProducer {

    private static final Logger log = LoggerFactory.getLogger(CrossCloudProducer.class);

    private static final String[][] RECORDS = {
            {"rec-301", "Alice Johnson",  "123-45-6789"},
            {"rec-302", "Bob Martinez",   "234-56-7890"},
            {"rec-303", "Carol Williams", "345-67-8901"},
            {"rec-304", "David Brown",    "456-78-9012"},
            {"rec-305", "Eva Davis",      "567-89-0123"},
            {"rec-306", "Frank Miller",   "678-90-1234"},
            {"rec-307", "Grace Wilson",   "789-01-2345"},
            {"rec-308", "Henry Moore",    "890-12-3456"},
            {"rec-309", "Iris Taylor",    "901-23-4567"},
            {"rec-310", "James Anderson", "012-34-5678"},
    };

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties cfg = load(propsFile);

        log.info("=== Cross-Cloud CSFLE Producer ===");
        log.info("Source cluster  : {}", cfg.getProperty("src.bootstrap.servers"));
        log.info("Topic           : {}", cfg.getProperty("topic"));

        // ── Step 1: Provision DEKs (idempotent) ────────────────────────────
        log.info("");
        log.info("Step 1 — Provisioning DEKs (src-wrapped → src SR, dst-wrapped → dst SR via schema linking)");

        // Both src and dst DEK subjects are written to the src SR.
        // The schema exporter replicates them to the dst SR automatically.
        // (Dst SR is in IMPORT mode and rejects direct writes.)
        ConfluentSchemaRegistryClient srcSr = new ConfluentSchemaRegistryClient(
                cfg.getProperty("src.sr.url"),
                cfg.getProperty("src.sr.api.key"),
                cfg.getProperty("src.sr.api.secret"));

        CrossCloudCsfleEngine engine = new CrossCloudCsfleEngine(srcSr, srcSr);
        engine.provisionAll(buildRules(cfg));
        log.info("DEKs provisioned.");

        // ── Step 2: Fetch + unwrap src DEK ────────────────────────────────
        log.info("");
        log.info("Step 2 — Fetching src-wrapped DEK from SR and unwrapping via AWS KMS");

        DekFetcher fetcher = new DekFetcher(
                cfg.getProperty("src.sr.url"),
                cfg.getProperty("src.sr.api.key"),
                cfg.getProperty("src.sr.api.secret"));

        DekResult dek = fetcher.fetchDek("social_security", "src");

        // ── Step 3: Produce encrypted records ─────────────────────────────
        try {
            log.info("DEK version {} will be embedded in each encrypted field.", dek.version());
            log.info("");
            log.info("Step 3 — Producing {} CSFLE-encrypted records to '{}'",
                    RECORDS.length, cfg.getProperty("topic"));
            log.info("─────────────────────────────────────────────────────────────────");

            try (KafkaProducer<String, String> producer = buildProducer(cfg)) {
                for (String[] rec : RECORDS) {
                    String id = rec[0], name = rec[1], ssn = rec[2];
                    String encSsn = FieldEncryptor.encrypt(ssn, dek.plaintext(), dek.version());
                    String value  = json(id, name, encSsn);

                    producer.send(new ProducerRecord<>(cfg.getProperty("topic"), id, value),
                            (meta, ex) -> {
                                if (ex != null) log.error("Produce error", ex);
                            });

                    log.info(String.format("  %-7s | %-17s | SSN encrypted → %s...",
                            id, name, encSsn.substring(0, Math.min(20, encSsn.length()))));
                }
                producer.flush();
            }

            log.info("─────────────────────────────────────────────────────────────────");
            log.info("All {} records produced. Records will appear in GCP cluster via cluster linking.", RECORDS.length);

        } finally {
            Arrays.fill(dek.plaintext(), (byte) 0);
            log.info("Plaintext DEK zeroed from memory.");
        }
    }

    private static KafkaProducer<String, String> buildProducer(Properties cfg) {
        Properties p = new Properties();
        p.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,      cfg.getProperty("src.bootstrap.servers"));
        p.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,   StringSerializer.class.getName());
        p.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        p.put(ProducerConfig.ACKS_CONFIG,                   "all");
        p.put("security.protocol", "SASL_SSL");
        p.put("sasl.mechanism",    "PLAIN");
        p.put("sasl.jaas.config",  jaas(cfg.getProperty("src.kafka.api.key"),
                                        cfg.getProperty("src.kafka.api.secret")));
        return new KafkaProducer<>(p);
    }

    private static List<EncryptionRule> buildRules(Properties cfg) {
        List<EncryptionRule> rules = new ArrayList<>();
        cfg.stringPropertyNames().stream()
                .filter(k -> k.endsWith(".field") && k.startsWith("rule."))
                .forEach(fieldKey -> {
                    String prefix = fieldKey.substring(0, fieldKey.lastIndexOf(".field"));
                    String srcId   = cfg.getProperty(prefix + ".src.kek.id");
                    String srcType = cfg.getProperty(prefix + ".src.kek.type");
                    String dstId   = cfg.getProperty(prefix + ".dst.kek.id");
                    String dstType = cfg.getProperty(prefix + ".dst.kek.type");
                    String field   = cfg.getProperty(fieldKey);

                    KekReference srcKek = srcType != null
                            ? new KekReference(srcId, KmsType.valueOf(srcType))
                            : new KekReference(srcId);
                    KekReference dstKek = dstType != null
                            ? new KekReference(dstId, KmsType.valueOf(dstType))
                            : new KekReference(dstId);

                    rules.add(new EncryptionRule(field, srcKek, dstKek));
                });
        return rules;
    }

    private static Properties load(String path) throws IOException {
        Properties p = new Properties();
        try (FileInputStream fis = new FileInputStream(path)) { p.load(fis); }
        return p;
    }

    private static String jaas(String key, String secret) {
        return "org.apache.kafka.common.security.plain.PlainLoginModule required " +
               "username=\"" + key + "\" password=\"" + secret + "\";";
    }

    private static String json(String id, String name, String encSsn) {
        return "{\"id\":\"" + id + "\",\"name\":\"" + name +
               "\",\"social_security\":\"" + encSsn + "\"}";
    }
}
