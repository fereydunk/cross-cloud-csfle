package io.confluent.csfle.crosscloud.app;

import io.confluent.csfle.crosscloud.crypto.FieldEncryptor;
import io.confluent.csfle.crosscloud.dek.DekFetcher;
import io.confluent.csfle.crosscloud.dek.DekResult;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-cloud CSFLE consumer — GCP destination side.
 *
 * Steps:
 *   1. Fetch the dst-wrapped DEK from the destination SR and unwrap using GCP Cloud KMS.
 *      The dst-wrapped DEK was provisioned by CrossCloudProducer (or CrossCloudCsfleRunner)
 *      and replicated here automatically by the schema exporter.
 *   2. Consume records from the GCP mirror topic (replicated via cluster linking).
 *   3. Decrypt the social_security field with AES-256-GCM and log plaintext.
 *   4. Zero the plaintext DEK on exit.
 *
 * No cross-cloud KMS call is made at read time — the GCP KMS is the only KMS needed here.
 */
public class CrossCloudConsumer {

    private static final Logger log = LoggerFactory.getLogger(CrossCloudConsumer.class);

    private static final Pattern ID_PATTERN  = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern NAME_PATTERN = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SSN_PATTERN  = Pattern.compile("\"social_security\"\\s*:\\s*\"([^\"]+)\"");

    private static final int POLL_TIMEOUT_SECONDS = 30;

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties cfg = load(propsFile);

        log.info("=== Cross-Cloud CSFLE Consumer (GCP Destination) ===");
        log.info("Cluster : {}", cfg.getProperty("dst.bootstrap.servers"));
        log.info("Topic   : {}", cfg.getProperty("topic"));

        DekFetcher fetcher = new DekFetcher(
                cfg.getProperty("dst.sr.url"),
                cfg.getProperty("dst.sr.api.key"),
                cfg.getProperty("dst.sr.api.secret"));

        // DEK cache: version → plaintext DEK bytes.
        // DEKs are fetched lazily from GCP SR and unwrapped via GCP Cloud KMS on first access.
        // Multiple versions may coexist on the topic after DEK rotation; each is cached separately.
        // All cached plaintext DEKs are zeroed on exit.
        Map<Integer, byte[]> dekCache = new HashMap<>();

        // ── Step 2 & 3: Consume and decrypt ────────────────────────────────
        try {
            log.info("");
            log.info("Step 2 — Consuming from GCP mirror topic and decrypting...");
            log.info("───────────────────────────────────────────────────────────────");
            log.info(String.format("  %-9s | %-18s | SSN (decrypted)", "ID", "Name"));
            log.info("───────────────────────────────────────────────────────────────");

            int decrypted = 0;
            int skipped   = 0;
            long deadline = System.currentTimeMillis() + POLL_TIMEOUT_SECONDS * 1_000L;

            try (KafkaConsumer<String, String> consumer = buildConsumer(cfg)) {
                consumer.subscribe(List.of(cfg.getProperty("topic")));

                while (System.currentTimeMillis() < deadline) {
                    ConsumerRecords<String, String> batch = consumer.poll(Duration.ofSeconds(2));

                    for (ConsumerRecord<String, String> record : batch) {
                        String raw    = record.value();
                        String id     = extract(ID_PATTERN, raw);
                        String name   = extract(NAME_PATTERN, raw);
                        String encSsn = extract(SSN_PATTERN, raw);

                        if (encSsn == null || !encSsn.contains(":")) {
                            skipped++;
                            continue;
                        }

                        try {
                            int version = FieldEncryptor.parseDekVersion(encSsn);
                            byte[] dek  = dekCache.computeIfAbsent(version, v -> {
                                DekResult r = fetcher.fetchDek("social_security", "dst", v);
                                return r.plaintext();
                            });
                            String plainSsn = FieldEncryptor.decrypt(encSsn, dek);
                            log.info(String.format("  %-9s | %-18s | %s", id, name, plainSsn));
                            decrypted++;
                        } catch (Exception e) {
                            skipped++;
                        }
                    }

                    if (decrypted > 0 && batch.isEmpty()) break;
                }
            }

            log.info("───────────────────────────────────────────────────────────────");
            log.info("Decrypted: {}   Skipped (not our format): {}", decrypted, skipped);
            if (decrypted == 0) {
                log.warn("No records decrypted. Ensure the producer has run and cluster linking has replicated the records.");
            }

        } finally {
            dekCache.values().forEach(dek -> Arrays.fill(dek, (byte) 0));
            log.info("Plaintext DEK(s) zeroed from memory.");
        }
    }

    private static KafkaConsumer<String, String> buildConsumer(Properties cfg) {
        Properties p = new Properties();
        p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,     cfg.getProperty("dst.bootstrap.servers"));
        p.put(ConsumerConfig.GROUP_ID_CONFIG,              "cross-cloud-csfle-consumer-" + System.currentTimeMillis());
        p.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,     "earliest");
        p.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG,    "true");
        p.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG,   StringDeserializer.class.getName());
        p.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        p.put("security.protocol", "SASL_SSL");
        p.put("sasl.mechanism",    "PLAIN");
        p.put("sasl.jaas.config",  jaas(cfg.getProperty("dst.kafka.api.key"),
                                        cfg.getProperty("dst.kafka.api.secret")));
        return new KafkaConsumer<>(p);
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

    private static String extract(Pattern p, String text) {
        if (text == null) return null;
        Matcher m = p.matcher(text);
        return m.find() ? m.group(1) : null;
    }
}
