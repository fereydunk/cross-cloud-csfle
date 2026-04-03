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
 * Source-side consumer — AWS cluster, AWS KMS only.
 *
 * Verifies that the src-wrapped DEK stored in the source Schema Registry can be
 * unwrapped by AWS KMS and used to decrypt records from the source Kafka topic.
 * No GCP KMS or GCP cluster access is required.
 *
 * Steps:
 *   1. Fetch the src-wrapped DEK from the source SR and unwrap using AWS KMS.
 *   2. Consume records from the source Kafka topic (lkc-z2zw17).
 *   3. Decrypt the social_security field with AES-256-GCM and log plaintext.
 *   4. Zero the plaintext DEK on exit.
 */
public class SourceConsumer {

    private static final Logger log = LoggerFactory.getLogger(SourceConsumer.class);

    private static final Pattern ID_PATTERN  = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern NAME_PATTERN = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SSN_PATTERN  = Pattern.compile("\"social_security\"\\s*:\\s*\"([^\"]+)\"");

    private static final int POLL_TIMEOUT_SECONDS = 30;

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties cfg = load(propsFile);

        log.info("=== Source Consumer (AWS cluster, AWS KMS only) ===");
        log.info("Cluster : {}", cfg.getProperty("src.bootstrap.servers"));
        log.info("Topic   : {}", cfg.getProperty("topic"));

        // ── Step 1: Unwrap src DEK using AWS KMS ─────────────────────────────
        log.info("");
        log.info("Step 1 — Fetching src-wrapped DEK from AWS SR and unwrapping via AWS KMS");

        DekFetcher fetcher = new DekFetcher(
                cfg.getProperty("src.sr.url"),
                cfg.getProperty("src.sr.api.key"),
                cfg.getProperty("src.sr.api.secret"));

        byte[] dek = fetcher.fetchPlaintextDek("social_security", "src");

        // ── Step 2 & 3: Consume and decrypt ─────────────────────────────────
        try {
            log.info("");
            log.info("Step 2 — Consuming from AWS source topic and decrypting...");
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
                log.warn("No records decrypted. Ensure the producer has run and records exist in the source topic.");
            }

        } finally {
            Arrays.fill(dek, (byte) 0);
            log.info("Plaintext DEK zeroed from memory.");
        }
    }

    private static KafkaConsumer<String, String> buildConsumer(Properties cfg) {
        Properties p = new Properties();
        p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,     cfg.getProperty("src.bootstrap.servers"));
        p.put(ConsumerConfig.GROUP_ID_CONFIG,              "cross-cloud-csfle-src-consumer-" + System.currentTimeMillis());
        p.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,     "earliest");
        p.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG,    "true");
        p.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG,   StringDeserializer.class.getName());
        p.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        p.put("security.protocol", "SASL_SSL");
        p.put("sasl.mechanism",    "PLAIN");
        p.put("sasl.jaas.config",  jaas(cfg.getProperty("src.kafka.api.key"),
                                        cfg.getProperty("src.kafka.api.secret")));
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
