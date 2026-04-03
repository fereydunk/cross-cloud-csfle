package io.confluent.csfle.crosscloud.app;

import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import io.confluent.csfle.crosscloud.crypto.FieldEncryptor;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Negative-test consumer — reads from the AWS source cluster but attempts to decrypt
 * using GCP Cloud KMS against the AWS-wrapped (src) DEK ciphertext.
 *
 * Purpose: prove the KMS boundary.
 *   - The src-wrapped DEK is AWS KMS ciphertext — only AWS KMS can decrypt it.
 *   - GCP Cloud KMS cannot decrypt AWS KMS ciphertext and will throw an error.
 *   - Therefore, a consumer with only GCP KMS access cannot read source records.
 *
 * Expected outcome:
 *   - GCP KMS decrypt call throws an exception (InvalidCiphertextException or similar).
 *   - No plaintext DEK is obtained.
 *   - No source records are decrypted.
 *
 * Steps:
 *   1. Fetch the src-wrapped DEK bytes from the source Schema Registry.
 *   2. Attempt to decrypt those bytes using GCP Cloud KMS with the dst KEK.
 *      → This MUST fail — AWS KMS ciphertext is opaque to GCP.
 *   3. Report the failure clearly (expected behaviour).
 */
public class SourceConsumerGcpAttempt {

    private static final Logger log = LoggerFactory.getLogger(SourceConsumerGcpAttempt.class);

    private static final Pattern SSN_PATTERN   = Pattern.compile("\"social_security\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SCHEMA_PATTERN = Pattern.compile("\"schema\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern CONST_PATTERN  = Pattern.compile(
            "\"wrappedDek\"\\s*:\\s*\\{[^}]*\"const\"\\s*:\\s*\"([^\"]+)\"");

    private static final int POLL_TIMEOUT_SECONDS = 30;

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties cfg = load(propsFile);

        String srcSrUrl     = cfg.getProperty("src.sr.url");
        String srcSrKey     = cfg.getProperty("src.sr.api.key");
        String srcSrSecret  = cfg.getProperty("src.sr.api.secret");
        String dstKekId     = cfg.getProperty("rule.ssn.dst.kek.id");

        log.info("=== Negative Test: GCP KMS cannot decrypt AWS-wrapped DEK ===");
        log.info("Source cluster  : {}", cfg.getProperty("src.bootstrap.servers"));
        log.info("Topic           : {}", cfg.getProperty("topic"));
        log.info("GCP KEK (dst)   : {}", dstKekId);
        log.info("");
        log.info("EXPECTED: GCP Cloud KMS rejects the AWS-wrapped ciphertext.");
        log.info("          No DEK obtained. No records decrypted.");

        // ── Step 1: Fetch the raw src-wrapped DEK bytes from AWS SR ──────────
        log.info("");
        log.info("Step 1 — Fetching src-wrapped DEK bytes from AWS SR");
        byte[] awsWrappedDekBytes = fetchSrcWrappedDekBytes(srcSrUrl, srcSrKey, srcSrSecret);
        log.info("  Fetched {} bytes of AWS KMS ciphertext", awsWrappedDekBytes.length);

        // ── Step 2: Attempt GCP KMS decrypt on AWS ciphertext ────────────────
        log.info("");
        log.info("Step 2 — Attempting GCP Cloud KMS decrypt on AWS KMS ciphertext");
        log.info("  GCP key: {}", dstKekId);
        log.info("  GCP Cloud KMS expects ciphertext produced by its own encrypt — NOT AWS KMS output.");

        byte[] dek = null;
        try {
            dek = decryptWithGcp(dstKekId, awsWrappedDekBytes);
            // If we reach here, something is very wrong
            log.error("UNEXPECTED: GCP Cloud KMS decrypted AWS ciphertext — this should not happen!");
        } catch (Exception e) {
            log.info("  GCP Cloud KMS rejected the AWS-wrapped ciphertext (expected):");
            log.info("  → {}: {}", e.getClass().getSimpleName(), e.getMessage());
            log.info("");
            log.info("RESULT: GCP KMS cannot decrypt AWS KMS ciphertext.");
            log.info("        Source records are protected — only AWS KMS can unlock them.");
            log.info("        A GCP-only consumer cannot access plaintext from the source cluster.");
            return;
        }

        // Only reached if GCP somehow decrypted — run as consumer to show the outcome
        try {
            log.info("(Proceeding to consume with obtained DEK — this path should not be reached)");
            runConsumer(cfg, dek);
        } finally {
            if (dek != null) Arrays.fill(dek, (byte) 0);
        }
    }

    /**
     * Fetches the src-wrapped DEK ciphertext bytes directly from the AWS SR.
     * The subject contains the base64-encoded AWS KMS ciphertext as a JSON schema const.
     */
    private static byte[] fetchSrcWrappedDekBytes(String srUrl, String apiKey, String apiSecret)
            throws IOException {
        String authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((apiKey + ":" + apiSecret).getBytes());
        String subject = "cross-cloud-dek-social_security-src";
        String url = srUrl.replaceAll("/$", "") + "/subjects/" + subject + "/versions/latest";

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .GET()
                .build();

        try {
            HttpClient httpClient = HttpClient.newHttpClient();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException("SR fetch failed [" + resp.statusCode() + "]: " + resp.body());
            }

            // Extract and unescape the schema JSON
            Matcher sm = SCHEMA_PATTERN.matcher(resp.body());
            if (!sm.find()) throw new RuntimeException("Could not find 'schema' field in SR response");
            String schema = sm.group(1).replace("\\\"", "\"").replace("\\n", "\n").replace("\\\\", "\\");

            // Extract the wrappedDek const value
            Matcher cm = CONST_PATTERN.matcher(schema);
            if (!cm.find()) throw new RuntimeException("Could not find 'wrappedDek' in schema");
            String wrappedB64 = cm.group(1);
            log.info("  src-wrapped DEK (first 20 chars): {}...", wrappedB64.substring(0, Math.min(20, wrappedB64.length())));
            return Base64.getDecoder().decode(wrappedB64);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("HTTP interrupted", e);
        }
    }

    /**
     * Attempts to decrypt the given ciphertext using GCP Cloud KMS.
     * Will throw for AWS KMS ciphertext since GCP cannot decrypt it.
     */
    private static byte[] decryptWithGcp(String kekId, byte[] ciphertext) throws IOException {
        try (KeyManagementServiceClient gcpClient = KeyManagementServiceClient.create()) {
            DecryptResponse response = gcpClient.decrypt(kekId, ByteString.copyFrom(ciphertext));
            return response.getPlaintext().toByteArray();
        }
    }

    private static void runConsumer(Properties cfg, byte[] dek) {
        Pattern idPat   = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
        Pattern namePat = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
        int decrypted = 0;
        long deadline = System.currentTimeMillis() + POLL_TIMEOUT_SECONDS * 1_000L;

        try (KafkaConsumer<String, String> consumer = buildConsumer(cfg)) {
            consumer.subscribe(List.of(cfg.getProperty("topic")));
            while (System.currentTimeMillis() < deadline) {
                ConsumerRecords<String, String> batch = consumer.poll(Duration.ofSeconds(2));
                for (ConsumerRecord<String, String> record : batch) {
                    String raw    = record.value();
                    String encSsn = extract(SSN_PATTERN, raw);
                    if (encSsn == null || !encSsn.contains(":")) continue;
                    try {
                        String plainSsn = FieldEncryptor.decrypt(encSsn, dek);
                        String id   = extract(idPat, raw);
                        String name = extract(namePat, raw);
                        log.info(String.format("  %-9s | %-18s | %s", id, name, plainSsn));
                        decrypted++;
                    } catch (Exception e) { /* skip */ }
                }
                if (decrypted > 0 && batch.isEmpty()) break;
            }
        }
        log.info("Decrypted: {}", decrypted);
    }

    private static KafkaConsumer<String, String> buildConsumer(Properties cfg) {
        Properties p = new Properties();
        p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,     cfg.getProperty("src.bootstrap.servers"));
        p.put(ConsumerConfig.GROUP_ID_CONFIG,              "cross-cloud-csfle-gcp-attempt-" + System.currentTimeMillis());
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
