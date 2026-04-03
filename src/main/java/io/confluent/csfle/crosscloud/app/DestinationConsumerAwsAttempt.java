package io.confluent.csfle.crosscloud.app;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import io.confluent.csfle.crosscloud.crypto.FieldEncryptor;
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
 * Negative-test consumer — reads from the GCP destination cluster but attempts to decrypt
 * using AWS KMS against the GCP-wrapped (dst) DEK ciphertext.
 *
 * Purpose: prove the KMS boundary on the destination side.
 *   - The dst-wrapped DEK is GCP Cloud KMS ciphertext — only GCP Cloud KMS can decrypt it.
 *   - AWS KMS cannot decrypt GCP Cloud KMS ciphertext and will throw an error.
 *   - Therefore, a consumer with only AWS KMS access cannot read destination records.
 *
 * Expected outcome:
 *   - AWS KMS decrypt call throws an exception (InvalidCiphertextException or similar).
 *   - No plaintext DEK is obtained.
 *   - No destination records are decrypted.
 *
 * Steps:
 *   1. Fetch the dst-wrapped DEK bytes from the destination Schema Registry (GCP SR).
 *   2. Attempt to decrypt those bytes using AWS KMS with the src KEK.
 *      → This MUST fail — GCP Cloud KMS ciphertext is opaque to AWS KMS.
 *   3. Report the failure clearly (expected behaviour).
 */
public class DestinationConsumerAwsAttempt {

    private static final Logger log = LoggerFactory.getLogger(DestinationConsumerAwsAttempt.class);

    private static final Pattern SSN_PATTERN    = Pattern.compile("\"social_security\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SCHEMA_PATTERN = Pattern.compile("\"schema\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern CONST_PATTERN  = Pattern.compile(
            "\"wrappedDek\"\\s*:\\s*\\{[^}]*\"const\"\\s*:\\s*\"([^\"]+)\"");

    private static final int POLL_TIMEOUT_SECONDS = 30;

    public static void main(String[] args) throws IOException {
        String propsFile = args.length > 0 ? args[0] : "deployment/deployment.properties";
        Properties cfg = load(propsFile);

        String dstSrUrl    = cfg.getProperty("dst.sr.url");
        String dstSrKey    = cfg.getProperty("dst.sr.api.key");
        String dstSrSecret = cfg.getProperty("dst.sr.api.secret");
        String srcKekId    = cfg.getProperty("rule.ssn.src.kek.id");

        log.info("=== Negative Test: AWS KMS cannot decrypt GCP-wrapped DEK ===");
        log.info("Destination cluster : {}", cfg.getProperty("dst.bootstrap.servers"));
        log.info("Topic               : {}", cfg.getProperty("topic"));
        log.info("AWS KEK (src)       : {}", srcKekId);
        log.info("");
        log.info("EXPECTED: AWS KMS rejects the GCP-wrapped ciphertext.");
        log.info("          No DEK obtained. No records decrypted.");

        // ── Step 1: Fetch the raw dst-wrapped DEK bytes from GCP SR ─────────
        log.info("");
        log.info("Step 1 — Fetching dst-wrapped DEK bytes from GCP SR");
        byte[] gcpWrappedDekBytes = fetchDstWrappedDekBytes(dstSrUrl, dstSrKey, dstSrSecret);
        log.info("  Fetched {} bytes of GCP Cloud KMS ciphertext", gcpWrappedDekBytes.length);

        // ── Step 2: Attempt AWS KMS decrypt on GCP ciphertext ───────────────
        log.info("");
        log.info("Step 2 — Attempting AWS KMS decrypt on GCP Cloud KMS ciphertext");
        log.info("  AWS key: {}", srcKekId);
        log.info("  AWS KMS expects ciphertext produced by its own encrypt — NOT GCP Cloud KMS output.");

        byte[] dek = null;
        try {
            dek = decryptWithAws(srcKekId, gcpWrappedDekBytes);
            // If we reach here, something is very wrong
            log.error("UNEXPECTED: AWS KMS decrypted GCP ciphertext — this should not happen!");
        } catch (Exception e) {
            log.info("  AWS KMS rejected the GCP-wrapped ciphertext (expected):");
            log.info("  → {}: {}", e.getClass().getSimpleName(), e.getMessage());
            log.info("");
            log.info("RESULT: AWS KMS cannot decrypt GCP Cloud KMS ciphertext.");
            log.info("        Destination records are protected — only GCP Cloud KMS can unlock them.");
            log.info("        An AWS-only consumer cannot access plaintext from the destination cluster.");
            return;
        }

        // Only reached if AWS somehow decrypted — run as consumer to show the outcome
        try {
            log.info("(Proceeding to consume with obtained DEK — this path should not be reached)");
            runConsumer(cfg, dek);
        } finally {
            if (dek != null) Arrays.fill(dek, (byte) 0);
        }
    }

    /**
     * Fetches the dst-wrapped DEK ciphertext bytes directly from the GCP SR.
     * The subject contains the base64-encoded GCP Cloud KMS ciphertext as a JSON schema const.
     */
    private static byte[] fetchDstWrappedDekBytes(String srUrl, String apiKey, String apiSecret)
            throws IOException {
        String authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((apiKey + ":" + apiSecret).getBytes());
        String subject = "cross-cloud-dek-social_security-dst";
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
            log.info("  dst-wrapped DEK (first 20 chars): {}...", wrappedB64.substring(0, Math.min(20, wrappedB64.length())));
            return Base64.getDecoder().decode(wrappedB64);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("HTTP interrupted", e);
        }
    }

    /**
     * Attempts to decrypt the given ciphertext using AWS KMS.
     * Will throw for GCP Cloud KMS ciphertext since AWS cannot decrypt it.
     */
    private static byte[] decryptWithAws(String kekId, byte[] ciphertext) {
        try (KmsClient awsClient = KmsClient.create()) {
            DecryptRequest request = DecryptRequest.builder()
                    .keyId(kekId)
                    .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
                    .build();
            DecryptResponse response = awsClient.decrypt(request);
            return response.plaintext().asByteArray();
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
        p.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG,     cfg.getProperty("dst.bootstrap.servers"));
        p.put(ConsumerConfig.GROUP_ID_CONFIG,              "cross-cloud-csfle-aws-attempt-" + System.currentTimeMillis());
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
