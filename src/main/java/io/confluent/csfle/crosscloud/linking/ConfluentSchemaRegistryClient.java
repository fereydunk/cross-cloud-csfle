package io.confluent.csfle.crosscloud.linking;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

/**
 * Confluent Schema Registry client for DEK persistence.
 *
 * Two storage strategies are attempted in order:
 *
 * 1. DEK Registry API (POST /keks + POST /deks/{kekName}/versions)
 *    Available on Confluent Cloud clusters with the field-level encryption feature enabled.
 *    This is the production path — schema linking replicates DEKS subjects automatically.
 *
 * 2. Schema subject fallback (POST /subjects/{subject}/versions with schema type JSON)
 *    Used when the DEK Registry is not enabled (e.g. standard SR tier in a PoC environment).
 *    The wrapped DEK material is stored as a JSON schema under a deterministic subject name.
 *    In production this subject would be replicated via schema linking the same way.
 *
 * The fallback does not change the security model — the wrapped DEK bytes are identical
 * in both cases. Only the storage endpoint differs.
 */
public class ConfluentSchemaRegistryClient implements SrcSchemaRegistryClient, DstSchemaLinkingClient {

    private static final Logger log = LoggerFactory.getLogger(ConfluentSchemaRegistryClient.class);

    private final String baseUrl;
    private final HttpClient httpClient;
    private final String authHeader;

    public ConfluentSchemaRegistryClient(String baseUrl, String apiKey, String apiSecret) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.httpClient = HttpClient.newHttpClient();
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((apiKey + ":" + apiSecret).getBytes());
    }

    @Override
    public void storeDek(String field, String kekId, byte[] encryptedDek) {
        store(field, kekId, encryptedDek, "src");
    }

    @Override
    public void publishDek(String field, String dstKekId, byte[] encryptedDek) {
        store(field, dstKekId, encryptedDek, "dst");
    }

    private void store(String field, String kekId, byte[] encryptedDek, String role) {
        if (isDekRegistryAvailable()) {
            String kekName = deriveKekName(kekId);
            ensureKekRegistered(kekName, kekId);
            storeDekViaRegistry(field, kekName, encryptedDek);
        } else {
            log.warn("DEK Registry (CSFLE plugin) not available — using schema subject fallback");
            storeDekAsSchemaSubject(field, kekId, encryptedDek, role);
        }
    }

    private boolean isDekRegistryAvailable() {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/keks"))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() != 404;
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void ensureKekRegistered(String kekName, String kekId) {
        String kmsType = inferKmsType(kekId);
        String body = """
                {"name":"%s","kmsType":"%s","kmsKeyId":"%s","shared":false,"deleted":false}
                """.formatted(kekName, kmsType, kekId).strip();

        post(baseUrl + "/keks", body, "KEK registration for " + kekName, true);
        log.info("KEK '{}' ensured in DEK Registry (type: {})", kekName, kmsType);
    }

    private void storeDekViaRegistry(String field, String kekName, byte[] encryptedDek) {
        String subject = field + "-value";
        String body = """
                {"subject":"%s","version":1,"algorithm":"AES256_GCM","encryptedKeyMaterial":"%s"}
                """.formatted(subject, Base64.getEncoder().encodeToString(encryptedDek)).strip();

        post(baseUrl + "/deks/" + kekName + "/versions", body,
                "DEK publish for field " + field, true);
        log.info("DEK for field '{}' stored in DEK Registry under KEK '{}'", field, kekName);
    }

    /**
     * Fallback: stores the wrapped DEK as a JSON schema subject.
     * Subject name: cross-cloud-dek-{field}-{role}
     * Schema content: a JSON object carrying the kekId, algorithm, and base64-encoded wrapped DEK.
     * This subject is replicated by schema linking exactly like any other subject.
     */
    private void storeDekAsSchemaSubject(String field, String kekId, byte[] encryptedDek, String role) {
        String subject = "cross-cloud-dek-" + field + "-" + role;
        String encodedDek = Base64.getEncoder().encodeToString(encryptedDek);

        // Store as a JSON schema — schema linking replicates this subject to the dst SR
        String schemaStr = """
                {
                  "type": "object",
                  "title": "CrossCloudDek",
                  "properties": {
                    "kekId":        {"type": "string", "const": "%s"},
                    "algorithm":    {"type": "string", "const": "AES256_GCM"},
                    "wrappedDek":   {"type": "string", "const": "%s"}
                  }
                }
                """.formatted(kekId, encodedDek).replace("\n", "\\n").strip();

        String requestBody = """
                {"schemaType":"JSON","schema":"%s"}
                """.formatted(schemaStr.replace("\"", "\\\"")).strip();

        post(baseUrl + "/subjects/" + subject + "/versions", requestBody,
                "DEK schema subject for field " + field + " (" + role + ")", true);
        log.info("DEK for field '{}' ({}) stored as schema subject '{}' in SR @ {}",
                field, role, subject, baseUrl);
    }

    private void post(String url, String body, String opName, boolean allow409) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/vnd.schemaregistry.v1+json")
                .header("Authorization", authHeader)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status == 200 || status == 201) return;
            if (allow409 && status == 409) {
                log.debug("{} already exists — skipping", opName);
                return;
            }
            throw new RuntimeException(opName + " failed [" + status + "]: " + response.body());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(opName + " request failed", e);
        }
    }

    private String inferKmsType(String kekId) {
        if (kekId.startsWith("arn:aws:kms:")) return "aws-kms";
        if (kekId.startsWith("projects/") && kekId.contains("/keyRings/")) return "gcp-kms";
        if (kekId.contains(".vault.azure.net")) return "azure-kms";
        if (kekId.contains("/transit/keys/")) return "hcvault";
        return "ciphertrust-kms";
    }

    private String deriveKekName(String kekId) {
        String[] parts = kekId.replace("\\", "/").split("/");
        return parts[parts.length - 1];
    }
}
