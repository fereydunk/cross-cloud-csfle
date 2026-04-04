package io.confluent.csfle.crosscloud.linking;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.List;

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

    // ── Split-mode provisioning: transfer subject ─────────────────────────────

    /**
     * Writes a temporary transfer subject containing the base64-encoded plaintext DEK.
     * Used in split-mode provisioning (phase 1, source side).
     * Schema linking replicates this subject to the destination SR over TLS.
     * Subject name: cross-cloud-dek-{field}-transfer
     */
    @Override
    public void writeTransferSubject(String field, byte[] plaintextDek) {
        String subject  = transferSubjectName(field);
        String b64Dek   = Base64.getEncoder().encodeToString(plaintextDek);

        String schemaStr = """
                {
                  "type": "object",
                  "title": "CrossCloudDekTransfer",
                  "properties": {
                    "field":        {"type": "string", "const": "%s"},
                    "plaintextDek": {"type": "string", "const": "%s"}
                  }
                }
                """.formatted(field, b64Dek).replace("\n", "\\n").strip();

        String requestBody = """
                {"schemaType":"JSON","schema":"%s"}
                """.formatted(schemaStr.replace("\"", "\\\"")).strip();

        post(baseUrl + "/subjects/" + subject + "/versions", requestBody,
                "DEK transfer subject for field " + field, true);
        log.info("Transfer subject '{}' written to SR @ {} — schema linking will replicate to dst SR",
                subject, baseUrl);
    }

    /**
     * Reads the plaintext DEK from a transfer subject in this SR.
     * Used in split-mode provisioning (phase 2, destination side).
     * Returns the raw plaintext DEK bytes — caller must zero after use.
     */
    public byte[] readTransferSubject(String field) {
        String subject = transferSubjectName(field);
        String url = baseUrl + "/subjects/" + subject + "/versions/latest";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException(
                        "Transfer subject '" + subject + "' not found [" + resp.statusCode() + "]: " +
                        resp.body() + " — run 'provision' (phase 1) on the source side first, " +
                        "then wait for schema linking to replicate.");
            }
            String responseJson = resp.body();
            String schema = extractSchemaString(responseJson);
            String b64Dek = extractConst(schema, "plaintextDek");
            log.info("Transfer subject '{}' read from SR @ {}", subject, baseUrl);
            return Base64.getDecoder().decode(b64Dek);
        } catch (java.io.IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("readTransferSubject failed for field '" + field + "'", e);
        }
    }

    /**
     * Deletes the transfer subject from this SR (both soft-delete and hard-delete).
     * Called by phase 2 after the plaintext DEK has been wrapped and stored.
     */
    public void deleteTransferSubject(String field) {
        String subject = transferSubjectName(field);
        delete(baseUrl + "/subjects/" + subject, "soft-delete transfer subject " + subject);
        delete(baseUrl + "/subjects/" + subject + "?permanent=true",
                "hard-delete transfer subject " + subject);
        log.info("Transfer subject '{}' deleted from SR @ {}", subject, baseUrl);
    }

    private static String transferSubjectName(String field) {
        return "cross-cloud-dek-" + field + "-transfer";
    }

    private String extractSchemaString(String responseJson) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\"schema\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
                .matcher(responseJson);
        if (!m.find()) throw new RuntimeException("Could not find 'schema' field in SR response");
        return m.group(1)
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\\\", "\\");
    }

    private String extractConst(String json, String propertyName) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "\"" + java.util.regex.Pattern.quote(propertyName) +
                "\"\\s*:\\s*\\{[^}]*\"const\"\\s*:\\s*\"([^\"]+)\"")
                .matcher(json);
        if (!m.find()) throw new RuntimeException(
                "Property '" + propertyName + "' not found in transfer subject schema");
        return m.group(1);
    }

    private void delete(String url, String opName) {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .DELETE()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200 && resp.statusCode() != 404) {
                throw new RuntimeException(opName + " failed [" + resp.statusCode() + "]: " + resp.body());
            }
        } catch (java.io.IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(opName + " request failed", e);
        }
    }

    // ── Public methods used by DekSyncer ─────────────────────────────────────

    /**
     * Returns all subject names registered in this Schema Registry.
     */
    public List<String> listSubjects() {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/subjects"))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException("listSubjects failed [" + resp.statusCode() + "]: " + resp.body());
            }
            return parseJsonStringArray(resp.body());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("listSubjects request failed", e);
        }
    }

    /**
     * Returns all version numbers registered for the given subject.
     */
    public List<Integer> listVersions(String subject) {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/subjects/" + subject + "/versions"))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 404) return List.of();
            if (resp.statusCode() != 200) {
                throw new RuntimeException("listVersions failed [" + resp.statusCode() + "]: " + resp.body());
            }
            return parseJsonIntArray(resp.body());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("listVersions request failed", e);
        }
    }

    /**
     * Returns true if the given subject has a schema at the specified version.
     */
    public boolean hasSubjectVersion(String subject, int version) {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/subjects/" + subject + "/versions/" + version))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200;
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Stores a DEK with an explicit role, used by DekSyncer when re-wrapping DEKs
     * from the surviving side and pushing to the recovering SR.
     */
    public void storeDekForRole(String field, String kekId, byte[] encryptedDek, String role) {
        store(field, kekId, encryptedDek, role);
    }

    /**
     * Sets the global Schema Registry mode (e.g. "READWRITE" or "IMPORT").
     * Used by DekSyncer to temporarily switch the recovering SR to READWRITE
     * for the duration of the DEK sync, then back to the original mode.
     */
    public void setMode(String mode) {
        String body = "{\"mode\":\"" + mode + "\"}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mode"))
                .header("Content-Type", "application/vnd.schemaregistry.v1+json")
                .header("Authorization", authHeader)
                .PUT(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException("setMode(" + mode + ") failed [" + resp.statusCode() + "]: " + resp.body());
            }
            log.info("SR mode set to {} @ {}", mode, baseUrl);
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("setMode request failed", e);
        }
    }

    /**
     * Returns the current global Schema Registry mode.
     */
    public String getMode() {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mode"))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException("getMode failed [" + resp.statusCode() + "]: " + resp.body());
            }
            // Response: {"mode":"READWRITE"} or {"mode":"IMPORT"}
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"mode\"\\s*:\\s*\"([^\"]+)\"")
                    .matcher(resp.body());
            return m.find() ? m.group(1) : "UNKNOWN";
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("getMode request failed", e);
        }
    }

    /**
     * Sets the mode for a single subject (e.g. "READWRITE" or "IMPORT").
     * Subject-level mode overrides the global mode for that subject only,
     * so the schema exporter continues running without disruption.
     */
    public void setSubjectMode(String subject, String mode) {
        String body = "{\"mode\":\"" + mode + "\"}";
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mode/" + subject))
                .header("Content-Type", "application/vnd.schemaregistry.v1+json")
                .header("Authorization", authHeader)
                .PUT(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException(
                        "setSubjectMode(" + subject + ", " + mode + ") failed [" +
                        resp.statusCode() + "]: " + resp.body());
            }
            log.info("Subject '{}' mode set to {} @ {}", subject, mode, baseUrl);
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("setSubjectMode request failed", e);
        }
    }

    /**
     * Deletes the subject-level mode override, reverting to the global SR mode.
     */
    public void deleteSubjectMode(String subject) {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mode/" + subject))
                .header("Authorization", authHeader)
                .DELETE()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            // 200 = deleted, 404 = no override existed — both are fine
            if (resp.statusCode() != 200 && resp.statusCode() != 404) {
                throw new RuntimeException(
                        "deleteSubjectMode(" + subject + ") failed [" +
                        resp.statusCode() + "]: " + resp.body());
            }
            log.info("Subject '{}' mode override cleared @ {}", subject, baseUrl);
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("deleteSubjectMode request failed", e);
        }
    }

    // ── JSON array parsing (without external JSON dependency) ───────────────

    private List<String> parseJsonStringArray(String json) {
        // Input: ["a","b","c"] or []
        String inner = json.trim().replaceAll("^\\[|\\]$", "").trim();
        if (inner.isEmpty()) return List.of();
        List<String> result = new java.util.ArrayList<>();
        for (String part : inner.split(",")) {
            String s = part.trim().replaceAll("^\"|\"$", "");
            if (!s.isEmpty()) result.add(s);
        }
        return result;
    }

    private List<Integer> parseJsonIntArray(String json) {
        // Input: [1,2,3] or []
        String inner = json.trim().replaceAll("^\\[|\\]$", "").trim();
        if (inner.isEmpty()) return List.of();
        List<Integer> result = new java.util.ArrayList<>();
        for (String part : inner.split(",")) {
            String s = part.trim();
            if (!s.isEmpty()) result.add(Integer.parseInt(s));
        }
        return result;
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
