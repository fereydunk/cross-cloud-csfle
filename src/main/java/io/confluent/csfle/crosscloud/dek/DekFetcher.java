package io.confluent.csfle.crosscloud.dek;

import io.confluent.csfle.crosscloud.config.KekReference;
import io.confluent.csfle.crosscloud.kms.KmsClient;
import io.confluent.csfle.crosscloud.kms.KmsClientFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads wrapped DEKs from Schema Registry schema subjects and unwraps them using the
 * appropriate KMS client.
 *
 * Subject naming convention (written by {@link io.confluent.csfle.crosscloud.linking.ConfluentSchemaRegistryClient}):
 *   cross-cloud-dek-{field}-src  — src-wrapped DEK (unwrapped with src KEK / AWS KMS)
 *   cross-cloud-dek-{field}-dst  — dst-wrapped DEK (unwrapped with dst KEK / GCP Cloud KMS)
 *
 * The subject's schema is a JSON Schema document carrying three const properties:
 *   kekId      — the KEK identifier used to wrap this DEK
 *   algorithm  — AES256_GCM
 *   wrappedDek — base64-encoded wrapped DEK bytes
 *
 * Version-aware fetching: each DEK subject may have multiple versions (one per rotation).
 * The SR version number is embedded in encrypted field values so consumers can fetch the
 * exact DEK version needed for each record. {@link #fetchDek(String, String)} fetches the
 * latest version; {@link #fetchDek(String, String, int)} fetches a specific version.
 *
 * Callers MUST zero the returned byte arrays after use.
 */
public class DekFetcher {

    private static final Logger log = LoggerFactory.getLogger(DekFetcher.class);

    private static final Pattern SCHEMA_PATTERN  = Pattern.compile("\"schema\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern VERSION_PATTERN = Pattern.compile("\"version\"\\s*:\\s*(\\d+)");
    private static final Pattern SUBJECT_PATTERN = Pattern.compile("^cross-cloud-dek-(.+)-([^-]+)$");

    private final String baseUrl;
    private final String authHeader;
    private final HttpClient httpClient;

    public DekFetcher(String baseUrl, String apiKey, String apiSecret) {
        this.baseUrl    = baseUrl.replaceAll("/$", "");
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((apiKey + ":" + apiSecret).getBytes());
        this.httpClient = HttpClient.newHttpClient();
    }

    // ── Primary API ───────────────────────────────────────────────────────────

    /**
     * Fetches and unwraps the latest DEK for the given field and role.
     *
     * @return DekResult with the SR version number and plaintext DEK — caller must zero plaintext
     */
    public DekResult fetchDek(String field, String role) {
        return fetchDekInternal(field, role, "latest");
    }

    /**
     * Fetches and unwraps a specific DEK version for the given field and role.
     * If version is 0, fetches the latest (backward compat with old wire format).
     *
     * @return DekResult with the SR version number and plaintext DEK — caller must zero plaintext
     */
    public DekResult fetchDek(String field, String role, int version) {
        if (version <= 0) return fetchDek(field, role); // 0 = old format, use latest
        return fetchDekInternal(field, role, String.valueOf(version));
    }

    /**
     * Backward-compatible convenience method. Returns only the plaintext DEK bytes.
     * Prefer {@link #fetchDek(String, String)} when the version is also needed.
     *
     * @return plaintext DEK bytes — caller must zero after use
     */
    public byte[] fetchPlaintextDek(String field, String role) {
        return fetchDek(field, role).plaintext();
    }

    // ── DekSyncer support: listing and raw wrapped-byte access ────────────────

    /**
     * Returns the field names of all DEK subjects for the given role in this SR.
     * E.g. for role="dst", finds all "cross-cloud-dek-{field}-dst" subjects and
     * returns the field names.
     */
    public List<String> listDekFields(String role) {
        List<String> allSubjects = listSubjects();
        List<String> fields = new ArrayList<>();
        String suffix = "-" + role;
        String prefix = "cross-cloud-dek-";
        for (String subject : allSubjects) {
            if (subject.startsWith(prefix) && subject.endsWith(suffix)) {
                String field = subject.substring(prefix.length(), subject.length() - suffix.length());
                if (!field.isEmpty()) fields.add(field);
            }
        }
        return fields;
    }

    /**
     * Returns all SR version numbers registered for the DEK subject of the given field and role.
     */
    public List<Integer> listVersions(String field, String role) {
        String subject = subjectName(field, role);
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
            return parseIntArray(resp.body());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("listVersions request failed for subject '" + subject + "'", e);
        }
    }

    /**
     * Fetches the wrapped (encrypted) DEK bytes for a specific version without unwrapping.
     * Returns the raw ciphertext — the caller is responsible for using the correct KMS to unwrap.
     *
     * To obtain plaintext DEK bytes (e.g. for re-wrapping), use {@link #fetchDek(String, String, int)}
     * which handles unwrapping via the KMS client automatically.
     */
    public byte[] fetchWrappedDekBytes(String field, String role, int version) {
        String responseJson = fetchSubjectAtVersion(subjectName(field, role),
                version <= 0 ? "latest" : String.valueOf(version));
        String schema     = extractSchemaString(responseJson);
        String wrappedB64 = extractConst(schema, "wrappedDek");
        return Base64.getDecoder().decode(wrappedB64);
    }

    /**
     * Returns the KEK ID embedded in the DEK subject for a specific version.
     * Used by {@link DekSyncer} to verify which KMS was used for a given DEK version.
     */
    public String fetchKekId(String field, String role, int version) {
        String responseJson = fetchSubjectAtVersion(subjectName(field, role),
                version <= 0 ? "latest" : String.valueOf(version));
        String schema = extractSchemaString(responseJson);
        return extractConst(schema, "kekId");
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private DekResult fetchDekInternal(String field, String role, String versionStr) {
        String subject = subjectName(field, role);
        log.info("Fetching DEK from SR subject '{}' version '{}'", subject, versionStr);

        String responseJson = fetchSubjectAtVersion(subject, versionStr);
        int srVersion       = extractVersion(responseJson);
        String schema       = extractSchemaString(responseJson);
        String kekId        = extractConst(schema, "kekId");
        String wrappedB64   = extractConst(schema, "wrappedDek");

        log.info("Wrapped DEK found — KEK: {}", kekId);
        byte[] wrappedDek = Base64.getDecoder().decode(wrappedB64);

        KekReference kekRef = new KekReference(kekId);
        try (KmsClient kms = KmsClientFactory.create(kekRef)) {
            log.info("Unwrapping with {} KMS...", kekRef.resolveType());
            byte[] plaintext = kms.unwrapDek(kekId, wrappedDek);
            log.info("DEK unwrapped ({} bytes), SR version={}", plaintext.length, srVersion);
            return new DekResult(srVersion, plaintext);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to unwrap DEK for field='" + field + "' role='" + role +
                    "' version='" + versionStr + "'", e);
        }
    }

    private String fetchSubjectAtVersion(String subject, String versionStr) {
        String url = baseUrl + "/subjects/" + subject + "/versions/" + versionStr;
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException(
                        "Schema subject '" + subject + "' version '" + versionStr + "' not found [" +
                        resp.statusCode() + "]: " + resp.body() +
                        " — run the provisioner first.");
            }
            return resp.body();
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("HTTP request failed for subject '" + subject + "'", e);
        }
    }

    private List<String> listSubjects() {
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
            return parseStringArray(resp.body());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("listSubjects request failed", e);
        }
    }

    private int extractVersion(String responseJson) {
        Matcher m = VERSION_PATTERN.matcher(responseJson);
        if (!m.find()) throw new RuntimeException("Could not find 'version' field in SR response");
        return Integer.parseInt(m.group(1));
    }

    private String extractSchemaString(String responseJson) {
        Matcher m = SCHEMA_PATTERN.matcher(responseJson);
        if (!m.find()) throw new RuntimeException("Could not find 'schema' field in SR response");
        return m.group(1)
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\\\", "\\");
    }

    private String extractConst(String json, String propertyName) {
        Pattern p = Pattern.compile(
                "\"" + Pattern.quote(propertyName) + "\"\\s*:\\s*\\{[^}]*\"const\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) {
            throw new RuntimeException(
                    "Property '" + propertyName + "' not found in SR response. " +
                    "DEK subject may be in an unexpected format.");
        }
        return m.group(1);
    }

    private static String subjectName(String field, String role) {
        return "cross-cloud-dek-" + field + "-" + role;
    }

    private static List<String> parseStringArray(String json) {
        String inner = json.trim().replaceAll("^\\[|\\]$", "").trim();
        if (inner.isEmpty()) return List.of();
        List<String> result = new ArrayList<>();
        for (String part : inner.split(",")) {
            String s = part.trim().replaceAll("^\"|\"$", "");
            if (!s.isEmpty()) result.add(s);
        }
        return result;
    }

    private static List<Integer> parseIntArray(String json) {
        String inner = json.trim().replaceAll("^\\[|\\]$", "").trim();
        if (inner.isEmpty()) return List.of();
        List<Integer> result = new ArrayList<>();
        for (String part : inner.split(",")) {
            String s = part.trim();
            if (!s.isEmpty()) result.add(Integer.parseInt(s));
        }
        return result;
    }
}
