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
import java.util.Base64;
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
 * Callers MUST zero the returned byte array after use.
 */
public class DekFetcher {

    private static final Logger log = LoggerFactory.getLogger(DekFetcher.class);

    private final String baseUrl;
    private final String authHeader;
    private final HttpClient httpClient;

    public DekFetcher(String baseUrl, String apiKey, String apiSecret) {
        this.baseUrl    = baseUrl.replaceAll("/$", "");
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((apiKey + ":" + apiSecret).getBytes());
        this.httpClient = HttpClient.newHttpClient();
    }

    /**
     * Fetches the plaintext DEK for the given field and role ("src" or "dst").
     *
     * @return plaintext DEK bytes — caller must zero after use
     */
    public byte[] fetchPlaintextDek(String field, String role) {
        String subject = "cross-cloud-dek-" + field + "-" + role;
        log.info("Fetching DEK from SR subject '{}'", subject);

        String responseJson = fetchSubject(subject);
        String schema       = extractSchemaString(responseJson);
        String kekId        = extractConst(schema, "kekId");
        String wrappedB64   = extractConst(schema, "wrappedDek");

        log.info("Wrapped DEK found — KEK: {}", kekId);
        byte[] wrappedDek = Base64.getDecoder().decode(wrappedB64);

        KekReference kekRef = new KekReference(kekId);
        try (KmsClient kms = KmsClientFactory.create(kekRef)) {
            log.info("Unwrapping with {} KMS...", kekRef.resolveType());
            byte[] plaintext = kms.unwrapDek(kekId, wrappedDek);
            log.info("DEK unwrapped ({} bytes)", plaintext.length);
            return plaintext;
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to unwrap DEK for field='" + field + "' role='" + role + "'", e);
        }
    }

    private String fetchSubject(String subject) {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/subjects/" + subject + "/versions/latest"))
                .header("Authorization", authHeader)
                .GET()
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new RuntimeException(
                        "Schema subject '" + subject + "' not found [" +
                        resp.statusCode() + "]: " + resp.body() +
                        " — run the provisioner first.");
            }
            return resp.body();
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("HTTP request failed for subject '" + subject + "'", e);
        }
    }

    /**
     * Extracts the value of the "schema" field from the SR response and unescapes it.
     * The SR wraps the schema as a JSON-encoded string ("schema":"...escaped...").
     */
    private String extractSchemaString(String responseJson) {
        Pattern p = Pattern.compile("\"schema\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(responseJson);
        if (!m.find()) throw new RuntimeException("Could not find 'schema' field in SR response");
        return m.group(1)
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\\\", "\\");
    }

    /**
     * Extracts a "const" value from an (already unescaped) JSON schema.
     *
     * Matches property patterns like:
     *   "propertyName":{"type":"string","const":"<value>"}
     */
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
}
