package io.confluent.csfle.crosscloud.kms;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;

/**
 * KMS client for Thales CipherTrust Manager using its REST API.
 *
 * The kekId format expected: {@code https://<ciphertrust-host>/api/v1/vault/keys/<key-id>}
 * Credentials are resolved from environment variables:
 *   CIPHERTRUST_USERNAME, CIPHERTRUST_PASSWORD (used to obtain a bearer token)
 *
 * Uses the CipherTrust /encrypt and /decrypt endpoints on the key resource.
 */
public class CipherTrustKmsClient implements KmsClient {

    private static final String USERNAME_ENV = "CIPHERTRUST_USERNAME";
    private static final String PASSWORD_ENV = "CIPHERTRUST_PASSWORD";

    private final HttpClient httpClient;

    public CipherTrustKmsClient() {
        this.httpClient = HttpClient.newBuilder()
                .build();
    }

    @Override
    public byte[] wrapDek(String kekId, byte[] plaintextDek) {
        String token = authenticate(resolveHost(kekId));
        String encoded = Base64.getEncoder().encodeToString(plaintextDek);
        String body = """
                {"plaintext":"%s"}
                """.formatted(encoded).strip();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(kekId + "/encrypt"))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RuntimeException("CipherTrust wrap failed: " + response.body());
            }
            return extractField(response.body(), "ciphertext").getBytes();
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("CipherTrust wrap request failed for key: " + kekId, e);
        }
    }

    @Override
    public byte[] unwrapDek(String kekId, byte[] wrappedDek) {
        String token = authenticate(resolveHost(kekId));
        String ciphertext = new String(wrappedDek);
        String body = """
                {"ciphertext":"%s"}
                """.formatted(ciphertext).strip();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(kekId + "/decrypt"))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RuntimeException("CipherTrust unwrap failed: " + response.body());
            }
            String plaintext = extractField(response.body(), "plaintext");
            return Base64.getDecoder().decode(plaintext);
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("CipherTrust unwrap request failed for key: " + kekId, e);
        }
    }

    private String authenticate(String host) {
        String username = System.getenv(USERNAME_ENV);
        String password = System.getenv(PASSWORD_ENV);
        if (username == null || password == null) {
            throw new IllegalStateException(
                    "CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD environment variables must be set");
        }
        String body = """
                {"username":"%s","password":"%s"}
                """.formatted(username, password).strip();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(host + "/api/v1/auth/tokens"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RuntimeException("CipherTrust auth failed: " + response.body());
            }
            return extractField(response.body(), "jwt");
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("CipherTrust authentication request failed", e);
        }
    }

    private String resolveHost(String kekId) {
        URI uri = URI.create(kekId);
        return uri.getScheme() + "://" + uri.getHost() +
               (uri.getPort() != -1 ? ":" + uri.getPort() : "");
    }

    // Minimal JSON field extractor — avoids pulling in a JSON library dependency
    private String extractField(String json, String field) {
        String key = "\"" + field + "\":\"";
        int start = json.indexOf(key);
        if (start == -1) throw new RuntimeException("Field '" + field + "' not found in response");
        start += key.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }

    @Override
    public void close() {
        // HttpClient lifecycle managed by JVM
    }
}
