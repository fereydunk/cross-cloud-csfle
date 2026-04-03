package io.confluent.csfle.crosscloud.config;

/**
 * Controls how DEKs are wrapped and distributed when src and dst use different KMS systems.
 *
 * <p><strong>Not applicable when src and dst KEKs resolve to the same KMS type.</strong>
 * In that case the provisioner detects the match automatically, wraps the DEK once,
 * and stores the same ciphertext for both the src and dst subjects. This property is
 * silently ignored for same-KMS rules.
 *
 * <p>When src and dst use different KMS types, set {@code dek.provisioning.mode} in
 * deployment.properties:
 *
 * <pre>
 * Situation 1 — same KMS type:
 *   Not applicable. One wrap call. dek.provisioning.mode is ignored.
 *
 * Situation 2 — different KMS types, both reachable from the provisioner:
 *   dek.provisioning.mode=dual   (default — no need to set explicitly)
 *
 * Situation 3 — different KMS types, dst KMS NOT reachable from the provisioner:
 *   dek.provisioning.mode=split
 * </pre>
 */
public enum DekProvisioningMode {

    /**
     * Default. Both KMS systems are reachable from the provisioner.
     * Two wrap calls, two DEK subjects (src + dst). Schema linking replicates
     * the encrypted DEK to the destination SR. No plaintext DEK leaves the JVM.
     */
    DUAL,

    /**
     * The destination KMS is NOT reachable from the provisioner on the source side.
     *
     * <p>Phase 1 ({@code provision} — source side): wraps with src KEK, stores src subject,
     * writes plaintext DEK as a temporary transfer subject in src SR. Schema linking
     * carries the transfer subject to the destination SR over TLS.
     *
     * <p>Phase 2 ({@code provision-dst} — destination side): reads plaintext DEK from
     * the transfer subject in dst SR, wraps with dst KEK, stores dst subject in dst SR,
     * deletes the transfer subject. Plaintext DEK is zeroed immediately after wrapping.
     *
     * <p>The transfer subject is protected in transit by schema linking TLS and at rest
     * by Schema Registry authentication (API key). It exists only for the window between
     * phase 1 and phase 2 and is deleted as soon as phase 2 completes.
     */
    SPLIT;

    public static DekProvisioningMode from(String value) {
        if (value == null || value.isBlank() || "dual".equalsIgnoreCase(value)) return DUAL;
        if ("split".equalsIgnoreCase(value)) return SPLIT;
        throw new IllegalArgumentException(
                "Invalid dek.provisioning.mode '" + value + "' — expected 'dual' or 'split'");
    }
}
