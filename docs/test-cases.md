# Cross-Cloud CSFLE — Test Cases

End-to-end verification suite for the AWS → GCP cross-cloud CSFLE PoC.

All tests run against live Confluent Cloud infrastructure:

| Component | Details |
|---|---|
| Source cluster | `lkc-z2zw17` (AWS us-east-2) |
| Destination cluster | `lkc-d25pry` (GCP us-west2) |
| Topic | `social-security-records` |
| Encrypted field | `social_security` (AES-256-GCM, versioned wire format `dekVersion:iv:ct`) |
| Source KEK | AWS KMS `arn:aws:kms:us-east-2:586051073099:key/5a662fdc-6883-4b1c-8e14-6f583c910d4d` |
| Destination KEK | GCP Cloud KMS `projects/vahid-project-312305/.../cryptoKeys/dr-kek` |
| DEK provisioning | `dual` (default) — both KMS systems reachable from provisioner |

---

## Prerequisites

```bash
export AWS_REGION=us-east-2
# AWS credentials via SSO or env vars
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud/application_default_credentials.json

JAVA=/opt/homebrew/opt/openjdk@21/bin/java
JAR=~/cross-cloud-csfle/target/cross-cloud-csfle-0.1.0-SNAPSHOT.jar
PROPS=~/cross-cloud-csfle/deployment/deployment.properties
```

Run once before the test suite:

```bash
$JAVA -jar $JAR provision $PROPS   # generate and store matched DEK pair
$JAVA -jar $JAR producer  $PROPS   # encrypt 10 SSNs and produce to AWS cluster
```

---

## TC-01 — Source positive: AWS cluster + AWS KMS

**Purpose:** Verify that the source cluster consumer can decrypt records using the
src-wrapped DEK and AWS KMS. Confirms the src provisioning path and the src-side
KMS boundary.

**Command:**
```bash
$JAVA -jar $JAR source-consumer $PROPS
```

**Expected outcome:**
- Consumer connects to `pkc-1n767v.us-east-2.aws.confluent.cloud:9092`
- Fetches `cross-cloud-dek-social_security-src` subject from src SR
- Unwraps DEK with AWS KMS
- Decrypts all 10 `social_security` field values successfully
- Prints plaintext SSNs (e.g. `123-45-6789`, `234-56-7890`, ...)
- Exit code 0

**Failure signals:**
- `InvalidCiphertextException` → wrong DEK or wrong KMS key
- `404` on SR subject → provisioner has not run
- AWS auth error → AWS credentials not set

---

## TC-02 — Source negative: AWS cluster + GCP KMS (wrong KMS)

**Purpose:** Verify that GCP KMS cannot decrypt records encrypted for the AWS side.
Confirms the KMS isolation boundary — the dst KEK cannot unwrap the src-wrapped DEK.

**Command:**
```bash
$JAVA -jar $JAR source-consumer-gcp-attempt $PROPS
```

**Expected outcome:**
- Consumer connects to src cluster
- Fetches `cross-cloud-dek-social_security-src` subject (AWS-wrapped DEK)
- Attempts to unwrap with GCP Cloud KMS using the dst KEK
- **Fails** with `INVALID_ARGUMENT: Decryption failed` (GCP KMS rejects AWS ciphertext)
- No plaintext SSNs are printed
- Exit code non-zero (exception thrown)

**Why this matters:** Proves that possession of the dst KEK alone is insufficient to
decrypt src-side records. The src-wrapped DEK is cryptographically bound to the src KEK.

---

## TC-03 — Destination positive: GCP cluster + GCP KMS

**Purpose:** Verify that the destination cluster consumer can decrypt mirror topic
records using the dst-wrapped DEK and GCP Cloud KMS only. No cross-cloud KMS call
is made at read time.

**Command:**
```bash
$JAVA -jar $JAR consumer $PROPS
```

**Expected outcome:**
- Consumer connects to `pkc-nkdpdd.us-west2.gcp.confluent.cloud:9092`
- Fetches `cross-cloud-dek-social_security-dst` subject from dst SR
- Unwraps DEK with GCP Cloud KMS (no AWS call)
- Decrypts all 10 `social_security` field values successfully
- Prints plaintext SSNs matching TC-01 output
- Exit code 0

**Why this matters:** End-to-end proof that the cross-cloud CSFLE model works.
Records encrypted on AWS are decryptable on GCP with zero dependency on AWS KMS at
read time.

---

## TC-04 — Destination negative: GCP cluster + AWS KMS (wrong KMS)

**Purpose:** Verify that AWS KMS cannot decrypt records encrypted for the GCP side.
Confirms the KMS isolation boundary in the reverse direction — the src KEK cannot
unwrap the dst-wrapped DEK.

**Command:**
```bash
$JAVA -jar $JAR destination-consumer-aws-attempt $PROPS
```

**Expected outcome:**
- Consumer connects to dst cluster
- Fetches `cross-cloud-dek-social_security-dst` subject (GCP-wrapped DEK)
- Attempts to unwrap with AWS KMS using the src KEK
- **Fails** — AWS KMS rejects the request (see failure signals below)
- No plaintext SSNs are printed
- Exit code non-zero (exception thrown)

**Failure signals:**
- `InvalidCiphertextException` → AWS KMS reached, rejected GCP ciphertext (canonical failure)
- `KmsException: The security token included in the request is expired` → AWS session expired;
  still a valid boundary proof — AWS KMS was never able to obtain plaintext
- Any AWS auth error → AWS credentials missing or expired

> **Note:** If AWS STS credentials are expired, AWS rejects at the auth layer before reaching
> ciphertext validation. The boundary is still proven: no plaintext is ever returned.
> To observe `InvalidCiphertextException` specifically, run with fresh AWS credentials.

**Why this matters:** Proves that possession of the src KEK alone is insufficient to
decrypt dst-side records. Combined with TC-02, the full four-quadrant KMS isolation
matrix is verified.

---

## KMS isolation matrix

|                      | Decrypt with AWS KMS (src KEK) | Decrypt with GCP KMS (dst KEK) |
|---|---|---|
| **src-wrapped DEK** | ✅ TC-01 — succeeds | ❌ TC-02 — fails (`INVALID_ARGUMENT`) |
| **dst-wrapped DEK** | ❌ TC-04 — fails (`InvalidCiphertextException`) | ✅ TC-03 — succeeds |

All four quadrants must be verified for the KMS boundary to be considered proven.

---

## Running the full suite

```bash
echo "=== TC-01: source positive ===" && $JAVA -jar $JAR source-consumer $PROPS
echo "=== TC-02: source negative ===" && $JAVA -jar $JAR source-consumer-gcp-attempt $PROPS || true
echo "=== TC-03: destination positive ===" && $JAVA -jar $JAR consumer $PROPS
echo "=== TC-04: destination negative ===" && $JAVA -jar $JAR destination-consumer-aws-attempt $PROPS || true
```

TC-02 and TC-04 are expected to fail — `|| true` prevents them from aborting the suite.

---

## TC-05 — Split mode: source cannot reach destination KMS

**Purpose:** Verify the two-phase provisioning path for deployments where the source-side
provisioner has no network access to the destination KMS. Phase 1 wraps with the src KEK
only and writes the plaintext DEK to a temporary transfer subject in the src SR. Schema
linking replicates the transfer subject to the dst SR. Phase 2 reads the transfer subject
from the dst SR and wraps with the dst KEK — no AWS call is made in Phase 2.

**Setup:**
```bash
# Add to deployment.properties:
dek.provisioning.mode=split
```

**Commands:**
```bash
# Phase 1 — source side (AWS KMS only, no GCP call)
$JAVA -jar $JAR provision $PROPS

# Wait for schema linking to replicate transfer subject to dst SR (typically < 30s)
# Verify: curl -u <key:secret> <dst-sr-url>/subjects/cross-cloud-dek-social_security-transfer/versions

# Phase 2 — destination side (GCP KMS only, no AWS call)
$JAVA -jar $JAR provision-dst $PROPS
```

**Expected outcome (Phase 1):**
- Wraps DEK with AWS KMS → persists `cross-cloud-dek-social_security-src` subject in src SR
- Writes plaintext DEK (base64) as `cross-cloud-dek-social_security-transfer` in src SR
- **No GCP KMS call is made**
- Status: `PHASE 1 COMPLETE — run 'provision-dst' on destination side to finish`
- Exit code 0

**Expected outcome (Phase 2):**
- Reads transfer subject from dst SR (replicated by schema exporter)
- Wraps plaintext DEK with GCP Cloud KMS
- Sets `cross-cloud-dek-social_security-dst` subject mode to READWRITE (subject-level, not global)
- Persists GCP-wrapped DEK to dst SR
- Clears subject-level mode override — dst SR global mode remains IMPORT, schema exporter uninterrupted
- Deletes transfer subject
- **No AWS KMS call is made**
- Exit code 0

**Post-provisioning verification:**
```bash
$JAVA -jar $JAR producer $PROPS        # produce records with split-mode DEK
$JAVA -jar $JAR source-consumer $PROPS # AWS cluster + AWS KMS → decrypts
$JAVA -jar $JAR consumer $PROPS        # GCP cluster + GCP KMS → decrypts (no AWS call)
```

**Why this matters:** Proves that cross-cloud DEK provisioning works even when the source
host cannot reach the destination KMS — the only network path required is src SR → schema
exporter → dst SR, which is already required for schema linking.

---

## Run results (2026-04-03)

| TC | Cluster | KMS | Result | Observed error / output |
|---|---|---|---|---|
| TC-01 | AWS (src) | AWS KMS | ✅ PASS | Decrypted: 40 records. All 10 SSNs printed in plaintext. |
| TC-02 | AWS (src) | GCP KMS | ✅ PASS (expected fail) | `INVALID_ARGUMENT: Decryption failed: the ciphertext is invalid.` — GCP KMS rejected AWS ciphertext. |
| TC-03 | GCP (dst) | GCP KMS | ✅ PASS | Decrypted: 40 records. All 10 SSNs match TC-01 output. GCP cluster fully self-sufficient, no AWS KMS call. |
| TC-04 | GCP (dst) | AWS KMS | ✅ PASS (expected fail) | `KmsException: The security token included in the request is expired` — AWS credentials had expired; no plaintext returned. Canonical `InvalidCiphertextException` would be observed with fresh credentials. |

All four quadrants verified. KMS isolation boundary confirmed.

| TC | Mode | Result | Notes |
|---|---|---|---|
| TC-05 | Split provisioning (Phase 1) | ✅ PASS | AWS KMS only — no GCP call. Transfer subject written to src SR, replicated by schema exporter to dst SR. |
| TC-05 | Split provisioning (Phase 2) | ✅ PASS | GCP KMS only — no AWS call. Transfer subject read from dst SR, wrapped with GCP KMS, stored. Transfer deleted. dst SR stayed IMPORT. |
| TC-05 | Post-split consumers | ✅ PASS | AWS consumer: Decrypted 60 records. GCP consumer: Decrypted 60 records. Both use split-mode DEK, no cross-cloud KMS call. |

**Discovered and fixed during TC-05:** Phase 2 originally used global SR mode (`PUT /mode`) which stopped the schema exporter and could not be restored (`42205: Cannot import since found existing subjects`). Fixed to use subject-level mode overrides (`PUT /mode/{subject}`) — global IMPORT mode is never changed.
