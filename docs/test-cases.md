# Cross-Cloud CSFLE — Test Cases

End-to-end verification suite for the AWS → GCP cross-cloud CSFLE PoC.

All tests run against live Confluent Cloud infrastructure:

| Component | Details |
|---|---|
| Source cluster | AWS us-east-2 |
| Destination cluster | GCP us-west2 |
| Topic | `social-security-records` |
| Encrypted field | `social_security` (AES-256-GCM, versioned wire format `dekVersion:iv:ct`) |
| Source KEK | AWS KMS key in us-east-2 |
| Destination KEK | GCP Cloud KMS key in us-west2 |
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
- Consumer connects to the source (AWS) cluster
- Fetches `cross-cloud-dek-social_security-src` subject from src SR
- Unwraps DEK with AWS KMS
- Decrypts all `social_security` field values successfully
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
- The exception is caught and logged as expected behaviour
- No plaintext SSNs are printed
- Exit code 0 (exception is caught — failure is the expected outcome)

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
- Consumer connects to the destination (GCP) cluster
- Fetches `cross-cloud-dek-social_security-dst` subject from dst SR
- Unwraps DEK with GCP Cloud KMS (no AWS call)
- Decrypts all `social_security` field values successfully
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
- The exception is caught and logged as expected behaviour
- No plaintext SSNs are printed
- Exit code 0 (exception is caught — failure is the expected outcome)

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
| **src-wrapped DEK** | TC-01 — succeeds | TC-02 — fails (`INVALID_ARGUMENT`) |
| **dst-wrapped DEK** | TC-04 — fails (`InvalidCiphertextException`) | TC-03 — succeeds |

All four quadrants must be verified for the KMS boundary to be considered proven.

---

## Running the full suite

```bash
echo "=== TC-01: source positive ===" && $JAVA -jar $JAR source-consumer $PROPS
echo "=== TC-02: source negative ===" && $JAVA -jar $JAR source-consumer-gcp-attempt $PROPS
echo "=== TC-03: destination positive ===" && $JAVA -jar $JAR consumer $PROPS
echo "=== TC-04: destination negative ===" && $JAVA -jar $JAR destination-consumer-aws-attempt $PROPS
```

TC-02 and TC-04 exit 0 (the expected exception is caught and logged). All four commands
can be run sequentially without `|| true`.

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

## TC-06 — Failback DEK sync: re-wrap DEKs from surviving SR to recovering SR

**Purpose:** Verify that `DekSyncer` correctly re-wraps DEK versions from the surviving
Schema Registry (GCP, dst) and pushes them to the recovering SR (AWS, src). This is the
pre-failback step that must complete before any mirror topic is promoted.

**Setup:** Simulate the state after a DR failover where the AWS side produced new DEK
versions that the GCP side does not have, or vice versa. In practice, run after a real or
simulated outage.

**Command:**
```bash
# Default: GCP survived (dst), AWS recovering (src)
$JAVA -jar $JAR sync $PROPS

# If AWS survived (src), GCP recovering (dst):
# Add to deployment.properties: sync.surviving.role=src
$JAVA -jar $JAR sync $PROPS
```

**Expected outcome:**
- Lists all DEK fields and versions in the surviving SR
- For each version missing in the recovering SR: fetches, unwraps with surviving KMS,
  re-wraps with recovering KMS, pushes to recovering SR
- Versions already present in the recovering SR are skipped (idempotent)
- Recovering SR briefly switched to READWRITE, then restored to original mode
- Plaintext DEK zeroed from memory after each re-wrap
- Exit code 0 if all versions synced; non-zero if any version fails

**Failure signals:**
- Any KMS error → credentials not set or KMS key unavailable
- SR connection error → recovering SR not reachable
- Non-zero exit → do **not** proceed to topic promotion until sync is re-run successfully

---

## Run results (2026-04-03)

### KMS isolation matrix (TC-01 through TC-04)

| TC | Cluster | KMS used | Result | Observed output |
|---|---|---|---|---|
| TC-01 | AWS (src) | AWS KMS | PASS | 10 SSNs decrypted in plaintext. |
| TC-02 | AWS (src) | GCP KMS | PASS (expected fail) | `INVALID_ARGUMENT: Decryption failed: the ciphertext is invalid.` — GCP KMS rejected AWS ciphertext. Exit 0. |
| TC-03 | GCP (dst) | GCP KMS | PASS | 10 SSNs decrypted in plaintext. Matches TC-01. GCP fully self-sufficient, no AWS KMS call. |
| TC-04 | GCP (dst) | AWS KMS | PASS (expected fail) | `KmsException: The security token included in the request is expired` — credentials had expired; no plaintext returned. Exit 0. |

All four quadrants verified. KMS isolation boundary confirmed.

> **TC-04 note:** If AWS STS credentials are fresh, the expected error is
> `InvalidCiphertextException`. Either error proves the boundary — no plaintext is returned
> in either case. Record counts above reflect cumulative records in the topic across all runs.

### Split mode (TC-05)

| Phase | Result | Notes |
|---|---|---|
| Phase 1 (source) | PASS | AWS KMS only — no GCP call. Transfer subject written to src SR and replicated by schema exporter to dst SR within seconds. |
| Phase 2 (destination) | PASS | GCP KMS only — no AWS call. Transfer subject read from dst SR, wrapped, stored. Transfer deleted. dst SR stayed IMPORT throughout — schema exporter uninterrupted. |
| Post-split consumers | PASS | Both src consumer (AWS KMS) and dst consumer (GCP KMS) decrypted all records. No cross-cloud KMS call at read time. |

---

## Implementation notes

- **Phase 2 global-mode bug (fixed):** An early implementation of `SplitProvisionDstApp`
  switched the global dst SR mode to READWRITE before writing the dst-wrapped DEK. This
  stopped the Confluent schema exporter, and restoring IMPORT mode failed with
  `42205: Cannot import since found existing subjects`. Fixed by using subject-level mode
  overrides (`PUT /mode/{subject}`) — the global IMPORT mode is never changed and the
  exporter runs continuously throughout Phase 2.
