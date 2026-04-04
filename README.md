# Cross-Cloud CSFLE

End-to-end Client-Side Field Level Encryption across cloud providers on Confluent Cloud.

When Kafka topic data is replicated from a source cluster (e.g. AWS) to a destination cluster (e.g. GCP) via cluster linking, the destination cannot decrypt CSFLE-encrypted fields because it has no access to the source KMS. This project solves that problem by provisioning the Data Encryption Key (DEK) at **both ends before any record is produced** — using only existing Confluent infrastructure, with no new components.

---

## How It Works

For each encrypted field, the engine:

1. Generates a new DEK in memory (AES-256, `SecureRandom`)
2. Wraps it with the **source KEK** → persists the wrapped DEK to the source Schema Registry
3. Wraps it with the **destination KEK** (in memory) → persists it *also* to the source SR under a `dst` subject so the schema exporter replicates it to the destination SR
4. Only after both steps succeed: the DEK is considered active and safe to use for encryption
5. The plaintext DEK is zeroed from memory immediately in a `finally` block

The destination cluster receives encrypted records via **cluster linking** and receives the destination-wrapped DEK via **schema exporter** (schema linking). At read time, the destination consumer unwraps the DEK using its local KMS — no cross-cloud KMS call is ever needed at read time.

```
Source cluster (AWS)                      Destination cluster (GCP)
────────────────────────────────          ─────────────────────────
 Provisioner
   ├─ Generate DEK (in memory)
   ├─ Wrap w/ AWS KMS → aws-wrapped-DEK
   │     └─ POST → src SR (subject: cross-cloud-dek-{field}-src)
   ├─ Wrap w/ GCP KMS → gcp-wrapped-DEK
   │     └─ POST → src SR (subject: cross-cloud-dek-{field}-dst)
   └─ Zero DEK

 Schema exporter replicates both subjects ──────────────────────→ dst SR (GCP)

 Producer
   ├─ Fetch aws-wrapped-DEK from src SR
   ├─ Unwrap via AWS KMS → plaintext DEK
   ├─ AES-256-GCM encrypt social_security field
   ├─ Produce record to src Kafka topic
   └─ Zero DEK

 Cluster linking replicates records ───────────────────────────→ dst Kafka topic

                                          Consumer
                                            ├─ Fetch gcp-wrapped-DEK from dst SR
                                            ├─ Unwrap via GCP Cloud KMS → plaintext DEK
                                            ├─ AES-256-GCM decrypt social_security field
                                            └─ Zero DEK
                                            (no cross-cloud KMS call at read time)
```

---

## Supported KMS Providers

| Provider | Type | KEK identifier format | Credentials |
|---|---|---|---|
| AWS KMS | `AWS` | `arn:aws:kms:<region>:<account>:key/<id>` | AWS default credential chain |
| GCP Cloud KMS | `GCP` | `projects/.../locations/.../keyRings/.../cryptoKeys/...` | GCP application default credentials |
| Azure Key Vault | `AZURE` | `https://<name>.vault.azure.net/keys/<key>/<version>` | Azure default credential chain |
| HashiCorp Vault | `HASHICORP_VAULT` | `https://<host>/v1/transit/keys/<key-name>` | `VAULT_TOKEN` env var |
| CipherTrust | `CIPHERTRUST` | `https://<host>/api/v1/vault/keys/<key-id>` | `CIPHERTRUST_USERNAME` / `CIPHERTRUST_PASSWORD` env vars |

**KMS type inference:** For AWS, GCP, and Azure, the type is inferred automatically from the KEK identifier URI — no explicit `type` field is needed. For HashiCorp Vault and CipherTrust, the type must be set explicitly if **both** the source and destination KEKs are external (see [Case 4](#kms-type-inference-cases)).

---

## KMS Type Inference Cases

| Case | src KEK | dst KEK | Explicit type needed? |
|---|---|---|---|
| 1 | CSP (e.g. AWS) | CSP (e.g. GCP) | No — both inferred from URI |
| 2 | CSP | External (e.g. Vault) | No — src inferred; dst is already specified |
| 3 | External | CSP | No — dst CSP URI is unambiguous |
| 4 | External | External | **Yes** — set `type` on both KEKs |

---

## Quick Start

### Prerequisites

- Java 17+
- Maven 3.8+
- Source and destination Confluent Cloud clusters
- Cluster linking configured between source and destination
- Schema exporter configured from source SR to destination SR
- KMS credentials for both source and destination KEKs

### Build

```bash
mvn package -q
# Produces: target/cross-cloud-csfle-0.1.0-SNAPSHOT.jar
```

### Configure

```bash
cp deployment/deployment.properties.template deployment/deployment.properties
# Edit deployment/deployment.properties with your cluster, SR, and KMS details
```

Minimal example (AWS → GCP, Case 1):

```properties
src.bootstrap.servers=pkc-xxxxx.us-east-1.aws.confluent.cloud:9092
src.kafka.api.key=...
src.kafka.api.secret=...

src.sr.url=https://psrc-xxxxx.us-east-1.aws.confluent.cloud
src.sr.api.key=...
src.sr.api.secret=...

dst.bootstrap.servers=pkc-yyyyy.us-west2.gcp.confluent.cloud:9092
dst.kafka.api.key=...
dst.kafka.api.secret=...

dst.sr.url=https://psrc-yyyyy.us-west2.gcp.confluent.cloud
dst.sr.api.key=...
dst.sr.api.secret=...

topic=my-topic

rule.ssn.field=social_security
rule.ssn.src.kek.id=arn:aws:kms:us-east-1:123456789012:key/abc-def
rule.ssn.dst.kek.id=projects/my-proj/locations/us-west2/keyRings/my-ring/cryptoKeys/my-key
```

### Run (standalone JAR)

```bash
# Set credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-2
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud/application_default_credentials.json

JAR=target/cross-cloud-csfle-0.1.0-SNAPSHOT.jar
PROPS=deployment/deployment.properties

# 1. Provision DEKs — dual mode (default: both KMS systems reachable)
java -jar $JAR provision $PROPS

# 1b. Split mode — when source cannot reach destination KMS
#     Phase 1 (source side):
java -jar $JAR provision $PROPS          # set dek.provisioning.mode=split in properties
#     Wait for schema linking to replicate transfer subject to dst SR, then:
#     Phase 2 (destination side):
java -jar $JAR provision-dst $PROPS

# 2. Produce 10 CSFLE-encrypted records to the source cluster
java -jar $JAR producer $PROPS

# 3. Consume and decrypt from the GCP mirror topic (destination, GCP KMS)
java -jar $JAR consumer $PROPS

# 4. (Failback only) Sync DEKs after link re-establishment
java -jar $JAR sync $PROPS
```

### KMS boundary verification

Four modes explicitly prove the KMS access boundary. See [`docs/test-cases.md`](docs/test-cases.md) for full test case specifications and live run results.

```bash
# Positive: AWS cluster + AWS KMS → decrypts successfully
java -jar $JAR source-consumer $PROPS

# Negative: AWS cluster + GCP KMS → fails (GCP cannot decrypt AWS ciphertext)
java -jar $JAR source-consumer-gcp-attempt $PROPS

# Positive: GCP cluster + GCP KMS → decrypts successfully  (same as 'consumer')
java -jar $JAR consumer $PROPS

# Negative: GCP cluster + AWS KMS → fails (AWS cannot decrypt GCP ciphertext)
java -jar $JAR destination-consumer-aws-attempt $PROPS
```

### Run (Docker Compose)

```bash
# Prerequisites:
#   1. Copy deployment/deployment.properties.template → deployment/deployment.properties and fill in.
#   2. Set GOOGLE_APPLICATION_CREDENTIALS to your GCP service account JSON path.
#   3. Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and optionally AWS_SESSION_TOKEN).

docker compose run provisioner        # one-time DEK setup (dual mode)
docker compose run provision-dst      # split-mode phase 2 (destination side only)
docker compose run producer           # produce 10 CSFLE-encrypted records
docker compose run consumer           # decrypt from GCP mirror topic
docker compose run dek-sync           # pre-failback DEK sync
```

---

## Project Structure

```
cross-cloud-csfle/
├── deployment/
│   ├── deployment.properties.template   # Config template — copy and fill in
│   └── deployment.properties            # Your local config — gitignored
├── docs/
│   ├── design.md                        # Full design decisions and trade-off record
│   ├── failover-design.md               # DR failover, failback, and DEK sync design
│   └── test-cases.md                    # 4-quadrant KMS isolation verification suite + run results
├── Dockerfile                           # Multi-stage Maven + JRE build
├── docker-compose.yml                   # provisioner / producer / consumer / test services
├── src/
│   ├── main/java/io/confluent/csfle/crosscloud/
│   │   ├── Main.java                    # Dispatcher: all run modes
│   │   ├── CrossCloudCsfleEngine.java   # Entry point — provisions DEKs for all rules
│   │   ├── CrossCloudCsfleRunner.java   # CLI runner for provision mode
│   │   ├── app/
│   │   │   ├── CrossCloudProducer.java              # AWS: provision + encrypt + produce
│   │   │   ├── CrossCloudConsumer.java              # GCP: fetch dst DEK + decrypt + consume
│   │   │   ├── SplitProvisionDstApp.java            # Split-mode phase 2: wrap with dst KEK, delete transfer subject
│   │   │   ├── DekSyncApp.java                      # Pre-failback DEK sync (re-wrap + push to recovering SR)
│   │   │   ├── SourceConsumer.java                  # AWS cluster + AWS KMS (positive test)
│   │   │   ├── SourceConsumerGcpAttempt.java        # AWS cluster + GCP KMS (negative test)
│   │   │   └── DestinationConsumerAwsAttempt.java   # GCP cluster + AWS KMS (negative test)
│   │   ├── config/
│   │   │   ├── EncryptionRule.java      # One rule = one field + src KEK + dst KEK
│   │   │   ├── KekReference.java        # KEK id + optional explicit type
│   │   │   ├── KmsType.java             # Enum: AWS, GCP, AZURE, HASHICORP_VAULT, CIPHERTRUST
│   │   │   ├── KmsTypeInferrer.java     # URI-based type inference for CSP KEKs
│   │   │   └── DekProvisioningMode.java # Enum: DUAL (default) / SPLIT
│   │   ├── crypto/
│   │   │   └── FieldEncryptor.java      # AES-256-GCM field encrypt/decrypt (dekVersion:iv:ct wire format)
│   │   ├── dek/
│   │   │   ├── DekFetcher.java          # Fetch wrapped DEK from SR subject; unwrap via KMS (version-aware)
│   │   │   ├── DekProvisioner.java      # Core: generate → wrap×2 → persist → zero; single-KMS DR path
│   │   │   ├── DekSyncer.java           # Failback sync: re-wrap missing DEK versions, push to recovering SR
│   │   │   ├── DekResult.java           # DEK plaintext + SR version number pair
│   │   │   ├── SyncReport.java          # DekSyncer outcome: counts, errors, completion gate
│   │   │   ├── DekProvisioningResult.java
│   │   │   ├── DekProvisioningException.java
│   │   │   └── WrappedDek.java
│   │   ├── kms/
│   │   │   ├── KmsClient.java           # Interface: wrapDek / unwrapDek
│   │   │   ├── KmsClientFactory.java    # Resolves KmsClient from KekReference
│   │   │   ├── AwsKmsClient.java
│   │   │   ├── GcpKmsClient.java
│   │   │   ├── AzureKmsClient.java
│   │   │   ├── HashiCorpVaultKmsClient.java
│   │   │   └── CipherTrustKmsClient.java
│   │   └── linking/
│   │       ├── SrcSchemaRegistryClient.java      # Interface: storeDek
│   │       ├── DstSchemaLinkingClient.java        # Interface: publishDek
│   │       └── ConfluentSchemaRegistryClient.java # Implements both; SR REST API client
│   └── test/java/io/confluent/csfle/crosscloud/
│       └── DekProvisionerTest.java
└── pom.xml
```

---

## Design Principles

**No new components.** The solution runs entirely within the existing producer/provisioner. No sidecar, no key proxy, no re-keying service.

**Both DEK copies stored at source SR.** The src-wrapped and dst-wrapped DEKs are both written to the source Schema Registry under separate subjects (`cross-cloud-dek-{field}-src` and `cross-cloud-dek-{field}-dst`). The destination SR is in `IMPORT` mode (controlled by the schema exporter) and rejects direct writes. The schema exporter replicates both subjects to the destination SR automatically.

**DEK plaintext never leaves JVM heap.** The plaintext DEK exists in memory only for the duration of the two `wrapDek()` calls and is explicitly zeroed in a `finally` block immediately after.

**Atomicity before activation.** A DEK is not put into use until both the src-wrapped and dst-wrapped copies are confirmed stored. If either fails, a `DekProvisioningException` is thrown and no records are encrypted with that DEK.

**Self-contained rules.** Each `EncryptionRule` carries explicit references to both the source and destination KEK.

See [`docs/design.md`](docs/design.md) for the full design and decision record.

---

## Schema Registry Storage

`ConfluentSchemaRegistryClient` uses two storage strategies, tried in order:

1. **DEK Registry API** (`/keks` + `/deks/{kekName}/versions`) — available when the Confluent Cloud field-level encryption feature is enabled.

2. **Schema subject fallback** — when the DEK Registry is not enabled, the wrapped DEK is stored as a JSON schema subject under a deterministic name (`cross-cloud-dek-{field}-src` and `cross-cloud-dek-{field}-dst`). Both are written to the **source SR**; the schema exporter replicates them to the destination SR. The security model is unchanged — only the storage endpoint differs.

---

## Running Tests

```bash
mvn test
```

Unit tests cover `EncryptionRule` validation, `KmsTypeInferrer` URI patterns, and `DekProvisioner` error handling using Mockito mocks. No real KMS or Schema Registry calls are made in tests.

---

## DEK Provisioning Mode

Controls how DEKs are wrapped and distributed when source and destination use different KMS systems. Set `dek.provisioning.mode` in `deployment.properties`.

| Situation | Example | Mode | Behaviour |
|---|---|---|---|
| Same KMS type | Both AWS KMS | *(auto-detected)* | One wrap call. `dek.provisioning.mode` ignored. |
| Different KMS, both reachable | On-prem Vault + AWS KMS | `dual` (default) | Two wrap calls. Encrypted DEK replicated via schema linking. |
| Different KMS, dst not reachable | On-prem KMS + cloud KMS | `split` | Two-phase. Source wraps with src KEK. Destination wraps with dst KEK via schema linking handoff. |

### Split mode — two-phase provisioning

Used when the source-side provisioner cannot reach the destination KMS (e.g. self-managed on-prem source, cloud destination).

```bash
# Phase 1 — source side: set dek.provisioning.mode=split in deployment.properties
java -jar $JAR provision $PROPS
# Wraps with src KEK. Writes plaintext DEK as a transfer subject in src SR.
# Schema linking replicates the transfer subject to dst SR over TLS.

# Wait for schema linking to replicate (check exporter status)

# Phase 2 — destination side: same deployment.properties with dst SR credentials and dst KEK
java -jar $JAR provision-dst $PROPS
# Reads plaintext DEK from transfer subject in dst SR.
# Wraps with dst KEK. Stores dst subject. Deletes transfer subject.
# Plaintext DEK zeroed from memory immediately after wrapping.
```

The transfer subject exists only between phase 1 and phase 2. It is protected in transit by schema linking TLS and at rest by Schema Registry API key authentication.

See [`docs/design.md`](docs/design.md) for the full decision record including the security trade-off.

---

## Disaster Recovery

For full design rationale see [`docs/failover-design.md`](docs/failover-design.md). Summary:

### Failover (link breaks, one KMS unavailable)

No intervention needed. The surviving side already has its own wrapped DEK. GCP consumers keep decrypting with GCP KMS; AWS consumers keep decrypting with AWS KMS.

If DEK rotation is required while one KMS is unreachable, use `DekProvisioner.provisionSingleKms()` to wrap the new DEK with the available KMS only. The second wrap is deferred to `DekSyncer` at link re-establishment. The DEK version is embedded in every encrypted field value (`dekVersion:iv:ct` wire format) so consumers resolve the exact DEK per record regardless of how many rotations have occurred.

### Failback (recovering side comes back up)

Run the DEK sync **before** promoting any mirror topics:

```bash
# Default: GCP survived (dst), AWS is recovering (src)
java -jar $JAR sync $PROPS

# Override if AWS survived instead:
# Add sync.surviving.role=src to deployment.properties, then:
java -jar $JAR sync $PROPS
```

`DekSyncer` will:
1. List all DEK versions in the surviving SR
2. For each version absent in the recovering SR: fetch → unwrap with surviving KMS → re-wrap with recovering KMS → push to recovering SR
3. Briefly switch the recovering SR to READWRITE for the write, then restore its original mode
4. Exit non-zero if any version fails — **do not promote topics until sync reports success**

The operation is idempotent. Re-running after a partial failure is safe.

See [`docs/failover-design.md`](docs/failover-design.md) for the full 22-step failback runbook with Confluent CLI commands.

---

## Limitations

- **DEK rotation** must be triggered at the producer. There is no background rotation service.
- **Multi-destination** replication requires one rule per destination KEK.
- **In-flight re-encryption** of already-replicated records is not supported.
- **Destination SR must be in IMPORT mode** when a schema exporter is active — do not attempt direct writes to the destination SR.

See [`docs/design.md`](docs/design.md) for the full scope of what this design does and does not cover.
