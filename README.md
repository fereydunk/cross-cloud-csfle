# Cross-Cloud CSFLE

Atomic DEK provisioning for Confluent CSFLE across cloud providers.

When Kafka topic data is replicated from a source cluster (e.g. AWS) to a destination cluster (e.g. GCP) via cluster linking, the destination cannot decrypt CSFLE-encrypted fields because it has no access to the source KMS. This library solves that problem by provisioning the Data Encryption Key (DEK) at **both ends before any record is produced** — using only existing Confluent infrastructure, with no new components.

---

## How It Works

For each encrypted field, the engine:

1. Generates a new DEK in memory (AES-256, `SecureRandom`)
2. Wraps it with the **source KEK** → persists the wrapped DEK to the source Schema Registry
3. Wraps it with the **destination KEK** (in memory, never stored at source) → publishes the wrapped DEK to the destination Schema Registry via schema linking
4. Only after both steps succeed: the DEK is considered active and safe to use for encryption
5. The plaintext DEK is zeroed from memory immediately after steps 2 and 3, in a `finally` block

The destination cluster receives encrypted records via **cluster linking** and receives the destination-wrapped DEK via **schema linking**. At read time, the destination consumer unwraps the DEK using its local KMS — no cross-cloud KMS call is ever needed at read time.

```
Source cluster                          Destination cluster
─────────────────────                   ─────────────────────
 Producer
   │
   ├─ Generate DEK (in memory only)
   ├─ Wrap w/ src KEK
   │     └─ persist → src Schema Registry
   ├─ Wrap w/ dst KEK (in memory only)
   │     └─ publish ───────────────────────→ dst Schema Registry  (schema linking)
   │
   │  [abort and zero DEK if either wrap fails — no records produced]
   │
   ├─ Zero plaintext DEK from memory
   ├─ Encrypt field data with DEK
   └─ Publish record ───────────────────────→ dst Kafka topic  (cluster linking)
                                                   │
                                              Consumer
                                                   ├─ Fetch dst-wrapped DEK from dst SR
                                                   ├─ Unwrap using dst KEK (local KMS call)
                                                   └─ Decrypt field — no cross-cloud KMS needed
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
- Source and destination Confluent Cloud clusters with cluster linking configured
- Schema linking configured between source and destination Schema Registries
- KMS credentials for both the source and destination KEKs

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

rule.ssn.field=ssn
rule.ssn.src.kek.id=arn:aws:kms:us-east-1:123456789012:key/abc-def
rule.ssn.dst.kek.id=projects/my-proj/locations/us-west2/keyRings/my-ring/cryptoKeys/my-key
```

### Run

```bash
# Case 1 (AWS → GCP): AWS credentials via environment
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1 \
java -jar target/cross-cloud-csfle-0.1.0-SNAPSHOT.jar deployment/deployment.properties

# Case 4 (Vault → CipherTrust): explicit types + env var credentials
VAULT_TOKEN=... CIPHERTRUST_USERNAME=admin CIPHERTRUST_PASSWORD=... \
java -jar target/cross-cloud-csfle-0.1.0-SNAPSHOT.jar deployment/deployment.properties
```

On success the runner logs the base64-encoded wrapped DEK material stored at each Schema Registry and confirms both copies are active.

---

## Project Structure

```
cross-cloud-csfle/
├── deployment/
│   ├── deployment.properties.template   # Config template — copy and fill in
│   └── deployment.properties            # Your local config — gitignored
├── docs/
│   └── design.md                        # Full design decisions and trade-off record
├── src/
│   ├── main/java/io/confluent/csfle/crosscloud/
│   │   ├── CrossCloudCsfleEngine.java   # Entry point — provisions DEKs for all rules
│   │   ├── CrossCloudCsfleRunner.java   # CLI runner — reads properties, calls engine
│   │   ├── config/
│   │   │   ├── EncryptionRule.java      # One rule = one field + src KEK + dst KEK
│   │   │   ├── KekReference.java        # KEK id + optional explicit type
│   │   │   ├── KmsType.java             # Enum: AWS, GCP, AZURE, HASHICORP_VAULT, CIPHERTRUST
│   │   │   └── KmsTypeInferrer.java     # URI-based type inference for CSP KEKs
│   │   ├── dek/
│   │   │   ├── DekProvisioner.java      # Core: generate → wrap×2 → persist → zero
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

**No new components.** The solution runs entirely within the existing producer. No sidecar, no key proxy, no re-keying service.

**DEK plaintext never leaves JVM heap.** The plaintext DEK exists in memory only for the duration of the two `wrapDek()` calls and is explicitly zeroed in a `finally` block immediately after — before any records are produced.

**Atomicity before activation.** A DEK is not put into use until both the src-wrapped and dst-wrapped copies are confirmed stored. If either wrap or persist step fails, a `DekProvisioningException` is thrown and no records are encrypted with that DEK.

**Self-contained rules.** Each `EncryptionRule` carries explicit references to both the source and destination KEK. Configuration is auditable and self-describing — a rule tells you exactly where both copies of the DEK live.

See [`docs/design.md`](docs/design.md) for the full design and decision record including all alternatives considered and why they were rejected.

---

## Schema Registry Storage

`ConfluentSchemaRegistryClient` uses two storage strategies, tried in order:

1. **DEK Registry API** (`/keks` + `/deks/{kekName}/versions`) — available when the Confluent Cloud field-level encryption feature is enabled. Schema linking replicates DEK subjects automatically.

2. **Schema subject fallback** — when the DEK Registry is not enabled (e.g. standard SR tier), the wrapped DEK is stored as a JSON schema subject under a deterministic name (`cross-cloud-dek-{field}-{role}`). Schema linking replicates this subject to the destination SR identically to any other subject. The security model is unchanged — only the storage endpoint differs.

---

## Running Tests

```bash
mvn test
```

Unit tests cover `EncryptionRule` validation (all four KMS cases), `KmsTypeInferrer` URI patterns, and `DekProvisioner` error handling using Mockito mocks. No real KMS or Schema Registry calls are made in tests.

---

## Limitations

- **DEK rotation** must be triggered at the producer. There is no background rotation service.
- **Multi-destination** replication requires one rule per destination KEK.
- **In-flight re-encryption** of already-replicated records is not supported.

See [`docs/design.md`](docs/design.md) for the full scope of what this design does and does not cover.
