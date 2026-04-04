# Cross-Cloud CSFLE — Design & Decision Record

## Purpose

Customers need to replicate Kafka topic data across cloud environments where the source and
destination use different KMS providers. Common scenarios include:

- AWS → GCP
- HashiCorp Vault → GCP
- CipherTrust → HashiCorp Vault
- Any combination of CSP-native and external KMS systems

Without cross-cloud CSFLE, the destination cluster cannot decrypt replicated records because
it has no access to the source KMS. This design solves that by provisioning the DEK at both
ends before any record is produced, so the destination is self-sufficient from the moment data
arrives.

---

## Hard Constraints

These constraints shaped every decision below and are not negotiable:

1. **No new component.** No sidecar, no key proxy, no migration service, no broker-side agent.
   The solution must work entirely within existing Confluent infrastructure.

2. **Data movement exclusively via cluster linking and schema linking.**
   Cluster linking carries encrypted records. Schema linking carries key material (wrapped DEKs).

3. **The DEK plaintext must never be written to disk or transmitted over the network.**
   It exists in JVM heap only, for the minimum duration required for the two wrap operations,
   and is zeroed immediately after.

---

## Two KEKs Per Encryption Rule

Each encryption rule carries explicit references to both the source and destination KEK:

```json
{
  "field": "ssn",
  "src_kek": {
    "id": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
  },
  "dst_kek": {
    "id": "projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key"
  }
}
```

**Why two KEKs in the rule, not discovered at runtime?**
The alternative was to discover the dst KEK at replication time — either from cluster metadata
or a separate config file. That was rejected because:

- Discovery at runtime requires coordination between the producer and a config authority,
  which is effectively a new component.
- Putting both KEKs in the rule makes the configuration self-contained and auditable.
  A rule tells you exactly where both copies of the DEK will live.
- It enables validation at startup, before any data is encrypted.

---

## KMS Type Inference and the Marker

### Why KMS type needs to be known

To wrap or unwrap a DEK, the engine must instantiate the correct KMS client (AWS SDK, GCP SDK,
Vault driver, CipherTrust REST client, etc.). This requires knowing the KMS type.

### Inference from URI (Cases 1–3)

For CSP-native KMS providers, the KEK identifier format is globally unique and unambiguous:

| KEK identifier pattern                             | Inferred KMS type |
|----------------------------------------------------|-------------------|
| `arn:aws:kms:<region>:<account>:key/<id>`          | AWS KMS           |
| `projects/.../keyRings/.../cryptoKeys/...`         | GCP Cloud KMS     |
| `https://<name>.vault.azure.net/keys/<key>/...`    | Azure Key Vault   |

No additional configuration is needed in these cases — the URI is the marker.

### The four cases

| Case | src_kek        | dst_kek        | Marker required? | Rationale                                                         |
|------|----------------|----------------|------------------|-------------------------------------------------------------------|
| 1    | CSP (e.g. AWS) | CSP (e.g. GCP) | No               | Both inferred from URI format                                     |
| 2    | CSP            | External       | No               | src inferred from URI; dst is already explicit in the rule        |
| 3    | External       | CSP            | No               | dst CSP is unambiguous — its URI uniquely identifies the provider |
| 4    | External       | External       | **Yes**          | Neither URI pattern is globally unique; type is genuinely ambiguous |

**Why Case 3 needs no marker:**
Even though the src KEK is external (e.g. HashiCorp Vault), the dst KEK is a CSP URI. The dst
type is unambiguous regardless of what the src is. The engine can instantiate the correct dst
KMS client from the URI alone. The src side does still need an explicit `type` in case 4, but
not when the counterpart is a CSP.

**Why Case 4 requires an explicit marker:**
HashiCorp Vault and CipherTrust both use HTTPS URIs with no globally standardized path
structure that distinguishes them from each other or from any other REST-based KMS. When
both src and dst are external, the engine cannot determine which SDK/driver to use from
the URI alone. The customer must provide an explicit `type` field:

```json
{
  "field": "ssn",
  "src_kek": {
    "id": "https://vault.example.com/v1/transit/keys/my-key",
    "type": "HASHICORP_VAULT"
  },
  "dst_kek": {
    "id": "https://ciphertrust.example.com/api/v1/keys/my-key",
    "type": "CIPHERTRUST"
  }
}
```

This is validated at `EncryptionRule` construction time — the engine fails fast before any
KMS call is made.

---

## DEK Provisioning Flow

### The exact steps (as designed)

```
1. Generate a new DEK in memory (AES-256, SecureRandom).
2. Wrap DEK with src KEK  → persist the encrypted DEK to src Schema Registry.
3. Wrap DEK with dst KEK  → persist the encrypted DEK also to src Schema Registry
                            under a "dst" subject name.
4. Schema exporter replicates both subjects to dst Schema Registry automatically.
5. Only after both step 2 and step 3 succeed → begin using this DEK to encrypt field data.
6. Encrypted records flow to dst cluster via cluster linking.
```

The DEK plaintext is zeroed from memory immediately after steps 2 and 3, regardless of
whether they succeed or fail.

### Why both DEK subjects are written to the source Schema Registry

The destination Schema Registry is placed in **IMPORT mode** by the schema exporter
(schema linking). In IMPORT mode, the Schema Registry rejects direct writes — only the
exporter may write to it. Attempting to write the dst-wrapped DEK directly to the dst SR
returns HTTP 422 (`Subject is not in read-write mode`).

The solution is to write **both** wrapped DEK subjects (`-src` and `-dst`) to the **source**
Schema Registry. The schema exporter then replicates both to the destination SR automatically,
preserving the same subject names and schema IDs.

```
src SR subjects:                          dst SR subjects (replicated by exporter):
  cross-cloud-dek-{field}-src  ──────→     cross-cloud-dek-{field}-src
  cross-cloud-dek-{field}-dst  ──────→     cross-cloud-dek-{field}-dst
```

### What is stored where

```
Source cluster                                  Destination cluster
──────────────────────────────────              ──────────────────────────────
src Schema Registry:                            dst Schema Registry:
  DEK encrypted with src KEK (-src subject)       DEK encrypted with src KEK (-src, replicated)
  DEK encrypted with dst KEK (-dst subject)       DEK encrypted with dst KEK (-dst, replicated)

src Kafka topic:                                dst Kafka topic:
  Records with fields encrypted by DEK             Same records (via cluster linking)
```

The source producer unwraps the `-src` subject using AWS KMS.
The destination consumer unwraps the `-dst` subject using GCP Cloud KMS.
Neither side ever needs to call the other's KMS.

### Why the split between schema linking and cluster linking

Schema linking replicates Schema Registry subjects (schemas and associated key metadata) from
src to dst. This is the natural transport for DEK material — it is metadata, not stream data,
and schema linking gives it the same lifecycle as the schema it belongs to.

Cluster linking replicates Kafka topic records. Encrypted field data travels here.

This split means the dst cluster receives both independently and can correlate them by subject
and version — exactly what Confluent's existing CSFLE consumer machinery already does.

### Atomicity guarantee

The DEK is not put into use until both wrapped copies are confirmed stored (steps 2 and 3).
If either step fails, a `DekProvisioningException` is thrown, the plaintext DEK is zeroed,
and no records are produced with that DEK.

This guarantees: **a record will never reach the destination with a DEK the destination
cannot unwrap.**

```
Source cluster                          Destination cluster
─────────────────────                   ─────────────────────
 Producer/Provisioner
   │
   ├─ Generate DEK (in memory only)
   ├─ Wrap w/ src KEK
   │     └─ persist → src SR (subject: cross-cloud-dek-{field}-src)
   ├─ Wrap w/ dst KEK (in memory only)
   │     └─ persist → src SR (subject: cross-cloud-dek-{field}-dst)
   │                    ↓
   │          Schema exporter replicates ─────────────────→ dst SR (both -src and -dst subjects)
   │
   │  [abort and zero DEK if either wrap/persist fails — no records produced]
   │
   ├─ Zero plaintext DEK from memory
   ├─ Encrypt field data with DEK
   └─ Publish record ──────────────────────────────────→ dst Kafka topic  (cluster linking)
                                                               │
                                                          Consumer
                                                               ├─ Fetch -dst subject from dst SR
                                                               ├─ Unwrap using GCP Cloud KMS
                                                               └─ Decrypt field — no cross-cloud KMS needed
```

---

## Design Decisions and Trade-offs

### Decision 1: No new component

**Decision:** The entire solution runs within the existing producer, using cluster linking and
schema linking for transport.

**Alternatives considered:**
- A key migration sidecar that runs alongside brokers and re-wraps DEKs asynchronously.
- A key proxy service that sits between the dst consumer and the src KMS.
- A background re-keying service triggered by cluster linking events.

**Why rejected:** All three require operating a new service, which adds deployment complexity,
a new failure domain, and an operational burden for customers. The no-new-component constraint
was set explicitly to avoid this.

**Consequence:** DEK rotation across clusters must be triggered at the producer level. There
is no background re-keying service.

---

### Decision 2: DEK wrapped in memory, not re-wrapped at the destination

**Decision:** The dst-wrapped DEK is produced by the source producer (in memory) and persisted
to the source Schema Registry under a `-dst` subject. The schema exporter replicates it to
the dst Schema Registry automatically. The dst never re-wraps anything — it only unwraps
using its own KEK.

**Alternative considered:** Have the dst cluster receive the src-wrapped DEK and call the
src KMS to unwrap it, then re-wrap with the dst KEK locally.

**Why rejected:**
- Requires the dst to have cross-cloud IAM/network access to the src KMS — exactly the
  coupling we are trying to eliminate.
- Introduces a runtime dependency: dst decryption is blocked if src KMS is unavailable.
- Contradicts the no-new-component constraint (the re-wrap agent would be a new component).

**Consequence:** The source producer must have network and authentication access to both
the src KMS and the dst KMS at provisioning time. This is a one-time setup cost, not an
ongoing runtime dependency.

---

### Decision 3: Atomicity before activation

**Decision:** The DEK is not used for encryption until both the src-wrapped and dst-wrapped
copies are confirmed persisted.

**Alternative considered:** Produce records optimistically and ship the dst-wrapped DEK
asynchronously, accepting a window where the dst cannot decrypt.

**Why rejected:** Data arriving at the destination that cannot be decrypted is a worse failure
mode than a brief delay in DEK activation. The destination having a gap in its data is far
more disruptive than the producer waiting an extra round-trip.

**Consequence:** If schema linking to the dst Schema Registry is unavailable, the producer
blocks on DEK provisioning and cannot encrypt new fields. Operators must ensure schema linking
is healthy before starting producers with cross-cloud rules.

---

### Decision 4: DEK plaintext zeroed immediately after wrapping

**Decision:** The plaintext DEK byte array is explicitly zeroed (`Arrays.fill(dek, (byte) 0)`)
in a `finally` block immediately after both wrap operations complete, whether they succeed or
fail.

**Alternative considered:** Rely on JVM garbage collection to eventually reclaim the array.

**Why rejected:** GC timing is non-deterministic. The plaintext DEK could remain in heap for
an arbitrary duration and appear in heap dumps or memory snapshots. Explicit zeroing minimises
the window of exposure.

**Constraint:** The plaintext DEK is never written to disk, serialized, or transmitted. It
exists only in JVM heap for the duration of the two `wrapDek()` calls.

---

### Decision 5: Explicit type marker only for Case 4

**Decision:** The `type` field in a `KekReference` is optional for CSP KEKs (inferred from
URI) and required only when both src and dst KEKs are external non-CSP systems.

**Alternative considered:** Always require an explicit `type` field on every KEK reference,
eliminating inference entirely.

**Why rejected:** The vast majority of customers will use at least one CSP-native KMS. Requiring
explicit types everywhere adds boilerplate that buys nothing for those cases — the ARN or GCP
resource path already unambiguously identifies the provider.

**Alternative considered:** Infer all types including external ones via heuristics (e.g., path
containing `/transit/keys/` implies Vault).

**Why rejected:** Path heuristics for external KMS systems are brittle — customers self-host
Vault and CipherTrust with custom paths. A wrong inference silently calls the wrong KMS,
which fails at runtime in a confusing way. Explicit is better here.

---

### Decision 6: Source retains its own src-wrapped DEK

**Decision:** After provisioning, the source Schema Registry holds a src-wrapped copy and the
dst Schema Registry holds a dst-wrapped copy. Both are independent.

**Alternative considered:** Only ship the dst-wrapped DEK and have the source also use it
(both src and dst share the dst KEK).

**Why rejected:** Sharing a KEK across clusters couples their key management. The source would
need access to the dst KMS for all future decrypt operations, re-introducing the cross-cloud
runtime dependency this design eliminates.

**Consequence:** Two wrapped copies of each DEK exist (one per cluster). This is a small,
acceptable storage overhead in exchange for full decoupling.

---

## Supported KMS Providers

| Provider         | Type enum           | URI inference                        | Credential source                         |
|------------------|---------------------|--------------------------------------|-------------------------------------------|
| AWS KMS          | `AWS`               | `arn:aws:kms:...`                    | AWS default credential chain              |
| GCP Cloud KMS    | `GCP`               | `projects/.../cryptoKeys/...`        | GCP application default credentials       |
| Azure Key Vault  | `AZURE`             | `https://*.vault.azure.net/keys/...` | Azure default credential chain            |
| HashiCorp Vault  | `HASHICORP_VAULT`   | None — explicit type required        | `VAULT_TOKEN` environment variable        |
| CipherTrust      | `CIPHERTRUST`       | None — explicit type required        | `CIPHERTRUST_USERNAME` / `_PASSWORD` envs |

---

## DEK Provisioning Mode

The provisioner supports three situations depending on KMS topology:

| Situation | KMS configuration | Behaviour | Property |
|---|---|---|---|
| 1 | src and dst use the same KMS type | One wrap call. Same ciphertext stored as both src and dst subjects. `dek.provisioning.mode` is ignored. | Not applicable |
| 2 | Different KMS types, both reachable from provisioner | Two wrap calls. Encrypted DEK replicated to dst SR via schema linking. | `dual` (default) |
| 3 | Different KMS types, dst KMS not reachable from provisioner | Phase 1 (source): src wrap + plaintext DEK written to transfer subject. Phase 2 (destination): read transfer subject, dst wrap, delete transfer subject. | `split` |

### Situation 1 — same KMS (auto-detected)

When `srcKek.resolveType() == dstKek.resolveType()`, the provisioner wraps once using the src
KEK and stores the same ciphertext under both the `-src` and `-dst` subjects. No second KMS
call is made. The `dek.provisioning.mode` property has no effect for these rules.

### Situation 2 — dual (default)

The existing provisioning flow. Both wrap calls happen in one pass. The `-dst` subject is
written to the source SR and schema linking replicates it to the destination SR.

### Situation 3 — split (two-phase)

Used when the source-side provisioner cannot reach the destination KMS (e.g. source is
on-prem with a local KMS; destination is in a cloud with a cloud-native KMS).

```
Phase 1 — source side (java -jar ... provision deployment.properties):
  1. Generate DEK in memory
  2. Wrap with src KEK → store as src subject in src SR
  3. Write plaintext DEK (base64) as a temporary transfer subject in src SR
  4. Schema linking replicates transfer subject to dst SR over TLS
  5. Zero plaintext DEK

Phase 2 — destination side (java -jar ... provision-dst deployment.properties):
  1. Switch dst SR to READWRITE temporarily
  2. Read transfer subject from dst SR → decode plaintext DEK
  3. Wrap with dst KEK → store as dst subject in dst SR
  4. Delete transfer subject from dst SR
  5. Restore dst SR to original mode
  6. Zero plaintext DEK
```

The transfer subject (`cross-cloud-dek-{field}-transfer`) is protected in transit by schema
linking TLS and at rest by Schema Registry authentication. It exists only for the window
between phase 1 and phase 2 — it is deleted as soon as phase 2 completes.

**Hard constraint relaxation:** split mode is the only situation where plaintext DEK material
exists outside the provisioner JVM (stored temporarily in Schema Registry). This is an
explicit trade-off accepted for deployments where dual-KMS access from a single host is not
possible. See constraint 3 in [Hard Constraints](#hard-constraints).

---

## What This Design Does Not Cover

- **DEK rotation:** Rotating to a new DEK requires re-provisioning (steps 1–4) and is
  triggered at the producer. There is no background rotation service.
- **Multi-destination replication:** A single rule has one src KEK and one dst KEK. Fanning
  out to multiple destinations requires multiple rules (one per destination KEK).
- **Key revocation:** Revoking a KEK at the src or dst KMS will prevent future DEK unwrapping
  on that side. Recovery requires re-provisioning with a new KEK.
- **In-flight re-encryption:** Records already replicated to the dst with one DEK cannot be
  re-encrypted in place. Re-encryption requires producing new records.

---

## KMS Isolation Verification

The four-quadrant KMS isolation matrix is verified by live test cases against the AWS→GCP
PoC infrastructure. See [`docs/test-cases.md`](test-cases.md) for full test case
specifications, commands, expected outcomes, and run results.
