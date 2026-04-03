# Cross-Cloud CSFLE — Failover & Failback Design

## Overview

This document captures the design decisions and final model for handling DR failover,
failback, and DEK lifecycle management across a broken or re-established cluster link.
It also documents how the DEK sync step integrates into Confluent's native failback
sequence of cluster link and schema exporter operations.

---

## Core Principle

The cryptographic layer is already complete at provisioning time. Both the source-wrapped
and destination-wrapped DEK exist in both Schema Registries before any record is produced.
This means each side is permanently self-sufficient — neither side ever needs to call the
other's KMS at read time, and neither side loses decryption capability when the link breaks.

---

## Two-Mode Model

### Normal operation (link active)

```
Provisioner:
  Generate DEK (in memory)
  Wrap with src KEK (AWS KMS)  → persist src-wrapped DEK to src SR
  Wrap with dst KEK (GCP KMS)  → persist dst-wrapped DEK to dst SR (via schema exporter)
  Zero plaintext DEK

Producer:
  Fetch src-wrapped DEK from src SR → unwrap with AWS KMS → encrypt field → produce record

Consumer (GCP):
  Fetch dst-wrapped DEK from dst SR → unwrap with GCP KMS → decrypt field
```

Both sides have both wrappings. Both sides can decrypt any record independently.
This is the current implementation — no changes required.

### DR mode (link broken, one KMS unavailable)

When the link breaks, the surviving side continues without disruption:

```
Surviving side (e.g. GCP):
  Existing DEK is already in GCP SR (dst-wrapped).
  GCP consumers keep decrypting existing records — no change, no intervention.
  GCP producers keep encrypting new records with the same DEK — no change.
```

**No new DEK is generated, no provisioning is needed, no mode switch is required.**
The surviving side operates identically to normal — it already has everything it needs.

---

## DEK Rotation During Outage

DEKs are only ever generated when a rotation policy requires it. There is no automatic
or time-based rotation in the provisioner — rotation is an explicit operator action.

If rotation is triggered while the link is broken and one KMS is unavailable:

```
Surviving side (e.g. GCP, AWS KMS unreachable):
  Generate new DEK (in memory)
  Wrap with GCP KMS only  → persist GCP-wrapped DEK to GCP SR
  Zero plaintext DEK
  Use new DEK for new records (embedded version in wire format)

  AWS-wrapped copy: deferred — AWS KMS is unreachable.
  AWS SR: does not yet have the new DEK.
```

New records are produced normally. The DEK version is embedded in each encrypted field
value so consumers can resolve the correct DEK regardless of how many rotations occurred.

---

## Wire Format

The encrypted field value embeds the DEK version at the time of encryption.

```
Before (current):   base64(iv):base64(ciphertext)
After:              dekVersion:base64(iv):base64(ciphertext)
```

- `FieldEncryptor.encrypt()` prepends the Schema Registry schema version of the DEK used.
- `FieldEncryptor.decrypt()` parses the version prefix, passes it to `DekFetcher`.
- `DekFetcher.fetchPlaintextDek()` resolves by explicit version when provided,
  falls back to `latest` for records written before the versioned wire format was deployed.

Old records (no version prefix) are treated as version 1. No migration required.

---

## How Confluent Failback Works

Confluent has **no native hooks** — no pre-promotion event, no pre-link-creation callback,
no extension point in cluster linking or schema linking. Every step in failover and failback
is an explicit CLI command or REST API call, which means the caller controls the ordering.
This is the integration point for the DEK sync step.

### Confluent failover sequence (AWS down, GCP takes over)

```
1. confluent schema-registry exporter pause <exporter> --sr-endpoint <aws-sr>
   (or exporter is already dead if AWS is fully down)

2. confluent schema-registry mode update --mode READWRITE --sr-endpoint <gcp-sr>
   GCP SR exits IMPORT mode. Producers can now register new schemas and DEK subjects.

3. confluent kafka mirror promote --all --link <aws-to-gcp-link> --cluster <gcp-cluster>
   Mirror topics become writable on GCP. The cluster link is severed.

4. Redirect producers and consumers to GCP cluster + GCP SR.
   GCP side operates independently using existing dst-wrapped DEKs.
```

### Confluent failback sequence (AWS recovers, returning to primary)

There are no shortcuts — failback requires a temporary reverse link and schema exporter.

```
PHASE 1 — Catch up records from GCP back to AWS

1. confluent kafka link create <gcp-to-aws-link> \
     --cluster <aws-cluster> \
     --source-cluster-id <gcp-cluster> \
     --source-bootstrap-server <gcp-bootstrap>

2. confluent kafka mirror create <topic> \
     --link <gcp-to-aws-link> \
     --cluster <aws-cluster>
   (Repeat for each topic. AWS mirror topics now consume from GCP.)

3. Poll until mirror lag reaches zero:
   confluent kafka mirror describe <topic> --link <gcp-to-aws-link> --cluster <aws-cluster>

PHASE 2 — Catch up schemas from GCP back to AWS

4. confluent schema-registry mode update --mode IMPORT --sr-endpoint <aws-sr>
   AWS SR enters IMPORT mode so the reverse exporter can write to it safely.

5. confluent schema-registry exporter create <gcp-to-aws-exporter> \
     --subjects "*" \
     --sr-endpoint <gcp-sr> \
     --destination-sr-url <aws-sr>
   AWS SR now receives all schemas registered on GCP during the DR period.

6. Wait until exporter status is RUNNING and all subjects are replicated.

PHASE 3 — DEK sync  ← injection point
   (See next section for full detail.)

PHASE 4 — Cut over back to AWS

7. confluent kafka mirror promote --all --link <gcp-to-aws-link> --cluster <aws-cluster>
   AWS topics become writable again.

8. confluent kafka link delete <gcp-to-aws-link> --cluster <aws-cluster>

9. Redirect producers and consumers back to AWS cluster + AWS SR.

PHASE 5 — Restore original topology

10. confluent schema-registry exporter delete <gcp-to-aws-exporter> --sr-endpoint <gcp-sr>

11. confluent schema-registry mode update --mode READWRITE --sr-endpoint <aws-sr>
    AWS SR exits IMPORT mode. Producers can write schemas directly again.

12. confluent kafka link create <aws-to-gcp-link> \
      --cluster <gcp-cluster> \
      --source-cluster-id <aws-cluster> \
      --source-bootstrap-server <aws-bootstrap>

13. confluent kafka mirror create <topic> --link <aws-to-gcp-link> --cluster <gcp-cluster>
    GCP mirror topics resume — GCP returns to DR role.

14. confluent schema-registry exporter create <aws-to-gcp-exporter> \
      --subjects "*" \
      --sr-endpoint <aws-sr> \
      --destination-sr-url <gcp-sr>

15. confluent schema-registry mode update --mode IMPORT --sr-endpoint <gcp-sr>
    GCP SR returns to IMPORT mode — schema exporter resumes full control.
```

---

## DEK Sync Integration Point

The DEK sync step runs in **Phase 3**, between schema catch-up and topic promotion.
At that point:
- AWS SR is in IMPORT mode and has received all GCP-era schemas (including any DEK subjects
  registered during the DR period).
- GCP mirror lag on AWS is zero — AWS has all records.
- Neither cluster has been promoted yet — no new records can be written anywhere.

This is the clean, atomic window: data is frozen, both SRs are current, both KMS systems
are reachable. The DEK sync runs here.

```
PHASE 3 — DEK sync (between steps 6 and 7 above)

DekSyncer:
  For each DEK subject in GCP SR:
    For each version that exists in GCP SR but has no AWS-wrapped counterpart in AWS SR:
      1. Fetch GCP-wrapped DEK from GCP SR
      2. Unwrap with GCP KMS  → plaintext DEK (in memory only)
      3. Wrap with AWS KMS    → AWS-wrapped DEK
      4. Push to AWS SR       (AWS SR is in IMPORT mode — write is permitted by DekSyncer
                               acting as the authoritative source, not a direct client write)
      5. Zero plaintext DEK

  Validate: every DEK version in GCP SR has a counterpart AWS-wrapped version in AWS SR.
  Only then: proceed to Phase 4 (topic promotion).
```

Note on IMPORT mode and DEK writes: the Schema Registry IMPORT mode prevents schema
registrations from regular producers/consumers. The DekSyncer writes DEK subjects as
schema subjects (the existing schema subject fallback storage strategy). Writing in IMPORT
mode requires the writer to present as an authoritative replication source. The current
`ConfluentSchemaRegistryClient` uses the normal schema registration endpoint, which IMPORT
mode will reject. Two options:

- **Option A**: Switch AWS SR to READWRITE for the duration of the DEK sync, then back
  to IMPORT. This is safe because DekSyncer is the only writer during this window.
- **Option B**: Use the Schema Registry `/subjects/{subject}/versions` endpoint with the
  `normalize=false` flag and the `X-Schema-Registry-Source` header that the schema
  exporter itself uses, which IMPORT mode permits. Requires inspecting the exporter's
  wire protocol.

**Option A is simpler and correct for this PoC.** The mode switch adds two API calls
and a few seconds; the correctness guarantee is clear.

```
DEK sync with mode management:

  PUT /mode → READWRITE on AWS SR
  Run DekSyncer (all versions, all subjects)
  Validate completeness
  PUT /mode → IMPORT on AWS SR
  Proceed to Phase 4
```

### Why this is the right injection point

| Property | Value |
|---|---|
| Both KMS systems reachable | Yes — AWS has recovered |
| Both SRs current | Yes — schema exporter catch-up is complete |
| No new records flowing | Yes — no topic has been promoted yet |
| Sync is idempotent | Yes — DekSyncer skips versions already present |
| Sync failure is recoverable | Yes — re-run DekSyncer, then retry promotion |
| Records cannot arrive undecryptable | Yes — promotion is blocked until sync validates |

---

## Full Failback Runbook with DEK Sync

```
Step  Who        Action
────  ─────────  ──────────────────────────────────────────────────────────────────
 1    Operator   Confirm AWS cluster is stable and fully recovered
 2    Confluent  Create reverse cluster link: GCP → AWS
 3    Confluent  Create mirror topics on AWS (from GCP)
 4    Operator   Wait: mirror lag = 0 on all topics
 5    Confluent  Set AWS SR → IMPORT mode
 6    Confluent  Create reverse schema exporter: GCP SR → AWS SR
 7    Operator   Wait: all GCP-era schemas replicated to AWS SR
 8    App        PUT /mode → READWRITE on AWS SR  (temporary, for DEK sync)
 9    App        Run DekSyncer: re-wrap GCP-era DEKs with AWS KMS, push to AWS SR
10    App        Validate: every DEK version in GCP SR present in AWS SR
11    App        PUT /mode → IMPORT on AWS SR
12    Confluent  Pause all GCP mirror topics on AWS
13    Confluent  Promote all AWS mirror topics (AWS becomes writable)
14    Confluent  Delete reverse cluster link (GCP → AWS)
15    Operator   Redirect producers and consumers to AWS
16    Confluent  Delete reverse schema exporter (GCP SR → AWS SR)
17    Confluent  PUT /mode → READWRITE on AWS SR
18    Confluent  Create original cluster link: AWS → GCP
19    Confluent  Create mirror topics on GCP (from AWS)
20    Confluent  Create original schema exporter: AWS SR → GCP SR
21    Confluent  PUT /mode → IMPORT on GCP SR
22    Operator   Validate: produce a CSFLE test record on AWS, decrypt on both sides
```

Steps 8–11 are the DEK sync window. Everything before is Confluent infrastructure
catch-up. Everything after is restoring the original topology.

---

## Confluent REST API Reference for Automation

```
# Mirror topic operations
GET    /kafka/v3/clusters/{id}/links/{link}/mirrors              # list mirrors + lag
POST   /kafka/v3/clusters/{id}/links/{link}/mirrors/{topic}:pauseMirror
POST   /kafka/v3/clusters/{id}/links/{link}/mirrors/{topic}:promoteMirror
POST   /kafka/v3/clusters/{id}/links/{link}/mirrors:promoteMirror  # batch promote

# Cluster link operations
POST   /kafka/v3/clusters/{id}/links             # create link
DELETE /kafka/v3/clusters/{id}/links/{link}      # delete link

# Schema Registry mode
GET    /mode                                     # get global mode
PUT    /mode   {"mode": "READWRITE"|"IMPORT"}    # set global mode

# Schema exporter
GET    /exporters                                # list exporters
POST   /exporters                                # create exporter
PUT    /exporters/{name}/pause                   # pause
PUT    /exporters/{name}/resume                  # resume
GET    /exporters/{name}/status                  # check status
DELETE /exporters/{name}                         # delete
```

---

## Decision Record

### Decision 1: Surviving side uses existing DEK during outage (no new DEK on failover)

**Decision:** When the link breaks, the surviving side continues using the most recent DEK.
No new DEK is provisioned at failover time.

**Why:** The dst-wrapped DEK was already replicated to the surviving SR before the link
broke. The surviving KMS can unwrap it. Producers and consumers see no disruption.
Generating a new DEK at failover time would create an unnecessary rotation event and
complicate the sync step without any benefit.

---

### Decision 2: Rotation during outage uses single-KMS wrap, deferred second wrap

**Decision:** If rotation is required while one KMS is unreachable, generate a new DEK
and wrap it with the available KMS only. The second wrap is deferred to the DEK sync step
when the link re-establishes and the other KMS becomes reachable again.

**Why:** Blocking rotation until both KMS systems are available defeats the purpose of
DR — the surviving side must be able to rotate keys independently. Deferring the second
wrap to sync time is safe: records produced during the outage are on the surviving side
and can only be read by the surviving side until sync completes, which is the correct
security posture for an active outage.

---

### Decision 3: DEK version embedded in encrypted field wire format

**Decision:** The wire format for encrypted field values is `dekVersion:base64(iv):base64(ct)`.
The version is the Schema Registry schema version of the DEK subject at encrypt time.

**Why:** Multiple DEK versions coexist on the same topic after any rotation (during or
outside an outage). The consumer must resolve the exact DEK version used to encrypt each
record. Embedding the version in the field value is self-describing, requires no separate
index, and works across cluster link replication without any additional metadata.

**Alternative rejected:** Always fetch `latest` and fall back through versions.
Rejected because: (a) slow for old records, (b) a failed AES-GCM decrypt is
indistinguishable from corrupt data at the application level.

---

### Decision 4: DEK sync is a prerequisite for topic promotion, not a background process

**Decision:** `DekSyncer` must complete and validate successfully before any mirror topic
is promoted on the recovering side. Promotion is blocked until sync is confirmed.

**Why:** If promotion happens before sync completes, the recovering side receives records
it cannot decrypt. There is no safe recovery without re-doing the sync and potentially
reprocessing records. The `pauseMirror` → DEK sync → `promoteMirror` sequence is the
natural window Confluent's API provides — we use it.

---

### Decision 5: DEK sync runs with AWS SR briefly in READWRITE mode

**Decision:** During the DEK sync window (steps 8–11 of the runbook), AWS SR is switched
to READWRITE so that DekSyncer can write the re-wrapped DEK subjects. It is switched back
to IMPORT immediately after sync completes.

**Why:** The Schema Registry IMPORT mode rejects writes from normal clients. Switching to
READWRITE for the sync window is safe because DekSyncer is the only writer during this
window (mirror topics are paused, producers have not been redirected to AWS yet). The
alternative — emulating the schema exporter wire protocol to write in IMPORT mode — is
complex and fragile.

---

## Build Status

| Component | Type | Status | Notes |
|---|---|---|---|
| `FieldEncryptor` | Modify | ✅ Done | `dekVersion:iv:ct` wire format; backward-compat with old `iv:ct` |
| `DekFetcher` | Modify | ✅ Done | `fetchDek(field, role, version)` + `listVersions()` + `listDekFields()` |
| `DekProvisioner` | Modify | ✅ Done | `provisionSingleKms(rule, useSrc)` — single-KMS DR path |
| `DekSyncer` | New | ✅ Done | Compares SRs, re-wraps missing versions, SR mode management, idempotent |
| `DekSyncApp` | New | ✅ Done | CLI entrypoint for `sync` mode; auto-detects surviving/recovering role |
| `SyncReport` | New | ✅ Done | Completion gate — non-zero exit and error list on any failure |
| `DekProvisioningMode` | New | ✅ Done | Enum: `DUAL` / `SPLIT`; single-KMS auto-detected |
| `SplitProvisionDstApp` | New | ✅ Done | Phase 2 runner for split-mode provisioning |
| `Main` | Modify | ✅ Done | `sync` and `provision-dst` modes wired |
| `FailbackRunner` | New | ⬜ Not started | Full Confluent REST API orchestration (link + exporter + DEK sync sequence) |

`FailbackRunner` would automate the 22-step runbook below. Until it exists, operators
follow the runbook manually, running `java -jar ... sync $PROPS` for steps 8–11.

---

## Failure Modes and Guards

| Scenario | Behaviour |
|---|---|
| DEK sync fails partway through | Idempotent — re-run DekSyncer; already-synced versions are skipped |
| Topic promoted before sync completes | Prevented by runbook ordering: sync validates before promotion |
| Both KMS systems unreachable during outage | No rotation possible; existing DEK continues; no disruption |
| Sync runs when no rotation occurred during outage | No-op; completes immediately; runbook proceeds |
| Recovering SR already has a version (partial previous sync) | DekSyncer detects it present and skips; no duplicate writes |
| Schema exporter catch-up incomplete when sync runs | Sync finds no GCP-era DEK subjects in AWS SR — detects mismatch, blocks promotion |
| AWS SR stuck in READWRITE after sync crash | Next runbook run re-checks mode, sets IMPORT, continues from safe state |
