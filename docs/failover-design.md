# Cross-Cloud CSFLE — Failover & Failback Design

## Overview

This document captures the design decisions and final model for handling DR failover,
failback, and DEK lifecycle management across a broken or re-established cluster link.

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
value so consumers can resolve the correct DEK regardless of how many rotations have occurred.

---

## Wire Format

The encrypted field value embeds the DEK version at the time of encryption.

```
Before (current):   base64(iv):base64(ciphertext)
After:              dekVersion:base64(iv):base64(ciphertext)
```

- `FieldEncryptor.encrypt()` prepends the SR schema version of the DEK used.
- `FieldEncryptor.decrypt()` parses the version prefix, passes it to `DekFetcher`.
- `DekFetcher.fetchPlaintextDek()` resolves by explicit version when provided,
  falls back to `latest` for records written before versioned wire format was deployed.

This is a small, self-describing change. Old records (no version prefix) are treated
as version 1. No migration required.

---

## Link Re-establishment and DEK Sync

When the link is re-established after an outage that included DEK rotation, the recovering
side is missing the AWS-wrapped copy of any DEKs provisioned during the outage.

**The sync step must complete before records begin flowing across the link.**

```
DekSyncer (runs at link re-establishment time):

  For each DEK subject in the surviving SR:
    For each version not present (as a counterpart wrap) in the recovering SR:
      1. Fetch wrapped DEK from surviving SR
      2. Unwrap with surviving KMS  → plaintext DEK (in memory only)
      3. Wrap with recovering KMS   → encrypted DEK
      4. Push to recovering SR
      5. Zero plaintext DEK

  Validate: recovering SR has a wrapped copy for every version in surviving SR.
  Only then: establish cluster link → records flow → recovering side decrypts everything.
```

After sync, both SRs are fully symmetric. The recovering side can decrypt all records —
both those produced before the outage (using the original DEK it already had) and those
produced during the outage (using the newly synced DEK copies).

If no rotation occurred during the outage, the sync step finds nothing to do and
completes immediately. Re-establishing the link is then purely an infrastructure operation.

---

## Failback (Recovering Side Becomes Primary Again)

After DEK sync is complete and the cluster link is re-established:

1. Records replicate from surviving side to recovering side (cluster link).
2. Schema exporter resumes, replicating any new schema subjects.
3. Once the recovering side is caught up (lag = 0):
   - Redirect producers back to the original primary.
   - GCP SR returns to IMPORT mode (schema exporter resumes control).
4. The surviving side returns to DR role — no crypto changes needed.

The recovering side needs no special handling. It has all DEK versions (from the sync step)
and all records (from the cluster link). Normal operation resumes.

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
and wrap it with the available KMS only. The second wrap is deferred to the sync step
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

### Decision 4: DEK sync is a prerequisite for link establishment, not a background process

**Decision:** The `DekSyncer` must complete successfully before the cluster link is
brought up. Link establishment is blocked until sync validates that the recovering SR
has a wrapped copy of every DEK version present in the surviving SR.

**Why:** If the link comes up before sync completes, the recovering side receives records
it cannot decrypt. There is no safe recovery from this without re-doing the sync and
potentially reprocessing records. The cost of waiting for sync (seconds to minutes,
depending on how many rotations occurred during the outage) is far lower than the cost
of a decryption failure window on the recovering side.

---

## What Needs to Be Built

| Component | Type | Description |
|---|---|---|
| `FieldEncryptor` | Modify | `dekVersion:iv:ct` wire format — encrypt embeds version, decrypt parses it |
| `DekFetcher` | Modify | Accept optional version; fetch by exact version or `latest` |
| `DekProvisioner` | Modify | Accept optional dst KMS client; skip dst wrap when absent |
| `DekSyncer` | New | Compares DEK subjects across two SRs; re-wraps and pushes missing copies |
| `Main` | Modify | Add `sync` mode to dispatcher |

### Build order

1. `FieldEncryptor` + `DekFetcher` — wire format and version resolution. Everything
   downstream depends on this being correct. Existing tests must still pass.
2. `DekProvisioner` — single-KMS path. Straightforward extension of existing logic.
3. `DekSyncer` — core new primitive. Depends on both KMS clients and both SR clients
   being injectable, which the existing interfaces already support.
4. `Main` dispatcher — add `sync` mode, update usage.

---

## Failure Modes and Guards

| Scenario | Behaviour |
|---|---|
| Sync step fails partway through | Idempotent — re-run DekSyncer; already-synced versions are skipped |
| Link established before sync completes | Records arrive that cannot be decrypted — prevented by sync-first constraint |
| Both KMS systems unreachable during outage | No rotation possible; existing DEK continues in use; no disruption to existing records |
| Sync runs when no rotation occurred during outage | No-op; completes immediately; link proceeds |
| Recovering SR already has a version (e.g. from a previous partial sync) | DekSyncer detects it is present and skips; no duplicate writes |
