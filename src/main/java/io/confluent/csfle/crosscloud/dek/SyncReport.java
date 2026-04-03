package io.confluent.csfle.crosscloud.dek;

import java.util.Collections;
import java.util.List;

/**
 * Result of a {@link DekSyncer#sync()} run.
 */
public final class SyncReport {

    private final int fieldsScanned;
    private final int versionsFound;
    private final int versionsSynced;
    private final int versionsAlreadyPresent;
    private final List<String> errors;

    public SyncReport(int fieldsScanned, int versionsFound,
                      int versionsSynced, int versionsAlreadyPresent,
                      List<String> errors) {
        this.fieldsScanned        = fieldsScanned;
        this.versionsFound        = versionsFound;
        this.versionsSynced       = versionsSynced;
        this.versionsAlreadyPresent = versionsAlreadyPresent;
        this.errors               = Collections.unmodifiableList(errors);
    }

    /** Number of distinct DEK fields found in the surviving SR. */
    public int fieldsScanned() { return fieldsScanned; }

    /** Total number of DEK versions found across all fields. */
    public int versionsFound() { return versionsFound; }

    /** DEK versions that were re-wrapped and pushed to the recovering SR. */
    public int versionsSynced() { return versionsSynced; }

    /** DEK versions that were already present on the recovering SR (skipped). */
    public int versionsAlreadyPresent() { return versionsAlreadyPresent; }

    /** Errors encountered during sync (non-fatal — other versions continue). */
    public List<String> errors() { return errors; }

    /** True if sync completed without any errors. */
    public boolean isComplete() { return errors.isEmpty(); }

    @Override
    public String toString() {
        return String.format(
                "SyncReport{fields=%d, versionsFound=%d, synced=%d, alreadyPresent=%d, errors=%d}",
                fieldsScanned, versionsFound, versionsSynced, versionsAlreadyPresent, errors.size());
    }
}
