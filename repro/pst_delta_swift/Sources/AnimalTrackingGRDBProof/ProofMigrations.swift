import Foundation
import GRDB

public enum ProofMigrationID {
    public static let core = "proof_0001_core"
    public static let synchronization = "proof_0002_sync_ledgers"
    public static let observation = "proof_0003_observation_state"
    public static let ordered = [core, synchronization, observation]
}

public enum ProofMigrator {
    public static func make() -> DatabaseMigrator {
        var migrator = DatabaseMigrator()
        migrator.registerMigration(ProofMigrationID.core) { db in
            try db.create(table: "property") { table in
                table.column("id", .text).primaryKey()
                table.column("status", .text).notNull()
                table.column("name", .text).notNull()
            }
            try db.execute(sql: "CREATE UNIQUE INDEX property_one_active ON property(status) WHERE status = 'ACTIVE'")

            try db.create(table: "spatial_position") { table in
                table.column("id", .text).primaryKey()
                table.column("property_id", .text).notNull().references("property", onDelete: .restrict)
                table.column("latitude_e7", .integer)
                table.column("longitude_e7", .integer)
                table.column("accuracy_mm", .integer)
                table.check(sql: "(latitude_e7 IS NULL AND longitude_e7 IS NULL) OR (latitude_e7 IS NOT NULL AND longitude_e7 IS NOT NULL)")
                table.check(sql: "latitude_e7 IS NULL OR latitude_e7 BETWEEN -900000000 AND 900000000")
                table.check(sql: "longitude_e7 IS NULL OR longitude_e7 BETWEEN -1800000000 AND 1800000000")
            }

            try db.create(table: "camera_site") { table in
                table.column("id", .text).primaryKey()
                table.column("property_id", .text).notNull().references("property", onDelete: .restrict)
                table.column("position_id", .text).references("spatial_position", onDelete: .restrict)
                table.column("label", .text).notNull()
            }

            try db.create(table: "camera_device") { table in
                table.column("id", .text).primaryKey()
                table.column("property_id", .text).notNull().references("property", onDelete: .restrict)
                table.column("serial", .text)
                table.column("label", .text).notNull()
            }
            try db.execute(sql: "CREATE UNIQUE INDEX camera_device_serial_unique ON camera_device(property_id, serial) WHERE serial IS NOT NULL")

            try db.create(table: "deployment") { table in
                table.column("id", .text).primaryKey()
                table.column("property_id", .text).notNull().references("property", onDelete: .restrict)
                table.column("site_id", .text).notNull().references("camera_site", onDelete: .restrict)
                table.column("device_id", .text).notNull().references("camera_device", onDelete: .restrict)
                table.column("start_instant", .double).notNull()
                table.column("end_instant", .double)
                table.check(sql: "end_instant IS NULL OR start_instant <= end_instant")
            }

            try db.create(table: "change_set") { table in
                table.column("id", .text).primaryKey()
                table.column("property_id", .text).notNull().references("property", onDelete: .restrict)
                table.column("changed_at", .double).notNull()
            }
            try db.create(table: "change_entry") { table in
                table.column("id", .text).primaryKey()
                table.column("change_set_id", .text).notNull().references("change_set", onDelete: .restrict)
                table.column("entity_type", .text).notNull()
                table.column("entity_id", .text).notNull()
            }
            try db.create(table: "source_state") { table in
                table.column("id", .text).primaryKey()
                table.column("property_id", .text).notNull().references("property", onDelete: .restrict)
                table.column("revision", .integer).notNull()
                table.column("is_current", .boolean).notNull()
            }
            try db.execute(sql: "CREATE UNIQUE INDEX source_state_one_current ON source_state(property_id) WHERE is_current = 1")
        }

        migrator.registerMigration(ProofMigrationID.synchronization) { db in
            try db.create(table: "sync_package_ledger") { table in
                table.column("package_id", .text).primaryKey()
                table.column("digest", .blob).notNull()
                table.column("origin_device_id", .text).notNull()
                table.column("origin_sequence", .integer).notNull()
                table.column("disposition", .text).notNull()
            }
            try db.create(table: "sync_item_ledger") { table in
                table.column("item_id", .text).primaryKey()
                table.column("package_id", .text).notNull().references("sync_package_ledger", onDelete: .restrict)
                table.column("disposition", .text).notNull()
                table.column("dependency_id", .text)
            }
            try db.create(table: "sync_conflict") { table in
                table.column("id", .text).primaryKey()
                table.column("item_id", .text).notNull().references("sync_item_ledger", onDelete: .restrict)
                table.column("state", .text).notNull()
                table.column("resolution_change_set_id", .text).references("change_set", onDelete: .restrict)
            }
            try db.create(table: "device_registry") { table in
                table.column("device_id", .text).primaryKey()
                table.column("lifecycle_state", .text).notNull()
                table.column("last_sequence", .integer).notNull().defaults(to: 0)
            }
            try db.create(table: "acknowledgement_ledger") { table in
                table.column("id", .text).primaryKey()
                table.column("package_id", .text).notNull().references("sync_package_ledger", onDelete: .restrict)
                table.column("device_id", .text).notNull().references("device_registry", onDelete: .restrict)
                table.column("acknowledged_at", .double).notNull()
            }
            try db.create(table: "analysis_run") { table in
                table.column("id", .text).primaryKey()
                table.column("source_state_id", .text).notNull().references("source_state", onDelete: .restrict)
                table.column("input_hash", .text).notNull()
                table.column("result_hash", .text).notNull()
                table.column("freshness", .text).notNull()
            }
        }

        migrator.registerMigration(ProofMigrationID.observation) { db in
            try db.create(table: "proof_runtime_state") { table in
                table.column("singleton", .integer).primaryKey(onConflict: .replace)
                table.column("semantic_state", .text).notNull()
                table.column("source_state_id", .text)
                table.column("completed", .integer).notNull().defaults(to: 0)
                table.column("total", .integer).notNull().defaults(to: 0)
                table.column("site_count", .integer).notNull().defaults(to: 0)
                table.column("device_count", .integer).notNull().defaults(to: 0)
                table.column("deployment_count", .integer).notNull().defaults(to: 0)
                table.column("pending_package_count", .integer).notNull().defaults(to: 0)
                table.column("conflict_count", .integer).notNull().defaults(to: 0)
                table.column("stale_run_count", .integer).notNull().defaults(to: 0)
                table.column("error_code", .text)
                table.check(sql: "singleton = 1")
            }
            try db.execute(sql: "INSERT INTO proof_runtime_state(singleton, semantic_state) VALUES (1, 'EMPTY')")
        }
        return migrator
    }
}
