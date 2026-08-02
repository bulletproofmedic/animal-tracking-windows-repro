import CryptoKit
import Foundation
import GRDB

public struct PSTIndependentOracle: Sendable {
    public init() {}

    public func scheduleProjection() throws -> Data {
        let generator = PSTDeltaGenerator()
        let order = try generator.uniqueOrder()
        let replay = Set(order.filter { $0.sequence.isMultiple(of: 10) })
        let mismatch = Set(PSTFixture.mismatchSequences.map { PSTPackageKey(origin: 4, sequence: $0) })
        var due: [Int: (PSTAttemptKind, PSTPackageKey)] = [:]
        var events: [(Int, PSTAttemptKind, PSTPackageKey)] = []
        var cursor = 0
        var index = 1
        while cursor < order.count || !due.isEmpty {
            if let event = due.removeValue(forKey: index) {
                events.append((index, event.0, event.1))
                if event.0 == .replay, mismatch.contains(event.1) { due[index + 1] = (.mismatch, event.1) }
            } else {
                guard cursor < order.count else { throw PSTError.unfilled(index) }
                let key = order[cursor]
                cursor += 1
                events.append((index, .first, key))
                if replay.contains(key) { due[index + 37] = (.replay, key) }
            }
            index += 1
        }
        guard events.count == 1_110 else { throw PSTError.invalidPopulation("oracle-events") }
        var first: [PSTPackageKey: Int] = [:]
        var replayIndex: [PSTPackageKey: Int] = [:]
        var mismatchIndex: [PSTPackageKey: Int] = [:]
        for event in events {
            switch event.1 {
            case .first: first[event.2] = event.0
            case .replay: replayIndex[event.2] = event.0
            case .mismatch: mismatchIndex[event.2] = event.0
            }
        }
        var csv = "attempt_index,delivery_kind,logical_origin_ordinal,origin_uuid,origin_sequence,package_id,first_attempt_index,replay_attempt_index,mismatch_attempt_index\n"
        for event in events {
            let origin = generator.origin(event.2.origin).uuid
            csv += "\(event.0),\(event.1.rawValue),\(event.2.origin),\(origin.uuidString.lowercased()),\(event.2.sequence),\(generator.packageID(event.2).uuidString.lowercased()),\(first[event.2]!),\(replayIndex[event.2].map(String.init) ?? ""),\(mismatchIndex[event.2].map(String.init) ?? "")\n"
        }
        return Data(csv.utf8)
    }
}

public enum PSTImportDisposition: String, Codable, Sendable {
    case applied = "APPLIED"
    case replay = "IDEMPOTENT_REPLAY_NO_MUTATION"
    case quarantined = "PERMANENT_INTEGRITY_QUARANTINE"
}

public final class PSTProofStore: @unchecked Sendable {
    private let queue: DatabaseQueue

    public init(path: String) throws {
        var configuration = Configuration()
        configuration.foreignKeysEnabled = true
        self.queue = try DatabaseQueue(path: path, configuration: configuration)
        try queue.write { db in
            try db.create(table: "package_ledger", ifNotExists: true) { table in
                table.column("package_id", .text).primaryKey()
                table.column("digest", .text).notNull()
                table.column("disposition", .text).notNull()
            }
            try db.create(table: "item_ledger", ifNotExists: true) { table in
                table.column("item_id", .text).primaryKey()
                table.column("package_id", .text).notNull().references("package_ledger", onDelete: .restrict)
            }
        }
    }

    public func importPackage(_ package: PSTMaterializedPackage, suppliedBytes: Data? = nil) throws -> PSTImportDisposition {
        let bytes = suppliedBytes ?? package.bytes
        let digest = PSTCanonical.sha256(bytes)
        return try queue.write { db in
            if let existing: String = try String.fetchOne(db, sql: "SELECT digest FROM package_ledger WHERE package_id = ?", arguments: [package.packageID.uuidString.lowercased()]) {
                return existing == digest ? .replay : .quarantined
            }
            guard digest == package.sha256 else { return .quarantined }
            try db.execute(
                sql: "INSERT INTO package_ledger(package_id, digest, disposition) VALUES (?, ?, ?)",
                arguments: [package.packageID.uuidString.lowercased(), digest, PSTImportDisposition.applied.rawValue]
            )
            for ordinal in 1...100 {
                let itemID = PSTUUIDv5.make(namespace: PSTFixture.itemNamespace, name: "\(package.packageID.uuidString.lowercased())/\(String(format: "%03d", ordinal))")
                try db.execute(sql: "INSERT INTO item_ledger(item_id, package_id) VALUES (?, ?)", arguments: [itemID.uuidString.lowercased(), package.packageID.uuidString.lowercased()])
            }
            return .applied
        }
    }

    public func counts() throws -> (packages: Int, items: Int) {
        try queue.read { db in
            (
                try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM package_ledger") ?? 0,
                try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM item_ledger") ?? 0
            )
        }
    }
}

extension UUID {
    var bytes: [UInt8] { withUnsafeBytes(of: uuid) { Array($0) } }

    init(bytes: [UInt8]) {
        self.init(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}
