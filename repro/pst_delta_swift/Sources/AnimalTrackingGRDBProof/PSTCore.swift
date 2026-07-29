import CryptoKit
import Foundation
import GRDB

public enum PSTFixture {
    public static let id = "PST-DELTA-001"
    public static let version = "1.1.0"
    public static let historicalVersion = "1.0.1"
    public static let originNamespace = UUID(uuidString: "ce7ecdb6-7a66-5cae-9f88-4f62a94be522")!
    public static let packageNamespace = UUID(uuidString: "09519fe7-361e-5b41-9514-80de0d814f47")!
    public static let itemNamespace = UUID(uuidString: "1b4457dc-6f0b-58fa-9a04-937beb21e032")!
    public static let scheduleProjectionSHA256 = "00d724bfcaad1ac6f31ba4f51d1a84e939c7031415d25a921a391b3934598a34"
    public static let fullSemanticFingerprint = "b332900252541a4d8527c16ab108dbec49e63a5d0b6355c733659a02786f2ff7"
    public static let mismatchSequences = [10, 40, 70, 100, 130, 160, 190, 220, 240, 250]
}

public enum PSTError: Error, Equatable {
    case unsupportedVersion(String)
    case invalidPopulation(String)
    case collision(Int)
    case unfilled(Int)
    case digestMismatch
}

public enum PSTCaseID: String, CaseIterable, Codable, Sendable {
    case t001 = "PST-T001", t002 = "PST-T002", t003 = "PST-T003", t004 = "PST-T004"
    case t005 = "PST-T005", t006 = "PST-T006", t007 = "PST-T007", t008 = "PST-T008"
    case t009 = "PST-T009", t010 = "PST-T010", t011 = "PST-T011", t012 = "PST-T012"
    case t013 = "PST-T013", t014 = "PST-T014", t015 = "PST-T015", t016 = "PST-T016"
    case t017 = "PST-T017", t018 = "PST-T018", t019 = "PST-T019", t020 = "PST-T020"
    case t021 = "PST-T021", t022 = "PST-T022", t023 = "PST-T023", t024 = "PST-T024"
    case t025 = "PST-T025", t026 = "PST-T026", t027 = "PST-T027", t028 = "PST-T028"
    case t029 = "PST-T029", t030 = "PST-T030", t031 = "PST-T031", t032 = "PST-T032"
    case t033 = "PST-T033", t034 = "PST-T034", t035 = "PST-T035"
}

public struct PSTCaseContract: Codable, Equatable, Sendable {
    public let id: PSTCaseID
    public let procedure: String
    public let setup: String
    public let action: String
    public let expectedState: String
    public let failureBehavior: String
    public let evidence: [String]
    public let blocked: Bool
}

public enum PSTCaseCatalog {
    private static let capabilities = [
        "Stable identity", "Foreign keys", "Protected history", "One active property", "One current source state",
        "Conditional serial uniqueness", "Paired coordinates", "Coordinate bounds", "Temporal bounds", "Exact decimal storage",
        "Compound uniqueness", "Index plan", "Atomic camera move", "Atomic rollback", "Package import transaction",
        "Package replay", "ID/digest mismatch", "Missing dependency", "Stale-base conflict", "Conflict resolution",
        "Savepoint group", "Migration order", "Interrupted migration", "Unsupported schema", "Integrity check",
        "Corruption response", "Backup/restore", "WAL/checkpoint", "File protection", "Representative bootstrap",
        "Representative delta volume", "SwiftUI isolation", "Background termination", "Device ledger", "Analysis stale propagation"
    ]

    public static let contracts: [PSTCaseContract] = PSTCaseID.allCases.enumerated().map { index, id in
        let blocked = [.t029, .t030, .t031, .t032].contains(id)
        return PSTCaseContract(
            id: id,
            procedure: "execute_\(id.rawValue.lowercased().replacingOccurrences(of: "-", with: "_"))",
            setup: "Create isolated proof store and deterministic fixtures for \(capabilities[index]).",
            action: "Execute the \(capabilities[index]) procedure through public GRDB APIs.",
            expectedState: blocked ? "BLOCKED until target-Apple prerequisite is physically observed." : "Deterministic invariant and evidence assertion pass.",
            failureBehavior: "Return FAIL with a stable code; do not silently continue or claim execution.",
            evidence: ["\(id.rawValue)_result.json", "PERSISTENCE_CASE_EVIDENCE_MANIFEST_2.json"],
            blocked: blocked
        )
    }
}

public struct PSTOrigin: Hashable, Codable, Sendable {
    public let ordinal: Int
    public let uuid: UUID
}

public struct PSTPackageKey: Hashable, Comparable, Codable, Sendable {
    public let origin: Int
    public let sequence: Int

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.origin == rhs.origin ? lhs.sequence < rhs.sequence : lhs.origin < rhs.origin
    }
}

public enum PSTAttemptKind: String, Codable, Sendable {
    case first = "FIRST"
    case replay = "REPLAY"
    case mismatch = "DIGEST_MISMATCH"
}

public struct PSTAttempt: Codable, Equatable, Sendable {
    public let index: Int
    public let kind: PSTAttemptKind
    public let key: PSTPackageKey
    public let originUUID: UUID
    public let packageID: UUID
    public let firstIndex: Int
    public let replayIndex: Int?
    public let mismatchIndex: Int?
}

public struct PSTPopulation: Codable, Equatable, Sendable {
    public let packages: Int
    public let items: Int
    public let dependencyItems: Int
    public let dependencyPackages: Int
    public let conflicts: Int
    public let mediaDescriptors: Int
    public let mediaIdentities: Int
    public let replays: Int
    public let mismatches: Int
    public let attempts: Int
}

private struct PSTItem: Codable {
    let fixtureID: String
    let fixtureVersion: String
    let itemID: UUID
    let itemOrdinal: Int
    let dependencyItemID: UUID?
    let staleBaseRevision: Int?
    let currentRevision: Int?
    let mutationAnchor: String?
    let terminalOutcome: String

    enum CodingKeys: String, CodingKey {
        case fixtureID = "fixture_id"
        case fixtureVersion = "fixture_version"
        case itemID = "item_id"
        case itemOrdinal = "item_ordinal"
        case dependencyItemID = "dependency_item_id"
        case staleBaseRevision = "stale_base_revision"
        case currentRevision = "current_revision"
        case mutationAnchor = "mutation_anchor"
        case terminalOutcome = "terminal_outcome"
    }
}

private struct PSTMedia: Codable {
    let itemID: UUID
    let mediaSHA256: String

    enum CodingKeys: String, CodingKey {
        case itemID = "item_id"
        case mediaSHA256 = "media_sha256"
    }
}

private struct PSTPackagePayload: Codable {
    let fixtureID: String
    let fixtureVersion: String
    let logicalOriginOrdinal: Int
    let originUUID: UUID
    let originSequence: Int
    let packageID: UUID
    let uniquePackageFirstRank: Int
    let items: [PSTItem]
    let mediaDescriptors: [PSTMedia]

    enum CodingKeys: String, CodingKey {
        case fixtureID = "fixture_id"
        case fixtureVersion = "fixture_version"
        case logicalOriginOrdinal = "logical_origin_ordinal"
        case originUUID = "origin_uuid"
        case originSequence = "origin_sequence"
        case packageID = "package_id"
        case uniquePackageFirstRank = "unique_package_first_rank"
        case items
        case mediaDescriptors = "media_descriptors"
    }
}

public struct PSTMaterializedPackage: Equatable, Sendable {
    public let rank: Int
    public let key: PSTPackageKey
    public let packageID: UUID
    public let bytes: Data
    public let sha256: String
    public let dependencyCount: Int
    public let conflictCount: Int
    public let mediaDescriptorCount: Int
}

public struct PSTMismatch: Equatable, Sendable {
    public let packageID: UUID
    public let original: Data
    public let mutated: Data
    public let originalSHA256: String
    public let mutatedSHA256: String
    public let byteOffsetZeroBased: Int
}

public enum PSTCanonical {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    public static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public enum PSTUUIDv5 {
    public static func make(namespace: UUID, name: String) -> UUID {
        let digest = Insecure.SHA1.hash(data: Data(namespace.bytes + Array(name.utf8)))
        var bytes = Array(digest.prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x50
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(bytes: bytes)
    }
}

public struct PSTDeltaGenerator: Sendable {
    public init() {}

    public func validate(version: String) throws {
        guard version == PSTFixture.version else { throw PSTError.unsupportedVersion(version) }
    }

    public func origins() -> [PSTOrigin] {
        (1...4).map { PSTOrigin(ordinal: $0, uuid: PSTUUIDv5.make(namespace: PSTFixture.originNamespace, name: "origin/\($0)")) }
    }

    public func origin(_ ordinal: Int) -> PSTOrigin {
        origins()[ordinal - 1]
    }

    public func packageID(_ key: PSTPackageKey) -> UUID {
        PSTUUIDv5.make(namespace: PSTFixture.packageNamespace, name: "\(origin(key.origin).uuid.uuidString.lowercased())/\(key.sequence)")
    }

    public func uniqueOrder() throws -> [PSTPackageKey] {
        let all = (1...4).flatMap { origin in (1...250).map { PSTPackageKey(origin: origin, sequence: $0) } }
        let replay = Set(all.filter { $0.sequence.isMultiple(of: 10) })
        let mismatch = Set(PSTFixture.mismatchSequences.map { PSTPackageKey(origin: 4, sequence: $0) })
        let nonMismatchReplay = replay.subtracting(mismatch).sorted()
        let nonReplay = Set(all).subtracting(replay).sorted()
        let spacers = Array(nonReplay.prefix(10))
        let spacerSet = Set(spacers)
        var result = nonMismatchReplay
        for (mismatchKey, spacer) in zip(mismatch.sorted(), spacers) {
            result.append(mismatchKey)
            result.append(spacer)
        }
        result.append(contentsOf: nonReplay.filter { !spacerSet.contains($0) })
        guard result.count == 1_000, Set(result).count == 1_000 else { throw PSTError.invalidPopulation("unique-order") }
        return result
    }

    public func attempts() throws -> [PSTAttempt] {
        let order = try uniqueOrder()
        let replayTargets = Set(order.filter { $0.sequence.isMultiple(of: 10) })
        let mismatchTargets = Set(PSTFixture.mismatchSequences.map { PSTPackageKey(origin: 4, sequence: $0) })
        var slots: [(PSTAttemptKind, PSTPackageKey)?] = Array(repeating: nil, count: 1_111)
        var lastFirst = 0
        for key in order {
            var selected: Int?
            for index in (lastFirst + 1)...1_110 {
                guard slots[index] == nil else { continue }
                if replayTargets.contains(key) {
                    guard index + 37 <= 1_110, slots[index + 37] == nil else { continue }
                    if mismatchTargets.contains(key) {
                        guard index + 38 <= 1_110, slots[index + 38] == nil else { continue }
                    }
                }
                selected = index
                break
            }
            guard let first = selected else { throw PSTError.unfilled(lastFirst + 1) }
            slots[first] = (.first, key)
            if replayTargets.contains(key) {
                slots[first + 37] = (.replay, key)
                if mismatchTargets.contains(key) { slots[first + 38] = (.mismatch, key) }
            }
            lastFirst = first
        }
        guard slots[1...].allSatisfy({ $0 != nil }) else { throw PSTError.invalidPopulation("final-slots") }
        var first: [PSTPackageKey: Int] = [:]
        var replay: [PSTPackageKey: Int] = [:]
        var mismatch: [PSTPackageKey: Int] = [:]
        for index in 1...1_110 {
            let slot = slots[index]!
            switch slot.0 {
            case .first: first[slot.1] = index
            case .replay: replay[slot.1] = index
            case .mismatch: mismatch[slot.1] = index
            }
        }
        return try (1...1_110).map { index in
            let slot = slots[index]!
            guard let firstIndex = first[slot.1] else { throw PSTError.unfilled(index) }
            return PSTAttempt(
                index: index,
                kind: slot.0,
                key: slot.1,
                originUUID: origin(slot.1.origin).uuid,
                packageID: packageID(slot.1),
                firstIndex: firstIndex,
                replayIndex: replay[slot.1],
                mismatchIndex: mismatch[slot.1]
            )
        }
    }

    public func scheduleProjection() throws -> Data {
        var csv = "attempt_index,delivery_kind,logical_origin_ordinal,origin_uuid,origin_sequence,package_id,first_attempt_index,replay_attempt_index,mismatch_attempt_index\n"
        for attempt in try attempts() {
            csv += "\(attempt.index),\(attempt.kind.rawValue),\(attempt.key.origin),\(attempt.originUUID.uuidString.lowercased()),\(attempt.key.sequence),\(attempt.packageID.uuidString.lowercased()),\(attempt.firstIndex),\(attempt.replayIndex.map(String.init) ?? ""),\(attempt.mismatchIndex.map(String.init) ?? "")\n"
        }
        return Data(csv.utf8)
    }

    public func population() -> PSTPopulation {
        PSTPopulation(packages: 1_000, items: 100_000, dependencyItems: 500, dependencyPackages: 50, conflicts: 25, mediaDescriptors: 10_000, mediaIdentities: 5_000, replays: 100, mismatches: 10, attempts: 1_110)
    }

    public func materialize(rank: Int) throws -> PSTMaterializedPackage {
        let order = try uniqueOrder()
        guard (1...order.count).contains(rank) else { throw PSTError.invalidPopulation("rank") }
        let key = order[rank - 1]
        let packageID = packageID(key)
        let dependencyRanks = Set(Array(201...240) + Array(281...290))
        let conflictRanks = Set(401...425)
        var items: [PSTItem] = []
        for ordinal in 1...100 {
            let itemID = PSTUUIDv5.make(namespace: PSTFixture.itemNamespace, name: "\(packageID.uuidString.lowercased())/\(String(format: "%03d", ordinal))")
            var dependency: UUID?
            if dependencyRanks.contains(rank), ordinal <= 10 {
                let prerequisiteID = self.packageID(order[rank + 39])
                dependency = PSTUUIDv5.make(namespace: PSTFixture.itemNamespace, name: "\(prerequisiteID.uuidString.lowercased())/\(String(format: "%03d", ordinal))")
            }
            let conflict = conflictRanks.contains(rank) && ordinal == 25
            items.append(PSTItem(
                fixtureID: PSTFixture.id,
                fixtureVersion: PSTFixture.version,
                itemID: itemID,
                itemOrdinal: ordinal,
                dependencyItemID: dependency,
                staleBaseRevision: conflict ? 1 : nil,
                currentRevision: conflict ? 2 : nil,
                mutationAnchor: ordinal == 100 ? "A" : nil,
                terminalOutcome: dependency != nil ? "WAITING_FOR_DEPENDENCY" : (conflict ? "STALE_BASE_CONFLICT" : "APPLIED")
            ))
        }
        let media: [PSTMedia] = (1...10).map { ordinal in
            let itemID = items[ordinal - 1].itemID
            let descriptorOrdinal = (rank - 1) * 10 + ordinal
            let identity = (descriptorOrdinal + 1) / 2
            return PSTMedia(itemID: itemID, mediaSHA256: PSTCanonical.sha256(Data("media/\(String(format: "%05d", identity))".utf8)))
        }
        let payload = PSTPackagePayload(
            fixtureID: PSTFixture.id,
            fixtureVersion: PSTFixture.version,
            logicalOriginOrdinal: key.origin,
            originUUID: origin(key.origin).uuid,
            originSequence: key.sequence,
            packageID: packageID,
            uniquePackageFirstRank: rank,
            items: items,
            mediaDescriptors: media
        )
        let bytes = try PSTCanonical.encode(payload)
        return PSTMaterializedPackage(
            rank: rank,
            key: key,
            packageID: packageID,
            bytes: bytes,
            sha256: PSTCanonical.sha256(bytes),
            dependencyCount: items.filter { $0.dependencyItemID != nil }.count,
            conflictCount: items.filter { $0.staleBaseRevision != nil }.count,
            mediaDescriptorCount: media.count
        )
    }

    public func mismatch(rank: Int) throws -> PSTMismatch {
        let package = try materialize(rank: rank)
        guard package.key.origin == 4, PSTFixture.mismatchSequences.contains(package.key.sequence) else { throw PSTError.invalidPopulation("mismatch-target") }
        let needle = Data("\"mutation_anchor\":\"A\"".utf8)
        guard let range = package.bytes.range(of: needle) else { throw PSTError.invalidPopulation("mutation-anchor") }
        let offset = range.upperBound - 2
        var mutated = package.bytes
        mutated[offset] = 0x42
        guard zip(package.bytes, mutated).filter({ $0 != $1 }).count == 1, package.bytes.count == mutated.count else { throw PSTError.digestMismatch }
        return PSTMismatch(
            packageID: package.packageID,
            original: package.bytes,
            mutated: mutated,
            originalSHA256: package.sha256,
            mutatedSHA256: PSTCanonical.sha256(mutated),
            byteOffsetZeroBased: offset
        )
    }

    public func validateFrozen() throws {
        try validate(version: PSTFixture.version)
        guard origins().map({ $0.uuid.uuidString.lowercased() }) == [
            "b45b8925-694b-5cc0-a8cb-0239d11d85ac",
            "e9d5ccf0-bdde-5aa4-a963-9cbef4a64f3c",
            "42ce1f04-2764-57e8-bf8f-58f56834c533",
            "8252d373-00a5-5342-92a1-8f22613f7ccb"
        ] else { throw PSTError.invalidPopulation("origins") }
        let schedule = try scheduleProjection()
        guard PSTCanonical.sha256(schedule) == PSTFixture.scheduleProjectionSHA256 else { throw PSTError.digestMismatch }
    }
}
