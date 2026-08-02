import CryptoKit
import Foundation

public struct PSTDeltaIndependentOracle: Sendable {
    public init() {}

    private struct Key: Hashable, Comparable, Sendable {
        let origin: Int
        let sequence: Int

        static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.origin == rhs.origin ? lhs.sequence < rhs.sequence : lhs.origin < rhs.origin
        }
    }

    private enum Kind: String, Sendable {
        case first = "FIRST"
        case replay = "REPLAY"
        case mismatch = "DIGEST_MISMATCH"
    }

    private func originUUID(_ ordinal: Int) -> UUID {
        DeterministicUUIDv5.make(namespace: FixtureIdentity.originNamespace, name: "origin/\(ordinal)")
    }

    private func packageUUID(_ key: Key) -> UUID {
        DeterministicUUIDv5.make(
            namespace: FixtureIdentity.packageNamespace,
            name: "\(originUUID(key.origin).uuidString.lowercased())/\(key.sequence)"
        )
    }

    private func uniqueOrder() throws -> [Key] {
        let all = (1...4).flatMap { origin in (1...250).map { Key(origin: origin, sequence: $0) } }
        let replay = Set(all.filter { $0.sequence % 10 == 0 })
        let mismatch = Set(DeltaFixtureGenerator.mismatchTargetSequences.map { Key(origin: 4, sequence: $0) })
        let nonMismatchReplay = replay.subtracting(mismatch).sorted()
        let nonReplay = Set(all).subtracting(replay).sorted()
        let spacers = Array(nonReplay.prefix(10))
        let remaining = nonReplay.filter { !Set(spacers).contains($0) }
        var result = nonMismatchReplay
        for index in mismatch.sorted().indices {
            result.append(mismatch.sorted()[index])
            result.append(spacers[index])
        }
        result.append(contentsOf: remaining)
        guard result.count == 1_000, Set(result).count == 1_000 else {
            throw FixtureValidationError.nonUniquePackageOrder
        }
        return result
    }

    public func scheduleProjectionData() throws -> Data {
        let order = try uniqueOrder()
        let replayTargets = Set(order.filter { $0.sequence % 10 == 0 })
        let mismatchTargets = Set(DeltaFixtureGenerator.mismatchTargetSequences.map { Key(origin: 4, sequence: $0) })
        var due: [Int: (Kind, Key)] = [:]
        var events: [(Int, Kind, Key)] = []
        var firstCursor = 0
        var attemptIndex = 1

        while firstCursor < order.count || !due.isEmpty {
            if let event = due.removeValue(forKey: attemptIndex) {
                events.append((attemptIndex, event.0, event.1))
                if event.0 == .replay, mismatchTargets.contains(event.1) {
                    guard due[attemptIndex + 1] == nil else {
                        throw FixtureValidationError.duplicateFinalAttemptIndex(attemptIndex + 1)
                    }
                    due[attemptIndex + 1] = (.mismatch, event.1)
                }
            } else {
                guard firstCursor < order.count else {
                    throw FixtureValidationError.unfilledFinalAttemptIndex(attemptIndex)
                }
                let key = order[firstCursor]
                firstCursor += 1
                events.append((attemptIndex, .first, key))
                if replayTargets.contains(key) {
                    guard due[attemptIndex + 37] == nil else {
                        throw FixtureValidationError.duplicateFinalAttemptIndex(attemptIndex + 37)
                    }
                    due[attemptIndex + 37] = (.replay, key)
                }
            }
            attemptIndex += 1
        }

        guard events.count == 1_110 else {
            throw FixtureValidationError.incompletePopulation("independent-schedule")
        }
        var first: [Key: Int] = [:]
        var replay: [Key: Int] = [:]
        var mismatch: [Key: Int] = [:]
        for (index, kind, key) in events {
            switch kind {
            case .first: first[key] = index
            case .replay: replay[key] = index
            case .mismatch: mismatch[key] = index
            }
        }

        var output = "attempt_index,delivery_kind,logical_origin_ordinal,origin_uuid,origin_sequence,package_id,first_attempt_index,replay_attempt_index,mismatch_attempt_index\n"
        output.reserveCapacity(107_061)
        for (index, kind, key) in events {
            guard let firstIndex = first[key] else { throw FixtureValidationError.unfilledFinalAttemptIndex(index) }
            let replayIndex = replay[key].map(String.init) ?? ""
            let mismatchIndex = mismatch[key].map(String.init) ?? ""
            output += "\(index),\(kind.rawValue),\(key.origin),\(originUUID(key.origin).uuidString.lowercased()),\(key.sequence),\(packageUUID(key).uuidString.lowercased()),\(firstIndex),\(replayIndex),\(mismatchIndex)\n"
        }
        return Data(output.utf8)
    }

    public func validate(consumer: DeltaFixtureGenerator = DeltaFixtureGenerator()) throws {
        let oracleBytes = try scheduleProjectionData()
        let consumerBytes = try consumer.scheduleProjectionData()
        guard oracleBytes == consumerBytes else {
            throw FixtureValidationError.staleSemanticFingerprint(CanonicalJSON.sha256(consumerBytes))
        }
        guard CanonicalJSON.sha256(oracleBytes) == FixtureIdentity.scheduleProjectionSHA256 else {
            throw FixtureValidationError.staleSemanticFingerprint(CanonicalJSON.sha256(oracleBytes))
        }
    }
}
