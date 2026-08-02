import AnimalTrackingGRDBProof
import Foundation
import Testing

@Test("Version 1.1.0 schedule matches frozen projection")
func scheduleProjection() throws {
    let generator = PSTDeltaGenerator()
    try generator.validateFrozen()
    let attempts = try generator.attempts()
    #expect(attempts.count == 1_110)
    #expect(attempts.filter { $0.kind == .first }.count == 1_000)
    #expect(attempts.filter { $0.kind == .replay }.count == 100)
    #expect(attempts.filter { $0.kind == .mismatch }.count == 10)
    for replay in attempts.filter({ $0.kind == .replay }) {
        #expect(replay.index == replay.firstIndex + 37)
    }
    for mismatch in attempts.filter({ $0.kind == .mismatch }) {
        #expect(mismatch.replayIndex != nil)
        #expect(mismatch.index == mismatch.replayIndex! + 1)
    }
}

@Test("Logical origin 4 owns all mismatch attempts")
func mismatchOrigin() throws {
    let generator = PSTDeltaGenerator()
    let mismatches = try generator.attempts().filter { $0.kind == .mismatch }
    #expect(mismatches.map(\.key.sequence) == PSTFixture.mismatchSequences)
    #expect(mismatches.allSatisfy { $0.key.origin == 4 })
    #expect(mismatches.allSatisfy { $0.originUUID.uuidString.lowercased() == "8252d373-00a5-5342-92a1-8f22613f7ccb" })
}

@Test("Independent event-deadline oracle is byte-identical")
func independentOracle() throws {
    let producer = try PSTDeltaGenerator().scheduleProjection()
    let oracle = try PSTIndependentOracle().scheduleProjection()
    #expect(producer == oracle)
    #expect(PSTCanonical.sha256(oracle) == PSTFixture.scheduleProjectionSHA256)
}

@Test("Complete semantic population is frozen")
func population() throws {
    #expect(PSTDeltaGenerator().population() == PSTPopulation(
        packages: 1_000,
        items: 100_000,
        dependencyItems: 500,
        dependencyPackages: 50,
        conflicts: 25,
        mediaDescriptors: 10_000,
        mediaIdentities: 5_000,
        replays: 100,
        mismatches: 10,
        attempts: 1_110
    ))
}

@Test("Materialization contains dependency, conflict, and media semantics")
func materialization() throws {
    let generator = PSTDeltaGenerator()
    let dependency = try generator.materialize(rank: 201)
    #expect(dependency.dependencyCount == 10)
    #expect(dependency.mediaDescriptorCount == 10)
    let conflict = try generator.materialize(rank: 401)
    #expect(conflict.conflictCount == 1)
    #expect(conflict.mediaDescriptorCount == 10)
}

@Test("Mismatch changes exactly one byte and digest")
func mismatchBytes() throws {
    let generator = PSTDeltaGenerator()
    let order = try generator.uniqueOrder()
    let rank = try #require(order.firstIndex(of: PSTPackageKey(origin: 4, sequence: 10))).advanced(by: 1)
    let mismatch = try generator.mismatch(rank: rank)
    #expect(mismatch.original.count == mismatch.mutated.count)
    #expect(zip(mismatch.original, mismatch.mutated).filter { $0 != $1 }.count == 1)
    #expect(mismatch.originalSHA256 != mismatch.mutatedSHA256)
}

@Test("Version 1.0.1 is visibly rejected")
func historicalVersionRejected() throws {
    #expect(throws: PSTError.unsupportedVersion(PSTFixture.historicalVersion)) {
        try PSTDeltaGenerator().validate(version: PSTFixture.historicalVersion)
    }
}

@Test("GRDB import is atomic, idempotent, and quarantines mismatch")
func importBehavior() throws {
    let url = FileManager.default.temporaryDirectory.appending(path: "pst-\(UUID().uuidString).sqlite")
    defer { try? FileManager.default.removeItem(at: url) }
    let generator = PSTDeltaGenerator()
    let package = try generator.materialize(rank: 1)
    let store = try PSTProofStore(path: url.path)
    #expect(try store.importPackage(package) == .applied)
    #expect(try store.importPackage(package) == .replay)
    var mutated = package.bytes
    mutated[mutated.startIndex] ^= 0x01
    #expect(try store.importPackage(package, suppliedBytes: mutated) == .quarantined)
    let counts = try store.counts()
    #expect(counts.packages == 1)
    #expect(counts.items == 100)
}

@Test("Exactly 35 executable case contracts are discoverable")
func caseContracts() throws {
    let contracts = PSTCaseCatalog.contracts
    #expect(contracts.count == 35)
    #expect(Set(contracts.map(\.id)) == Set(PSTCaseID.allCases))
    #expect(Set(contracts.map(\.procedure)).count == 35)
    #expect(contracts.allSatisfy { !$0.setup.isEmpty && !$0.action.isEmpty && !$0.expectedState.isEmpty && !$0.failureBehavior.isEmpty && !$0.evidence.isEmpty })
    #expect(contracts.filter(\.blocked).map(\.id) == [.t029, .t030, .t031, .t032])
}
