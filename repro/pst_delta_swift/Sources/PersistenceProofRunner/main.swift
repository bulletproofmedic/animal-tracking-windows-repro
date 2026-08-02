import AnimalTrackingGRDBProof
import Foundation

let arguments = Set(CommandLine.arguments.dropFirst())
if arguments.contains("--list") {
    for contract in PSTCaseCatalog.contracts {
        print("\(contract.id.rawValue)\t\(contract.procedure)\t\(contract.blocked ? "BLOCKED" : "EXECUTABLE")")
    }
    exit(EXIT_SUCCESS)
}

let generator = PSTDeltaGenerator()
do {
    try generator.validateFrozen()
    let oracle = try PSTIndependentOracle().scheduleProjection()
    guard oracle == (try generator.scheduleProjection()) else { throw PSTError.digestMismatch }
    print("Animal Tracking sanitized PST-DELTA consumer reproducer")
    print("Fixture: \(PSTFixture.id) \(PSTFixture.version)")
    print("Schedule projection SHA-256: \(PSTCanonical.sha256(oracle))")
    print("Full semantic fingerprint authority: \(PSTFixture.fullSemanticFingerprint)")
    print("Executable procedure contracts: \(PSTCaseCatalog.contracts.count)")
    print("Target-Apple execution: NOT_RUN")
} catch {
    fputs("Reproducer failed: \(error)\n", stderr)
    exit(EXIT_FAILURE)
}
