// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "PSTDeltaSwiftReproducer",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "AnimalTrackingGRDBProof", targets: ["AnimalTrackingGRDBProof"]),
        .executable(name: "PersistenceProofRunner", targets: ["PersistenceProofRunner"])
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", exact: "7.10.0")
    ],
    targets: [
        .target(
            name: "AnimalTrackingGRDBProof",
            dependencies: [.product(name: "GRDB", package: "GRDB.swift")],
            path: "Sources/AnimalTrackingGRDBProof",
            exclude: [
                "EvidenceWriter.swift", "FailureInjection.swift", "GRDBProofStore.swift",
                "PSTDeltaIndependentOracle.swift", "ProofHarness.swift", "ProofMigrations.swift"
            ],
            sources: ["PSTCore.swift", "PSTOracleStore.swift"]
        ),
        .executableTarget(
            name: "PersistenceProofRunner",
            dependencies: ["AnimalTrackingGRDBProof"],
            path: "Sources/PersistenceProofRunner",
            sources: ["main.swift"]
        ),
        .testTarget(
            name: "AnimalTrackingGRDBProofTests",
            dependencies: ["AnimalTrackingGRDBProof"],
            path: "Tests/AnimalTrackingGRDBProofTests",
            exclude: ["PreparationTests.swift"],
            sources: ["PSTDeltaTests.swift"]
        )
    ],
    swiftLanguageModes: [.v6]
)
