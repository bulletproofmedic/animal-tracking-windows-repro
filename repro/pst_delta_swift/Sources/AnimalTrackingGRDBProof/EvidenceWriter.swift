import PersistenceProofDomain
import CryptoKit
import Foundation

public struct EvidenceRecord: Codable, Sendable {
    public let caseID: ProofCaseID?
    public let event: String
    public let observedAt: Date
    public let fields: [String: String]

    public init(caseID: ProofCaseID?, event: String, observedAt: Date, fields: [String: String]) {
        self.caseID = caseID
        self.event = event
        self.observedAt = observedAt
        self.fields = fields
    }
}

public struct EvidenceManifestEntry: Codable, Equatable, Sendable {
    public let path: String
    public let bytes: Int
    public let sha256: String
    public let caseID: ProofCaseID?
    public let classification: String
}

public struct EvidenceWriter: Sendable {
    public let paths: ProofPaths

    public init(paths: ProofPaths) {
        self.paths = paths
    }

    @discardableResult
    public func append(_ record: EvidenceRecord, filename: String) throws -> String {
        try paths.createDirectories()
        let url = paths.rawEvidence.appending(path: filename)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(record) + Data([0x0A])
        if FileManager.default.fileExists(atPath: url.path) {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } else {
            try data.write(to: url, options: .atomic)
        }
        return try Self.sha256(url: url)
    }

    @discardableResult
    public func writeCaseResult(_ result: ProofCaseExecutionResult) throws -> EvidenceManifestEntry {
        try paths.createDirectories()
        let filename = "\(result.caseID.rawValue)_result.json"
        let url = paths.derivedEvidence.appending(path: filename)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(result) + Data([0x0A])
        try data.write(to: url, options: .atomic)
        return EvidenceManifestEntry(
            path: "evidence/derived/\(filename)",
            bytes: data.count,
            sha256: Self.sha256(data: data),
            caseID: result.caseID,
            classification: "PROJECT_INTERNAL"
        )
    }

    @discardableResult
    public func writeQuarantine(
        caseID: ProofCaseID,
        packageID: UUID,
        payload: Data,
        expectedDigest: String,
        observedDigest: String,
        byteOffsetZeroBased: Int
    ) throws -> EvidenceManifestEntry {
        try paths.createDirectories()
        let filename = "\(caseID.rawValue)_\(packageID.uuidString.lowercased())_mismatch.bin"
        let url = paths.quarantine.appending(path: filename)
        try payload.write(to: url, options: .atomic)
        let metadata = EvidenceRecord(
            caseID: caseID,
            event: "PERMANENT_INTEGRITY_QUARANTINE",
            observedAt: Date(),
            fields: [
                "package_id": packageID.uuidString.lowercased(),
                "expected_sha256": expectedDigest,
                "observed_sha256": observedDigest,
                "mismatch_byte_offset_zero_based": String(byteOffsetZeroBased),
                "payload_file": filename
            ]
        )
        _ = try append(metadata, filename: "\(caseID.rawValue)_quarantine.jsonl")
        return EvidenceManifestEntry(
            path: "evidence/quarantine/\(filename)",
            bytes: payload.count,
            sha256: Self.sha256(data: payload),
            caseID: caseID,
            classification: "PROJECT_INTERNAL"
        )
    }

    @discardableResult
    public func writeManifest(entries: [EvidenceManifestEntry], filename: String = "PERSISTENCE_CASE_EVIDENCE_MANIFEST_2.json") throws -> EvidenceManifestEntry {
        try paths.createDirectories()
        let sorted = entries.sorted { lhs, rhs in
            if lhs.caseID?.rawValue == rhs.caseID?.rawValue { return lhs.path < rhs.path }
            return (lhs.caseID?.rawValue ?? "") < (rhs.caseID?.rawValue ?? "")
        }
        let url = paths.derivedEvidence.appending(path: filename)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(sorted) + Data([0x0A])
        try data.write(to: url, options: .atomic)
        return EvidenceManifestEntry(
            path: "evidence/derived/\(filename)",
            bytes: data.count,
            sha256: Self.sha256(data: data),
            caseID: nil,
            classification: "PROJECT_INTERNAL"
        )
    }

    public static func sha256(url: URL) throws -> String {
        sha256(data: try Data(contentsOf: url))
    }

    public static func sha256(data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
