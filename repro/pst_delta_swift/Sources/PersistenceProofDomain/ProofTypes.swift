import Foundation

public enum ProofCaseID: String, CaseIterable, Codable, Sendable {
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

public enum ProofResultState: String, Codable, Sendable {
    case pass = "PASS"
    case fail = "FAIL"
    case blocked = "BLOCKED"
    case notRun = "NOT_RUN"
}

public enum ProofCasePrerequisite: String, Codable, CaseIterable, Sendable {
    case none = "NONE"
    case targetAppleCompile = "TARGET_APPLE_COMPILE"
    case physicalDevice = "PHYSICAL_DEVICE"
    case ownerOracle = "OWNER_ORACLE"
    case signingAndInstallIdentity = "SIGNING_AND_INSTALL_IDENTITY"
}

public struct ProofCaseRoute: Codable, Equatable, Sendable {
    public let id: ProofCaseID
    public let capability: String
    public let grdbPublicAPIs: [String]
    public let requiresPhysicalDevice: Bool
    public let requiresOwnerOracle: Bool

    public init(
        id: ProofCaseID,
        capability: String,
        grdbPublicAPIs: [String],
        requiresPhysicalDevice: Bool = false,
        requiresOwnerOracle: Bool = false
    ) {
        self.id = id
        self.capability = capability
        self.grdbPublicAPIs = grdbPublicAPIs
        self.requiresPhysicalDevice = requiresPhysicalDevice
        self.requiresOwnerOracle = requiresOwnerOracle
    }
}

public struct ProofCaseContract: Codable, Equatable, Sendable {
    public let route: ProofCaseRoute
    public let procedureSymbol: String
    public let setup: String
    public let action: String
    public let expectedState: String
    public let failureBehavior: String
    public let evidenceOutputs: [String]
    public let prerequisites: [ProofCasePrerequisite]

    public init(
        route: ProofCaseRoute,
        procedureSymbol: String,
        setup: String,
        action: String,
        expectedState: String,
        failureBehavior: String,
        evidenceOutputs: [String],
        prerequisites: [ProofCasePrerequisite] = [.none]
    ) {
        self.route = route
        self.procedureSymbol = procedureSymbol
        self.setup = setup
        self.action = action
        self.expectedState = expectedState
        self.failureBehavior = failureBehavior
        self.evidenceOutputs = evidenceOutputs
        self.prerequisites = prerequisites
    }
}

public struct ProofCasePreparation: Codable, Equatable, Sendable {
    public let route: ProofCaseRoute
    public let state: ProofResultState
    public let note: String
}

public struct ProofCaseExecutionResult: Codable, Equatable, Sendable {
    public let caseID: ProofCaseID
    public let procedureSymbol: String
    public let state: ProofResultState
    public let startedAt: Date
    public let finishedAt: Date
    public let assertions: [String: Bool]
    public let measurements: [String: String]
    public let evidenceFiles: [String]
    public let failureCode: String?
    public let note: String

    public init(
        caseID: ProofCaseID,
        procedureSymbol: String,
        state: ProofResultState,
        startedAt: Date,
        finishedAt: Date,
        assertions: [String: Bool],
        measurements: [String: String] = [:],
        evidenceFiles: [String] = [],
        failureCode: String? = nil,
        note: String
    ) {
        self.caseID = caseID
        self.procedureSymbol = procedureSymbol
        self.state = state
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.assertions = assertions
        self.measurements = measurements
        self.evidenceFiles = evidenceFiles
        self.failureCode = failureCode
        self.note = note
    }
}

public enum ProofReadState: Equatable, Sendable {
    case bootstrapping(progressCompleted: Int, progressTotal: Int)
    case empty
    case ready(sourceStateID: UUID, siteCount: Int, deviceCount: Int, deploymentCount: Int, pendingPackageCount: Int)
    case importing(processedItems: Int, totalItems: Int)
    case waitingForDependency(packageCount: Int, itemCount: Int)
    case conflictReviewRequired(conflictCount: Int)
    case analysisStale(staleRunCount: Int, currentSourceStateID: UUID)
    case recoveryRequired(code: String)
}

public enum FailurePoint: String, CaseIterable, Codable, Sendable {
    case beforeMigration
    case afterMigrationStatement
    case beforeTransactionCommit
    case afterDomainMutationBeforeLedger
    case afterStagedPackageBeforeActivation
    case duringCheckpoint
    case duringBackup
    case afterObservationCommitBeforeDelivery
}

public struct ProofPaths: Sendable {
    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    public var database: URL { root.appending(path: "stores/animal-tracking-proof.sqlite") }
    public var bootstrapStaging: URL { root.appending(path: "fixtures/bootstrap/staging") }
    public var deltaStaging: URL { root.appending(path: "fixtures/delta/staging") }
    public var rawEvidence: URL { root.appending(path: "evidence/raw") }
    public var derivedEvidence: URL { root.appending(path: "evidence/derived") }
    public var quarantine: URL { root.appending(path: "evidence/quarantine") }

    public func createDirectories(fileManager: FileManager = .default) throws {
        for directory in [database.deletingLastPathComponent(), bootstrapStaging, deltaStaging, rawEvidence, derivedEvidence, quarantine] {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }
}
