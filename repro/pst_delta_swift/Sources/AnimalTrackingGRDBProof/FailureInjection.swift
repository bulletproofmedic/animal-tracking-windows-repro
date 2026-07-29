import Foundation
import PersistenceProofDomain

public enum InjectedProofFailure: Error, Equatable, Sendable {
    case triggered(FailurePoint)
}

public final class FailureInjector: @unchecked Sendable {
    private let lock = NSLock()
    private var armed: Set<FailurePoint> = []

    public init() {}

    public func arm(_ point: FailurePoint) {
        lock.lock()
        armed.insert(point)
        lock.unlock()
    }

    public func disarm(_ point: FailurePoint) {
        lock.lock()
        armed.remove(point)
        lock.unlock()
    }

    public func disarmAll() {
        lock.lock()
        armed.removeAll()
        lock.unlock()
    }

    public func check(_ point: FailurePoint) throws {
        lock.lock()
        let shouldThrow = armed.remove(point) != nil
        lock.unlock()
        if shouldThrow {
            throw InjectedProofFailure.triggered(point)
        }
    }
}
