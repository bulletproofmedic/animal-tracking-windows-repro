import Foundation

public protocol ProofObservationCancellable: AnyObject, Sendable {
    func cancel()
}

public protocol ProofStateRepository: Sendable {
    func startObservation(
        onError: @escaping @Sendable (any Error) -> Void,
        onChange: @escaping @Sendable (ProofReadState) -> Void
    ) -> any ProofObservationCancellable
}

public final class ProofObservationToken: ProofObservationCancellable, @unchecked Sendable {
    private let lock = NSLock()
    private var cancellation: (@Sendable () -> Void)?

    public init(cancellation: @escaping @Sendable () -> Void) {
        self.cancellation = cancellation
    }

    public func cancel() {
        lock.lock()
        let action = cancellation
        cancellation = nil
        lock.unlock()
        action?()
    }

    deinit {
        cancel()
    }
}
