import Foundation
import Darwin

/// Keeps two app copies from concurrently applying conflicting configurations.
public final class RoutingInstanceLock {
    private let descriptor: Int32
    public init(at url: URL) throws {
        let descriptor = open(url.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            close(descriptor); throw MihomoClientError.unavailable
        }
        self.descriptor = descriptor
    }
    deinit { close(descriptor) }
}
