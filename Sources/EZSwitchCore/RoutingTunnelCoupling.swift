import Foundation

/// Decides when the tunnel may switch automatic routing back on.
///
/// The tunnel closing forces automatic routing off, because the coordinator cannot
/// protect anything without it. Restoring is allowed only when the tunnel itself
/// took the switch away: a manual choice always wins, and one restore is owed per
/// off-to-on edge, so a failed attempt cannot become a retry loop.
public struct RoutingTunnelCoupling: Equatable, Sendable {
    /// Automatic routing is off because the tunnel went away, not because the user said so.
    public private(set) var suspended: Bool
    private var previousTunnel: Bool?
    private var owed: Bool

    public init(suspended: Bool = false) {
        self.suspended = suspended
        self.previousTunnel = nil
        self.owed = suspended
    }

    /// The controller reported the tunnel off. `wasEnabled` is the switch state the
    /// coordinator forced off; only that case arms a restore.
    public mutating func tunnelWentOff(wasEnabled: Bool) {
        guard wasEnabled else { return }
        suspended = true
        owed = true
    }

    /// The user moved the switch themselves. Either direction retires a pending restore.
    public mutating func userSetEnabled() {
        suspended = false
        owed = false
    }

    /// Observe the tunnel and report whether a restore should be attempted now.
    public mutating func observeTunnel(enabled: Bool) -> Bool {
        defer { previousTunnel = enabled }
        guard suspended, owed, enabled, previousTunnel != true else { return false }
        owed = false
        return true
    }

    public mutating func restoreSucceeded() {
        suspended = false
        owed = false
    }

    /// Keep the suspension, but wait for the next off-to-on edge before trying again.
    public mutating func restoreFailed() {
        owed = true
    }
}
