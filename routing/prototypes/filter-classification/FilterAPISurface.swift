// Compile with -typecheck only. No entry point, filter configuration or activation.
import Foundation
import Network
import NetworkExtension

func inspectDeclaredFilterAPIs(flow: NEFilterSocketFlow,
                              dataProvider: NEFilterDataProvider,
                              packetProvider: NEFilterPacketProvider) {
    _ = flow.identifier
    _ = flow.sourceAppAuditToken
    _ = flow.sourceProcessAuditToken
    _ = flow.localFlowEndpoint
    _ = flow.remoteFlowEndpoint
    _ = flow.remoteHostname
    _ = flow.socketFamily
    _ = flow.socketType
    _ = flow.socketProtocol
    _ = NEFilterNewFlowVerdict.pause()
    dataProvider.update(flow, using: .drop(), for: .any)
    dataProvider.resumeFlow(flow, with: NEFilterNewFlowVerdict.drop())
    packetProvider.packetHandler = { context, interface, direction, bytes, length in
        _ = context
        _ = nw_interface_get_index(interface)
        _ = nw_interface_get_name(interface)
        _ = direction
        _ = bytes
        _ = length
        return .drop
    }
}
