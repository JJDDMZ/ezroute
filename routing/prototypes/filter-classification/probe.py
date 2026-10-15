#!/usr/bin/env python3
"""Offline information-loss counterexamples; this is not a working packet filter."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class ObservableSocket:
    process: str
    local: tuple
    remote: tuple
    protocol: str
    interface: str


def run_cases():
    cases = []

    def check(name, condition, implication):
        if not condition:
            raise RuntimeError("Counterexample failed: " + name)
        cases.append({"id": name, "reproduced": True, "implication": implication})

    # Documentation addresses only; the program performs no DNS or socket calls.
    direct = ObservableSocket("mihomo-instance-A", ("192.0.2.10", 51000),
                              ("203.0.113.20", 443), "tcp", "en0")
    proxy = ObservableSocket("mihomo-instance-A", ("192.0.2.10", 51001),
                             ("203.0.113.20", 443), "tcp", "en0")
    check("C01-process-role-collision", direct.process == proxy.process,
          "A process audit identity can cover both roles; it is not a role label.")
    check("C02-remote-endpoint-collision", direct.remote == proxy.remote,
          "A direct server and proxy endpoint can coincide; destination is insufficient.")

    inbound = ("127.0.0.1", 43000)
    check("C03-inbound-outbound-port-mismatch", inbound != direct.local,
          "Client ingress tuple is not the physical outbound socket tuple.")

    # Same observation has two possible policy histories before tracking exists.
    worlds = [(direct, [], "direct"), (direct, [], "proxy")]
    check("C04-pre-tracker-indistinguishability", worlds[0][:2] == worlds[1][:2]
          and worlds[0][2] != worlds[1][2],
          "Before a tracker exists, socket observation plus empty statistics cannot determine role.")

    dial_complete = False
    tracker_available = dial_complete
    strict_gate_allows = tracker_available
    check("C05-paused-dial-circular-wait", not tracker_available and not strict_gate_allows,
          "Waiting for post-dial statistics while pausing dial cannot bootstrap authorization.")

    old_record = {"tuple": direct, "role": "direct", "generation": 1}
    reused_socket = {"tuple": direct, "role": "proxy", "generation": 2}
    check("C06-stale-tuple-reuse", old_record["tuple"] == reused_socket["tuple"]
          and old_record["role"] != reused_socket["role"],
          "A tuple cache without lifetime identity can authorize a later different flow.")

    old_network = ("en0", "phone", 1)
    new_network = ("en0", "campus", 2)
    check("C07-wireless-interface-reuse", old_network[0] == new_network[0]
          and old_network[1:] != new_network[1:],
          "Interface equality cannot detect an authorization change before the identity event.")

    logical_flows = ["client-A", "client-B"]
    physical_socket = [proxy, proxy]
    check("C08-many-logical-flows-one-transport", len(set(logical_flows)) == 2
          and len(set(physical_socket)) == 1,
          "A shared transport needs socket-level authorization; logical IDs do not imply one-to-one mapping.")
    return cases


def check_sources(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    for entry in manifest["entries"]:
        if hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise RuntimeError("Source hash mismatch: " + entry["path"])
    tracker = (directory / "tunnel/statistic/tracker.go").read_text()
    tunnel = (directory / "tunnel/tunnel.go").read_text()
    route = (directory / "hub/route/connections.go").read_text()
    inbound = (directory / "adapter/inbound/socket.go").read_text()
    outbound = (directory / "adapter/outbound/base.go").read_text()
    fields = re.search(r"type TrackerInfo struct \{(.*?)\n\}", tracker, re.S).group(1)
    tcp = tunnel.split("func handleTCPConn(", 1)[1].split("func logMetadataErr(", 1)[0]
    facts = {
        "tracker_uuid_generated_in_mihomo": "UUID:          utils.NewUUIDV4()" in tracker,
        "tcp_dial_precedes_tracker": tcp.index("proxy.DialContext(") < tcp.index("statistic.NewTCPTracker("),
        "tcp_optional_handshake_write_precedes_tracker": tcp.index("remoteConn.Write(peekBytes)") < tcp.index("statistic.NewTCPTracker("),
        "tracker_does_not_serialize_outbound_local_tuple": "LocalAddr" not in fields and "localPort" not in fields,
        "websocket_is_periodic_statistics_snapshot": "statistic.DefaultManager.Snapshot()" in route and "time.NewTicker(" in route,
        "socket_metadata_source_is_inbound_client": "WithSrcAddr(conn.RemoteAddr())" in inbound,
        "remote_destination_uses_address_string_without_socket_tuple": "return m.String()" in outbound.split("func (c *conn) RemoteDestination()", 1)[1].split("func (c *conn) Chains()", 1)[0],
    }
    if not all(facts.values()):
        raise RuntimeError("Source assumptions changed: " + json.dumps(facts))
    return {"manifest": manifest, "facts": facts}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", help="Optional saved public-source directory; never live configuration")
    arguments = parser.parse_args()
    result = {"kind": "synthetic-information-loss-counterexamples", "cases": run_cases(),
              "runtime_filter_executed": False, "physical_egress_verified": False}
    if arguments.source_dir:
        result["source_checks"] = check_sources(arguments.source_dir)
    print(json.dumps(result, indent=2))
