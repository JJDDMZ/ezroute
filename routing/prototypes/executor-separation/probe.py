#!/usr/bin/env python3
"""Review pinned SOCKS handoff source facts offline; never run a relay or filter."""
import argparse
import hashlib
import json
from pathlib import Path

COMMIT = "88dcbf7f1614a67c3b36b848ee3592dfa92ada36"
FILES = {"adapter/outbound/socks5.go", "listener/socks/tcp.go",
         "listener/socks/udp.go", "transport/socks5/socks5.go"}


def review(directory):
    root = Path(directory)
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("commit") != COMMIT:
        raise RuntimeError("Unexpected source revision")
    entries = manifest["entries"]
    if len(entries) != len(FILES) or {e["path"] for e in entries} != FILES:
        raise RuntimeError("Unexpected source collection")
    sources = {}
    for entry in entries:
        data = (root / entry["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise RuntimeError("Source hash mismatch: " + entry["path"])
        sources[entry["path"]] = data.decode()
    tcp = sources["listener/socks/tcp.go"]
    udp = sources["listener/socks/udp.go"]
    outbound = sources["adapter/outbound/socks5.go"]
    transport = sources["transport/socks5/socks5.go"]
    udp_handler = udp.split("func handleSocksUDP(", 1)[1]
    tcp_handler = tcp.split("func HandleSocks5(", 1)[1]
    # These are narrow structural checks, not a proof of absence across the core.
    facts = {
        "tcp_auth_store_used_for_handshake":
            "socks5.ServerHandshake(conn, authenticator)" in tcp_handler,
        "default_listener_has_skip_auth_branch":
            "inbound.SkipAuthRemoteAddr(c.RemoteAddr())" in tcp and "store = authStore.Nil" in tcp,
        "tcp_connect_hands_target_to_tunnel":
            "inbound.NewSocket(target, conn, C.SOCKS5, additions...)" in tcp_handler,
        "udp_associate_handler_only_waits_on_tcp":
            "io.Copy(io.Discard, conn)" in tcp_handler.split("if command == socks5.CmdUDPAssociate {", 1)[1].split("}", 1)[0],
        "udp_handler_decodes_and_dispatches_without_auth_store":
            "socks5.DecodeUDPPacket(buf)" in udp_handler and
            "tunnel.HandleUDPPacket(" in udp_handler and "AuthStore" not in udp_handler and "Authenticator" not in udp_handler,
        "udp_outbound_resolves_before_association":
            outbound.index("ss.ResolveUDP(ctx, metadata)") < outbound.index("socks5.CmdUDPAssociate"),
        "udp_codec_has_address_payload_not_session_parameter":
            "func DecodeUDPPacket(packet []byte) (addr Addr, payload []byte, err error)" in transport,
    }
    if not all(facts.values()):
        raise RuntimeError("Reviewed assumptions changed: " + json.dumps(facts))
    return {"task": "S01-H ordinary SOCKS executor handoff review", "manifest": manifest,
            "source_facts": facts, "runtime_executed": False,
            "authenticated_udp_handoff_proved": False,
            "strict_process_interface_enforcement_proved": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, help="Saved public-source directory")
    arguments = parser.parse_args()
    print(json.dumps(review(arguments.source_dir), indent=2))
