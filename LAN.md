# LAN access

Default is loopback, with the original upstream policies. Explicit LAN mode accepts a literal RFC1918 IPv4 address only; wildcard, public and hostname binds are rejected. The LAN mode is fixed at startup and requires a restart to change.

On a trusted network, install the ARM64 IPK from CI, then run as root on the router:

```sh
uci set openwrt-mcp.@server[0].listen='192.168.1.1:8730'
uci set openwrt-mcp.@server[0].allow_lan='1'
uci commit openwrt-mcp
openwrt-mcp pair nexum
openwrt-mcp allow nexum ubus_call,logread 'system.info system.board network.interface.dump network.interface.*.status network.device.status iwinfo.devices iwinfo.info iwinfo.assoclist luci-rpc.getDHCPLeases luci-rpc.getHostHints' never
openwrt-mcp allow nexum exec '*' never
/etc/init.d/openwrt-mcp restart
```

Keep the token private. Configure Streamable HTTP at `http://192.168.1.1:8730/mcp` with `Authorization: Bearer <token>`. Check firewall input policy and do not expose this port on WAN or guest networks. Plain HTTP does not encrypt the token; use only on a trusted LAN. The /health endpoint is intentionally public and contains version/source only.

The LAN server exposes ubus_list, restricted ubus_call, exec and logread, plus the passive diagnostic tools below. The exec tool accepts arbitrary argv; invoke `/bin/sh -c` when you need pipelines, redirection or shell syntax. It runs as root. Grant it only to a trusted client on a trusted LAN, and keep WAN and guest ingress blocked. A broad grant is root-equivalent access. Raw UCI tools and WireGuard credential generation remain unavailable over this listener. Logs and diagnostic replies can still contain sensitive data. Test exact methods against the device; availability is firmware-dependent. The audit file is capped at approximately 1 MiB plus one rotated generation by default. No LuCI integration yet.

Before installation verify CI and package checksum, and back up the router configuration. The first installation starts on loopback. To disable LAN access, set allow_lan=0 and listen back to 127.0.0.1:8730 and restart. To remove, stop the service and use opkg remove openwrt-mcp.

## Diagnostic extension
Existing policies are not broadened. Grant passive tools separately:

```sh
openwrt-mcp allow nexum get_proxy_status,get_network_packages,get_routing_state,get_logs_page '' never
openwrt-mcp allow nexum dns_lookup 'dns.127.0.0.1 dns.1.1.1.1 dns.1.0.0.1' never
# Optional, explicit target (replace with your proxy IP):
openwrt-mcp allow nexum tcp_probe 'tcp.192.0.2.5:443' never
/etc/init.d/openwrt-mcp restart
```

DNS probes use A/AAAA and port 53 only; TCP is only a connection probe, not VLESS/TLS. Proxy summary is intentionally partial and never returns raw config. Log pages are newest first with shifting offsets (ring buffer). No packet capture, raw UCI tools or WireGuard credential generation via MCP.

## Updating
After a version is released from main, install its versioned IPK once. Subsequent upgrades: `openwrt-mcp update` over SSH. The updater pins a release, verifies its SHA-256, preserves the UCI conffile and token state, and checks health. Temporary private backup survives until reboot; automatic binary rollback is not implemented. SHA-256 protects file integrity, not a compromised publisher. Only opkg/aarch64_cortex-a53 supported by this build. No auto-update or remotely callable update tool.
