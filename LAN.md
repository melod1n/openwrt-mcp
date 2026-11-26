# LAN diagnostic preview

Default is loopback, with the original upstream policies. Explicit LAN mode accepts a literal RFC1918 IPv4 address only; wildcard, public and hostname binds are rejected. The LAN mode is fixed at startup and requires a restart to change.

On a trusted network, install the ARM64 IPK from CI, then run as root on the router:

```sh
uci set openwrt-mcp.@server[0].listen='192.168.1.1:8730'
uci set openwrt-mcp.@server[0].allow_lan='1'
uci commit openwrt-mcp
openwrt-mcp pair nexum
openwrt-mcp allow nexum ubus_call,logread 'system.info system.board network.interface.dump network.interface.*.status network.device.status iwinfo.devices iwinfo.info iwinfo.assoclist luci-rpc.getDHCPLeases luci-rpc.getHostHints' never
/etc/init.d/openwrt-mcp restart
```

Keep the token private. Configure Streamable HTTP at `http://192.168.1.1:8730/mcp` with `Authorization: Bearer <token>`. Check firewall input policy and do not expose this port on WAN or guest networks. Plain HTTP does not encrypt the token; use only on a trusted LAN. The /health endpoint is intentionally public and contains version/source only.

The LAN server exposes only ubus_list, restricted ubus_call and logread. Even permissive standing policies cannot enable mutation, exec, raw UCI reads or WireGuard credential generation over this listener. Logs and diagnostic replies can still contain sensitive data. Test exact methods against the device; availability is firmware-dependent. The audit file is capped at approximately 1 MiB plus one rotated generation by default. No LuCI integration yet.

Before installation verify CI and package checksum, and back up the router configuration. The first installation starts on loopback. To disable LAN access, set allow_lan=0 and listen back to 127.0.0.1:8730 and restart. To remove, stop the service and use opkg remove openwrt-mcp.
