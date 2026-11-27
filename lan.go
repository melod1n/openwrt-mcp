package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Only literal loopback or explicitly opted-in RFC1918 IPv4 listeners are allowed.
// Binding a LAN address is not a firewall rule: keep WAN ingress blocked.
func validateListen(address string, allowLAN bool) (bool, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false, fmt.Errorf("bad listen address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return false, nil
	}
	if allowLAN && ip != nil && ip.To4() != nil && ip.IsPrivate() && !strings.Contains(host, ":") {
		return true, nil
	}
	return false, fmt.Errorf("listen address %q requires loopback or explicit allow_lan with a private IPv4 address", address)
}

func lanToolAllowed(name string) bool {
	switch name {
	case "ubus_list", "ubus_call", "exec", "logread", "get_proxy_status", "get_network_packages", "get_routing_state", "get_logs_page", "tcp_probe", "dns_lookup":
		return true
	default:
		return false
	}
}

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func lanStringArg(args map[string]any, key string, optional bool) bool {
	if len(args) == 0 {
		return optional
	}
	if len(args) != 1 {
		return false
	}
	value, ok := args[key].(string)
	return ok && interfaceName.MatchString(value)
}

// Never use wildcard method ACLs as a substitute for this independent ubus boundary.
func lanUbusAllowed(in ubusCallIn) bool {
	switch in.Object {
	case "system":
		return (in.Method == "info" || in.Method == "board") && len(in.Args) == 0
	case "network.interface":
		return in.Method == "dump" && len(in.Args) == 0
	case "network.device":
		return in.Method == "status" && lanStringArg(in.Args, "name", true)
	case "iwinfo":
		switch in.Method {
		case "devices":
			return len(in.Args) == 0
		case "info", "assoclist":
			return lanStringArg(in.Args, "device", false)
		}
	case "luci-rpc":
		return (in.Method == "getDHCPLeases" || in.Method == "getHostHints") && len(in.Args) == 0
	}
	if name, ok := strings.CutPrefix(in.Object, "network.interface."); ok && interfaceName.MatchString(name) {
		return in.Method == "status" && len(in.Args) == 0
	}
	return false
}
