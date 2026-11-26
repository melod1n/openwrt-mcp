package main

import "testing"

func TestValidateListen(t *testing.T) {
	for _, tc := range []struct {
		address string
		allow, lan, valid bool
	}{
		{"127.0.0.1:8730", false, false, true},
		{"[::1]:8730", false, false, true},
		{"192.168.1.1:8730", false, false, false},
		{"192.168.1.1:8730", true, true, true},
		{"10.0.0.1:8730", true, true, true},
		{"0.0.0.0:8730", true, false, false},
		{"[::]:8730", true, false, false},
		{"8.8.8.8:8730", true, false, false},
		{"openwrt.lan:8730", true, false, false},
		{":8730", true, false, false},
	} {
		lan, err := validateListen(tc.address, tc.allow)
		if lan != tc.lan || (err == nil) != tc.valid {
			t.Errorf("%+v: got LAN=%v err=%v", tc, lan, err)
		}
	}
}

func TestLANReadOnlyAllowlist(t *testing.T) {
	for _, name := range []string{"exec", "uci_apply", "uci_confirm", "uci_get", "wg_new_client", "mfa_unlock", "future_tool"} {
		if lanToolAllowed(name) {
			t.Errorf("unexpected LAN tool %s", name)
		}
	}
	for _, name := range []string{"ubus_list", "ubus_call", "logread"} {
		if !lanToolAllowed(name) {
			t.Errorf("missing LAN tool %s", name)
		}
	}
	for _, tc := range []struct {
		in ubusCallIn
		allow bool
	}{
		{ubusCallIn{Object:"system", Method:"info"}, true},
		{ubusCallIn{Object:"network.interface.wan", Method:"status"}, true},
		{ubusCallIn{Object:"network.device", Method:"status", Args:map[string]any{"name":"eth1"}}, true},
		{ubusCallIn{Object:"iwinfo", Method:"assoclist", Args:map[string]any{"device":"phy0-ap0"}}, true},
		{ubusCallIn{Object:"luci-rpc", Method:"getDHCPLeases"}, true},
		{ubusCallIn{Object:"system", Method:"reboot"}, false},
		{ubusCallIn{Object:"network.interface.wan", Method:"down"}, false},
		{ubusCallIn{Object:"uci", Method:"set"}, false},
		{ubusCallIn{Object:"file", Method:"exec"}, false},
		{ubusCallIn{Object:"network.interface.wan", Method:"status", Args:map[string]any{"unexpected":true}}, false},
		{ubusCallIn{Object:"iwinfo", Method:"info", Args:map[string]any{"device":"-x"}}, false},
		{ubusCallIn{Object:"iwinfo", Method:"assoclist"}, false},
	} {
		if got := lanUbusAllowed(tc.in); got != tc.allow {
			t.Errorf("%+v: got %v", tc.in, got)
		}
	}
}
