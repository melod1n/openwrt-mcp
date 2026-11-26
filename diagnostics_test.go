package main

import (
 "encoding/json"
 "strings"
 "testing"
)
func TestDiagnosticSafety(t *testing.T){
 for _,s:=range []string{"-x","127.0.0.1","169.254.169.254","0.0.0.0","224.0.0.1","fe80::1%eth0","::ffff:127.0.0.1"}{if diagIP(s){t.Errorf("allowed %s",s)}}
 for _,s:=range []string{"1.1.1.1","192.168.1.1","2001:db8::1"}{if !diagIP(s){t.Errorf("denied %s",s)}}
 if !diagResolverIP("127.0.0.1"){t.Fatal("local DNS denied")}
 for _,s:=range []string{"https://user:secret@example.org/dns?token=secret","secret","vless://secret"}{if diagSafeValue(s)!="[omitted]"{t.Fatal("secret leaked")}}
 v,e:=diagProxySummary([]byte(`{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","tag":"secret"}]},"outbounds":[{"type":"vless","server":"192.0.2.5","server_port":443,"uuid":"secret","tls":{"private_key":"secret"},"tag":"secret"}]}`));if e!=nil{t.Fatal(e)}
 b,_:=json.Marshal(v);if strings.Contains(string(b),"secret")||!strings.Contains(string(b),"192.0.2.5"){t.Fatalf("unsafe summary: %s",b)}
 for _,n:=range []string{"get_proxy_status","get_network_packages","get_routing_state","get_logs_page","tcp_probe","dns_lookup"}{if !lanToolAllowed(n){t.Errorf("not exported %s",n)}}
}
func TestDiagnosticPagination(t *testing.T){
 out,_,e:=diagPage("Wed Nov 25 a\nWed Nov 25 b\nWed Nov 25 c\nThu Nov 26 d\n",diagLogIn{Day:"Wed Nov 25",Offset:1,Limit:1});if e!=nil{t.Fatal(e)}
 var v struct{Entries []string `json:"entries"`;Next int `json:"next_offset"`;More bool `json:"has_more"`}
 if e=json.Unmarshal([]byte(out),&v);e!=nil||len(v.Entries)!=1||v.Entries[0]!="Wed Nov 25 b"||v.Next!=2||!v.More{t.Fatalf("bad page %s %v",out,e)}
}
