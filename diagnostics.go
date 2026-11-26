package main

import (
 "bufio"
 "context"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/netip"
 "os"
 "regexp"
 "strings"
 "time"

 "github.com/modelcontextprotocol/go-sdk/mcp"
)

type diagEmpty struct{}
type diagLogIn struct {
 Pattern string `json:"pattern,omitempty" jsonschema:"literal substring filter"`
 Day string `json:"day,omitempty" jsonschema:"syslog date prefix such as Wed Nov 25"`
 Offset int `json:"offset,omitempty" jsonschema:"skip matching entries, newest first"`
 Limit int `json:"limit,omitempty" jsonschema:"entries per page, default 50 max 100"`
}
type diagTCPIn struct {
 IP string `json:"ip" jsonschema:"literal unicast IPv4 or IPv6 address, explicitly granted by ACL"`
 Port int `json:"port" jsonschema:"TCP port, 1 to 65535"`
}
type diagDNSIn struct {
 Host string `json:"host" jsonschema:"DNS hostname"`
 Resolver string `json:"resolver" jsonschema:"literal DNS server IP; requires explicit ACL; port 53"`
}
var diagHost = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.?$`)
func diagIP(s string) bool {
 ip,e:=netip.ParseAddr(s)
 return e==nil && ip.Zone()=="" && ip.Unmap().IsGlobalUnicast() && !ip.Unmap().IsLinkLocalUnicast()
}
func diagResolverIP(s string) bool {
 ip,e:=netip.ParseAddr(s)
 return diagIP(s) || (e==nil && ip.Zone()=="" && ip.IsLoopback())
}
func diagJSON(v any, summary string) (string,string,error) {
 b,e:=json.Marshal(v)
 if e!=nil { return "",summary,e }
 if len(b)>48<<10 { return "",summary,fmt.Errorf("diagnostic output exceeds limit; narrow query") }
 return string(b),summary,nil
}
func diagTCP(ctx context.Context,in diagTCPIn)(string,string,error){
 if !diagIP(in.IP)||in.Port<1||in.Port>65535{return "","tcp",fmt.Errorf("invalid unicast IP or port")}
 ctx,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 start:=time.Now()
 c,e:=(&net.Dialer{}).DialContext(ctx,"tcp",net.JoinHostPort(in.IP,fmt.Sprint(in.Port)))
 if c!=nil {c.Close()}
 result:=map[string]any{"ip":in.IP,"port":in.Port,"ok":e==nil,"elapsed_ms":time.Since(start).Milliseconds()}
 if e!=nil {result["error"]=e.Error()}
 return diagJSON(result,"tcp probe")
}
func diagDNS(ctx context.Context,in diagDNSIn)(string,string,error){
 if !diagHost.MatchString(in.Host)||!diagResolverIP(in.Resolver){return "","dns",fmt.Errorf("invalid DNS hostname or resolver IP")}
 ctx,cancel:=context.WithTimeout(ctx,6*time.Second);defer cancel()
 resolver:=&net.Resolver{PreferGo:true,Dial:func(ctx context.Context,network,_ string)(net.Conn,error){
 return (&net.Dialer{}).DialContext(ctx,network,net.JoinHostPort(in.Resolver,"53"))
 }}
 start:=time.Now()
 ips,e:=resolver.LookupNetIP(ctx,"ip",strings.TrimSuffix(in.Host,".")+".")
 result:=map[string]any{"host":in.Host,"resolver":in.Resolver,"ok":e==nil,"elapsed_ms":time.Since(start).Milliseconds(),"addresses":ips}
 if e!=nil {result["error"]=e.Error()}
 return diagJSON(result,"DNS probe")
}
func diagPage(out string,in diagLogIn)(string,string,error){
 if in.Offset<0||in.Offset>20000||len(in.Pattern)>128||len(in.Day)>32{return "","logs",fmt.Errorf("invalid log filter or offset")}
 limit:=in.Limit;if limit<=0{limit=50};if limit>100{limit=100}
 lines:=strings.Split(out,"\n"); entries:=make([]string,0,limit);total:=0;size:=0
 for i:=len(lines)-1;i>=0;i-- {
  l:=lines[i];if l==""||!strings.HasPrefix(l,in.Day)||!strings.Contains(l,in.Pattern){continue}
  total++
  if total<=in.Offset||len(entries)>=limit{continue}
  if len(l)>2048{l=l[:2048]+" [line truncated]"}
  // conservative bound accounts for JSON escapes, even with ANSI sequences
  b,_:=json.Marshal(l);if size+len(b)>24<<10{continue}
  entries=append(entries,l);size+=len(b)+1
 }
 // Recompute an exact contiguous page when budget cut it short.
 if len(entries)>0{
  // The loop may skip a long line; keep only entries until the first budget miss.
  entries=entries[:0];size=0;seen:=0
  for i:=len(lines)-1;i>=0;i--{
   l:=lines[i];if l==""||!strings.HasPrefix(l,in.Day)||!strings.Contains(l,in.Pattern){continue};seen++;if seen<=in.Offset{continue}
   if len(l)>2048{l=l[:2048]+" [line truncated]"}
   b,_:=json.Marshal(l);if len(entries)>=limit||size+len(b)>24<<10{break}
   entries=append(entries,l);size+=len(b)+1
  }
 }
 return diagJSON(map[string]any{"entries":entries,"matching":total,"next_offset":in.Offset+len(entries),"has_more":in.Offset+len(entries)<total,"order":"newest_first","snapshot":"latest 2000 ring entries; offsets can shift as logs arrive"},"paged logs")
}
func diagLogs(ctx context.Context,in diagLogIn)(string,string,error){
 out,e:=run(ctx,5*time.Second,"logread","-l","2000");if e!=nil{return "","logs",e};return diagPage(out,in)
}
func diagRouting(ctx context.Context,_ diagEmpty)(string,string,error){
 result:=map[string]any{}
 for _,family:=range []string{"-4","-6"}{
  for _,kind:=range []string{"route","rule"}{
   argv:=[]string{"ip",family,kind,"show"};if kind=="route"{argv=append(argv,"table","all")}
   out,e:=run(ctx,5*time.Second,argv...)
   entry:=map[string]any{"output":out,"ok":e==nil};if e!=nil{entry["error"]=e.Error()};result[family+"_"+kind]=entry
  }
 }
 return diagJSON(result,"routes and policy rules")
}
func diagRead(path string)([]byte,error){
 f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
 b,e:=io.ReadAll(io.LimitReader(f,1<<20+1));if len(b)>1<<20{return nil,fmt.Errorf("config too large")};return b,e
}
// Allowlist only scalar values with a bounded safe grammar. Never return raw UCI
// or sing-box JSON: proxy credentials, URLs, keys and subscriptions are omitted.
func diagSafeValue(v string) string {
 if len(v)>253{return "[omitted]"}
 if _,e:=netip.ParseAddr(v);e==nil{return v}
 if v=="0"||v=="1"||v=="true"||v=="false"{return v}
 switch v{case "udp","tcp","tls","https","quic","h3","local","direct","proxy","fakeip","auto","ipv4_only","ipv6_only","prefer_ipv4","prefer_ipv6":return v}
 return "[omitted]"
}
func diagProxySummary(raw []byte)(map[string]any,error){
 var cfg struct{
  DNS struct{Servers []map[string]any `json:"servers"`;Final string `json:"final"`} `json:"dns"`
  Outbounds []map[string]any `json:"outbounds"`
 }
 if e:=json.Unmarshal(raw,&cfg);e!=nil{return nil,fmt.Errorf("cannot parse sing-box configuration")}
 pick:=func(in []map[string]any)[]map[string]any{
  out:=make([]map[string]any,0)
  for i,v:=range in{
   if i>=80{break}
   item:=map[string]any{"index":i}
   for _,k:=range []string{"type","server","address","detour","tag","domain_resolver"}{
    if val,ok:=v[k].(string);ok{
     // tags/detours can be user-defined credential strings; expose only whether configured
     if k=="tag"||k=="detour"||k=="domain_resolver"{item[k+"_configured"]=val!="";continue}
     if k=="type"{if regexp.MustCompile(`^[a-z0-9_-]{1,32}$`).MatchString(val){item[k]=val};continue}
     item[k]=diagSafeValue(val)
    }
   }
   if p,ok:=v["server_port"].(float64);ok&&p>=1&&p<=65535{item["server_port"]=p}
   out=append(out,item)
  };return out
 }
 return map[string]any{"dns_servers":pick(cfg.DNS.Servers),"dns_server_count":len(cfg.DNS.Servers),"dns_final_configured":cfg.DNS.Final!="","outbounds":pick(cfg.Outbounds),"outbound_count":len(cfg.Outbounds)},nil
}
func diagProxy(ctx context.Context,_ diagEmpty)(string,string,error){
 result:=map[string]any{}
 for _,name:=range []string{"podkop","forkop","sing-box","sing-box-forkop","dnsmasq","https-dns-proxy"}{
  out,e:=run(ctx,3*time.Second,"pidof",name)
  if e==nil {result[name+"_pids"]=strings.Fields(out)}
 }
 for _,name:=range []string{"podkop","forkop","dhcp"}{
  raw,e:=diagRead("/etc/config/"+name);if e!=nil{continue}
  sections:=parseUCI(bufio.NewScanner(strings.NewReader(string(raw))))
  vals:=make([]map[string]any,0)
  for _,s:=range sections{
   row:=map[string]any{}
   for _,k:=range []string{"dns_server","bootstrap_dns_server","dns_type","dns_detour_enabled","interface_monitoring","output_interface","unmatched_dns_mode","noresolv","localuse","port","strictorder","allservers"}{
    if v,ok:=s.Options[k];ok{row[k]=diagSafeValue(v)}
   }
   if len(row)>0{vals=append(vals,row)}
  }
  result[name+"_safe_options"]=vals
 }
 if raw,e:=diagRead("/etc/sing-box/config.json");e==nil{
  if v,e:=diagProxySummary(raw);e==nil{result["singbox"]=v}else{result["singbox_error"]=e.Error()}
 }else{result["singbox_error"]="fixed config path unavailable"}
 return diagJSON(result,"proxy and DNS snapshot (credentials omitted)")
}
func diagPackages(ctx context.Context,_ diagEmpty)(string,string,error){
 out,e:=run(ctx,8*time.Second,"opkg","list-installed");if e!=nil{return "","packages",e}
 keep:=[]string{}
 for _,line:=range strings.Split(out,"\n"){
  name,_,_:=strings.Cut(line," - ")
  switch name{case "podkop","luci-app-podkop","podkop-engine","forkop","luci-app-forkop","sing-box","sing-box-forkop","dnsmasq","dnsmasq-full","https-dns-proxy","firewall4","nftables","openwrt-mcp","ip-full","ip-tiny","ethtool":keep=append(keep,line)}
 }
 return diagJSON(map[string]any{"packages":keep},"network package versions")
}
func registerDiagnostics(s *Server,srv *mcp.Server,client string){
 addTool(s,srv,client,"get_proxy_status","Read fixed proxy/DNS config paths; only allowlisted non-secret fields and process IDs, no raw credentials.",func(diagEmpty)[]string{return nil},diagProxy)
 addTool(s,srv,client,"get_network_packages","Read installed network package versions (opkg).",func(diagEmpty)[]string{return nil},diagPackages)
 addTool(s,srv,client,"get_routing_state","Read IPv4/IPv6 routing tables and policy rules; no changes.",func(diagEmpty)[]string{return nil},diagRouting)
 addTool(s,srv,client,"get_logs_page","Read bounded filtered log page, newest first; offsets may shift with new logs.",func(diagLogIn)[]string{return nil},diagLogs)
 addTool(s,srv,client,"tcp_probe","Single TCP connection to literal IP and port; ACL scope tcp.<ip>:<port>; does not test proxy handshake.",func(in diagTCPIn)[]string{return []string{"tcp."+net.JoinHostPort(in.IP,fmt.Sprint(in.Port))}},diagTCP)
 addTool(s,srv,client,"dns_lookup","Resolve A/AAAA using specified literal DNS server IP and port 53; ACL scope dns.<resolver>.",func(in diagDNSIn)[]string{return []string{"dns."+in.Resolver}},diagDNS)
}
