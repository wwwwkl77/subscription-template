{{- $GiB := 1073741824.0 -}}
{{- $used := printf "%.2f" (divf (add (.UserInfo.Download | default 0 | float64) (.UserInfo.Upload | default 0 | float64)) $GiB) -}}
{{- $traffic := (.UserInfo.Traffic | default 0 | float64) -}}
{{- $total := printf "%.2f" (divf $traffic $GiB) -}}

{{- $exp := "" -}}
{{- $expStr := printf "%v" .UserInfo.ExpiredAt -}}
{{- if regexMatch `^[0-9]+$` $expStr -}}
  {{- $ts := $expStr | float64 -}}
  {{- $sec := ternary (divf $ts 1000.0) $ts (ge (len $expStr) 13) -}}
  {{- $exp = (date "2006-01-02 15:04:05" (unixEpoch ($sec | int64))) -}}
{{- else -}}
  {{- $exp = $expStr -}}
{{- end -}}

{{- $supportedProxies := list -}}
{{- range $proxy := .Proxies -}}
  {{- if or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "vless") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") (eq $proxy.Type "tuic") -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

{{- $proxyNames := "" -}}
{{- if gt (len $supportedProxies) 0 -}}
  {{- range $proxy := $supportedProxies -}}
    {{- if eq $proxyNames "" -}}
      {{- $proxyNames = printf "\"%s\"" $proxy.Name -}}
    {{- else -}}
      {{- $proxyNames = printf "%s, \"%s\"" $proxyNames $proxy.Name -}}
    {{- end -}}
  {{- end -}}
  {{- $proxyNames = printf ", %s" $proxyNames -}}
{{- end -}}

<!--
{{ .SiteName }}-{{ .SubscribeName }}
Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $exp }}
-->
{
  "log": {"level": "info", "timestamp": true},
  "experimental": {
    "cache_file": {"enabled": true, "path": "cache.db", "cache_id": "my_profile", "store_fakeip": false},
    "clash_api": {"external_controller": "127.0.0.1:9090", "external_ui": "ui", "secret": "", "external_ui_download_url": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip", "external_ui_download_detour": "direct", "default_mode": "rule"}
  },
  "dns": {
    "servers": [
      {"tag": "dns_proxy","address": "tls://8.8.8.8","detour": "Proxy"},
      {"tag": "dns_direct","address": "https://223.5.5.5/dns-query","detour": "direct"}
    ],
    "rules": [
      {"rule_set": "geosite-cn", "server": "dns_direct"},
      {"clash_mode": "direct", "server": "dns_direct"},
      {"clash_mode": "global", "server": "dns_proxy"},
      {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"}
    ],
    "final": "dns_direct",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {"tag": "tun-in", "type": "tun", "address": ["172.18.0.1/30","fdfe:dcba:9876::1/126"], "auto_route": true, "strict_route": true, "stack": "system",
      "platform": {"http_proxy": {"enabled": true, "server": "127.0.0.1", "server_port": 7890}}},
    {"tag": "mixed-in", "type": "mixed", "listen": "127.0.0.1", "listen_port": 7890}
  ],
  "outbounds": [
    {"tag": "Proxy", "type": "selector", "outbounds": ["Auto - UrlTest", "direct"{{ $proxyNames }}]},
    {"tag": "Domestic", "type": "selector", "outbounds": ["direct", "Proxy"{{ $proxyNames }}]},
    {"tag": "Others", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "AI Suite", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Netflix", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Disney Plus", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "YouTube", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Max", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Spotify", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Apple", "type": "selector", "outbounds": ["direct", "Proxy"{{ $proxyNames }}]},
    {"tag": "Telegram", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Microsoft", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Tiktok", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "AdBlock", "type": "selector", "outbounds": ["block", "direct", "Proxy"]},
    {{- if gt (len $supportedProxies) 0 }}
    {"tag": "Auto - UrlTest", "type": "urltest", "outbounds": [{{ $proxyNames | trimPrefix ", " }}], "url": "http://cp.cloudflare.com/", "interval": "10m", "tolerance": 50}
    {{- range $i, $proxy := $supportedProxies }},
{{- $server := $proxy.Server -}}
{{- if and (contains $proxy.Server ":") (not (hasPrefix "[" $proxy.Server)) -}}
  {{- $server = printf "[%s]" $proxy.Server -}}
{{- end -}}

{{- $sni := default "" $proxy.SNI -}}
{{- if eq $sni "" -}}
  {{- $sni = default "" $proxy.Host -}}
{{- end -}}
{{- if and (eq $sni "") (not (or (regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" $proxy.Server) (contains $proxy.Server ":"))) -}}
  {{- $sni = $proxy.Server -}}
{{- end -}}

{{- $password := $.UserInfo.Password -}}
{{- if and (eq $proxy.Type "shadowsocks") (ne (default "" $proxy.ServerKey) "") -}}
  {{- $method := $proxy.Method -}}
  {{- if or (hasPrefix "2022-blake3-" $method) (eq $method "2022-blake3-aes-128-gcm") (eq $method "2022-blake3-aes-256-gcm") -}}
    {{- $userKeyLen := ternary 16 32 (hasSuffix "128-gcm" $method) -}}
    {{- $pwdStr := printf "%s" $password -}}
    {{- $userKey := ternary $pwdStr (trunc $userKeyLen $pwdStr) (le (len $pwdStr) $userKeyLen) -}}
    {{- $serverB64 := b64enc $proxy.ServerKey -}}
    {{- $userB64 := b64enc $userKey -}}
    {{- $password = printf "%s:%s" $serverB64 $userB64 -}}
  {{- end -}}
{{- end -}}

{{- $common := `"tcp_fast_open": true, "udp_over_tcp": false` -}}

{{- if eq $proxy.Type "shadowsocks" -}}
  {{- $method := default "aes-128-gcm" $proxy.Method -}}
    { "type": "shadowsocks", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "method": {{ $method | quote }}, "password": {{ $password | quote }}, {{ $common }} }
{{- else if eq $proxy.Type "trojan" -}}
    { "type": "trojan", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end -}}}{{- else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ default "grpc" $proxy.ServiceName | quote }}}{{- end }}, {{ $common }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}} }
{{- else if eq $proxy.Type "vless" -}}
    { "type": "vless", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $password | quote }}{{- if ne (default "" $proxy.Flow) "" }}, "flow": {{ $proxy.Flow | quote }}{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end -}}}{{- else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ default "grpc" $proxy.ServiceName | quote }}}{{- end }}, {{ $common }}{{- if ne (default "" $proxy.RealityPublicKey) "" }}, "reality": { "enabled": true, "public_key": {{ $proxy.RealityPublicKey | quote }}{{- if ne (default "" $proxy.RealityShortId) "" }}, "short_id": {{ $proxy.RealityShortId | quote }}{{- end }}{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }} }{{- else if or (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "") $proxy.AllowInsecure (ne (default "" $proxy.Fingerprint) "") }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}}{{- end }} }
{{- else if eq $proxy.Type "vmess" -}}
    { "type": "vmess", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $password | quote }}, "security": "auto", {{ $common }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end -}}}{{- else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ default "grpc" $proxy.ServiceName | quote }}}{{- end }}{{- if or (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "") $proxy.AllowInsecure (ne (default "" $proxy.Fingerprint) "") }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}}{{- end }} }
{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") -}}
    { "type": "hysteria2", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, "obfs": { "type": "salamander", "password": {{ $proxy.ObfsPassword | quote }} }{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, "ports": {{ $proxy.HopPorts | quote }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, "hop_interval": {{ $proxy.HopInterval }}{{- end }}, {{ $common }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}} }
{{- else if eq $proxy.Type "tuic" -}}
    { "type": "tuic", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ default "" $proxy.ServerKey | quote }}, "password": {{ $password | quote }}{{- if $proxy.DisableSNI }}, "disable_sni": true{{- end }}{{- if $proxy.ReduceRtt }}, "reduce_rtt": true{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}, "udp_relay_mode": {{ $proxy.UDPRelayMode | quote }}{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}, "congestion_control": {{ $proxy.CongestionController | quote }}{{- end }}, {{ $common }}, "alpn": ["h3"], "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}} }
{{- else if eq $proxy.Type "anytls" -}}
    { "type": "anytls", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}, {{ $common }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}} }
{{- else if eq $proxy.Type "wireguard" -}}
    { "type": "wireguard", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "private_key": {{ default "" $proxy.ServerKey | quote }}, "peer_public_key": {{ default "" $proxy.RealityPublicKey | quote }}{{- if ne (default "" $proxy.Path) "" }}, "pre_shared_key": {{ $proxy.Path | quote }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, "local_address": [{{ $proxy.RealityServerAddr | quote }}]{{- end }}, {{ $common }} }
{{- else -}}
    { "type": "direct", "tag": {{ $proxy.Name | quote }}, {{ $common }} }
{{- end }}
    {{- end }},
    {{- end }}
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "auto_detect_interface": true, "final": "Proxy",
    "rules": [
      {"type": "logical", "mode": "or", "rules": [{"port": 53},{"protocol": "dns"}], "action": "hijack-dns"},
      {"rule_set": "geosite-category-ads-all", "outbound": "AdBlock"},
      {"clash_mode": "direct", "outbound": "direct"},
      {"clash_mode": "global", "outbound": "Proxy"},
      {"domain": ["clash.razord.top","yacd.metacubex.one","yacd.haishan.me","d.metacubex.one"], "outbound": "direct"},
      {"ip_is_private": true, "outbound": "direct"},
      {"rule_set": ["geoip-netflix","geosite-netflix"], "outbound": "Netflix"},
      {"rule_set": "geosite-disney", "outbound": "Disney Plus"},
      {"rule_set": "geosite-youtube", "outbound": "YouTube"},
      {"rule_set": "geosite-max", "outbound": "Max"},
      {"rule_set": "geosite-spotify", "outbound": "Spotify"},
      {"rule_set": ["geoip-apple","geosite-apple"], "outbound": "Apple"},
      {"rule_set": ["geoip-telegram","geosite-telegram"], "outbound": "Telegram"},
      {"rule_set": "geosite-openai", "outbound": "AI Suite"},
      {"rule_set": "geosite-microsoft", "outbound": "Microsoft"},
      {"rule_set": "geosite-tiktok", "outbound": "Tiktok"},
      {"rule_set": "geosite-private", "outbound": "direct"},
      {"rule_set": ["geoip-cn","geosite-cn"], "outbound": "Domestic"},
      {"rule_set": "geosite-geolocation-!cn", "outbound": "Others"}
    ],
    "rule_set": [
      {"tag": "geoip-cn","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs","download_detour": "direct"},
      {"tag": "geosite-cn","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs","download_detour": "direct"},
      {"tag": "geosite-private","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/private.srs","download_detour": "direct"},
      {"tag": "geosite-geolocation-!cn","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs","download_detour": "direct"},
      {"tag": "geosite-category-ads-all","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs","download_detour": "direct"},
      {"tag": "geoip-netflix","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/netflix.srs","download_detour": "direct"},
      {"tag": "geosite-netflix","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs","download_detour": "direct"},
      {"tag": "geosite-disney","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/disney.srs","download_detour": "direct"},
      {"tag": "geosite-youtube","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs","download_detour": "direct"},
      {"tag": "geosite-max","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/hbomax.srs","download_detour": "direct"},
      {"tag": "geosite-spotify","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/spotify.srs","download_detour": "direct"},
      {"tag": "geoip-apple","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo-lite/geoip/apple.srs","download_detour": "direct"},
      {"tag": "geosite-apple","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/apple.srs","download_detour": "direct"},
      {"tag": "geoip-telegram","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/telegram.srs","download_detour": "direct"},
      {"tag": "geosite-telegram","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/telegram.srs","download_detour": "direct"},
      {"tag": "geosite-openai","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs","download_detour": "direct"},
      {"tag": "geosite-microsoft","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/microsoft.srs","download_detour": "direct"},
      {"tag": "geosite-tiktok","type": "remote","format": "binary","url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/tiktok.srs","download_detour": "direct"}
    ]
  }
}
