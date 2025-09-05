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
  {{- if or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "vless") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") (eq $proxy.Type "tuic") (eq $proxy.Type "wireguard") (eq $proxy.Type "shadowtls") -}}
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
Sing-box 1.12+ Configuration
-->
{
  "log": {
    "level": "info",
    "timestamp": true,
    "output": "box.log"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "cache.db",
      "cache_id": "my_profile",
      "store_fakeip": false,
      "store_rdrc": false,
      "rdrc_timeout": "7d"
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
      "external_ui_download_detour": "direct",
      "secret": "",
      "default_mode": "rule",
      "store_mode": true,
      "store_selected": true,
      "store_fakeip": false,
      "cache_file": "clash.db",
      "cache_id": "clash_profile"
    },
    "v2ray_api": {
      "listen": "127.0.0.1:8080",
      "stats": {
        "enabled": true,
        "inbounds": ["tun-in", "mixed-in"],
        "outbounds": ["Proxy", "direct", "block"],
        "users": []
      }
    }
  },
  "dns": {
    "servers": [
      {
        "tag": "dns_proxy",
        "address": "tls://1.1.1.1",
        "address_resolver": "dns_resolver",
        "strategy": "prefer_ipv4",
        "detour": "Proxy"
      },
      {
        "tag": "dns_direct",
        "address": "https://223.5.5.5/dns-query",
        "address_resolver": "dns_resolver",
        "strategy": "prefer_ipv4",
        "detour": "direct"
      },
      {
        "tag": "dns_fakeip",
        "address": "fakeip"
      },
      {
        "tag": "dns_resolver",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "dns_resolver"
      },
      {
        "clash_mode": "direct",
        "server": "dns_direct"
      },
      {
        "clash_mode": "global",
        "server": "dns_proxy"
      },
      {
        "query_type": ["A", "AAAA"],
        "rule_set": ["geosite-cn", "geosite-private"],
        "server": "dns_direct"
      },
      {
        "query_type": ["A", "AAAA"],
        "rule_set": "geosite-geolocation-!cn",
        "server": "dns_fakeip"
      }
    ],
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    },
    "final": "dns_direct",
    "strategy": "prefer_ipv4",
    "disable_cache": false,
    "disable_expire": false,
    "independent_cache": false,
    "reverse_mapping": false
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  },
  "inbounds": [
    {
      "tag": "tun-in",
      "type": "tun",
      "interface_name": "utun-sing-box",
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fdfe:dcba:9876::1/126",
      "mtu": 9000,
      "gso": false,
      "auto_route": true,
      "strict_route": true,
      "stack": "system",
      "endpoint_independent_nat": false,
      "sniff": true,
      "sniff_override_destination": false,
      "domain_strategy": "prefer_ipv4",
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 7890
        }
      }
    },
    {
      "tag": "mixed-in",
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 7890,
      "sniff": true,
      "sniff_override_destination": false,
      "domain_strategy": "prefer_ipv4",
      "set_system_proxy": false
    }
  ],
  "outbounds": [
    {"tag": "Proxy", "type": "selector", "outbounds": ["Auto - UrlTest", "direct"{{ $proxyNames }}], "default": "Auto - UrlTest"},
    {"tag": "Domestic", "type": "selector", "outbounds": ["direct", "Proxy"{{ $proxyNames }}], "default": "direct"},
    {"tag": "Others", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "AI Suite", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Netflix", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Disney Plus", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "YouTube", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Max", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Spotify", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Apple", "type": "selector", "outbounds": ["direct", "Proxy"{{ $proxyNames }}], "default": "direct"},
    {"tag": "Telegram", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Microsoft", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "Tiktok", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}], "default": "Proxy"},
    {"tag": "AdBlock", "type": "selector", "outbounds": ["block", "direct", "Proxy"], "default": "block"},
    {{- if gt (len $supportedProxies) 0 }}
    {"tag": "Auto - UrlTest", "type": "urltest", "outbounds": [{{ $proxyNames | trimPrefix ", " }}], "url": "http://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50, "idle_timeout": "30m", "interrupt_exist_connections": false}
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

{{- $common := `"tcp_fast_open": false, "tcp_multi_path": false, "udp_fragment": true, "connect_timeout": "5s", "udp_timeout": "5m", "domain_strategy": "prefer_ipv4"` -}}

{{- if eq $proxy.Type "shadowsocks" -}}
  {{- $method := default "aes-128-gcm" $proxy.Method -}}
    { "type": "shadowsocks", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "method": {{ $method | quote }}, "password": {{ $password | quote }}, {{ $common }}{{- if ne (default "" $proxy.Plugin) "" }}, "plugin": {{ $proxy.Plugin | quote }}{{- if ne (default "" $proxy.PluginOpts) "" }}, "plugin_opts": {{ $proxy.PluginOpts | quote }}{{- end }}{{- end }} }
{{- else if eq $proxy.Type "trojan" -}}
    { "type": "trojan", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end }}, "max_early_data": 0, "early_data_header_name": "Sec-WebSocket-Protocol"}{{- else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ default "grpc" $proxy.ServiceName | quote }}, "idle_timeout": "15s", "ping_timeout": "15s", "permit_without_stream": false}{{- end }}, {{ $common }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}, "alpn": ["h2", "http/1.1"]} }
{{- else if eq $proxy.Type "vless" -}}
    { "type": "vless", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $password | quote }}{{- if ne (default "" $proxy.Flow) "" }}, "flow": {{ $proxy.Flow | quote }}{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end }}, "max_early_data": 0, "early_data_header_name": "Sec-WebSocket-Protocol"}{{- else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ default "grpc" $proxy.ServiceName | quote }}, "idle_timeout": "15s", "ping_timeout": "15s", "permit_without_stream": false}{{- end }}, {{ $common }}{{- if ne (default "" $proxy.RealityPublicKey) "" }}, "reality": { "enabled": true, "public_key": {{ $proxy.RealityPublicKey | quote }}{{- if ne (default "" $proxy.RealityShortId) "" }}, "short_id": {{ $proxy.RealityShortId | quote }}{{- end }}{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }} }{{- else if or (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "") $proxy.AllowInsecure (ne (default "" $proxy.Fingerprint) "") }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}, "alpn": ["h2", "http/1.1"]}{{- end }} }
{{- else if eq $proxy.Type "vmess" -}}
    { "type": "vmess", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $password | quote }}, "security": "auto", "global_padding": false, "authenticated_length": true, {{ $common }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end }}, "max_early_data": 0, "early_data_header_name": "Sec-WebSocket-Protocol"}{{- else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ default "grpc" $proxy.ServiceName | quote }}, "idle_timeout": "15s", "ping_timeout": "15s", "permit_without_stream": false}{{- end }}{{- if or (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "") $proxy.AllowInsecure (ne (default "" $proxy.Fingerprint) "") }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}, "alpn": ["h2", "http/1.1"]}{{- end }} }
{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") -}}
    { "type": "hysteria2", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, "obfs": { "type": "salamander", "password": {{ $proxy.ObfsPassword | quote }} }{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, "ports": {{ $proxy.HopPorts | quote }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, "hop_interval": {{ $proxy.HopInterval }}{{- end }}, {{ $common }}, "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}, "alpn": ["h3"]}, "brutal": {"enabled": false} }
{{- else if eq $proxy.Type "tuic" -}}
    { "type": "tuic", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ default "" $proxy.ServerKey | quote }}, "password": {{ $password | quote }}{{- if $proxy.DisableSNI }}, "disable_sni": true{{- end }}{{- if $proxy.ReduceRtt }}, "reduce_rtt": true{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}, "udp_relay_mode": {{ $proxy.UDPRelayMode | quote }}{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}, "congestion_control": {{ $proxy.CongestionController | quote }}{{- end }}, {{ $common }}, "alpn": ["h3"], "tls": {"enabled": true{{- if ne $sni "" }}, "server_name": {{ $sni | quote }}{{- end }}{{- if $proxy.AllowInsecure }}, "insecure": true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{- end }}}, "zero_rtt_handshake": false, "heartbeat": "10s" }
{{- else if eq $proxy.Type "wireguard" -}}
    { "type": "wireguard", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "private_key": {{ default "" $proxy.ServerKey | quote }}, "peer_public_key": {{ default "" $proxy.RealityPublicKey | quote }}{{- if ne (default "" $proxy.Path) "" }}, "pre_shared_key": {{ $proxy.Path | quote }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, "local_address": [{{ $proxy.RealityServerAddr | quote }}]{{- end }}, {{ $common }}, "mtu": 1408, "gso": false, "fake_packets": "1-3" }
{{- else if eq $proxy.Type "shadowtls" -}}
    { "type": "shadowtls", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "version": {{ default 3 $proxy.Version }}, "password": {{ $password | quote }}{{- if ne (default "" $proxy.Host) "" }}, "tls": {"enabled": true, "server_name": {{ $proxy.Host | quote }}}{{- end }}, {{ $common }} }
{{- else -}}
    { "type": "direct", "tag": {{ $proxy.Name | quote }}, {{ $common }} }
{{- end }}
    {{- end }},
    {{- end }}
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "dns", "tag": "dns-out"}
  ],
  "route": {
    "geoip": {
      "path": "geoip.db",
      "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
      "download_detour": "direct"
    },
    "geosite": {
      "path": "geosite.db",
      "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
      "download_detour": "direct"
    },
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "clash_mode": "direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "global",
        "outbound": "Proxy"
      },
      {
        "domain": ["clash.razord.top","yacd.metacubex.one","yacd.haishan.me","d.metacubex.one"],
        "outbound": "direct"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-category-ads-all",
        "outbound": "AdBlock"
      },
      {
        "rule_set": ["geoip-netflix","geosite-netflix"],
        "outbound": "Netflix"
      },
      {
        "rule_set": "geosite-disney",
        "outbound": "Disney Plus"
      },
      {
        "rule_set": "geosite-youtube",
        "outbound": "YouTube"
      },
      {
        "rule_set": "geosite-max",
        "outbound": "Max"
      },
      {
        "rule_set": "geosite-spotify",
        "outbound": "Spotify"
      },
      {
        "rule_set": ["geoip-apple","geosite-apple"],
        "outbound": "Apple"
      },
      {
        "rule_set": ["geoip-telegram","geosite-telegram"],
        "outbound": "Telegram"
      },
      {
        "rule_set": "geosite-openai",
        "outbound": "AI Suite"
      },
      {
        "rule_set": "geosite-microsoft",
        "outbound": "Microsoft"
      },
      {
        "rule_set": "geosite-tiktok",
        "outbound": "Tiktok"
      },
      {
        "rule_set": "geosite-private",
        "outbound": "direct"
      },
      {
        "rule_set": ["geoip-cn","geosite-cn"],
        "outbound": "Domestic"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "Others"
      }
    ],
    "rule_set": [
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-private",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/private.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-geolocation-!cn",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geoip-netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/netflix.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-disney",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/disney.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-max",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/hbomax.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-spotify",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/spotify.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geoip-apple",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo-lite/geoip/apple.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-apple",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/apple.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geoip-telegram",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/telegram.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-telegram",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/telegram.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-microsoft",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/microsoft.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-tiktok",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/tiktok.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      }
    ],
    "final": "Proxy",
    "auto_detect_interface": true,
    "override_android_vpn": false,
    "default_interface": "",
    "default_mark": 0
  }
}
