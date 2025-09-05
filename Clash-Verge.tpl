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

{{- /* Create a comma-separated list of proxy names for use in proxy-groups */ -}}
{{- $proxyNamesList := list -}}
{{- range $_, $p := .Proxies -}}
    {{- $proxyNamesList = append $proxyNamesList ($p.Name | quote) -}}
{{- end -}}
{{- $proxyNames := join ", " $proxyNamesList -}}

# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $exp }}
port: 8888
socks-port: 8889
mixed-port: 8899
allow-lan: true
mode: Rule
log-level: info
external-controller: '127.0.0.1:6170'
secret: {{ .SiteName }}
experimental:
    ignore-resolve-fail: true
cfw-latency-url: 'http://cp.cloudflare.com/generate_204'
cfw-latency-timeout: 3000
cfw-latency-type: 1
cfw-conn-break-strategy: true
clash-for-android:
    ui-subtitle-pattern: ''
url-rewrite:
    - '^https?:\/\/(www.)?(g|google)\.cn https://www.google.com 302'
    - '^https?:\/\/(ditu|maps).google\.cn https://maps.google.com 302'
proxies:
{{- range $proxy := .Proxies }}
  {{- $pwd := $.UserInfo.Password -}}
  {{- $name := $proxy.Name | quote -}}
  {{- /* 修正 #1：明确使用 .Host 作为服务器地址，解决 server:[] 问题 */ -}}
  {{- $server := $proxy.Host -}}
  {{- if contains $server ":" -}}
    {{- $server = printf "[%s]" $server -}}
  {{- end -}}
  {{- $port := $proxy.Port -}}
  {{- $host := $proxy.Host -}}
  {{- $path := $proxy.Path | quote -}}
  {{- $sni := or $proxy.SNI $server -}}
  {{- $svc := $proxy.ServiceName | quote -}}
  {{- $common := "udp: true, tfo: true" -}}

  {{- if eq $proxy.Type "shadowsocks" }}
    - {name: {{$name}}, type: ss, server: {{$server}}, port: {{$port}}, cipher: {{ default "aes-128-gcm" $proxy.Method }}, password: {{$pwd}}, {{$common}}}
  {{- end }}

  {{- if eq $proxy.Type "vmess" }}
    - {name: {{$name}}, type: vmess, server: {{$server}}, port: {{$port}}, uuid: {{$pwd}}, alterId: 0, cipher: auto, tls: {{if $proxy.Security}}true{{else}}false{{end}}, skip-cert-verify: {{if $proxy.AllowInsecure}}true{{else}}false{{end}}, servername: {{$sni}}, network: {{$proxy.Transport}}, ws-opts: {path: {{$path}}, headers: {Host: {{$host}}}}, grpc-opts: {grpc-service-name: {{$svc}}}, {{$common}}}
  {{- end }}

  {{- if eq $proxy.Type "vless" }}
    - {name: {{$name}}, type: vless, server: {{$server}}, port: {{$port}}, uuid: {{$pwd}}, flow: {{$proxy.Flow}}, tls: {{if or $proxy.Security $proxy.RealityPublicKey}}true{{else}}false{{end}}, skip-cert-verify: {{if $proxy.AllowInsecure}}true{{else}}false{{end}}, servername: {{$sni}}, reality-opts: {public-key: {{$proxy.RealityPublicKey}}, short-id: {{$proxy.RealityShortId}}}, client-fingerprint: {{$proxy.Fingerprint}}, network: {{$proxy.Transport}}, ws-opts: {path: {{$path}}, headers: {Host: {{$host}}}}, grpc-opts: {grpc-service-name: {{$svc}}}, {{$common}}}
  {{- end }}

  {{- if eq $proxy.Type "trojan" }}
    - {name: {{$name}}, type: trojan, server: {{$server}}, port: {{$port}}, password: {{$pwd}}, sni: {{$sni}}, skip-cert-verify: {{if $proxy.AllowInsecure}}true{{else}}false{{end}}, network: {{$proxy.Transport}}, ws-opts: {path: {{$path}}, headers: {Host: {{$host}}}}, grpc-opts: {grpc-service-name: {{$svc}}}, {{$common}}}
  {{- end }}

  {{- if eq $proxy.Type "hysteria2" }}
    {{- /* 修正 #2：在这里对 obfs 参数进行安全判断 */ -}}
    {{- if and $proxy.Obfs $proxy.ObfsPassword }}
    - {name: {{$name}}, type: hysteria2, server: {{$server}}, port: {{$port}}, password: {{$pwd}}, sni: {{$sni}}, obfs: {{$proxy.Obfs}}, obfs-password: {{$proxy.ObfsPassword}}, hop-port: {{$proxy.HopPorts}}, skip-cert-verify: {{if $proxy.AllowInsecure}}true{{else}}false{{end}}, {{$common}}}
    {{- else }}
    - {name: {{$name}}, type: hysteria2, server: {{$server}}, port: {{$port}}, password: {{$pwd}}, sni: {{$sni}}, hop-port: {{$proxy.HopPorts}}, skip-cert-verify: {{if $proxy.AllowInsecure}}true{{else}}false{{end}}, {{$common}}}
    {{- end }}
  {{- end }}

  {{- if eq $proxy.Type "tuic" }}
    - {name: {{$name}}, type: tuic, server: {{$server}}, port: {{$port}}, uuid: {{$proxy.ServerKey}}, password: {{$pwd}}, congestion-controller: {{ $proxy.CongestionController | default "bbr" }}, sni: {{$sni}}, disable-sni: {{$proxy.DisableSNI}}, reduce-rtt: {{$proxy.ReduceRtt}}, udp-relay-mode: {{$proxy.UDPRelayMode | default "native"}}, skip-cert-verify: {{if $proxy.AllowInsecure}}true{{else}}false{{end}}, {{$common}}}
  {{- end }}
{{- end }}

proxy-groups:
  - { name: 🚀 Proxy, type: select, proxies: [🌏 Auto, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🍎 Apple, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🔍 Google, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🪟 Microsoft, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 📺 GlobalMedia, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 📟 Telegram, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🤖 AI, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🪙 Crypto, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🎮 Game, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🇨🇳 China, type: select, proxies: [🎯 Direct, 🚀 Proxy, {{ $proxyNames }}] }
  - { name: 🎯 Direct, type: select, proxies: [DIRECT], hidden: true }
  - { name: 🐠 Final, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🌏 Auto, type: url-test, proxies: [{{ $proxyNames }}] }

rules:
  - RULE-SET, Apple, 🍎 Apple
  - RULE-SET, Google, 🔍 Google
  - RULE-SET, Microsoft, 🪟 Microsoft
  - RULE-SET, Github, 🪟 Microsoft
  - RULE-SET, HBO, 📺 GlobalMedia
  - RULE-SET, Disney, 📺 GlobalMedia
  - RULE-SET, TikTok, 📺 GlobalMedia
  - RULE-SET, Netflix, 📺 GlobalMedia
  - RULE-SET, GlobalMedia, 📺 GlobalMedia
  - RULE-SET, Telegram, 📟 Telegram
  - RULE-SET, OpenAI, 🤖 AI
  - RULE-SET, Gemini, 🤖 AI
  - RULE-SET, Copilot, 🤖 AI
  - RULE-SET, Claude, 🤖 AI
  - RULE-SET, Crypto, 🪙 Crypto
  - RULE-SET, Cryptocurrency, 🪙 Crypto
  - RULE-SET, Game, 🎮 Game
  - RULE-SET, Global, 🚀 Proxy
  - RULE-SET, ChinaMax, 🇨🇳 China
  - RULE-SET, Lan, 🎯 Direct
  - GEOIP, CN, 🇨🇳 China
  - MATCH, 🐠 Final

rule-providers:
  Apple:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Apple/Apple_Classical_No_Resolve.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google_No_Resolve.yaml
    interval: 86400
  Microsoft:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Microsoft/Microsoft.yaml
    interval: 86400
  Github:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GitHub/GitHub.yaml
    interval: 86400
  HBO:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/HBO/HBO.yaml
    interval: 86400
  Disney:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Disney/Disney.yaml
    interval: 86400
  TikTok:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/TikTok/TikTok.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Netflix/Netflix.yaml
    interval: 86400
  GlobalMedia:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GlobalMedia/GlobalMedia_Classical_No_Resolve.yaml
    interval: 86400
  Telegram:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Telegram/Telegram_No_Resolve.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/OpenAI/OpenAI.yaml
    interval: 86400
  Gemini:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Gemini/Gemini.yaml
    interval: 86400
  Copilot:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Copilot/Copilot.yaml
    interval: 86400
  Claude:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Claude/Claude.yaml
    interval: 86400
  Crypto:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Crypto/Crypto.yaml
    interval: 86400
  Cryptocurrency:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Cryptocurrency/Cryptocurrency.yaml
    interval: 86400
  Game:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Game/Game.yaml
    interval: 86400
  Global:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global_Classical_No_Resolve.yaml
    interval: 86400
  ChinaMax:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMax/ChinaMax_Classical_No_Resolve.yaml
    interval: 86400
  Lan:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Lan/Lan.yaml
    interval: 86400
