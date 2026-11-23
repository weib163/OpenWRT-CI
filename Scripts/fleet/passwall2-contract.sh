#!/bin/bash
# 检查 PassWall 2 源码里还有没有 fleet-agent 要写的配置项。
# PassWall 2 改了字段名时，编译直接失败，而不是编出一个同步脚本悄悄失效的固件。
# 用法：passwall2-contract.sh luci-app-passwall2 目录
set -euo pipefail

DIR="${1:-}"
[ -d "$DIR" ] || { echo "::error::找不到 PassWall 2 源码目录：$DIR"; exit 1; }

missing=()
need() {  # need 说明 字符串...：每个字符串都得在源码里出现
	local what="$1" s
	shift
	for s in "$@"; do
		grep -rqF -- "$s" "$DIR" || missing+=("$what：$s")
	done
}

need "sing-box 节点" '"reality_publicKey"' '"reality_shortId"' '"tls_serverName"' '"tls_allowInsecure"' \
	'"utls"' '"fingerprint"' '"ws_path"' '"ws_host"' '"flow"' '"alpn"' '"domain_strategy"' '"ipv4_only"'
need "自动选择节点" '"_urltest"' '"urltest_node"' '"urltest_url"' '"urltest_interval"' '"urltest_tolerance"' \
	'"urltest_idle_timeout"' '"urltest_interrupt_exist_connections"' '"node_add_mode"'
need "分流" '"_shunt"' '"shunt_group"' '"default_node"' '"shunt_rules"' '"domain_list"' '"ip_list"' \
	'"_direct"' '"_blackhole"'
need "全局设置" '"remote_dns_query_strategy"' '"direct_dns_query_strategy"' '"UseIPv4"' '"ipv6_tproxy"' \
	"start_daemon"
need "默认分流规则" "config shunt_rules 'CN'" "config shunt_rules 'DirectFront'" "config shunt_rules 'ProxyFront'" \
	"config shunt_rules 'DirectGame'" "config shunt_rules 'ProxyGame'" "option group 'CN'"

if [ "${#missing[@]}" -gt 0 ]; then
	echo "::error::PassWall 2 的配置字段变了，fleet-agent 需要先适配再编译："
	printf '  %s\n' "${missing[@]}"
	exit 1
fi
echo "PassWall 2 配置字段检查通过。"
