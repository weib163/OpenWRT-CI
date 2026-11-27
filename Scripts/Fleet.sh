#!/bin/bash
# 把集群管理相关的东西写进固件：
#   1. fleet-agent 路由器同步脚本（开机跑一次，之后每 10 分钟一次；同步时顺带上报 CPU 温度、版本和出错情况），
#      以及编译号（批量升级认版本用）
#   2. fleet-agent --health 每分钟一次：超温告警开始/解除时马上上报，屏幕上插播提示（断网、到期、留言等）
#   3. 雅典娜前面板屏幕的出厂设置（时间、路由器编号、温度轮播，超温闪烁告警，夜间调暗）
#   4. 升级包验签公钥（GitHub 仓库变量 FW_SIGN_PUBKEY）；没有公钥的固件不接受远程升级
#   5. 只用 IPv4：WAN 不拿 IPv6、局域网不发 IPv6 地址、DNS 不回 IPv6 记录、局域网的 IPv6 流量一律拒绝
#   6. 复位键：短按重启；长按 30 秒以上才恢复出厂（防止客户随手一按把配置清空）
#   7. 网页终端 ttyd 改为所有接口监听，Headscale 内网才能打开（外网仍被防火墙挡住）
#   8. 可选：设置 root 密码（GitHub Secret ROOT_PW_HASH，只在密码为空时生效）
#   9. 代理：sing-box 由 fleet-proxy 服务运行（家里设备：国内直连，海外 → VPN 节点；服务器再把每个客户
#      转到他自己的住宅 IP，住宅 IP 的账号密码不进路由器），国内名单（geosite-cn / geoip-cn）编译时打包；
#      防火墙不许家里设备绕开代理直接上网（断网保护）
#  10. WiFi：每台独立的名字（前缀-设备码）和密码；带了种子（GitHub Secret WIFI_SEED）时密码每台固定，恢复出厂不变
#  11. 升级时保留 fleet 的设置和上次的代理配置（升级后马上用上，不用等第一次同步）
#  12. 上网设置页：家里打开 http://路由器地址 看状态、收款码、点“我已付款”，用 WiFi 密码登录后改宽带设置、
#      手动升级（只认签过名的升级包）。完整后台（LuCI）、SSH、网页终端在家里打不开，只能经 Headscale 内网
#  13. 去掉 UPnP（家里设备不能自己在路由器上开端口、绕开代理收外网连接）
#  14. 可选：只认管理员的 SSH 公钥（GitHub 仓库变量 ADMIN_SSH_PUBKEY），不再接受密码登录 SSH
# 在 ./wrt/ 目录下运行。
set -e

FILES_DIR="./files"
SRC="$GITHUB_WORKSPACE/Scripts/fleet"
mkdir -p "$FILES_DIR/usr/bin" "$FILES_DIR/etc/config" "$FILES_DIR/etc/init.d" "$FILES_DIR/etc/uci-defaults" \
	"$FILES_DIR/etc/fleet" "$FILES_DIR/etc/rc.button" "$FILES_DIR/usr/share/fleet" "$FILES_DIR/lib/upgrade/keep.d"

install -m 755 "$SRC/fleet-agent.lua" "$FILES_DIR/usr/bin/fleet-agent"
install -m 644 "$SRC/fleet-setup.lua" "$FILES_DIR/usr/share/fleet/fleet-setup.lua"
# 固件版本号 + 编译日期，例如 1.1.0-26.11.23：fleet-agent 同步时报给管理页“固件”一栏
if [ -n "$WRT_VER" ]; then
	printf '%s-%s\n' "$WRT_VER" "${WRT_DATE%%-*}" > "$FILES_DIR/etc/fleet-firmware"
	echo "固件版本：$(cat "$FILES_DIR/etc/fleet-firmware")"
fi
# 屏幕出厂设置：只有装了屏幕驱动的雅典娜会用到，其他机型开机时自己跳过
install -m 755 "$SRC/screen-defaults.sh" "$FILES_DIR/etc/uci-defaults/94-fleet-screen"

# 编译号：和发布页文件名里的日期一致，例如 26.11.24-01.23.45
if [[ "$WRT_DATE" =~ ^[0-9]{2}\.[0-9]{2}\.[0-9]{2}-[0-9]{2}\.[0-9]{2}\.[0-9]{2}$ ]]; then
	printf '%s\n' "$WRT_DATE" > "$FILES_DIR/etc/fleet/build_id"
	echo "编译号：$WRT_DATE"
else
	echo "::warning::WRT_DATE 格式不对（$WRT_DATE），固件没有编译号，不能参加批量升级"
fi

# 升级包验签公钥（signify/usign 格式：两行，第二行是 base64）
PUBKEY="$(printf '%s' "$FW_SIGN_PUBKEY" | tr -d '\r')"
if [ -n "$PUBKEY" ]; then
	if [ "$(printf '%s\n' "$PUBKEY" | grep -c '')" -ne 2 ] \
		|| ! printf '%s\n' "$PUBKEY" | head -n 1 | grep -q '^untrusted comment: ' \
		|| ! printf '%s\n' "$PUBKEY" | tail -n 1 | grep -Eq '^[A-Za-z0-9+/]{40,60}={0,2}$'; then
		echo "::error::FW_SIGN_PUBKEY 格式不对：应该是 ota-keygen.sh 显示的两行公钥"
		exit 1
	fi
	printf '%s\n' "$PUBKEY" > "$FILES_DIR/etc/fleet/fw-sign.pub"
	chmod 644 "$FILES_DIR/etc/fleet/fw-sign.pub"
	echo "升级验签公钥已写入固件。"
else
	echo "FW_SIGN_PUBKEY 未设置：这版固件不接受远程升级（以后升级要手动刷）。"
fi

# WiFi 名字前缀：工作流里的 WRT_SSID（只留字母、数字、- 和 _）
WIFI_PREFIX=$(printf '%s' "${WRT_SSID:-WiFi}" | tr -cd 'A-Za-z0-9_-' | cut -c1-20)
[ -n "$WIFI_PREFIX" ] || WIFI_PREFIX=WiFi

cat > "$FILES_DIR/etc/config/fleet" <<EOF
config agent 'main'
	option enabled '1'
	# 留空：自动找带 tag:fleet 标签的下发服务器
	option server ''
	option port '8080'
	option timeout '20'
	# CPU 超过这个温度（℃）算超温：屏幕闪烁告警、马上报给下发服务；降到低 3℃ 以下解除
	option temp_alert '90'
	# 0 = 不接受批量升级
	option ota '1'
	# WiFi 名字 = 前缀-设备码。另有 wifi 一项由脚本记录：pending 待设置，auto 按种子设好，random 随机设好，kept 老机器保持原样
	option wifi_prefix '$WIFI_PREFIX'
EOF
echo "WiFi 名字前缀：$WIFI_PREFIX"

# WiFi 密码种子：密码 = 种子 + MAC 算出来，每台固定、恢复出厂不变。种子要和签名私钥一样备份好
SEED="$(printf '%s' "$WIFI_SEED" | tr -d '\r\n')"
if [ -n "$SEED" ]; then
	if [ "${#SEED}" -lt 16 ] || printf '%s' "$SEED" | grep -q '[[:space:]]'; then
		echo "::error::WIFI_SEED 至少 16 位，不能有空格"
		exit 1
	fi
	printf '%s\n' "$SEED" > "$FILES_DIR/etc/fleet/wifi-seed"
	chmod 600 "$FILES_DIR/etc/fleet/wifi-seed"
	echo "WiFi 密码种子已写入固件。"
else
	echo "::warning::WIFI_SEED 未设置：这版固件的 WiFi 密码每次恢复出厂都会随机换"
fi

# 国内名单（sing-box 规则集）：编译时下载打包，跟着固件更新。下不来就停下，不能出一版国内也走代理的固件
fetch_rule() {
	local name=$1 url=$2 out="$FILES_DIR/usr/share/fleet/$1.srs"
	curl -fsSL --retry 3 --connect-timeout 20 -o "$out" "$url" || { echo "::error::$name 下载失败"; exit 1; }
	if [ "$(stat -c %s "$out")" -lt 10000 ] || [ "$(head -c 3 "$out")" != "SRS" ]; then
		echo "::error::$name 内容不对（太小或者不是 sing-box 规则集）"
		exit 1
	fi
	echo "国内名单 $name：$(stat -c %s "$out") 字节"
}
fetch_rule geosite-cn https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs
fetch_rule geoip-cn https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs

# 代理服务：配置由 fleet-agent 生成（/etc/fleet/proxy.json）；进程退出 5 秒后自动拉起。
# sing-box 包自带的 sing-box 服务不用（第一次开机时关掉）。
cat > "$FILES_DIR/etc/init.d/fleet-proxy" <<'EOF'
#!/bin/sh /etc/rc.common
# 家里设备的代理：国内直连，海外 → VPN 节点 → 住宅 IP。日志：logread -e sing-box
USE_PROCD=1
START=90
STOP=10
CONF=/etc/fleet/proxy.json

start_service() {
	/usr/bin/fleet-agent --proxy-init
	[ -s "$CONF" ] || return 1
	mkdir -p /tmp/fleet-proxy
	procd_open_instance
	procd_set_param command /usr/bin/sing-box run -c "$CONF" -D /tmp/fleet-proxy
	procd_set_param respawn 3600 5 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param limits nofile="65535 65535"
	procd_close_instance
}
EOF
chmod 755 "$FILES_DIR/etc/init.d/fleet-proxy"

cat > "$FILES_DIR/etc/uci-defaults/92-fleet-proxy" <<'EOF'
#!/bin/sh
# 断网保护：家里设备不许绕开代理直接上网。代理停了家里就上不了网，不会漏出真实 IP。
# 访问光猫后台这类内网地址不受影响；路由器自己的流量（Tailscale、同步、对时）不经过这里。
uci -q delete firewall.fleet_lan_private
uci -q delete firewall.fleet_killswitch
uci set firewall.fleet_lan_private=rule
uci set firewall.fleet_lan_private.name='fleet-lan-to-wan-private'
uci set firewall.fleet_lan_private.src='lan'
uci set firewall.fleet_lan_private.dest='wan'
uci set firewall.fleet_lan_private.family='ipv4'
uci set firewall.fleet_lan_private.proto='all'
uci add_list firewall.fleet_lan_private.dest_ip='10.0.0.0/8'
uci add_list firewall.fleet_lan_private.dest_ip='172.16.0.0/12'
uci add_list firewall.fleet_lan_private.dest_ip='192.168.0.0/16'
uci set firewall.fleet_lan_private.target='ACCEPT'
uci set firewall.fleet_killswitch=rule
uci set firewall.fleet_killswitch.name='fleet-no-direct-internet'
uci set firewall.fleet_killswitch.src='lan'
uci set firewall.fleet_killswitch.dest='wan'
uci set firewall.fleet_killswitch.family='ipv4'
uci set firewall.fleet_killswitch.proto='all'
uci set firewall.fleet_killswitch.target='REJECT'
uci commit firewall
[ -x /etc/init.d/sing-box ] && /etc/init.d/sing-box disable
/etc/init.d/fleet-proxy enable
exit 0
EOF

# WiFi 名字和密码：刷机或恢复出厂后第一次开机设置（无线配置还没生成的话，fleet-agent --health 每分钟补）
cat > "$FILES_DIR/etc/uci-defaults/93-fleet-wifi" <<'EOF'
#!/bin/sh
/usr/bin/fleet-agent --wifi-init
exit 0
EOF

# 升级时保留：fleet 设置（WiFi 状态在里面）、上次的下发配置和代理配置、检测弹窗的按设备记录（丢了会每台设备重弹一次）。别的 /etc/fleet 文件跟着新固件走
cat > "$FILES_DIR/lib/upgrade/keep.d/fleet" <<'EOF'
/etc/config/fleet
/etc/fleet/last.json
/etc/fleet/state.json
/etc/fleet/proxy.json
/etc/fleet/portal-clients.json
EOF

cat > "$FILES_DIR/etc/init.d/fleet-agent" <<'EOF'
#!/bin/sh /etc/rc.common
# 开机后等 Tailscale 连上再同步一次；之后由 cron 每 10 分钟同步
START=99
start() {
	( sleep 120; /usr/bin/fleet-agent --now ) >/dev/null 2>&1 &
}
EOF
chmod 755 "$FILES_DIR/etc/init.d/fleet-agent"

cat > "$FILES_DIR/etc/uci-defaults/97-fleet-agent" <<'EOF'
#!/bin/sh
/etc/init.d/fleet-agent enable
touch /etc/crontabs/root
grep -q '/usr/bin/fleet-agent$' /etc/crontabs/root || echo '*/10 * * * * PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/fleet-agent' >> /etc/crontabs/root
grep -q '/usr/bin/fleet-agent --health' /etc/crontabs/root || echo '* * * * * PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/fleet-agent --health' >> /etc/crontabs/root
/etc/init.d/cron enable
exit 0
EOF

# 只用 IPv4。翻墙只走 IPv4：客户设备拿不到 IPv6 地址，也就不会绕过代理用 IPv6 直连出去。
cat > "$FILES_DIR/etc/uci-defaults/94-fleet-ipv4-only" <<'EOF'
#!/bin/sh
uci -q delete network.globals.ula_prefix
uci -q delete network.wan6
uci -q get network.wan >/dev/null && uci set network.wan.ipv6='0'
uci -q delete network.lan.ip6assign
if uci -q get dhcp.lan >/dev/null; then
	uci set dhcp.lan.ra='disabled'
	uci set dhcp.lan.dhcpv6='disabled'
	uci set dhcp.lan.ndp='disabled'
fi
uci -q get dhcp.odhcpd >/dev/null && uci set dhcp.odhcpd.maindhcp='0'
uci -q get dhcp.@dnsmasq[0] >/dev/null && uci set dhcp.@dnsmasq[0].filter_aaaa='1'
for zone in $(uci -q show firewall | sed -n 's/^firewall\.\([^.=]*\)=zone$/\1/p'); do
	uci -q del_list firewall."$zone".network='wan6'
done
if ! uci -q get firewall.fleet_no_ipv6 >/dev/null; then
	uci set firewall.fleet_no_ipv6=rule
	uci set firewall.fleet_no_ipv6.name='fleet-block-ipv6-from-lan'
	uci set firewall.fleet_no_ipv6.src='lan'
	uci set firewall.fleet_no_ipv6.dest='*'
	uci set firewall.fleet_no_ipv6.family='ipv6'
	uci set firewall.fleet_no_ipv6.proto='all'
	uci set firewall.fleet_no_ipv6.target='REJECT'
fi
uci commit network
uci commit dhcp
uci commit firewall
/etc/init.d/odhcpd disable 2>/dev/null
exit 0
EOF

# 复位键：按住不到 30 秒松开 = 重启；30 秒以上 = 恢复出厂（LED 进入安全模式样式时就可以松手了）。
# 客户随手一按只会重启。真要恢复出厂，按住 30 秒；恢复后路由器会用固件里的登录密钥自动重新连上，
# 在管理页“待开通”里出现，点一下换绑就恢复服务。
cat > "$FILES_DIR/etc/rc.button/reset" <<'EOF'
#!/bin/sh

. /lib/functions.sh

OVERLAY="$( grep ' /overlay ' /proc/mounts )"

case "$ACTION" in
pressed)
	[ -z "$OVERLAY" ] && return 0

	return 30
;;
timeout)
	. /etc/diag.sh
	set_state failsafe
;;
released)
	if [ "$SEEN" -ge 30 -a -n "$OVERLAY" ]
	then
		echo "FACTORY RESET" > /dev/console
		factoryreset -y && reboot &
	else
		echo "REBOOT" > /dev/console
		sync
		reboot
	fi
;;
esac

return 0
EOF
chmod 755 "$FILES_DIR/etc/rc.button/reset"

# ttyd 默认只在 LAN 口监听，Headscale 内网打不开网页终端；改成所有接口监听。
# WAN 方向的入站默认被防火墙拒绝，tailscale0 单独一个区（见 Tailscale.sh）。
cat > "$FILES_DIR/etc/uci-defaults/96-ttyd-all-interfaces" <<'EOF'
#!/bin/sh
uci -q get ttyd.@ttyd[0] >/dev/null || exit 0
uci -q delete ttyd.@ttyd[0].interface
uci commit ttyd
exit 0
EOF

# 上网设置页：独立的 uhttpd（81 端口），家里打开 http://路由器地址（80 端口）由防火墙转过来
mkdir -p "$FILES_DIR/www/fleet-setup/cgi-bin" "$FILES_DIR/www/fleet-setup/pay"
install -m 644 "$SRC/setup-page.html" "$FILES_DIR/www/fleet-setup/index.html"
install -m 644 "$SRC/portal.html" "$FILES_DIR/www/fleet-setup/portal.html"
cat > "$FILES_DIR/www/fleet-setup/cgi-bin/api" <<'EOF'
#!/usr/bin/lua
dofile("/usr/share/fleet/fleet-setup.lua").cgi()
EOF
chmod 755 "$FILES_DIR/www/fleet-setup/cgi-bin/api"

cat > "$FILES_DIR/etc/uci-defaults/98-fleet-setup" <<'EOF'
#!/bin/sh
# 上网设置页（81 端口，只放 /www/fleet-setup）
uci -q delete uhttpd.fleetsetup
uci set uhttpd.fleetsetup=uhttpd
uci add_list uhttpd.fleetsetup.listen_http='0.0.0.0:81'
uci set uhttpd.fleetsetup.home='/www/fleet-setup'
uci set uhttpd.fleetsetup.cgi_prefix='/cgi-bin'
uci set uhttpd.fleetsetup.index_page='index.html'
uci set uhttpd.fleetsetup.max_requests='4'
uci set uhttpd.fleetsetup.max_connections='16'
uci set uhttpd.fleetsetup.script_timeout='300'
uci set uhttpd.fleetsetup.network_timeout='60'
uci set uhttpd.fleetsetup.http_keepalive='0'
uci set uhttpd.fleetsetup.tcp_keepalive='1'
uci set uhttpd.fleetsetup.no_dirlists='1'
uci set uhttpd.fleetsetup.rfc1918_filter='1'
uci set uhttpd.fleetsetup.redirect_https='0'
# 连通性探测（手机连 WiFi 时发的那几个）没有对应的文件：uhttpd 按这个地址找处理程序，
# 探测请求就到了 /cgi-bin/api?a=probe，由它决定弹检测页还是回探测要的成功响应
uci set uhttpd.fleetsetup.error_page='/cgi-bin/api?a=probe'
uci commit uhttpd

# 家里打开 http://路由器地址（80 端口）→ 上网设置页（81 端口）。内网地址改了 fleet-agent 会跟着改这条
LAN_IP=$(uci -q get network.lan.ipaddr | cut -d/ -f1)
[ -n "$LAN_IP" ] || LAN_IP=192.168.10.1
uci -q delete firewall.fleet_setup_redirect
uci set firewall.fleet_setup_redirect=redirect
uci set firewall.fleet_setup_redirect.name='fleet-setup-page'
uci set firewall.fleet_setup_redirect.src='lan'
uci set firewall.fleet_setup_redirect.family='ipv4'
uci set firewall.fleet_setup_redirect.proto='tcp'
uci set firewall.fleet_setup_redirect.src_dip="$LAN_IP"
uci set firewall.fleet_setup_redirect.src_dport='80'
uci set firewall.fleet_setup_redirect.dest_port='81'
uci set firewall.fleet_setup_redirect.target='DNAT'

# 家里打不开完整后台（80/443）、SSH（22）、网页终端（7681）：只能经 Headscale 内网（tailscale 区不受影响）
uci -q delete firewall.fleet_lan_no_admin
uci set firewall.fleet_lan_no_admin=rule
uci set firewall.fleet_lan_no_admin.name='fleet-lan-no-admin'
uci set firewall.fleet_lan_no_admin.src='lan'
uci set firewall.fleet_lan_no_admin.proto='tcp'
uci set firewall.fleet_lan_no_admin.dest_port='22 80 443 7681'
uci set firewall.fleet_lan_no_admin.target='REJECT'
uci commit firewall

# 去掉 UPnP：别的配置万一带进来，也不让它运行
if [ -x /etc/init.d/miniupnpd ]; then
	/etc/init.d/miniupnpd disable
	uci -q set upnpd.config.enabled='0' && uci commit upnpd
fi
exit 0
EOF

# 只认管理员的 SSH 公钥（可选）。SSH 本来就只能经 Headscale 内网连，这是再加一道
SSH_LINES=$(printf '%s\n' "$ADMIN_SSH_PUBKEY" | tr -d '\r' | grep -v '^[[:space:]]*$' || true)
SSH_KEYS=$(printf '%s\n' "$SSH_LINES" | grep -E '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{60,800}( [^[:cntrl:]]{0,100})?$' || true)
if [ -n "$SSH_LINES" ] && [ "$SSH_KEYS" != "$SSH_LINES" ]; then
	echo "::error::ADMIN_SSH_PUBKEY 格式不对：每行一把 ssh-ed25519/ssh-rsa 公钥（.pub 文件的内容）"
	exit 1
fi
if [ -n "$SSH_KEYS" ]; then
	mkdir -p "$FILES_DIR/etc/dropbear"
	printf '%s\n' "$SSH_KEYS" > "$FILES_DIR/etc/dropbear/authorized_keys"
	chmod 600 "$FILES_DIR/etc/dropbear/authorized_keys"
	cat > "$FILES_DIR/etc/uci-defaults/96-fleet-ssh-key-only" <<'EOF'
#!/bin/sh
[ -s /etc/dropbear/authorized_keys ] || exit 0
chmod 700 /etc/dropbear && chmod 600 /etc/dropbear/authorized_keys
for s in $(uci -q show dropbear | sed -n 's/^dropbear\.\([^.=]*\)=dropbear$/\1/p'); do
	uci set dropbear."$s".PasswordAuth='off'
	uci set dropbear."$s".RootPasswordAuth='off'
done
uci commit dropbear
exit 0
EOF
	echo "SSH 只认管理员公钥（$(printf '%s\n' "$SSH_KEYS" | grep -c '') 把）。"
else
	echo "ADMIN_SSH_PUBKEY 未设置：SSH 用 root 密码登录（只能经 Headscale 内网连）。"
fi

if [ -n "$ROOT_PW_HASH" ]; then
	# 只接受 crypt 格式（$1$/$5$/$6$），避免写坏 /etc/shadow
	if ! printf '%s' "$ROOT_PW_HASH" | grep -Eq '^\$(1|5|6)\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{20,100}$'; then
		echo "::error::ROOT_PW_HASH 格式不对，应该是 openssl passwd -6 生成的那一串"
		exit 1
	fi
	{
		printf '#!/bin/sh\n'
		printf '# root 还没设密码时，设成固件里带的默认密码（之后自己改过的不会被覆盖）\n'
		printf "HASH='%s'\n" "$ROOT_PW_HASH"
		printf '%s\n' 'grep -q "^root::" /etc/shadow && sed -i "s|^root::|root:${HASH}:|" /etc/shadow'
		printf 'exit 0\n'
	} > "$FILES_DIR/etc/uci-defaults/95-root-password"
	echo "root 默认密码已写入固件。"
else
	echo "::warning::ROOT_PW_HASH 未设置：root 没有密码（家里打不开后台，但 Headscale 内网里的设备能直接登录）。"
fi

echo "fleet-agent 已写入固件。"
