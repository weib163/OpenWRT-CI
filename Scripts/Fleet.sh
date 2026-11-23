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
# 在 ./wrt/ 目录下运行。
set -e

FILES_DIR="./files"
SRC="$GITHUB_WORKSPACE/Scripts/fleet"
mkdir -p "$FILES_DIR/usr/bin" "$FILES_DIR/etc/config" "$FILES_DIR/etc/init.d" "$FILES_DIR/etc/uci-defaults" \
	"$FILES_DIR/etc/fleet" "$FILES_DIR/etc/rc.button"

install -m 755 "$SRC/fleet-agent.lua" "$FILES_DIR/usr/bin/fleet-agent"
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

cat > "$FILES_DIR/etc/config/fleet" <<'EOF'
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
	echo "ROOT_PW_HASH 未设置：root 保持无密码（局域网里的人能直接登录后台和终端）。"
fi

echo "fleet-agent 已写入固件。"
