#!/bin/bash
# 把集群管理相关的东西写进固件：
#   1. fleet-agent 路由器同步脚本（开机跑一次，之后每 10 分钟一次；同步时顺带上报 CPU 温度）
#   2. fleet-agent --health 每分钟一次：超温告警开始/解除时马上上报，屏幕上插播提示（断网、到期、留言等）
#   3. 雅典娜前面板屏幕的出厂设置（时间、路由器编号、温度轮播，超温闪烁告警，夜间调暗）
#   4. 网页终端 ttyd 改为所有接口监听，Tailscale 内网才能打开（外网仍被防火墙挡住）
#   5. 可选：设置 root 密码（GitHub Secret ROOT_PW_HASH，只在密码为空时生效）
# 在 ./wrt/ 目录下运行。
set -e

FILES_DIR="./files"
SRC="$GITHUB_WORKSPACE/Scripts/fleet"
mkdir -p "$FILES_DIR/usr/bin" "$FILES_DIR/etc/config" "$FILES_DIR/etc/init.d" "$FILES_DIR/etc/uci-defaults"

install -m 755 "$SRC/fleet-agent.lua" "$FILES_DIR/usr/bin/fleet-agent"
# 屏幕出厂设置：只有装了屏幕驱动的雅典娜会用到，其他机型开机时自己跳过
install -m 755 "$SRC/screen-defaults.sh" "$FILES_DIR/etc/uci-defaults/94-fleet-screen"

cat > "$FILES_DIR/etc/config/fleet" <<'EOF'
config agent 'main'
	option enabled '1'
	# 留空：自动找带 tag:fleet 标签的下发服务器
	option server ''
	option port '8080'
	option timeout '20'
	# CPU 超过这个温度（℃）算超温：屏幕闪烁告警、马上报给下发服务；降到低 3℃ 以下解除
	option temp_alert '90'
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

# ttyd 默认只在 LAN 口监听，Tailscale 内网打不开网页终端；改成所有接口监听。
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
