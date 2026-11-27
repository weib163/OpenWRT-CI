#!/bin/bash
# 把 Tailscale 开机自动登录脚本和防火墙设置写进固件。
# 登录密钥和服务器地址只从 GitHub Secrets 读取，不写在仓库里：
#   TS_AUTHKEY      登录密钥（Headscale 的预授权密钥，或官方 Tailscale 的授权密钥）
#   TS_LOGIN_SERVER 自建 Headscale 的地址，例如 https://hs.example.com；不填就连官方 Tailscale
# 在 ./wrt/ 目录下运行。

FILES_DIR="./files"
mkdir -p "$FILES_DIR/etc/uci-defaults" "$FILES_DIR/etc/init.d" "$FILES_DIR/usr/bin"

# 防火墙：tailscale0 单独一个区，可以访问路由器本机，不经它转发到局域网
cat > "$FILES_DIR/etc/uci-defaults/98-tailscale-firewall" <<'EOF'
#!/bin/sh
uci -q get firewall.tailscale >/dev/null && exit 0
uci set firewall.tailscale=zone
uci set firewall.tailscale.name='tailscale'
uci set firewall.tailscale.input='ACCEPT'
uci set firewall.tailscale.output='ACCEPT'
uci set firewall.tailscale.forward='REJECT'
uci add_list firewall.tailscale.device='tailscale0'
uci commit firewall
exit 0
EOF

if [ -z "$TS_AUTHKEY" ]; then
	echo "TS_AUTHKEY 未设置：固件只带防火墙设置，不带自动登录。"
	exit 0
fi

printf '%s' "$TS_AUTHKEY" > "$FILES_DIR/etc/ts-authkey"
chmod 600 "$FILES_DIR/etc/ts-authkey"

LOGIN_SERVER=$(printf '%s' "$TS_LOGIN_SERVER" | tr -d '[:space:]')
if [ -n "$LOGIN_SERVER" ]; then
	case "$LOGIN_SERVER" in
		http://*|https://*) ;;
		*) LOGIN_SERVER="https://$LOGIN_SERVER" ;;
	esac
	printf '%s\n' "${LOGIN_SERVER%/}" > "$FILES_DIR/etc/ts-loginserver"
	chmod 600 "$FILES_DIR/etc/ts-loginserver"
	echo "自动登录目标：自建 Headscale。"
else
	echo "自动登录目标：官方 Tailscale。"
fi

cat > "$FILES_DIR/usr/bin/ts-autologin.sh" <<'EOF'
#!/bin/sh
# 开机后自动登录；登录成功就删掉密钥文件并关闭自己，失败则下次开机再试。
# --recover：Tailscale 要求重新登录时由 fleet-agent 调用（比如服务器重装过）。
#   密钥文件已经删掉的话，用只读分区里固件自带的那份；只试几次，不关闭开机自启（本来就关了）。
RECOVER=0
[ "${1:-}" = "--recover" ] && RECOVER=1
KEY_FILE=/etc/ts-authkey
SERVER_FILE=/etc/ts-loginserver
if [ ! -s "$KEY_FILE" ] && [ "$RECOVER" = 1 ] && [ -s /rom/etc/ts-authkey ]; then
	KEY_FILE=/rom/etc/ts-authkey
fi
[ -s "$KEY_FILE" ] || exit 0
[ -s "$SERVER_FILE" ] || { [ "$RECOVER" = 1 ] && [ -s /rom/etc/ts-loginserver ] && SERVER_FILE=/rom/etc/ts-loginserver; }

WANT_SERVER=""
[ -s "$SERVER_FILE" ] && WANT_SERVER=$(cat "$SERVER_FILE")

finish() {
	if [ "$RECOVER" = 0 ]; then
		rm -f /etc/ts-authkey
		/etc/init.d/ts-autologin disable
	fi
	logger -t ts-autologin "$1"
	exit 0
}

# 主机名 = 型号 + 完整 MAC，例如 re-cs-02-aabbccddeeff，200 台也不会重名
make_name() {
	MODEL=$(cut -d ',' -f 2 /tmp/sysinfo/board_name 2>/dev/null | tr -cd 'a-z0-9-')
	[ -n "$MODEL" ] || MODEL=router
	MAC=$(cat /sys/class/net/br-lan/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null)
	echo "$MODEL-$(echo "$MAC" | tr -d ':\n' | tr 'A-F' 'a-f')"
}

current_server() {
	tailscale debug prefs 2>/dev/null | sed -n 's/.*"ControlURL": *"\([^"]*\)".*/\1/p' | head -n 1
}

LIMIT=240
[ "$RECOVER" = 1 ] && LIMIT=5
i=0
while [ $i -lt $LIMIT ]; do
	i=$((i + 1))

	if ! pgrep tailscaled >/dev/null 2>&1; then
		/etc/init.d/tailscale enable 2>/dev/null
		/etc/init.d/tailscale start 2>/dev/null
		sleep 15
		continue
	fi

	EXTRA=""
	# 恢复登录时已有旧设置，带 --reset 免得 tailscale up 因为参数不一致拒绝执行
	[ "$RECOVER" = 1 ] && EXTRA="--reset"
	if tailscale status >/dev/null 2>&1; then
		if [ -z "$WANT_SERVER" ] || [ "$(current_server)" = "$WANT_SERVER" ]; then
			finish "already logged in"
		fi
		# 还登录在别的服务器上（例如从官方版固件保留配置升级过来）：改登自建服务器
		EXTRA="--reset --force-reauth"
	fi

	if [ -n "$WANT_SERVER" ]; then
		# Headscale：标签写在预授权密钥里，登录时自动带上
		set -- --login-server="$WANT_SERVER"
	else
		set -- --advertise-tags=tag:router
	fi

	NAME=$(make_name)
	if tailscale up $EXTRA "$@" --auth-key="$(cat "$KEY_FILE")" \
		--hostname="$NAME" --accept-dns=false --timeout=60s >/dev/null 2>&1; then
		finish "joined tailnet as $NAME"
	fi
	sleep 30
done
if [ "$RECOVER" = 1 ]; then
	logger -t ts-autologin "recover failed, fleet-agent will retry in an hour"
else
	logger -t ts-autologin "gave up for this boot, will retry next boot"
fi
EOF
chmod 755 "$FILES_DIR/usr/bin/ts-autologin.sh"

cat > "$FILES_DIR/etc/init.d/ts-autologin" <<'EOF'
#!/bin/sh /etc/rc.common
START=99
start() {
	[ -s /etc/ts-authkey ] || return 0
	/usr/bin/ts-autologin.sh >/dev/null 2>&1 &
}
EOF
chmod 755 "$FILES_DIR/etc/init.d/ts-autologin"

cat > "$FILES_DIR/etc/uci-defaults/99-ts-autologin" <<'EOF'
#!/bin/sh
/etc/init.d/ts-autologin enable
exit 0
EOF

echo "Tailscale 自动登录已写入固件。"
