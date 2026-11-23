#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 VIKINGYFY

#安装和更新软件包
UPDATE_PACKAGE() {
	local PKG_NAME=$1
	local PKG_REPO=$2
	local PKG_BRANCH=$3
	local PKG_SPECIAL=$4
	local PKG_LIST=("$PKG_NAME" $5)  # 第5个参数为自定义名称列表
	local REPO_NAME=${PKG_REPO#*/}
	local REPO_PATH="./package/$REPO_NAME"

	echo " "

	# 删除本地可能存在的不同名称的软件包
	for NAME in "${PKG_LIST[@]}"; do
		# 查找匹配的目录
		echo "Search directory: $NAME"
		local FOUND_DIRS=$(find ./feeds/luci/ ./feeds/packages/ -maxdepth 3 -type d -iname "*$NAME*" 2>/dev/null)

		# 删除找到的目录
		if [ -n "$FOUND_DIRS" ]; then
			while read -r DIR; do
				rm -rf "$DIR"
				echo "Delete directory: $DIR"
			done <<< "$FOUND_DIRS"
		else
			echo "Not fonud directory: $NAME"
		fi
	done

	# 克隆 GitHub 仓库
	git clone --depth=1 --single-branch --branch $PKG_BRANCH "https://github.com/$PKG_REPO.git" $REPO_PATH

	# 处理克隆的仓库
	if [[ "$PKG_SPECIAL" == "pkg" ]]; then
		find $REPO_PATH/*/ -maxdepth 3 -type d -iname "*$PKG_NAME*" -prune -exec cp -rf {} ./package \;
		rm -rf $REPO_PATH
	fi
}

# 调用示例
# UPDATE_PACKAGE "OpenAppFilter" "destan19/OpenAppFilter" "master" "" "custom_name1 custom_name2"
# UPDATE_PACKAGE "open-app-filter" "destan19/OpenAppFilter" "master" "" "luci-app-appfilter oaf" 这样会把原有的open-app-filter，luci-app-appfilter，oaf相关组件删除，不会出现coremark错误。

# UPDATE_PACKAGE "包名" "项目地址" "项目分支" "pkg，可选，从大杂烩中单独提取包名插件"
UPDATE_PACKAGE "argon" "sbwml/luci-theme-argon" "openwrt-25.12"
UPDATE_PACKAGE "aurora" "eamonxg/luci-theme-aurora" "master"
UPDATE_PACKAGE "aurora-config" "eamonxg/luci-app-aurora-config" "master"
UPDATE_PACKAGE "fluent" "LazuliKao/luci-theme-fluent" "main"
UPDATE_PACKAGE "footstrap" "VizzleTF/luci-theme-footstrap" "main"
UPDATE_PACKAGE "kucat" "sirpdboy/luci-theme-kucat" "master"
UPDATE_PACKAGE "kucat-config" "sirpdboy/luci-app-kucat-config" "master"
UPDATE_PACKAGE "shadcn" "eamonxg/luci-theme-shadcn" "main"
UPDATE_PACKAGE "vantage" "anothaDev/luci-theme-vantage" "main"

UPDATE_PACKAGE "momo" "nikkinikki-org/OpenWrt-momo" "main"
UPDATE_PACKAGE "nikki" "nikkinikki-org/OpenWrt-nikki" "main"
UPDATE_PACKAGE "openclash" "vernesong/OpenClash" "dev" "pkg"
UPDATE_PACKAGE "passwall" "Openwrt-Passwall/openwrt-passwall" "main" "pkg"
UPDATE_PACKAGE "passwall2" "Openwrt-Passwall/openwrt-passwall2" "main" "pkg"

UPDATE_PACKAGE "diskmanager" "4IceG/luci-app-mini-diskmanager" "main"
UPDATE_PACKAGE "easytier" "EasyTier/luci-app-easytier" "main"
UPDATE_PACKAGE "qmodem" "FUjr/QModem" "main"
UPDATE_PACKAGE "viking" "VIKINGYFY/packages" "main" "" "axonhub gecoosac miniupnpd sing-box luci-app-homeproxy luci-app-timewol luci-app-upnp luci-app-wolplus luci-app-wolultra"

UPDATE_PACKAGE "diskman" "sbwml/luci-app-diskman" "main"
UPDATE_PACKAGE "mosdns" "sbwml/luci-app-mosdns" "v5" "" "v2dat"
UPDATE_PACKAGE "openlist2" "sbwml/luci-app-openlist2" "main"
UPDATE_PACKAGE "qbittorrent" "sbwml/luci-app-qbittorrent" "master" "" "qt6base qt6tools rblibtorrent"
UPDATE_PACKAGE "quickfile" "sbwml/luci-app-quickfile" "main"

UPDATE_PACKAGE "ddns-go" "sirpdboy/luci-app-ddns-go" "main"
UPDATE_PACKAGE "netspeedtest" "sirpdboy/netspeedtest" "main" "" "homebox ookla-speedtest"
UPDATE_PACKAGE "netwizard" "sirpdboy/luci-app-netwizard" "main"
UPDATE_PACKAGE "partexp" "sirpdboy/luci-app-partexp" "main"
UPDATE_PACKAGE "timecontrol" "sirpdboy/luci-app-timecontrol" "main"

UPDATE_PACKAGE "natmapt" "muink/openwrt-natmapt" "master"
UPDATE_PACKAGE "stuntman" "muink/openwrt-stuntman" "master"
UPDATE_PACKAGE "luci-app-natmapt" "muink/luci-app-natmapt" "master"

UPDATE_PACKAGE "airpi3000m-fancontrol" "LianXia233/luci-app-airpi3000m-fancontrol" "main"
UPDATE_PACKAGE "chfs" "LianXia233/luci-app-chfs" "main"
UPDATE_PACKAGE "fm350" "LianXia233/luci-app-fm350" "main"
UPDATE_PACKAGE "h5000m-netmode" "LianXia233/luci-app-h5000m-netmode" "main"
UPDATE_PACKAGE "mt5700" "LianXia233/luci-app-mt5700" "main"
UPDATE_PACKAGE "mt5700m" "LianXia233/luci-app-mt5700m" "main"
UPDATE_PACKAGE "netmonitor" "LianXia233/luci-app-netmonitor" "main"
UPDATE_PACKAGE "qmodem-generic" "LianXia233/luci-app-qmodem-generic" "main"

#雅典娜（RE-CS-02）前面板屏幕：源码自带的旧驱动换成增强版（超温闪烁告警、本机控制接口、夜间调暗）
#tag、提交和预编译程序的哈希都钉死：上游改动任何一样都会在这里直接停下，不会悄悄换掉
ATHENA_LED_REPO="unraveloop/JDC-AX6600-Athena-LED-Controller"
ATHENA_LED_TAG="v2.4.0"
ATHENA_LED_COMMIT="a0eae21dc1119a56aaf8633c610af03a92f7493c"
ATHENA_LED_HASH="243560a5e6bb52e5a493f7efa528771a6ab26e325a69b6e1d9d89647eaac5f3f"

UPDATE_ATHENA_LED() {
	local DIR="./package/athena-led-enhanced"
	local DEVICE_MK="./target/linux/qualcommax/image/ipq60xx.mk"

	echo " "
	# 旧驱动（同名的 luci-app-athena-led）和它的 /etc/config/athena_led 会和新包冲突，先删掉
	rm -rf ./package/emortal/luci-app-athena-led "$DIR"
	find ./feeds/luci/ ./feeds/packages/ -maxdepth 3 -type d \
		\( -name "luci-app-athena-led" -o -name "athena-led" \) -prune -exec rm -rf {} + 2>/dev/null

	git clone --depth=1 --single-branch --branch "$ATHENA_LED_TAG" "https://github.com/$ATHENA_LED_REPO.git" "$DIR" || return 1
	if [ "$(git -C "$DIR" rev-parse HEAD)" != "$ATHENA_LED_COMMIT" ]; then
		echo "$ATHENA_LED_TAG 指向的提交变了（期望 $ATHENA_LED_COMMIT）"
		return 1
	fi

	# 上游的 Makefile 不校验下载的程序（PKG_HASH:=skip），这里填上 v2.4.0 发布包的 sha256
	sed -i "s/^PKG_HASH:=skip$/PKG_HASH:=$ATHENA_LED_HASH/" "$DIR/athena-led/Makefile"
	grep -qx "PKG_HASH:=$ATHENA_LED_HASH" "$DIR/athena-led/Makefile" || return 1

	# 界面包直接调用 po2lmo，完整编译时它不在 PATH 里，中文会被悄悄跳过：改用 luci-base 编出来的那份
	local LUCI_MK="$DIR/luci-app-athena-led/Makefile"
	# shellcheck disable=SC2016 # $(...) 是 Makefile 里的写法，要原样写进去
	sed -i 's#&& po2lmo #\&\& $(STAGING_DIR_HOSTPKG)/bin/po2lmo #' "$LUCI_MK"
	sed -i 's#^PKG_LICENSE_FILES:=LICENSE$#&\nPKG_BUILD_DEPENDS:=luci-base/host#' "$LUCI_MK"
	# shellcheck disable=SC2016
	grep -qF '$(STAGING_DIR_HOSTPKG)/bin/po2lmo ./po/zh_Hans/athena_led.po' "$LUCI_MK" || return 1
	grep -qx 'PKG_BUILD_DEPENDS:=luci-base/host' "$LUCI_MK" || return 1

	# 增强版把中文翻译直接打在界面包里，没有单独的 luci-i18n-athena-led-zh-cn 包，从设备默认包里去掉
	if [ -f "$DEVICE_MK" ]; then
		sed -i 's/ luci-i18n-athena-led-zh-cn//g' "$DEVICE_MK"
		if grep -q 'luci-i18n-athena-led-zh-cn' "$DEVICE_MK"; then
			echo "$DEVICE_MK 里还有 luci-i18n-athena-led-zh-cn"
			return 1
		fi
	fi
	echo "athena-led $ATHENA_LED_TAG is ready!"
}

if ! UPDATE_ATHENA_LED; then
	echo "::error::雅典娜屏幕驱动准备失败，停止编译"
	exit 1
fi

#更新软件包版本
UPDATE_VERSION() {
	local PKG_NAME=$1
	local PKG_MARK=${2:-false}
	local PKG_FILES=$(find ./package/ ./feeds/packages/ -maxdepth 3 -type f -wholename "*/$PKG_NAME/Makefile")

	if [ -z "$PKG_FILES" ]; then
		echo "$PKG_NAME not found!"
		return
	fi

	echo -e "\n$PKG_NAME version update has started!"

	for PKG_FILE in $PKG_FILES; do
		local PKG_REPO=$(grep -Po "PKG_SOURCE_URL:=https://.*github.com/\K[^/]+/[^/]+(?=.*)" $PKG_FILE)
		local PKG_TAG=$(curl -sL "https://api.github.com/repos/$PKG_REPO/releases" | jq -r "map(select(.prerelease == $PKG_MARK)) | first | .tag_name")

		local OLD_VER=$(grep -Po "PKG_VERSION:=\K.*" "$PKG_FILE")
		local OLD_URL=$(grep -Po "PKG_SOURCE_URL:=\K.*" "$PKG_FILE")
		local OLD_FILE=$(grep -Po "PKG_SOURCE:=\K.*" "$PKG_FILE")
		local OLD_HASH=$(grep -Po "PKG_HASH:=\K.*" "$PKG_FILE")

		local PKG_URL=$([[ "$OLD_URL" == *"releases"* ]] && echo "${OLD_URL%/}/$OLD_FILE" || echo "${OLD_URL%/}")

		local NEW_VER=$(echo $PKG_TAG | sed -E 's/[^0-9]+/\./g; s/^\.|\.$//g')
		local NEW_URL=$(echo $PKG_URL | sed "s/\$(PKG_VERSION)/$NEW_VER/g; s/\$(PKG_NAME)/$PKG_NAME/g")
		local NEW_HASH=$(curl -sL "$NEW_URL" | sha256sum | cut -d ' ' -f 1)

		echo "old version: $OLD_VER $OLD_HASH"
		echo "new version: $NEW_VER $NEW_HASH"

		if [[ "$NEW_VER" =~ ^[0-9].* ]] && dpkg --compare-versions "$OLD_VER" lt "$NEW_VER"; then
			sed -i "s/PKG_VERSION:=.*/PKG_VERSION:=$NEW_VER/g" "$PKG_FILE"
			sed -i "s/PKG_HASH:=.*/PKG_HASH:=$NEW_HASH/g" "$PKG_FILE"
			echo "$PKG_FILE version has been updated!"
		else
			echo "$PKG_FILE version is already the latest!"
		fi
	done
}

#UPDATE_VERSION "软件包名" "测试版，true，可选，默认为否"
#UPDATE_VERSION "sing-box"

#引入私有扩展脚本
if [ -f "$GITHUB_WORKSPACE/Scripts/PRIVATE.sh" ]; then
	source "$GITHUB_WORKSPACE/Scripts/PRIVATE.sh"
fi
