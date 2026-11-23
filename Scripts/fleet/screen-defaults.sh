#!/bin/sh
# 雅典娜前面板屏幕的出厂设置。固件里装成 /etc/uci-defaults/94-fleet-screen，刷机后第一次开机运行。
#   轮播：时间（冒号闪烁）15 秒 → 路由器编号 4 秒 → CPU 温度 4 秒
#   超温闪烁告警：阈值跟 fleet.main.temp_alert 走（默认 90℃，3℃ 滞回）
#   夜间 22:00~07:00 调暗；本机控制接口 127.0.0.1:8377（fleet-agent 用它在屏幕上插播提示）
# 只写一次：写过以后（athena_led.general.fleet_defaults 有值），在后台改的屏幕设置都会保留。
# 屏幕编号先显示 ??????，开机后 fleet-agent --health 把它换成设备名最后 6 位（和管理页、面板用户名对得上）。

FLEET_SCREEN_DEFAULTS=1

[ -x /etc/init.d/athena_led ] || exit 0
[ -x /usr/bin/athena-led ] || exit 0
[ "$(uci -q get athena_led.general.fleet_defaults)" = "$FLEET_SCREEN_DEFAULTS" ] && exit 0

# CPU 温度传感器编号按名字找：上游内核是 4，换内核编号变了也不怕
ZONE=4
for z in /sys/class/thermal/thermal_zone*; do
	case "$(cat "$z/type" 2>/dev/null)" in
		cpu*)
			ZONE=${z##*thermal_zone}
			break
			;;
	esac
done

TEMP_ALERT=$(uci -q get fleet.main.temp_alert)
case "$TEMP_ALERT" in
	'' | *[!0-9]*) TEMP_ALERT=90 ;;
esac

# 整份重写：也顺带清掉旧驱动留下的、格式不一样的配置
cat > /etc/config/athena_led <<EOF
config settings 'general'
	option enabled '1'
	option fleet_defaults '$FLEET_SCREEN_DEFAULTS'
	option profile_mode 'single'
	option light_level '5'
	option night_light_enable '1'
	option night_start '22:00'
	option night_end '07:00'
	option night_light_level '1'
	option enable_sleep '0'
	option off_time '23:00'
	option on_time '07:00'
	option gpio_backend 'auto'
	option gpio_base 'auto'
	option button_gpio '71'
	option net_interface 'br-lan'
	option custom_content '??????'
	option http_url ''
	option http_length '15'
	option http_cache_secs '60'
	option stock_url ''
	option weather_city 'auto'
	option weather_source 'uapis'
	option weather_format 'simple'
	option seniverse_key ''
	option temp_sensors '$ZONE'
	option temp_alert '$TEMP_ALERT'
	option temp_alert_sensor '$ZONE'
	option control_port '8377'
	option mqtt_broker ''
	option mqtt_topic 'athena-led/display'
	option mqtt_user ''
	option mqtt_pass ''
	option disable_led_clock '0'
	option disable_led_medal '0'
	option disable_led_up '0'
	option disable_led_down '0'

config single_module
	option module 'time_group'
	option param 'timeBlink'
	option duration '15'

config single_module
	option module 'banner'
	option duration '4'

config single_module
	option module 'temp_single'
	option param '$ZONE'
	option duration '4'
EOF

/etc/init.d/athena_led enable
exit 0
