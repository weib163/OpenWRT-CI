#!/usr/bin/lua
-- fleet-agent：从下发服务拉取本机的节点配置，写进 PassWall 2；同步时顺带上报 CPU 温度。
--
-- 开机运行一次，之后每 10 分钟由 cron 运行；调试时执行 fleet-agent --now（跳过随机等待）。
-- fleet-agent --health 由 cron 每分钟运行：超温告警开始或解除时马上同步一次（不等 10 分钟），
--   并在雅典娜屏幕上插播提示（断网、管理通道断开、到期、后台留言），把屏幕编号填成设备名最后 6 位。
-- 只改名字以 fleet_ 开头的节点和分流规则；客户自己加的节点不动。
-- 日志：logread -e fleet-agent
--
-- 依赖固件里已有的 lua、luci-lib-jsonc（luci.jsonc）、libuci-lua（uci）、uclient-fetch、tailscale。

local M = {}
M.VERSION = "1.1.0"
M.PW = "passwall2"
M.PREFIX = "fleet_"
M.STATE_FILE = "/etc/fleet/state.json"
M.LAST_FILE = "/etc/fleet/last.json"
M.LOCK_DIR = "/var/lock/fleet-agent.lock"
M.FLEET_TAG = "tag:fleet"
-- 温度和屏幕：状态都放内存盘（/tmp），每分钟写也不伤闪存
M.HEALTH_FILE = "/tmp/fleet/health.json"
M.REPORTED_FILE = "/tmp/fleet/reported"
M.HEALTH_LOCK_DIR = "/var/lock/fleet-health.lock"
M.TEMP_ALERT_DEFAULT = 90
M.TEMP_HYSTERESIS = 3
M.SCREEN = "athena_led"
-- 占位符不能以 - 开头：屏幕程序把它当命令行参数收，会被当成选项而启动失败
M.SCREEN_PLACEHOLDER = "??????"
-- 断网这类紧急提示每分钟插播 8 秒；到期、留言这类长期提示每 2 分钟插播 15 秒（屏幕程序每次插播都记一行日志）
M.SCREEN_URGENT_SECONDS = 8
M.SCREEN_NOTE_SECONDS = 15

local STATUSES = { active = true, unchanged = true, pending = true, expired = true,
	limited = true, disabled = true, no_nodes = true }
local FINGERPRINTS = { chrome = true, firefox = true, edge = true, safari = true, ["360"] = true,
	qq = true, ios = true, android = true, random = true, randomized = true }

-- ------------------------------------------------------------ 校验
local function str(v)
	if type(v) == "string" then return v end
	return nil
end

function M.is_ipv4(s)
	if type(s) ~= "string" then return false end
	local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return false end
	for _, o in ipairs({ a, b, c, d }) do
		if #o > 3 or tonumber(o) > 255 then return false end
	end
	return true
end

function M.is_ipv6(s)
	return type(s) == "string" and #s >= 2 and #s <= 39 and s:find(":", 1, true) ~= nil
		and s:match("^[%x:]+$") ~= nil
end

function M.is_hostname(s)
	if type(s) ~= "string" or #s < 1 or #s > 253 then return false end
	if s:sub(-1) == "." then s = s:sub(1, -2) end
	if s == "" or s:find("..", 1, true) or s:sub(1, 1) == "." then return false end
	for label in s:gmatch("[^%.]+") do
		if #label > 63 or not label:match("^[%w][%w%-]*$") or label:sub(-1) == "-" then return false end
	end
	return true
end

function M.is_address(s)
	return M.is_ipv4(s) or M.is_ipv6(s) or M.is_hostname(s)
end

function M.is_cidr(s)
	if type(s) ~= "string" then return false end
	local ip, len = s:match("^([%d%.]+)/(%d+)$")
	if ip and M.is_ipv4(ip) and tonumber(len) <= 32 then return true end
	ip, len = s:match("^([%x:]+)/(%d+)$")
	return ip ~= nil and M.is_ipv6(ip) and tonumber(len) <= 128
end

function M.is_uuid(s)
	return type(s) == "string"
		and s:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil
end

function M.is_path(s)
	return type(s) == "string" and #s <= 201 and s:match("^/[%w%._~%%!%$&%(%)%*%+,;=:@/%?%-]*$") ~= nil
end

-- 去掉控制字符和引号，按 UTF-8 安全地截到 limit 字节
function M.clean_remark(s, fallback, limit)
	limit = limit or 96
	if type(s) ~= "string" then return fallback end
	s = s:gsub("[%c\"'\\`]", "")
	if #s > limit then
		s = s:sub(1, limit)
		-- 找到最后一个字符的起点，不完整就去掉
		local i = #s
		while i > 0 and s:byte(i) >= 0x80 and s:byte(i) < 0xC0 do i = i - 1 end
		if i > 0 then
			local lead = s:byte(i)
			local need = (lead >= 0xF0 and 4) or (lead >= 0xE0 and 3) or (lead >= 0xC0 and 2) or 1
			if #s - i + 1 < need then s = s:sub(1, i - 1) end
		end
	end
	s = s:gsub("^%s+", ""):gsub("%s+$", "")
	if s == "" then return fallback end
	return s
end

-- 屏幕留言：只留屏幕字库里有的字符（字母按大写显示），最多 24 个；不合格返回 nil
function M.clean_notice(s)
	if type(s) ~= "string" then return nil end
	s = s:upper():gsub("%s+", " "):gsub("^ ", ""):gsub(" $", "")
	if s == "" or #s > 24 or not s:match("^[A-Z0-9 %.:%+%-=/%*%%%(%)%?~_]+$") then return nil end
	return s
end

local function interval_seconds(s)
	local n, unit = s:match("^(%d+)([smh]?)$")
	if not n then return nil end
	n = tonumber(n)
	if unit == "m" then return n * 60 elseif unit == "h" then return n * 3600 end
	return n
end

function M.validate_node(n)
	if type(n) ~= "table" then return nil, "不是对象" end
	local id = str(n.id)
	if not id or #id > 24 or not id:match("^[%w_]+$") then return nil, "id" end
	if n.protocol ~= "vless" then return nil, "protocol" end
	local address = str(n.address)
	if not address or not M.is_address(address) then return nil, "address" end
	local port = tonumber(n.port)
	if not port or port ~= math.floor(port) or port < 1 or port > 65535 then return nil, "port" end
	local uuid = str(n.uuid)
	if not uuid or not M.is_uuid(uuid) then return nil, "uuid" end
	if n.tls ~= true then return nil, "tls" end
	local transport = n.transport
	if transport ~= "tcp" and transport ~= "ws" then return nil, "transport" end
	local fp = str(n.fingerprint) or "chrome"
	if not FINGERPRINTS[fp] then fp = "chrome" end
	-- 校验后的结果再校验一次也要通过（last.json 存的就是它）
	local node = { id = id, protocol = "vless", tls = true, remarks = M.clean_remark(n.remarks, id),
		address = address, port = port, uuid = uuid, transport = transport, fingerprint = fp,
		reality = (n.reality == true) }
	if n.flow ~= nil then
		if n.flow ~= "xtls-rprx-vision" or transport ~= "tcp" then return nil, "flow" end
		node.flow = n.flow
	end
	if n.sni ~= nil then
		if not M.is_hostname(n.sni) then return nil, "sni" end
		node.sni = n.sni
	end
	if node.reality then
		if not node.sni then return nil, "reality 缺伪装域名" end
		local pbk = str(n.public_key)
		if not pbk or #pbk < 42 or #pbk > 46 or not pbk:match("^[%w_%-]+=?=?$") then return nil, "public_key" end
		local sid = n.short_id or ""
		if type(sid) ~= "string" or #sid > 16 or not sid:match("^%x*$") then return nil, "short_id" end
		node.public_key, node.short_id = pbk, sid
	elseif n.alpn ~= nil then
		local alpn = str(n.alpn)
		if not alpn or #alpn > 64 or not alpn:match("^[%w%./,%-]+$") then return nil, "alpn" end
		node.alpn = alpn
	end
	if transport == "ws" then
		local path = n.ws_path or "/"
		if not M.is_path(path) then return nil, "ws_path" end
		node.ws_path = path
		if n.ws_host ~= nil then
			if not M.is_hostname(n.ws_host) then return nil, "ws_host" end
			node.ws_host = n.ws_host
		end
	end
	return node
end

-- 校验下发服务的回复；任何一项不合格就整份丢弃（继续用旧配置）
function M.validate(r)
	if type(r) ~= "table" then return nil, "回复不是 JSON 对象" end
	local st = r.status
	if type(st) ~= "string" or not STATUSES[st] then return nil, "status 不合法" end
	local out = { status = st }
	if r.version ~= nil then
		if type(r.version) ~= "string" or #r.version > 64 or not r.version:match("^%x*$") then
			return nil, "version 不合法"
		end
		out.version = r.version
	end
	local refresh = tonumber(r.refresh_seconds)
	out.refresh = (refresh and refresh >= 60 and refresh <= 86400) and math.floor(refresh) or 600
	-- 留言只是屏幕上显示的字，不合格就当没有，不影响节点配置
	out.notice = M.clean_notice(r.notice)
	if st == "unchanged" then return out end

	local oe = r.on_expire or "block"
	if oe ~= "block" and oe ~= "direct" then return nil, "on_expire 不合法" end
	out.on_expire = oe
	if st ~= "active" then return out end

	if type(r.nodes) ~= "table" or #r.nodes < 1 or #r.nodes > 60 then return nil, "nodes 不合法" end
	out.nodes = {}
	local seen = {}
	for i, n in ipairs(r.nodes) do
		local node, err = M.validate_node(n)
		if not node then return nil, "第 " .. i .. " 个节点不合法：" .. err end
		if seen[node.id] then return nil, "节点 id 重复：" .. node.id end
		seen[node.id] = true
		out.nodes[#out.nodes + 1] = node
	end

	local a = type(r.auto) == "table" and r.auto or {}
	local url = str(a.url) or "https://www.gstatic.com/generate_204"
	if #url > 200 or not url:match("^https?://[%w%.%-]+:?%d*/?[%w%._~%%/%?=&%-]*$") then return nil, "auto.url 不合法" end
	local interval = str(a.interval) or "3m"
	local secs = interval_seconds(interval)
	if not secs or secs < 10 then return nil, "auto.interval 不合法" end
	if secs > 1800 then interval = "30m" end -- 测速间隔不能超过空闲超时（30m）
	local tol = tonumber(a.tolerance) or 50
	if tol < 0 or tol > 10000 then return nil, "auto.tolerance 不合法" end
	out.auto = { url = url, interval = interval, tolerance = math.floor(tol) }

	out.direct = {}
	if r.direct ~= nil then
		if type(r.direct) ~= "table" or #r.direct > 20 then return nil, "direct 不合法" end
		for _, d in ipairs(r.direct) do
			if not (M.is_address(d) or M.is_cidr(d)) then return nil, "direct 里有不合法的项" end
			out.direct[#out.direct + 1] = d
		end
	end
	return out
end

-- ------------------------------------------------------------ 生成要写入的 UCI 段
local function node_section(node)
	local o = {
		remarks = node.remarks, type = "sing-box", protocol = "vless", group = "fleet",
		address = node.address, port = tostring(node.port), uuid = node.uuid,
		tls = "1", tls_allowInsecure = "0", transport = node.transport,
		utls = "1", fingerprint = node.fingerprint,
		reality = node.reality and "1" or "0",
	}
	if node.flow then o.flow = node.flow end
	if node.sni then o.tls_serverName = node.sni end
	if node.reality then
		o.reality_publicKey = node.public_key
		o.reality_shortId = node.short_id
	end
	if node.alpn then o.alpn = node.alpn end
	if node.transport == "ws" then
		o.ws_path = node.ws_path
		if node.ws_host then o.ws_host = node.ws_host end
	end
	return { name = M.PREFIX .. node.id, stype = "nodes", options = o }
end

local function direct_rule(direct)
	if not direct or #direct == 0 then return nil end
	local domains, ips = {}, {}
	for _, d in ipairs(direct) do
		if M.is_ipv4(d) or M.is_ipv6(d) or M.is_cidr(d) then ips[#ips + 1] = d
		else domains[#domains + 1] = "domain:" .. d end
	end
	local o = { remarks = "fleet_direct", network = "tcp,udp", group = "CN" }
	if #domains > 0 then o.domain_list = table.concat(domains, "\n") end
	if #ips > 0 then o.ip_list = table.concat(ips, "\n") end
	return { name = M.PREFIX .. "direct", stype = "shunt_rules", options = o }
end

local function shunt_section(target, has_direct)
	local o = {
		remarks = "分流（fleet）", type = "sing-box", protocol = "_shunt", group = "fleet",
		shunt_group = "CN",
		CN = "_direct", DirectFront = "_direct", DirectGame = "_direct",
		ProxyFront = target, ProxyGame = target, default_node = target,
	}
	if has_direct then o[M.PREFIX .. "direct"] = "_direct" end
	return { name = M.PREFIX .. "shunt", stype = "nodes", options = o }
end

-- 正常：节点 + 自动选择 + （直连规则）+ 分流
function M.plan_active(cfg)
	local plan, members = {}, {}
	for _, node in ipairs(cfg.nodes) do
		local sec = node_section(node)
		plan[#plan + 1] = sec
		members[#members + 1] = sec.name
	end
	plan[#plan + 1] = { name = M.PREFIX .. "auto", stype = "nodes", options = {
		remarks = "自动选择（fleet）", type = "sing-box", protocol = "_urltest", group = "fleet",
		node_add_mode = "manual", urltest_node = members,
		urltest_url = cfg.auto.url, urltest_interval = cfg.auto.interval,
		urltest_tolerance = tostring(cfg.auto.tolerance), urltest_idle_timeout = "30m",
		urltest_interrupt_exist_connections = "0",
	} }
	local rule = direct_rule(cfg.direct)
	if rule then plan[#plan + 1] = rule end
	plan[#plan + 1] = shunt_section(M.PREFIX .. "auto", rule ~= nil)
	return plan
end

-- 主动停用：本机不再留任何节点（UUID 一起删掉），翻墙流量直接丢弃，国内照常
function M.plan_blocked(direct)
	local plan = {}
	local rule = direct_rule(direct)
	if rule then plan[#plan + 1] = rule end
	plan[#plan + 1] = shunt_section("_blackhole", rule ~= nil)
	return plan
end

-- ------------------------------------------------------------ 写 UCI
function M.global_section(c)
	local g
	c:foreach(M.PW, "global", function(s) g = g or s[".name"] end)
	return g
end

function M.snapshot(c)
	local lines = {}
	for _, stype in ipairs({ "nodes", "shunt_rules" }) do
		c:foreach(M.PW, stype, function(s)
			local name = s[".name"]
			if name:sub(1, #M.PREFIX) == M.PREFIX then
				local keys = {}
				for k in pairs(s) do
					if k:sub(1, 1) ~= "." then keys[#keys + 1] = k end
				end
				table.sort(keys)
				local parts = { stype .. ":" .. name }
				for _, k in ipairs(keys) do
					local v = s[k]
					if type(v) == "table" then v = table.concat(v, ",") end
					parts[#parts + 1] = k .. "=" .. tostring(v)
				end
				lines[#lines + 1] = table.concat(parts, "|")
			end
		end)
	end
	table.sort(lines)
	local g = M.global_section(c)
	if g then
		lines[#lines + 1] = "global|node=" .. tostring(c:get(M.PW, g, "node"))
			.. "|enabled=" .. tostring(c:get(M.PW, g, "enabled"))
	end
	return table.concat(lines, "\n")
end

-- 用 plan 替换全部 fleet_ 段，设主节点和总开关；有变化才提交。返回 changed, err
function M.apply(c, plan, enabled)
	local g = M.global_section(c)
	if not g then return false, "PassWall 2 配置里没有 global 段" end
	local before = M.snapshot(c)
	for _, stype in ipairs({ "nodes", "shunt_rules" }) do
		local names = {}
		c:foreach(M.PW, stype, function(s)
			if s[".name"]:sub(1, #M.PREFIX) == M.PREFIX then names[#names + 1] = s[".name"] end
		end)
		for _, n in ipairs(names) do c:delete(M.PW, n) end
	end
	local has_shunt = false
	for _, sec in ipairs(plan) do
		c:set(M.PW, sec.name, sec.stype)
		local keys = {}
		for k in pairs(sec.options) do keys[#keys + 1] = k end
		table.sort(keys)
		for _, k in ipairs(keys) do c:set(M.PW, sec.name, k, sec.options[k]) end
		if sec.name == M.PREFIX .. "shunt" then has_shunt = true end
	end
	if has_shunt then c:set(M.PW, g, "node", M.PREFIX .. "shunt") end
	c:set(M.PW, g, "enabled", enabled and "1" or "0")
	local d
	c:foreach(M.PW, "global_delay", function(s) d = d or s[".name"] end)
	if d and c:get(M.PW, d, "start_daemon") ~= "1" then c:set(M.PW, d, "start_daemon", "1") end
	if M.snapshot(c) == before then
		c:revert(M.PW)
		return false
	end
	c:commit(M.PW)
	return true
end

-- 主节点是不是由本脚本管理（客户自己配的不碰）
function M.managed(c)
	local g = M.global_section(c)
	local node = g and c:get(M.PW, g, "node") or ""
	return node:sub(1, #M.PREFIX) == M.PREFIX
end

function M.set_enabled(c, on)
	local g = M.global_section(c)
	if not g then return false end
	local want = on and "1" or "0"
	if c:get(M.PW, g, "enabled") == want then return false end
	c:set(M.PW, g, "enabled", want)
	c:commit(M.PW)
	return true
end

-- ------------------------------------------------------------ 运行环境（测试时替换）
local function shell_quote(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end
M.shell_quote = shell_quote

M.env = {
	exec = function(cmd)
		local p = io.popen(cmd)
		if not p then return "" end
		local out = p:read("*a") or ""
		p:close()
		return out
	end,
	run = function(cmd) return os.execute(cmd) end,
	read = function(path)
		local f = io.open(path, "r")
		if not f then return nil end
		local data = f:read("*a")
		f:close()
		return data
	end,
	write = function(path, data)
		local tmp = path .. ".tmp"
		local f = io.open(tmp, "w")
		if not f then return false end
		f:write(data)
		f:close()
		return os.rename(tmp, path)
	end,
	remove = function(path) os.remove(path) end,
	cursor = function() return require("uci").cursor() end,
	log = function(msg) os.execute("logger -t fleet-agent " .. shell_quote(msg)) end,
	sleep = function(n) os.execute("sleep " .. tonumber(n)) end,
	now = function() return os.time() end,
	restart_passwall = function() os.execute("/etc/init.d/passwall2 restart >/dev/null 2>&1 &") end,
	restart_screen = function() os.execute("/etc/init.d/athena_led restart >/dev/null 2>&1 &") end,
}

local function json()
	return require("luci.jsonc")
end

local function urlencode(s)
	return (tostring(s):gsub("[^%w%-%._~]", function(ch) return string.format("%%%02X", ch:byte()) end))
end

-- 在 tailscale status --json 里找带 tag:fleet 标签的下发服务器，返回它的 IPv4
function M.discover(status)
	if type(status) ~= "table" or status.BackendState ~= "Running" then return nil end
	local best
	for _, peer in pairs(status.Peer or {}) do
		local is_fleet = false
		for _, t in ipairs(peer.Tags or {}) do
			if t == M.FLEET_TAG then is_fleet = true end
		end
		if is_fleet then
			for _, ip in ipairs(peer.TailscaleIPs or {}) do
				if M.is_ipv4(ip) and (not best or ip < best) then best = ip end
			end
		end
	end
	return best
end

-- 用 uclient-fetch 取回复；返回 body 或 nil（任何非 200 都算失败）
function M.fetch(url, timeout)
	local out = M.env.exec("uclient-fetch -q -T " .. tonumber(timeout or 20) .. " -O - " .. shell_quote(url)
		.. " 2>/dev/null; echo \"__FLEET_RC=$?\"")
	local body, rc = out:match("^(.*)__FLEET_RC=(%d+)%s*$")
	if not body or rc ~= "0" or body == "" then return nil end
	return body
end

function M.read_json(path)
	local data = M.env.read(path)
	if not data or data == "" then return nil end
	local ok, v = pcall(json().parse, data)
	if ok and type(v) == "table" then return v end
	return nil
end

function M.write_json(path, v)
	M.env.write(path, json().stringify(v))
end

local function read_conf(c)
	local conf = { enabled = "1", server = "", port = "8080", timeout = "20", temp_alert = "" }
	c:foreach("fleet", "agent", function(s)
		for k in pairs(conf) do
			if s[k] ~= nil then conf[k] = s[k] end
		end
	end)
	return conf
end

-- 报给管理页“固件”一栏：优先用我们的固件版本号（/etc/fleet-firmware，如 1.1.0-26.11.23），
-- 老固件没有这个文件就用 OpenWrt 源码版本
local function firmware_version()
	for _, path in ipairs({ "/etc/fleet-firmware", "/etc/openwrt_version" }) do
		local v = (M.env.read(path) or ""):gsub("%s+", "")
		if v ~= "" and #v <= 40 and v:match("^[%w%._%+%-]+$") then return v end
	end
	return ""
end

-- ------------------------------------------------------------ 温度
-- 超温阈值（℃）：fleet.main.temp_alert，不合理的值按默认 90
function M.temp_threshold(conf)
	local v = tonumber(conf and conf.temp_alert)
	if not v or v < 40 or v > 130 then return M.TEMP_ALERT_DEFAULT end
	return math.floor(v)
end

local function read_celsius(path)
	local raw = tonumber((M.env.read(path) or ""):match("%-?%d+"))
	if not raw then return nil end
	if math.abs(raw) > 1000 then raw = raw / 1000 end -- 一般是千分之一度
	return raw
end

-- CPU 温度（℃，四舍五入）：按名字找 cpu 开头的传感器，找不到用 thermal_zone4；读不到返回 nil
function M.cpu_temp()
	local best
	for i = 0, 15 do
		local zone = "/sys/class/thermal/thermal_zone" .. i
		local t = M.env.read(zone .. "/type")
		if t and t:match("^%s*cpu") then
			local c = read_celsius(zone .. "/temp")
			if c and (not best or c > best) then best = c end
		end
	end
	best = best or read_celsius("/sys/class/thermal/thermal_zone4/temp")
	if not best or best < -40 or best > 150 then return nil end
	return math.floor(best + 0.5)
end

-- 读一次温度，按 3℃ 滞回判断是否超温（和屏幕程序的告警一致）。
-- 返回 { temp, hot, since, changed }，changed = 这次刚开始或刚解除
function M.health_check(threshold, now)
	local prev = M.read_json(M.HEALTH_FILE) or {}
	local was_hot = prev.hot == true
	local temp = M.cpu_temp()
	local hot = was_hot
	if temp then
		if temp >= threshold then
			hot = true
		elseif temp <= threshold - M.TEMP_HYSTERESIS then
			hot = false
		end
	end
	local since = nil
	if hot then since = (was_hot and tonumber(prev.since)) or now end
	local cur = { temp = temp, hot = hot, since = since, threshold = threshold }
	if prev.temp ~= temp or prev.hot ~= hot or prev.since ~= since or prev.threshold ~= threshold then
		M.write_json(M.HEALTH_FILE, cur)
	end
	cur.changed = (hot ~= was_hot)
	return cur
end

-- 最近一次成功报给下发服务的超温状态（重启后没有记录，按“没超温”算）
function M.reported_hot()
	return (M.env.read(M.REPORTED_FILE) or ""):match("^1") ~= nil
end

-- ------------------------------------------------------------ 屏幕
local SCREEN_STATUS_TEXT = { expired = "EXPIRED", limited = "LIMIT", disabled = "STOPPED",
	pending = "WAIT", no_nodes = "NO NODE" }

-- 屏幕上要插播的提示（只用屏幕字库里有的字符）和它是否紧急；一切正常返回 nil
-- 顺序：断网 > 管理通道断开 > 后台留言 > 账号状态
function M.screen_message(ctx)
	if ctx.wan_up == false then return "NET DOWN", true end
	if ctx.ts_up == false then return "TS DOWN", true end
	if ctx.notice then return ctx.notice, false end
	local text = SCREEN_STATUS_TEXT[ctx.status or ""]
	if text then return text, false end
	return nil
end

-- 有没有默认路由（主路由表）：nil = 读不到，不判断
function M.wan_up()
	local routes = M.env.read("/proc/net/route")
	if not routes then return nil end
	for line in routes:gmatch("[^\n]+") do
		local dest, flags, mask = line:match("^%S+%s+(%x+)%s+%x+%s+(%x+)%s+%S+%s+%S+%s+%S+%s+(%x+)")
		if dest == "00000000" and mask == "00000000" and (tonumber(flags, 16) or 0) % 2 == 1 then
			return true
		end
	end
	return false
end

-- 屏幕编号：设备名（ts-autologin 设成“型号-12 位 MAC”）的最后 6 位，大写；拿不到设备名就用 br-lan 的 MAC
function M.screen_id(ts)
	local me = type(ts) == "table" and type(ts.Self) == "table" and ts.Self or {}
	local hex
	for _, name in ipairs({ me.HostName, me.DNSName }) do
		if type(name) == "string" then
			hex = name:lower():gsub("%.$", ""):match("^([^%.]*)"):match("%-(%x%x%x%x%x%x%x%x%x%x%x%x)$")
			if hex then break end
		end
	end
	if not hex then
		local mac = (M.env.read("/sys/class/net/br-lan/address") or ""):lower():gsub("[^%x]", "")
		if #mac == 12 then hex = mac end
	end
	return hex and hex:sub(7):upper() or nil
end

function M.screen_command(port, secs, text)
	return string.format("printf 'show %d %%s\\n' %s | nc 127.0.0.1 %d >/dev/null 2>&1 &",
		secs, M.shell_quote(text), port)
end

-- 雅典娜屏幕：编号和超温阈值跟着 fleet 设置走（只管我们写过出厂设置的屏幕），再插播提示
function M.screen_tick(c, ctx)
	local g = {}
	c:foreach(M.SCREEN, "settings", function(sec)
		if sec[".name"] == "general" then g = sec end
	end)
	if g.enabled ~= "1" or not g.fleet_defaults then return end

	local changed = false
	local id = M.screen_id(ctx.ts)
	local text = g.custom_content
	-- 只替换占位符或我们上次填的编号；在后台改成别的文字就不再动它
	if id and text ~= id and (text == M.SCREEN_PLACEHOLDER or (g.fleet_id and text == g.fleet_id)) then
		c:set(M.SCREEN, "general", "custom_content", id)
		c:set(M.SCREEN, "general", "fleet_id", id)
		changed = true
	end
	local threshold = tostring(ctx.threshold)
	if ctx.threshold and g.temp_alert ~= threshold then
		c:set(M.SCREEN, "general", "temp_alert", threshold)
		changed = true
	end
	if changed then
		c:commit(M.SCREEN)
		M.env.restart_screen()
		M.env.log("屏幕设置已更新（编号 " .. (id or "-") .. "，超温阈值 " .. threshold .. "℃）")
		return -- 屏幕程序正在重启，这一分钟不插播
	end

	local msg, urgent = M.screen_message(ctx)
	local port = tonumber(g.control_port)
	if not msg or not port or port < 1 or port > 65535 then return end
	if urgent then
		M.env.run(M.screen_command(math.floor(port), M.SCREEN_URGENT_SECONDS, msg))
	elseif math.floor(M.env.now() / 60) % 2 == 0 then
		M.env.run(M.screen_command(math.floor(port), M.SCREEN_NOTE_SECONDS, msg))
	end
end

-- 按回复改本机配置；返回 changed
function M.handle(c, resp, state)
	local st = resp.status
	if st == "active" then
		local changed, err = M.apply(c, M.plan_active(resp), true)
		if err then error(err) end
		M.write_json(M.LAST_FILE, resp)
		return changed
	elseif st == "unchanged" then
		-- 客户在后台改了 fleet_ 节点：按上次的完整配置写回去
		if state.snapshot and M.snapshot(c) ~= state.snapshot then
			if state.status == "active" then
				local last = M.read_json(M.LAST_FILE)
				local cfg = last and M.validate(last)
				if cfg and cfg.status == "active" then
					M.env.log("发现 fleet_ 节点被改动，已按下发的配置恢复")
					return (M.apply(c, M.plan_active(cfg), true))
				end
			end
			state.version = nil -- 下次要完整配置
		end
		return false
	elseif st == "pending" then
		if M.managed(c) then return M.set_enabled(c, false) end
		return false
	elseif st == "expired" or st == "limited" or st == "no_nodes" then
		-- 保留节点和 UUID：续费后服务器一启用就恢复
		if resp.on_expire == "direct" then return M.set_enabled(c, false) end
		if M.managed(c) then return M.set_enabled(c, true) end
		return false
	elseif st == "disabled" then
		local last = M.read_json(M.LAST_FILE)
		local cfg = last and M.validate(last)
		local direct = (cfg and cfg.direct) or {}
		local changed = M.apply(c, M.plan_blocked(direct), resp.on_expire ~= "direct")
		M.env.remove(M.LAST_FILE)
		return changed
	end
	return false
end

-- 每台路由器用自己的内网地址做随机种子，200 台同时被 cron 叫醒也会错开请求
local function seed_from(text)
	local n = os.time()
	for i = 1, #text do n = (n * 31 + text:byte(i)) % 2147483647 end
	return n
end

function M.run(opts)
	opts = opts or {}
	local c = M.env.cursor()
	local conf = read_conf(c)
	if conf.enabled ~= "1" then return 0 end

	local ok, ts = pcall(json().parse, M.env.exec("tailscale status --json 2>/dev/null"))
	if not ok or type(ts) ~= "table" or ts.BackendState ~= "Running" then
		M.env.log("Tailscale 没登录或没在运行，跳过这一轮")
		return 0
	end
	if not opts.now then
		local self_ips = (type(ts.Self) == "table" and ts.Self.TailscaleIPs) or {}
		math.randomseed(seed_from(tostring(self_ips[1] or "")))
		M.env.sleep(math.random(0, 240))
	end
	local server = conf.server
	if server == "" then server = M.discover(ts) end
	if not server or not M.is_address(server) then
		M.env.log("没找到下发服务器（带 " .. M.FLEET_TAG .. " 标签的设备），跳过这一轮")
		return 0
	end
	local port = tonumber(conf.port) or 8080
	if port < 1 or port > 65535 then port = 8080 end

	local state = M.read_json(M.STATE_FILE) or {}
	local ver = (type(state.version) == "string" and state.version:match("^%x*$")) and state.version or ""
	local host = M.is_ipv6(server) and ("[" .. server .. "]") or server
	local url = string.format("http://%s:%d/v1/config?ver=%s&fw=%s&agent=%s", host, port, ver,
		urlencode(firmware_version()), urlencode(M.VERSION))
	-- 顺带上报 CPU 温度和是否超温（下发服务据此在管理页和面板用户备注里显示告警）
	local health = M.health_check(M.temp_threshold(conf), M.env.now())
	if health.temp then
		url = url .. string.format("&temp=%d&hot=%d", health.temp, health.hot and 1 or 0)
	end
	local body = M.fetch(url, tonumber(conf.timeout) or 20)
	if not body then
		M.env.log("连不上下发服务或它暂时出错，保持现有配置")
		return 0
	end
	local pok, raw = pcall(json().parse, body)
	local resp, err = M.validate(pok and raw or nil)
	if not resp then
		M.env.log("下发的配置不合格（" .. tostring(err) .. "），整份丢弃，保持现有配置")
		return 0
	end
	if health.temp then
		M.env.write(M.REPORTED_FILE, health.hot and "1" or "0")
	end

	local changed = M.handle(c, resp, state)
	if changed then
		M.env.restart_passwall()
		M.env.log("配置已更新（" .. resp.status .. "），重启 PassWall 2")
	end
	local unchanged = resp.status == "unchanged"
	local new_state = {
		version = unchanged and state.version or resp.version,
		status = unchanged and state.status or resp.status,
		on_expire = resp.on_expire or state.on_expire,
		snapshot = M.snapshot(c),
		notice = unchanged and M.clean_notice(state.notice) or resp.notice,
	}
	if new_state.version ~= state.version or new_state.status ~= state.status
		or new_state.snapshot ~= state.snapshot or new_state.on_expire ~= state.on_expire
		or new_state.notice ~= state.notice then
		M.write_json(M.STATE_FILE, new_state) -- 只在有变化时写闪存
	end
	return 0
end

-- 防止两份同时运行；锁目录里记 PID，进程已不在就当作残留锁清掉
local function lock(dir, retried)
	if M.env.run("mkdir " .. dir .. " 2>/dev/null") == 0 then
		M.env.write(dir .. "/pid", tostring(M.env.exec("echo $PPID"):match("%d+") or ""))
		return true
	end
	local pid = (M.env.read(dir .. "/pid") or ""):match("%d+")
	if not retried and pid and not M.env.read("/proc/" .. pid .. "/stat") then
		M.env.run("rm -rf " .. dir)
		return lock(dir, true)
	end
	return false
end

local function unlock(dir)
	M.env.run("rm -rf " .. dir)
end

-- 同步一次（拿到锁才做）；返回 run 的结果或 nil
local function sync(opts)
	if not lock(M.LOCK_DIR) then return nil end
	local ok, err = pcall(M.run, opts)
	unlock(M.LOCK_DIR)
	if not ok then
		M.env.log("出错：" .. tostring(err))
		return 1
	end
	return err or 0
end

-- 每分钟一次：超温状态变了且还没报给服务器就马上同步；再管屏幕
function M.health_run()
	local c = M.env.cursor()
	local conf = read_conf(c)
	local threshold = M.temp_threshold(conf)
	local health = M.health_check(threshold, M.env.now())
	if health.changed and health.temp then
		if health.hot then
			M.env.log("CPU 温度 " .. health.temp .. "℃，超过 " .. threshold .. "℃，告警")
		else
			M.env.log("CPU 温度降到 " .. health.temp .. "℃，超温告警解除")
		end
	end

	local fleet_on = conf.enabled == "1"
	if fleet_on and health.temp and health.hot ~= M.reported_hot() then
		sync({ now = true })
	end

	local ok, v = pcall(json().parse, M.env.exec("tailscale status --json 2>/dev/null"))
	local ts = ok and type(v) == "table" and v or nil
	local ts_up -- 停用同步时不判断管理通道
	if fleet_on then
		ts_up = ts ~= nil and ts.BackendState == "Running"
			and not (type(ts.Self) == "table" and ts.Self.Online == false)
	end
	local state = M.read_json(M.STATE_FILE) or {}
	M.screen_tick(M.env.cursor(), {
		ts = ts, ts_up = ts_up, wan_up = M.wan_up(), threshold = threshold,
		status = state.status, notice = M.clean_notice(state.notice),
	})
	return 0
end

function M.main(argv)
	local opts = {}
	for _, a in ipairs(argv or {}) do
		if a == "--now" then opts.now = true end
		if a == "--health" then opts.health = true end
		if a == "--version" then print(M.VERSION) return 0 end
	end
	M.env.run("mkdir -p /etc/fleet /tmp/fleet")
	if opts.health then
		if not lock(M.HEALTH_LOCK_DIR) then return 0 end
		local ok, err = pcall(M.health_run)
		unlock(M.HEALTH_LOCK_DIR)
		if not ok then
			M.env.log("温度/屏幕检查出错：" .. tostring(err))
			return 1
		end
		return err or 0
	end
	return sync(opts) or 0
end

if not FLEET_AGENT_LIBRARY then
	os.exit(M.main(arg))
end
return M
