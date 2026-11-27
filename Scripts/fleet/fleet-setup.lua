-- 上网设置页的后台（uhttpd CGI，/www/fleet-setup/cgi-bin/api 调它）。
--
-- 家里设备打开 http://192.168.10.1 就是这个页面（完整后台 LuCI、SSH、网页终端只能经 Headscale 内网打开）：
--   * 不用登录：看状态（宽带、海外网络、到期、时区）和客服二维码（扫码打开客服网站：续费、客服、售后、问题反馈）；
--     服务器没开客服网站时直接显示收款码、联系方式和“我已付款”；
--   * 用 WiFi 密码登录：宽带设置（自动获取 / 宽带拨号 / 静态 IP）、手动升级固件（只认我们签过名的升级包）。
--
-- 安全：
--   * 只认 IP 直写、单个词或 .lan 结尾的访问地址（防 DNS 重绑定）；
--   * 写操作只收 JSON 或二进制、带 Origin 时必须和访问地址一致（别的网站借浏览器发不过来）；
--   * 登录凭据放 Authorization 头（不用 Cookie，没有跨站请求伪造的问题）；连错 5 次锁 10 分钟；
--   * 升级包：两个文件（firmware.bin + firmware.bin.sig）的 tar，用固件里的公钥验签、sysupgrade -T 检查都过了才让刷。

local agent = FLEET_SETUP_AGENT
if not agent then
	FLEET_AGENT_LIBRARY = true
	agent = dofile("/usr/bin/fleet-agent")
end

local M = { agent = agent }
M.STATE_DIR = "/tmp/fleet-setup"
M.SESSIONS = M.STATE_DIR .. "/sessions.json"
M.FAILS = M.STATE_DIR .. "/fails.json"
M.PAID_STAMP = M.STATE_DIR .. "/paid.stamp"
M.UPGRADE_DIR = "/tmp/fleet-manual"
M.SESSION_IDLE = 1800
M.MAX_SESSIONS = 8
M.MAX_FAILS = 5
M.LOCK_SECONDS = 600
M.MAX_PACKAGE = 80 * 1024 * 1024
M.MIN_PACKAGE = 1024 * 1024

local shell_quote = agent.shell_quote

M.env = {
	getenv = os.getenv,
	read_stdin = function(n) return io.stdin:read(n) end,
	write_stdout = function(s) io.stdout:write(s) end,
	random_hex = function(bytes)
		local f = io.open("/dev/urandom", "rb")
		if not f then return nil end
		local raw = f:read(bytes)
		f:close()
		if not raw or #raw ~= bytes then return nil end
		return (raw:gsub(".", function(ch) return string.format("%02x", ch:byte()) end))
	end,
	-- 把请求体写进文件（升级包）：边读边写，不整个放进内存
	save_stdin = function(path, length)
		local f = io.open(path, "wb")
		if not f then return false end
		local left = length
		while left > 0 do
			local chunk = io.stdin:read(math.min(65536, left))
			if not chunk or #chunk == 0 then break end
			f:write(chunk)
			left = left - #chunk
		end
		f:close()
		return left == 0
	end,
}

local function json()
	return require("luci.jsonc")
end

local function trim(s)
	return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

-- ---------------------------------------------------------------- 请求检查

-- 防 DNS 重绑定：只认 IP 直写（可以带端口）、单个词的名字、.lan 结尾、localhost
function M.host_ok(host)
	host = tostring(host or ""):lower()
	local name = host:match("^%[([%x:]+)%]:?%d*$") or host:match("^([^:]+):?%d*$")
	if not name or name == "" then return false end
	if agent.is_ipv4(name) or agent.is_ipv6(name) then return true end
	if not name:match("^[%w%-%.]+$") then return false end
	if name == "localhost" or not name:find("%.") then return true end
	return name:match("%.lan$") ~= nil
end

-- 写操作：只收 JSON 或二进制（别的网站用表单发不过来）；带 Origin 时必须和访问地址一致
function M.write_ok(req, want_type)
	if req.method ~= "POST" then return false end
	local ctype = (req.content_type or ""):lower():match("^([^;%s]+)") or ""
	if ctype ~= want_type then return false end
	if req.origin and req.origin ~= "" and req.origin ~= "null" then
		local origin_host = req.origin:lower():match("^https?://([^/]+)$")
		if origin_host ~= tostring(req.host or ""):lower() then return false end
	end
	return true
end

-- ---------------------------------------------------------------- 登录

local function now() return agent.env.now() end

function M.wifi_password()
	local _, key = agent.wifi_info(agent.env.cursor())
	return key
end

local function same(a, b)
	if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
	local diff = 0
	for i = 1, #a do
		if a:byte(i) ~= b:byte(i) then diff = diff + 1 end
	end
	return diff == 0
end

local function load_sessions()
	local s = agent.read_json(M.SESSIONS)
	return type(s) == "table" and s or {}
end

-- 返回 true 或 nil, 原因（locked 时第三个值是还要等几秒）
function M.login(password)
	agent.env.run("mkdir -p " .. M.STATE_DIR .. " && chmod 700 " .. M.STATE_DIR)
	local fails = agent.read_json(M.FAILS) or {}
	local t = now()
	local locked_until = tonumber(fails["until"]) or 0
	if locked_until > t then return nil, "locked", locked_until - t end
	local key = M.wifi_password()
	if not key then return nil, "no_password" end
	if not same(password, key) then
		local count = (t - (tonumber(fails.since) or 0) < M.LOCK_SECONDS) and (tonumber(fails.count) or 0) + 1 or 1
		local new = { count = count, since = (count == 1) and t or fails.since }
		if count >= M.MAX_FAILS then new["until"] = t + M.LOCK_SECONDS end
		agent.write_json(M.FAILS, new)
		agent.env.log("上网设置页登录失败（第 " .. count .. " 次）")
		if new["until"] then return nil, "locked", M.LOCK_SECONDS end
		return nil, "bad_password"
	end
	agent.env.remove(M.FAILS)
	local token = M.env.random_hex(16)
	if not token then return nil, "internal" end
	local sessions, list = load_sessions(), {}
	for tok, last in pairs(sessions) do
		if type(tok) == "string" and t - (tonumber(last) or 0) < M.SESSION_IDLE then list[#list + 1] = { tok, last } end
	end
	table.sort(list, function(a, b) return a[2] > b[2] end)
	local keep = { [token] = t }
	for i = 1, math.min(#list, M.MAX_SESSIONS - 1) do keep[list[i][1]] = list[i][2] end
	agent.write_json(M.SESSIONS, keep)
	return token
end

function M.session_ok(auth)
	local token = tostring(auth or ""):match("^Bearer%s+(%x+)$")
	if not token or #token ~= 32 then return false end
	local sessions = load_sessions()
	local last = tonumber(sessions[token])
	if not last or now() - last >= M.SESSION_IDLE then return false end
	if now() - last > 60 then -- 一分钟最多写一次
		sessions[token] = now()
		agent.write_json(M.SESSIONS, sessions)
	end
	return true, token
end

function M.logout(token)
	local sessions = load_sessions()
	sessions[token] = nil
	agent.write_json(M.SESSIONS, sessions)
end

-- ---------------------------------------------------------------- 宽带设置

-- 子网掩码：二进制是一串 1 后面跟一串 0，/8 到 /30
local function is_mask(m)
	if not agent.is_ipv4(m) then return false end
	local ones, seen_zero = 0, false
	for o in m:gmatch("%d+") do
		local v = tonumber(o)
		for bit = 7, 0, -1 do
			local set = math.floor(v / 2 ^ bit) % 2 == 1
			if set then
				if seen_zero then return false end
				ones = ones + 1
			else
				seen_zero = true
			end
		end
	end
	return ones >= 8 and ones <= 30
end

local function ip_num(ip)
	local n = 0
	for o in tostring(ip):gmatch("%d+") do n = n * 256 + tonumber(o) end
	return n
end

local function same_subnet(a, b, mask)
	local m = ip_num(mask)
	local function band(x, y)
		local r, bit = 0, 1
		for _ = 1, 32 do
			if x % 2 == 1 and y % 2 == 1 then r = r + bit end
			x, y, bit = math.floor(x / 2), math.floor(y / 2), bit * 2
		end
		return r
	end
	return band(ip_num(a), m) == band(ip_num(b), m)
end

function M.lan_ip(c)
	local ip = c:get("network", "lan", "ipaddr")
	if type(ip) == "table" then ip = ip[1] end
	return type(ip) == "string" and ip:match("^([%d%.]+)") or nil
end

function M.wan_view()
	local c = agent.env.cursor()
	local dns = c:get("network", "wan", "dns")
	if type(dns) == "string" then dns = { dns } end
	local out = { proto = c:get("network", "wan", "proto") or "dhcp" }
	if out.proto == "pppoe" then
		out.username = c:get("network", "wan", "username") or ""
		out.has_password = (c:get("network", "wan", "password") or "") ~= ""
	elseif out.proto == "static" then
		out.ipaddr = c:get("network", "wan", "ipaddr") or ""
		out.netmask = c:get("network", "wan", "netmask") or ""
		out.gateway = c:get("network", "wan", "gateway") or ""
		out.dns = agent.array(type(dns) == "table" and dns or {})
	end
	return out
end

-- 看着像可以打的字（不含换行、引号以外的控制字符）
local function printable(s, max)
	return type(s) == "string" and #s >= 1 and #s <= max and not s:find("[%z\1-\31\127]")
end

-- 返回 true 或 nil, 给客户看的原因
function M.set_wan(w)
	if type(w) ~= "table" then return nil, "格式不对" end
	local c = agent.env.cursor()
	if c:get("network", "wan") ~= "interface" then return nil, "这台路由器没有 wan 接口" end
	local proto = w.proto
	local clear = { "username", "password", "ipaddr", "netmask", "gateway", "dns", "service", "ac" }
	if proto == "dhcp" then
		for _, k in ipairs(clear) do c:delete("network", "wan", k) end
		c:set("network", "wan", "proto", "dhcp")
	elseif proto == "pppoe" then
		local user, pass = w.username, w.password
		if not printable(user, 64) or user:find("[%s'\"\\]") then return nil, "宽带账号不对（不能有空格、引号）" end
		local old_pass = c:get("network", "wan", "password")
		if pass == nil or pass == "" then
			if c:get("network", "wan", "proto") ~= "pppoe" or not old_pass or old_pass == "" then
				return nil, "请填宽带密码"
			end
			pass = old_pass
		elseif not printable(pass, 64) then
			return nil, "宽带密码不对（1 到 64 个字符）"
		end
		for _, k in ipairs(clear) do c:delete("network", "wan", k) end
		c:set("network", "wan", "proto", "pppoe")
		c:set("network", "wan", "username", user)
		c:set("network", "wan", "password", pass)
		c:set("network", "wan", "ipv6", "0") -- 固件只用 IPv4
	elseif proto == "static" then
		local ip, mask, gw = trim(w.ipaddr), trim(w.netmask), trim(w.gateway)
		if not agent.is_ipv4(ip) then return nil, "IP 地址不对" end
		if not is_mask(mask) then return nil, "子网掩码不对" end
		if not agent.is_ipv4(gw) then return nil, "网关不对" end
		if not same_subnet(ip, gw, mask) then return nil, "网关和 IP 地址不在一个网段" end
		local lan = M.lan_ip(c)
		if lan and same_subnet(ip, lan, "255.255.255.0") then return nil, "这个地址和路由器的内网（" .. lan .. "）冲突" end
		local dns = {}
		for _, d in ipairs(type(w.dns) == "table" and w.dns or {}) do
			d = trim(d)
			if d ~= "" then
				if not agent.is_ipv4(d) or #dns >= 2 then return nil, "DNS 不对（最多两个 IPv4 地址）" end
				dns[#dns + 1] = d
			end
		end
		for _, k in ipairs(clear) do c:delete("network", "wan", k) end
		c:set("network", "wan", "proto", "static")
		c:set("network", "wan", "ipaddr", ip)
		c:set("network", "wan", "netmask", mask)
		c:set("network", "wan", "gateway", gw)
		if #dns > 0 then c:set("network", "wan", "dns", dns) end
	else
		return nil, "上网方式不对"
	end
	c:commit("network")
	agent.env.log("上网设置页改了宽带设置：" .. proto)
	agent.env.run("( sleep 1; /etc/init.d/network reload ) >/dev/null 2>&1 &")
	return true
end

-- ---------------------------------------------------------------- 手动升级

local function free_tmp_bytes()
	local kb = tonumber(agent.env.exec("df -k /tmp 2>/dev/null | awk 'NR==2 {print $4}'"):match("%d+") or "0")
	return kb * 1024
end

-- 升级包：只能有 firmware.bin 和 firmware.bin.sig 两个普通文件（busybox tar -tv 的输出）。返回两个成员名或 nil
function M.check_members(listing)
	local found = {}
	local n = 0
	for line in tostring(listing or ""):gmatch("[^\n]+") do
		n = n + 1
		local kind = line:sub(1, 1)
		local name = line:match("%s(%S+)$")
		if kind ~= "-" or not name then return nil end
		local plain = name:gsub("^%./", "")
		if plain ~= "firmware.bin" and plain ~= "firmware.bin.sig" then return nil end
		if found[plain] then return nil end
		found[plain] = name
	end
	if n ~= 2 or not found["firmware.bin"] or not found["firmware.bin.sig"] then return nil end
	return found["firmware.bin"], found["firmware.bin.sig"]
end

-- 收下上传的升级包并检查。返回 { size = 固件大小 } 或 nil, 原因
function M.receive_upgrade(length)
	local dir = M.UPGRADE_DIR
	local pkg, img, sig = dir .. "/pkg.tar", dir .. "/firmware.bin", dir .. "/firmware.bin.sig"
	local function fail(why)
		agent.env.run("rm -rf " .. dir)
		return nil, why
	end
	if not length or length < M.MIN_PACKAGE or length > M.MAX_PACKAGE then return nil, "文件大小不对，不像升级包" end
	local pub = agent.env.read(agent.PUBKEY)
	if not pub or pub == "" or not agent.env.exec("command -v usign 2>/dev/null"):match("usign") then
		return nil, "这版固件不支持手动升级（没有签名公钥）"
	end
	agent.env.run("rm -rf " .. dir)
	if free_tmp_bytes() < length * 2 + 32 * 1024 * 1024 then return nil, "路由器内存不够，重启路由器后再试" end
	agent.env.run("mkdir -p " .. dir .. " && chmod 700 " .. dir)
	if not M.env.save_stdin(pkg, length) then return fail("上传没完成，再试一次") end
	local a, b = M.check_members(agent.env.exec("tar -tvf " .. shell_quote(pkg) .. " 2>/dev/null"))
	if not a then return fail("不是升级包（要用发给你的 .tar 升级包，别解压）") end
	if agent.env.run("tar -xf " .. shell_quote(pkg) .. " -C " .. shell_quote(dir) .. " " .. shell_quote(a) .. " "
		.. shell_quote(b) .. " >/dev/null 2>&1") ~= 0 then
		return fail("升级包解不开")
	end
	agent.env.run("rm -f " .. shell_quote(pkg))
	if a ~= "firmware.bin" then agent.env.run("mv -f " .. shell_quote(dir .. "/" .. a) .. " " .. shell_quote(img)) end
	if b ~= "firmware.bin.sig" then agent.env.run("mv -f " .. shell_quote(dir .. "/" .. b) .. " " .. shell_quote(sig)) end
	if agent.env.run("usign -V -q -m " .. shell_quote(img) .. " -p " .. shell_quote(agent.PUBKEY) .. " -x "
		.. shell_quote(sig)) ~= 0 then
		agent.env.log("上网设置页：手动升级包签名不对，拒绝")
		return fail("签名不对：这不是我们发布的固件，不能刷")
	end
	if agent.env.run("sysupgrade -T " .. shell_quote(img) .. " >/dev/null 2>&1") ~= 0 then
		return fail("这个固件不适合这台路由器（型号不对）")
	end
	local size = tonumber((agent.env.exec("wc -c < " .. shell_quote(img)):match("%d+")) or "0")
	agent.env.write(dir .. "/verified", tostring(now()))
	agent.env.log("上网设置页：手动升级包校验通过（" .. math.floor(size / 1048576) .. "MB）")
	return { size = size }
end

function M.start_flash()
	local dir = M.UPGRADE_DIR
	local stamp = tonumber(agent.env.read(dir .. "/verified") or "")
	if not stamp or now() - stamp > 1800 or not agent.env.exists(dir .. "/firmware.bin") then
		return nil, "先上传升级包"
	end
	agent.env.log("上网设置页：开始手动升级（保留配置），路由器会自动重启")
	agent.env.upgrade(dir .. "/firmware.bin")
	return true
end

-- ---------------------------------------------------------------- 请求处理

-- req：{ method, action, host, origin, content_type, length, auth, body（JSON 请求才有） }
-- 返回 HTTP 状态码, 回复（Lua 表）
function M.handle(req)
	-- 连通性探测（uhttpd 的 404 处理送来的，见 Fleet.sh 的 error_page）：只认 GET；
	-- 探测域名不在 host_ok 的白名单里，所以这条分支放最前面
	if req.action == "probe" and req.method == "GET" then return M.probe(req) end
	if not M.host_ok(req.host) then return 403, { error = "bad_host" } end
	local action = req.action
	local authed, token = M.session_ok(req.auth)

	if action == "status" and req.method == "GET" then
		local info = agent.status_info()
		info.wan_proto = agent.env.cursor():get("network", "wan", "proto") or ""
		info.logged_in = authed
		return 200, info
	end

	if action == "portal-status" and req.method == "GET" then
		-- 检测页要的路由器侧状态（不用登录；不含任何密钥）
		return 200, agent.portal_status()
	end

	if action == "portal-done" then
		-- 检测页点“完成”：记一次（一天内不再弹），时区照 tzcheck 的路子记
		if not M.write_ok(req, "application/json") then return 403, { error = "csrf" } end
		local body = type(req.body) == "table" and req.body or {}
		local lang = body.lang
		if lang ~= nil and (type(lang) ~= "string" or #lang > 20 or not lang:match("^[%w%-]+$")) then
			return 400, { error = "lang" }
		end
		if body.tz ~= nil or body.offset ~= nil then
			local res, why = agent.record_client_tz(req.remote, body.tz, body.offset)
			-- 时区格式不对才 400；ARP 里查不到这台设备只是记不上，不卡用户
			if not res and why ~= "mac" then return 400, { error = why } end
		end
		agent.record_portal(req.remote, "done", body.tz, lang)
		return 200, { ok = true }
	end

	if action == "portal-optout" then
		-- 检测页点“这台设备不再提示”：以后不再弹
		if not M.write_ok(req, "application/json") then return 403, { error = "csrf" } end
		agent.record_portal(req.remote, "optout")
		return 200, { ok = true }
	end

	if action == "status" and req.method == "GET" then
		local info = agent.status_info()
		info.wan_proto = agent.env.cursor():get("network", "wan", "proto") or ""
		info.logged_in = authed
		return 200, info
	end

	if action == "tzcheck" then
		-- 页面读出这台设备的时区报上来：只用来提醒，不拦上网
		if not M.write_ok(req, "application/json") then return 403, { error = "csrf" } end
		local body = type(req.body) == "table" and req.body or {}
		local res, why = agent.record_client_tz(req.remote, body.tz, body.offset)
		if not res then return 400, { error = why } end
		return 200, res
	end

	if action == "upload" then
		if not M.write_ok(req, "application/octet-stream") then return 403, { error = "csrf" } end
		if not authed then return 401, { error = "login" } end
		local res, why = M.receive_upgrade(req.length)
		if not res then return 400, { error = "upgrade", message = why } end
		return 200, { ok = true, size = res.size }
	end

	if req.method == "GET" and action == "wan" then
		if not authed then return 401, { error = "login" } end
		return 200, M.wan_view()
	end

	if not M.write_ok(req, "application/json") then return 403, { error = "csrf" } end
	local body = type(req.body) == "table" and req.body or {}

	if action == "login" then
		local tok, why, wait = M.login(body.password)
		if not tok then return (why == "locked") and 429 or 401, { error = why, wait = wait } end
		return 200, { ok = true, token = tok }
	elseif action == "paid" then
		-- 不用登录（到期的客户最需要）；两分钟最多一次，服务器那边同一台 30 分钟只记一次
		local last = tonumber(agent.env.read(M.PAID_STAMP) or "") or 0
		if now() - last < 120 then return 200, { ok = true, repeated = true } end
		local ok, why = agent.paid(body.channel)
		if not ok then return 503, { error = why or "server" } end
		agent.env.run("mkdir -p " .. M.STATE_DIR)
		agent.env.write(M.PAID_STAMP, tostring(now()))
		return 200, { ok = true }
	end

	if not authed then return 401, { error = "login" } end
	if action == "logout" then
		M.logout(token)
		return 200, { ok = true }
	elseif action == "wan" then
		local ok, why = M.set_wan(body)
		if not ok then return 400, { error = "wan", message = why } end
		return 200, { ok = true }
	elseif action == "flash" then
		local ok, why = M.start_flash()
		if not ok then return 400, { error = "upgrade", message = why } end
		return 200, { ok = true }
	end
	return 404, { error = "not_found" }
end

local REASONS = { [200] = "OK", [204] = "No Content", [302] = "Found", [400] = "Bad Request", [401] = "Unauthorized", [403] = "Forbidden",
	[404] = "Not Found", [413] = "Payload Too Large", [429] = "Too Many Requests", [500] = "Internal Server Error",
	[503] = "Service Unavailable" }

-- 连通性探测（uhttpd 的 404 处理把探测请求送到这里）：
-- 该弹检测页就 302 到检测页（同时记一次弹出）；否则回探测本来要的成功响应。
-- 返回 code, body, raw：raw 有值时 cgi() 用 respond_raw 回非 JSON 响应。
function M.probe(req)
	local status, ctype, body = agent.probe_response(req.host)
	if not status then return 404, { error = "not_found" } end
	if agent.portal_due(req.remote) then
		agent.record_portal(req.remote, "shown")
		local lan = M.lan_ip(agent.env.cursor())
		local loc = lan and ("http://" .. lan .. "/portal.html") or "/portal.html"
		return 302, {}, { location = loc }
	end
	return status, {}, { content_type = ctype, body = body }
end

function M.respond(code, body)
	local data = agent.encode_json(body)
	M.env.write_stdout(string.format("Status: %d %s\r\nContent-Type: application/json; charset=utf-8\r\n"
		.. "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n\r\n%s",
		code, REASONS[code] or "OK", #data, data))
end

-- 非 JSON 响应（连通性探测的 204 / 302 / 200 纯文本）：状态行 + 头 + 体
function M.respond_raw(code, raw)
	local body = raw.body or ""
	local head = string.format("Status: %d %s\r\nCache-Control: no-store\r\n", code, REASONS[code] or "OK")
	if raw.location then head = head .. "Location: " .. raw.location .. "\r\n" end
	if raw.content_type then head = head .. "Content-Type: " .. raw.content_type .. "; charset=utf-8\r\n" end
	head = head .. string.format("Content-Length: %d\r\n\r\n", #body)
	M.env.write_stdout(head .. body)
end

function M.cgi()
	local env = M.env.getenv
	local query = env("QUERY_STRING") or ""
	local req = {
		method = env("REQUEST_METHOD") or "GET",
		action = query:match("^a=([%w_]+)$") or query:match("[?&]a=([%w_]+)") or "",
		host = env("HTTP_HOST") or "",
		origin = env("HTTP_ORIGIN"),
		content_type = env("CONTENT_TYPE") or "",
		length = tonumber(env("CONTENT_LENGTH") or ""),
		auth = env("HTTP_AUTHORIZATION"),
		remote = env("REMOTE_ADDR"),
	}
	local ctype = req.content_type:lower():match("^([^;%s]+)") or ""
	if req.method == "POST" and ctype == "application/json" then
		if not req.length or req.length > 8192 then
			M.respond(413, { error = "too_big" })
			return
		end
		local raw = req.length > 0 and M.env.read_stdin(req.length) or ""
		local ok, v = pcall(json().parse, raw or "")
		req.body = ok and type(v) == "table" and v or {}
	end
	local ok, code, body, raw = pcall(M.handle, req)
	if not ok then
		agent.env.log("上网设置页出错：" .. tostring(code))
		M.respond(500, { error = "internal" })
		return
	end
	if raw then M.respond_raw(code, raw) else M.respond(code, body) end
end

return M
