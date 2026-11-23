"""fleet-agent（路由器同步脚本）测试：用 Lua 5.1（和 OpenWrt 同版本）跑真实脚本，
UCI 和 luci.jsonc 用假实现；下发服务的回复直接用 fleet_server.py 生成，保证两边格式对得上。

运行：python3 -m unittest discover -s Scripts/fleet/tests -v
需要：pip install lupa；以及私有仓库里的 fleet/server/fleet_server.py（用环境变量 FLEET_SERVER_DIR 指定目录）。
"""

import copy
import json
import os
import sys
import unittest

from lupa import lua51

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "..", "fleet-agent.lua")
SERVER_DIR = os.environ.get("FLEET_SERVER_DIR", os.path.join(HERE, "..", "..", "..", "..", "openwrt-ci-private", "fleet", "server"))
sys.path.insert(0, SERVER_DIR)
import fleet_server as fs  # noqa: E402

FAKE_UCI = r"""
local function deepcopy(v)
  if type(v) ~= "table" then return v end
  local r = {}
  for k, x in pairs(v) do r[k] = deepcopy(x) end
  return r
end
local Cursor = {}
Cursor.__index = Cursor
function Cursor:find(config, name)
  for i, s in ipairs(self.staged[config] or {}) do
    if s[".name"] == name then return s, i end
  end
end
function Cursor:foreach(config, stype, fn)
  for _, s in ipairs(self.staged[config] or {}) do
    if stype == nil or s[".type"] == stype then fn(deepcopy(s)) end
  end
end
function Cursor:get(config, name, opt)
  local s = self:find(config, name)
  if not s then return nil end
  if opt == nil then return s[".type"] end
  return deepcopy(s[opt])
end
function Cursor:set(config, name, a, b)
  self.staged[config] = self.staged[config] or {}
  if b == nil then
    local s = self:find(config, name)
    if s then s[".type"] = a else table.insert(self.staged[config], { [".name"] = name, [".type"] = a }) end
  else
    local s = self:find(config, name)
    assert(s, "set on missing section " .. name)
    s[a] = deepcopy(b)
  end
  return true
end
function Cursor:delete(config, name, opt)
  local s, i = self:find(config, name)
  if not s then return false end
  if opt then s[opt] = nil else table.remove(self.staged[config], i) end
  return true
end
function Cursor:commit(config) self.committed[config] = deepcopy(self.staged[config]); self.commits = self.commits + 1 end
function Cursor:revert(config) self.staged[config] = deepcopy(self.committed[config]) end
function new_cursor(data)
  return setmetatable({ committed = deepcopy(data), staged = deepcopy(data), commits = 0 }, Cursor)
end
return new_cursor
"""

DEFAULT_PW = [
    {".name": "cfg01", ".type": "global", "enabled": "0", "node": "rulenode", "localhost_proxy": "1"},
    {".name": "cfg02", ".type": "global_delay", "start_daemon": "1", "start_delay": "60"},
    {".name": "examplenode", ".type": "nodes", "remarks": "Example", "type": "Xray", "protocol": "socks"},
    {".name": "rulenode", ".type": "nodes", "protocol": "_shunt", "shunt_group": "CN"},
    {".name": "CN", ".type": "shunt_rules", "group": "CN", "domain_list": "geosite:cn"},
    {".name": "customer_node", ".type": "nodes", "remarks": "客户自己的", "type": "sing-box", "protocol": "vmess"},
]


def server_response(status="active", on_expire="block", nodes=None, direct=("hs.example.com", "198.51.100.7")):
    cfg = fs.Config(direct=list(direct))
    if nodes is None:
        sys.path.insert(0, os.path.join(SERVER_DIR, "tests"))
        import test_fleet_server as t
        nodes, _ = fs.convert_proxy_configs([t.reality_cfg("aaaaaaaa-1111-4111-8111-111111111111"),
                                             t.ws_cfg("bbbbbbbb-2222-4222-8222-222222222222")])
    return fs.build_response(cfg, status, on_expire, nodes)


class AgentHarness:
    def __init__(self):
        self.lua = lua51.LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        jsonc = self.lua.table_from({"parse": self._parse, "stringify": self._stringify})
        g.package.loaded["luci.jsonc"] = jsonc
        g.FLEET_AGENT_LIBRARY = True
        with open(AGENT, encoding="utf-8") as f:
            src = f.read()
        if src.startswith("#!"):
            src = "--" + src[2:]
        self.M = self.lua.execute(src)
        self.new_cursor = self.lua.execute(FAKE_UCI)
        self.files = {}
        self.logs = []
        self.commands = []
        self.restarts = 0
        self.screen_restarts = 0
        self.exec_map = {}
        env = self.M.env
        env.exec = self._exec
        env.run = lambda cmd: (self.commands.append(cmd), 0)[1]
        env.read = lambda path: self.files.get(path)
        env.write = lambda path, data: self.files.__setitem__(path, data) or True
        env.remove = lambda path: self.files.pop(path, None)
        env.log = lambda msg: self.logs.append(msg)
        env.sleep = lambda n: None
        env.restart_passwall = self._restart
        env.restart_screen = self._restart_screen
        self.now = 1800000000  # 整分钟、偶数分钟
        env.now = lambda: self.now
        self.cursor = self.new_cursor(self.to_lua({"passwall2": copy.deepcopy(DEFAULT_PW),
                                                   "fleet": [{".name": "main", ".type": "agent", "enabled": "1",
                                                              "server": "", "port": "8080"}]}))
        env.cursor = lambda: self.cursor

    # ---- JSON 桥
    def to_lua(self, v):
        if isinstance(v, dict):
            return self.lua.table_from({k: self.to_lua(x) for k, x in v.items() if x is not None})
        if isinstance(v, list):
            return self.lua.table_from([self.to_lua(x) for x in v])
        return v

    def to_py(self, v):
        if hasattr(v, "keys") and not isinstance(v, (str, bytes)):
            keys = list(v.keys())
            if keys and all(isinstance(k, int) for k in keys) and sorted(keys) == list(range(1, len(keys) + 1)):
                return [self.to_py(v[k]) for k in sorted(keys)]
            return {k: self.to_py(v[k]) for k in keys}
        return v

    def _parse(self, s):
        try:
            return self.to_lua(json.loads(s))
        except (ValueError, TypeError):
            return None

    def _stringify(self, t):
        return json.dumps(self.to_py(t), ensure_ascii=False)

    def _exec(self, cmd):
        self.commands.append(cmd)
        for key, val in self.exec_map.items():
            if key in cmd:
                return val(cmd) if callable(val) else val
        return ""

    def _restart(self):
        self.restarts += 1

    def _restart_screen(self):
        self.screen_restarts += 1

    # ---- 便捷方法
    def sections(self, stype=None):
        out = {}
        for s in self.to_py(self.cursor.committed["passwall2"]):
            if stype is None or s[".type"] == stype:
                out[s[".name"]] = s
        return out

    def global_opts(self):
        return [s for s in self.to_py(self.cursor.committed["passwall2"]) if s[".type"] == "global"][0]

    def validate(self, resp):
        res = self.M.validate(self.to_lua(resp))
        if isinstance(res, tuple):
            return res
        return res, None

    def handle(self, resp, state=None):
        cfg, err = self.validate(resp)
        assert cfg is not None, err
        return self.M.handle(self.cursor, cfg, self.to_lua(state or {}))


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()

    def test_accepts_real_server_output(self):
        cfg, err = self.h.validate(server_response())
        self.assertIsNotNone(cfg, err)
        py = self.h.to_py(cfg)
        self.assertEqual(len(py["nodes"]), 2)
        self.assertEqual(py["direct"], ["hs.example.com", "198.51.100.7"])
        for status in ("pending", "expired", "limited", "disabled", "no_nodes"):
            self.assertIsNotNone(self.h.validate(server_response(status))[0], status)
        self.assertIsNotNone(self.h.validate({"schema": 1, "status": "unchanged", "version": "ab12"})[0])

    def test_rejects_bad_or_malicious_fields(self):
        good = server_response()
        mutations = [
            ("address", "1.2.3.4; rm -rf /"), ("address", "evil'host"), ("port", 0), ("port", 70000), ("port", "443x"),
            ("uuid", "not-a-uuid"), ("protocol", "vmess"), ("transport", "grpc"), ("tls", False),
            ("public_key", "abc'def"), ("short_id", "zz"), ("sni", "bad host"), ("flow", "xtls-rprx-direct"),
            ("id", "../etc"), ("id", "x" * 30),
        ]
        for key, value in mutations:
            resp = copy.deepcopy(good)
            resp["nodes"][0][key] = value
            cfg, err = self.h.validate(resp)
            self.assertIsNone(cfg, "%s=%r 应该被拒绝" % (key, value))
        bad_ws = copy.deepcopy(good)
        bad_ws["nodes"][1]["ws_path"] = "/a b'"
        self.assertIsNone(self.h.validate(bad_ws)[0])
        for top in ({"status": "hacked"}, {"status": "active", "on_expire": "sometimes", "nodes": good["nodes"]},
                    {"status": "active", "nodes": []}, {"status": "active", "version": "zz!", "nodes": good["nodes"]},
                    dict(good, direct=["ok.com", "bad entry"]), dict(good, auto={"url": "file:///etc/shadow"})):
            self.assertIsNone(self.h.validate(top)[0], str(top)[:80])

    def test_long_interval_is_capped(self):
        resp = server_response()
        resp["auto"]["interval"] = "2h"
        cfg, _ = self.h.validate(resp)
        self.assertEqual(self.h.to_py(cfg)["auto"]["interval"], "30m")

    def test_remark_cleaning_keeps_utf8_valid(self):
        long = "菲律宾" * 40 + "'\"\x01"
        cleaned = self.h.M.clean_remark(long, "fallback")
        cleaned.encode("utf-8")  # 截断后仍是合法 UTF-8
        self.assertNotIn("'", cleaned)
        self.assertLessEqual(len(cleaned.encode("utf-8")), 96)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()

    def test_active_writes_passwall2_sections(self):
        self.assertTrue(self.h.handle(server_response()))
        nodes = self.h.sections("nodes")
        reality = nodes["fleet_haaaaaaaa11"]
        self.assertEqual(reality["type"], "sing-box")
        self.assertEqual(reality["protocol"], "vless")
        self.assertEqual((reality["tls"], reality["reality"], reality["reality_publicKey"], reality["reality_shortId"],
                          reality["tls_serverName"], reality["flow"], reality["transport"], reality["port"]),
                         ("1", "1", "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "a1b2c3d4", "www.microsoft.com",
                          "xtls-rprx-vision", "tcp", "443"))
        ws = nodes["fleet_hbbbbbbbb22"]
        self.assertEqual((ws["transport"], ws["ws_path"], ws["ws_host"], ws["reality"], ws["alpn"]),
                         ("ws", "/ws-9f3k?ed=2048", "cdn.example.com", "0", "h2,http/1.1"))
        auto = nodes["fleet_auto"]
        self.assertEqual(auto["protocol"], "_urltest")
        self.assertEqual(auto["urltest_node"], ["fleet_haaaaaaaa11", "fleet_hbbbbbbbb22"])
        shunt = nodes["fleet_shunt"]
        self.assertEqual((shunt["protocol"], shunt["shunt_group"], shunt["CN"], shunt["default_node"],
                          shunt["ProxyFront"], shunt["fleet_direct"]),
                         ("_shunt", "CN", "_direct", "fleet_auto", "fleet_auto", "_direct"))
        rule = self.h.sections("shunt_rules")["fleet_direct"]
        self.assertEqual((rule["group"], rule["domain_list"], rule["ip_list"]),
                         ("CN", "domain:hs.example.com", "198.51.100.7"))
        g = self.h.global_opts()
        self.assertEqual((g["node"], g["enabled"]), ("fleet_shunt", "1"))
        # 客户自己的节点、PassWall 2 自带的段都没动
        self.assertIn("customer_node", nodes)
        self.assertIn("examplenode", nodes)
        self.assertIn("CN", self.h.sections("shunt_rules"))

    def test_same_config_twice_does_not_write_flash(self):
        resp = server_response()
        self.assertTrue(self.h.handle(resp))
        commits = self.h.cursor.commits
        self.assertFalse(self.h.handle(resp))
        self.assertEqual(self.h.cursor.commits, commits)

    def test_removed_node_is_deleted(self):
        resp = server_response()
        self.h.handle(resp)
        resp2 = copy.deepcopy(resp)
        resp2["nodes"] = resp2["nodes"][:1]
        self.assertTrue(self.h.handle(resp2))
        nodes = self.h.sections("nodes")
        self.assertNotIn("fleet_hbbbbbbbb22", nodes)
        self.assertEqual(nodes["fleet_auto"]["urltest_node"], ["fleet_haaaaaaaa11"])

    def test_expired_block_keeps_nodes_direct_turns_off(self):
        self.h.handle(server_response())
        self.assertFalse(self.h.handle(server_response("expired", "block")))
        self.assertIn("fleet_haaaaaaaa11", self.h.sections("nodes"))
        self.assertEqual(self.h.global_opts()["enabled"], "1")
        self.assertTrue(self.h.handle(server_response("expired", "direct")))
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.assertIn("fleet_haaaaaaaa11", self.h.sections("nodes"))  # UUID 保留，续费即恢复

    def test_disabled_removes_uuids_and_blackholes_proxy(self):
        self.h.handle(server_response())
        self.assertTrue(self.h.handle(server_response("disabled", "block")))
        nodes = self.h.sections("nodes")
        self.assertFalse([n for n in nodes.values() if n.get("uuid") and n[".name"].startswith("fleet_")])
        shunt = nodes["fleet_shunt"]
        self.assertEqual((shunt["default_node"], shunt["ProxyFront"], shunt["CN"]), ("_blackhole", "_blackhole", "_direct"))
        self.assertEqual(self.h.global_opts()["enabled"], "1")
        self.assertIn("fleet_direct", self.h.sections("shunt_rules"))  # 管理通道仍然直连

    def test_pending_only_touches_managed_router(self):
        self.assertFalse(self.h.handle(server_response("pending")))
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.h.handle(server_response())
        self.assertTrue(self.h.handle(server_response("pending")))
        self.assertEqual(self.h.global_opts()["enabled"], "0")

    def test_tampered_nodes_are_restored(self):
        resp = server_response()
        self.h.handle(resp)
        snapshot = self.h.M.snapshot(self.h.cursor)
        state = {"version": resp["version"], "status": "active", "snapshot": snapshot}
        # 客户在后台改了 UUID
        c = self.h.cursor
        c.set(c, "passwall2", "fleet_haaaaaaaa11", "uuid", "00000000-0000-4000-8000-000000000000")
        c.commit(c, "passwall2")
        changed = self.h.handle({"schema": 1, "status": "unchanged", "version": resp["version"]}, state)
        self.assertTrue(changed)
        self.assertEqual(self.h.sections("nodes")["fleet_haaaaaaaa11"]["uuid"], fs_vless())


def fs_vless():
    sys.path.insert(0, os.path.join(SERVER_DIR, "tests"))
    import test_fleet_server as t
    return t.VLESS_ID


class RunTests(unittest.TestCase):
    STATUS = {
        "BackendState": "Running",
        "Self": {"TailscaleIPs": ["100.64.0.20", "fd7a:115c:a1e0::20"]},
        "Peer": {
            "k1": {"HostName": "my-phone", "TailscaleIPs": ["100.64.0.2"], "Tags": None},
            "k2": {"HostName": "fleet", "TailscaleIPs": ["100.64.0.9", "fd7a:115c:a1e0::9"], "Tags": ["tag:fleet"]},
        },
    }

    def setUp(self):
        self.h = AgentHarness()
        self.h.files["/etc/openwrt_version"] = "r28000-abcdef\n"
        self.h.exec_map["tailscale status --json"] = json.dumps(self.STATUS)
        self.h.exec_map["echo $PPID"] = "1234\n"

    def serve(self, body):
        self.h.exec_map["uclient-fetch"] = lambda cmd: (json.dumps(body) if body is not None else "") + \
            ("__FLEET_RC=0\n" if body is not None else "__FLEET_RC=4\n")

    def test_full_run_applies_and_saves_state(self):
        resp = server_response()
        self.serve(resp)
        self.assertEqual(self.h.M.main(self.h.lua.table_from(["--now"])), 0)
        fetch = [c for c in self.h.commands if "uclient-fetch" in c][0]
        self.assertIn("'http://100.64.0.9:8080/v1/config?ver=&fw=r28000-abcdef&agent=1.1.0'", fetch)
        self.assertEqual(self.h.restarts, 1)
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual((state["version"], state["status"]), (resp["version"], "active"))
        self.assertIn("/etc/fleet/last.json", self.h.files)
        # 第二轮：带上版本号，服务端说没变化 → 不重启
        self.serve({"schema": 1, "status": "unchanged", "version": resp["version"], "refresh_seconds": 600})
        self.h.M.main(self.h.lua.table_from(["--now"]))
        fetch2 = [c for c in self.h.commands if "uclient-fetch" in c][-1]
        self.assertIn("ver=" + resp["version"], fetch2)
        self.assertEqual(self.h.restarts, 1)

    def test_server_unreachable_keeps_config(self):
        self.serve(server_response())
        self.h.M.main(self.h.lua.table_from(["--now"]))
        before = self.h.sections()
        self.serve(None)
        self.h.M.main(self.h.lua.table_from(["--now"]))
        self.assertEqual(self.h.sections(), before)
        self.assertTrue(any("保持现有配置" in m for m in self.h.logs))

    def test_garbage_response_is_discarded(self):
        self.h.exec_map["uclient-fetch"] = "<html>oops</html>__FLEET_RC=0\n"
        self.h.M.main(self.h.lua.table_from(["--now"]))
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.assertTrue(any("不合格" in m for m in self.h.logs))

    def test_tailscale_down_skips(self):
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "NeedsLogin"})
        self.serve(server_response())
        self.h.M.main(self.h.lua.table_from(["--now"]))
        self.assertFalse([c for c in self.h.commands if "uclient-fetch" in c])

    def test_disabled_in_uci_does_nothing(self):
        c = self.h.cursor
        c.set(c, "fleet", "main", "enabled", "0")
        c.commit(c, "fleet")
        self.serve(server_response())
        self.h.M.main(self.h.lua.table_from(["--now"]))
        self.assertFalse([c for c in self.h.commands if "uclient-fetch" in c])

    def test_url_quoting_is_safe(self):
        q = self.h.M.shell_quote("a'b")
        self.assertEqual(q, "'a'\\''b'")


if __name__ == "__main__":
    unittest.main()


class EndToEndTests(unittest.TestCase):
    """真实的 fleet-server（HTTP）+ 假 Remnawave + 路由器脚本，走完整个生命周期。"""

    NAME = "re-cs-02-1c2ab34d5e6f"

    def setUp(self):
        import threading
        import urllib.error
        import urllib.request
        sys.path.insert(0, os.path.join(SERVER_DIR, "tests"))
        import test_fleet_server as t
        self.t = t
        self.panel = t.FakePanel()
        cfg = fs.Config.from_env({"REMNAWAVE_URL": self.panel.url, "REMNAWAVE_TOKEN": "test-token", "FLEET_DB": ":memory:",
                                  "FLEET_CACHE_TTL": "0", "FLEET_DIRECT": "hs.example.com", "FLEET_RATE_PER_MINUTE": "1000"})
        cfg.port = 0
        whois = fs.WhoisCache(cfg, lambda c, ip: t.whois_router("node-1", self.NAME), ttl=0)
        self.fleet = fs.Fleet(cfg, fs.Store(":memory:"), fs.RemnawaveClient(cfg), whois)
        self.server = fs.make_server(cfg, self.fleet, "127.0.0.1")
        port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

        self.h = AgentHarness()
        self.h.files["/etc/openwrt_version"] = "r28000\n"
        status = copy.deepcopy(RunTests.STATUS)
        self.h.exec_map["tailscale status --json"] = json.dumps(status)
        self.h.exec_map["echo $PPID"] = "99\n"
        c = self.h.cursor
        c.set(c, "fleet", "main", "server", "127.0.0.1")
        c.set(c, "fleet", "main", "port", str(port))
        c.commit(c, "fleet")

        def fetch(cmd):
            url = cmd.split("'")[1]
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    return r.read().decode() + "__FLEET_RC=0\n"
            except urllib.error.HTTPError:
                return "__FLEET_RC=8\n"  # uclient-fetch 遇到非 200 时退出码非 0
        self.h.exec_map["uclient-fetch"] = fetch

    def tearDown(self):
        self.server.shutdown()
        self.panel.close()

    def cycle(self):
        self.assertEqual(self.h.M.main(self.h.lua.table_from(["--now"])), 0)

    def test_lifecycle(self):
        t = self.t
        # 1. 新路由器：面板里还没有用户 → 待开通，PassWall 2 保持关闭
        self.cycle()
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.assertEqual(self.fleet.store.get("node-1")["last_status"], "pending")
        # 2. 面板里建好同名用户 → 自动绑定，写入节点并打开
        self.panel.users[self.NAME] = t.make_user(self.NAME)
        self.panel.configs[self.NAME] = [t.reality_cfg("aaaaaaaa-1111-4111-8111-111111111111"),
                                         t.ws_cfg("bbbbbbbb-2222-4222-8222-222222222222")]
        self.cycle()
        nodes = self.h.sections("nodes")
        self.assertIn("fleet_haaaaaaaa11", nodes)
        self.assertEqual((self.h.global_opts()["node"], self.h.global_opts()["enabled"]), ("fleet_shunt", "1"))
        restarts = self.h.restarts
        # 3. 没变化 → 不重启
        self.cycle()
        self.assertEqual(self.h.restarts, restarts)
        # 4. 面板里换了地址 → 下一轮更新
        self.panel.configs[self.NAME][0]["address"] = "203.0.113.99"
        self.cycle()
        self.assertEqual(self.h.sections("nodes")["fleet_haaaaaaaa11"]["address"], "203.0.113.99")
        # 5. 到期（默认 block）→ 节点保留，PassWall 2 开着；设了 EXPIRE_DIRECT → 关掉
        self.panel.users[self.NAME]["status"] = "EXPIRED"
        self.cycle()
        self.assertIn("fleet_haaaaaaaa11", self.h.sections("nodes"))
        self.assertEqual(self.h.global_opts()["enabled"], "1")
        self.panel.users[self.NAME]["tag"] = "EXPIRE_DIRECT"
        self.cycle()
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        # 6. 续费 → 恢复
        self.panel.users[self.NAME].update(status="ACTIVE", tag=None)
        self.cycle()
        self.assertEqual(self.h.global_opts()["enabled"], "1")
        # 7. 面板暂时连不上 → 保持现状
        before = self.h.sections()
        self.panel.down = True
        self.cycle()
        self.assertEqual(self.h.sections(), before)
        self.panel.down = False
        # 8. 停用 → 节点和 UUID 删掉，翻墙流量丢弃，管理通道直连规则还在
        self.panel.users[self.NAME]["status"] = "DISABLED"
        self.cycle()
        nodes = self.h.sections("nodes")
        self.assertNotIn("fleet_haaaaaaaa11", nodes)
        self.assertEqual(nodes["fleet_shunt"]["default_node"], "_blackhole")
        self.assertIn("fleet_direct", self.h.sections("shunt_rules"))


# ---------------------------------------------------------------- 温度、超温上报、屏幕
THERMAL = "/sys/class/thermal/thermal_zone%d/%s"
ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
ROUTE_LAN = "br-lan\t000AA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
ROUTE_UP = ROUTE_HEADER + "wan\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" + ROUTE_LAN
ROUTE_DOWN = ROUTE_HEADER + ROUTE_LAN
SCREEN = {".name": "general", ".type": "settings", "enabled": "1", "fleet_defaults": "1",
          "custom_content": "??????", "temp_alert": "90", "control_port": "8377"}


class HealthTests(unittest.TestCase):
    STATUS = copy.deepcopy(RunTests.STATUS)
    STATUS["Self"]["HostName"] = "re-cs-02-1c2ab34d5e6f"
    STATUS["Self"]["Online"] = True

    def setUp(self):
        self.h = AgentHarness()
        self.h.files["/etc/openwrt_version"] = "r28000\n"
        self.h.files["/proc/net/route"] = ROUTE_UP
        self.h.files[THERMAL % (0, "type")] = "nss-top-thermal\n"
        self.h.files[THERMAL % (0, "temp")] = "61000\n"
        self.h.files[THERMAL % (4, "type")] = "cpu-thermal\n"
        self.set_temp(72.5)
        self.h.exec_map["tailscale status --json"] = json.dumps(self.STATUS)
        self.h.exec_map["echo $PPID"] = "77\n"
        c = self.h.cursor
        self.h.cursor = self.h.new_cursor(self.h.to_lua({
            "passwall2": self.h.to_py(c.committed["passwall2"]),
            "fleet": self.h.to_py(c.committed["fleet"]),
            "athena_led": [dict(SCREEN)],
        }))
        self.serve(server_response())

    def set_temp(self, celsius):
        self.h.files[THERMAL % (4, "temp")] = "%d\n" % int(celsius * 1000)

    def serve(self, body):
        self.body = body
        self.h.exec_map["uclient-fetch"] = lambda cmd: json.dumps(self.body) + "__FLEET_RC=0\n"

    def fetches(self):
        return [c for c in self.h.commands if "uclient-fetch" in c]

    def screen_cmds(self):
        return [c for c in self.h.commands if "nc 127.0.0.1" in c]

    def health(self):
        self.assertEqual(self.h.M.main(self.h.lua.table_from(["--health"])), 0)

    def screen_conf(self):
        return [s for s in self.h.to_py(self.h.cursor.committed["athena_led"]) if s[".name"] == "general"][0]

    def test_cpu_temp_uses_cpu_zone_and_rounds(self):
        self.assertEqual(self.h.M.cpu_temp(), 73)
        del self.h.files[THERMAL % (4, "type")]  # 没有叫 cpu 的传感器：退回 thermal_zone4
        self.assertEqual(self.h.M.cpu_temp(), 73)
        del self.h.files[THERMAL % (4, "temp")]
        self.assertIsNone(self.h.M.cpu_temp())

    def test_hysteresis(self):
        M = self.h.M
        self.set_temp(89)
        r = M.health_check(90, 1000)
        self.assertEqual((r.temp, r.hot, r.changed), (89, False, False))
        self.set_temp(90)
        r = M.health_check(90, 1060)
        self.assertEqual((r.hot, r.since, r.changed), (True, 1060, True))
        self.set_temp(88)  # 只降了 2℃：还算超温，开始时间不变
        r = M.health_check(90, 1120)
        self.assertEqual((r.hot, r.since, r.changed), (True, 1060, False))
        self.set_temp(87)
        r = M.health_check(90, 1180)
        self.assertEqual((r.hot, r.since, r.changed), (False, None, True))

    def test_sync_reports_temperature(self):
        self.h.M.main(self.h.lua.table_from(["--now"]))
        self.assertIn("&temp=73&hot=0'", self.fetches()[-1])
        self.assertEqual(self.h.files[self.h.M.REPORTED_FILE], "0")

    def test_overheat_is_reported_at_once_and_only_once(self):
        self.h.M.main(self.h.lua.table_from(["--now"]))
        n = len(self.fetches())
        self.set_temp(95)
        self.health()
        self.assertEqual(len(self.fetches()), n + 1)
        self.assertIn("&temp=95&hot=1'", self.fetches()[-1])
        self.assertTrue(any("超过 90℃" in m for m in self.h.logs))
        self.health()  # 已经报过：不再同步
        self.assertEqual(len(self.fetches()), n + 1)
        self.set_temp(86)
        self.health()
        self.assertIn("&temp=86&hot=0'", self.fetches()[-1])
        self.assertTrue(any("解除" in m for m in self.h.logs))

    def test_unreported_alarm_retries_next_minute(self):
        self.set_temp(95)
        self.h.exec_map["uclient-fetch"] = "__FLEET_RC=4\n"  # 下发服务暂时连不上
        self.health()
        self.health()
        self.assertEqual(len(self.fetches()), 2)
        self.serve(server_response())
        self.health()
        self.assertEqual(self.h.files[self.h.M.REPORTED_FILE], "1")
        self.health()
        self.assertEqual(len(self.fetches()), 3)

    def test_threshold_from_fleet_config(self):
        c = self.h.cursor
        c.set(c, "fleet", "main", "temp_alert", "75")
        c.commit(c, "fleet")
        self.set_temp(80)
        self.health()
        self.assertIn("&hot=1'", self.fetches()[-1])
        self.assertEqual(self.screen_conf()["temp_alert"], "75")  # 屏幕的闪烁告警也跟着改
        for bad in ("abc", "5", "500"):
            self.assertEqual(self.h.M.temp_threshold(self.h.lua.table_from({"temp_alert": bad})), 90)

    def test_fleet_disabled_still_runs_screen_but_never_syncs(self):
        c = self.h.cursor
        c.set(c, "fleet", "main", "enabled", "0")
        c.commit(c, "fleet")
        self.set_temp(99)
        self.health()
        self.assertEqual(self.fetches(), [])
        self.assertEqual(self.screen_conf()["custom_content"], "4D5E6F")

    def test_screen_id_from_device_name(self):
        self.health()
        conf = self.screen_conf()
        self.assertEqual((conf["custom_content"], conf["fleet_id"]), ("4D5E6F", "4D5E6F"))
        self.assertEqual(self.h.screen_restarts, 1)
        self.health()
        self.assertEqual(self.h.screen_restarts, 1)

    def test_screen_id_falls_back_to_lan_mac(self):
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "Running", "Self": {"HostName": "OpenWrt"}})
        self.h.files["/sys/class/net/br-lan/address"] = "1C:2A:B3:00:00:0A\n"
        self.health()
        self.assertEqual(self.screen_conf()["custom_content"], "00000A")

    def test_screen_text_set_by_admin_is_kept(self):
        c = self.h.cursor
        c.set(c, "athena_led", "general", "custom_content", "HELLO")
        c.commit(c, "athena_led")
        self.health()
        self.assertEqual(self.screen_conf()["custom_content"], "HELLO")
        self.assertEqual(self.h.screen_restarts, 0)

    def test_screen_not_managed_is_left_alone(self):
        c = self.h.cursor
        c.delete(c, "athena_led", "general", "fleet_defaults")
        c.commit(c, "athena_led")
        self.set_temp(95)
        self.health()
        self.assertEqual(self.screen_conf()["custom_content"], "??????")
        self.assertEqual(self.screen_cmds(), [])

    def test_screen_messages(self):
        self.health()  # 第一次：填编号、重启屏幕程序，这一分钟不插播
        self.assertEqual(self.screen_cmds(), [])
        self.health()  # 一切正常：不插播
        self.assertEqual(self.screen_cmds(), [])

        cases = [
            ({"/proc/net/route": ROUTE_DOWN}, None, "NET DOWN"),
            ({}, {"BackendState": "NeedsLogin"}, "TS DOWN"),
            ({}, dict(self.STATUS, Self=dict(self.STATUS["Self"], Online=False)), "TS DOWN"),
        ]
        for files, ts, text in cases:
            self.h.files.update(files)
            if ts is not None:
                self.h.exec_map["tailscale status --json"] = json.dumps(ts)
            for minute in (0, 1):  # 紧急提示每分钟都插播 8 秒
                self.h.now = 1800000000 + minute * 60
                n = len(self.screen_cmds())
                self.health()
                self.assertEqual(len(self.screen_cmds()), n + 1)
                self.assertIn("'show 8 %s\\n' '" + text + "'", self.screen_cmds()[-1])
            self.h.files["/proc/net/route"] = ROUTE_UP
            self.h.exec_map["tailscale status --json"] = json.dumps(self.STATUS)

        for status, text in (("expired", "EXPIRED"), ("limited", "LIMIT"), ("disabled", "STOPPED"),
                             ("pending", "WAIT"), ("no_nodes", "NO NODE")):
            self.h.files["/etc/fleet/state.json"] = json.dumps({"status": status})
            self.h.now = 1800000000
            self.health()
            self.assertIn("'show 15 %s\\n' '" + text + "'", self.screen_cmds()[-1])
            n = len(self.screen_cmds())
            self.h.now = 1800000060  # 长期提示隔一分钟才插播一次
            self.health()
            self.assertEqual(len(self.screen_cmds()), n)
        # 后台留言比账号状态优先
        self.h.now = 1800000000
        self.h.files["/etc/fleet/state.json"] = json.dumps({"status": "expired", "notice": "PAY BY 12-01"})
        self.health()
        self.assertIn("'PAY BY 12-01'", self.screen_cmds()[-1])

    def test_screen_command_is_quoted(self):
        cmd = self.h.M.screen_command(8377, 8, "A'B")
        self.assertEqual(cmd, "printf 'show 8 %s\\n' 'A'\\''B' | nc 127.0.0.1 8377 >/dev/null 2>&1 &")

    def test_wan_up(self):
        self.assertTrue(self.h.M.wan_up())
        self.h.files["/proc/net/route"] = ROUTE_DOWN
        self.assertFalse(self.h.M.wan_up())
        del self.h.files["/proc/net/route"]
        self.assertIsNone(self.h.M.wan_up())


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()

    def test_clean_notice(self):
        M = self.h.M
        self.assertEqual(M.clean_notice("  pay   by 12-01 "), "PAY BY 12-01")
        self.assertEqual(M.clean_notice("CALL 13800000000"), "CALL 13800000000")
        for bad in ("续费", "a" * 25, "x;rm -rf /", "a'b", "", "   ", None, 5):
            self.assertIsNone(M.clean_notice(bad), repr(bad))

    def test_notice_saved_and_kept_when_unchanged(self):
        h = self.h
        h.files["/etc/openwrt_version"] = "r28000\n"
        h.exec_map["tailscale status --json"] = json.dumps(RunTests.STATUS)
        h.exec_map["echo $PPID"] = "5\n"
        resp = server_response()
        resp["notice"] = "pay by 12-01"
        h.exec_map["uclient-fetch"] = json.dumps(resp) + "__FLEET_RC=0\n"
        h.M.main(h.lua.table_from(["--now"]))
        self.assertEqual(json.loads(h.files["/etc/fleet/state.json"])["notice"], "PAY BY 12-01")
        h.exec_map["uclient-fetch"] = json.dumps({"schema": 1, "status": "unchanged", "version": resp["version"]}) + "__FLEET_RC=0\n"
        h.M.main(h.lua.table_from(["--now"]))
        self.assertEqual(json.loads(h.files["/etc/fleet/state.json"])["notice"], "PAY BY 12-01")
        # 新配置里没有留言：清掉
        h.exec_map["uclient-fetch"] = json.dumps(server_response()) + "__FLEET_RC=0\n"
        h.M.main(h.lua.table_from(["--now"]))
        self.assertNotIn("notice", json.loads(h.files["/etc/fleet/state.json"]))

    def test_bad_notice_does_not_block_config(self):
        resp = server_response()
        resp["notice"] = "续费"
        cfg, err = self.h.validate(resp)
        self.assertIsNotNone(cfg, err)
        self.assertIsNone(self.h.to_py(cfg).get("notice"))


class EndToEndHealthTests(EndToEndTests):
    """真实 fleet-server + 路由器脚本：超温告警、面板备注、屏幕留言。"""

    test_lifecycle = None  # 父类的完整生命周期这里不重复跑

    def test_overheat_and_notice(self):
        t = self.t
        self.panel.users[self.NAME] = t.make_user(self.NAME)
        self.panel.configs[self.NAME] = [t.reality_cfg("aaaaaaaa-1111-4111-8111-111111111111")]
        self.h.files[THERMAL % (4, "type")] = "cpu-thermal\n"
        self.h.files[THERMAL % (4, "temp")] = "71000\n"
        self.cycle()
        node = self.fleet.store.get("node-1")
        self.assertEqual((node["username"], node["temp"], node["hot"]), (self.NAME, 71, 0))

        # 超温：每分钟的检查马上上报，管理页数据和面板备注都更新
        self.h.files[THERMAL % (4, "temp")] = "95000\n"
        self.assertEqual(self.h.M.main(self.h.lua.table_from(["--health"])), 0)
        self.assertEqual(self.fleet.store.get("node-1")["hot"], 1)
        self.assertTrue(self.fleet.notes.flush())
        self.assertEqual(self.panel.users[self.NAME]["description"], "⚠ 路由器温度过高：95℃\n张三 13800000000")

        # 后台写留言：下一轮同步路由器就拿到
        self.fleet.store.set_notice("node-1", "PAY BY 12-01")
        self.cycle()
        self.assertEqual(json.loads(self.h.files["/etc/fleet/state.json"])["notice"], "PAY BY 12-01")

        # 降温：马上报“恢复”，备注那一行去掉
        self.h.files[THERMAL % (4, "temp")] = "80000\n"
        self.h.M.main(self.h.lua.table_from(["--health"]))
        self.assertEqual(self.fleet.store.get("node-1")["hot"], 0)
        self.assertTrue(self.fleet.notes.flush())
        self.assertEqual(self.panel.users[self.NAME]["description"], "张三 13800000000")
        kinds = [e["kind"] for e in self.fleet.store.events(10, ["overheat", "overheat_clear"])]
        self.assertEqual(kinds, ["overheat_clear", "overheat"])
