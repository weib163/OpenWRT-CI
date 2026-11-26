"""在 Python 里跑真实的 fleet-agent.lua（Lua 5.1，和 OpenWrt 同版本）：UCI、luci.jsonc、命令执行都换成假的。

私有仓库的端到端测试也用它，所以别依赖本目录以外的东西。需要：pip install lupa
"""

import copy
import json
import os

from lupa import lua51

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "..", "fleet-agent.lua")
FIXTURES = os.path.join(HERE, "fixtures", "server_responses.json")

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

# 刚刷好时的系统配置（只留测试用得到的部分）
DEFAULT_UCI = {
    "fleet": [{".name": "main", ".type": "agent", "enabled": "1", "server": "", "port": "8080", "ota": "1",
               "wifi_prefix": "OWRT"}],
    "dhcp": [{".name": "cfg01411c", ".type": "dnsmasq", "domainneeded": "1", "filter_aaaa": "1"},
             {".name": "lan", ".type": "dhcp", "interface": "lan"}],
    "system": [{".name": "cfg01e48a", ".type": "system", "hostname": "OWRT"},
               {".name": "ntp", ".type": "timeserver", "enabled": "1",
                "server": ["ntp.aliyun.com", "time1.cloud.tencent.com"]}],
    "wireless": [{".name": "radio0", ".type": "wifi-device", "band": "2g"},
                 {".name": "default_radio0", ".type": "wifi-iface", "device": "radio0", "mode": "ap",
                  "ssid": "OWRT", "key": "12345678", "encryption": "psk2+ccmp"},
                 {".name": "radio1", ".type": "wifi-device", "band": "5g"},
                 {".name": "default_radio1", ".type": "wifi-iface", "device": "radio1", "mode": "ap",
                  "ssid": "OWRT", "key": "12345678", "encryption": "psk2+ccmp"}],
}
PROXY_FILE = "/etc/fleet/proxy.json"
TRACE = "fl=29f\nh=www.cloudflare.com\nip=203.0.113.50\nts=1764000000\nloc=US\n"
LAN_MAC = "1c:2a:b3:4d:5e:6f\n"

TS_STATUS = {
    "BackendState": "Running",
    "Self": {"TailscaleIPs": ["100.64.0.20", "fd7a:115c:a1e0::20"]},
    "Peer": {
        "k1": {"HostName": "my-phone", "TailscaleIPs": ["100.64.0.2"], "Tags": None},
        "k2": {"HostName": "fleet", "TailscaleIPs": ["100.64.0.9", "fd7a:115c:a1e0::9"], "Tags": ["tag:fleet"]},
    },
}


def load_fixtures():
    with open(FIXTURES, encoding="utf-8") as f:
        return json.load(f)


class AgentHarness:
    def __init__(self, now=1764000000):  # 整分钟、偶数分钟（屏幕的长期提示只在偶数分钟插播）
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
        self.relogins = 0
        self.upgrades = []
        self.exec_map = {}
        self.run_map = {}
        self.now = now
        env = self.M.env
        env.exec = self._exec
        env.run = self._run
        env.read = lambda path: self.files.get(path)
        env.write = lambda path, data: self.files.__setitem__(path, data) or True
        env.remove = lambda path: self.files.pop(path, None)
        env.log = lambda msg: self.logs.append(msg)
        env.sleep = lambda n: None
        env.now = lambda: self.now
        env.exists = lambda path: path in self.files
        env.restart_proxy = self._restart
        env.restart_dnsmasq = self._restart_dnsmasq
        env.wifi_reload = self._wifi_reload
        env.restart_screen = self._restart_screen
        env.relogin = self._relogin
        env.upgrade = lambda img: self.upgrades.append(img)
        self.dnsmasq_restarts = 0
        self.wifi_reloads = 0
        self.cursor = self.new_cursor(self.to_lua(copy.deepcopy(DEFAULT_UCI)))
        env.cursor = lambda: self.cursor
        # 固件里带的东西
        self.files["/usr/share/fleet/geosite-cn.srs"] = "SRS"
        self.files["/usr/share/fleet/geoip-cn.srs"] = "SRS"
        self.files["/etc/ts-loginserver"] = "https://hs.example.com\n"
        self.files["/sys/class/net/br-lan/address"] = LAN_MAC
        self.exec_map["sing-box version"] = "sing-box version 1.14.4\n\nEnvironment: go1.25.5 linux/arm64\n"
        self.exec_map["socks5h://127.0.0.1:7891"] = TRACE
        self.exec_map["pidof sing-box"] = "ok\n"

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

    def _run(self, cmd):
        self.commands.append(cmd)
        for key, val in self.run_map.items():
            if key in cmd:
                return val(cmd) if callable(val) else val
        return 0

    def _restart(self):
        self.restarts += 1

    def _restart_dnsmasq(self):
        self.dnsmasq_restarts += 1

    def _wifi_reload(self):
        self.wifi_reloads += 1

    def _restart_screen(self):
        self.screen_restarts += 1

    def _relogin(self):
        self.relogins += 1

    # ---- 便捷方法
    def proxy(self):
        """现在的 sing-box 配置（解析好的 JSON）；没有返回 None。"""
        text = self.files.get(PROXY_FILE)
        return json.loads(text) if text else None

    def uci(self, config):
        return self.to_py(self.cursor.committed[config])

    def uci_section(self, config, name):
        return [s for s in self.uci(config) if s[".name"] == name][0]

    def validate(self, resp):
        res = self.M.validate(self.to_lua(resp))
        if isinstance(res, tuple):
            return res
        return res, None

    def handle(self, resp, state=None):
        cfg, err = self.validate(resp)
        assert cfg is not None, err
        return self.M.handle(self.cursor, cfg, self.to_lua(state or {}))

    def main(self, *args):
        return self.M.main(self.lua.table_from(list(args) or ["--now"]))

    def set_uci(self, config, section, option, value):
        c = self.cursor
        c.set(c, config, section, option, value)
        c.commit(c, config)
