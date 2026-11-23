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

# PassWall 2 刚装好时的配置（取自 26.11.11-1 的 0_default_config，只留测试用得到的部分）
DEFAULT_PW = [
    {".name": "cfg01", ".type": "global", "enabled": "0", "node": "rulenode", "localhost_proxy": "1",
     "direct_dns_query_strategy": "UseIP", "remote_dns_query_strategy": "UseIPv4"},
    {".name": "cfg02", ".type": "global_delay", "start_daemon": "1", "start_delay": "60"},
    {".name": "cfg03", ".type": "global_forwarding", "tcp_redir_ports": "1:65535", "ipv6_tproxy": "0"},
    {".name": "examplenode", ".type": "nodes", "remarks": "Example", "type": "Xray", "protocol": "socks"},
    {".name": "rulenode", ".type": "nodes", "protocol": "_shunt", "shunt_group": "CN"},
    {".name": "CN", ".type": "shunt_rules", "group": "CN", "domain_list": "geosite:cn"},
    {".name": "customer_node", ".type": "nodes", "remarks": "客户自己的", "type": "sing-box", "protocol": "vmess"},
]

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
        env.restart_passwall = self._restart
        env.restart_screen = self._restart_screen
        env.relogin = self._relogin
        env.upgrade = lambda img: self.upgrades.append(img)
        self.cursor = self.new_cursor(self.to_lua({"passwall2": copy.deepcopy(DEFAULT_PW),
                                                   "fleet": [{".name": "main", ".type": "agent", "enabled": "1",
                                                              "server": "", "port": "8080", "ota": "1"}]}))
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

    def _run(self, cmd):
        self.commands.append(cmd)
        for key, val in self.run_map.items():
            if key in cmd:
                return val(cmd) if callable(val) else val
        return 0

    def _restart(self):
        self.restarts += 1

    def _restart_screen(self):
        self.screen_restarts += 1

    def _relogin(self):
        self.relogins += 1

    # ---- 便捷方法
    def sections(self, stype=None):
        out = {}
        for s in self.to_py(self.cursor.committed["passwall2"]):
            if stype is None or s[".type"] == stype:
                out[s[".name"]] = s
        return out

    def section_of_type(self, stype):
        return [s for s in self.to_py(self.cursor.committed["passwall2"]) if s[".type"] == stype][0]

    def global_opts(self):
        return self.section_of_type("global")

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
