"""上网设置页后台（fleet-setup.lua）测试：用真实的路由器脚本（fleet-agent）当库，UCI 和命令执行用假的。

运行：python3 -m unittest discover -s Scripts/fleet/tests -v
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import TS_STATUS, AgentHarness, load_fixtures  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SETUP = os.path.join(HERE, "..", "fleet-setup.lua")
FX = load_fixtures()
WIFI_KEY = "12345678"  # 假 UCI 里的 WiFi 密码
PUB = "untrusted comment: fleet firmware signing key public key\nRWQf6LRCGA9i5yJJmB0uO6gNhGeM6A1CLMNHnPeUX4s4lh7Qz7QzQ9wz\n"
LISTING = ("-rw-r--r-- 0/0  31457280 2026-11-26 10:00:00 firmware.bin\n"
           "-rw-r--r-- 0/0       150 2026-11-26 10:00:00 firmware.bin.sig\n")


class SetupHarness:
    def __init__(self):
        self.a = AgentHarness()
        c = self.a.cursor
        for name, data in (("network", [{".name": "lan", ".type": "interface", "proto": "static", "ipaddr": "192.168.10.1"},
                                        {".name": "wan", ".type": "interface", "proto": "dhcp", "device": "eth0"}]),):
            c.committed[name] = self.a.to_lua(data)
            c.staged[name] = self.a.to_lua(data)
        g = self.a.lua.globals()
        g.FLEET_SETUP_AGENT = self.a.M
        with open(SETUP, encoding="utf-8") as f:
            self.S = self.a.lua.execute(f.read())
        self.tokens = iter(["%032x" % i for i in range(1, 100)])
        self.S.env.random_hex = lambda n: next(self.tokens)
        self.saved = []
        self.save_ok = True
        self.S.env.save_stdin = self._save_stdin
        self.a.exec_map["tailscale status --json"] = json.dumps(TS_STATUS)

    def _save_stdin(self, path, length):
        self.saved.append((path, length))
        if self.save_ok:
            self.a.files[path] = "tar-bytes"
        return self.save_ok

    def call(self, action, method="POST", body=None, auth=None, ctype=None, host="192.168.10.1", origin=None,
             length=None):
        if ctype is None:
            ctype = "application/json" if method == "POST" else ""
        req = {"method": method, "action": action, "host": host, "content_type": ctype}
        if origin is not None:
            req["origin"] = origin
        if auth:
            req["auth"] = "Bearer " + auth
        if length is not None:
            req["length"] = length
        if body is not None:
            req["body"] = body
        code, res = self.S.handle(self.a.to_lua(req))
        return code, self.a.to_py(res)

    def login(self, password=WIFI_KEY):
        code, res = self.call("login", body={"password": password})
        assert code == 200, res
        return res["token"]

    def wan(self):
        return [s for s in self.a.uci("network") if s[".name"] == "wan"][0]


class RequestCheckTests(unittest.TestCase):
    def setUp(self):
        self.h = SetupHarness()

    def test_host_check_blocks_dns_rebinding(self):
        for host in ("192.168.10.1", "192.168.10.1:81", "[fd00::1]:81", "localhost", "router", "openwrt.lan",
                     "jdcloud.lan:80"):
            self.assertTrue(self.h.S.host_ok(host), host)
        for host in ("evil.example.com", "192.168.10.1.nip.io", "", "a b", "lan.evil.com:80"):
            self.assertFalse(self.h.S.host_ok(host), host)
        code, res = self.h.call("status", method="GET", host="attacker.example")
        self.assertEqual((code, res["error"]), (403, "bad_host"))

    def test_writes_need_json_and_same_origin(self):
        # 别的网站用表单发过来：Content-Type 不对
        code, res = self.h.call("login", body={"password": WIFI_KEY}, ctype="application/x-www-form-urlencoded")
        self.assertEqual((code, res["error"]), (403, "csrf"))
        code, res = self.h.call("login", body={"password": WIFI_KEY}, origin="http://evil.example")
        self.assertEqual((code, res["error"]), (403, "csrf"))
        code, res = self.h.call("login", method="GET", body={"password": WIFI_KEY})
        self.assertEqual(code, 403)
        code, _ = self.h.call("login", body={"password": WIFI_KEY}, origin="http://192.168.10.1")
        self.assertEqual(code, 200)


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.h = SetupHarness()

    def test_status_needs_no_login_and_has_no_secrets(self):
        self.h.a.files["/etc/fleet/state.json"] = json.dumps({"status": "expired", "expire_at": 1798761600,
                                                               "tz_label": "UTC-8", "tz_zone": "America/Los_Angeles"})
        self.h.a.files["/www/fleet-setup/pay/info.json"] = json.dumps({"version": "ab12", "text": "月付 99",
                                                                        "files": ["wechat.png", "../x.png"]})
        code, res = self.h.call("status", method="GET")
        self.assertEqual(code, 200)
        self.assertEqual((res["status"], res["expire_at"], res["tz"], res["tz_zone"], res["logged_in"], res["wan_proto"]),
                         ("expired", 1798761600, "UTC-8", "America/Los_Angeles", False, "dhcp"))
        self.assertEqual((res["pay_files"], res["pay_text"]), (["wechat.png"], "月付 99"))  # 不合格的文件名不给
        self.assertNotIn(WIFI_KEY, json.dumps(res))

    def test_wrong_password_locks_after_five_tries(self):
        for i in range(4):
            code, res = self.h.call("login", body={"password": "wrong%d" % i})
            self.assertEqual((code, res["error"]), (401, "bad_password"))
        code, res = self.h.call("login", body={"password": "wrong"})
        self.assertEqual((code, res["error"], res["wait"]), (429, "locked", 600))
        code, res = self.h.call("login", body={"password": WIFI_KEY})  # 锁着的时候密码对了也不行
        self.assertEqual(code, 429)
        self.h.a.now += 601
        token = self.h.login()
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        self.assertNotIn("/tmp/fleet-setup/fails.json", self.h.a.files)

    def test_session(self):
        code, res = self.h.call("wan", method="GET")
        self.assertEqual(code, 401)
        token = self.h.login()
        code, res = self.h.call("wan", method="GET", auth=token)
        self.assertEqual((code, res["proto"]), (200, "dhcp"))
        code, res = self.h.call("status", method="GET", auth=token)
        self.assertTrue(res["logged_in"])
        self.h.a.now += 1801  # 半小时没动：要重新登录
        code, _ = self.h.call("wan", method="GET", auth=token)
        self.assertEqual(code, 401)
        token = self.h.login()
        code, _ = self.h.call("logout", body={}, auth=token)
        self.assertEqual(code, 200)
        code, _ = self.h.call("wan", method="GET", auth=token)
        self.assertEqual(code, 401)
        code, _ = self.h.call("wan", method="GET", auth="zz" * 16)
        self.assertEqual(code, 401)

    def test_no_wifi_password_means_no_login(self):
        c = self.h.a.cursor
        for name in ("default_radio0", "default_radio1"):
            c.delete(c, "wireless", name, "key")
        c.commit(c, "wireless")
        code, res = self.h.call("login", body={"password": ""})
        self.assertEqual((code, res["error"]), (401, "no_password"))


class WanTests(unittest.TestCase):
    def setUp(self):
        self.h = SetupHarness()
        self.token = self.h.login()

    def save(self, data):
        return self.h.call("wan", body=data, auth=self.token)

    def test_pppoe(self):
        code, res = self.save({"proto": "pppoe", "username": "07551234567@163.gd", "password": "p@ss w'rd"})
        self.assertEqual(code, 200, res)
        wan = self.h.wan()
        self.assertEqual((wan["proto"], wan["username"], wan["password"], wan["ipv6"]),
                         ("pppoe", "07551234567@163.gd", "p@ss w'rd", "0"))
        self.assertIn("( sleep 1; /etc/init.d/network reload ) >/dev/null 2>&1 &", self.h.a.commands)
        # 看的时候不给密码
        code, res = self.h.call("wan", method="GET", auth=self.token)
        self.assertEqual((res["username"], res["has_password"]), ("07551234567@163.gd", True))
        self.assertNotIn("password", res)
        # 只改账号、密码留空：保留原来的密码
        self.save({"proto": "pppoe", "username": "new-user", "password": ""})
        self.assertEqual((self.h.wan()["username"], self.h.wan()["password"]), ("new-user", "p@ss w'rd"))

    def test_bad_pppoe(self):
        for data in ({"proto": "pppoe", "username": "a b", "password": "x"},
                     {"proto": "pppoe", "username": "x" * 65, "password": "x"},
                     {"proto": "pppoe", "username": "user", "password": "line\nbreak"},
                     {"proto": "pppoe", "username": "user"},  # 第一次设拨号必须填密码
                     {"proto": "l2tp"}):
            code, res = self.save(data)
            self.assertEqual(code, 400, data)
            self.assertTrue(res["message"])
        self.assertEqual(self.h.wan()["proto"], "dhcp")

    def test_static_and_back_to_dhcp(self):
        code, res = self.save({"proto": "static", "ipaddr": "100.64.10.20", "netmask": "255.255.255.0",
                               "gateway": "100.64.10.1", "dns": ["223.5.5.5", "119.29.29.29"]})
        self.assertEqual(code, 200, res)
        wan = self.h.wan()
        self.assertEqual((wan["proto"], wan["ipaddr"], wan["netmask"], wan["gateway"], wan["dns"]),
                         ("static", "100.64.10.20", "255.255.255.0", "100.64.10.1", ["223.5.5.5", "119.29.29.29"]))
        self.save({"proto": "pppoe", "username": "u1", "password": "p1"})
        self.assertNotIn("ipaddr", self.h.wan())
        self.save({"proto": "dhcp"})
        wan = self.h.wan()
        self.assertEqual(wan["proto"], "dhcp")
        for key in ("username", "password", "ipaddr", "gateway"):
            self.assertNotIn(key, wan)

    def test_bad_static(self):
        base = {"proto": "static", "ipaddr": "100.64.10.20", "netmask": "255.255.255.0", "gateway": "100.64.10.1"}
        for change in ({"ipaddr": "100.64.10"}, {"netmask": "255.0.255.0"}, {"netmask": "255.255.255.255"},
                       {"gateway": "100.64.11.1"}, {"ipaddr": "192.168.10.50", "gateway": "192.168.10.254"},
                       {"dns": ["1.1.1.1", "8.8.8.8", "9.9.9.9"]}, {"dns": ["dns.example"]}):
            code, res = self.save(dict(base, **change))
            self.assertEqual(code, 400, change)
        self.assertEqual(self.h.wan()["proto"], "dhcp")


class PaidTests(unittest.TestCase):
    def setUp(self):
        self.h = SetupHarness()
        self.posts = []

        def fetch(cmd):
            self.posts.append(cmd)
            return '{"ok": true}__FLEET_RC=0\n'
        self.h.a.exec_map["uclient-fetch -q -T 10 --post-data="] = fetch

    def test_paid_without_login_and_rate_limited(self):
        code, res = self.h.call("paid", body={"channel": "alipay"})
        self.assertEqual((code, res["ok"]), (200, True))
        self.assertIn("--post-data='ch=alipay'", self.posts[0])
        code, res = self.h.call("paid", body={"channel": "alipay"})  # 两分钟内再点：不再发
        self.assertEqual((code, res.get("repeated")), (200, True))
        self.assertEqual(len(self.posts), 1)
        self.h.a.now += 121
        self.h.call("paid", body={"channel": "wechat"})
        self.assertEqual(len(self.posts), 2)

    def test_paid_when_management_is_down(self):
        self.h.a.exec_map["tailscale status --json"] = json.dumps({"BackendState": "Stopped"})
        code, res = self.h.call("paid", body={"channel": "wechat"})
        self.assertEqual((code, res["error"]), (503, "no_tailscale"))
        self.assertNotIn("/tmp/fleet-setup/paid.stamp", self.h.a.files)  # 没发出去：可以马上再试


class TzCheckTests(unittest.TestCase):
    def test_tzcheck(self):
        h = SetupHarness()
        h.a.exec_map["date +%z"] = "-0800\n"
        h.a.files["/proc/net/arp"] = "IP address HW type Flags HW address Mask Device\n192.168.10.50 0x1 0x2 aa:bb:cc:dd:ee:01 * br-lan\n"
        h.a.files["/etc/fleet/state.json"] = json.dumps({"tz_zone": "America/Los_Angeles", "tz_label": "UTC-8"})
        req = {"method": "POST", "action": "tzcheck", "host": "192.168.10.1", "content_type": "application/json",
               "remote": "192.168.10.50", "body": {"tz": "Asia/Shanghai", "offset": 480}}
        code, res = h.S.handle(h.a.to_lua(req))
        self.assertEqual((code, h.a.to_py(res)["ok"]), (200, False))
        req["body"] = {"tz": "America/Los_Angeles", "offset": -480}
        code, res = h.S.handle(h.a.to_lua(req))
        self.assertTrue(h.a.to_py(res)["ok"])
        req["body"] = {"tz": "x'; reboot", "offset": 0}
        self.assertEqual(h.S.handle(h.a.to_lua(req))[0], 400)
        req["content_type"] = "text/plain"
        self.assertEqual(h.S.handle(h.a.to_lua(req))[0], 403)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.h = SetupHarness()
        self.token = self.h.login()
        a = self.h.a
        a.files["/etc/fleet/fw-sign.pub"] = PUB
        a.exec_map["command -v usign"] = "/usr/bin/usign\n"
        a.exec_map["df -k /tmp"] = "400000\n"
        a.exec_map["tar -tvf"] = LISTING
        a.exec_map["wc -c <"] = "31457280\n"

        def extract(cmd):
            a.files["/tmp/fleet-manual/firmware.bin"] = "fw"
            a.files["/tmp/fleet-manual/firmware.bin.sig"] = "sig"
            return 0
        a.run_map["tar -xf"] = extract

    def upload(self, length=40 * 1024 * 1024, token=None, ctype="application/octet-stream"):
        return self.h.call("upload", auth=token or self.token, ctype=ctype, length=length)

    def test_happy_path(self):
        code, res = self.upload()
        self.assertEqual((code, res["ok"], res["size"]), (200, True, 31457280), res)
        cmds = "\n".join(self.h.a.commands)
        self.assertIn("usign -V -q -m '/tmp/fleet-manual/firmware.bin' -p '/etc/fleet/fw-sign.pub' -x "
                      "'/tmp/fleet-manual/firmware.bin.sig'", cmds)
        self.assertIn("sysupgrade -T '/tmp/fleet-manual/firmware.bin'", cmds)
        self.assertEqual(self.h.a.upgrades, [])  # 校验完先不刷，等客户点“开始升级”
        code, res = self.h.call("flash", body={}, auth=self.token)
        self.assertEqual(code, 200, res)
        self.assertEqual(self.h.a.upgrades, ["/tmp/fleet-manual/firmware.bin"])

    def test_refusals(self):
        code, _ = self.upload(token="ab" * 16)
        self.assertEqual(code, 401)
        code, _ = self.upload(ctype="application/json")
        self.assertEqual(code, 403)
        for length in (100, 200 * 1024 * 1024, None):
            code, res = self.upload(length=length)
            self.assertEqual(code, 400, length)
        code, res = self.h.call("flash", body={}, auth=self.token)  # 还没上传
        self.assertEqual(code, 400)
        self.assertEqual(self.h.a.upgrades, [])

    def check_refused(self, text):
        code, res = self.upload()
        self.assertEqual(code, 400)
        self.assertIn(text, res["message"])
        self.assertIn("rm -rf /tmp/fleet-manual", self.h.a.commands)
        code, _ = self.h.call("flash", body={}, auth=self.token)
        self.assertEqual(code, 400)
        self.assertEqual(self.h.a.upgrades, [])

    def test_bad_signature(self):
        self.h.a.run_map["usign -V"] = 1
        self.check_refused("签名不对")

    def test_wrong_board(self):
        self.h.a.run_map["sysupgrade -T"] = 1
        self.check_refused("型号不对")

    def test_not_a_package(self):
        self.h.a.exec_map["tar -tvf"] = LISTING + "-rw-r--r-- 0/0 10 2026-11-26 10:00:00 extra\n"
        self.check_refused("不是升级包")

    def test_no_public_key(self):
        del self.h.a.files["/etc/fleet/fw-sign.pub"]
        code, res = self.upload()
        self.assertEqual(code, 400)
        self.assertIn("不支持手动升级", res["message"])

    def test_low_memory(self):
        self.h.a.exec_map["df -k /tmp"] = "60000\n"
        code, res = self.upload()
        self.assertEqual(code, 400)
        self.assertIn("内存不够", res["message"])

    def test_interrupted_upload(self):
        self.h.save_ok = False
        self.check_refused("上传没完成")

    def test_member_check(self):
        cm = self.h.S.check_members
        self.assertEqual(cm(LISTING), ("firmware.bin", "firmware.bin.sig"))
        self.assertEqual(cm(LISTING.replace(" firmware", " ./firmware")), ("./firmware.bin", "./firmware.bin.sig"))
        for bad in ("", LISTING.splitlines()[0],
                    LISTING.replace("-rw-r--r-- 0/0  31457280", "lrwxrwxrwx 0/0 0"),  # 符号链接
                    LISTING.replace("firmware.bin.sig", "../firmware.bin.sig"),
                    LISTING.replace("firmware.bin.sig", "firmware.bin"),
                    "drwxr-xr-x 0/0 0 2026-11-26 10:00:00 etc/\n" + LISTING):
            self.assertIsNone(cm(bad), bad)


class CgiTests(unittest.TestCase):
    def test_cgi_end_to_end(self):
        h = SetupHarness()
        env = {"REQUEST_METHOD": "POST", "QUERY_STRING": "a=login", "HTTP_HOST": "192.168.10.1",
               "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": "25"}
        out = []
        h.S.env.getenv = lambda name: env.get(name)
        h.S.env.read_stdin = lambda n: '{"password": "12345678"}'
        h.S.env.write_stdout = out.append
        h.S.cgi()
        head, body = out[0].split("\r\n\r\n", 1)
        self.assertTrue(head.startswith("Status: 200 OK"))
        self.assertIn("Cache-Control: no-store", head)
        token = json.loads(body)["token"]
        # 带着登录凭据读宽带设置
        env.update({"REQUEST_METHOD": "GET", "QUERY_STRING": "a=wan", "HTTP_AUTHORIZATION": "Bearer " + token})
        env.pop("CONTENT_TYPE")
        h.S.cgi()
        head, body = out[1].split("\r\n\r\n", 1)
        self.assertTrue(head.startswith("Status: 200 OK"))
        self.assertEqual(json.loads(body)["proto"], "dhcp")
        # 请求体太大
        env.update({"REQUEST_METHOD": "POST", "QUERY_STRING": "a=login", "CONTENT_TYPE": "application/json",
                    "CONTENT_LENGTH": "999999"})
        h.S.cgi()
        self.assertTrue(out[2].startswith("Status: 413"))

    def test_status_json_lists_are_lists(self):
        h = SetupHarness()
        code, _ = h.call("status", method="GET")
        out = []
        h.S.env.write_stdout = out.append
        res = h.S.handle(h.a.to_lua({"method": "GET", "action": "status", "host": "192.168.10.1"}))
        h.S.respond(*res)
        body = json.loads(out[0].split("\r\n\r\n", 1)[1])
        self.assertEqual(body["pay_files"], [])  # 页面脚本按数组用


if __name__ == "__main__":
    unittest.main()
