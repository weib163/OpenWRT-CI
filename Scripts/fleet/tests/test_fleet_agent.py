"""fleet-agent（路由器同步脚本）测试：用 Lua 5.1（和 OpenWrt 同版本）跑真实脚本，UCI 和命令执行用假的；
下发服务的回复用 fixtures/server_responses.json（由私有仓库的服务器代码生成，那边有测试保证两边一致）。

运行：python3 -m unittest discover -s Scripts/fleet/tests -v
需要：pip install lupa
"""

import base64
import copy
import hashlib
import json
import os
import re
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import TS_STATUS, AgentHarness, load_fixtures  # noqa: E402

FX = load_fixtures()
BUILD_OLD = "26.11.20-10.00.00"
FW_OLD = "1.1.0-26.11.20"
BOARD = "jdcloud,re-cs-02"
PUB = "untrusted comment: fleet firmware signing key public key\nRWQf6LRCGA9i5yJJmB0uO6gNhGeM6A1CLMNHnPeUX4s4lh7Qz7QzQ9wz\n"


def resp(name):
    return copy.deepcopy(FX[name])


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()

    def test_accepts_real_server_output(self):
        cfg, err = self.h.validate(resp("active"))
        self.assertIsNotNone(cfg, err)
        py = self.h.to_py(cfg)
        self.assertEqual(len(py["nodes"]), 2)
        self.assertEqual(py["direct"], ["hs.example.com", "198.51.100.7"])
        self.assertEqual((py["udp"], py["global"], py["has_residential"], py["expire_at"]), (True, False, True, 1798761600))
        self.assertEqual(py["timezone"], {"zone": "America/Los_Angeles", "posix": "PST8PDT,M3.2.0,M11.1.0", "label": "UTC-8"})
        self.assertEqual([f["name"] for f in py["pay"]["files"]], ["wechat.png", "alipay.jpg", "service.png"])
        self.assertIn("fleet-help", py["pay"]["contact"])
        for name in ("pending", "expired", "limited", "disabled", "no_nodes", "unchanged", "active_no_udp",
                     "active_global", "noip", "active_plain", "active_half_hour_tz", "notice"):
            self.assertIsNotNone(self.h.validate(resp(name))[0], name)
        # 到期、待开通的回复也带收款码、到期时间、时区（客户最需要看到收款码）
        exp = self.h.to_py(self.h.validate(resp("expired"))[0])
        self.assertEqual((exp["expire_at"], exp["timezone"]["zone"], len(exp["pay"]["files"])),
                         (1798761600, "America/Los_Angeles", 3))
        self.assertEqual(len(self.h.to_py(self.h.validate(resp("pending"))[0])["pay"]["files"]), 3)

    def test_rejects_bad_or_malicious_fields(self):
        good = resp("active")
        mutations = [
            ("address", "1.2.3.4; rm -rf /"), ("address", "evil'host"), ("address", "2001:db8::1"), ("port", 0),
            ("port", 70000), ("port", "443x"), ("uuid", "not-a-uuid"), ("protocol", "vmess"), ("transport", "grpc"),
            ("tls", False), ("public_key", "abc'def"), ("short_id", "zz"), ("sni", "bad host"),
            ("flow", "xtls-rprx-direct"), ("id", "../etc"), ("id", "x" * 30),
        ]
        for key, value in mutations:
            r = copy.deepcopy(good)
            r["nodes"][0][key] = value
            cfg, err = self.h.validate(r)
            self.assertIsNone(cfg, "%s=%r 应该被拒绝" % (key, value))
        bad_ws = copy.deepcopy(good)
        bad_ws["nodes"][1]["ws_path"] = "/a b'"
        self.assertIsNone(self.h.validate(bad_ws)[0])
        for top in ({"status": "hacked"}, {"status": "active", "udp": "yes", "nodes": good["nodes"]},
                    {"status": "active", "nodes": []}, {"status": "active", "version": "zz!", "nodes": good["nodes"]},
                    dict(good, direct=["ok.com", "bad entry"]), dict(good, auto={"url": "file:///etc/shadow"}),
                    dict(good, has_residential=1), dict(good, **{"global": "true"}), dict(good, expire_at=-5)):
            self.assertIsNone(self.h.validate(top)[0], str(top)[:80])

    def test_timezone_and_pay_validation(self):
        good = resp("active")
        bad_tz = [("zone", "America/New York"), ("zone", "a;reboot"), ("zone", "../../etc/passwd"), ("zone", "x" * 50),
                  ("posix", "PST8PDT; reboot"), ("posix", "EST5EDT\n"), ("posix", ""), ("label", "utc-8"),
                  ("label", "UTC-8 SET"), ("zone", None)]
        for key, value in bad_tz:
            r = copy.deepcopy(good)
            if value is None:
                del r["timezone"][key]
            else:
                r["timezone"][key] = value
            self.assertIsNone(self.h.validate(r)[0], "timezone.%s=%r 应该被拒绝" % (key, value))
        bad_pay = [("version", "XYZ"), ("version", ""), ("text", "a\x01b"), ("text", "x" * 1501), ("files", "a.png"),
                   ("contact", "a\x02"), ("contact", "x" * 601), ("contact", 5),
                   ("files", [{"name": "x.png", "sha256": "0" * 64, "size": 1}] * 5)]
        for key, value in bad_pay:
            r = copy.deepcopy(good)
            r["pay"][key] = value
            self.assertIsNone(self.h.validate(r)[0], "pay.%s=%r 应该被拒绝" % (key, str(value)[:30]))
        for key, value in (("name", "../shadow.png"), ("name", "qr.gif"), ("name", "a b.png"), ("sha256", "abc"),
                           ("size", 0), ("size", 2 * 1024 * 1024), ("size", "big")):
            r = copy.deepcopy(good)
            r["pay"]["files"][0][key] = value
            self.assertIsNone(self.h.validate(r)[0], "pay.files.%s=%r 应该被拒绝" % (key, value))
        # 说明文字可以换行，中文按字节算
        r = copy.deepcopy(good)
        r["pay"]["text"] = "第一行\n第二行" * 40
        self.assertIsNotNone(self.h.validate(r)[0])
        half = self.h.to_py(self.h.validate(resp("active_half_hour_tz"))[0])["timezone"]
        self.assertEqual(half["label"], "UTC-3:30")
        # 校验后的结果再校验一次也要通过（last.json 存的就是它）
        cfg, _ = self.h.validate(good)
        self.assertEqual(self.h.to_py(self.h.M.validate(cfg)), self.h.to_py(cfg))

    def test_old_residential_field_is_ignored(self):
        old = dict(resp("active"), residential={"server": "203.0.113.9", "port": 1080, "username": "bob",
                                                 "password": "s3cret", "udp": True}, on_expire="direct")
        cfg, err = self.h.validate(old)
        self.assertIsNotNone(cfg, err)
        self.assertNotIn("residential", self.h.to_py(cfg))
        self.h.handle(old)
        text = self.h.files["/etc/fleet/proxy.json"]
        self.assertNotIn("s3cret", text)  # 住宅 IP 的账号密码绝不进路由器
        self.assertNotIn('"socks"', text)

    def test_long_interval_is_capped(self):
        r = resp("active")
        r["auto"]["interval"] = "2h"
        cfg, _ = self.h.validate(r)
        self.assertEqual(self.h.to_py(cfg)["auto"]["interval"], "30m")

    def test_remark_cleaning_keeps_utf8_valid(self):
        cleaned = self.h.M.clean_remark("菲律宾" * 40 + "'\"\x01", "fallback")
        cleaned.encode("utf-8")
        self.assertNotIn("'", cleaned)
        self.assertLessEqual(len(cleaned.encode("utf-8")), 96)

    def test_hostname_rules(self):
        M = self.h.M
        self.assertTrue(M.is_hostname("cdn.example.com"))
        self.assertFalse(M.is_hostname("1.2.3.4"))  # 是 IP 不是域名
        self.assertFalse(M.is_node_address("2001:db8::1"))
        self.assertTrue(M.is_node_address("203.0.113.10"))

    def vo(self, o, board):
        res = self.h.M.validate_ota(self.h.to_lua(o), board)
        return res if isinstance(res, tuple) else (res, None)

    def test_ota_validation(self):
        good = resp("ota")
        o, err = self.vo(good, BOARD)
        self.assertIsNotNone(o, err)
        for key, value in (("version", "latest"), ("board", "jdcloud,re-ss-01"), ("url", "/ota/../../etc/shadow"),
                           ("url", "http://evil.example/fw.bin"), ("sig", "/ota/x.sig"), ("sha256", "abc"),
                           ("size", 10), ("size", 10 ** 10)):
            bad = dict(good, **{key: value})
            o, err = self.vo(bad, BOARD)
            self.assertIsNone(o, "%s=%r 应该被拒绝" % (key, value))
        other = dict(good, url=good["url"].replace("26.11.24-01.23.45/", "26.11.25-00.00.00/"))
        self.assertIsNone(self.vo(other, BOARD)[0])  # 路径里的版本要和 version 一致
        self.assertIsNone(self.vo(good, "")[0])


def outbound(conf, tag):
    return [o for o in conf["outbounds"] if o["tag"] == tag][0]


class ProxyTests(unittest.TestCase):
    """生成的 sing-box 配置：链路、国内直连、断网保护、DNS。"""

    def setUp(self):
        self.h = AgentHarness()

    def handle(self, name, state=None):
        return self.h.to_py(self.h.handle(resp(name), state))

    def test_vpn(self):
        res = self.handle("active")
        self.assertEqual((res["mode"], res["proxy"]), ("vpn", True))
        conf = self.h.proxy()
        tun = conf["inbounds"][0]
        self.assertEqual((tun["type"], tun["auto_route"], tun["auto_redirect"], tun["include_interface"]),
                         ("tun", True, True, ["br-lan"]))
        self.assertIn("100.64.0.0/10", tun["route_exclude_address"])  # Tailscale 不进代理
        reality = outbound(conf, "node_haaaaaaaa11")
        self.assertEqual((reality["server"], reality["server_port"], reality["uuid"], reality["flow"]),
                         ("203.0.113.10", 443, FX["vless_id"], "xtls-rprx-vision"))
        self.assertEqual(reality["tls"], {"enabled": True, "server_name": "www.microsoft.com",
                                          "utls": {"enabled": True, "fingerprint": "chrome"},
                                          "reality": {"enabled": True, "public_key": FX["public_key"],
                                                      "short_id": "a1b2c3d4"}})
        ws = outbound(conf, "node_hbbbbbbbb22")
        self.assertEqual(ws["transport"], {"type": "ws", "path": "/ws-9f3k", "max_early_data": 2048,
                                           "early_data_header_name": "Sec-WebSocket-Protocol",
                                           "headers": {"Host": "cdn.example.com"}})
        self.assertEqual(ws["tls"]["alpn"], ["http/1.1"])  # WebSocket 不能协商成 h2
        vpn = outbound(conf, "vpn")
        self.assertEqual((vpn["type"], vpn["outbounds"], vpn["interval"]),
                         ("urltest", ["node_haaaaaaaa11", "node_hbbbbbbbb22"], "3m"))
        # 住宅 IP 在服务器上转：路由器里没有 SOCKS 出站、没有住宅 IP 的账号密码
        self.assertEqual([o["type"] for o in conf["outbounds"]], ["direct", "vless", "vless", "urltest"])
        route = conf["route"]
        self.assertEqual(route["final"], "vpn")  # 海外只有这一条路，没有直连
        self.assertNotIn({"action": "reject"}, route["rules"])
        self.assertIn({"ip_cidr": ["::/0"], "action": "reject"}, route["rules"])  # IPv6 一律不走
        self.assertIn({"rule_set": ["geosite-cn", "geoip-cn"], "action": "route", "outbound": "direct"}, route["rules"])
        self.assertIn({"domain_suffix": ["hs.example.com"], "action": "route", "outbound": "direct"}, route["rules"])
        self.assertIn({"ip_cidr": ["198.51.100.7"], "action": "route", "outbound": "direct"}, route["rules"])
        self.assertEqual([r["path"] for r in route["rule_set"]],
                         ["/usr/share/fleet/geosite-cn.srs", "/usr/share/fleet/geoip-cn.srs"])
        dns = conf["dns"]
        self.assertEqual((dns["final"], dns["strategy"]), ("remote", "ipv4_only"))
        remote = [x for x in dns["servers"] if x["tag"] == "remote"][0]
        # 海外域名经 VPN 用 DoH 去查：服务器把它和数据一起转到住宅 IP
        self.assertEqual((remote["type"], remote["server"], remote["detour"]), ("https", "1.1.1.1", "vpn"))
        self.assertIn({"rule_set": ["geosite-cn"], "action": "route", "server": "local"}, dns["rules"])
        self.assertTrue(any(i["tag"] == "probe-in" and i["listen"] == "127.0.0.1" for i in conf["inbounds"]))
        # 配置里有 VLESS 的 UUID：写完只给 root 读
        self.assertIn("chmod 600 /etc/fleet/proxy.json", self.h.commands)
        self.assertTrue(any(c.startswith("sing-box check -c /etc/fleet/proxy.json.new") for c in self.h.commands))

    def test_udp_switch(self):
        self.handle("active")
        self.assertNotIn({"network": ["udp"], "action": "reject"}, self.h.proxy()["route"]["rules"])
        self.handle("active_no_udp")
        self.assertEqual(self.h.proxy()["route"]["rules"][-1], {"network": ["udp"], "action": "reject"})

    def test_global_mode_sends_china_through_vpn_too(self):
        self.handle("active_global")
        conf = self.h.proxy()
        self.assertNotIn("rule_set", conf["route"])
        self.assertFalse([r for r in conf["route"]["rules"] if "rule_set" in r])
        self.assertFalse([r for r in conf["dns"]["rules"] if "rule_set" in r])
        self.assertEqual(conf["route"]["final"], "vpn")
        # 管理通道照样直连
        self.assertIn({"domain_suffix": ["hs.example.com"], "action": "route", "outbound": "direct"}, conf["route"]["rules"])

    def test_no_residential_or_not_active_blocks_overseas(self):
        for name in ("noip", "pending", "expired", "limited", "no_nodes", "disabled"):
            h = AgentHarness()
            res = h.to_py(h.handle(resp(name)))
            conf = h.proxy()
            self.assertEqual(res["mode"], "noip" if name == "noip" else "block", name)
            self.assertEqual(conf["route"]["rules"][-1], {"action": "reject"}, name)
            self.assertEqual(conf["dns"]["final"], "local", name)
            self.assertEqual([o["type"] for o in conf["outbounds"]], ["direct"], name)  # 没有节点、没有 UUID
            self.assertNotIn(FX["vless_id"], h.files["/etc/fleet/proxy.json"], name)
            self.assertIn({"rule_set": ["geosite-cn", "geoip-cn"], "action": "route", "outbound": "direct"},
                          conf["route"]["rules"])  # 国内照常
            self.assertIn({"domain_suffix": ["hs.example.com"], "action": "route", "outbound": "direct"},
                          conf["route"]["rules"])  # 管理通道照样直连

    def test_expired_or_disabled_drops_nodes_and_uuid(self):
        self.handle("active")
        for name in ("expired", "disabled"):
            self.handle(name)
            self.assertNotIn(FX["vless_id"], self.h.files["/etc/fleet/last.json"], name)
            self.assertNotIn(FX["vless_id"], self.h.files["/etc/fleet/proxy.json"], name)
            self.handle("active")
            self.assertIn(FX["vless_id"], self.h.files["/etc/fleet/proxy.json"])  # 续费后马上恢复

    def test_same_config_twice_does_not_write_flash(self):
        self.assertTrue(self.handle("active")["proxy"])
        writes = [c for c in self.h.commands if c.startswith("sing-box check")]
        res = self.handle("active")
        self.assertFalse(res["proxy"])
        self.assertFalse(res["dns"])
        self.assertEqual([c for c in self.h.commands if c.startswith("sing-box check")], writes)

    def test_check_failure_keeps_old_config(self):
        self.handle("active")
        before = self.h.files["/etc/fleet/proxy.json"]
        self.h.run_map["sing-box check"] = 1
        res = self.handle("active_no_udp")
        self.assertEqual((res["proxy"], res["code"]), (False, "proxy_check"))
        self.assertEqual(self.h.files["/etc/fleet/proxy.json"], before)
        self.assertNotIn("/etc/fleet/proxy.json.new", self.h.files)

    def test_tampered_config_is_rewritten(self):
        r = resp("active")
        self.h.handle(r)
        good = self.h.files["/etc/fleet/proxy.json"]
        self.h.files["/etc/fleet/proxy.json"] = good.replace('"reject"', '"route"')
        state = {"version": r["version"], "status": "active"}
        self.assertTrue(self.handle("unchanged", state)["proxy"])
        self.assertEqual(self.h.files["/etc/fleet/proxy.json"], good)

    def test_unchanged_without_last_config_asks_for_full(self):
        state = self.h.to_lua({"version": "abc", "status": "active"})
        res = self.h.M.handle(self.h.cursor, self.h.validate(resp("unchanged"))[0], state)
        self.assertEqual(self.h.to_py(res)["mode"], "block")
        self.assertIsNone(state["version"])

    def test_missing_rule_files(self):
        del self.h.files["/usr/share/fleet/geoip-cn.srs"]
        res = self.handle("active")
        self.assertEqual(res["code"], "no_rules")
        self.assertNotIn("rule_set", self.h.proxy()["route"])

    def test_dns_points_to_sing_box_and_management_stays_direct(self):
        res = self.handle("active")
        self.assertTrue(res["dns"])
        d = self.h.uci_section("dhcp", "cfg01411c")
        self.assertEqual(d["noresolv"], "1")
        self.assertEqual(d["server"][0], "127.0.0.1#1053")
        for domain in ("hs.example.com", "ntp.aliyun.com", "time1.cloud.tencent.com"):
            self.assertIn("/%s/223.5.5.5" % domain, d["server"])
        self.assertEqual(len(d["server"]), 1 + 3 * 2)
        # 有人改了 DNS：下一轮改回来
        self.h.set_uci("dhcp", "cfg01411c", "server", ["8.8.8.8"])
        self.assertTrue(self.handle("active")["dns"])
        self.assertEqual(self.h.uci_section("dhcp", "cfg01411c")["server"][0], "127.0.0.1#1053")

    def test_proxy_init_first_boot(self):
        self.assertEqual(self.h.main("--proxy-init"), 0)
        conf = self.h.proxy()
        self.assertEqual(conf["route"]["rules"][-1], {"action": "reject"})
        self.assertEqual(self.h.dnsmasq_restarts, 1)
        self.assertIn("chmod 700 /etc/fleet", " ".join(self.h.commands))
        # 已有配置：不动
        self.h.files["/etc/fleet/proxy.json"] = "{}"
        self.h.main("--proxy-init")
        self.assertEqual(self.h.files["/etc/fleet/proxy.json"], "{}")
        # 已有配置新版 sing-box 不认（升级后）：重新生成
        self.h.run_map["sing-box check -c /etc/fleet/proxy.json >"] = 1
        self.h.main("--proxy-init")
        self.assertNotEqual(self.h.files.get("/etc/fleet/proxy.json"), "{}")

    def test_proxy_init_after_upgrade_restores_vpn(self):
        r = resp("active")
        self.h.files["/etc/fleet/last.json"] = json.dumps(r)
        self.h.files["/etc/fleet/state.json"] = json.dumps({"status": "active", "version": r["version"]})
        self.h.main("--proxy-init")
        self.assertEqual(self.h.proxy()["route"]["final"], "vpn")

    def test_timezone_follows_residential_ip(self):
        self.h.set_uci("dhcp", "lan", "dhcp_option", ["6,192.168.10.1", '100,"CST-8"'])
        res = self.handle("active")
        self.assertTrue(res["tz"])
        sysc = self.h.uci_section("system", "cfg01e48a")
        # LuCI 的写法用空格；开机脚本找时区文件时换回下划线
        self.assertEqual((sysc["zonename"], sysc["timezone"]), ("America/Los Angeles", "PST8PDT,M3.2.0,M11.1.0"))
        self.assertIn("/etc/init.d/system reload >/dev/null 2>&1", self.h.commands)
        # DHCP 选项 100（POSIX）、101（IANA 名）发给家里设备；别的选项保留，旧的 100 换掉
        self.assertEqual(self.h.uci_section("dhcp", "lan")["dhcp_option"],
                         ["6,192.168.10.1", '100,"PST8PDT,M3.2.0,M11.1.0"', '101,"America/Los_Angeles"'])
        self.assertTrue(res["dns"])  # dnsmasq 要重启才会发新的选项
        # 第二次一样：什么都不改
        commits = self.h.cursor.commits
        res = self.handle("active")
        self.assertFalse(res["tz"])
        self.assertFalse(res["dns"])
        self.assertEqual(self.h.cursor.commits, commits)

    def test_no_timezone_in_reply_leaves_system_alone(self):
        self.handle("active_plain")
        sysc = self.h.uci_section("system", "cfg01e48a")
        self.assertNotIn("zonename", sysc)
        self.assertNotIn("dhcp_option", self.h.uci_section("dhcp", "lan"))

    def test_json_is_stable_and_escaped(self):
        M = self.h.M
        t = self.h.to_lua({"b": 1, "a": ["x\"y\n", True], "c": {"z": 1.5}})
        self.assertEqual(json.loads(M.encode_json(t)), {"a": ["x\"y\n", True], "b": 1, "c": {"z": 1.5}})
        self.assertEqual(M.encode_json(t), M.encode_json(t))
        self.assertEqual(M.encode_json(M.array()), "[]")


class WifiTests(unittest.TestCase):
    SEED = "correct-horse-battery-staple-0123456789"

    def setUp(self):
        self.h = AgentHarness()
        self.h.exec_map["sha256sum"] = self.fake_sha

    @staticmethod
    def fake_sha(cmd):
        import hashlib
        if "/dev/urandom" in cmd:
            return hashlib.sha256(os.urandom(32)).hexdigest() + "  -\n"
        arg = cmd.split("printf '%s' ", 1)[1].rsplit(" | sha256sum", 1)[0]
        assert arg.startswith("'") and arg.endswith("'")
        text = arg[1:-1].replace("'\\''", "'")
        return hashlib.sha256(text.encode()).hexdigest() + "  -\n"

    @classmethod
    def expected_key(cls, seed, mac):
        import hashlib
        digest = hashlib.sha256(("%s:%s" % (seed, mac)).encode()).digest()
        chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return "".join(chars[b % 32] for b in digest[:10])

    def ifaces(self):
        return [s for s in self.h.uci("wireless") if s[".type"] == "wifi-iface"]

    def test_fresh_flash_with_seed(self):
        self.h.files["/etc/fleet/wifi-seed"] = self.SEED + "\n"
        self.assertEqual(self.h.main("--wifi-init"), 0)
        key = self.expected_key(self.SEED, "1c2ab34d5e6f")
        for s in self.ifaces():
            self.assertEqual((s["ssid"], s["key"]), ("OWRT-4D5E6F", key))
        self.assertEqual(self.h.uci_section("fleet", "main")["wifi"], "auto")
        self.assertEqual(self.h.wifi_reloads, 1)
        self.assertTrue(all(ch in "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" for ch in key) and len(key) == 10)
        self.assertFalse(any(key in m for m in self.h.logs))  # 日志里不写密码

    def test_factory_reset_gives_same_password(self):
        self.h.files["/etc/fleet/wifi-seed"] = self.SEED
        self.h.main("--wifi-init")
        first = self.ifaces()[0]["key"]
        again = AgentHarness()
        again.exec_map["sha256sum"] = self.fake_sha
        again.files["/etc/fleet/wifi-seed"] = self.SEED
        again.main("--wifi-init")
        self.assertEqual([s for s in again.uci("wireless") if s[".type"] == "wifi-iface"][0]["key"], first)
        # 另一台（MAC 不同）密码不同
        other = AgentHarness()
        other.exec_map["sha256sum"] = self.fake_sha
        other.files["/etc/fleet/wifi-seed"] = self.SEED
        other.files["/sys/class/net/br-lan/address"] = "1c:2a:b3:4d:5e:70\n"
        other.main("--wifi-init")
        self.assertNotEqual([s for s in other.uci("wireless") if s[".type"] == "wifi-iface"][0]["key"], first)

    def test_without_seed_is_random(self):
        self.h.main("--wifi-init")
        self.assertEqual(self.h.uci_section("fleet", "main")["wifi"], "random")
        self.assertNotEqual(self.ifaces()[0]["key"], "12345678")

    def test_upgrade_from_old_firmware_keeps_wifi(self):
        self.h.files["/etc/config/passwall2"] = "config global\n"
        self.h.files["/etc/fleet/wifi-seed"] = self.SEED
        self.h.main("--wifi-init")
        self.assertEqual([(s["ssid"], s["key"]) for s in self.ifaces()], [("OWRT", "12345678")] * 2)
        self.assertEqual(self.h.uci_section("fleet", "main")["wifi"], "kept")
        self.h.main("--health")
        self.assertEqual(self.ifaces()[0]["key"], "12345678")

    def test_already_set_is_not_touched_again(self):
        self.h.files["/etc/fleet/wifi-seed"] = self.SEED
        self.h.main("--wifi-init")
        self.h.set_uci("wireless", "default_radio0", "key", "customer-own-pass")
        self.h.main("--wifi-init")
        self.h.main("--health")
        self.assertEqual(self.ifaces()[0]["key"], "customer-own-pass")

    def test_wireless_config_appears_later(self):
        c = self.h.cursor
        for name in ("default_radio0", "default_radio1"):
            c.delete(c, "wireless", name)
        c.commit(c, "wireless")
        self.h.files["/etc/fleet/wifi-seed"] = self.SEED
        self.h.main("--wifi-init")
        self.assertEqual(self.h.uci_section("fleet", "main")["wifi"], "pending")
        c.set(c, "wireless", "default_radio0", "wifi-iface")
        c.set(c, "wireless", "default_radio0", "mode", "ap")
        c.set(c, "wireless", "default_radio0", "encryption", "none")
        c.commit(c, "wireless")
        self.h.main("--health")  # 每分钟的检查补上
        s = self.h.uci_section("wireless", "default_radio0")
        self.assertEqual((s["ssid"], s["encryption"]), ("OWRT-4D5E6F", "psk2"))
        self.assertEqual(self.h.uci_section("fleet", "main")["wifi"], "auto")


class RunTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()
        self.h.files["/etc/fleet/build_id"] = BUILD_OLD + "\n"
        self.h.files["/etc/fleet-firmware"] = FW_OLD + "\n"
        self.h.files["/tmp/sysinfo/board_name"] = BOARD + "\n"
        self.h.exec_map["tailscale status --json"] = json.dumps(TS_STATUS)
        self.h.exec_map["tailscale version"] = "1.90.6\n  tailscale commit: abc\n"
        self.h.exec_map["echo $PPID"] = "1234\n"
        # 收款码下载：图片内容只在 Python 这边（Lua 只看命令输出的大小和 sha256）
        self.pay_images = {k: base64.b64decode(v) for k, v in FX["pay_images"].items()}
        self.pay_downloads = []
        self.h.run_map["uclient-fetch -q -T 30 -O '/tmp/fleet/pay/"] = self._pay_download
        self.h.exec_map["wc -c < '/tmp/fleet/pay/"] = self._size_and_hash
        self.h.run_map["mv -f '/tmp/fleet/pay/"] = self._mv

    def _pay_download(self, cmd):
        path, url = re.findall(r"'([^']*)'", cmd)[:2]
        self.pay_downloads.append(url)
        name = url.split("/v1/pay/")[1].split("?")[0]
        if name not in self.pay_images:
            return 1
        self.h.files[path] = self.pay_images[name]
        return 0

    def _size_and_hash(self, cmd):
        path = re.findall(r"'([^']*)'", cmd)[0]
        data = self.h.files.get(path)
        if data is None:
            return ""
        data = data if isinstance(data, bytes) else data.encode()
        return "%d\n%s  %s\n" % (len(data), hashlib.sha256(data).hexdigest(), path)

    def _mv(self, cmd):
        src, dst = re.findall(r"'([^']*)'", cmd)[:2]
        self.h.files[dst] = self.h.files.pop(src)
        return 0

    def serve(self, body):
        def fetch(cmd):
            self.last_url = cmd.split("'")[1]
            if body is None:
                return "__FLEET_RC=4\n"
            return (body if isinstance(body, str) else json.dumps(body)) + "__FLEET_RC=0\n"
        self.h.exec_map["uclient-fetch -q -T 20 -O -"] = fetch

    def query(self):
        from urllib.parse import parse_qs, urlsplit
        return {k: v[0] for k, v in parse_qs(urlsplit(self.last_url).query, keep_blank_values=True).items()}

    def test_full_run_reports_and_saves_state(self):
        r = resp("active")
        self.serve(r)
        self.assertEqual(self.h.main(), 0)
        self.assertTrue(self.last_url.startswith("http://100.64.0.9:8080/v1/config?"))
        q = self.query()
        self.assertEqual((q["ver"], q["fw"], q["build"], q["agent"], q["board"], q["ts"], q["pw"], q["err"], q["px"]),
                         ("", FW_OLD, BUILD_OLD, "1.4.0", BOARD, "1.90.6", "1.14.4", "", ""))
        self.assertEqual((q["ws"], q["wk"]), ("OWRT", "12345678"))
        self.assertEqual(self.h.restarts, 1)
        self.assertEqual(self.h.dnsmasq_restarts, 1)
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual((state["version"], state["status"], state["chain"], state["egress"]),
                         (r["version"], "active", "ok", "203.0.113.50"))
        # 到期时间、时区（刚设好：屏幕提醒 3 天）
        self.assertEqual((state["expire_at"], state["tz_at"], state["tz_label"]), (1798761600, self.h.now, "UTC-8"))
        self.assertEqual(self.h.screen_restarts, 1)  # 屏幕时钟跟着新时区
        # 收款码下载到上网设置页
        self.assertEqual(self.h.files["/www/fleet-setup/pay/wechat.png"], self.pay_images["wechat.png"])
        self.assertEqual(self.h.files["/www/fleet-setup/pay/alipay.jpg"], self.pay_images["alipay.jpg"])
        info = json.loads(self.h.files["/www/fleet-setup/pay/info.json"])
        self.assertEqual((info["version"], info["files"]), (r["pay"]["version"], ["wechat.png", "alipay.jpg", "service.png"]))
        self.assertIn("fleet-help", info["contact"])
        self.assertEqual(self.h.files["/www/fleet-setup/pay/service.png"], self.pay_images["service.png"])
        self.assertIn("付款时备注设备码", info["text"])
        self.assertTrue(any("出口 IP：203.0.113.50" in m for m in self.h.logs))
        r2 = copy.deepcopy(r)
        r2["status"] = "unchanged"
        self.serve(resp("unchanged") | {"version": r["version"]})
        self.h.main()
        q = self.query()
        self.assertEqual((q["ver"], q["px"], q["eg"]), (r["version"], "ok", "203.0.113.50"))
        self.assertEqual((self.h.restarts, self.h.dnsmasq_restarts, self.h.screen_restarts), (1, 1, 1))
        self.assertEqual(len(self.pay_downloads), 3)  # 收款码版本没变：不再下载
        self.assertEqual(json.loads(self.h.files["/etc/fleet/state.json"])["tz_at"], self.h.now)

    def test_pay_codes_follow_server(self):
        r = resp("active")
        self.serve(r)
        self.h.main()
        # 换了一张图：整批重下，旧的删掉
        new_png = b"\x89PNG\r\n\x1a\n" + b"new-wechat" * 3
        self.pay_images["wechat.png"] = new_png
        r2 = copy.deepcopy(r)
        r2["version"] = "1" * 16
        r2["pay"]["version"] = "2" * 16
        r2["pay"]["files"] = [{"name": "wechat.png", "sha256": hashlib.sha256(new_png).hexdigest(), "size": len(new_png)}]
        self.serve(r2)
        self.h.main()
        self.assertEqual(self.h.files["/www/fleet-setup/pay/wechat.png"], new_png)
        self.assertNotIn("/www/fleet-setup/pay/alipay.jpg", self.h.files)
        # 下载的内容和清单对不上：不换，留着旧的
        r3 = copy.deepcopy(r2)
        r3["version"], r3["pay"]["version"] = "3" * 16, "4" * 16
        r3["pay"]["files"][0]["sha256"] = "0" * 64
        self.serve(r3)
        self.h.main()
        self.assertEqual(self.h.files["/www/fleet-setup/pay/wechat.png"], new_png)
        self.assertEqual(json.loads(self.h.files["/www/fleet-setup/pay/info.json"])["version"], "2" * 16)
        self.assertTrue(any("收款码没更新" in m for m in self.h.logs))
        self.assertFalse([k for k in self.h.files if k.startswith("/tmp/fleet/pay/")])
        # 服务器上删光了：路由器也删掉
        r4 = copy.deepcopy(r)
        r4["version"] = "5" * 16
        del r4["pay"]
        self.serve(r4)
        self.h.main()
        self.assertNotIn("/www/fleet-setup/pay/wechat.png", self.h.files)
        self.assertFalse(json.loads(self.h.files["/www/fleet-setup/pay/info.json"])["files"])

    def test_lost_last_config_keeps_pay_codes_and_expiry(self):
        r = resp("active")
        self.serve(r)
        self.h.main()
        del self.h.files["/etc/fleet/last.json"]  # 比如闪存出过问题
        self.serve(resp("unchanged") | {"version": r["version"]})
        self.h.main()
        self.assertIn("/www/fleet-setup/pay/wechat.png", self.h.files)  # 收款码没被删
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual((state["expire_at"], state.get("version")), (1798761600, None))  # 下一轮要完整配置

    def test_expired_still_gets_pay_codes(self):
        self.serve(resp("expired"))
        self.h.main()
        self.assertIn("/www/fleet-setup/pay/wechat.png", self.h.files)
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual((state["status"], state["expire_at"]), ("expired", 1798761600))

    def test_chain_down_is_reported_and_shown(self):
        self.h.exec_map["socks5h://127.0.0.1:7891"] = ""
        self.serve(resp("active"))
        self.h.main()
        self.assertEqual(self.h.files.get("/etc/fleet/last_error"), "chain_down")
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual((state["chain"], state.get("egress")), ("down", None))
        self.assertEqual(len([c for c in self.h.commands if "socks5h://127.0.0.1:7891" in c]), 2)  # 重试过一次
        self.h.exec_map["socks5h://127.0.0.1:7891"] = "ip=203.0.113.50\n"
        self.h.main()
        self.assertEqual(self.query()["err"], "chain_down")
        self.assertNotIn("/etc/fleet/last_error", self.h.files)

    def test_no_residential_state(self):
        self.serve(resp("noip"))
        self.h.main()
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual(state["chain"], "noip")
        self.assertFalse([c for c in self.h.commands if "socks5h://" in c])  # 没有链路就不查

    def test_old_firmware_without_build_id(self):
        del self.h.files["/etc/fleet/build_id"]
        del self.h.files["/etc/fleet-firmware"]
        self.h.files["/etc/openwrt_version"] = "r28000-abcdef\n"
        self.serve(resp("active"))
        self.h.main()
        self.assertEqual((self.query()["fw"], self.query()["build"]), ("r28000-abcdef", ""))

    def test_server_unreachable_keeps_config(self):
        self.serve(resp("active"))
        self.h.main()
        before = self.h.files["/etc/fleet/proxy.json"]
        self.serve(None)
        self.h.main()
        self.assertEqual(self.h.files["/etc/fleet/proxy.json"], before)
        self.assertTrue(any("保持现有配置" in m for m in self.h.logs))

    def test_bad_response_is_reported_next_time_then_cleared(self):
        self.serve("<html>oops</html>")
        self.h.main()
        self.assertNotIn("/etc/fleet/proxy.json", self.h.files)
        self.assertEqual(self.h.files.get("/etc/fleet/last_error"), "bad_response")
        self.serve(resp("active"))
        self.h.main()
        self.assertEqual(self.query()["err"], "bad_response")
        self.assertNotIn("/etc/fleet/last_error", self.h.files)

    def test_apply_failure_is_reported(self):
        self.h.run_map["sing-box check"] = 1
        self.serve(resp("active"))
        self.h.main()
        self.assertEqual(self.h.files.get("/etc/fleet/last_error"), "proxy_check")
        self.assertEqual(self.h.restarts, 0)
        self.assertIsNone(json.loads(self.h.files["/etc/fleet/state.json"]).get("version"))

    def test_needs_login_triggers_relogin_once_an_hour(self):
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "NeedsLogin"})
        self.serve(resp("active"))
        self.h.main()
        self.h.main()
        self.assertEqual(self.h.relogins, 1)
        self.assertFalse(any("uclient-fetch" in c for c in self.h.commands))
        self.h.now += 3601
        self.h.main()
        self.assertEqual(self.h.relogins, 2)
        self.h.exec_map["tailscale status --json"] = json.dumps(TS_STATUS)
        self.h.main()
        self.assertEqual(self.query()["err"], "ts_relogin")

    def test_stopped_tailscale_is_not_touched(self):
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "Stopped"})
        self.h.main()
        self.assertEqual(self.h.relogins, 0)

    def test_disabled_in_uci_does_nothing(self):
        self.h.set_uci("fleet", "main", "enabled", "0")
        self.serve(resp("active"))
        self.h.main()
        self.assertFalse([c for c in self.h.commands if "uclient-fetch" in c])

    def test_url_quoting_is_safe(self):
        self.assertEqual(self.h.M.shell_quote("a'b"), "'a'\\''b'")

    def test_paid_is_forwarded_to_server(self):
        posted = []

        def fetch(cmd):
            posted.append(cmd)
            return '{"ok": true}__FLEET_RC=0\n'
        self.h.exec_map["uclient-fetch -q -T 10 --post-data="] = fetch
        ok = self.h.M.paid("wechat")
        self.assertTrue(ok)
        self.assertIn("--post-data='ch=wechat'", posted[0])
        self.assertIn("'http://100.64.0.9:8080/v1/paid'", posted[0])
        # 不认识的渠道当空的发；乱写的东西进不了命令行
        self.h.M.paid("x'; reboot")
        self.assertIn("--post-data='ch='", posted[1])
        # 管理通道断了：告诉页面
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "Stopped"})
        res = self.h.M.paid("alipay")
        self.assertEqual(res[1] if isinstance(res, tuple) else None, "no_tailscale")

    def test_support_qr(self):
        qr = base64.b64decode(FX["support_qr"])
        got = []

        def download(cmd):
            path, url = re.findall(r"'([^']*)'", cmd)[:2]
            got.append(url)
            self.h.files[path] = qr
            return 0
        self.h.run_map["uclient-fetch -q -T 30 -O '/tmp/fleet/kf.png'"] = download
        self.h.exec_map = dict({"wc -c < '/tmp/fleet/kf.png'": self._size_and_hash}, **self.h.exec_map)

        def mv(cmd):
            src, dst = re.findall(r"'([^']*)'", cmd)[:2]
            self.h.files[dst] = self.h.files.pop(src)
            return 0
        self.h.run_map["mkdir -p /www/fleet-setup && mv -f "] = mv
        r = resp("active")
        self.serve(r)
        self.h.main()
        self.assertEqual(got, ["http://100.64.0.9:8080/v1/support-qr.png"])
        self.assertEqual(self.h.files["/www/fleet-setup/kf.png"], qr)
        info = self.h.to_py(self.h.M.status_info())
        self.assertEqual(info["support_url"], "https://kf.example.com/?d=4D5E6F")
        self.serve(resp("unchanged") | {"version": r["version"]})
        self.h.main()
        self.assertEqual(len(got), 1)  # 没变：不再下载
        # 服务器关了客服网站：二维码去掉，页面退回直接显示收款码
        r2 = copy.deepcopy(r)
        r2["version"] = "9" * 16
        del r2["support"]
        self.serve(r2)
        self.h.main()
        self.assertNotIn("/www/fleet-setup/kf.png", self.h.files)
        self.assertEqual(self.h.to_py(self.h.M.status_info())["support_url"], "")

    def test_bad_support_block_rejected(self):
        for change in ({"url": "http://kf.example.com/?d=4D5E6F"}, {"url": "https://kf.example.com/x?d=1"},
                       {"url": "https://evil.com/?d=12;reboot"}, {"qr": {"sha256": "ab", "size": 10}},
                       {"qr": {"sha256": "0" * 64, "size": 900000}}):
            r = copy.deepcopy(resp("active"))
            r["support"].update(change)
            self.assertIsNone(self.h.validate(r)[0], change)

    def test_client_timezone_reminder(self):
        h = self.h
        h.exec_map["date +%z"] = "-0800\n"
        h.files["/proc/net/arp"] = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                                    "192.168.10.50    0x1         0x2         aa:bb:cc:dd:ee:01     *        br-lan\n"
                                    "192.168.10.51    0x1         0x2         aa:bb:cc:dd:ee:02     *        br-lan\n")
        h.files["/tmp/dhcp.leases"] = "1800003600 aa:bb:cc:dd:ee:01 192.168.10.50 iPhone-Li 01:aa\n"
        # 服务器还没设时区：不判断
        res = h.to_py(h.M.record_client_tz("192.168.10.50", "Asia/Shanghai", 480))
        self.assertTrue(res["ok"])
        self.assertEqual(h.M.tz_mismatch_report(h.to_lua({})), "0")
        self.assertNotIn("( sleep 2; /usr/bin/fleet-agent --now ) >/dev/null 2>&1 &", h.commands)
        del h.files["/etc/fleet/tz-clients.json"]
        state = {"tz_zone": "America/Los_Angeles", "tz_label": "UTC-8"}
        h.files["/etc/fleet/state.json"] = json.dumps(state)
        res = h.to_py(h.M.record_client_tz("192.168.10.50", "Asia/Shanghai", 480))
        self.assertEqual((res["ok"], res["zone"], res["label"]), (False, "America/Los_Angeles", "UTC-8"))
        self.assertIn("( sleep 2; /usr/bin/fleet-agent --now ) >/dev/null 2>&1 &", h.commands)  # 马上报给服务器
        # 同一时区的别名（温哥华）算对；不在租约里的设备用 MAC 后 4 位
        self.assertTrue(h.to_py(h.M.record_client_tz("192.168.10.51", "America/Vancouver", -480))["ok"])
        h.M.record_client_tz("192.168.10.51", "UTC", 0)
        self.assertEqual(h.M.tz_mismatch_report(h.to_lua(state)), "2:iPhone-Li~Asia/Shanghai,EE02~UTC")
        # 改好了：提醒取消
        h.M.record_client_tz("192.168.10.50", "America/Los_Angeles", -480)
        h.M.record_client_tz("192.168.10.51", "America/Los_Angeles", -480)
        self.assertEqual(h.M.tz_mismatch_report(h.to_lua(state)), "0")
        # 30 天没再检测的记录作废
        h.M.record_client_tz("192.168.10.50", "Asia/Tokyo", 540)
        h.now += 31 * 86400
        self.assertEqual(h.M.tz_mismatch_report(h.to_lua(state)), "0")
        for ip, tz, off in (("192.168.10.99", "UTC", 0), ("192.168.10.50", "a b", 0), ("192.168.10.50", "UTC", 9999),
                            ("x", "UTC", 0)):
            res = h.M.record_client_tz(ip, tz, off)
            self.assertIsNone(res[0] if isinstance(res, tuple) else res, (ip, tz, off))

    def test_status_info_for_setup_page(self):
        self.serve(resp("active"))
        self.h.main()
        info = self.h.to_py(self.h.M.status_info())
        self.assertEqual((info["status"], info["chain"], info["expire_at"], info["tz"]), ("active", "ok", 1798761600, "UTC-8"))
        self.assertEqual((info["pay_files"], info["ssid"]), (["wechat.png", "alipay.jpg", "service.png"], "OWRT"))
        self.assertIn("fleet-help", info["contact"])
        self.assertEqual(info["device"], "4D5E6F")  # 拿不到设备名时用 br-lan 的 MAC
        self.assertNotIn("12345678", json.dumps(info))  # 不带 WiFi 密码


class OtaTests(RunTests):
    """继承 RunTests 的准备工作；回复里带升级信息。"""

    def setUp(self):
        super().setUp()
        self.h.files["/etc/fleet/fw-sign.pub"] = PUB
        self.ota = resp("ota")
        self.h.exec_map["command -v usign"] = "/usr/bin/usign\n"
        self.h.exec_map["df -k /tmp"] = "480000\n"
        self.h.exec_map["wc -c"] = "%d\n" % self.ota["size"]
        self.h.exec_map["sha256sum"] = "%s  /tmp/fleet-ota/fw.bin\n" % self.ota["sha256"]

    def serve_ota(self, **change):
        r = resp("active")
        r["ota"] = dict(self.ota, **change)
        self.serve(r)

    def errors(self):
        return self.h.files.get("/etc/fleet/last_error")

    def test_happy_path_upgrades(self):
        self.serve_ota()
        self.h.main()
        self.assertEqual(self.h.upgrades, ["/tmp/fleet-ota/fw.bin"])
        cmds = "\n".join(self.h.commands)
        self.assertIn("'http://100.64.0.9:8080%s'" % self.ota["url"], cmds)
        self.assertIn("usign -V -q -m '/tmp/fleet-ota/fw.bin' -p '/etc/fleet/fw-sign.pub' -x '/tmp/fleet-ota/fw.bin.sig'", cmds)
        self.assertIn("sysupgrade -T '/tmp/fleet-ota/fw.bin'", cmds)
        att = json.loads(self.h.files["/etc/fleet/ota.json"])
        self.assertEqual((att["version"], att["tries"]), (self.ota["version"], 1))
        self.assertIsNone(self.errors())
        # 节点配置照样写好了（先更新配置，再升级）
        self.assertIn("/etc/fleet/proxy.json", self.h.files)

    def check_refused(self, code):
        self.h.main()
        self.assertEqual(self.h.upgrades, [])
        self.assertEqual(self.errors(), code)

    def test_no_public_key(self):
        del self.h.files["/etc/fleet/fw-sign.pub"]
        self.serve_ota()
        self.check_refused("ota_nokey")

    def test_bad_checksum(self):
        self.h.exec_map["sha256sum"] = "%s  /tmp/fleet-ota/fw.bin\n" % ("0" * 64)
        self.serve_ota()
        self.check_refused("ota_sha256")

    def test_bad_signature(self):
        self.h.run_map["usign -V"] = 256
        self.serve_ota()
        self.check_refused("ota_sig")

    def test_truncated_download(self):
        self.h.exec_map["wc -c"] = "100\n"
        self.serve_ota()
        self.check_refused("ota_download")

    def test_download_failure(self):
        self.h.run_map["uclient-fetch"] = 1024
        self.serve_ota()
        self.check_refused("ota_download")

    def test_image_rejected_by_sysupgrade(self):
        self.h.run_map["sysupgrade -T"] = 256
        self.serve_ota()
        self.check_refused("ota_image")

    def test_not_enough_memory(self):
        self.h.exec_map["df -k /tmp"] = "1000\n"
        self.serve_ota()
        self.check_refused("ota_space")

    def test_wrong_board(self):
        self.serve_ota(board="jdcloud,re-ss-01")
        self.check_refused("ota_board")

    def test_ota_switched_off_in_uci(self):
        self.h.set_uci("fleet", "main", "ota", "0")
        self.serve_ota()
        self.h.main()
        self.assertEqual(self.h.upgrades, [])
        self.assertFalse(any("fleet-ota" in c for c in self.h.commands))

    def test_gives_up_after_two_tries_and_reports_failure(self):
        self.serve_ota()
        self.h.main()
        self.assertEqual(len(self.h.upgrades), 1)
        # 升级没成功，还是老版本：过了 15 分钟报一次 ota_failed
        self.h.now += 600
        self.h.main()
        self.assertNotEqual(self.query()["err"], "ota_failed")
        self.h.now += 600
        self.h.main()
        self.assertEqual(self.query()["err"], "ota_failed")
        self.assertEqual(len(self.h.upgrades), 2)  # 第二次尝试
        self.h.now += 3600
        self.h.main()
        self.h.main()
        self.assertEqual(len(self.h.upgrades), 2)  # 同一版本最多试两次

    def test_success_clears_attempt_record(self):
        self.serve_ota()
        self.h.main()
        self.h.files["/etc/fleet/build_id"] = self.ota["version"] + "\n"
        self.serve(resp("unchanged"))
        self.h.main()
        self.assertNotIn("/etc/fleet/ota.json", self.h.files)
        self.assertEqual(self.query()["build"], self.ota["version"])

    def test_old_firmware_cannot_be_upgraded(self):
        # 没有编译号（比如 1.1.0 之前的固件）：型号对上也不升级，等手动刷
        del self.h.files["/etc/fleet/build_id"]
        self.serve_ota()
        self.h.main()
        self.assertEqual(self.h.upgrades, [])


# ---------------------------------------------------------------- 温度、超温上报、屏幕
THERMAL = "/sys/class/thermal/thermal_zone%d/%s"
ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
ROUTE_LAN = "br-lan\t000AA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
ROUTE_UP = ROUTE_HEADER + "wan\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" + ROUTE_LAN
ROUTE_DOWN = ROUTE_HEADER + ROUTE_LAN
SCREEN = {".name": "general", ".type": "settings", "enabled": "1", "fleet_defaults": "1",
          "custom_content": "??????", "temp_alert": "90", "control_port": "8377"}


class HealthTests(unittest.TestCase):
    STATUS = copy.deepcopy(TS_STATUS)
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
        data = {k: self.h.to_py(c.committed[k]) for k in ("fleet", "dhcp", "system", "wireless")}
        data["athena_led"] = [dict(SCREEN), {".name": "cfg0a", ".type": "single_module", "module": "banner",
                                             "duration": "4"}]
        self.h.cursor = self.h.new_cursor(self.h.to_lua(data))
        self.serve(resp("active"))

    def set_temp(self, celsius):
        self.h.files[THERMAL % (4, "temp")] = "%d\n" % int(celsius * 1000)

    def serve(self, body):
        self.body = body
        self.h.exec_map["uclient-fetch"] = lambda cmd: json.dumps(self.body) + "__FLEET_RC=0\n"

    def fetches(self):
        return [c for c in self.h.commands if "uclient-fetch" in c and "/v1/config" in c]

    def screen_cmds(self):
        return [c for c in self.h.commands if "nc 127.0.0.1" in c]

    def health(self):
        self.assertEqual(self.h.main("--health"), 0)

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
        self.h.main("--now")
        self.assertIn("&temp=73&hot=0'", self.fetches()[-1])
        self.assertEqual(self.h.files[self.h.M.REPORTED_FILE], "0")

    def test_overheat_is_reported_at_once_and_only_once(self):
        self.h.main("--now")
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
        self.serve(resp("active"))
        self.health()
        self.assertEqual(self.h.files[self.h.M.REPORTED_FILE], "1")
        self.health()
        self.assertEqual(len(self.fetches()), 3)

    def test_threshold_from_fleet_config(self):
        self.h.set_uci("fleet", "main", "temp_alert", "75")
        self.set_temp(80)
        self.health()
        self.assertIn("&hot=1'", self.fetches()[-1])
        self.assertEqual(self.screen_conf()["temp_alert"], "75")  # 屏幕的闪烁告警也跟着改
        for bad in ("abc", "5", "500"):
            self.assertEqual(self.h.M.temp_threshold(self.h.lua.table_from({"temp_alert": bad})), 90)

    def test_fleet_disabled_still_runs_screen_but_never_syncs(self):
        self.h.set_uci("fleet", "main", "enabled", "0")
        self.set_temp(99)
        self.health()
        self.assertEqual(self.fetches(), [])
        self.assertEqual(self.screen_conf()["custom_content"], "4D5E6F 12345678")

    def test_screen_id_from_device_name(self):
        self.health()
        conf = self.screen_conf()
        # 编号后面跟 WiFi 密码
        self.assertEqual((conf["custom_content"], conf["fleet_id"]), ("4D5E6F 12345678", "4D5E6F 12345678"))
        self.assertEqual(self.h.screen_restarts, 1)
        banner = [x for x in self.h.uci("athena_led") if x.get("module") == "banner"][0]
        self.assertEqual(banner["duration"], "10")
        self.health()
        self.assertEqual(self.h.screen_restarts, 1)

    def test_screen_follows_wifi_password(self):
        self.h.set_uci("athena_led", "general", "custom_content", "4D5E6F")  # 1.2.0 写的只有编号
        self.h.set_uci("athena_led", "general", "fleet_id", "4D5E6F")
        self.h.set_uci("wireless", "default_radio0", "key", "K7MH3X9QPW")
        self.health()
        self.assertEqual(self.screen_conf()["custom_content"], "4D5E6F K7MH3X9QPW")
        # 客户把密码改成了带小写的：屏幕显示不了小写，只显示编号
        self.h.set_uci("wireless", "default_radio0", "key", "my-home-wifi")
        self.health()
        self.assertEqual(self.screen_conf()["custom_content"], "4D5E6F")

    def test_screen_id_falls_back_to_lan_mac(self):
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "Running", "Self": {"HostName": "OpenWrt"}})
        self.h.files["/sys/class/net/br-lan/address"] = "1C:2A:B3:00:00:0A\n"
        self.health()
        self.assertEqual(self.screen_conf()["custom_content"], "00000A 12345678")

    def test_screen_text_set_by_admin_is_kept(self):
        self.h.set_uci("athena_led", "general", "custom_content", "HELLO")
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
        # 链路断了：紧急提示，每分钟都插播
        self.h.files["/etc/fleet/state.json"] = json.dumps({"status": "active", "chain": "down"})
        self.h.now = 1800000060
        self.health()
        self.assertIn("'show 8 %s\\n' 'PROXY ERR'", self.screen_cmds()[-1])
        # 没分配住宅 IP：长期提示
        self.h.files["/etc/fleet/state.json"] = json.dumps({"status": "active", "chain": "noip"})
        self.h.now = 1800000000
        self.health()
        self.assertIn("'show 15 %s\\n' 'NO IP'", self.screen_cmds()[-1])

    def test_expiry_and_timezone_reminders(self):
        self.health()  # 第一次：填编号、重启屏幕程序
        now = 1800000000
        cases = [
            ({"status": "active", "expire_at": now + 3 * 86400 - 100}, "EXP 3D"),
            ({"status": "active", "expire_at": now + 3600}, "EXP 1D"),
            ({"status": "active", "expire_at": now - 10}, "EXP TODAY"),  # 面板还没改成到期
            ({"status": "active", "expire_at": now + 10 * 86400, "tz_at": now - 3600, "tz_label": "UTC-8"},
             "TZ UTC-8 SET PHONE"),
            ({"status": "active", "expire_at": now + 86400, "chain": "noip", "tz_at": now, "tz_label": "UTC-8"}, "EXP 1D"),
            ({"status": "active", "chain": "noip", "tz_at": now, "tz_label": "UTC-8"}, "NO IP"),
            ({"status": "active", "tz_at": now, "tz_label": "x'; reboot"}, "TZ CHANGED SET PHONE"),
        ]
        for state, text in cases:
            self.h.files["/etc/fleet/state.json"] = json.dumps(state)
            self.h.now = now
            self.health()
            self.assertIn("'show 15 %s\\n' '" + text + "'", self.screen_cmds()[-1], state)
        # 时区提醒只显示 3 天；到期还远：不插播
        self.h.files["/etc/fleet/state.json"] = json.dumps({"status": "active", "expire_at": now + 30 * 86400,
                                                             "tz_at": now - 4 * 86400, "tz_label": "UTC-8"})
        n = len(self.screen_cmds())
        self.health()
        self.assertEqual(len(self.screen_cmds()), n)

    def test_net_down_shows_setup_page_address(self):
        self.h.cursor.committed["network"] = self.h.to_lua([{".name": "lan", ".type": "interface", "ipaddr": "192.168.10.1"}])
        self.h.cursor.staged["network"] = self.h.cursor.committed["network"]
        self.health()
        self.h.files["/proc/net/route"] = ROUTE_DOWN
        self.health()
        self.assertIn("'show 8 %s\\n' 'NET DOWN 192.168.10.1'", self.screen_cmds()[-1])

    def test_ping_triggers_immediate_sync(self):
        self.h.main("--now")
        n = len(self.fetches())
        answer = {"sync": False}
        self.h.exec_map = dict({"/v1/ping?ver=": lambda cmd: json.dumps(answer) + "__FLEET_RC=0\n"}, **self.h.exec_map)
        self.health()
        self.assertEqual(len(self.fetches()), n)
        self.assertTrue([c for c in self.h.commands if "/v1/ping?ver=" in c])
        answer["sync"] = True  # 管理页刚续费
        self.health()
        self.assertEqual(len(self.fetches()), n + 1)

    def test_setup_page_redirect_follows_lan_address(self):
        c = self.h.cursor
        for name, data in (("network", [{".name": "lan", ".type": "interface", "ipaddr": "192.168.2.1/24"}]),
                           ("firewall", [{".name": "fleet_setup_redirect", ".type": "redirect", "src_dip": "192.168.10.1",
                                          "src_dport": "80", "dest_port": "81"}])):
            c.committed[name] = self.h.to_lua(data)
            c.staged[name] = self.h.to_lua(data)
        self.health()
        fw = [x for x in self.h.uci("firewall") if x[".name"] == "fleet_setup_redirect"][0]
        self.assertEqual(fw["src_dip"], "192.168.2.1")
        self.assertIn("/etc/init.d/firewall reload >/dev/null 2>&1", self.h.commands)
        n = self.h.commands.count("/etc/init.d/firewall reload >/dev/null 2>&1")
        self.health()
        self.assertEqual(self.h.commands.count("/etc/init.d/firewall reload >/dev/null 2>&1"), n)

    def test_proxy_watchdog(self):
        self.h.files["/etc/fleet/proxy.json"] = "{}"
        self.health()
        self.assertEqual(self.h.restarts, 0)
        self.h.exec_map["pidof sing-box"] = ""  # 进程或 nft 表没了
        self.health()
        self.assertEqual(self.h.restarts, 1)
        self.h.now += 60
        self.health()
        self.assertEqual(self.h.restarts, 1)  # 5 分钟内不重复重启
        self.h.now += 300
        self.health()
        self.assertEqual(self.h.restarts, 2)
        cmd = [c for c in self.h.commands if "pidof sing-box" in c][-1]
        self.assertIn("nft list table inet sing-box", cmd)

    def test_needs_login_shows_on_screen_and_still_relogins(self):
        # 每分钟的检查只管屏幕；重新登录由每 10 分钟的同步去做（一小时最多一次）
        self.health()
        self.h.exec_map["tailscale status --json"] = json.dumps({"BackendState": "NeedsLogin"})
        self.health()
        self.assertIn("'TS DOWN'", self.screen_cmds()[-1])
        self.assertEqual(self.h.relogins, 0)
        self.h.main("--now")
        self.assertEqual(self.h.relogins, 1)

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
        h.exec_map["tailscale status --json"] = json.dumps(TS_STATUS)
        h.exec_map["echo $PPID"] = "5\n"
        r = resp("notice")
        self.assertEqual(r["notice"], "PAY BY 12-01")  # 服务器发出来的就是规范写法
        h.exec_map["uclient-fetch"] = json.dumps(r) + "__FLEET_RC=0\n"
        h.main()
        self.assertEqual(json.loads(h.files["/etc/fleet/state.json"])["notice"], "PAY BY 12-01")
        h.exec_map["uclient-fetch"] = json.dumps(resp("unchanged")) + "__FLEET_RC=0\n"
        h.main()
        self.assertEqual(json.loads(h.files["/etc/fleet/state.json"])["notice"], "PAY BY 12-01")
        # 新配置里没有留言：清掉
        h.exec_map["uclient-fetch"] = json.dumps(resp("active")) + "__FLEET_RC=0\n"
        h.main()
        self.assertNotIn("notice", json.loads(h.files["/etc/fleet/state.json"]))

    def test_bad_notice_does_not_block_config(self):
        r = resp("active")
        r["notice"] = "续费"
        cfg, err = self.h.validate(r)
        self.assertIsNotNone(cfg, err)
        self.assertIsNone(self.h.to_py(cfg).get("notice"))


if __name__ == "__main__":
    unittest.main()
