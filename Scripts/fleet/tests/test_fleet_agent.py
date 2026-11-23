"""fleet-agent（路由器同步脚本）测试：用 Lua 5.1（和 OpenWrt 同版本）跑真实脚本，UCI 和命令执行用假的；
下发服务的回复用 fixtures/server_responses.json（由私有仓库的服务器代码生成，那边有测试保证两边一致）。

运行：python3 -m unittest discover -s Scripts/fleet/tests -v
需要：pip install lupa
"""

import copy
import json
import os
import sys
import unittest

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
        for name in ("pending", "expired_block", "expired_direct", "limited", "disabled", "no_nodes", "unchanged"):
            self.assertIsNotNone(self.h.validate(resp(name))[0], name)

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
        for top in ({"status": "hacked"}, {"status": "active", "on_expire": "sometimes", "nodes": good["nodes"]},
                    {"status": "active", "nodes": []}, {"status": "active", "version": "zz!", "nodes": good["nodes"]},
                    dict(good, direct=["ok.com", "bad entry"]), dict(good, auto={"url": "file:///etc/shadow"})):
            self.assertIsNone(self.h.validate(top)[0], str(top)[:80])

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


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()

    def test_active_writes_passwall2_sections(self):
        self.assertTrue(self.h.handle(resp("active")))
        nodes = self.h.sections("nodes")
        reality = nodes["fleet_haaaaaaaa11"]
        self.assertEqual((reality["type"], reality["protocol"], reality["domain_strategy"]), ("sing-box", "vless", "ipv4_only"))
        self.assertEqual((reality["tls"], reality["reality"], reality["reality_publicKey"], reality["reality_shortId"],
                          reality["tls_serverName"], reality["flow"], reality["transport"], reality["port"]),
                         ("1", "1", FX["public_key"], "a1b2c3d4", "www.microsoft.com", "xtls-rprx-vision", "tcp", "443"))
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
        self.assertIn("customer_node", nodes)
        self.assertIn("examplenode", nodes)
        self.assertIn("CN", self.h.sections("shunt_rules"))

    def test_ipv4_only_settings(self):
        c = self.h.cursor
        c.set(c, "passwall2", "cfg03", "ipv6_tproxy", "1")
        c.commit(c, "passwall2")
        self.h.handle(resp("active"))
        g = self.h.global_opts()
        self.assertEqual((g["direct_dns_query_strategy"], g["remote_dns_query_strategy"]), ("UseIPv4", "UseIPv4"))
        self.assertEqual(self.h.section_of_type("global_forwarding")["ipv6_tproxy"], "0")

    def test_same_config_twice_does_not_write_flash(self):
        r = resp("active")
        self.assertTrue(self.h.handle(r))
        commits = self.h.cursor.commits
        self.assertFalse(self.h.handle(r))
        self.assertEqual(self.h.cursor.commits, commits)

    def test_removed_node_is_deleted(self):
        r = resp("active")
        self.h.handle(r)
        r2 = copy.deepcopy(r)
        r2["nodes"] = r2["nodes"][:1]
        self.assertTrue(self.h.handle(r2))
        nodes = self.h.sections("nodes")
        self.assertNotIn("fleet_hbbbbbbbb22", nodes)
        self.assertEqual(nodes["fleet_auto"]["urltest_node"], ["fleet_haaaaaaaa11"])

    def test_expired_block_keeps_nodes_direct_turns_off(self):
        self.h.handle(resp("active"))
        self.assertFalse(self.h.handle(resp("expired_block")))
        self.assertIn("fleet_haaaaaaaa11", self.h.sections("nodes"))
        self.assertEqual(self.h.global_opts()["enabled"], "1")
        self.assertTrue(self.h.handle(resp("expired_direct")))
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.assertIn("fleet_haaaaaaaa11", self.h.sections("nodes"))

    def test_disabled_removes_uuids_and_blackholes_proxy(self):
        self.h.handle(resp("active"))
        self.assertTrue(self.h.handle(resp("disabled")))
        nodes = self.h.sections("nodes")
        self.assertFalse([n for n in nodes.values() if n.get("uuid") and n[".name"].startswith("fleet_")])
        shunt = nodes["fleet_shunt"]
        self.assertEqual((shunt["default_node"], shunt["ProxyFront"], shunt["CN"]), ("_blackhole", "_blackhole", "_direct"))
        self.assertEqual(self.h.global_opts()["enabled"], "1")
        self.assertIn("fleet_direct", self.h.sections("shunt_rules"))

    def test_pending_only_touches_managed_router(self):
        self.assertFalse(self.h.handle(resp("pending")))
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.h.handle(resp("active"))
        self.assertTrue(self.h.handle(resp("pending")))
        self.assertEqual(self.h.global_opts()["enabled"], "0")

    def test_tampered_nodes_are_restored(self):
        r = resp("active")
        self.h.handle(r)
        state = {"version": r["version"], "status": "active", "snapshot": self.h.M.snapshot(self.h.cursor)}
        self.h.set_uci("passwall2", "fleet_haaaaaaaa11", "uuid", "00000000-0000-4000-8000-000000000000")
        self.assertTrue(self.h.handle(resp("unchanged"), state))
        self.assertEqual(self.h.sections("nodes")["fleet_haaaaaaaa11"]["uuid"], FX["vless_id"])

    def test_ipv6_turned_back_on_is_noticed(self):
        r = resp("active")
        self.h.handle(r)
        state = {"version": r["version"], "status": "active", "snapshot": self.h.M.snapshot(self.h.cursor)}
        self.h.set_uci("passwall2", "cfg03", "ipv6_tproxy", "1")
        self.assertTrue(self.h.handle(resp("unchanged"), state))
        self.assertEqual(self.h.section_of_type("global_forwarding")["ipv6_tproxy"], "0")


class RunTests(unittest.TestCase):
    def setUp(self):
        self.h = AgentHarness()
        self.h.files["/etc/fleet/build_id"] = BUILD_OLD + "\n"
        self.h.files["/etc/fleet-firmware"] = FW_OLD + "\n"
        self.h.files["/tmp/sysinfo/board_name"] = BOARD + "\n"
        self.h.exec_map["tailscale status --json"] = json.dumps(TS_STATUS)
        self.h.exec_map["tailscale version"] = "1.90.6\n  tailscale commit: abc\n"
        self.h.exec_map["luci-app-passwall2"] = "luci-app-passwall2-26.11.11-r1 noarch {feeds/x} (GPL-3.0) [installed]\n"
        self.h.exec_map["echo $PPID"] = "1234\n"

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
        self.assertEqual((q["ver"], q["fw"], q["build"], q["agent"], q["board"], q["ts"], q["pw"], q["err"]),
                         ("", FW_OLD, BUILD_OLD, "1.2.0", BOARD, "1.90.6", "26.11.11-r1", ""))
        self.assertEqual(self.h.restarts, 1)
        state = json.loads(self.h.files["/etc/fleet/state.json"])
        self.assertEqual((state["version"], state["status"]), (r["version"], "active"))
        self.serve(resp("unchanged"))
        self.h.main()
        self.assertEqual(self.query()["ver"], r["version"])
        self.assertEqual(self.h.restarts, 1)

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
        before = self.h.sections()
        self.serve(None)
        self.h.main()
        self.assertEqual(self.h.sections(), before)
        self.assertTrue(any("保持现有配置" in m for m in self.h.logs))

    def test_bad_response_is_reported_next_time_then_cleared(self):
        self.serve("<html>oops</html>")
        self.h.main()
        self.assertEqual(self.h.global_opts()["enabled"], "0")
        self.assertEqual(self.h.files.get("/etc/fleet/last_error"), "bad_response")
        self.serve(resp("active"))
        self.h.main()
        self.assertEqual(self.query()["err"], "bad_response")
        self.assertNotIn("/etc/fleet/last_error", self.h.files)

    def test_apply_failure_is_reported(self):
        c = self.h.cursor
        c.delete(c, "passwall2", "cfg01")  # 没有 global 段，写不进去
        c.commit(c, "passwall2")
        self.serve(resp("active"))
        self.h.main()
        self.assertEqual(self.h.files.get("/etc/fleet/last_error"), "apply")
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
        self.assertIn("fleet_haaaaaaaa11", self.h.sections("nodes"))

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
        self.h.cursor = self.h.new_cursor(self.h.to_lua({
            "passwall2": self.h.to_py(c.committed["passwall2"]),
            "fleet": self.h.to_py(c.committed["fleet"]),
            "athena_led": [dict(SCREEN)],
        }))
        self.serve(resp("active"))

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
