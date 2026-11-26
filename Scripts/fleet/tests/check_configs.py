"""用真的 sing-box 检查路由器脚本生成的配置（CI 里跑：Fleet-Tests 工作流先编译锁定版本的 sing-box）。

用法：python3 check_configs.py <sing-box 程序> [国内名单目录]
不给名单目录就从 SagerNet 下载 geosite-cn.srs / geoip-cn.srs（和固件编译时一样）。
每种情况（正常、关 UDP、全部走 VPN、没分配住宅 IP、到期、停用、第一次开机）都生成一份配置，
逐个执行 sing-box check，有一份不通过就失败。
"""

import json
import os
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import AgentHarness, load_fixtures  # noqa: E402

RULES = {
    "geosite-cn": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
}
CASES = ("active", "active_no_udp", "active_global", "noip", "active_plain", "pending", "expired", "limited",
         "no_nodes", "disabled", "notice")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    sing_box = sys.argv[1]
    work = tempfile.mkdtemp(prefix="fleet-check-")
    rule_dir = sys.argv[2] if len(sys.argv) > 2 else work
    for name, url in RULES.items():
        path = os.path.join(rule_dir, name + ".srs")
        if not os.path.exists(path):
            urllib.request.urlretrieve(url, path)

    fixtures = load_fixtures()
    configs = {}
    for case in CASES:
        h = AgentHarness()
        h.handle(fixtures[case])
        configs[case] = h.files["/etc/fleet/proxy.json"]
    h = AgentHarness()
    h.main("--proxy-init")
    configs["first_boot"] = h.files["/etc/fleet/proxy.json"]

    failed = []
    for case, text in configs.items():
        conf = json.loads(text)
        for rs in (conf.get("route") or {}).get("rule_set") or []:
            rs["path"] = os.path.join(rule_dir, os.path.basename(rs["path"]))
        path = os.path.join(work, case + ".json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False, indent=2)
        res = subprocess.run([sing_box, "check", "-c", path], capture_output=True, text=True)
        ok = res.returncode == 0
        print("%-14s %s %s" % (case, "通过" if ok else "不通过", (res.stdout + res.stderr).strip()))
        if not ok:
            failed.append(case)
    if failed:
        raise SystemExit("sing-box 不认这些配置：" + "、".join(failed))
    print("全部通过（%d 份）" % len(configs))


if __name__ == "__main__":
    main()
