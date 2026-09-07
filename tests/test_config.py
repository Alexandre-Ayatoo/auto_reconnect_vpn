import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from test_supervisor import v, FakeKernel, physical

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import convert_vpn_config as converter

BSM = '''#!/bin/bash
CHECK_INTERVAL=5
MAX_FAILED_PINGS=3
COOLDOWN=60
UNDERLAY_HEALTH_CHECK_ENABLED="no"
UNDERLAY_MAX_FAILED_PINGS=3
PING_TARGET_1="203.0.113.251" # commentaire : ancien ppp254001
PING_TARGET_2="203.0.113.252"
IPSEC_PEER="51.75.129.106/32"
IPSEC_PEER_2="51.75.129.105/32"
IPSEC_VPN_NAME="l2tp-ipsec-vpn"
IPSEC_VPN_NAME_2="l2tp-ipsec-vpn-2"
L2TP_SESSION_1="myvpn"
L2TP_SESSION_2="myvpn-2"
PPP_INTERFACE="ppp255001"
PPP_INTERFACE_2="ppp255002"
VPN_UNDERLAY_1="51.75.129.106/32"
VPN_UNDERLAY_2="51.75.129.105/32"
VPN_UNDERLAY_1_METRIC_BASE=2
VPN_UNDERLAY_2_METRIC_BASE=2
ENABLE_TUN1_DEFAULT_ROUTE="no"
ENABLE_TUN2_DEFAULT_ROUTE="no"
TUN1_DEFAULT_METRIC=""
TUN2_DEFAULT_METRIC="2"
L2TP_CONTROL_PATH="/var/run/xl2tpd/l2tp-control"
log() { echo "$*"; }
while true; do destructive_command; done
'''


class ConfigTests(unittest.TestCase):
    def test_pidfile_candidates_accept_one_valid_daemon_and_reject_ambiguity(self):
        def read(path, *args, **kwargs):
            values = {"/run/charon.pid": "100", "/run/xl2tpd.pid": "200",
                      "/proc/100/comm": "charon", "/proc/200/comm": "xl2tpd",
                      "/proc/300/comm": "xl2tpd"}
            if str(path) not in values:
                raise FileNotFoundError(str(path))
            return values[str(path)]
        with patch.object(v, "CHARON_PIDFILE", ["/run/charon.pid"]), \
             patch.object(v, "XL2TPD_PIDFILE", ["/run/xl2tpd.pid", "/run/xl2tpd/xl2tpd.pid"]), \
             patch.object(v.Path, "read_text", read), \
             patch.object(v.os, "stat", return_value=SimpleNamespace(st_ino=123)):
            self.assertEqual(v.daemon_context(), [])
        def ambiguous(path, *args, **kwargs):
            if str(path) == "/run/xl2tpd/xl2tpd.pid":
                return "300"
            return read(path)
        with patch.object(v, "CHARON_PIDFILE", ["/run/charon.pid"]), \
             patch.object(v, "XL2TPD_PIDFILE", ["/run/xl2tpd.pid", "/run/xl2tpd/xl2tpd.pid"]), \
             patch.object(v.Path, "read_text", ambiguous), \
             patch.object(v.os, "stat", return_value=SimpleNamespace(st_ino=123)):
            self.assertIn("plusieurs PID", v.daemon_context()[0])

    def test_import_bsm_exact_effective_values(self):
        cfg, _ = converter.convert(BSM, "")
        self.assertEqual(cfg["check_interval"], 5)
        self.assertFalse(cfg["underlay_health_enabled"])
        self.assertEqual([t["iface"] for t in cfg["tunnels"]], ["ppp255001", "ppp255002"])
        self.assertEqual([t["underlay_base"] for t in cfg["tunnels"]], [2, 2])
        self.assertEqual([t["manage_default"] for t in cfg["tunnels"]], [False, False])
        self.assertEqual(cfg["full_ipsec_after"], 0)
        expected = json.loads((ROOT / "configs/rt-bsm-1.json").read_text())
        self.assertEqual(cfg, expected)

    def test_unknown_config_and_string_boolean_rejected(self):
        cfg, _ = converter.convert(BSM, "")
        with self.assertRaises(ValueError):
            v.validate_config(dict(cfg, wrong_key=1))
        cfg["tunnels"][0]["manage_default"] = "false"
        with self.assertRaisesRegex(ValueError, "manage_default"):
            v.validate_config(cfg)

    def test_expansions_are_never_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "executed"
            bad = BSM.replace('PPP_INTERFACE="ppp255001"',
                              'PPP_INTERFACE="$(touch ' + str(marker) + ')"')
            with self.assertRaisesRegex(ValueError, "expression shell refusée"):
                converter.convert(bad, "")
            self.assertFalse(marker.exists())

    def test_missing_flags_fail_instead_of_enabling_defaults(self):
        with self.assertRaisesRegex(ValueError, "ENABLE_TUN1_DEFAULT_ROUTE"):
            converter.convert(BSM.replace('ENABLE_TUN1_DEFAULT_ROUTE="no"', ''), "")

    def test_exclusions_and_independent_underlay_threshold(self):
        text = BSM.replace('log()', '''UNDERLAY_EXCLUDE_GWS=("192.0.2.1")
UNDERLAY_EXCLUDE_DEVS=("eth2")
UNDERLAY_EXCLUDE_GWDEV=("192.0.2.2@eth3")
log()''').replace("UNDERLAY_MAX_FAILED_PINGS=3", "UNDERLAY_MAX_FAILED_PINGS=7")
        cfg, _ = converter.convert(text, "vpn-test")
        self.assertEqual(cfg["exclude_gwdev"], [["192.0.2.2", "eth3"]])
        self.assertEqual(cfg["underlay_failed_probes"], 7)
        self.assertEqual(cfg["failed_probes"], 3)
        self.assertEqual(cfg["expected_netns"], "vpn-test")

    def test_array_comments_with_parenthesized_examples(self):
        for values in ('', '"192.0.2.1"'):
            with self.subTest(values=values):
                source = BSM.replace('log()', '''UNDERLAY_EXCLUDE_GWS=(%s) # ex: ("10.44.0.1" "192.0.2.1")
UNDERLAY_EXCLUDE_DEVS=() # ex: ("eth2" "br1")
UNDERLAY_EXCLUDE_GWDEV=() # ex: ("10.44.0.1@eth2")
log()''' % values)
                cfg, _ = converter.convert(source, "")
                self.assertEqual(cfg["exclude_gws"], ["192.0.2.1"] if values else [])
                self.assertEqual(cfg["exclude_devs"], [])
                self.assertEqual(cfg["exclude_gwdev"], [])

    def test_array_trailing_commands_and_multiline_are_rejected(self):
        for raw in ('() ; touch /tmp/should-not-run', '("192.0.2.1"\n)',
                    '("$(hostname)")'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                converter.assignments('UNDERLAY_EXCLUDE_GWS=' + raw)

    def test_import_requires_explicit_namespace_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, dest = Path(tmp) / "old.sh", Path(tmp) / "config.json"
            source.write_text(BSM)
            dest.write_text("keep")
            base = [sys.executable, str(ROOT / "convert_vpn_config.py"), str(source)]
            result = subprocess.run(base, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            result = subprocess.run(base + ["--current-namespace", "--output", str(dest)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(dest.read_text(), "keep")

    def test_offline_cli_has_no_network_dependency(self):
        result = subprocess.run([sys.executable, str(ROOT / "vpn_supervisor.py"), "--config",
                                 str(ROOT / "configs/rt-bsm-1.json"), "--validate-config"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("aucune commande réseau", result.stderr)


class RuntimeConfigTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.saved = {v.CONFIG_ALIASES.get(k, k.upper()): copy.deepcopy(getattr(v, v.CONFIG_ALIASES.get(k, k.upper())))
                      for k in v.CONFIG_DEFAULTS if k != "schema_version"}

    def tearDown(self):
        for key, value in self.saved.items():
            setattr(v, key, value)

    async def test_bsm_never_changes_ppp_defaults_even_on_failure(self):
        v.load_config(ROOT / "configs/rt-bsm-1.json")
        s = v.Supervisor()
        routes = [physical(metric=0), dict(dst="default", dev="ppp255001", protocol="static", metric=10)]
        v.check_default_priority(routes)  # zéro est permis : aucune default PPP gérée
        with patch.object(v, "command", AsyncMock()) as cmd:
            for t in v.TUNNELS:
                s.health[t["name"]] = v.Health(up=True, known=True)
            await s.defaults(routes)
            for t in v.TUNNELS:
                s.health[t["name"]] = v.Health(up=False, known=True, bad=3)
            await s.defaults(routes)
        cmd.assert_not_called()

    async def test_bsm_public_routes_use_base_two_for_both_peers(self):
        v.load_config(ROOT / "configs/rt-bsm-1.json")
        p = physical(metric=0)
        kernel = FakeKernel([p])
        with patch.object(v, "command", kernel.command):
            await v.Supervisor().public_routes(kernel.routes[:], [p])
        managed = [r for r in kernel.routes if v.destination(r) != "default"]
        self.assertEqual(len(managed), 2)
        self.assertEqual([r["metric"] for r in managed], [2, 2])

    async def test_require_up_rejects_unhealthy_tunnels_without_writes(self):
        v.load_config(ROOT / "configs/rt-bsm-1.json")
        s = v.Supervisor()
        with tempfile.TemporaryDirectory() as tmp:
            import os
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            with patch.object(v, "CONTROL_FIFO", fifo), patch.object(v, "daemon_context", return_value=[]), \
                 patch.object(v, "ip_json", AsyncMock(side_effect=[[physical(metric=0)], []])), \
                 patch.object(s, "ping", AsyncMock(return_value=False)), \
                 patch.object(s, "ipsec_ok", AsyncMock(return_value=True)), \
                 patch.object(v, "command", AsyncMock()) as cmd:
                with self.assertRaisesRegex(RuntimeError, "non validé opérationnel"):
                    await v.preflight(s, True, require_up=True)
                cmd.assert_not_called()

    async def test_loading_config_replaces_previous_machine_values(self):
        v.load_config(ROOT / "configs/rt-bsm-1.json")
        self.assertEqual(v.EXPECTED_NETNS, "")
        self.assertEqual(v.TUNNELS[0]["iface"], "ppp255001")
        v.load_config(ROOT / "configs/localhost-netns1.json")
        self.assertEqual(v.EXPECTED_NETNS, "netns1")
        self.assertEqual(v.TUNNELS[0]["iface"], "ppp001001")

    async def test_command_default_timeout_uses_loaded_configuration(self):
        v.COMMAND_TIMEOUT = 0.05
        result = await v.command(sys.executable, "-c", "import time; time.sleep(5)")
        self.assertEqual(result[0], 124)
