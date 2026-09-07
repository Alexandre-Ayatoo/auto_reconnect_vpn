import asyncio
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

SCRIPT = Path(__file__).parents[1] / "vpn_supervisor.py"
spec = importlib.util.spec_from_file_location("vpn", SCRIPT)
v = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = v
spec.loader.exec_module(v)
v.load_config(Path(__file__).parents[1] / "configs/localhost-netns1.json")


def physical(gw="192.0.2.1", dev="eth0", metric=100):
    return dict(dst="default", gateway=gw, dev=dev, metric=metric, protocol=16)


class FakeKernel:
    """Modèle FIB minimal : replace sélectionne destination+metric, pas l'ancienne metric."""
    def __init__(self, routes):
        self.routes = copy.deepcopy(routes)
        self.calls = []

    async def command(self, *args, **kwargs):
        self.calls.append(args)
        assert args[:3] == ("ip", "-4", "route"), args
        action = args[3]
        tokens = list(args[4:])
        route = {}
        if tokens[0] == "unreachable":
            route["type"] = tokens.pop(0)
        route["dst"] = tokens.pop(0)
        while tokens:
            key = tokens.pop(0)
            if key == "onlink":
                route["flags"] = ["onlink"]
                continue
            value = tokens.pop(0)
            if key == "table":
                continue
            key = {"via": "gateway", "proto": "protocol"}.get(key, key)
            route[key] = int(value) if key == "metric" else value
        if action == "replace":
            self.routes = [r for r in self.routes if not
                           (v.destination(r) == v.destination(route) and r.get("metric", 0) == route.get("metric", 0))]
            self.routes.append(route)
            return 0, "", ""
        if action == "del":
            before = len(self.routes)
            self.routes = [r for r in self.routes if not (v.route_key(r) == v.route_key(route)
                          and str(r.get("protocol", "boot")) == str(route["protocol"]))]
            return (0, "", "") if before != len(self.routes) else (2, "", "No such process")
        raise AssertionError(args)


class ParsingTests(unittest.TestCase):
    def test_discovery_ignores_direct_ppp_and_uses_physical_metrics(self):
        routes = [dict(dst="default", dev="ppp001001", scope="link"),
                  physical("192.0.2.1", "eth0", 500), physical("192.0.2.9", "eth1", 50),
                  physical("192.0.2.1", "eth0", 600)]
        self.assertEqual([r["dev"] for r in v.discover(routes)], ["eth1", "eth0"])

    def test_same_interface_two_gateways_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "plusieurs passerelles"):
            v.discover([physical(), physical("192.0.2.9")])

    def test_exclusion(self):
        with patch.object(v, "EXCLUDE_GWDEV", {("192.0.2.1", "eth0")}):
            self.assertEqual(v.discover([physical()]), [])

    def test_physical_default_zero_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "default concurrente"):
            v.check_default_priority([physical(metric=0)])
        v.check_default_priority([physical(metric=100), dict(dst="default", dev="ppp001001")])

    def test_sa_exact_name_and_peer(self):
        t = v.TUNNELS[0]
        correct = "l2tp-ipsec-vpn[3]: ESTABLISHED 3 minutes ago, 10.0.0.1[local]...51.75.129.106[remote]\n" \
                  "l2tp-ipsec-vpn{5}: INSTALLED, TRANSPORT, reqid 1, ESP in UDP SPIs: aa_i bb_o\n"
        self.assertTrue(v.sa_installed(correct, t))
        self.assertFalse(v.sa_installed(correct.replace("vpn{5}", "vpn-2{5}"), t))
        self.assertFalse(v.sa_installed(correct.replace("51.75.129.106", "51.75.129.105"), t))
        self.assertFalse(v.sa_installed(correct.replace("ESTABLISHED", "CONNECTING"), t))
        self.assertFalse(v.sa_installed(correct.replace("51.75.129.106", "51.75.129.1060"), t))

    def test_hysteresis_and_startup_learning(self):
        h = v.Health()
        h.feed(True)
        self.assertFalse(h.known)
        h.feed(True)
        self.assertTrue(h.up)
        h.feed(False)
        h.feed(False)
        self.assertTrue(h.up)
        h.feed(False)
        self.assertFalse(h.up)
        h.feed(True)
        self.assertFalse(h.up)
        h.feed(True)
        self.assertTrue(h.up)

    def test_fifo_without_reader_returns_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            with patch.object(v, "CONTROL_FIFO", fifo):
                start = time.monotonic()
                with self.assertRaises(OSError):
                    v.fifo_write("c myvpn")
                self.assertLess(time.monotonic() - start, 0.1)

    def test_fifo_command_and_regular_file_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            try:
                with patch.object(v, "CONTROL_FIFO", fifo):
                    v.fifo_write("c myvpn")
                self.assertEqual(os.read(fd, 512), b"c myvpn\n")
            finally:
                os.close(fd)
            regular = Path(tmp) / "file"
            regular.write_text("preserve")
            with patch.object(v, "CONTROL_FIFO", str(regular)):
                with self.assertRaises(RuntimeError):
                    v.fifo_write("c myvpn")
            self.assertEqual(regular.read_text(), "preserve")


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_boot_protocol_requires_detailed_ip_output(self):
        # Régression issue du JSON réel communiqué par l'utilisateur.
        route = dict(dst="51.75.129.106", gateway="192.168.2.1", dev="eth5", metric=100, flags=[])
        async def ip_output(*args, **kwargs):
            shown = dict(route)
            if "-details" in args:
                shown["protocol"] = "3"
                shown["type"] = "1"
                shown["scope"] = "0"
            uplink = physical("192.168.2.1", "eth5")
            if "-details" in args:
                uplink["type"] = "1"
            return 0, json.dumps([shown, uplink]), ""
        with patch.object(v, "command", ip_output):
            routes = await v.ip_json("route", "show", "table", "main")
        s = v.Supervisor()
        paths = v.discover(routes)
        self.assertEqual(len(paths), 1)
        s.check_public_conflicts(routes, paths)
        self.assertEqual(v.protocol(routes[0]), "3")
        self.assertEqual(routes[0]["type"], "unicast")

    async def test_numeric_route_types_normalized_for_keys_and_commands(self):
        raw = [dict(type="1", dst="51.75.129.106", protocol="186", metric=100),
               dict(type=7, dst="51.75.129.105", protocol="186", metric=32000),
               dict(type="blackhole", dst="192.0.2.1")]
        with patch.object(v, "command", AsyncMock(return_value=(0, json.dumps(raw), ""))):
            routes = await v.ip_json("route", "show", "table", "main")
        self.assertEqual([r["type"] for r in routes], ["unicast", "unreachable", "blackhole"])
        self.assertEqual(v.route_args(routes[0])[0], "51.75.129.106/32")
        self.assertEqual(v.route_args(routes[1])[0], "unreachable")
        self.assertEqual(v.route_key(routes[1])[-1], "unreachable")

    async def test_loop_failover_continues_during_slow_recovery(self):
        kernel = FakeKernel([physical(), dict(dst="default", dev="ppp001001", protocol="boot")])
        s = v.Supervisor()
        t1, t2 = v.TUNNELS
        blocked = asyncio.Event()
        entered = asyncio.Event()
        async def slow_recovery(*_):
            entered.set()
            await blocked.wait()
        async def read(*_):
            return copy.deepcopy(kernel.routes)
        async def ping(dev, target):
            return dev == t2["iface"]
        with patch.object(v, "command", kernel.command), patch.object(v, "ip_json", read), \
             patch.object(v, "daemon_context", return_value=[]), patch.object(v, "UNDERLAY_HEALTH_ENABLED", False), \
             patch.object(s, "ipsec_ok", AsyncMock(return_value=True)), \
             patch.object(s, "ping", ping), patch.object(s, "reconnect", slow_recovery):
            for _ in range(3):
                await s.cycle()
            await asyncio.wait_for(entered.wait(), 1)
            await asyncio.wait_for(s.cycle(), 1)
            self.assertFalse(s.recovery[t1["name"]].done())
            self.assertFalse(any(r.get("dev") == t1["iface"] for r in kernel.routes))
            self.assertTrue(any(r.get("dev") == t2["iface"] for r in kernel.routes))
            blocked.set()
            await s.recovery[t1["name"]]

    async def test_failed_public_routes_do_not_freeze_health_checks(self):
        s = v.Supervisor()
        s.health[v.TUNNELS[0]["name"]] = v.Health(up=True, known=True)
        async def probe(t, context):
            s.health[t["name"]].feed(False)
            return False
        with patch.object(v, "ip_json", AsyncMock(return_value=[physical()])), \
             patch.object(v, "daemon_context", return_value=[]), patch.object(v, "UNDERLAY_HEALTH_ENABLED", False), \
             patch.object(s, "public_routes", AsyncMock(side_effect=RuntimeError("gateway unavailable"))), \
             patch.object(s, "probe_tunnel", probe), patch.object(s, "defaults", AsyncMock()) as defaults:
            for _ in range(3):
                await s.cycle()
        self.assertFalse(s.health[v.TUNNELS[0]["name"]].up)
        self.assertEqual(defaults.await_count, 3)
        self.assertEqual(s.recovery, {})

    async def test_ping_and_ipsec_probes_run_concurrently(self):
        s = v.Supervisor()
        started = set()
        ready = asyncio.Event()
        async def rendezvous(label):
            started.add(label)
            if len(started) == 2:
                ready.set()
            await ready.wait()
            return True
        with patch.object(s, "ping", lambda *args: rendezvous("ping")), \
             patch.object(s, "ipsec_ok", lambda *args: rendezvous("ipsec")):
            await asyncio.wait_for(s.probe_tunnel(v.TUNNELS[0], True), 1)
        self.assertEqual(started, {"ping", "ipsec"})

    async def test_penalty_persists_and_restore_removes_old_metric(self):
        paths = [physical(), physical("198.51.100.1", "eth1", 200)]
        kernel = FakeKernel(paths)
        s = v.Supervisor()
        with patch.object(v, "command", kernel.command), patch.object(v, "UNDERLAY_FAILURE_ACTION", "penalize"):
            await s.public_routes(kernel.routes[:], paths)
            h = s.underlay[(v.TUNNELS[0]["peer"], "192.0.2.1", "eth0")]
            for _ in range(3):
                h.feed(False)
            await s.public_routes(kernel.routes[:], paths)
            peer_routes = [r for r in kernel.routes if v.destination(r) == "51.75.129.106/32"]
            self.assertEqual({r["metric"] for r in peer_routes}, {101, 5100})
            before = len(kernel.calls)
            await s.public_routes(kernel.routes[:], paths)
            self.assertEqual(len(kernel.calls), before, "no repeated writes while state unchanged")
            # Redémarrage du superviseur : conserver une pénalité présente en FIB.
            fresh = v.Supervisor()
            await fresh.public_routes(kernel.routes[:], paths)
            self.assertFalse(fresh.underlay[("51.75.129.106", "192.0.2.1", "eth0")].up)
            h.feed(True)
            h.feed(True)
            await s.public_routes(kernel.routes[:], paths)
            peer_routes = [r for r in kernel.routes if v.destination(r) == "51.75.129.106/32"]
            self.assertEqual({r["metric"] for r in peer_routes}, {100, 101})

    async def test_route_change_adds_before_deletes(self):
        kernel = FakeKernel([dict(dst="51.75.129.106/32", gateway="192.0.2.1", dev="eth0", metric=100, protocol=186)])
        desired = dict(dst="51.75.129.106/32", gateway="192.0.2.1", dev="eth0", metric=5100)
        with patch.object(v, "command", kernel.command):
            await v.Supervisor().reconcile(kernel.routes[:], [desired])
        self.assertEqual([c[3] for c in kernel.calls], ["replace", "del"])

    async def test_failed_add_never_deletes_old_route(self):
        cmd = AsyncMock(return_value=(2, "", "unreachable gateway"))
        with patch.object(v, "command", cmd):
            with self.assertRaises(RuntimeError):
                await v.Supervisor().reconcile([dict(dst="default", dev="eth0", metric=0)],
                                               [dict(dst="default", dev="eth0", metric=5000)])
        self.assertEqual(cmd.await_count, 1)

    async def test_underlay_disappearance_and_rediscovery(self):
        p = physical()
        kernel = FakeKernel([p])
        s = v.Supervisor()
        with patch.object(v, "command", kernel.command):
            await s.public_routes(kernel.routes[:], [p])
            kernel.routes.remove(p)
            await s.public_routes(kernel.routes[:], [])
            self.assertTrue(all(r["type"] == "unreachable" for r in kernel.routes))
            p2 = physical("198.51.100.1", "eth2")
            kernel.routes.append(p2)
            await s.public_routes(kernel.routes[:], [p2])
            self.assertEqual(len(kernel.routes), 3)
            self.assertFalse(any(r.get("type") == "unreachable" for r in kernel.routes))
            self.assertTrue(all(r["dev"] == "eth2" for r in kernel.routes))

    async def test_legacy_adoption_and_foreign_conflict(self):
        p = physical()
        legacy = dict(dst="51.75.129.106", gateway="192.0.2.1", dev="eth0", metric=100, protocol=3)
        kernel = FakeKernel([p, legacy])
        s = v.Supervisor()
        with patch.object(v, "command", kernel.command):
            await s.public_routes(kernel.routes[:], [p])
        adopted = [r for r in kernel.routes if v.destination(r) == "51.75.129.106/32"]
        self.assertEqual(len(adopted), 1)
        self.assertEqual(str(adopted[0]["protocol"]), "186")
        with self.assertRaisesRegex(RuntimeError, "non gérée"):
            s.check_public_conflicts([dict(legacy, protocol=4)], [p])

    async def test_defaults_initial_learning_failure_and_restore(self):
        physical_route = physical()
        kernel = FakeKernel([physical_route, dict(dst="default", dev="ppp001001", protocol="boot")])
        s = v.Supervisor()
        t1, t2 = v.TUNNELS
        with patch.object(v, "command", kernel.command):
            await s.defaults(kernel.routes[:])
            self.assertEqual(len(kernel.calls), 0, "do not withdraw a healthy VPN on startup")
            s.health[t2["name"]] = v.Health(up=True, known=True)
            for _ in range(3):
                s.health[t1["name"]].feed(False)
            await s.defaults(kernel.routes[:])
            self.assertEqual([r["dev"] for r in kernel.routes], ["eth0", "ppp001002"])
            self.assertEqual([c[3] for c in kernel.calls], ["replace", "del"])
            for _ in range(2):
                s.health[t1["name"]].feed(True)
            await s.defaults(kernel.routes[:])
            self.assertEqual({r["dev"] for r in kernel.routes}, {"eth0", "ppp001001", "ppp001002"})
            self.assertIn(physical_route, kernel.routes)

    async def test_default_wrong_metric_is_corrected(self):
        kernel = FakeKernel([dict(dst="default", dev="ppp001001", metric=500, protocol="boot")])
        s = v.Supervisor()
        s.health[v.TUNNELS[0]["name"]] = v.Health(up=True, known=True)
        with patch.object(v, "command", kernel.command):
            await s.defaults(kernel.routes[:])
        self.assertEqual([r["metric"] for r in kernel.routes], [0])

    async def test_ipsec_failure_does_not_start_l2tp(self):
        s = v.Supervisor()
        t = v.TUNNELS[0]
        async def no_sleep(_):
            pass
        with patch.object(v, "daemon_context", return_value=[]), \
             patch.object(v, "command", AsyncMock(return_value=(124, "", "timeout"))), \
             patch.object(s, "ipsec_ok", AsyncMock(return_value=False)), \
             patch.object(s, "send_l2tp", AsyncMock()) as fifo, patch.object(v.asyncio, "sleep", no_sleep):
            await s.reconnect(t, False)
        fifo.assert_not_called()
        self.assertGreater(s.next_recovery[t["name"]], time.monotonic() + 59)

    async def test_reconnect_is_targeted_and_full_recovery_after_three(self):
        s = v.Supervisor()
        t = v.TUNNELS[1]
        s.attempts[t["name"]] = 2
        cmd = AsyncMock(return_value=(0, "", ""))
        async def no_sleep(_):
            pass
        with patch.object(v, "daemon_context", return_value=[]), \
             patch.object(v, "command", cmd), patch.object(s, "ipsec_ok", AsyncMock(return_value=True)), \
             patch.object(s, "interface_exists", AsyncMock(side_effect=[True, False])), \
             patch.object(s, "send_l2tp", AsyncMock()) as fifo, patch.object(v.asyncio, "sleep", no_sleep):
            await s.reconnect(t, True)
        self.assertEqual([c.args for c in cmd.await_args_list],
                         [("ipsec", "down", t["name"]), ("ipsec", "up", t["name"])])
        self.assertEqual([c.args[0] for c in fifo.call_args_list], ["d myvpn-2", "c myvpn-2"])

    async def test_ping_execution_error_is_not_a_failed_probe(self):
        s = v.Supervisor()
        cmd = AsyncMock(return_value=(2, "", "ping: invalid option -- '4'"))
        with patch.object(s, "interface_exists", AsyncMock(return_value=True)), patch.object(v, "command", cmd):
            with self.assertRaisesRegex(RuntimeError, "indéterminé"):
                await s.ping("ppp001001", "203.0.113.251")
        self.assertEqual(cmd.await_args.args,
                         ("ping", "-I", "ppp001001", "-c", "1", "-W", "2", "203.0.113.251"))

    async def test_missing_interface_is_a_real_failure(self):
        s = v.Supervisor()
        with patch.object(v, "command", AsyncMock(return_value=(1, "", 'Device "ppp001001" does not exist.'))) as cmd:
            self.assertFalse(await s.ping("ppp001001", "203.0.113.251"))
        self.assertEqual(cmd.await_count, 1)

    async def test_probe_error_prevents_defaults_and_recovery(self):
        s = v.Supervisor()
        with patch.object(v, "ip_json", AsyncMock(return_value=[physical()])), \
             patch.object(s, "public_routes", AsyncMock()), patch.object(v, "daemon_context", return_value=[]), \
             patch.object(s, "ping", AsyncMock(side_effect=RuntimeError("test ping indéterminé"))), \
             patch.object(s, "ipsec_ok", AsyncMock(return_value=True)), \
             patch.object(s, "defaults", AsyncMock()) as defaults:
            for _ in range(3):
                with self.assertRaisesRegex(RuntimeError, "indéterminé"):
                    await s.cycle()
        defaults.assert_not_called()
        self.assertEqual(s.recovery, {})
        self.assertTrue(all(h.bad == 0 for h in s.health.values()))

    async def test_l2tp_connect_waits_for_previous_interface_disappearance(self):
        s = v.Supervisor()
        t = v.TUNNELS[0]
        events = []
        async def exists(dev):
            events.append("interface")
            return events.count("interface") == 1
        async def sleep(_):
            pass
        async def send(message):
            events.append(message)
        with patch.object(v, "daemon_context", return_value=[]), \
             patch.object(s, "interface_exists", exists), patch.object(v.asyncio, "sleep", sleep), \
             patch.object(s, "send_l2tp", send):
            await s.reconnect(t, True)
        self.assertEqual(events, ["d myvpn", "interface", "interface", "c myvpn"])

    async def test_concurrent_l2tp_commands_are_separate_fifo_reads(self):
        s = v.Supervisor()
        received = []
        with tempfile.TemporaryDirectory() as tmp:
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            async def consume():
                for _ in range(100):
                    try:
                        data = os.read(reader, 4096)
                    except BlockingIOError:
                        data = b""
                    if data:
                        received.append(data)
                    if len(received) == 2:
                        return
                    await asyncio.sleep(0.01)
                raise AssertionError("two distinct reads not observed")
            try:
                with patch.object(v, "CONTROL_FIFO", fifo):
                    await asyncio.wait_for(asyncio.gather(s.send_l2tp("c myvpn"),
                                                         s.send_l2tp("c myvpn-2"), consume()), 2)
            finally:
                os.close(reader)
        self.assertEqual(received, [b"c myvpn\n", b"c myvpn-2\n"])

    async def test_stalled_fifo_disables_subsequent_writes(self):
        s = v.Supervisor()
        with tempfile.TemporaryDirectory() as tmp:
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            try:
                with patch.object(v, "CONTROL_FIFO", fifo), patch.object(v, "COMMAND_TIMEOUT", 0.02):
                    with self.assertRaisesRegex(RuntimeError, "pas consommé"):
                        await s.send_l2tp("c myvpn")
                    with self.assertRaisesRegex(RuntimeError, "bloqué"):
                        await s.send_l2tp("c myvpn-2")
                self.assertEqual(os.read(reader, 4096), b"c myvpn\n")
            finally:
                os.close(reader)

    async def test_wrong_namespace_blocks_all_recovery_commands(self):
        s = v.Supervisor()
        with patch.object(v, "daemon_context", return_value=["charon autre netns"]), \
             patch.object(v, "command", AsyncMock()) as cmd, patch.object(v, "fifo_write") as fifo:
            await s.reconnect(v.TUNNELS[0], False)
        cmd.assert_not_called()
        fifo.assert_not_called()

    async def test_timeout_is_bounded_and_cancellation_reaps(self):
        start = time.monotonic()
        result = await v.command(sys.executable, "-c", "import time; time.sleep(30)", timeout=0.15)
        self.assertEqual(result[0], 124)
        self.assertLess(time.monotonic() - start, 2)
        task = asyncio.create_task(v.command(sys.executable, "-c", "import time; time.sleep(30)"))
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_check_is_read_only(self):
        s = v.Supervisor()
        read = AsyncMock(side_effect=[[physical()], [dict(priority=0), dict(priority=32766), dict(priority=32767)]])
        with tempfile.TemporaryDirectory() as tmp:
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            with patch.object(v, "CONTROL_FIFO", fifo), patch.object(v, "daemon_context", return_value=[]), \
                 patch.object(v, "ip_json", read), patch.object(s, "ping", AsyncMock(return_value=False)), \
                 patch.object(s, "ipsec_ok", AsyncMock(return_value=False)), \
                 patch.object(v, "command", AsyncMock()) as cmd, patch.object(v, "fifo_write") as write:
                await v.preflight(s, True)
            cmd.assert_not_called()
            write.assert_not_called()
            self.assertEqual([c.args for c in read.await_args_list],
                             [("route", "show", "table", "main"), ("rule", "show")])

    async def test_check_reports_unqueried_ipsec_as_unknown(self):
        s = v.Supervisor()
        with tempfile.TemporaryDirectory() as tmp:
            fifo = str(Path(tmp) / "control")
            os.mkfifo(fifo)
            with patch.object(v, "CONTROL_FIFO", fifo), \
                 patch.object(v, "daemon_context", return_value=["xl2tpd PIDFILE absent"]), \
                 patch.object(v, "ip_json", AsyncMock(side_effect=[[physical()], []])), \
                 patch.object(s, "ping", AsyncMock(return_value=False)), \
                 patch.object(s, "ipsec_ok", AsyncMock()) as sa, \
                 self.assertLogs(v.LOG, level="INFO") as logs:
                with self.assertRaisesRegex(RuntimeError, "PIDFILE absent"):
                    await v.preflight(s, True)
            sa.assert_not_called()
            self.assertTrue(any("SA IPsec=non vérifiée" in line for line in logs.output))
            self.assertFalse(any("SA IPsec=False" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main(verbosity=2)
