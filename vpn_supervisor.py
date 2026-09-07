#!/usr/bin/env python3
"""Superviseur L2TP/IPsec commun à plusieurs machines, Python 3.9+.

Configuration obligatoire : /etc/auto-reconnect-vpn.json ou --config CHEMIN.
  --validate-config : contrôle JSON hors ligne, sans privilège ni commandes
  --check           : diagnostic sans modifier les routes ou les connexions
  --check --require-up : diagnostic qui exige aussi tous les tunnels opérationnels
  --run             : supervision active (arrêter l'ancien superviseur auparavant)

Exécuter dans le même namespace que charon, xl2tpd et les PPP. Le programme
ne change pas lui-même de namespace : conserver le wrapper de l'unité existante.
expected_netns="" signifie namespace courant, avec validation des PID des démons.

manage_default=false : aucune route par défaut de ce tunnel n'est gérée.
manage_default=true : le superviseur gère exclusivement sa default ; les hooks
pppd concurrents doivent être désactivés pour cette fonction. Les defaults
physiques restent intactes et doivent avoir une métrique supérieure aux defaults
gérées. Routes plus spécifiques, règles ip rule, NAT, pare-feu, forwarding,
MTU/MSS, DNS et configuration des services VPN restent externes.

Voir README.md pour la migration et les exemples de configuration.
"""

import argparse
import array
import asyncio
import copy
import fcntl
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import stat
import termios
import time
from dataclasses import dataclass
from pathlib import Path

# La configuration est chargée uniquement par main(), jamais à l'import.
# Aucun nom de serveur ni d'interface n'est sélectionné implicitement.
CONFIG_DEFAULTS = {
    "schema_version": 1, "expected_netns": "", "tunnels": [],
    "check_interval": 2.0, "failed_probes": 3, "successful_probes": 2,
    "reconnect_cooldown": 60.0, "full_ipsec_after": 3,
    "underlay_check_every": 10.0, "underlay_health_enabled": False,
    "underlay_failed_probes": 3, "underlay_successful_probes": 2,
    "underlay_failure_action": "none", "underlay_penalty": 5000,
    "route_protocol": 186, "control_fifo": "/run/xl2tpd/l2tp-control",
    "charon_pidfiles": ["/run/charon.pid"],
    "xl2tpd_pidfiles": ["/run/xl2tpd.pid", "/run/xl2tpd/xl2tpd.pid"],
    "command_timeout": 3.0, "ipsec_up_timeout": 20.0,
    "l2tp_disconnect_timeout": 12.0, "heartbeat_every": 60.0,
    "start_stopped_services": False,
    "service_units": ["strongswan-starter.service", "xl2tpd.service"],
    "service_check_every": 30.0,
    "exclude_gws": [], "exclude_devs": [], "exclude_gwdev": [],
}
CONFIG_ALIASES = {"expected_netns": "EXPECTED_NETNS", "charon_pidfiles": "CHARON_PIDFILE",
                  "xl2tpd_pidfiles": "XL2TPD_PIDFILE", "underlay_health_enabled": "UNDERLAY_HEALTH_ENABLED"}


def validate_config(data):
    """Validation pure : ne lance aucune commande ni lecture réseau."""
    if not isinstance(data, dict):
        raise ValueError("configuration JSON attendue : objet")
    missing = {"schema_version", "expected_netns", "tunnels"} - data.keys()
    unknown = data.keys() - CONFIG_DEFAULTS.keys()
    if missing or unknown:
        raise ValueError("clés manquantes=%s ; inconnues=%s" % (sorted(missing), sorted(unknown)))
    cfg = copy.deepcopy(CONFIG_DEFAULTS)
    cfg.update(copy.deepcopy(data))
    if type(cfg["schema_version"]) is not int or cfg["schema_version"] != 1:
        raise ValueError("schema_version doit valoir 1")
    for key, default in CONFIG_DEFAULTS.items():
        value = cfg[key]
        if type(default) is bool and type(value) is not bool:
            raise ValueError(key + " doit être un booléen JSON true/false")
        if type(default) is float and (type(value) not in (int, float) or not 0 < value < float("inf")):
            raise ValueError(key + " doit être un nombre positif fini")
        if type(default) is int:
            minimum = 0 if key == "full_ipsec_after" else 1
            if type(value) is not int or value < minimum:
                raise ValueError(key + " doit être un entier >= " + str(minimum))
        if type(default) is str and not isinstance(value, str):
            raise ValueError(key + " doit être une chaîne")
        if type(default) is list and not isinstance(value, list):
            raise ValueError(key + " doit être une liste")
    if cfg["expected_netns"] and not re.fullmatch(r"[A-Za-z0-9_.-]+", cfg["expected_netns"]):
        raise ValueError("expected_netns invalide")
    if cfg["underlay_failure_action"] not in ("none", "penalize"):
        raise ValueError("underlay_failure_action : none ou penalize")
    if not 5 <= cfg["route_protocol"] <= 255:
        raise ValueError("route_protocol doit être compris entre 5 et 255 et réservé localement")
    for key in ("charon_pidfiles", "xl2tpd_pidfiles"):
        if not cfg[key] or any(not isinstance(p, str) or not p.startswith("/") for p in cfg[key]):
            raise ValueError(key + " : liste non vide de chemins absolus attendue")
    if not cfg["control_fifo"].startswith("/"):
        raise ValueError("control_fifo doit être absolu")
    for gw in cfg["exclude_gws"]:
        if not isinstance(gw, str):
            raise ValueError("exclude_gws : adresses IPv4 sous forme de chaînes")
        ipaddress.IPv4Address(gw)
    for key in ("exclude_devs", "service_units"):
        if any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]+", x) for x in cfg[key]):
            raise ValueError(key + " contient un nom invalide")
    for pair in cfg["exclude_gwdev"]:
        if (not isinstance(pair, list) or len(pair) != 2 or
                any(not isinstance(x, str) for x in pair) or not pair[1]):
            raise ValueError("exclude_gwdev : paires [passerelle, interface] attendues")
        ipaddress.IPv4Address(pair[0])
    if cfg["start_stopped_services"] and not cfg["service_units"]:
        raise ValueError("service_units est vide")
    if not cfg["tunnels"]:
        raise ValueError("au moins un tunnel est requis")
    required = {"name", "session", "iface", "peer", "target", "metric", "underlay_base", "manage_default"}
    for i, t in enumerate(cfg["tunnels"]):
        if not isinstance(t, dict) or set(t) != required:
            raise ValueError("tunnel %s : clés attendues %s" % (i, sorted(required)))
        for key in ("name", "session", "iface"):
            if not isinstance(t[key], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", t[key]):
                raise ValueError("tunnel %s : %s invalide" % (i, key))
        if len(t["iface"].encode()) > 15:
            raise ValueError("nom d'interface trop long")
        for key in ("peer", "target"):
            if not isinstance(t[key], str):
                raise ValueError(key + " doit être une adresse IPv4 en chaîne")
            ipaddress.IPv4Address(t[key])
        if type(t["manage_default"]) is not bool:
            raise ValueError("manage_default doit être true ou false, jamais une chaîne")
        for key in ("metric", "underlay_base"):
            if type(t[key]) is not int or not 0 <= t[key] <= 4294967295 - cfg["underlay_penalty"] - 100:
                raise ValueError(key + " : métrique invalide")
    for key in ("name", "session", "iface", "peer"):
        if len({t[key] for t in cfg["tunnels"]}) != len(cfg["tunnels"]):
            raise ValueError("tunnels : " + key + " dupliqué")
    metrics = [t["metric"] for t in cfg["tunnels"] if t["manage_default"]]
    if len(set(metrics)) != len(metrics):
        raise ValueError("les defaults gérées doivent avoir des métriques distinctes")
    return cfg


def load_config(path):
    def unique_keys(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("clé JSON dupliquée : " + key)
            obj[key] = value
        return obj
    cfg = validate_config(json.loads(Path(path).read_text(), object_pairs_hook=unique_keys))
    for key, value in cfg.items():
        if key == "schema_version":
            continue
        if key in ("exclude_gws", "exclude_devs"):
            value = set(value)
        elif key == "exclude_gwdev":
            value = {tuple(pair) for pair in value}
        globals()[CONFIG_ALIASES.get(key, key.upper())] = value
    return cfg

# Valeurs neutres à l'import ; main() exige le fichier de configuration.
for _key, _value in copy.deepcopy(CONFIG_DEFAULTS).items():
    if _key != "schema_version":
        globals()[CONFIG_ALIASES.get(_key, _key.upper())] = _value


LOG = logging.getLogger("vpn-supervisor")
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
os.environ["LC_ALL"] = "C"


async def command(*args, timeout=None):
    """Pas de shell ; timeout et annulation tuent aussi les descendants."""
    if timeout is None:
        timeout = COMMAND_TIMEOUT
    proc = await asyncio.create_subprocess_exec(
        *map(str, args), stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.communicate()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return 124, "", "délai dépassé"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


async def ip_json(*args):
    # Sans -details, iproute2 omet le protocole boot (3), y compris en JSON.
    # Le demander explicitement pour reconnaître les routes de l'ancien script.
    rc, out, err = await command("ip", "-details", "-N", "-j", "-4", *args)
    if rc:
        raise RuntimeError("lecture ip impossible : " + err.strip())
    value = json.loads(out)
    if not isinstance(value, list):
        raise RuntimeError("sortie ip JSON invalide")
    # Normaliser les types numériques de -N à la frontière JSON.
    route_types = {str(n): name for n, name in enumerate(
        "unspec unicast local broadcast anycast multicast blackhole unreachable prohibit throw nat xresolve".split())}
    for item in value:
        if "type" in item:
            item["type"] = route_types.get(str(item["type"]), item["type"])
    return value


def protocol(route):
    return str(route.get("protocol", ""))


def destination(route):
    dst = route.get("dst", "default")
    if dst in ("default", "0.0.0.0/0"):
        return "default"
    return str(ipaddress.ip_network(dst, strict=False))


def route_key(route):
    return (destination(route), route.get("gateway"), route.get("dev"),
            int(route.get("metric", 0)), route.get("type", "unicast"))


def route_args(route):
    args = []
    if route.get("type", "unicast") != "unicast":
        args.append(route["type"])
    args += [destination(route), "table", "main"]
    if route.get("gateway"):
        args += ["via", route["gateway"]]
    if route.get("dev"):
        args += ["dev", route["dev"]]
    args += ["metric", str(route.get("metric", 0))]
    if "onlink" in route.get("flags", []):
        args.append("onlink")
    return args


def discover(routes):
    """Découverte à chaque cycle ; priorité des defaults physiques conservée."""
    found = {}
    for r in routes:
        if destination(r) != "default" or r.get("type", "unicast") != "unicast":
            continue
        if r.get("nexthops") or r.get("nhid"):
            raise RuntimeError("default multipath/nhid : définir des defaults simples avant utilisation")
        dev, gw = r.get("dev", ""), r.get("gateway")
        if not dev or dev.startswith("ppp"):
            continue
        if gw in EXCLUDE_GWS or dev in EXCLUDE_DEVS or (gw, dev) in EXCLUDE_GWDEV:
            continue
        key = (gw, dev)
        if key not in found or r.get("metric", 0) < found[key].get("metric", 0):
            found[key] = r
    result = sorted(found.values(), key=lambda r: (r.get("metric", 0), r.get("gateway", ""), r["dev"]))
    if len(result) >= 100:
        raise RuntimeError("trop d'accès pour les plages de métriques réservées")
    if UNDERLAY_HEALTH_ENABLED and len({r["dev"] for r in result}) != len(result):
        raise RuntimeError("plusieurs passerelles sur une interface : ping -I ne les distingue pas ; "
                           "exclure un couple ou désactiver UNDERLAY_HEALTH_ENABLED")
    return result


def check_default_priority(routes):
    managed = {t["iface"] for t in TUNNELS if t["manage_default"]}
    limit = max((t["metric"] for t in TUNNELS if t["manage_default"]), default=-1)
    for r in routes:
        if (destination(r) == "default" and r.get("dev") not in managed
                and int(r.get("metric", 0)) <= limit):
            raise RuntimeError("default concurrente de métrique <= %s : %s ; "
                               "augmenter sa métrique dans la configuration réseau" % (limit, r))


def sa_installed(text, tunnel):
    name = re.escape(tunnel["name"])
    ike = re.search(r"^\s*" + name + r"\[\d+\]:\s+ESTABLISHED\b[^\n]*", text, re.M)
    child = re.search(r"^\s*" + name + r"\{\d+\}:\s+INSTALLED\b", text, re.M)
    # Vérifier le peer du côté distant de l'IKE, pas un sélecteur /32 quelconque.
    remote = ike.group(0).split("...", 1)[-1] if ike else ""
    peer = re.search(r"(?<![\d.])" + re.escape(tunnel["peer"]) + r"(?![\d.])", remote)
    return bool(ike and "..." in ike.group(0) and child and peer)


def daemon_context():
    """Les sockets de contrôle ne sont pas isolées par le seul netns."""
    errors = []
    inode = os.stat("/proc/self/ns/net").st_ino
    for label, paths in (("charon", CHARON_PIDFILE), ("xl2tpd", XL2TPD_PIDFILE)):
        if isinstance(paths, str):
            paths = [paths]
        candidates = {}
        for path in paths:
            try:
                pid = int(Path(path).read_text().strip())
                if pid <= 1:
                    continue
                comm = Path("/proc/%d/comm" % pid).read_text().strip()
                if not comm.startswith(label):
                    continue
                candidates[pid] = os.stat("/proc/%d/ns/net" % pid).st_ino
            except (OSError, ValueError):
                continue
        if not candidates:
            errors.append(label + " : aucun PID valide dans " + ", ".join(paths))
        elif len(candidates) > 1:
            errors.append(label + " : plusieurs PID candidats ; préciser un seul PIDFILE dans la configuration")
        elif next(iter(candidates.values())) != inode:
            errors.append(label + " appartient à un autre netns")
    return errors


def fifo_write(message, keep_open=False):
    """Ouverture non bloquante : un FIFO sans lecteur ne fige jamais la boucle."""
    fd = os.open(CONTROL_FIFO, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    written = False
    try:
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise RuntimeError("le contrôle xl2tpd n'est pas un FIFO")
        data = (message + "\n").encode()
        if len(data) > 512 or os.write(fd, data) != len(data):
            raise RuntimeError("écriture FIFO incomplète")
        written = True
    finally:
        if not (keep_open and written):
            os.close(fd)
    return fd if keep_open else None


@dataclass
class Health:
    up: bool = False
    known: bool = False
    good: int = 0
    bad: int = 0

    def feed(self, ok, failed=None, successful=None):
        failed = FAILED_PROBES if failed is None else failed
        successful = SUCCESSFUL_PROBES if successful is None else successful
        before = self.up
        if ok:
            self.good = min(self.good + 1, successful)
            self.bad = 0
            if self.good >= successful:
                self.up = True
                self.known = True
        else:
            self.bad = min(self.bad + 1, failed)
            self.good = 0
            if self.bad >= failed:
                self.up = False
                self.known = True
        return self.up != before


class Supervisor:
    def __init__(self):
        self.health = {t["name"]: Health() for t in TUNNELS}
        self.underlay = {}
        self.recovery = {}
        self.next_recovery = {}
        self.attempts = {}
        self.last_underlay = -float("inf")
        self.last_services = -float("inf")
        self.last_heartbeat = -float("inf")
        self.messages = {}
        self.service_task = None
        self.control_lock = asyncio.Lock()
        self.control_blocked = False
        self.stop = asyncio.Event()

    def notice(self, key, message, level=logging.INFO):
        if self.messages.get(key) != message:
            self.messages[key] = message
            LOG.log(level, message)

    async def interface_exists(self, dev):
        rc, _, err = await command("ip", "link", "show", "dev", dev)
        if rc == 0:
            return True
        if rc == 1 and ("does not exist" in err or "Cannot find device" in err):
            return False
        raise RuntimeError("contrôle interface %s impossible (code %s) : %s" % (dev, rc, err.strip()))

    async def ping(self, dev, target):
        if not await self.interface_exists(dev):
            return False
        # Conserver les options et le délai du script Bash validé sur cette machine.
        rc, out, err = await command("ping", "-I", dev, "-c", "1", "-W", "2", target, timeout=3.0)
        detail = (err.strip() or out.strip())[:800]
        if rc not in (0, 1) or any(word in detail.lower() for word in
                                  ("usage:", "invalid option", "unrecognized option", "illegal option")):
            # Un problème d'exécution n'est pas une preuve de panne du tunnel.
            # L'exception interrompt le cycle avant toute modification des defaults.
            raise RuntimeError("test ping indéterminé via %s vers %s (code %s) : %s" % (dev, target, rc, detail))
        key = "ping-" + dev + "-" + target
        if rc == 1:
            self.notice(key, "Ping sans réponse via %s vers %s : %s" % (dev, target, detail), logging.WARNING)
        else:
            self.messages.pop(key, None)
        return rc == 0

    async def ipsec_ok(self, t):
        rc, out, _ = await command("ipsec", "status", t["name"])
        return rc == 0 and sa_installed(out, t)

    async def send_l2tp(self, message):
        # Le lecteur xl2tpd peut traiter un read entier comme une seule commande.
        # Des écritures atomiques ne garantissent pas deux lectures distinctes.
        async with self.control_lock:
            if self.control_blocked:
                raise RuntimeError("contrôle xl2tpd bloqué après une commande non consommée")
            fd = fifo_write(message, keep_open=True)
            try:
                deadline = time.monotonic() + COMMAND_TIMEOUT
                while True:
                    pending = array.array("i", [0])
                    fcntl.ioctl(fd, termios.FIONREAD, pending, True)
                    if pending[0] == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("xl2tpd n'a pas consommé sa commande ; envois suivants bloqués")
                    await asyncio.sleep(0.05)
            except BaseException:
                self.control_blocked = True
                raise
            finally:
                os.close(fd)

    def old_route(self, r, t, paths):
        if protocol(r) not in ("3", "boot"):
            return False
        pairs = sorted((p.get("gateway") or "", p["dev"]) for p in paths)
        key = (r.get("gateway") or "", r.get("dev"))
        if key not in pairs:
            return False
        base = t["underlay_base"] + pairs.index(key)
        return int(r.get("metric", 0)) in (base, base + UNDERLAY_PENALTY)

    def scoped(self, r, t, paths):
        return (destination(r) == t["peer"] + "/32" and
                (protocol(r) == str(ROUTE_PROTOCOL) or self.old_route(r, t, paths)))

    def check_public_conflicts(self, routes, paths):
        for t in TUNNELS:
            for r in routes:
                if destination(r) == t["peer"] + "/32" and not self.scoped(r, t, paths):
                    raise RuntimeError("/32 préexistante non gérée vers " + t["peer"] + ": " + str(r))

    async def reconcile(self, current, desired):
        """Ajouter la nouvelle métrique AVANT suppression exacte de l'ancienne."""
        wanted = {route_key(r) for r in desired}
        for r in desired:
            if any(route_key(old) == route_key(r) and protocol(old) == str(ROUTE_PROTOCOL)
                   and old.get("flags", []) == r.get("flags", []) for old in current):
                continue
            rc, _, err = await command("ip", "-4", "route", "replace", *route_args(r), "proto", str(ROUTE_PROTOCOL))
            if rc:
                raise RuntimeError("ajout route échoué : " + err.strip())
            LOG.info("Route assurée : %s", " ".join(route_args(r)))
        # replace peut déjà avoir remplacé une entrée de même destination/métrique.
        for old in current:
            if route_key(old) in wanted:
                continue
            if any(destination(old) == destination(new) and old.get("metric", 0) == new.get("metric", 0)
                   for new in desired):
                continue
            rc, _, err = await command("ip", "-4", "route", "del", *route_args(old),
                                       "proto", protocol(old) or "boot")
            if rc and "No such process" not in err and "Cannot find device" not in err:
                raise RuntimeError("suppression route échouée : " + err.strip())
            LOG.info("Route retirée : %s", " ".join(route_args(old)))

    async def public_routes(self, routes, paths):
        self.check_public_conflicts(routes, paths)
        for t in TUNNELS:
            desired = []
            for i, p in enumerate(paths):
                key = (t["peer"], p.get("gateway"), p["dev"])
                if key not in self.underlay:
                    penalized = any(self.scoped(r, t, paths) and r.get("gateway") == p.get("gateway")
                                    and r.get("dev") == p["dev"] and r.get("metric", 0) >= UNDERLAY_PENALTY
                                    for r in routes)
                    self.underlay[key] = Health(up=not penalized, known=True)
                h = self.underlay[key]
                penalty = UNDERLAY_PENALTY if (UNDERLAY_HEALTH_ENABLED and not h.up and
                                               UNDERLAY_FAILURE_ACTION == "penalize") else 0
                desired.append(dict(dst=t["peer"] + "/32", gateway=p.get("gateway"), dev=p["dev"],
                                    metric=t["underlay_base"] + i + penalty,
                                    flags=["onlink"] if "onlink" in p.get("flags", []) else []))
            if not desired:
                # Ne jamais laisser une IP publique VPN retomber dans une default PPP.
                desired = [dict(dst=t["peer"] + "/32", type="unreachable", metric=32000)]
            await self.reconcile([r for r in routes if self.scoped(r, t, paths)], desired)

    async def defaults(self, routes):
        # Ajouter les defaults des tunnels sains avant de retirer celles des KO.
        ordered = sorted(TUNNELS, key=lambda t: not self.health[t["name"]].up)
        for t in ordered:
            if not t["manage_default"]:
                continue
            if not self.health[t["name"]].known:
                # Au démarrage, préserver une route existante pendant l'apprentissage.
                continue
            current = [r for r in routes if destination(r) == "default" and r.get("dev") == t["iface"]]
            desired = ([dict(dst="default", dev=t["iface"], metric=t["metric"])]
                       if self.health[t["name"]].up else [])
            try:
                await self.reconcile(current, desired)
            except RuntimeError as exc:
                # Une route qui ne peut pas être ajoutée ne doit pas empêcher
                # de retirer celle d'un autre tunnel déclaré en panne.
                self.notice("default-" + t["name"], str(exc), logging.ERROR)
            else:
                self.messages.pop("default-" + t["name"], None)

    async def probe_tunnel(self, t, context_ok):
        ping_ok, sa_ok = await asyncio.gather(self.ping(t["iface"], t["target"]),
                                             self.ipsec_ok(t) if context_ok else self.false())
        h = self.health[t["name"]]
        if h.feed(ping_ok and sa_ok):
            LOG.log(logging.INFO if h.up else logging.WARNING,
                    "%s : %s (PPP=%s, IPsec=%s)", t["name"], "UP" if h.up else "DOWN", ping_ok, sa_ok)
        if h.up and ping_ok and sa_ok:
            self.attempts[t["name"]] = 0
        return sa_ok

    @staticmethod
    async def false():
        return False

    async def probe_path(self, t, p):
        key = (t["peer"], p.get("gateway"), p["dev"])
        # Confirmer le next-hop réellement choisi avec cette interface.
        try:
            got = await ip_json("route", "get", t["peer"], "oif", p["dev"])
        except RuntimeError:
            if self.underlay[key].feed(False, UNDERLAY_FAILED_PROBES, UNDERLAY_SUCCESSFUL_PROBES):
                LOG.warning("Underlay %s : DOWN (route inutilisable)", key)
            return
        if not got or got[0].get("dev") != p["dev"] or got[0].get("gateway") != p.get("gateway"):
            self.notice(str(key), "Test underlay indéterminé (routage différent) : " + str(key), logging.WARNING)
            return
        h = self.underlay[key]
        if h.feed(await self.ping(p["dev"], t["peer"]), UNDERLAY_FAILED_PROBES, UNDERLAY_SUCCESSFUL_PROBES):
            LOG.warning("Underlay %s : %s", key, "UP" if h.up else "DOWN")

    async def reconnect(self, t, sa_ok):
        name = t["name"]
        try:
            if self.control_blocked:
                raise RuntimeError("contrôle xl2tpd bloqué ; aucune nouvelle relance")
            errors = daemon_context()
            if errors:
                raise RuntimeError(" ; ".join(errors))
            self.attempts[name] = self.attempts.get(name, 0) + 1
            LOG.warning("%s : reconnexion, tentative %s", name, self.attempts[name])
            if FULL_IPSEC_AFTER and sa_ok and self.attempts[name] >= FULL_IPSEC_AFTER:
                rc, _, _ = await command("ipsec", "down", name, timeout=8)
                if rc:
                    raise RuntimeError("ipsec down a échoué")
                sa_ok = False
                self.attempts[name] = 0
            if not sa_ok:
                rc, _, _ = await command("ipsec", "up", name, timeout=IPSEC_UP_TIMEOUT)
                if rc:
                    LOG.warning("%s : ipsec up code %s ; contrôle de la SA", name, rc)
                # Le retour d'ipsec up seul ne suffit pas ; la SA doit être installée.
                for _ in range(3):
                    if await self.ipsec_ok(t):
                        sa_ok = True
                        break
                    await asyncio.sleep(1)
            if not sa_ok:
                raise RuntimeError("pas de SA IPsec installée ; connexion L2TP différée")
            if daemon_context():
                raise RuntimeError("contexte des démons modifié pendant la reconnexion")
            await self.send_l2tp("d " + t["session"])
            deadline = time.monotonic() + L2TP_DISCONNECT_TIMEOUT
            while await self.interface_exists(t["iface"]):
                if time.monotonic() >= deadline:
                    raise RuntimeError("ancienne interface PPP toujours présente ; appel L2TP différé")
                await asyncio.sleep(0.5)
            await asyncio.sleep(0.5)
            await self.send_l2tp("c " + t["session"])
            LOG.info("%s : reconnexion demandée à xl2tpd", name)
        except (OSError, RuntimeError) as exc:
            LOG.error("%s : %s", name, exc)
        finally:
            self.next_recovery[name] = time.monotonic() + RECONNECT_COOLDOWN

    async def start_services(self):
        # Ne redémarre jamais un service actif : une panne VPN reste ciblée.
        for unit in SERVICE_UNITS:
            rc, out, _ = await command("systemctl", "show", unit, "--property=ActiveState", "--value")
            if rc == 0 and out.strip() in ("inactive", "failed"):
                LOG.warning("Démarrage de %s", unit)
                rc, _, _ = await command("systemctl", "start", unit, timeout=20)
                if rc:
                    LOG.error("Démarrage de %s échoué (code %s)", unit, rc)

    async def cycle(self):
        routes = await ip_json("route", "show", "table", "main")
        paths = discover(routes)
        check_default_priority(routes)
        public_ready = True
        try:
            await self.public_routes(routes, paths)
        except RuntimeError as exc:
            public_ready = False
            self.notice("public-routes", str(exc), logging.ERROR)
        else:
            self.messages.pop("public-routes", None)
        now = time.monotonic()
        if START_STOPPED_SERVICES and now - self.last_services >= SERVICE_CHECK_EVERY:
            if self.service_task is None or self.service_task.done():
                self.last_services = now
                self.service_task = asyncio.create_task(self.start_services())
        errors = daemon_context()
        self.notice("context", "Démons : " + (" ; ".join(errors) if errors else "contexte OK"),
                    logging.ERROR if errors else logging.INFO)
        results = await asyncio.gather(*(self.probe_tunnel(t, not errors) for t in TUNNELS))
        await self.defaults(routes)
        # Les récupérations longues sont des tâches indépendantes de la boucle.
        for t, sa_ok in zip(TUNNELS, results):
            name = t["name"]
            task = self.recovery.get(name)
            if (paths and public_ready and not errors and self.health[name].bad >= FAILED_PROBES
                    and (task is None or task.done())
                    and time.monotonic() >= self.next_recovery.get(name, 0)):
                self.recovery[name] = asyncio.create_task(self.reconnect(t, sa_ok))
        if UNDERLAY_HEALTH_ENABLED and now - self.last_underlay >= UNDERLAY_CHECK_EVERY:
            self.last_underlay = now
            results = await asyncio.gather(*(self.probe_path(t, p) for t in TUNNELS for p in paths),
                                           return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    self.notice("probe-error", "Test underlay : " + str(result), logging.WARNING)
            # Relecture : ne pas travailler avec l'état d'avant la réconciliation.
            await self.public_routes(await ip_json("route", "show", "table", "main"), paths)
        if now - self.last_heartbeat >= HEARTBEAT_EVERY:
            self.last_heartbeat = now
            LOG.info("État : %s ; accès détectés=%s", ", ".join(
                "%s=%s" % (n, ("UP" if h.up else "DOWN") if h.known else "INIT")
                for n, h in self.health.items()), len(paths))

    async def run(self):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop.set)
        try:
            while not self.stop.is_set():
                start = time.monotonic()
                try:
                    await self.cycle()
                    self.messages.pop("cycle-error", None)
                except (OSError, ValueError, RuntimeError) as exc:
                    self.notice("cycle-error", "Cycle interrompu : " + str(exc), logging.ERROR)
                try:
                    await asyncio.wait_for(self.stop.wait(), max(0.1, CHECK_INTERVAL - (time.monotonic() - start)))
                except asyncio.TimeoutError:
                    pass
        finally:
            tasks = list(self.recovery.values()) + ([self.service_task] if self.service_task else [])
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            LOG.info("Supervision arrêtée ; routes conservées")


def prerequisites():
    if os.geteuid() != 0:
        raise RuntimeError("exécuter en root")
    for binary in ("ip", "ipsec", "ping") + (("systemctl",) if START_STOPPED_SERVICES else ()):
        if not shutil.which(binary):
            raise RuntimeError("commande manquante : " + binary)
    if EXPECTED_NETNS:
        if os.stat("/run/netns/" + EXPECTED_NETNS).st_ino != os.stat("/proc/self/ns/net").st_ino:
            raise RuntimeError("lancer dans le namespace " + EXPECTED_NETNS)
    if UNDERLAY_FAILURE_ACTION not in ("none", "penalize"):
        raise RuntimeError("UNDERLAY_FAILURE_ACTION invalide")
    for key in ("name", "iface", "peer"):
        if len({t[key] for t in TUNNELS}) != len(TUNNELS):
            raise RuntimeError("paramètre dupliqué : " + key)
    for t in TUNNELS:
        ipaddress.IPv4Address(t["peer"])
        ipaddress.IPv4Address(t["target"])
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", t["session"]):
            raise RuntimeError("nom de session L2TP invalide")


async def preflight(supervisor, diagnostic, require_up=False):
    routes = await ip_json("route", "show", "table", "main")
    paths = discover(routes)
    check_default_priority(routes)
    supervisor.check_public_conflicts(routes, paths)
    if not paths:
        raise RuntimeError("aucune default underlay utilisable ; configurer le réseau avant lancement")
    LOG.info("Accès détectés : %s", [(p.get("gateway"), p["dev"], p.get("metric", 0)) for p in paths])
    LOG.info("Commande ping : %s", shutil.which("ping"))
    errors = daemon_context()
    try:
        if not stat.S_ISFIFO(os.stat(CONTROL_FIFO).st_mode):
            errors.append("contrôle xl2tpd : pas un FIFO")
    except OSError:
        errors.append("contrôle xl2tpd absent : " + CONTROL_FIFO)
    if diagnostic:
        probe_failures = []
        for t in TUNNELS:
            ping_ok, sa_ok = await asyncio.gather(supervisor.ping(t["iface"], t["target"]),
                                                 supervisor.ipsec_ok(t) if not errors else supervisor.false())
            sa_status = sa_ok if not errors else "non vérifiée (contexte des démons invalide)"
            LOG.info("%s : ping PPP=%s ; SA IPsec=%s", t["name"], ping_ok, sa_status)
            if require_up and (errors or not ping_ok or not sa_ok):
                probe_failures.append(t["name"] + " : tunnel non validé opérationnel")
        rules = await ip_json("rule", "show")
        if any(r.get("priority") not in (0, 32766, 32767) for r in rules):
            LOG.warning("ip rules personnalisées présentes : vérifier leur priorité sur la table main")
        errors.extend(probe_failures)
    if errors:
        if diagnostic:
            raise RuntimeError(" ; ".join(errors))
        LOG.warning("%s ; attente des démons dans la boucle", " ; ".join(errors))


async def main_async(args):
    prerequisites()
    supervisor = Supervisor()
    # Un verrou par namespace, sans suppression du fichier (évite les races).
    lock = None
    if args.run:
        path = "/run/auto-reconnect-vpn-%s.lock" % os.stat("/proc/self/ns/net").st_ino
        lock = open(path, "a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("une instance de cette version tourne déjà dans ce namespace")
    try:
        await preflight(supervisor, args.check, args.require_up)
        if args.check:
            LOG.info("Prérequis vérifiés, aucune route ni connexion modifiée")
            return
        await supervisor.run()
    finally:
        if lock:
            lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="/etc/auto-reconnect-vpn.json", help="configuration JSON de cette machine")
    parser.add_argument("--require-up", action="store_true", help="avec --check, exiger tous les tunnels UP")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="diagnostic sans modification")
    mode.add_argument("--run", action="store_true", help="activer la supervision et les modifications réseau")
    mode.add_argument("--validate-config", action="store_true", help="valider le JSON uniquement, hors ligne")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.require_up and not args.check:
            parser.error("--require-up nécessite --check")
        cfg = load_config(args.config)
        LOG.info("Configuration : %s ; namespace attendu=%s", args.config, EXPECTED_NETNS or "courant (PID vérifiés)")
        for t in cfg["tunnels"]:
            LOG.info("%s : interface=%s, serveur=%s, cible=%s, default gérée=%s, metric /32=%s",
                     t["name"], t["iface"], t["peer"], t["target"], t["manage_default"], t["underlay_base"])
        if args.validate_config:
            LOG.info("Configuration valide ; aucune commande réseau exécutée")
            return 0
        asyncio.run(main_async(args))
    except (OSError, ValueError, RuntimeError) as exc:
        LOG.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
