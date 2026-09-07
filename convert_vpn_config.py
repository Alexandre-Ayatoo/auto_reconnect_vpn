#!/usr/bin/env python3
"""Extraire des paramètres littéraux du script Bash historique, SANS l'exécuter.

Exemple :
  python3 convert_vpn_config.py /usr/local/bin/auto_reconnect_vpn.sh \
    --netns netns1 --output /etc/auto-reconnect-vpn.json

Utiliser --current-namespace lorsque l'unité existante choisit déjà le contexte
ou que les démons fonctionnent dans le namespace courant. Aucun contexte n'est
déduit du prompt d'un terminal ou du nom de la machine.

Seules les affectations littérales connues avant la première fonction sont lues.
Les expressions, substitutions, variables et tableaux multilignes sont refusés.
La sortie existante n'est jamais écrasée sans --force.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import shlex
import sys

from vpn_supervisor import validate_config


SCALARS = {
    "CHECK_INTERVAL", "MAX_FAILED_PINGS", "COOLDOWN", "UNDERLAY_HEALTH_CHECK_ENABLED",
    "UNDERLAY_MAX_FAILED_PINGS", "UNDERLAY_FAILURE_ACTION", "UNDERLAY_PENALTY_METRIC",
    "PING_TARGET_1", "PING_TARGET_2", "IPSEC_PEER", "IPSEC_PEER_2",
    "IPSEC_VPN_NAME", "IPSEC_VPN_NAME_2", "L2TP_SESSION_1", "L2TP_SESSION_2",
    "PPP_INTERFACE", "PPP_INTERFACE_2", "VPN_UNDERLAY_1", "VPN_UNDERLAY_2",
    "VPN_UNDERLAY_1_METRIC_BASE", "VPN_UNDERLAY_2_METRIC_BASE",
    "ENABLE_TUN1_DEFAULT_ROUTE", "ENABLE_TUN2_DEFAULT_ROUTE",
    "TUN1_DEFAULT_METRIC", "TUN2_DEFAULT_METRIC", "L2TP_CONTROL_PATH",
}
ARRAYS = {"UNDERLAY_EXCLUDE_GWS", "UNDERLAY_EXCLUDE_DEVS", "UNDERLAY_EXCLUDE_GWDEV"}


def assignments(source):
    result = {}
    # Compatible avec un fichier .sh et avec un transcript contenant `cat ...`.
    for line in source.splitlines():
        if re.match(r"^\s*(?:function\s+)?\w+\s*\(\s*\)\s*\{", line):
            break
        match = re.match(r"^\s*([A-Z][A-Z0-9_]*)=(.*)$", line)
        if not match:
            continue
        key, raw = match.groups()
        if key not in SCALARS | ARRAYS:
            continue
        if key in result:
            raise ValueError("affectation répétée, à vérifier manuellement : " + key)
        if key in ARRAYS:
            # La parenthèse fermante doit être suivie uniquement d'un commentaire.
            array = re.fullmatch(r"\((.*)\)\s*(?:#.*)?", raw)
            if not array:
                raise ValueError("tableau non littéral ou multiligne : " + key)
            raw = array.group(1)
        tokens = shlex.split(raw, comments=True, posix=True)
        if key in SCALARS and len(tokens) != 1:
            raise ValueError("valeur scalaire non littérale : " + key)
        if any(any(c in token for c in ("$", "`", "\n", ";", "|", "&", "<", ">")) for token in tokens):
            raise ValueError("expression shell refusée pour " + key)
        result[key] = tokens if key in ARRAYS else tokens[0]
    return result


def yes_no(value, key):
    if value not in ("yes", "no"):
        raise ValueError(key + " doit valoir yes ou no")
    return value == "yes"


def host_ip(value):
    iface = ipaddress.IPv4Interface(value)
    if iface.network.prefixlen != 32:
        raise ValueError("adresse d'hôte /32 attendue : " + value)
    return str(iface.ip)


def convert(source, netns):
    old = assignments(source)
    cfg = {"schema_version": 1, "expected_netns": netns, "tunnels": [],
           "full_ipsec_after": 0, "start_stopped_services": False}
    notes = []
    mapping = {
        "CHECK_INTERVAL": ("check_interval", float),
        "MAX_FAILED_PINGS": ("failed_probes", int),
        "COOLDOWN": ("reconnect_cooldown", float),
        "UNDERLAY_MAX_FAILED_PINGS": ("underlay_failed_probes", int),
        "UNDERLAY_PENALTY_METRIC": ("underlay_penalty", int),
        "L2TP_CONTROL_PATH": ("control_fifo", str),
    }
    for key, (new, parser) in mapping.items():
        if key in old:
            cfg[new] = parser(old[key])
    # Préserver les cinq secondes du script historique si la variable manque.
    cfg.setdefault("check_interval", 5.0)
    key = "UNDERLAY_HEALTH_CHECK_ENABLED"
    cfg["underlay_health_enabled"] = yes_no(old.get(key, "no"), key)
    action = old.get("UNDERLAY_FAILURE_ACTION", "none")
    if action == "delete":
        action = "none"
        notes.append("UNDERLAY_FAILURE_ACTION=delete converti en none : la nouvelle version ne supprime pas les /32 sur échec ICMP.")
    elif "UNDERLAY_FAILURE_ACTION" not in old and cfg["underlay_health_enabled"]:
        notes.append("Ancienne suppression sur échec ICMP non reprise : underlay_failure_action=none.")
    cfg["underlay_failure_action"] = action
    for old_key, new_key in (("UNDERLAY_EXCLUDE_GWS", "exclude_gws"),
                             ("UNDERLAY_EXCLUDE_DEVS", "exclude_devs"),
                             ("UNDERLAY_EXCLUDE_GWDEV", "exclude_gwdev")):
        if old_key in old:
            cfg[new_key] = ([pair.split("@", 1) for pair in old[old_key]]
                            if new_key == "exclude_gwdev" else old[old_key])
    for n in (1, 2):
        suffix = "" if n == 1 else "_2"
        names = {
            "name": "IPSEC_VPN_NAME" + suffix,
            "session": "L2TP_SESSION_" + str(n),
            "iface": "PPP_INTERFACE" + suffix,
            "peer": "IPSEC_PEER" + suffix,
            "target": "PING_TARGET_" + str(n),
            "underlay_base": "VPN_UNDERLAY_%s_METRIC_BASE" % n,
            "manage_default": "ENABLE_TUN%s_DEFAULT_ROUTE" % n,
            "metric": "TUN%s_DEFAULT_METRIC" % n,
        }
        missing = [key for key in names.values() if key not in old]
        if missing:
            raise ValueError("paramètres requis absents : " + ", ".join(missing))
        t = {key: old[value] for key, value in names.items()}
        t["peer"] = host_ip(t["peer"])
        t["target"] = host_ip(t["target"])
        underlay_key = "VPN_UNDERLAY_" + str(n)
        if underlay_key not in old or host_ip(old[underlay_key]) != t["peer"]:
            raise ValueError(underlay_key + " doit correspondre au peer public ; vérifier ce cas manuellement")
        t["underlay_base"] = int(t["underlay_base"])
        t["metric"] = int(t["metric"]) if t["metric"] else 0
        t["manage_default"] = yes_no(t["manage_default"], names["manage_default"])
        cfg["tunnels"].append(t)
    # Validation complète, mais sortie lisible : omettre les options communes inchangées.
    validate_config(cfg)
    notes.append("Namespace choisi explicitement : " + (netns or "courant ; contrôle des PID maintenu"))
    notes.append("PIDFILES : chemins candidats usuels, vérifiés par --check avant bascule.")
    notes.append("full_ipsec_after=0 préserve l'absence de down/up IPsec forcé du Bash.")
    notes.append("Les /32 sont désormais réconciliées à chaque cycle, uniquement si nécessaire.")
    return cfg, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", help="ancien .sh ou transcript de sa lecture")
    namespace = parser.add_mutually_exclusive_group(required=True)
    namespace.add_argument("--netns", help="nom du namespace utilisé par l'unité existante")
    namespace.add_argument("--current-namespace", action="store_true", help="conserver le contexte d'exécution fourni par l'appelant")
    parser.add_argument("--output", help="fichier JSON ; sinon sortie standard")
    parser.add_argument("--force", action="store_true", help="autoriser l'écrasement du fichier de sortie")
    args = parser.parse_args()
    try:
        cfg, notes = convert(Path(args.source).read_text(), args.netns or "")
        payload = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            with open(args.output, "w" if args.force else "x") as stream:
                stream.write(payload)
        else:
            sys.stdout.write(payload)
        for note in notes:
            print("INFO : " + note, file=sys.stderr)
    except (OSError, ValueError) as exc:
        print("ERREUR : " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
