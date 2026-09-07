# Supervision L2TP/IPsec sur plusieurs machines

Le programme commun est `vpn_supervisor.py`. Les noms de tunnels, interfaces,
peers, règles de gestion des defaults et paramètres de contrôle sont dans un
fichier JSON propre à chaque machine. Python 3.9+ et la bibliothèque standard
suffisent ; les outils système `ip`, `ipsec` et `ping` restent nécessaires.

Ce paquet n'écrase pas l'ancien `auto_reconnect_vpn.py` : le nouveau nom permet
de préparer et vérifier la migration avant de changer le service. Aucun
installateur ne modifie automatiquement les routes ou les unités systemd.

## Les deux profils fournis

| Paramètre | `localhost-netns1.json` | `rt-bsm-1.json` |
|---|---|---|
| Interface tunnel 1 | `ppp001001` | `ppp255001` |
| Interface tunnel 2 | `ppp001002` | `ppp255002` |
| Gestion des defaults PPP | activée, métriques 0 et 2 | désactivée pour les deux |
| Métriques de base des /32 publiques | 100 et 200 | 2 et 2 |
| Contrôle ICMP des IP publiques | activé, aucune pénalisation | désactivé |
| Cadence cible | 2 secondes | 5 secondes, reprise du Bash |
| Namespace attendu | `netns1` | contexte d'exécution courant, à vérifier |
| Relance IPsec forcée après plusieurs échecs L2TP | troisième tentative | désactivée, comme dans le Bash |

Le profil `rt-bsm-1.json` reprend les affectations réelles du script joint.
Les commentaires qui mentionnent `ppp254001` ne sont pas les valeurs utilisées :
le script configure bien `ppp255001` et `ppp255002`.

Le prompt `(default)` lors d'un `cat` ne prouve pas le namespace dans lequel
le service s'exécute. Dans le profil rt-bsm-1, `expected_netns: ""` ne change
pas de namespace et n'en impose pas le nom. Le contrôle exige toujours que les
PID de charon et xl2tpd appartiennent au namespace du superviseur. Examiner
`systemctl cat auto_reconnect_vpn.service` et conserver son mode d'exécution.

## Convertir les autres scripts sans les exécuter

Décompresser le paquet puis se placer dans son répertoire :

```bash
cd vpn-multimachine
```

Pour une unité existante utilisant `netns1` :

```bash
python3 convert_vpn_config.py /usr/local/bin/auto_reconnect_vpn.sh \
  --netns netns1 --output /tmp/auto-reconnect-vpn.json
```

Pour une unité exécutée directement dans le contexte voulu, ou dont le
namespace est déjà fixé par un autre mécanisme systemd :

```bash
python3 convert_vpn_config.py /usr/local/bin/auto_reconnect_vpn.sh \
  --current-namespace --output /tmp/auto-reconnect-vpn.json
```

Le convertisseur reconnaît le format historique à deux tunnels présenté dans
la conversation, y compris un transcript de `cat`. Il ne fait ni `source`, ni
`eval`, ni appel à Bash. Les valeurs calculées, substitutions, doubles
affectations et tableaux multilignes sont refusés : renseigner alors le JSON
manuellement. Il refuse aussi une sortie déjà présente ; choisir un nouveau
chemin ou utiliser `--force` après en avoir vérifié le contenu.

Les indicateurs `ENABLE_TUN*_DEFAULT_ROUTE`, métriques, interfaces, IP, noms de
connexions, sessions, exclusions et temporisations sont repris. Les métriques
vides deviennent 0. La destination underlay doit correspondre au peer public.

Différences signalées à la conversion :

- Le mode de suppression des /32 sur échec ICMP n'est pas repris : conversion
  vers `none`. Un mode `penalize` explicitement configuré est conservé.
- `full_ipsec_after: 0` conserve l'absence de `ipsec down` forcé du Bash.
- Les /32 sont réconciliées à chaque cycle uniquement si nécessaire. L'ancien
  `ROUTE_ENSURE_EVERY` n'est donc pas une option de la nouvelle configuration.
- La reprise d'une default attend deux succès, et les compteurs de panne PPP
  et underlay restent configurables séparément.

## Vérifier avant de basculer

Validation du fichier uniquement, sans privilèges ni accès réseau :

```bash
python3 vpn_supervisor.py --config /tmp/auto-reconnect-vpn.json --validate-config
```

Diagnostic sur la machine cible, en root et dans le contexte réseau de son
service existant. L'ancien superviseur peut continuer pendant ce contrôle.

Exécution directe :

```bash
python3 vpn_supervisor.py --config /tmp/auto-reconnect-vpn.json --check --require-up
```

Exécution dans `netns1` :

```bash
ip netns exec netns1 python3 vpn_supervisor.py \
  --config /tmp/auto-reconnect-vpn.json --check --require-up
```

`--check --require-up` retourne 0 seulement si les prérequis et tous les tests
PPP/IPsec réussissent. Aucun ajout de route, connexion L2TP ou démarrage de
service n'est effectué. Sans `--require-up`, le diagnostic peut réussir même
avec un tunnel déjà en panne : ce mode convient au dépannage, pas à la
validation d'une migration d'un système actuellement fonctionnel.

Si un PIDFILE manque, préciser `charon_pidfiles` ou `xl2tpd_pidfiles` dans le
JSON. Les chemins xl2tpd usuels sont examinés par défaut. Un PID vivant dans
un autre namespace ou plusieurs PID candidats distincts provoquent une erreur
explicite ; le programme ne choisit pas silencieusement une instance.

## Installer après validation

Conserver une copie de tout fichier déjà présent aux chemins de destination.
Pour une première installation, depuis le répertoire extrait :

```bash
install -m 0755 vpn_supervisor.py /usr/local/bin/vpn_supervisor.py
install -m 0600 /tmp/auto-reconnect-vpn.json /etc/auto-reconnect-vpn.json
```

Arrêter une éventuelle instance lancée à la main avec Ctrl+C. Créer ensuite
un drop-in dans le service existant, en choisissant UN des deux exemples du
répertoire `systemd` et en conservant le contexte réseau existant :

```bash
mkdir -p /etc/systemd/system/auto_reconnect_vpn.service.d
```

Par exemple, si le service utilise `ip netns exec netns1` :

```bash
install -m 0644 systemd/netns1.conf.example \
  /etc/systemd/system/auto_reconnect_vpn.service.d/50-vpn-supervisor.conf
```

S'il s'exécute directement dans son contexte réseau, utiliser
`systemd/current-namespace.conf.example` à la place. Pour un autre netns,
adapter le nom dans le drop-in et `expected_netns` dans le JSON.
Ne pas écraser un drop-in de même nom sans le sauvegarder.

```bash
systemctl daemon-reload
systemctl enable auto_reconnect_vpn.service
systemctl restart auto_reconnect_vpn.service
systemctl status auto_reconnect_vpn.service --no-pager -l
journalctl -u auto_reconnect_vpn.service -n 30 -f
```

Le redémarrage de ce service remplace le superviseur, sans redémarrer globalement
strongSwan ou xl2tpd. La santé est initialement `INIT`, puis `UP` après deux
succès. La portée du verrou reste un superviseur par namespace, même avec
plusieurs fichiers JSON. Regrouper les tunnels d'un même namespace dans un seul
fichier. Le verrou est partagé avec la version Python précédente ; il ne peut
pas verrouiller un ancien processus Bash.

## Revenir à l'ancien superviseur

Si `50-vpn-supervisor.conf` a été créé pour cette migration et n'existait pas
auparavant, le retirer rétablit l'ExecStart initial. Sinon restaurer sa sauvegarde.

```bash
systemctl stop auto_reconnect_vpn.service
rm /etc/systemd/system/auto_reconnect_vpn.service.d/50-vpn-supervisor.conf
systemctl daemon-reload
systemctl start auto_reconnect_vpn.service
```

Les anciens programmes n'ont pas été écrasés. Les routes ne sont pas supprimées
à l'arrêt du superviseur. Ce retour ne restaure pas automatiquement d'éventuels
changements de configuration réseau effectués séparément.

## Paramètres utiles dans chaque JSON

| Champ | Effet |
|---|---|
| `expected_netns` | nom exact attendu ; chaîne vide pour le contexte courant |
| `tunnels[].name` | nom exact de la connexion strongSwan |
| `tunnels[].session` | nom de session xl2tpd |
| `tunnels[].iface` | nom final de l'interface PPP, après les hooks éventuels |
| `tunnels[].peer` | IPv4 publique du serveur VPN, sans `/32` |
| `tunnels[].target` | IPv4 à tester dans le tunnel |
| `tunnels[].manage_default` | booléen JSON : `false` interdit toute gestion explicite de sa default |
| `tunnels[].metric` | métrique de default, utilisée uniquement si sa gestion est activée |
| `tunnels[].underlay_base` | base des métriques /32 pour ce serveur |
| `underlay_health_enabled` | activer les pings des IP publiques |
| `underlay_failure_action` | `none` pour journaliser ; `penalize` uniquement si ce test est pertinent |
| `failed_probes` / `successful_probes` | seuils PPP, 3 échecs / 2 succès par défaut |
| `underlay_failed_probes` / `underlay_successful_probes` | seuils indépendants pour les accès publics |
| `check_interval` | cadence cible ; durée des commandes incluse autant que possible |
| `reconnect_cooldown` | attente après la fin d'une tentative, 60 secondes par défaut |
| `full_ipsec_after` | 0 pour désactiver les down/up forcés ; sinon nombre de tentatives infructueuses |
| `control_fifo` | chemin du FIFO de l'instance xl2tpd concernée |
| `charon_pidfiles` / `xl2tpd_pidfiles` | listes de chemins candidats pour identifier les démons |
| `start_stopped_services` | désactivé par défaut ; ne l'activer qu'avec des unités système vérifiées |
| `route_protocol` | identifiant numérique à réserver dans ce namespace, 186 par compatibilité |

La table de routage gérée reste `main` en IPv4. Aucune route par défaut physique
n'est réécrite. Si des defaults PPP sont gérées, les defaults concurrentes
doivent être moins prioritaires. Si toutes sont désactivées, aucune contrainte
de métrique n'est imposée aux defaults physiques.

La reprise des anciennes /32 est volontairement limitée aux routes `boot`
reconnues pour les passerelles et métriques prévues, ainsi qu'aux routes déjà
marquées avec le protocole configuré. Un routage statique différent, multipath,
une ancienne numérotation de métriques différente ou un ensemble de passerelles
modifié peut nécessiter une vérification manuelle avant migration. Les règles
`ip rule`, routes plus spécifiques, NAT, forwarding, pare-feu, DNS et MTU restent
du ressort de la configuration réseau existante. Une reconnexion PPP peut
naturellement faire disparaître les routes liées à cette interface, même quand
`manage_default` est désactivé ; le script n'en ajoute ou n'en retire alors aucune
explicitement.

## Vérification du paquet

```bash
python3 -m unittest discover -s tests -v
```

Les tests couvrent notamment l'adresse passée à ping, les erreurs de commande,
les deux formats JSON iproute2 rencontrés, le FIFO réel avec deux commandes
concurrentes, les bascules de routes simulées, la validation de configuration,
la conversion sans exécution du Bash et l'absence de modification des defaults
pour le profil rt-bsm-1. Ils ne remplacent pas le diagnostic sur chaque hôte.
