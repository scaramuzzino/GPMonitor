#!/usr/bin/env python3
"""
gp-monitor probe — READ-ONLY.
Emette su stdout un unico documento JSON con: RAM, DISCO, RETE (contatori),
connessioni, container Docker, e metriche di sicurezza (firewall/ssh/fail2ban).
Solo stdlib. Pensato per girare come comando forzato in authorized_keys.
"""
import json
import os
import re
import shutil
import subprocess
import time

PROBE_VERSION = 3


def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ""


def have(binname):
    return shutil.which(binname) is not None


def _which_fw(binname):
    # sotto comando forzato SSH il PATH può essere minimale: cerca anche in sbin
    p = shutil.which(binname)
    if p:
        return p
    for d in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
        cand = os.path.join(d, binname)
        if os.path.exists(cand):
            return cand
    return None


def to_pct(s):
    try:
        return float(str(s).strip().rstrip("%"))
    except Exception:
        return None


def to_int(s):
    try:
        return int(str(s).strip())
    except Exception:
        return None


def hostname():
    try:
        with open("/etc/hostname") as f:
            return f.read().strip()
    except Exception:
        return os.uname().nodename


def ncpu():
    """Numero di CPU online (per normalizzare l'uso CPU dei container)."""
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


def ram():
    d = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                parts = v.split()
                if parts:
                    d[k] = int(parts[0]) * 1024  # kB -> byte
    except Exception:
        pass
    total = d.get("MemTotal", 0)
    avail = d.get("MemAvailable", 0)
    swt = d.get("SwapTotal", 0)
    swf = d.get("SwapFree", 0)
    return {
        "total": total,
        "available": avail,
        "used": max(0, total - avail),
        "swap_total": swt,
        "swap_used": max(0, swt - swf),
    }


def disk():
    # findmnt -P: coppie chiave="valore", robusto a campi vuoti; --real esclude pseudo-fs
    out = run(["findmnt", "-Pbno", "TARGET,FSTYPE,SIZE,USED,AVAIL,USE%", "--real"])
    res = []
    for line in out.splitlines():
        # la chiave può contenere '%' (es. USE%) → non usare \w che lo esclude
        kv = dict(re.findall(r'([A-Z%]+)="([^"]*)"', line))
        if not kv.get("TARGET"):
            continue
        size = to_int(kv.get("SIZE")) or 0
        used = to_int(kv.get("USED")) or 0
        avail = to_int(kv.get("AVAIL")) or 0
        # calcolo la percentuale dai byte (più robusto del campo USE% di findmnt)
        pct = to_pct(kv.get("USE%"))
        if pct is None:
            pct = round(used / size * 100, 1) if size else 0
        res.append({
            "target": kv.get("TARGET"),
            "fstype": kv.get("FSTYPE"),
            "size": size,
            "used": used,
            "avail": avail,
            "use_pct": pct,
        })
    return res


def net():
    res = []
    try:
        with open("/proc/net/dev") as f:
            lines = f.read().splitlines()[2:]
        for line in lines:
            iface, _, rest = line.partition(":")
            iface = iface.strip()
            f = rest.split()
            if iface == "lo" or len(f) < 16:
                continue
            # /proc/net/dev: rx bytes,packets,... (0,1); tx bytes,packets a (8,9)
            res.append({
                "iface": iface,
                "rx_bytes": int(f[0]), "rx_pkts": int(f[1]),
                "tx_bytes": int(f[8]), "tx_pkts": int(f[9]),
            })
    except Exception:
        pass
    return res


def conns():
    out = run(["ss", "-tan"])
    total = estab = 0
    for line in out.splitlines()[1:]:
        total += 1
        if "ESTAB" in line:
            estab += 1
    return {"total": total, "estab": estab}


def _listen_ports():
    """Porte TCP in ascolto: servono a distinguere connessioni in ingresso da quelle in uscita."""
    ports = set()
    out = run(["ss", "-tln"])
    for line in out.splitlines():
        f = line.split()
        if len(f) < 4 or f[0] != "LISTEN":
            continue
        _, _, port = f[3].rpartition(":")
        p = to_int(port)
        if p is not None:
            ports.add(p)
    return ports


def flows(cap=40):
    """Aggrega le connessioni TCP ESTABLISHED per (IP remoto, porta di servizio).
    'in' = qualcuno si connette a una nostra porta in ascolto; 'out' = noi verso un servizio remoto.
    Ritorna i primi `cap` peer per numero di connessioni (per il diagramma di flusso)."""
    listen = _listen_ports()
    inbound, outbound = {}, {}
    out = run(["ss", "-tan"])
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] != "ESTAB":
            continue
        lip, _, lport = f[3].rpartition(":")
        pip, _, pport = f[4].rpartition(":")
        pip = pip.strip("[]")
        lport, pport = to_int(lport), to_int(pport)
        if pip in ("127.0.0.1", "::1", "") or lport is None:
            continue
        if lport in listen:                       # connessione in ingresso verso un nostro servizio
            k = (pip, lport)
            inbound[k] = inbound.get(k, 0) + 1
        else:                                     # connessione in uscita verso un servizio remoto
            k = (pip, pport)
            outbound[k] = outbound.get(k, 0) + 1

    def top(d):
        items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:cap]
        return [{"ip": ip, "port": port, "n": n} for (ip, port), n in items]

    return {"in": top(inbound), "out": top(outbound),
            "in_peers": len(inbound), "out_peers": len(outbound)}


def docker_images_count():
    if not have("docker"):
        return None
    ids = [l for l in run(["docker", "images", "-q"]).splitlines() if l.strip()]
    return len(set(ids))


def docker_containers():
    if not have("docker"):
        return None
    states = {}
    ps = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}\t{{.Status}}"])
    for line in ps.splitlines():
        p = line.split("\t")
        if len(p) < 2:
            continue
        health = ""
        status = p[2] if len(p) > 2 else ""
        m = re.search(r"\((healthy|unhealthy|health: starting|starting)\)", status)
        if m:
            health = m.group(1)
        states[p[0]] = {"state": p[1], "health": health}

    live = {}
    stats = run(
        ["docker", "stats", "--no-stream", "--format",
         "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"],
        timeout=20,
    )
    for line in stats.splitlines():
        p = line.split("\t")
        if len(p) < 7:
            continue
        live[p[0]] = {
            "cpu_pct": to_pct(p[1]),
            "mem_usage": p[2],
            "mem_pct": to_pct(p[3]),
            "net_io": p[4],
            "blk_io": p[5],
            "pids": to_int(p[6]),
        }

    res = []
    for name, st in states.items():
        row = {"name": name}
        row.update(st)
        row.update(live.get(name, {
            "cpu_pct": None, "mem_usage": None, "mem_pct": None,
            "net_io": None, "blk_io": None, "pids": None,
        }))
        res.append(row)
    res.sort(key=lambda r: r["name"])
    return res


def security():
    sec = {
        "fw_dropped_pkts": 0,
        "ssh_failed_1h": None,
        "ssh_invalid_1h": None,
        "f2b_banned": None,
        "f2b_total_failed": None,
        "listening": [],
    }

    # Firewall: pacchetti bloccati in INGRESSO. Funziona con iptables "puro",
    # Docker (DOCKER-USER) e ufw (che usa catene proprie ufw-*). Si conta:
    #  - il policy-drop delle catene di ingresso (INPUT/FORWARD): "Chain X (policy DROP N packets"
    #  - ogni regola con target DROP/REJECT in QUALSIASI catena, tranne quelle di uscita (output)
    # iptables è spesso in /usr/sbin: con which non basta il PATH minimale del comando forzato.
    ipt = _which_fw("iptables")
    ip6 = _which_fw("ip6tables")
    if ipt:
        dropped = 0
        found = False
        for tool in filter(None, (ipt, ip6)):
            out = run([tool, "-nvxL"])
            cur_is_egress = False
            for line in out.splitlines():
                if line.startswith("Chain "):
                    name = line.split()[1]
                    cur_is_egress = "output" in name.lower() or name == "OUTPUT"
                    m = re.search(r"policy DROP (\d+) packets", line)
                    if m and name in ("INPUT", "FORWARD"):
                        dropped += int(m.group(1))
                        found = True
                    continue
                f = line.split()
                # riga-regola: pkts bytes target ...  (la col. header inizia con "pkts")
                if len(f) >= 3 and f[0].isdigit() and f[2] in ("DROP", "REJECT") and not cur_is_egress:
                    dropped += int(f[0])
                    found = True
        sec["fw_dropped_pkts"] = dropped if found else None

    # Tentativi SSH nell'ultima ora (journald)
    if have("journalctl"):
        j = run(["journalctl", "-u", "ssh.service", "-u", "sshd.service",
                 "--since", "-1h", "-q", "--no-pager"], timeout=20)
        if j:
            sec["ssh_failed_1h"] = j.count("Failed password")
            sec["ssh_invalid_1h"] = j.count("Invalid user")
        else:
            sec["ssh_failed_1h"] = 0
            sec["ssh_invalid_1h"] = 0

    # fail2ban (jail sshd)
    if have("fail2ban-client"):
        s = run(["fail2ban-client", "status", "sshd"])
        mb = re.search(r"Currently banned:\s*(\d+)", s)
        mf = re.search(r"Total failed:\s*(\d+)", s)
        if mb:
            sec["f2b_banned"] = int(mb.group(1))
        if mf:
            sec["f2b_total_failed"] = int(mf.group(1))

    # Porte in ascolto (superficie d'attacco)
    out = run(["ss", "-tulnH"])
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto = f[0]
        local = f[4]
        addr, _, port = local.rpartition(":")
        sec["listening"].append({"proto": proto, "addr": addr, "port": port})
    return sec


# pacchetti di sicurezza rilevanti: se un servizio con CVE mappa su uno di questi
# e il pacchetto e' gia' all'ultima versione, i CVE di vulners sono verosimilmente
# falsi positivi (backport della distro). Lista curata, allineata alla mappa APT del collector.
_SEC_PKGS = [
    "openssh-server", "openssh-client", "openssl", "libssl3", "libssl1.1",
    "nginx", "nginx-core", "apache2", "apache2-bin", "lighttpd", "haproxy", "squid", "varnish",
    "postfix", "exim4", "dovecot-core", "dovecot-imapd", "dovecot-pop3d", "cyrus-imapd",
    "postgresql", "mariadb-server", "mysql-server", "redis-server", "memcached",
    "mongodb-org-server", "rabbitmq-server",
    "vsftpd", "proftpd-basic", "pure-ftpd", "bind9", "unbound", "dnsmasq", "isc-dhcp-server",
    "openvpn", "strongswan", "chrony", "ntp", "snmpd", "rsync", "samba", "cups", "mosquitto",
    "php", "docker-ce", "containerd.io", "tomcat9", "jetty9",
]


def packages():
    """Su Debian/Ubuntu: versioni installate dei pacchetti di sicurezza rilevanti +
    quali hanno un upgrade pendente. Il collector lo usa per capire se un servizio con
    CVE e' gia' all'ultima versione disponibile (probabile falso positivo da backport)
    o ha davvero un aggiornamento da applicare. None su altri OS / gestori diversi da APT."""
    if not (have("dpkg-query") and have("apt-get")):
        return None
    installed = {}
    out = run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"] + _SEC_PKGS, timeout=15)
    for line in out.splitlines():
        f = line.split()
        if len(f) == 2 and f[1]:
            installed[f[0]] = f[1]
    upgradable = []
    # simulazione (-s): non modifica nulla, non richiede rete se le liste apt sono in cache
    sim = run(["apt-get", "-s", "upgrade"], timeout=25)
    for line in sim.splitlines():
        if line.startswith("Inst "):
            parts = line.split()
            if len(parts) >= 2:
                upgradable.append(parts[1])
    return {"installed": installed, "upgradable": sorted(set(upgradable))}


def main():
    doc = {
        "v": PROBE_VERSION,
        "host": hostname(),
        "ts": int(time.time()),
        "cpus": ncpu(),
        "ram": ram(),
        "disk": disk(),
        "net": net(),
        "conns": conns(),
        "flows": flows(),
        "docker": docker_containers(),
        "docker_images": docker_images_count(),
        "security": security(),
        "packages": packages(),
    }
    print(json.dumps(doc, separators=(",", ":")))


if __name__ == "__main__":
    main()
