#!/usr/bin/env python3
# Sonda macOS agentless per gp-monitor. Emette lo STESSO schema JSON della sonda Linux
# (monitor-probe.py); i campi non applicabili su macOS -> null/vuoti.
# Solo stdlib. Read-only. Va installata a comando forzato in ~/.ssh/authorized_keys.
import json, subprocess, time, re, socket

PROBE_VERSION = 2

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""

def hostname():
    return (run(["scutil", "--get", "ComputerName"]).strip() or socket.gethostname())

def ncpu():
    try:
        return int(run(["sysctl", "-n", "hw.ncpu"]).strip())
    except Exception:
        return None

def ram():
    try:
        total = int(run(["sysctl", "-n", "hw.memsize"]).strip())
    except Exception:
        total = 0
    vs = run(["vm_stat"])
    pgsize = 4096
    m = re.search(r"page size of (\d+)", vs)
    if m:
        pgsize = int(m.group(1))
    def pages(key):
        mm = re.search(rf"{re.escape(key)}:\s+(\d+)", vs)
        return int(mm.group(1)) if mm else 0
    # memoria "disponibile" ~ free + inactive + speculative (riutilizzabile)
    avail = (pages("Pages free") + pages("Pages inactive") + pages("Pages speculative")) * pgsize
    avail = min(avail, total) if total else avail
    used = max(0, total - avail)
    # swap: "total = 2048.00M  used = 12.00M  free = ..."
    su = run(["sysctl", "-n", "vm.swapusage"])
    def sz(k):
        mm = re.search(rf"{k}\s*=\s*([\d.]+)([KMGT]?)", su)
        if not mm:
            return 0
        v = float(mm.group(1))
        return int(v * {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}.get(mm.group(2), 1))
    return {"total": total, "available": avail, "used": used,
            "swap_total": sz("total"), "swap_used": sz("used")}

def disk():
    # volumi APFS di sistema (firmlink) da nascondere: sono overhead a 0-1%, non dati reali
    SKIP = ("/System/Volumes/VM", "/System/Volumes/Preboot", "/System/Volumes/Update",
            "/System/Volumes/xarts", "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware",
            "/System/Volumes/Recovery")
    out = run(["df", "-k"]).splitlines()
    res, seen = [], set()
    for ln in out[1:]:
        f = ln.split()
        if len(f) < 9 or not f[0].startswith("/dev/"):
            continue
        mount = f[-1]
        if mount in seen or mount in SKIP:
            continue
        try:
            size = int(f[1]) * 1024
            used = int(f[2]) * 1024
            avail = int(f[3]) * 1024
        except Exception:
            continue
        seen.add(mount)
        pct = round(used / (used + avail) * 100, 1) if (used + avail) else 0
        res.append({"target": mount, "fstype": "apfs", "size": size,
                    "used": used, "avail": avail, "use_pct": pct})
    # su APFS "/" è il volume sealed (0%); ordino per utilizzo desc così il dato
    # principale (es. /System/Volumes/Data) e' il primo/piu' significativo
    res.sort(key=lambda d: d["use_pct"], reverse=True)
    return res[:8]

def net():
    lines = run(["netstat", "-ib"]).splitlines()
    if not lines:
        return []
    hdr = lines[0].split()
    idx = {n: i for i, n in enumerate(hdr)}
    need = ("Ibytes", "Obytes", "Ipkts", "Opkts")
    res, seen = [], set()
    for ln in lines[1:]:
        f = ln.split()
        iface = f[0] if f else ""
        if not iface or iface in seen or iface == "lo0":
            continue
        try:
            if all(n in idx for n in need) and len(f) > max(idx[n] for n in need):
                rx_bytes = int(f[idx["Ibytes"]]); tx_bytes = int(f[idx["Obytes"]])
                rx_pkts = int(f[idx["Ipkts"]]); tx_pkts = int(f[idx["Opkts"]])
            else:
                continue
        except Exception:
            continue
        seen.add(iface)
        res.append({"iface": iface, "rx_bytes": rx_bytes, "rx_pkts": rx_pkts,
                    "tx_bytes": tx_bytes, "tx_pkts": tx_pkts})
    return res

def conns():
    out = run(["netstat", "-an", "-p", "tcp"])
    estab = total = 0
    for ln in out.splitlines():
        if ln.startswith("tcp"):
            total += 1
            if ln.rstrip().endswith("ESTABLISHED"):
                estab += 1
    return {"total": total, "estab": estab}

def listening():
    out = run(["netstat", "-an", "-p", "tcp"])
    res = []
    for ln in out.splitlines():
        if "LISTEN" not in ln:
            continue
        f = ln.split()
        if len(f) < 4:
            continue
        m = re.match(r"(.*)\.(\d+)$", f[3])
        if m:
            res.append({"proto": "tcp", "addr": m.group(1), "port": int(m.group(2))})
    return res[:60]

def docker():
    if not run(["which", "docker"]).strip():
        return [], None
    ps = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.State}}\t{{.Status}}"])
    conts = []
    for ln in ps.splitlines():
        p = ln.split("\t")
        if len(p) < 2:
            continue
        conts.append({"name": p[0], "state": p[1], "health": "",
                      "cpu_pct": None, "mem_usage": None, "mem_pct": None,
                      "net_io": None, "blk_io": None, "pids": None})
    imgs = len([x for x in run(["docker", "images", "-q"]).splitlines() if x.strip()]) or None
    return conts, imgs

def security():
    return {"fw_dropped_pkts": 0, "ssh_failed_1h": None, "ssh_invalid_1h": None,
            "f2b_banned": None, "f2b_total_failed": None, "listening": listening()}

def main():
    conts, imgs = docker()
    doc = {
        "v": PROBE_VERSION, "os": "darwin",
        "host": hostname(), "ts": int(time.time()), "cpus": ncpu(),
        "ram": ram(), "disk": disk(), "net": net(), "conns": conns(),
        "flows": {"in": [], "out": [], "in_peers": 0, "out_peers": 0},
        "docker": conts, "docker_images": imgs, "security": security(),
    }
    print(json.dumps(doc, separators=(",", ":")))

if __name__ == "__main__":
    main()
