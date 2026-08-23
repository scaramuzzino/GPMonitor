#!/usr/bin/env python3
"""Backup coerente del DB SQLite di gp-monitor, con rotazione.

Usa l'API di backup online di SQLite: sicuro anche mentre il collector scrive.
Percorsi e ritenzione configurabili via variabili d'ambiente:

  GPMON_DB          percorso del DB          (default: ./data/metrics.db)
  GPMON_BACKUP_DIR  cartella dei backup      (default: ./backups)
  GPMON_BACKUP_KEEP quanti backup tenere     (default: 15)

Esegue un backup giornaliero gzippato (metrics-YYYYMMDD.db.gz) e cancella i
piu' vecchi oltre GPMON_BACKUP_KEEP. Pensato per cron, es.:

  30 3 * * *  /usr/bin/python3 /path/to/db-backup.py >> /var/log/gpmon-backup.log 2>&1

Autore: Stefano Scaramuzzino
"""
import sqlite3, time, os, glob, gzip, shutil

SRC = os.environ.get("GPMON_DB", "./data/metrics.db")
DST_DIR = os.environ.get("GPMON_BACKUP_DIR", "./backups")
KEEP = int(os.environ.get("GPMON_BACKUP_KEEP", "15"))

os.makedirs(DST_DIR, exist_ok=True)
stamp = time.strftime("%Y%m%d")
raw = os.path.join(DST_DIR, f"metrics-{stamp}.db")

src = sqlite3.connect(SRC)
dst = sqlite3.connect(raw)
try:
    with dst:
        src.backup(dst)
finally:
    dst.close(); src.close()

with open(raw, "rb") as fi, gzip.open(raw + ".gz", "wb", compresslevel=6) as fo:
    shutil.copyfileobj(fi, fo)
os.remove(raw)

files = sorted(glob.glob(os.path.join(DST_DIR, "metrics-*.db.gz")))
for f in files[:-KEEP]:
    os.remove(f)

size = os.path.getsize(raw + ".gz")
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] backup ok: {raw}.gz "
      f"({size/1e6:.2f} MB), conservati {min(len(files), KEEP)} backup", flush=True)
