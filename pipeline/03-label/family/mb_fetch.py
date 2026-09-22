"""Telechargement MalwareBazaar avec pool de cles + rotation Tor.

MalwareBazaar plafonne a 2000 telechargements par jour ET par IP ET par cle.
Les deux limites s'appliquent : une seule cle derriere Tor bute sur la cle,
plusieurs cles sur une seule IP butent sur l'IP. Ce module fait tourner les
deux en parallele, ce qui donne ~2000/jour et par cle disponible.

Fichier de cles : une cle par ligne, les lignes vides et les # sont ignorees.

    import mb_fetch
    pool = mb_fetch.KeyPool("keys_mb.txt")
    data = mb_fetch.fetch_by_sha256(sha, pool)      # octets du PE, dezippe

Toute panne leve NotAvailable : jamais de retour silencieux.
"""
import io
import itertools
import os
import threading
import time
from pathlib import Path

import requests
import pyzipper

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
DAILY_QUOTA = int(os.getenv("MB_DAILY_QUOTA", "2000"))
COOLDOWN = int(os.getenv("MB_KEY_COOLDOWN", "86400"))  # 24 h
USE_TOR = os.getenv("MB_USE_TOR", "0") == "1"
TOR_PORT = int(os.getenv("MB_TOR_PORT", "9050"))
TOR_CTRL_PORT = int(os.getenv("MB_TOR_CTRL_PORT", "9051"))
TOR_PASSWORD = os.getenv("MB_TOR_PASSWORD", "pfe2026")
ROTATE_EVERY = int(os.getenv("MB_TOR_ROTATE_EVERY", "1500"))

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


class NotAvailable(Exception):
    """L'echantillon n'est pas recuperable (absent, ou quota epuise)."""


class AllKeysExhausted(NotAvailable):
    """Toutes les cles ont atteint leur quota journalier."""


class KeyPool:
    """Pool de cles avec compteur par cle et mise au repos apres epuisement."""

    def __init__(self, path=None, keys=None):
        if keys is None:
            keys = []
            if path and Path(path).exists():
                for line in Path(path).read_text().splitlines():
                    k = line.strip()
                    if k and not k.startswith("#"):
                        keys.append(k)
            env = os.getenv("MALWAREBAZAAR_API_KEY")
            if env and env not in keys:
                keys.append(env)
        if not keys:
            raise NotAvailable("aucune cle MalwareBazaar disponible")
        self._lock = threading.Lock()
        self._used = {k: 0 for k in keys}
        self._blocked_until = {k: 0.0 for k in keys}
        self._cycle = itertools.cycle(keys)
        self._keys = keys
        self._downloads = 0

    def acquire(self):
        """Retourne une cle utilisable, ou leve AllKeysExhausted."""
        with self._lock:
            now = time.time()
            for _ in range(len(self._keys)):
                k = next(self._cycle)
                if self._blocked_until[k] > now:
                    continue
                if self._used[k] >= DAILY_QUOTA:
                    self._blocked_until[k] = now + COOLDOWN
                    continue
                self._used[k] += 1
                self._downloads += 1
                rotate = self._downloads % ROTATE_EVERY == 0
                return k, rotate
            soonest = min(self._blocked_until.values())
            raise AllKeysExhausted(
                f"{len(self._keys)} cles epuisees, reprise dans "
                f"{int(max(0, soonest - now) / 60)} min")

    def block(self, key, seconds=COOLDOWN):
        """Marque une cle comme rate-limitee."""
        with self._lock:
            self._blocked_until[key] = time.time() + seconds

    def stats(self):
        with self._lock:
            now = time.time()
            return {"cles": len(self._keys),
                    "actives": sum(1 for k in self._keys
                                   if self._blocked_until[k] <= now
                                   and self._used[k] < DAILY_QUOTA),
                    "telecharges": self._downloads,
                    "par_cle": dict(self._used)}


def _proxies():
    if not USE_TOR:
        return None
    return {"http": f"socks5h://127.0.0.1:{TOR_PORT}",
            "https": f"socks5h://127.0.0.1:{TOR_PORT}"}


_tor_lock = threading.Lock()


def rotate_ip():
    if not USE_TOR:
        return
    with _tor_lock:
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=TOR_CTRL_PORT) as c:
                c.authenticate(password=TOR_PASSWORD)
                c.signal(Signal.NEWNYM)
                time.sleep(5)
        except Exception:
            pass


def _unzip(zip_bytes):
    with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.setpassword(ZIP_PASSWORD)
        names = zf.namelist()
        if not names:
            raise NotAvailable("ZIP vide")
        return zf.read(names[0])


def fetch_by_sha256(sha256, pool, max_retries=6, timeout=120):
    """Telecharge et dezippe un echantillon. Leve NotAvailable sinon."""
    for attempt in range(max_retries):
        key, rotate = pool.acquire()          # leve AllKeysExhausted si vide
        if rotate:
            rotate_ip()
        try:
            resp = requests.post(
                MB_API_URL,
                data={"query": "get_file", "sha256_hash": sha256},
                headers={"Auth-Key": key, "User-Agent": _UA},
                proxies=_proxies(), timeout=timeout)
        except Exception as e:
            if attempt == max_retries - 1:
                raise NotAvailable(f"reseau: {e}")
            rotate_ip()
            time.sleep(2 * (attempt + 1))
            continue

        if resp.content[:2] == b"PK":
            return _unzip(resp.content)

        try:
            js = resp.json()
        except Exception:
            raise NotAvailable(f"reponse illisible (HTTP {resp.status_code})")
        status = js.get("query_status", "?")
        msg = str(js.get("message", ""))

        if status in ("file_not_found", "no_results"):
            raise NotAvailable("not in MalwareBazaar")
        if status == "illegal_search_term":
            raise NotAvailable(f"sha256 invalide: {sha256}")
        # rate limit : cette cle est grillee pour la journee, on change d'IP
        pool.block(key)
        rotate_ip()
        time.sleep(2)
    raise NotAvailable(f"echec apres {max_retries} tentatives (dernier: {status} {msg[:80]})")


def fetch_by_md5(md5, bridge, pool, **kw):
    """Resout le md5 en sha256 via `bridge` (dict) puis telecharge."""
    sha = bridge.get(md5.strip().lower())
    if not sha:
        raise NotAvailable("md5 absent de la table md5->sha256")
    return fetch_by_sha256(sha, pool, **kw)


def load_bridge(path):
    import csv
    with open(path, encoding="utf-8") as fh:
        return {r["md5"].strip().lower(): r["sha256"].strip().lower()
                for r in csv.DictReader(fh)}
