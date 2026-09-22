#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_portableapps.py - collecte de PE benins depuis PortableApps.com

Source : le miroir officiel SourceForge, canal de distribution public du projet.
On n'utilise PAS updater/update.ini : son en-tete interdit explicitement l'usage
des liens par des tiers.

Pourquoi cette source : PortableApps est massivement 32 bits et GUI, et melange
MinGW, GCC, Delphi et MSVC de plusieurs epoques. C'est exactement ce qui manque
au corpus benin actuel, ou 70 % des fichiers sont des DLL tirees d'une seule ISO
Windows, compilees par un seul compilateur.

Deux pieges traites explicitement :

  1. le lanceur <Nom>Portable.exe est genere par le meme build pour les ~460
     applications. Les prendre tous remplacerait un raccourci par un autre.
     --launcher-cap les plafonne, 0 par defaut, donc exclusion totale.

  2. une application extraite peut contenir des centaines de DLL d'un meme build.
     --per-app plafonne, avec preference donnee aux EXE pour corriger le
     desequilibre EXE/DLL mesure sur le corpus actuel.

Quatre etapes, chacune reprenable :

  discover  liste les applications du miroir
  index     releve les versions de chaque application via RSS, md5 inclus
  verify    controle les md5 des installeurs sur VirusTotal, par recherche de
            hachage, sans aucun televersement
  harvest   telecharge, extrait, moissonne les PE, supprime l'installeur

Regle heritee du pipeline malware : un echec passager n'ecrit RIEN, sinon la
reprise le prend pour un resultat acquis. Une mesure qui n'a pas eu lieu vaut
null, jamais zero.
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

try:
    import lief
    lief.logging.disable()
    HAVE_LIEF = True
except Exception:
    HAVE_LIEF = False


PROJECT = "portableapps"
BASE = "https://sourceforge.net/projects/" + PROJECT + "/files/"
RSS = "https://sourceforge.net/projects/" + PROJECT + "/rss?path=/"
UA = ("StaticPE-research/1.0 (academic dataset construction; "
      "contact lachhab.aymane11@gmail.com)")


# --------------------------------------------------------------- exceptions

class Transient(Exception):
    """Refus passager : 5xx, 429, coupure reseau. N'ecrit rien, sera retente."""


class Permanent(Exception):
    """Echec definitif : 404, archive illisible. Consigne pour ne pas reessayer."""


# --------------------------------------------------------------- utilitaires

def http_get(url, stream=False, timeout=90, tries=4, params=None):
    headers = {"User-Agent": UA}
    last = None
    for attempt in range(tries):
        try:
            r = requests.get(url, headers=headers, params=params, stream=stream,
                             timeout=timeout, allow_redirects=True)
        except Exception as exc:
            last = "reseau: " + str(exc)
            time.sleep(3 * (attempt + 1))
            continue
        if r.status_code == 200:
            return r
        if r.status_code in (404, 410):
            raise Permanent("HTTP " + str(r.status_code))
        if r.status_code in (429, 500, 502, 503, 504):
            last = "HTTP " + str(r.status_code)
            time.sleep(5 * (attempt + 1))
            continue
        raise Permanent("HTTP " + str(r.status_code))
    raise Transient(last or "tentatives epuisees")


def jsonl_append(path, obj):
    """Ecriture ligne par ligne avec vidange immediate : un arret brutal ne perd
    que la ligne en cours, pas le fichier."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def jsonl_read(path):
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # ligne tronquee par un arret brutal, on l'ignore
    return out


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------- etape 1

def cmd_discover(args):
    out = args.out / "apps.json"
    if out.exists() and not args.force:
        apps = json.load(open(out, encoding="utf-8"))
        print("deja fait : " + str(len(apps)) + " applications (" + str(out) + ")")
        return
    r = http_get(BASE)
    pattern = 'href="/projects/' + PROJECT + '/files/([^"/]+)/"'
    found = re.findall(pattern, r.text)
    apps = sorted({urllib.parse.unquote(x) for x in found})
    apps = [a for a in apps if a not in (".", "..")]
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(apps, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(str(len(apps)) + " applications -> " + str(out))


# --------------------------------------------------------------- etape 2

ITEM_RE = re.compile(r"<item>(.*?)</item>", re.S)
LINK_RE = re.compile(r"<link>(.*?)</link>")
SIZE_RE = re.compile(r'filesize="(\d+)"')
MD5_RE = re.compile(r'<media:hash algo="md5">([0-9a-f]{32})</media:hash>')
DATE_RE = re.compile(r"<pubDate>(.*?)</pubDate>")


def cmd_index(args):
    apps_path = args.out / "apps.json"
    if not apps_path.exists():
        sys.exit("lance d'abord : discover")
    apps = json.load(open(apps_path, encoding="utf-8"))

    cand = args.out / "candidates.jsonl"
    done = {c["app"] for c in jsonl_read(cand)}
    todo = [a for a in apps if a not in done]
    print(str(len(done)) + " applications deja indexees, " + str(len(todo)) + " restantes")

    for i, app in enumerate(todo, 1):
        url = RSS + urllib.parse.quote(app)
        try:
            r = http_get(url)
        except Transient as exc:
            print("  [" + str(i) + "] " + app + " : passager (" + str(exc) +
                  "), rien consigne")
            continue  # aucune trace : la reprise le refera
        except Permanent as exc:
            jsonl_append(cand, {"app": app, "error": str(exc), "versions": []})
            continue

        versions = []
        for item in ITEM_RE.findall(r.text):
            link = LINK_RE.search(item)
            if not link or ".paf.exe" not in link.group(1):
                continue
            md5 = MD5_RE.search(item)
            size = SIZE_RE.search(item)
            date = DATE_RE.search(item)
            versions.append({
                "url": link.group(1),
                "name": urllib.parse.unquote(link.group(1).rsplit("/", 2)[-2]),
                "md5": md5.group(1) if md5 else None,
                "size": int(size.group(1)) if size else None,
                "date": date.group(1) if date else None,
            })
        # le flux SourceForge va deja du plus recent au plus ancien
        jsonl_append(cand, {"app": app, "error": None, "versions": versions})
        if i % 25 == 0:
            print("  [" + str(i) + "/" + str(len(todo)) + "] " + app + " : " +
                  str(len(versions)) + " versions", flush=True)
        time.sleep(args.delay)

    rows = jsonl_read(cand)
    n_versions = sum(len(c["versions"]) for c in rows)
    n_err = sum(1 for c in rows if c["error"])
    print("")
    print(str(len(rows)) + " applications, " + str(n_versions) + " versions, " +
          str(n_err) + " en erreur -> " + str(cand))


# --------------------------------------------------------------- selection

def select_versions(rows, keep_recent, keep_old):
    """Une ou deux versions par application. La plus recente pour le logiciel
    courant, une ancienne pour la diversite d'epoque de compilation, qui est
    precisement ce qui manque a un corpus tire d'une seule ISO."""
    selected = []
    for entry in rows:
        versions = [v for v in entry["versions"] if v.get("md5")]
        if not versions:
            continue
        chosen = versions[:keep_recent]
        if keep_old and len(versions) > keep_recent:
            chosen = chosen + versions[-keep_old:]
        for v in chosen:
            item = dict(v)
            item["app"] = entry["app"]
            selected.append(item)
    return selected


# --------------------------------------------------------------- etape 3

def cmd_verify(args):
    rows = jsonl_read(args.out / "candidates.jsonl")
    if not rows:
        sys.exit("lance d'abord : index")
    selected = select_versions(rows, args.keep_recent, args.keep_old)

    vpath = args.out / "vt.jsonl"
    seen = {v["md5"] for v in jsonl_read(vpath)}
    todo = [s for s in selected if s["md5"] not in seen]

    if not args.vt_keys:
        print("aucune cle VirusTotal fournie : etape sautee.")
        print("les installeurs resteront a vt_verdict=null, c'est-a-dire")
        print("NON MESURE, ce qui n'est pas la meme chose que propre.")
        return

    keys = [k.strip() for k in Path(args.vt_keys).read_text().split() if k.strip()]
    if not keys:
        sys.exit("fichier de cles vide")
    minutes = len(todo) / float(4 * len(keys))
    print(str(len(keys)) + " cles VirusTotal, " + str(len(todo)) +
          " installeurs a controler (~" + str(int(minutes)) + " min)")

    for i, s in enumerate(todo, 1):
        key = keys[i % len(keys)]
        try:
            r = requests.get(
                "https://www.virustotal.com/api/v3/files/" + s["md5"],
                headers={"x-apikey": key, "User-Agent": UA}, timeout=60)
        except Exception as exc:
            print("  reseau (" + str(exc) + ") : rien consigne, sera repris")
            time.sleep(5)
            continue

        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            clean = (stats.get("malicious", 0) == 0 and
                     stats.get("suspicious", 0) <= 2)
            jsonl_append(vpath, {"md5": s["md5"], "app": s["app"],
                                 "verdict": "clean" if clean else "flagged",
                                 "stats": stats})
        elif r.status_code == 404:
            # inconnu de VirusTotal : ni propre ni sale, troisieme etat
            jsonl_append(vpath, {"md5": s["md5"], "app": s["app"],
                                 "verdict": "unknown", "stats": None})
        elif r.status_code == 429:
            time.sleep(20)
            continue  # rien ecrit, sera repris
        else:
            print("  HTTP " + str(r.status_code) + " : rien consigne")
            time.sleep(5)
            continue

        if i % 50 == 0:
            print("  [" + str(i) + "/" + str(len(todo)) + "]", flush=True)
        time.sleep(60.0 / (4 * len(keys)))

    print("controle termine -> " + str(vpath))


# --------------------------------------------------------------- etape 4

def find_7z():
    candidates = ["7z", "7za", "7zz", r"C:\Program Files\7-Zip\7z.exe"]
    for c in candidates:
        if shutil.which(c) or os.path.exists(c):
            return c
    return None


def is_pe(path):
    try:
        with open(path, "rb") as fh:
            if fh.read(2) != b"MZ":
                return False
            fh.seek(0x3C)
            raw = fh.read(4)
            if len(raw) != 4:
                return False
            off = int.from_bytes(raw, "little")
            if off <= 0 or off > 0x1000:
                return False
            fh.seek(off)
            return fh.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def pe_info(path):
    """Renvoie (est_dll, machine, imphash). Des None si LIEF n'a pas tourne :
    non mesure, ce qui n'est pas la meme chose que faux."""
    if not HAVE_LIEF:
        return None, None, None
    try:
        binary = lief.PE.parse(str(path))
        if binary is None:
            return None, None, None
        chars = binary.header.characteristics_list
        is_dll = any("DLL" in str(c) for c in chars)
        machine = str(binary.header.machine).split(".")[-1]
        try:
            imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.DEFAULT)
        except Exception:
            imphash = None
        return is_dll, machine, (imphash or None)
    except Exception:
        return None, None, None


LAUNCHER_RE = re.compile(r"Portable\.exe$", re.I)


def harvest_tree(root, per_app, launcher_cap, prefer_exe, exe_only):
    """Moissonne les PE d'une application extraite en respectant les plafonds."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size < 1024 or size > 200 * 1024 * 1024:
                continue
            if not is_pe(p):
                continue
            rel = p.relative_to(root).as_posix()
            depth = rel.count("/")
            launcher = bool(LAUNCHER_RE.search(fn)) and depth <= 1
            is_dll, machine, imphash = pe_info(p)
            found.append({"path": p, "rel": rel, "launcher": launcher,
                          "is_dll": is_dll, "machine": machine,
                          "imphash": imphash, "size": size})

    launchers = [x for x in found if x["launcher"]]
    others = [x for x in found if not x["launcher"]]

    if exe_only:
        # is_dll is False, pas "not is_dll" : None veut dire non mesure,
        # et un fichier non mesure ne doit pas passer pour un EXE
        others = [x for x in others if x["is_dll"] is False]

    # un seul build genere tous les lanceurs : plafond separe
    keep = launchers[:launcher_cap]

    if prefer_exe:
        # is_dll None veut dire non mesure : place entre les EXE et les DLL
        others.sort(key=lambda x: (x["is_dll"] is True, x["is_dll"] is None))

    room = max(0, per_app - len(keep))
    keep = keep + others[:room]
    return keep, len(found)


def cmd_harvest(args):
    sevenz = find_7z()
    if not sevenz:
        sys.exit("7z introuvable. Linux : apt install p7zip-full. Windows : 7-Zip.")
    if not HAVE_LIEF:
        print("ATTENTION : lief absent.")
        print("is_dll, machine et imphash seront null, donc le tri EXE/DLL et la")
        print("deduplication par imphash sont desactives. Installe lief d'abord.")
        print("")

    rows = jsonl_read(args.out / "candidates.jsonl")
    if not rows:
        sys.exit("lance d'abord : index")
    selected = select_versions(rows, args.keep_recent, args.keep_old)

    vt = {v["md5"]: v["verdict"] for v in jsonl_read(args.out / "vt.jsonl")}
    if args.require_clean:
        before = len(selected)
        selected = [s for s in selected if vt.get(s["md5"]) == "clean"]
        print("filtre VirusTotal : " + str(len(selected)) + "/" + str(before) +
              " installeurs retenus")

    idx = args.out / "harvest.jsonl"
    history = jsonl_read(idx)
    done_pkgs = {r["md5"] for r in history if r.get("kind") == "package"}
    seen_sha = {r["sha256"] for r in history if r.get("kind") == "pe"}
    seen_imp = {r["imphash"] for r in history
                if r.get("kind") == "pe" and r.get("imphash")}

    todo = [s for s in selected if s["md5"] not in done_pkgs]
    random.seed(0)
    random.shuffle(todo)  # etale la charge sur les applications
    if args.limit:
        todo = todo[:args.limit]

    store = args.store
    store.mkdir(parents=True, exist_ok=True)
    work = args.work
    work.mkdir(parents=True, exist_ok=True)

    print(str(len(done_pkgs)) + " paquets deja moissonnes, " + str(len(todo)) +
          " a traiter")
    print(str(len(seen_sha)) + " PE deja stockes")
    print("")

    kept_total = 0
    for i, s in enumerate(todo, 1):
        tmp = work / s["md5"]
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        installer = tmp / "installer.exe"

        try:
            r = http_get(s["url"], stream=True, timeout=300)
            with open(installer, "wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    fh.write(chunk)
        except Transient as exc:
            print("  [" + str(i) + "/" + str(len(todo)) + "] " + s["app"] +
                  " : passager (" + str(exc) + "), rien consigne")
            shutil.rmtree(tmp, ignore_errors=True)
            continue  # aucune trace : sera repris
        except Permanent as exc:
            jsonl_append(idx, {"kind": "package", "md5": s["md5"],
                               "app": s["app"], "error": str(exc), "kept": 0})
            shutil.rmtree(tmp, ignore_errors=True)
            continue

        got = installer.stat().st_size
        if s["size"] and abs(got - s["size"]) > 4096:
            print("  [" + str(i) + "/" + str(len(todo)) + "] " + s["app"] +
                  " : taille inattendue (" + str(got) + " vs " + str(s["size"]) +
                  "), rien consigne")
            shutil.rmtree(tmp, ignore_errors=True)
            continue

        extracted = tmp / "x"
        extracted.mkdir()
        try:
            rc = subprocess.run([sevenz, "x", "-y", "-o" + str(extracted),
                                 str(installer)],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=args.extract_timeout)
            code = rc.returncode
        except subprocess.TimeoutExpired:
            code = -1

        if code != 0 or not any(extracted.iterdir()):
            jsonl_append(idx, {"kind": "package", "md5": s["md5"],
                               "app": s["app"], "error": "7z rc=" + str(code),
                               "kept": 0})
            shutil.rmtree(tmp, ignore_errors=True)
            continue

        keep, total = harvest_tree(extracted, args.per_app, args.launcher_cap,
                                   not args.no_prefer_exe, args.exe_only)

        # l'installeur lui-meme est un EXE benin autonome, empaquete NSIS,
        # 32 bits et GUI : structurellement le profil d'un malware, ce qui est
        # rare du cote benin. On le garde plutot que de le jeter.
        if args.keep_installer and is_pe(installer):
            is_dll, machine, imphash = pe_info(installer)
            keep.append({"path": installer, "rel": "(installateur)",
                         "launcher": False, "is_dll": is_dll,
                         "machine": machine, "imphash": imphash,
                         "size": got})

        kept = 0
        for pe in keep:
            sha = sha256_of(pe["path"])
            if sha in seen_sha:
                continue
            if args.dedupe_imphash and pe["imphash"] and pe["imphash"] in seen_imp:
                continue
            shutil.copy2(pe["path"], store / (sha + ".bin"))
            seen_sha.add(sha)
            if pe["imphash"]:
                seen_imp.add(pe["imphash"])
            jsonl_append(idx, {
                "kind": "pe",
                "sha256": sha,
                "app": s["app"],
                "package": s["name"],
                "package_md5": s["md5"],
                "rel_path": pe["rel"],
                "launcher": pe["launcher"],
                "is_dll": pe["is_dll"],
                "machine": pe["machine"],
                "imphash": pe["imphash"],
                "size": pe["size"],
                "vt_verdict": vt.get(s["md5"]),  # null si non mesure
                "source": "portableapps/sourceforge",
            })
            kept += 1

        jsonl_append(idx, {"kind": "package", "md5": s["md5"], "app": s["app"],
                           "error": None, "pe_found": total, "kept": kept})
        kept_total += kept
        shutil.rmtree(tmp, ignore_errors=True)
        print("  [" + str(i) + "/" + str(len(todo)) + "] " +
              s["app"][:36].ljust(36) + " " + str(total).rjust(4) +
              " PE trouves, " + str(kept).rjust(3) + " gardes  (total " +
              str(len(seen_sha)) + ")", flush=True)
        time.sleep(args.delay)

    print("")
    print(str(kept_total) + " nouveaux PE. Stock : " + str(len(seen_sha)) +
          " fichiers dans " + str(store))


# --------------------------------------------------------------- rapport

def cmd_report(args):
    rows = [r for r in jsonl_read(args.out / "harvest.jsonl")
            if r.get("kind") == "pe"]
    if not rows:
        sys.exit("rien a resumer : lance d'abord harvest")

    n = len(rows)
    dll = sum(1 for r in rows if r["is_dll"] is True)
    exe = sum(1 for r in rows if r["is_dll"] is False)
    unknown = sum(1 for r in rows if r["is_dll"] is None)
    x64 = sum(1 for r in rows if r["machine"] in ("AMD64", "ARM64"))
    x86 = sum(1 for r in rows if r["machine"] == "I386")
    launchers = sum(1 for r in rows if r["launcher"])
    apps = len({r["app"] for r in rows})

    def pct(k):
        return str(round(100.0 * k / n, 1)).rjust(5)

    print(str(n) + " PE, " + str(apps) + " applications")
    print("  EXE      " + str(exe).rjust(6) + "  " + pct(exe) + " %   cible 68 %")
    print("  DLL      " + str(dll).rjust(6) + "  " + pct(dll) + " %   cible 32 %")
    if unknown:
        print("  non mesure " + str(unknown).rjust(4) + "  " + pct(unknown) +
              " %   <- lief absent")
    print("  32 bits  " + str(x86).rjust(6) + "  " + pct(x86) + " %   cible 80 %")
    print("  64 bits  " + str(x64).rjust(6) + "  " + pct(x64) + " %")
    print("  lanceurs " + str(launchers).rjust(6))

    counts = Counter(r["app"] for r in rows)
    print("")
    print("  applications les plus representees :")
    for app, k in counts.most_common(8):
        print("    " + str(k).rjust(4) + "  " + app)


# --------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("pa_collect"))
    ap.add_argument("--store", type=Path, default=Path("pa_collect/pe"))
    ap.add_argument("--work", type=Path, default=Path("pa_collect/work"))
    ap.add_argument("--delay", type=float, default=1.0,
                    help="pause entre requetes, par courtoisie (defaut 1 s)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("index")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("verify")
    p.add_argument("--vt-keys", help="fichier de cles VirusTotal, une par ligne")
    p.add_argument("--keep-recent", type=int, default=1)
    p.add_argument("--keep-old", type=int, default=1)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("harvest")
    p.add_argument("--keep-recent", type=int, default=1)
    p.add_argument("--keep-old", type=int, default=1)
    p.add_argument("--per-app", type=int, default=30,
                   help="PE maximum par application (defaut 30)")
    p.add_argument("--launcher-cap", type=int, default=0,
                   help="lanceurs <Nom>Portable.exe gardes par application, "
                        "0 par defaut donc exclus")
    p.add_argument("--no-prefer-exe", action="store_true")
    p.add_argument("--keep-installer", action="store_true", default=True,
                   help="garder aussi l'installeur .paf.exe : un EXE benin "
                        "autonome, NSIS, 32 bits, profil proche d'un malware")
    p.add_argument("--no-keep-installer", dest="keep_installer",
                   action="store_false")
    p.add_argument("--exe-only", action="store_true",
                   help="ne garder que les executables, aucune DLL. "
                        "Rend environ 2 PE par application au lieu de 30.")
    p.add_argument("--dedupe-imphash", action="store_true", default=True)
    p.add_argument("--require-clean", action="store_true",
                   help="ne garder que les installeurs verdict=clean")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--extract-timeout", type=int, default=900)
    p.set_defaults(func=cmd_harvest)

    p = sub.add_parser("report")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
