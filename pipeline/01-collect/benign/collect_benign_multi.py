#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_benign_multi.py - collecte de PE benins depuis plusieurs sources

POURQUOI CE SCRIPT EXISTE
-------------------------
Le corpus benin actuel est 70,3 % de DLL tirees d'une seule ISO Windows. Mesure
sur les 85 080 echantillons, six features de pur FORMAT - est-ce une DLL, est-ce
64 bits, est-ce graphique - suffisent a atteindre AUC 0,9055 et 83 % d'exactitude.
Le modele n'apprend pas la malveillance, il apprend "DLL systeme Microsoft 64
bits" contre "executable graphique 32 bits".

Le but n'est donc pas de collecter PLUS de benins, mais des benins dont la
distribution de format ressemble a celle des malwares :

                        actuel        malwares       cible
    EXE                  29,7 %         71,0 %       ~68 %
    32 bits              56,5 %         88,2 %       ~80 %

SOURCES ET CE QU'ELLES APPORTENT
--------------------------------
archive.org / tucows   partagiciels Windows des annees 90-2000. Mesure sur un
                       echantillon : 0,62 PE par item, 100 % EXE, 1 Mo par item.
                       32 312 items, soit environ 20 000 executables pour 32 Go.
                       C'est la source d'EXE, celle qui corrige le desequilibre.

portableapps           miroir SourceForge officiel, 459 applications. Mesure :
                       96 % de 32 bits, mais 86 % de DLL. Corrige l'architecture
                       et la monoculture de compilateur, pas le rapport EXE/DLL.

On n'utilise PAS portableapps.com/updater/update.ini : son en-tete interdit
explicitement l'usage des liens par des tiers.

PIEGES TRAITES
--------------
Lanceurs PortableApps : le meme build genere <Nom>Portable.exe pour les 459
applications. Les prendre tous remplacerait un raccourci par un autre.
--launcher-cap les plafonne, 0 par defaut.

Correlation intra-application : une application extraite peut contenir des
centaines de DLL d'un meme build. --per-app plafonne.

Windows CE : tucows contient des PE ARM et MIPS pour Pocket PC. Les malwares du
corpus sont tous I386 ou AMD64. --machines filtre, et le rapport dit combien ont
ete ecartes plutot que de les faire disparaitre en silence.

Provenance : SourceForge a fait tourner de 2013 a 2016 le programme DevShare, qui
empaquetait des installeurs avec des logiciels publicitaires ; archive.org heberge
deliberement du logiciel malveillant historique. Pour ces sources la verification
VirusTotal n'est pas un confort, elle est necessaire. Sans cles, vt_verdict reste
a null - NON MESURE, ce qui n'est pas "propre".

REGLES HERITEES DU PIPELINE MALWARE
-----------------------------------
Un echec passager n'ecrit RIEN : la reprise saute ce qu'elle trouve, donc une
trace posee par un echec transitoire devient un resultat acquis et faux.
Une mesure qui n'a pas eu lieu vaut null, jamais 0.

ETAPES, chacune reprenable
--------------------------
  discover  etablit la liste des unites a traiter
  index     releve pour chaque unite les archives telechargeables, md5 inclus
  verify    controle les md5 sur VirusTotal par recherche de hachage, sans
            aucun televersement
  harvest   telecharge, extrait, moissonne les PE, supprime l'archive
  report    distribution obtenue face a la cible
"""

import argparse
import hashlib
import io
import json
import math
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import zipfile
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


UA = ("StaticPE-research/1.0 (academic dataset construction; "
      "contact lachhab.aymane11@gmail.com)")

PA_PROJECT = "portableapps"
PA_BASE = "https://sourceforge.net/projects/" + PA_PROJECT + "/files/"
PA_RSS = "https://sourceforge.net/projects/" + PA_PROJECT + "/rss?path=/"

IA_SEARCH = "https://archive.org/advancedsearch.php"
# scrape gere la pagination par curseur et n'a pas la limite de
# 10 000 resultats de advancedsearch, qui refuse au-dela.
IA_SCRAPE = "https://archive.org/services/search/v1/scrape"
IA_META = "https://archive.org/metadata/"
IA_DL = "https://archive.org/download/"

SF_RSS = "https://sourceforge.net/projects/{}/rss?path=/"
# Extensions retenues cote SourceForge. Les .paf.exe de PortableApps sont
# traites par leur propre source ; ici on vise les installeurs classiques.
SF_EXT = (".exe", ".msi", ".zip", ".7z")

# Types d'installeurs winget qui contiennent des PE exploitables. Les msix
# et appx sont des conteneurs UWP : ils en contiennent aussi, mais leur
# profil est different et ils sont exclus par defaut.
WG_TYPES = ("nullsoft", "inno", "wix", "msi", "exe", "burn", "portable", "zip")

ARCHIVE_EXT = (".zip", ".exe", ".msi", ".cab", ".7z", ".rar", ".arj", ".lzh")
DEFAULT_MACHINES = "I386,AMD64"


# ============================================================ exceptions

class Transient(Exception):
    """Refus passager : 5xx, 429, coupure reseau. N'ecrit rien, sera retente."""


class Permanent(Exception):
    """Echec definitif : 404, archive illisible. Consigne pour ne pas reessayer."""


# ============================================================ utilitaires

_session = None


def session():
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers.update({"User-Agent": UA})
    return _session


def http_get(url, stream=False, timeout=120, tries=4, params=None):
    last = None
    for attempt in range(tries):
        try:
            r = session().get(url, params=params, stream=stream, timeout=timeout,
                              allow_redirects=True)
        except Exception as exc:
            last = "reseau: " + str(exc)
            time.sleep(3 * (attempt + 1))
            continue
        if r.status_code == 200:
            return r
        if r.status_code in (403, 404, 410):
            raise Permanent("HTTP " + str(r.status_code))
        if r.status_code in (429, 500, 502, 503, 504):
            last = "HTTP " + str(r.status_code)
            time.sleep(5 * (attempt + 1))
            continue
        raise Permanent("HTTP " + str(r.status_code))
    raise Transient(last or "tentatives epuisees")


def jsonl_append(path, obj):
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
                pass  # ligne tronquee par un arret brutal
    return out


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def is_pe(data):
    if len(data) < 1024 or data[:2] != b"MZ":
        return False
    try:
        off = int.from_bytes(data[0x3C:0x40], "little")
    except Exception:
        return False
    if not (0 < off < 0x1000):
        return False
    return data[off:off + 4] == b"PE\x00\x00"


def pe_info(data):
    """(est_dll, machine, imphash). None = non mesure, pas faux."""
    if not HAVE_LIEF:
        return None, None, None
    try:
        b = lief.PE.parse(list(data))
        if b is None:
            return None, None, None
        is_dll = b.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
        machine = str(b.header.machine).split(".")[-1]
        try:
            imphash = lief.PE.get_imphash(b, lief.PE.IMPHASH_MODE.PEFILE)
        except Exception:
            imphash = None
        return bool(is_dll), machine, (imphash or None)
    except Exception:
        return None, None, None


def find_7z():
    for c in ["7z", "7za", "7zz", r"C:\Program Files\7-Zip\7z.exe"]:
        if shutil.which(c) or os.path.exists(c):
            return c
    return None


# ============================================================ discover

def discover_portableapps(args):
    r = http_get(PA_BASE)
    pattern = 'href="/projects/' + PA_PROJECT + '/files/([^"/]+)/"'
    apps = sorted({urllib.parse.unquote(x) for x in re.findall(pattern, r.text)})
    return [{"source": "portableapps", "unit": a} for a in apps
            if a not in (".", "..")]


def discover_archive(args):
    """Endpoint scrape avec pagination par curseur.

    advancedsearch.php refuse au-dela du dix-milliemme resultat, une limite de
    Solr : sur une collection de trente mille items, le recensement s'arrete a
    la onzieme page. scrape n'a pas cette limite et rend bien zero pour une
    collection inexistante, ce qui a ete verifie."""
    requete = "collection:" + args.collection
    out = []
    cursor = None
    page = 0
    vus = set()
    premier_precedent = None

    while True:
        page += 1
        params = {"q": requete, "fields": "identifier", "count": 1000}
        if cursor:
            params["cursor"] = cursor
        r = http_get(IA_SCRAPE, params=params)
        d = r.json()

        if "error" in d:
            raise Permanent("archive.org : " + str(d["error"])[:200])

        items = d.get("items") or []
        total = d.get("total")

        if page == 1:
            if not total:
                raise Permanent("collection " + args.collection + " : 0 item. "
                                "Verifier le nom, une collection inexistante "
                                "rend zero et non une erreur.")
            print("collection " + args.collection + " : " + str(total) + " items")

        if not items:
            break

        # Garde-fou : deux pages consecutives commencant par le meme identifiant
        # signifieraient que le curseur n'est pas pris en compte et qu'on tourne
        # en rond. Sans cette verification, on collecterait mille fois la meme
        # page en croyant avancer.
        premier = items[0].get("identifier")
        if premier is not None and premier == premier_precedent:
            raise Permanent("page " + str(page) + " : le curseur ne progresse "
                            "pas, meme premier identifiant qu'a la page "
                            "precedente (" + str(premier) + ")")
        premier_precedent = premier

        for x in items:
            ident = x.get("identifier")
            if ident and ident not in vus:
                vus.add(ident)
                out.append({"source": "archive", "unit": ident,
                            "collection": args.collection})

        if args.max_items and len(out) >= args.max_items:
            out = out[:args.max_items]
            break

        cursor = d.get("cursor")
        if not cursor:
            break                          # derniere page : plus de curseur
        time.sleep(args.delay)

    return out


def discover_sourceforge(args):
    """Liste de projets fournie a la main : SourceForge n'est pas enumerable.

    /directory, /sitemap.xml et la recherche rendent tous 403. Le RSS par projet,
    lui, repond. On ne peut donc pas decouvrir les projets, seulement les lire."""
    if not args.projects:
        raise Permanent("SourceForge n'est pas enumerable : passe --projects "
                        "avec un fichier contenant un identifiant par ligne")
    noms = []
    for ligne in Path(args.projects).read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if ligne and not ligne.startswith("#"):
            noms.append(ligne)
    print("liste de projets : " + str(len(noms)) + " entrees")
    return [{"source": "sourceforge", "unit": n} for n in noms]



_WG_VER = re.compile(r"(\d+)")


def _wg_version_key(nom):
    """Tri des versions par composants numeriques. Un tri lexical placerait
    la version 9 apres la version 10."""
    return [int(x) for x in _WG_VER.findall(nom)[:6]] or [0]


def _wg_parse_installers(texte):
    """Lecture ciblee du manifeste, sans dependance YAML.

    On ne lit que quatre champs et ils sont toujours au meme niveau
    d'indentation sous une entree de la liste Installers. Un analyseur YAML
    complet serait plus propre mais ajouterait une dependance a installer sur
    le cluster pour lire quatre lignes."""
    out = []
    courant = None
    for ligne in texte.splitlines():
        nu = ligne.strip()
        if nu.startswith("- Architecture:"):
            if courant and courant.get("url"):
                out.append(courant)
            courant = {"arch": nu.split(":", 1)[1].strip()}
            continue
        if courant is None:
            continue
        if nu.startswith("Architecture:"):
            courant["arch"] = nu.split(":", 1)[1].strip()
        elif nu.startswith("InstallerType:"):
            courant["type"] = nu.split(":", 1)[1].strip()
        elif nu.startswith("InstallerUrl:"):
            courant["url"] = nu.split(":", 1)[1].strip()
        elif nu.startswith("InstallerSha256:"):
            courant["sha256"] = nu.split(":", 1)[1].strip().lower()
    if courant and courant.get("url"):
        out.append(courant)
    return out


def discover_winget(args):
    """Parcourt un clone local du depot et retient la version la plus recente
    de chaque paquet."""
    if not args.winget_repo:
        raise Permanent("passe --winget-repo avec le chemin d'un clone de "
                        "microsoft/winget-pkgs "
                        "(git clone --depth 1 https://github.com/microsoft/winget-pkgs)")
    racine = Path(args.winget_repo) / "manifests"
    if not racine.is_dir():
        raise Permanent("dossier manifests introuvable dans " + str(args.winget_repo))

    # paquet -> dossier de sa version la plus recente
    paquets = {}
    for chemin in racine.rglob("*.installer.yaml"):
        version_dir = chemin.parent
        paquet = version_dir.parent
        cle = str(paquet.relative_to(racine)).replace("\\", "/")
        actuel = paquets.get(cle)
        if actuel is None or _wg_version_key(version_dir.name) > _wg_version_key(actuel.name):
            paquets[cle] = version_dir

    print("depot winget : " + str(len(paquets)) + " paquets")
    unites = [{"source": "winget", "unit": cle, "path": str(paquets[cle])}
              for cle in sorted(paquets)]
    if args.max_items:
        unites = unites[:args.max_items]
    return unites


def index_winget(unit_path, args):
    """Lit le manifeste et rend les installeurs retenus.

    L'architecture etant declaree, on peut preferer le x86 : c'est la seule des
    quatre sources qui le permette avant telechargement."""
    dossier = Path(unit_path)
    fichiers = list(dossier.glob("*.installer.yaml"))
    if not fichiers:
        raise Permanent("pas de manifeste installer dans " + str(dossier))
    installeurs = _wg_parse_installers(
        fichiers[0].read_text(encoding="utf-8", errors="replace"))

    retenus = []
    for i in installeurs:
        t = (i.get("type") or "").lower()
        if t and t not in WG_TYPES:
            continue
        if not i["url"].lower().endswith((".exe", ".msi", ".zip")):
            continue
        retenus.append(i)

    if not retenus:
        return []

    # x86 d'abord, puis x64, puis le reste
    ordre = {"x86": 0, "x64": 1}
    retenus.sort(key=lambda i: ordre.get((i.get("arch") or "").lower(), 2))
    if args.winget_x86_only:
        retenus = [i for i in retenus if (i.get("arch") or "").lower() == "x86"]

    out = []
    for i in retenus[:args.archives_per_item]:
        out.append({
            "url": i["url"],
            "name": i["url"].rsplit("/", 1)[-1].split("?")[0],
            # winget publie du SHA-256, pas du MD5. VirusTotal accepte les deux.
            "md5": None,
            "sha256": i.get("sha256"),
            "size": None,
            "arch_declared": i.get("arch"),
            "installer_type": i.get("type"),
        })
    return out


def cmd_discover(args):
    out = args.out / "units.jsonl"
    known = {(u["source"], u["unit"]) for u in jsonl_read(out)}

    if args.source == "archive":
        # archive.org rend une page par vingtaine de secondes ; sur trente pages
        # une coupure reseau est probable. On ecrit donc au fil de l'eau et on
        # retient le curseur, pour qu'une relance reprenne ou elle s'est arretee
        # au lieu de tout recommencer.
        added = discover_archive_incremental(args, out, known)
    else:
        if args.source == "portableapps":
            units = discover_portableapps(args)
        elif args.source == "sourceforge":
            units = discover_sourceforge(args)
        else:
            units = discover_winget(args)
        added = 0
        for u in units:
            if (u["source"], u["unit"]) in known:
                continue
            jsonl_append(out, u)
            added += 1

    total = len(jsonl_read(out))
    print(str(added) + " nouvelles unites, " + str(total) + " au total -> " + str(out))


def discover_archive_incremental(args, out, known):
    """Meme parcours que discover_archive, mais chaque page est ecrite des
    qu'elle arrive et le curseur est conserve sur disque.

    Le curseur est la seule information qui ne se reconstruit pas : sans lui,
    reprendre veut dire retelecharger toutes les pages deja vues."""
    etat = args.out / ("_cursor_" + args.collection + ".txt")
    cursor = None
    if etat.exists():
        cursor = etat.read_text(encoding="utf-8").strip() or None
        if cursor:
            print("reprise au curseur enregistre")

    requete = "collection:" + args.collection
    added = 0
    page = 0
    premier_precedent = None
    deja = len([1 for k in known if k[0] == "archive"])

    while True:
        page += 1
        params = {"q": requete, "fields": "identifier", "count": 1000}
        if cursor:
            params["cursor"] = cursor
        r = http_get(IA_SCRAPE, params=params)
        d = r.json()
        if "error" in d:
            raise Permanent("archive.org : " + str(d["error"])[:200])

        items = d.get("items") or []
        if page == 1 and not cursor:
            total = d.get("total")
            if not total:
                raise Permanent("collection " + args.collection + " : 0 item. "
                                "Une collection inexistante rend zero et non "
                                "une erreur ; verifier le nom.")
            print("collection " + args.collection + " : " + str(total) + " items")
        if not items:
            break

        premier = items[0].get("identifier")
        if premier is not None and premier == premier_precedent:
            raise Permanent("le curseur ne progresse pas : meme premier "
                            "identifiant qu'a la page precedente")
        premier_precedent = premier

        for x in items:
            ident = x.get("identifier")
            if not ident or ("archive", ident) in known:
                continue
            known.add(("archive", ident))
            jsonl_append(out, {"source": "archive", "unit": ident,
                               "collection": args.collection})
            added += 1

        print("  page " + str(page) + " : " + str(deja + added) + " unites",
              flush=True)

        if args.max_items and (deja + added) >= args.max_items:
            break

        cursor = d.get("cursor")
        # le curseur est ecrit APRES la page qu'il suit : si le programme meurt
        # entre les deux, on refait une page au lieu d'en sauter une
        etat.write_text(cursor or "", encoding="utf-8")
        if not cursor:
            break
        time.sleep(args.delay)

    return added


# ============================================================ index

PA_ITEM = re.compile(r"<item>(.*?)</item>", re.S)
PA_LINK = re.compile(r"<link>(.*?)</link>")
PA_SIZE = re.compile(r'filesize="(\d+)"')
PA_MD5 = re.compile(r'<media:hash algo="md5">([0-9a-f]{32})</media:hash>')


def index_portableapps(unit, args):
    r = http_get(PA_RSS + urllib.parse.quote(unit))
    versions = []
    for item in PA_ITEM.findall(r.text):
        link = PA_LINK.search(item)
        if not link or ".paf.exe" not in link.group(1):
            continue
        md5 = PA_MD5.search(item)
        size = PA_SIZE.search(item)
        versions.append({
            "url": link.group(1),
            "name": urllib.parse.unquote(link.group(1).rsplit("/", 2)[-2]),
            "md5": md5.group(1) if md5 else None,
            "size": int(size.group(1)) if size else None,
        })
    # le flux va deja du plus recent au plus ancien
    keep = versions[:args.keep_recent]
    if args.keep_old and len(versions) > args.keep_recent:
        keep = keep + versions[-args.keep_old:]
    return keep


def index_archive(unit, args):
    r = http_get(IA_META + urllib.parse.quote(unit))
    meta = r.json()
    files = meta.get("files", []) or []
    out = []
    for f in files:
        name = f.get("name", "")
        if not name.lower().endswith(ARCHIVE_EXT):
            continue
        size = f.get("size")
        try:
            size = int(size) if size is not None else None
        except (TypeError, ValueError):
            size = None
        if size is not None and size > args.max_archive_mb * 1024 * 1024:
            continue
        out.append({
            "url": IA_DL + urllib.parse.quote(unit) + "/" + urllib.parse.quote(name),
            "name": name,
            "md5": f.get("md5"),
            "size": size,
        })
    return out[:args.archives_per_item]


def index_sourceforge(unit, args):
    """Meme flux que PortableApps, mais on garde les installeurs et archives,
    et seulement les versions les plus recentes pour eviter de collectionner
    vingt builds du meme logiciel."""
    r = http_get(SF_RSS.format(urllib.parse.quote(unit)))
    vus = set()
    out = []
    for item in PA_ITEM.findall(r.text):
        link = PA_LINK.search(item)
        if not link:
            continue
        url = link.group(1)
        nom = urllib.parse.unquote(url.rsplit("/", 2)[-2])
        if not nom.lower().endswith(SF_EXT):
            continue
        md5 = PA_MD5.search(item)
        size = PA_SIZE.search(item)
        taille = int(size.group(1)) if size else None
        if taille and taille > args.max_archive_mb * 1024 * 1024:
            continue
        # un seul fichier par nom de base : sinon on prend toutes les
        # traductions et toutes les architectures du meme installeur
        cle = nom.lower().split("-")[0].split("_")[0]
        if cle in vus:
            continue
        vus.add(cle)
        out.append({"url": url, "name": nom,
                    "md5": md5.group(1) if md5 else None, "size": taille})
        if len(out) >= args.archives_per_item:
            break
    return out


def cmd_index(args):
    units = jsonl_read(args.out / "units.jsonl")
    if not units:
        sys.exit("lance d'abord : discover")
    if args.source:
        units = [u for u in units if u["source"] == args.source]

    cand = args.out / "candidates.jsonl"
    done = {(c["source"], c["unit"]) for c in jsonl_read(cand)}
    todo = [u for u in units if (u["source"], u["unit"]) not in done]
    print(str(len(done)) + " unites deja indexees, " + str(len(todo)) + " restantes")

    for i, u in enumerate(todo, 1):
        try:
            if u["source"] == "portableapps":
                archives = index_portableapps(u["unit"], args)
            elif u["source"] == "sourceforge":
                archives = index_sourceforge(u["unit"], args)
            elif u["source"] == "winget":
                archives = index_winget(u["path"], args)
            else:
                archives = index_archive(u["unit"], args)
        except Transient as exc:
            print("  " + u["unit"][:50] + " : passager (" + str(exc) +
                  "), rien consigne")
            continue  # aucune trace : sera repris
        except Permanent as exc:
            jsonl_append(cand, {"source": u["source"], "unit": u["unit"],
                                "error": str(exc), "archives": []})
            continue
        except Exception as exc:
            jsonl_append(cand, {"source": u["source"], "unit": u["unit"],
                                "error": "parse: " + str(exc)[:120], "archives": []})
            continue

        jsonl_append(cand, {"source": u["source"], "unit": u["unit"],
                            "error": None, "archives": archives})
        if i % 100 == 0:
            print("  [" + str(i) + "/" + str(len(todo)) + "] " + u["unit"][:44],
                  flush=True)
        time.sleep(args.delay)

    rows = jsonl_read(cand)
    n_arch = sum(len(c["archives"]) for c in rows)
    n_err = sum(1 for c in rows if c["error"])
    print("")
    print(str(len(rows)) + " unites, " + str(n_arch) + " archives, " +
          str(n_err) + " en erreur -> " + str(cand))



class ArchiveTropLongue(Exception):
    """Une archive a depasse son budget de temps, tous traitements confondus."""


def _alarme(signum, frame):
    raise ArchiveTropLongue("budget de temps depasse")


def budget(secondes):
    """Limite le temps passe sur UNE archive, ou qu'elle bloque.

    Le delai de requests est un delai ENTRE PAQUETS, pas une duree totale : un
    serveur qui envoie un octet toutes les dix secondes ne le declenche jamais.
    Le moissonnage s'est fige ainsi apres 853 archives. 7z, zipfile et LIEF
    peuvent aussi partir en boucle sur un fichier malforme.

    signal.alarm coupe quoi qu'il arrive. Il n'existe que dans le fil principal,
    ce qui convient : la boucle de moissonnage est monothread."""
    if not hasattr(signal, "SIGALRM"):
        return None                        # Windows : pas de garde-fou
    signal.signal(signal.SIGALRM, _alarme)
    signal.alarm(int(secondes))
    return True


def fin_budget():
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)


def telecharger(url, timeout=300, tries=4):
    """Telecharge le corps entier, avec la lecture DANS le bloc protege.

    http_get ne couvre que l'etablissement de la reponse. En mode stream, les
    octets arrivent ensuite, et une connexion coupee a ce moment leve une
    ChunkedEncodingError hors de toute protection : le processus entier
    s'arretait. C'est arrive apres 577 archives, sur un fichier de 120 Mo.

    Un refus passager doit etre retente, jamais tuer le run."""
    dernier = None
    for essai in range(tries):
        try:
            r = session().get(url, stream=True, timeout=timeout,
                              allow_redirects=True)
        except Exception as exc:
            dernier = "reseau: " + str(exc)[:120]
            time.sleep(3 * (essai + 1))
            continue

        if r.status_code in (403, 404, 410):
            raise Permanent("HTTP " + str(r.status_code))
        if r.status_code != 200:
            dernier = "HTTP " + str(r.status_code)
            time.sleep(5 * (essai + 1))
            continue

        try:
            morceaux = []
            for bloc in r.iter_content(1 << 20):
                if bloc:
                    morceaux.append(bloc)
            return b"".join(morceaux)
        except Exception as exc:
            # coupure en cours de lecture : c'est ici que le run mourait
            dernier = "lecture interrompue: " + str(exc)[:120]
            time.sleep(3 * (essai + 1))
            continue

    raise Transient(dernier or "tentatives epuisees")


def publisher_of(a):
    """Editeur d'une archive, tel qu'il sert au plafonnement.

    winget range ses paquets en <lettre>/<Editeur>/<Produit>/..., donc le
    deuxieme segment est l'editeur. Les trois autres sources n'ont pas cette
    hierarchie : leur unite fait office d'editeur, et le plafond y rejoint
    simplement --per-unit."""
    src = a.get("source")
    unit = a.get("unit") or ""
    if src == "winget":
        parts = unit.split("/")
        return "winget:" + (parts[1] if len(parts) > 1 else unit)
    return str(src) + ":" + unit


def sample_hash(a):
    """VirusTotal et Hybrid Analysis acceptent md5, sha1 ou sha256. winget
    publie du sha256, les trois autres sources du md5."""
    return a.get("md5") or a.get("sha256")


def flatten(rows, source=None):
    out = []
    for c in rows:
        if source and c["source"] != source:
            continue
        for a in c["archives"]:
            item = dict(a)
            item["source"] = c["source"]
            item["unit"] = c["unit"]
            out.append(item)
    return out


# ============================================================ verify

HA_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"

# Verdicts Hybrid Analysis consideres comme une accusation. "no specific threat"
# et "whitelisted" sont des acquittements ; l'absence de rapport n'est ni l'un
# ni l'autre, c'est un troisieme etat.
HA_BAD = {"malicious", "suspicious"}
HA_OK = {"no specific threat", "whitelisted"}


def ha_lookup(md5, key, debug=False):
    """Renvoie ('flagged'|'clean'|'unknown', detail) ou leve Transient.

    Meme discipline que le vote de packing : une source qui n'a pas repondu ne
    vote pas. Un refus passager leve une exception et n'ecrit rien, sinon la
    reprise prendrait le silence pour un acquittement."""
    try:
        r = session().post(HA_URL,
                           headers={"api-key": key,
                                    "accept": "application/json",
                                    "User-Agent": "Falcon Sandbox"},
                           data={"hash": md5}, timeout=60)
    except Exception as exc:
        raise Transient("reseau: " + str(exc))

    if r.status_code in (429, 500, 502, 503, 504):
        raise Transient("HTTP " + str(r.status_code))
    if r.status_code == 403:
        raise Permanent("cle refusee: " + r.text[:120])
    if r.status_code != 200:
        raise Transient("HTTP " + str(r.status_code))

    try:
        reports = r.json()
    except Exception:
        raise Transient("reponse illisible")

    if debug:
        print("  [debug] premiere reponse Hybrid Analysis, a verifier :")
        print("  " + json.dumps(reports, ensure_ascii=False)[:600])

    if not isinstance(reports, list):
        reports = [reports] if reports else []
    if not reports:
        return "unknown", None      # inconnu du service, pas un acquittement

    verdicts = []
    worst_av = 0
    for rep in reports:
        if not isinstance(rep, dict):
            continue
        v = (rep.get("verdict") or "").strip().lower()
        if v:
            verdicts.append(v)
        try:
            worst_av = max(worst_av, int(rep.get("av_detect") or 0))
        except (TypeError, ValueError):
            pass

    detail = {"verdicts": verdicts, "av_detect": worst_av}
    if any(v in HA_BAD for v in verdicts) or worst_av > 10:
        return "flagged", detail
    if any(v in HA_OK for v in verdicts):
        return "clean", detail
    return "unknown", detail


def combine(vt, ha):
    """Vote a deux sources, meme regle que le packing : une accusation suffit.
    Une source sans donnee ne vote pas ; si aucune n'a de donnee le resultat est
    'unknown', jamais 'clean'."""
    votes = [v for v in (vt, ha) if v is not None]
    if not votes:
        return None                 # non mesure
    if "flagged" in votes:
        return "flagged"
    if "clean" in votes:
        return "clean"
    return "unknown"


class KeyPool:
    """Cles a quotas inegaux. Une cle qui rend 429 est mise de cote pour un
    temps croissant ; une cle refusee est retiree definitivement.

    Distinguer les deux compte : un quota epuise revient demain, une cle
    invalide ne reviendra jamais, et les confondre fait soit boucler dans le
    vide, soit jeter une cle qui marche."""

    def __init__(self, keys, per_minute=4.0):
        self.keys = list(keys)
        self.blocked = {}          # cle -> instant de reveil
        self.dead = set()          # cles refusees, retirees definitivement
        self.used = {k: 0 for k in self.keys}
        self.interval = 60.0 / per_minute
        self.last = {k: 0.0 for k in self.keys}
        self.idx = 0

    def alive(self):
        now = time.time()
        return [k for k in self.keys
                if k not in self.dead and self.blocked.get(k, 0) <= now]

    def acquire(self):
        """Rend une cle utilisable, en attendant si necessaire. None si toutes
        sont mortes."""
        while True:
            if not [k for k in self.keys if k not in self.dead]:
                return None
            ready = self.alive()
            if ready:
                now = time.time()
                ready.sort(key=lambda k: self.last[k])
                k = ready[0]
                wait = self.interval - (now - self.last[k])
                if wait > 0:
                    time.sleep(wait)
                self.last[k] = time.time()
                self.used[k] += 1
                return k
            # toutes bloquees : attendre le premier reveil
            wake = min(self.blocked[k] for k in self.keys if k not in self.dead)
            delay = max(1.0, wake - time.time())
            print("  toutes les cles sont au repos, reprise dans " +
                  str(int(delay)) + " s", flush=True)
            time.sleep(min(delay, 60))

    def block(self, key, seconds):
        self.blocked[key] = time.time() + seconds

    def kill(self, key, why):
        self.dead.add(key)
        print("  cle retiree (" + why + "), il en reste " +
              str(len([k for k in self.keys if k not in self.dead])), flush=True)

    def report(self):
        live = [k for k in self.keys if k not in self.dead]
        total = sum(self.used.values())
        print("")
        print(str(total) + " requetes reparties sur " + str(len(live)) +
              " cles vivantes, " + str(len(self.dead)) + " retirees")


def cmd_verify(args):
    rows = jsonl_read(args.out / "candidates.jsonl")
    if not rows:
        sys.exit("lance d'abord : index")
    archives = [a for a in flatten(rows, args.source)
                if a.get("md5") or a.get("sha256")]

    vpath = args.out / "vt.jsonl"
    seen = {v["md5"] for v in jsonl_read(vpath)}
    todo = [a for a in archives if sample_hash(a) not in seen]

    # VirusTotal gratuit plafonne a 500 requetes par jour et par cle, ce qui
    # rend la verification exhaustive impossible a cette echelle. On tire donc
    # un echantillon ALEATOIRE, reproductible par sa graine, et l'article
    # rapporte le taux de contamination observe avec son intervalle plutot que
    # de laisser croire a un controle complet.
    if args.sample and len(todo) > args.sample:
        random.seed(args.sample_seed)
        todo = random.sample(todo, args.sample)
        print("echantillon aleatoire de " + str(len(todo)) +
              " archives (graine " + str(args.sample_seed) + ")")

    if args.daily_budget:
        cap = args.daily_budget * len(
            [k for k in Path(args.vt_keys).read_text().split() if k.strip()]
        ) if args.vt_keys else 0
        if cap and len(todo) > cap:
            print("budget journalier : " + str(cap) + " requetes, " +
                  str(len(todo) - cap) + " reportees a demain")
            todo = todo[:cap]

    if not args.vt_keys:
        print("aucune cle VirusTotal fournie : etape sautee.")
        print("vt_verdict restera a null, c'est-a-dire NON MESURE.")
        print("Pour tucows et SourceForge ce controle est necessaire : la")
        print("premiere heberge du logiciel malveillant historique, la seconde a")
        print("empaquete des logiciels publicitaires entre 2013 et 2016.")
        return

    keys = [k.strip() for k in Path(args.vt_keys).read_text().split() if k.strip()]
    if not keys:
        sys.exit("fichier de cles vide")
    print(str(len(keys)) + " cles, " + str(len(todo)) + " archives a controler (~" +
          str(int(len(todo) / (4.0 * len(keys)))) + " min)")

    pool = KeyPool(keys)
    i = 0
    pending = list(todo)
    while pending:
        a = pending.pop(0)
        i += 1
        key = pool.acquire()
        if key is None:
            print("  plus aucune cle utilisable : arret, " + str(len(pending) + 1) +
                  " archives non traitees. Rien de faux n'a ete ecrit.")
            break
        try:
            r = session().get(
                "https://www.virustotal.com/api/v3/files/" + sample_hash(a),
                headers={"x-apikey": key}, timeout=60)
        except Exception as exc:
            print("  reseau (" + str(exc) + ") : rien consigne")
            pending.append(a)
            time.sleep(5)
            continue

        if r.status_code == 200:
            st = r.json()["data"]["attributes"]["last_analysis_stats"]
            clean = st.get("malicious", 0) == 0 and st.get("suspicious", 0) <= 2
            jsonl_append(vpath, {"md5": sample_hash(a), "unit": a["unit"],
                                 "verdict": "clean" if clean else "flagged",
                                 "stats": st})
        elif r.status_code == 404:
            # inconnu de VirusTotal : troisieme etat, ni propre ni sale
            jsonl_append(vpath, {"md5": sample_hash(a), "unit": a["unit"],
                                 "verdict": "unknown", "stats": None})
        elif r.status_code in (429, 204):
            # quota epuise pour CETTE cle : elle dort une heure, l'archive
            # repart dans la file. Rien n'est ecrit : un silence de quota n'est
            # pas un acquittement.
            pool.block(key, 3600)
            pending.append(a)
            i -= 1
            continue
        elif r.status_code in (401, 403):
            pool.kill(key, "HTTP " + str(r.status_code))
            pending.append(a)
            i -= 1
            continue
        else:
            print("  HTTP " + str(r.status_code) + " : rien consigne")
            pending.append(a)
            time.sleep(5)
            continue

        if i % 100 == 0:
            print("  [" + str(i) + "/" + str(len(todo)) + "]  cles vivantes : " +
                  str(len(pool.alive())), flush=True)
    pool.report()

    print("controle VirusTotal termine -> " + str(vpath))
    if args.ha_keys:
        verify_ha(args, archives)


def verify_ha(args, archives):
    """Second votant. Son quota gratuit est bien plus etroit que celui de
    VirusTotal, donc par defaut on ne l'interroge que la ou il apporte quelque
    chose : les archives que VirusTotal signale ou ne connait pas."""
    keys = [k.strip() for k in Path(args.ha_keys).read_text().split() if k.strip()]
    if not keys:
        print("fichier de cles Hybrid Analysis vide")
        return

    hpath = args.out / "ha.jsonl"
    seen = {v["md5"] for v in jsonl_read(hpath)}
    vt = {v["md5"]: v["verdict"] for v in jsonl_read(args.out / "vt.jsonl")}

    todo = [a for a in archives if a.get("md5") and a["md5"] not in seen]
    if not args.ha_all:
        todo = [a for a in todo if vt.get(a["md5"]) in (None, "flagged", "unknown")]
        print("Hybrid Analysis : " + str(len(todo)) + " archives (celles que "
              "VirusTotal signale ou ignore)")
    else:
        print("Hybrid Analysis : " + str(len(todo)) + " archives (toutes)")

    if todo:
        print("a " + str(args.ha_rate) + " req/min par cle sur " + str(len(keys)) +
              " cles : ~" + str(int(len(todo) / (args.ha_rate * len(keys)))) + " min")

    debug = True
    for i, a in enumerate(todo, 1):
        key = keys[i % len(keys)]
        try:
            verdict, detail = ha_lookup(a["md5"], key, debug=debug)
            debug = False
        except Transient as exc:
            print("  passager (" + str(exc) + ") : rien consigne")
            time.sleep(15)
            continue                # aucune trace : sera repris
        except Permanent as exc:
            print("  ARRET Hybrid Analysis : " + str(exc))
            return
        jsonl_append(hpath, {"md5": a["md5"], "unit": a["unit"],
                             "verdict": verdict, "detail": detail})
        if i % 50 == 0:
            print("  [" + str(i) + "/" + str(len(todo)) + "]", flush=True)
        time.sleep(60.0 / (args.ha_rate * len(keys)))

    print("controle Hybrid Analysis termine -> " + str(hpath))


# ============================================================ harvest

LAUNCHER_RE = re.compile(r"Portable\.exe$", re.I)


def blobs_from_zip(data, limit):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return None  # illisible : le fichier n'etait pas un zip
    out = []
    for name in z.namelist()[:limit]:
        try:
            info = z.getinfo(name)
            if info.file_size > 200 * 1024 * 1024:
                continue
            out.append((name, z.read(name)))
        except Exception:
            continue
    return out


def blobs_from_7z(sevenz, data, work, limit, timeout):
    """Pour un installeur NSIS ou Inno, que zipfile ne sait pas ouvrir.

    Le dossier temporaire porte le hachage du contenu et non un nom fixe. Avec un
    nom fixe, un run interrompu laisse le dossier en place ; sous Windows le
    nettoyage echoue si un fichier est encore verrouille, et la creation suivante
    leve FileExistsError. Le hachage evite aussi toute collision entre processus
    concurrents."""
    tmp = work / ("x7z_" + hashlib.sha256(data[:4096]).hexdigest()[:16])
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)
    src = tmp / "archive.bin"
    src.write_bytes(data)
    dst = tmp / "out"
    dst.mkdir(exist_ok=True)
    try:
        rc = subprocess.run([sevenz, "x", "-y", "-o" + str(dst), str(src)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=timeout)
        code = rc.returncode
    except Exception:
        code = -1
    out = []
    if code == 0:
        for dirpath, _dirs, files in os.walk(dst):
            for fn in files:
                p = Path(dirpath) / fn
                try:
                    if p.stat().st_size > 200 * 1024 * 1024:
                        continue
                    out.append((p.relative_to(dst).as_posix(), p.read_bytes()))
                except Exception:
                    continue
                if len(out) >= limit:
                    break
            if len(out) >= limit:
                break
    shutil.rmtree(tmp, ignore_errors=True)
    return out


def cmd_harvest(args):
    sevenz = find_7z()
    if not sevenz:
        print("AVERTISSEMENT : 7z introuvable. Les installeurs NSIS et Inno ne")
        print("seront pas ouverts, seuls les zip le seront. Linux : apt install")
        print("p7zip-full. Windows : 7-Zip.")
        print("")
    if not HAVE_LIEF:
        sys.exit("lief est indispensable ici : sans lui on ne peut ni filtrer "
                 "les machines ni dedupliquer par imphash. pip install lief")

    machines = {m.strip().upper() for m in args.machines.split(",") if m.strip()}

    rows = jsonl_read(args.out / "candidates.jsonl")
    if not rows:
        sys.exit("lance d'abord : index")
    archives = flatten(rows, args.source)

    vt = {v["md5"]: v["verdict"] for v in jsonl_read(args.out / "vt.jsonl")}
    ha = {v["md5"]: v["verdict"] for v in jsonl_read(args.out / "ha.jsonl")}
    verdicts = {m: combine(vt.get(m), ha.get(m)) for m in set(vt) | set(ha)}
    if args.require_clean:
        before = len(archives)
        archives = [a for a in archives if verdicts.get(sample_hash(a)) == "clean"]
        print("filtre VirusTotal : " + str(len(archives)) + "/" + str(before) +
              " archives retenues")

    idx = args.out / "harvest.jsonl"
    history = jsonl_read(idx)
    done = {r["url"] for r in history if r.get("kind") == "archive"}
    seen_sha = {r["sha256"] for r in history if r.get("kind") == "pe"}
    seen_imp = {r["imphash"] for r in history
                if r.get("kind") == "pe" and r.get("imphash")}

    todo = [a for a in archives if a["url"] not in done]

    # Plafond par editeur. Mesure sur le catalogue winget : Mozilla y occupe 443
    # paquets sur 4 994, uniquement des variantes de langue de Firefox et
    # Thunderbird. A soixante megaoctets l'installeur, cela represente une
    # vingtaine de gigaoctets telecharges pour des binaires que la deduplication
    # par sha256 ecartera ensuite. Le plafond evite la depense, pas seulement
    # le doublon.
    if args.max_per_publisher:
        par_editeur = {}
        for a in todo:
            par_editeur.setdefault(publisher_of(a), []).append(a)
        garde, ecartes = [], 0
        random.seed(0)
        for editeur, lot in sorted(par_editeur.items()):
            if len(lot) > args.max_per_publisher:
                # tirage aleatoire plutot que les N premiers : l'ordre est
                # alphabetique, prendre la tete donnerait toutes les langues
                # commencant par a
                choisis = random.sample(lot, args.max_per_publisher)
                ecartes += len(lot) - args.max_per_publisher
            else:
                choisis = lot
            garde.extend(choisis)
        if ecartes:
            gros = sorted(((len(v), k) for k, v in par_editeur.items()),
                          reverse=True)[:5]
            print("plafond par editeur (" + str(args.max_per_publisher) + ") : "
                  + str(ecartes) + " archives ecartees")
            print("  les plus reduits : " +
                  ", ".join(k + " " + str(n) for n, k in gros
                            if n > args.max_per_publisher))
        todo = garde

    random.seed(0)
    random.shuffle(todo)  # etale la charge entre unites et sources
    if args.limit:
        todo = todo[:args.limit]

    store = args.store
    store.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)

    print(str(len(done)) + " archives deja traitees, " + str(len(todo)) + " a faire")
    print(str(len(seen_sha)) + " PE deja stockes")
    print("")

    dropped_machine = 0
    dropped_size = 0
    kept_total = 0
    bytes_kept = 0

    for i, a in enumerate(todo, 1):
      # Filet large : une erreur imprevue sur UNE archive ne doit pas emporter
      # les vingt-cinq mille autres. Le run a deja ete tue une fois par une
      # coupure de connexion en cours de lecture.
      try:
        budget(args.archive_timeout)
        try:
            data = telecharger(a["url"])
        except Transient as exc:
            print("  " + a["unit"][:44] + " : passager (" + str(exc) +
                  "), rien consigne")
            continue  # aucune trace : sera repris
        except Permanent as exc:
            jsonl_append(idx, {"kind": "archive", "url": a["url"],
                               "unit": a["unit"], "error": str(exc), "kept": 0})
            continue

        if a.get("size") and abs(len(data) - a["size"]) > 4096:
            print("  " + a["unit"][:44] + " : taille inattendue, rien consigne")
            continue

        name = a["name"].lower()
        blobs = None
        if name.endswith(".zip"):
            blobs = blobs_from_zip(data, args.max_files_per_archive)
        if blobs is None:
            if sevenz:
                blobs = blobs_from_7z(sevenz, data, args.work,
                                      args.max_files_per_archive,
                                      args.extract_timeout)
            else:
                blobs = []
        # l'archive elle-meme peut etre un PE : un installeur autonome, NSIS ou
        # Inno, 32 bits et graphique. C'est structurellement le profil d'un
        # malware, ce qui est rare du cote benin.
        if args.keep_installer and is_pe(data):
            blobs = list(blobs) + [("(archive)", data)]

        candidates = []
        for rel, blob in blobs:
            if not is_pe(blob):
                continue
            is_dll, machine, imphash = pe_info(blob)
            if machine is not None and machines and machine.upper() not in machines:
                dropped_machine += 1
                continue
            if args.max_pe_mb and len(blob) > args.max_pe_mb * 1024 * 1024:
                # un plafond de taille introduit un biais de taille : il est
                # compte et affiche, jamais silencieux
                dropped_size += 1
                continue
            depth = rel.count("/")
            launcher = bool(LAUNCHER_RE.search(rel.rsplit("/", 1)[-1])) and depth <= 1
            candidates.append({"rel": rel, "blob": blob, "launcher": launcher,
                               "is_dll": is_dll, "machine": machine,
                               "imphash": imphash})

        launchers = [c for c in candidates if c["launcher"]]
        others = [c for c in candidates if not c["launcher"]]
        if args.exe_only:
            # "is False", pas "not": None veut dire non mesure, et un fichier
            # non mesure ne doit pas passer pour un executable
            others = [c for c in others if c["is_dll"] is False]
        if not args.no_prefer_exe:
            others.sort(key=lambda c: (c["is_dll"] is True, c["is_dll"] is None))

        keep = launchers[:args.launcher_cap]
        keep = keep + others[:max(0, args.per_unit - len(keep))]

        kept = 0
        for c in keep:
            sha = sha256_bytes(c["blob"])
            if sha in seen_sha:
                continue
            if args.dedupe_imphash and c["imphash"] and c["imphash"] in seen_imp:
                continue
            (store / (sha + ".bin")).write_bytes(c["blob"])
            seen_sha.add(sha)
            bytes_kept += len(c["blob"])
            if c["imphash"]:
                seen_imp.add(c["imphash"])
            jsonl_append(idx, {
                "kind": "pe",
                "sha256": sha,
                "source": a["source"],
                "unit": a["unit"],
                "archive": a["name"],
                "archive_md5": a.get("md5"),
                "archive_sha256": a.get("sha256"),
                "arch_declared": a.get("arch_declared"),
                "rel_path": c["rel"],
                "launcher": c["launcher"],
                "is_dll": c["is_dll"],
                "machine": c["machine"],
                "imphash": c["imphash"],
                "size": len(c["blob"]),
                "vt_verdict": vt.get(sample_hash(a)),   # null si non mesure
                "ha_verdict": ha.get(sample_hash(a)),   # null si non mesure
                "verdict": verdicts.get(sample_hash(a)),
            })
            kept += 1

        jsonl_append(idx, {"kind": "archive", "url": a["url"], "unit": a["unit"],
                           "error": None, "pe_found": len(candidates), "kept": kept})
        kept_total += kept
        if i % args.progress_every == 0 or kept:
            print("  [" + str(i) + "/" + str(len(todo)) + "] " +
                  a["unit"][:40].ljust(40) + " " + str(len(candidates)).rjust(3) +
                  " PE, " + str(kept).rjust(3) + " gardes  (total " +
                  str(len(seen_sha)) + ")", flush=True)
        fin_budget()
        time.sleep(args.delay)

      except KeyboardInterrupt:
        fin_budget()
        raise
      except ArchiveTropLongue:
        fin_budget()
        print("  " + str(a.get("unit", "?"))[:44] + " : abandon apres " +
              str(args.archive_timeout) + " s, rien consigne", flush=True)
        continue
      except Exception as exc:
        # l'archive est perdue, le run continue. On ne consigne rien : sans
        # savoir si la cause est passagere, ecrire un echec definitif ferait
        # sauter l'archive a la reprise alors qu'elle est peut-etre valide.
        print("  " + str(a.get("unit", "?"))[:44] + " : erreur imprevue (" +
              exc.__class__.__name__ + ": " + str(exc)[:90] +
              "), rien consigne", flush=True)
        continue

    print("")
    print(str(kept_total) + " nouveaux PE. Stock : " + str(len(seen_sha)))
    if dropped_machine:
        print(str(dropped_machine) + " PE ecartes par le filtre de machine (" +
              args.machines + ") - Windows CE, ARM, MIPS")
    if dropped_size:
        print(str(dropped_size) + " PE ecartes par le plafond de taille (" +
              str(args.max_pe_mb) + " Mo) - BIAIS DE TAILLE a documenter")
    if kept_total:
        print("")
        print(str(round(bytes_kept / 1e9, 2)) + " Go ecrits, soit " +
              str(round(bytes_kept / 1e6 / kept_total, 2)) + " Mo par PE.")
        print("Projection a 34 000 PE : " +
              str(round(34000 * bytes_kept / kept_total / 1e9, 1)) + " Go.")


# ============================================================ report

def cmd_report(args):
    rows = [r for r in jsonl_read(args.out / "harvest.jsonl")
            if r.get("kind") == "pe"]
    if not rows:
        sys.exit("rien a resumer : lance d'abord harvest")
    n = len(rows)

    def line(label, k, target=None):
        s = "  " + label.ljust(22) + str(k).rjust(7) + "  " + \
            (str(round(100.0 * k / n, 1)) + " %").rjust(7)
        if target:
            s += "   cible " + target
        print(s)

    print(str(n) + " PE, " + str(len({r["unit"] for r in rows})) + " unites, " +
          str(len({r["source"] for r in rows})) + " sources")
    print("")
    line("EXE", sum(1 for r in rows if r["is_dll"] is False), "68 %")
    line("DLL", sum(1 for r in rows if r["is_dll"] is True), "32 %")
    unknown = sum(1 for r in rows if r["is_dll"] is None)
    if unknown:
        line("non mesure", unknown)
    print("")
    line("32 bits", sum(1 for r in rows if r["machine"] == "I386"), "80 %")
    line("64 bits", sum(1 for r in rows if r["machine"] in ("AMD64", "ARM64")))
    print("")
    line("verifie propre", sum(1 for r in rows if r.get("verdict") == "clean"))
    line("inconnu des deux", sum(1 for r in rows if r.get("verdict") == "unknown"))
    line("non verifie", sum(1 for r in rows if r.get("verdict") is None))
    line("  par VirusTotal", sum(1 for r in rows if r.get("vt_verdict") == "clean"))
    line("  par Hybrid Anal.", sum(1 for r in rows if r.get("ha_verdict") == "clean"))

    total_bytes = sum(r["size"] for r in rows)
    print("")
    print("  volume         " + str(round(total_bytes / 1e9, 2)).rjust(9) +
          " Go   " + str(round(total_bytes / 1e6 / n, 2)) + " Mo par PE")
    print("")
    print("  par source :")
    for src, k in Counter(r["source"] for r in rows).most_common():
        sub = [r for r in rows if r["source"] == src]
        exe = sum(1 for r in sub if r["is_dll"] is False)
        print("    " + str(k).rjust(7) + "  " + src.ljust(16) + " dont " +
              str(round(100.0 * exe / len(sub), 1)) + " % EXE")

    print("")
    print("  unites les plus representees :")
    for unit, k in Counter(r["unit"] for r in rows).most_common(6):
        print("    " + str(k).rjust(5) + "  " + unit[:60])


# ============================================================ cli

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("benign_collect"))
    ap.add_argument("--store", type=Path, default=Path("benign_collect/pe"))
    ap.add_argument("--work", type=Path, default=Path("benign_collect/work"))
    ap.add_argument("--delay", type=float, default=0.5,
                    help="pause entre requetes, par courtoisie")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover")
    p.add_argument("--source",
                   choices=["portableapps", "archive", "sourceforge", "winget"],
                   required=True)
    p.add_argument("--winget-repo",
                   help="source winget : chemin d'un clone superficiel de "
                        "microsoft/winget-pkgs")
    p.add_argument("--projects",
                   help="source sourceforge : fichier listant les identifiants "
                        "de projets, un par ligne. SourceForge bloque toute "
                        "enumeration, la liste doit donc etre fournie.")
    p.add_argument("--collection", default="tucows",
                   help="collection archive.org (defaut tucows : 32 312 items, "
                        "partagiciels Windows, 0,62 PE par item, ~100 %% EXE)")
    p.add_argument("--max-items", type=int, default=0)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("index")
    p.add_argument("--source",
                   choices=["portableapps", "archive", "sourceforge", "winget"])
    p.add_argument("--keep-recent", type=int, default=1,
                   help="portableapps : versions recentes par application")
    p.add_argument("--keep-old", type=int, default=1,
                   help="portableapps : versions anciennes, pour la diversite "
                        "d'epoque de compilation")
    p.add_argument("--winget-x86-only", action="store_true",
                   help="source winget : ne garder que les installeurs declares "
                        "x86. C'est la seule source ou l'architecture est connue "
                        "avant telechargement.")
    p.add_argument("--archives-per-item", type=int, default=1,
                   help="archive.org : archives par item")
    p.add_argument("--max-archive-mb", type=int, default=200)
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("verify")
    p.add_argument("--source",
                   choices=["portableapps", "archive", "sourceforge", "winget"])
    p.add_argument("--vt-keys", help="fichier de cles VirusTotal, une par ligne")
    p.add_argument("--ha-keys", help="fichier de cles Hybrid Analysis, une par "
                                     "ligne. Second votant.")
    p.add_argument("--ha-rate", type=float, default=3.0,
                   help="requetes par minute et par cle Hybrid Analysis "
                        "(defaut 3, prudent : leur quota gratuit est etroit)")
    p.add_argument("--sample", type=int, default=0,
                   help="ne verifier qu'un echantillon aleatoire de N archives. "
                        "VirusTotal gratuit plafonne a 500 requetes par jour et "
                        "par cle : a 33 000 archives la verification exhaustive "
                        "demanderait 66 jours-cle.")
    p.add_argument("--sample-seed", type=int, default=0,
                   help="graine de l'echantillon, pour qu'il soit reproductible")
    p.add_argument("--daily-budget", type=int, default=0,
                   help="requetes VirusTotal par cle et par jour (500 pour un "
                        "compte gratuit). Arrete avant d'epuiser le quota.")
    p.add_argument("--ha-all", action="store_true",
                   help="interroger Hybrid Analysis pour TOUTES les archives et "
                        "pas seulement celles que VirusTotal signale ou ignore")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("harvest")
    p.add_argument("--source",
                   choices=["portableapps", "archive", "sourceforge", "winget"])
    p.add_argument("--per-unit", type=int, default=30,
                   help="PE maximum par unite, contre la correlation intra-paquet")
    p.add_argument("--launcher-cap", type=int, default=0,
                   help="lanceurs <Nom>Portable.exe gardes, 0 = exclus")
    p.add_argument("--machines", default=DEFAULT_MACHINES,
                   help="machines acceptees (defaut I386,AMD64 : ecarte le "
                        "Windows CE ARM et MIPS de tucows)")
    p.add_argument("--exe-only", action="store_true")
    p.add_argument("--no-prefer-exe", action="store_true")
    p.add_argument("--dedupe-imphash", action="store_true", default=True)
    p.add_argument("--keep-installer", action="store_true", default=True)
    p.add_argument("--no-keep-installer", dest="keep_installer",
                   action="store_false")
    p.add_argument("--require-clean", action="store_true",
                   help="ne garder que les archives verdict=clean")
    p.add_argument("--max-pe-mb", type=int, default=0,
                   help="ecarter les PE au-dessus de N Mo, 0 = aucun plafond. "
                        "Introduit un biais de taille : le compte est affiche")
    p.add_argument("--max-per-publisher", type=int, default=20,
                   help="archives maximum par editeur. Sur winget, Mozilla "
                        "occupe 443 paquets sur 4994, toutes des variantes de "
                        "langue. 0 pour desactiver le plafond.")
    p.add_argument("--max-files-per-archive", type=int, default=400)
    p.add_argument("--archive-timeout", type=int, default=420,
                   help="budget total par archive, telechargement et extraction "
                        "compris. Au-dela on abandonne et on passe a la "
                        "suivante, sans rien consigner.")
    p.add_argument("--extract-timeout", type=int, default=600)
    p.add_argument("--progress-every", type=int, default=25)
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_harvest)

    p = sub.add_parser("report")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
