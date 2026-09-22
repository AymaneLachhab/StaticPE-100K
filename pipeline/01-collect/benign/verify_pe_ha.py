#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_pe_ha.py - controle des PE benins sur Hybrid Analysis, par SHA-256

POURQUOI CE SCRIPT
------------------
VirusTotal gratuit plafonne a 500 requetes par jour et par cle, ce qui rend la
verification exhaustive impossible a l'echelle du corpus. Hybrid Analysis
annonce, dans l'en-tete api-limits de chaque reponse, 200 requetes par minute et
2 000 par heure, sans plafond journalier. Trois cles suffisent donc a controler
trente mille fichiers en quelques heures.

POURQUOI LES FICHIERS ET NON LES ARCHIVES
-----------------------------------------
L'endpoint /api/v2/overview/ n'accepte que le SHA-256 : teste avec un MD5 il
repond "This value is not valid". Or trois des quatre sources de collecte ne
publient qu'un MD5 pour leurs archives.

Les PE moissonnes, eux, sont nommes par leur SHA-256. On verifie donc les
fichiers plutot que leurs conteneurs, ce qui est de toute facon plus precis :
un installeur propre pourrait contenir un binaire signale.

CE QUE LE VERDICT VEUT DIRE
---------------------------
  clean     Hybrid Analysis connait le fichier et ne le signale pas, ou le place
            explicitement en liste blanche.
  flagged   verdict malicious ou suspicious, ou une part notable des moteurs le
            signale.
  unknown   le service ne connait pas ce hachage. Ce n'est PAS un acquittement :
            la plupart des logiciels benins ne lui ont jamais ete soumis.

La distinction entre "clean" et "unknown" est le coeur du script. Les confondre
transformerait une absence de donnee en preuve d'innocence.

REPRISE
-------
Le fichier de sortie est lu au demarrage et les hachages deja controles sont
sautes. Un refus passager n'ecrit rien : une trace posee par un echec transitoire
serait prise pour un resultat acquis a la reprise.
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("pip install requests")


HA_OVERVIEW = "https://www.hybrid-analysis.com/api/v2/overview/"
UA = "Falcon Sandbox"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Verdicts consideres comme une accusation. "no specific threat" et
# "whitelisted" sont des acquittements ; l'absence de rapport n'est ni l'un
# ni l'autre.
HA_BAD = {"malicious", "suspicious"}
HA_OK = {"no specific threat", "whitelisted"}


class Transient(Exception):
    """Refus passager. N'ecrit rien, sera retente."""


class Permanent(Exception):
    """Cle refusee. Retire la cle du pool."""


# --------------------------------------------------------------- pool de cles

class KeyPool:
    """Cles a quotas separes.

    Hybrid Analysis annonce ses limites dans l'en-tete api-limits de chaque
    reponse, sous la forme {"limits":{"minute":200,"hour":2000},"used":{...}}.
    On les lit plutot que de les supposer : si le service change ses quotas, le
    script suit sans modification."""

    def __init__(self, keys, per_minute):
        self.keys = list(keys)
        self.dead = set()
        self.blocked = {}
        self.used = {k: 0 for k in self.keys}
        self.interval = 60.0 / max(per_minute, 0.1)
        self.last = {k: 0.0 for k in self.keys}
        self.limits = {}

    def vivantes(self):
        now = time.time()
        return [k for k in self.keys
                if k not in self.dead and self.blocked.get(k, 0) <= now]

    def acquire(self):
        while True:
            restantes = [k for k in self.keys if k not in self.dead]
            if not restantes:
                return None
            pretes = self.vivantes()
            if pretes:
                pretes.sort(key=lambda k: self.last[k])
                k = pretes[0]
                attente = self.interval - (time.time() - self.last[k])
                if attente > 0:
                    time.sleep(attente)
                self.last[k] = time.time()
                self.used[k] += 1
                return k
            reveil = min(self.blocked[k] for k in restantes)
            delai = max(1.0, reveil - time.time())
            print("  toutes les cles au repos, reprise dans %d s" % int(delai),
                  flush=True)
            time.sleep(min(delai, 60))

    def block(self, key, seconds):
        self.blocked[key] = time.time() + seconds

    def kill(self, key, why):
        self.dead.add(key)
        vivantes = len([k for k in self.keys if k not in self.dead])
        print("  cle retiree (%s), il en reste %d" % (why, vivantes), flush=True)

    def note_limits(self, key, header):
        """Enregistre les quotas annonces par le service, pour les afficher."""
        if not header:
            return
        try:
            self.limits[key] = json.loads(header)
        except Exception:
            pass

    def report(self):
        vivantes = [k for k in self.keys if k not in self.dead]
        print("")
        print("%d requetes sur %d cles vivantes, %d retirees"
              % (sum(self.used.values()), len(vivantes), len(self.dead)))
        for k in vivantes[:5]:
            lim = self.limits.get(k)
            if lim:
                print("  %s...  limites %s  utilise %s"
                      % (k[:10], lim.get("limits"), lim.get("used")))


# --------------------------------------------------------------- utilitaires

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
        for ligne in fh:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                out.append(json.loads(ligne))
            except json.JSONDecodeError:
                pass  # ligne tronquee par un arret brutal
    return out


def lire_hachages(store):
    """Les PE sont nommes <sha256>.bin. On ne fait pas confiance au nom : il est
    valide contre le motif attendu, sinon un fichier egare passerait pour un
    hachage."""
    out = []
    for p in Path(store).iterdir():
        if not p.is_file():
            continue
        nom = p.stem
        if SHA256_RE.match(nom):
            out.append(nom)
    return sorted(set(out))


def interpreter(d, seuil_multiscan):
    """Traduit un rapport en (verdict, detail).

    Un verdict malveillant isole ne suffit pas. Le premier fichier signale par
    ce script etait Squirrel.exe, l'installeur standard des applications
    Electron, sous la famille Trojan_Win32_Wacatac_C_ml : une signature
    d'apprentissage automatique connue pour ses faux positifs sur les
    installeurs et les empaqueteurs. Son multiscan valait 4 : quatre pour cent
    des moteurs le signalaient, quatre-vingt-seize le laissaient passer.

    La regle exige donc un accord entre moteurs, et n'ecrase pas le desaccord :
    un verdict malveillant que le multiscan ne soutient pas devient "disputed",
    consigne a part. C'est la meme discipline que le vote de packing, ou un
    seul votant ne tranche pas et ou l'indecision porte son propre nom."""
    verdict_brut = (d.get("verdict") or "").strip().lower()
    liste_blanche = d.get("whitelisted")
    multiscan = d.get("multiscan_result")
    try:
        multiscan = int(multiscan) if multiscan is not None else None
    except (TypeError, ValueError):
        multiscan = None

    detail = {
        "verdict_brut": verdict_brut or None,
        "whitelisted": liste_blanche,
        "multiscan_result": multiscan,
        "vx_family": d.get("vx_family"),
        "type_short": d.get("type_short"),
        "size": d.get("size"),
    }

    accuse = verdict_brut in HA_BAD
    soutenu = multiscan is not None and multiscan >= seuil_multiscan

    # une part notable de moteurs s'accorde : accusation retenue, que le
    # verdict global suive ou non
    if soutenu:
        return "flagged", detail

    if accuse:
        # accusation sans soutien des moteurs. On ne la retient pas, on ne
        # l'efface pas non plus : elle porte son propre etat.
        detail["raison"] = ("verdict %s mais multiscan %s, sous le seuil de %d"
                            % (verdict_brut, multiscan, seuil_multiscan))
        return "disputed", detail

    if liste_blanche is True:
        return "clean", detail
    if verdict_brut in HA_OK:
        return "clean", detail

    # rapport present mais sans verdict exploitable : ni l'un ni l'autre
    return "unknown", detail


def interroger(session, sha, key, seuil):
    """Renvoie (verdict, detail, entete_limites) ou leve."""
    try:
        r = session.get(HA_OVERVIEW + sha,
                        headers={"api-key": key, "User-Agent": UA,
                                 "accept": "application/json"},
                        timeout=60)
    except Exception as exc:
        raise Transient("reseau: " + str(exc))

    entete = r.headers.get("api-limits")

    if r.status_code == 200:
        try:
            d = r.json()
        except Exception:
            raise Transient("reponse illisible")
        v, detail = interpreter(d, seuil)
        return v, detail, entete

    if r.status_code == 404:
        # inconnu du service : troisieme etat, jamais un acquittement
        return "unknown", {"raison": "hachage inconnu de Hybrid Analysis"}, entete

    if r.status_code in (401, 403):
        raise Permanent("HTTP %d %s" % (r.status_code, r.text[:80]))

    if r.status_code == 429:
        raise Transient("quota")

    if r.status_code in (500, 502, 503, 504):
        raise Transient("HTTP %d" % r.status_code)

    raise Transient("HTTP %d %s" % (r.status_code, r.text[:80]))


# --------------------------------------------------------------- principal

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", type=Path, default=Path("benign_collect/pe"),
                    help="dossier des PE nommes <sha256>.bin")
    ap.add_argument("--out", type=Path, default=Path("benign_collect/ha_pe.jsonl"))
    ap.add_argument("--keys", default="ha_keys.txt",
                    help="fichier de cles Hybrid Analysis, une par ligne")
    ap.add_argument("--rate", type=float, default=100.0,
                    help="requetes par minute et par cle. Le service en annonce "
                         "200 ; le defaut reste en dessous par courtoisie.")
    ap.add_argument("--multiscan-threshold", type=int, default=10,
                    help="part de moteurs signalant le fichier au-dela de "
                         "laquelle il est declare flagged (defaut 10 %%)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--progress-every", type=int, default=200)
    args = ap.parse_args()

    if not args.store.is_dir():
        sys.exit("dossier introuvable : %s" % args.store)

    cles = [l.strip() for l in Path(args.keys).read_text().split() if l.strip()]
    if not cles:
        sys.exit("aucune cle dans %s" % args.keys)

    tous = lire_hachages(args.store)
    deja = {r["sha256"] for r in jsonl_read(args.out)}
    todo = [h for h in tous if h not in deja]
    if args.limit:
        todo = todo[:args.limit]

    debit = args.rate * len(cles)
    print("%d PE dans le stock, %d deja controles, %d a faire"
          % (len(tous), len(deja), len(todo)))
    print("%d cles a %.0f req/min : ~%.0f par minute, soit %.1f h"
          % (len(cles), args.rate, debit, len(todo) / max(debit, 1) / 60))
    print("sortie : %s" % args.out)
    print("")

    if not todo:
        return

    pool = KeyPool(cles, args.rate)
    session = requests.Session()
    compte = Counter()
    fait = 0
    en_attente = list(todo)

    while en_attente:
        sha = en_attente.pop(0)
        key = pool.acquire()
        if key is None:
            print("plus aucune cle utilisable : arret, %d fichiers non traites. "
                  "Rien de faux n'a ete ecrit." % (len(en_attente) + 1))
            break
        try:
            verdict, detail, entete = interroger(
                session, sha, key, args.multiscan_threshold)
            pool.note_limits(key, entete)
        except Transient as exc:
            # rien n'est ecrit : le silence d'un quota n'est pas un acquittement
            if "quota" in str(exc):
                pool.block(key, 300)
            en_attente.append(sha)
            time.sleep(2)
            continue
        except Permanent as exc:
            pool.kill(key, str(exc))
            en_attente.append(sha)
            continue

        jsonl_append(args.out, {"sha256": sha, "verdict": verdict,
                                "detail": detail, "source": "hybrid-analysis"})
        compte[verdict] += 1
        fait += 1
        if fait % args.progress_every == 0:
            print("  %d/%d  %s  (%d cles vivantes)"
                  % (fait, len(todo), dict(compte), len(pool.vivantes())),
                  flush=True)

    pool.report()
    print("")
    print("verdicts : %s" % dict(compte))
    total = sum(compte.values())
    if total:
        inconnus = compte.get("unknown", 0)
        litiges = compte.get("disputed", 0)
        print("%.1f %% inconnus du service. Rappel : inconnu n'est pas propre."
              % (100.0 * inconnus / total))
        if litiges:
            print("%.1f %% en litige : accuses par le verdict global mais pas "
                  "par les moteurs. A trancher, pas a ignorer."
                  % (100.0 * litiges / total))


if __name__ == "__main__":
    main()
