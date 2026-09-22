# -*- coding: utf-8 -*-
"""Selectionne des PE legitimes installes localement, EXE et DLL en nombre egal.

Le corpus benin penche deja lourdement vers la DLL : 86 pour cent des fichiers
de Program Files en sont, contre 29 pour cent chez les malwares. Prendre tout
creuserait le confondant de format qu'on a mesure a AUC 0,9055. On prend donc
autant de DLL que d'EXE, et les DLL sont tirees en tourniquet sur les editeurs
pour qu'un seul gros logiciel n'en fournisse pas la moitie.

Ecrit selection.jsonl : un enregistrement par fichier retenu, avec son sha256,
son editeur et son chemin d'origine. Sans ce manifeste la source ne serait plus
identifiable une fois les fichiers renommes par empreinte.
"""

import argparse
import collections
import hashlib
import io
import json
import os
import random
import shutil
from pathlib import Path

RACINES = [Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)")]


def editeur(chemin, racine):
    """Le premier niveau sous Program Files : Mozilla Firefox, 7-Zip, Git..."""
    try:
        rel = chemin.relative_to(racine)
    except ValueError:
        return "?"
    return rel.parts[0] if rel.parts else "?"


def sha256(chemin, taille_bloc=1 << 20):
    h = hashlib.sha256()
    with open(chemin, "rb") as fh:
        while True:
            b = fh.read(taille_bloc)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def est_pe(chemin):
    """Verifie la signature MZ. Une extension ne prouve rien."""
    try:
        with open(chemin, "rb") as fh:
            return fh.read(2) == b"MZ"
    except Exception:
        return False


def recenser(max_mo):
    plafond = max_mo * 1024 * 1024
    exe, dll = [], []
    for racine in RACINES:
        if not racine.exists():
            continue
        for dossier, _, fichiers in os.walk(racine):
            for nom in fichiers:
                bas = nom.lower()
                if not (bas.endswith(".exe") or bas.endswith(".dll")):
                    continue
                p = Path(dossier) / nom
                try:
                    if p.stat().st_size > plafond or p.stat().st_size < 1024:
                        continue
                except OSError:
                    continue
                if not est_pe(p):
                    continue
                (exe if bas.endswith(".exe") else dll).append((p, editeur(p, racine)))
    return exe, dll


def tourniquet(items, combien, graine, max_par_editeur=None):
    """Tire en alternant les editeurs, pour qu'aucun ne domine la selection.

    max_par_editeur reprend le meme plafond que la collecte distante
    (--max-per-publisher 20) : sans lui, un seul SDK ou une seule suite
    d'outils peut a elle seule fournir la moitie de la selection locale.
    """
    par_editeur = collections.defaultdict(list)
    for p, ed in items:
        par_editeur[ed].append(p)
    rnd = random.Random(graine)
    for ed in par_editeur:
        rnd.shuffle(par_editeur[ed])
        if max_par_editeur:
            par_editeur[ed] = par_editeur[ed][:max_par_editeur]
    ordre = sorted(par_editeur, key=lambda e: -len(par_editeur[e]))
    choix, i = [], 0
    while len(choix) < combien:
        avance = False
        for ed in ordre:
            if i < len(par_editeur[ed]):
                choix.append((par_editeur[ed][i], ed))
                avance = True
                if len(choix) >= combien:
                    break
        if not avance:
            break
        i += 1
    return choix


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-pe-mb", type=float, default=10.0,
                    help="meme plafond que la collecte distante (defaut 10)")
    ap.add_argument("--sortie", default="benign_local")
    ap.add_argument("--max-per-publisher", type=int, default=20,
                    help="meme plafond que la collecte distante (defaut 20, 0 pour desactiver)")
    ap.add_argument("--graine", type=int, default=20260903)
    ap.add_argument("--copier", action="store_true",
                    help="sans ce drapeau, rien n est copie : on ne fait que recenser")
    a = ap.parse_args()

    exe, dll = recenser(a.max_pe_mb)
    print("recenses (<= %.0f Mo, signature MZ verifiee)" % a.max_pe_mb)
    print("  exe : %d" % len(exe))
    print("  dll : %d" % len(dll))

    plafond = a.max_per_publisher or None
    # Le plafond par editeur s'applique separement aux deux reservoirs : avec
    # bien moins d'exe que de dll disponibles dans Program Files, il vide le
    # reservoir exe plus vite. Tirer d'abord sans limite de compte pour
    # mesurer ce qu'il reste de chaque cote, puis egaliser sur le plus petit.
    dispo_exe = tourniquet(exe, len(exe), a.graine, plafond)
    dispo_dll = tourniquet(dll, len(dll), a.graine + 1, plafond)
    n = min(len(dispo_exe), len(dispo_dll))
    pris_exe = dispo_exe[:n]
    pris_dll = dispo_dll[:n]
    pris = pris_exe + pris_dll
    print("retenus : %d exe + %d dll = %d" % (len(pris_exe), len(pris_dll), len(pris)))

    part = collections.Counter(ed for _, ed in pris)
    print("editeurs distincts : %d" % len(part))
    print("les cinq plus fournis :")
    for ed, c in part.most_common(5):
        print("  %-40s %4d  (%.1f%%)" % (ed[:40], c, 100.0 * c / len(pris)))

    dest = Path(a.sortie)
    if a.copier:
        dest.mkdir(parents=True, exist_ok=True)
    vus, lignes, doublons = set(), [], 0
    for p, ed in pris:
        try:
            h = sha256(p)
        except Exception as exc:
            print("illisible : %s (%s)" % (p, exc))
            continue
        if h in vus:
            doublons += 1
            continue
        vus.add(h)
        lignes.append({"sha256": h, "source": "local_program_files",
                       "publisher": ed, "path": str(p),
                       "kind": "dll" if p.suffix.lower() == ".dll" else "exe",
                       "size": p.stat().st_size})
        if a.copier:
            cible = dest / (h + ".bin")
            if not cible.exists():
                shutil.copy2(p, cible)

    with io.open(Path(a.sortie + "_selection.jsonl"), "w", encoding="utf-8") as fh:
        for r in lignes:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    octets = sum(r["size"] for r in lignes)
    print("---")
    print("uniques : %d   doublons ecartes : %d" % (len(lignes), doublons))
    print("volume  : %.0f Mo" % (octets / 1024.0 / 1024.0))
    print("manifeste : %s_selection.jsonl" % a.sortie)
    print("copie   : %s" % ("faite dans " + str(dest) if a.copier
                            else "AUCUNE (ajouter --copier)"))


if __name__ == "__main__":
    main()
