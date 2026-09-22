#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter_clean.py - ne garder que les PE benins verdict "clean"

Lit les verdicts de verify_pe_ha.py et deplace hors du stock tout ce qui n'est
pas "clean". Le deplacement, plutot que la suppression, rend la decision
reversible : les fichiers ecartes restent sur disque dans un dossier a part, et
un seul --restore les remet en place.

CE QUE VOUS PERDEZ, ET IL FAUT LE SAVOIR
----------------------------------------
Sur les premiers echantillons mesures, la repartition est :
  clean     48 %   Hybrid Analysis connait le fichier et ne le signale pas
  unknown   44 %   le service ne l'a jamais vu
  disputed   8 %   accuse par le verdict global, pas par les moteurs
  flagged    0 %

Ecarter les "unknown" retire pres de la moitie du corpus. Ces fichiers ne sont
pas suspects : personne n'a simplement soumis le printf.exe d'OpenVPN a un bac a
sable d'analyse de malwares. Le corpus restant sera donc constitue de logiciels
que quelqu'un a juge utile de faire analyser, ce qui n'est pas un echantillon
representatif de logiciel benin.

C'est une decision assumee, pas un defaut du script. Elle doit figurer dans
l'article : le nombre d'ecartes, leur verdict, et la graine si un tirage
intervient.

UTILISATION
-----------
  --dry-run     compte sans rien deplacer  (par defaut)
  --apply       deplace reellement
  --restore     remet tout en place
  --keep        verdicts a conserver, par defaut "clean" seul
"""

import argparse
import json
import shutil
import sys
from collections import Counter
from pathlib import Path


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
                pass
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", type=Path, default=Path("benign_collect/pe"))
    ap.add_argument("--verdicts", type=Path,
                    default=Path("benign_collect/ha_pe.jsonl"))
    ap.add_argument("--aside", type=Path,
                    default=Path("benign_collect/pe_ecartes"),
                    help="dossier ou sont deplaces les fichiers non retenus")
    ap.add_argument("--features", type=Path,
                    default=Path("benign_collect/features"),
                    help="les JSON correspondants sont deplaces aussi")
    ap.add_argument("--keep", default="clean",
                    help="verdicts conserves, separes par des virgules "
                         "(ex: clean,unknown)")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restore", action="store_true")
    args = ap.parse_args()

    if not args.store.is_dir():
        sys.exit("dossier introuvable : %s" % args.store)

    # ------------------------------------------------------------ restore
    if args.restore:
        if not args.aside.is_dir():
            sys.exit("rien a restaurer : %s n'existe pas" % args.aside)
        n = 0
        for p in args.aside.iterdir():
            if p.is_file():
                shutil.move(str(p), str(args.store / p.name))
                n += 1
        fa = args.aside.parent / (args.features.name + "_ecartes")
        m = 0
        if fa.is_dir():
            for p in fa.iterdir():
                if p.is_file():
                    shutil.move(str(p), str(args.features / p.name))
                    m += 1
        print("%d PE et %d features remis en place" % (n, m))
        return

    # ------------------------------------------------------------ filtrage
    garder = {v.strip() for v in args.keep.split(",") if v.strip()}
    verdicts = {r["sha256"]: r["verdict"] for r in jsonl_read(args.verdicts)}

    if not verdicts:
        sys.exit("aucun verdict dans %s : lance d'abord verify_pe_ha.py"
                 % args.verdicts)

    fichiers = [p for p in args.store.iterdir()
                if p.is_file() and p.suffix == ".bin"]

    compte = Counter()
    a_ecarter = []
    for p in fichiers:
        v = verdicts.get(p.stem)
        if v is None:
            # pas encore verifie : on ne touche a rien. Un fichier non mesure
            # n'est pas un fichier rejete.
            compte["non verifie"] += 1
            continue
        compte[v] += 1
        if v not in garder:
            a_ecarter.append((p, v))

    n = len(fichiers)
    print("%d PE dans le stock" % n)
    for k, v in compte.most_common():
        print("  %-12s %5d  %5.1f %%" % (k, v, 100.0 * v / max(n, 1)))
    print("")
    print("verdicts conserves : %s" % ", ".join(sorted(garder)))
    print("a ecarter          : %d fichiers  (%.1f %%)"
          % (len(a_ecarter), 100.0 * len(a_ecarter) / max(n, 1)))
    print("non verifies       : %d, laisses en place"
          % compte.get("non verifie", 0))

    if not args.apply:
        print("")
        print("Rien n'a ete deplace. Ajoute --apply pour appliquer.")
        return

    args.aside.mkdir(parents=True, exist_ok=True)
    fa = args.aside.parent / (args.features.name + "_ecartes")
    fa.mkdir(parents=True, exist_ok=True)

    deplaces = 0
    feat_deplaces = 0
    for p, v in a_ecarter:
        try:
            shutil.move(str(p), str(args.aside / p.name))
            deplaces += 1
        except Exception as exc:
            print("  echec sur %s : %s" % (p.name, exc))
            continue
        fj = args.features / (p.stem + ".json")
        if fj.exists():
            try:
                shutil.move(str(fj), str(fa / fj.name))
                feat_deplaces += 1
            except Exception:
                pass

    print("")
    print("%d PE deplaces vers %s" % (deplaces, args.aside))
    print("%d features deplacees vers %s" % (feat_deplaces, fa))
    print("")
    print("Pour annuler : --restore")
    print("Pour l'article : %d fichiers ecartes sur %d, repartition ci-dessus."
          % (deplaces, n))


if __name__ == "__main__":
    main()
