#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_benign.py - extraction des features sur les PE benins deja collectes

POURQUOI UN SCRIPT SEPARE
-------------------------
cluster_all_in_one.py part d'une liste de MD5 a telecharger : acquisition,
extraction, vote de packing et capa se font en une passe, puis le binaire est
supprime. Les PE benins, eux, sont deja sur disque et on les GARDE. Il faut donc
la meme analyse, mais sans l'etage d'acquisition.

CE QUI N'EST PAS DUPLIQUE
-------------------------
Ce script n'ecrit aucune logique d'extraction. Il importe extract_features et
check_sample depuis cluster_all_in_one, exactement les fonctions qui produisent
le cote malware. C'est la seule facon d'etre sur que les deux moities du jeu de
donnees portent les memes colonnes : une reimplementation, meme fidele au depart,
divergerait a la premiere correction appliquee d'un seul cote.

Consequence pratique : ce script doit tourner avec le meme cluster_all_in_one.py
que le corpus malware. Le manifeste enregistre les versions pour que l'ecart soit
detectable plutot que silencieux.

REPRISE
-------
Un fichier dont le JSON existe deja est saute. L'ecriture est atomique, par
fichier temporaire puis renommage : un arret brutal ne laisse jamais un JSON
tronque qui serait ensuite pris pour un resultat acquis.
"""

import argparse
import gzip
import json
import os
import sys
import time
import traceback
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import cluster_all_in_one as C
except Exception as exc:
    sys.exit("impossible d'importer cluster_all_in_one.py : %s\n"
             "Ce script doit vivre a cote de lui." % exc)

import shutil


# --------------------------------------------------------------- ecriture

class Writer:
    """Un enregistrement par ligne, gzip. L'ajout est sur : gzip concatene deux
    flux valides en un flux valide, donc une reprise n'invalide pas le fichier
    deja ecrit."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._deja = self._lire_faits()

    def _lire_faits(self):
        faits = set()
        if not self.path.exists():
            return faits
        try:
            with gzip.open(self.path, "rt", encoding="utf-8",
                           errors="replace") as fh:
                for ligne in fh:
                    ligne = ligne.strip()
                    if not ligne:
                        continue
                    try:
                        faits.add(json.loads(ligne)["sha256"])
                    except Exception:
                        pass  # ligne tronquee par un arret brutal
        except Exception:
            pass
        return faits

    def done(self):
        return self._deja

    def write(self, rec):
        with gzip.open(self.path, "at", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
        self._deja.add(rec["sha256"])


# --------------------------------------------------------------- traitement

def traiter(chemin, feat_dir, faire_controle):
    """Analyse un fichier. Renvoie l'enregistrement de controle, ou None si
    seules les features etaient demandees."""
    sha = chemin.stem
    rec = {"sha256": sha, "label": "benign", "source": "collecte_benigne",
           "path": chemin.name, "analysed_at": time.strftime("%Y-%m-%dT%H:%M:%S")}

    try:
        data = chemin.read_bytes()
    except Exception as exc:
        rec["features"] = "read error"
        rec["error"] = str(exc)[:200]
        return rec

    rec["size"] = len(data)

    # --- sortie 1 : les features statiques
    feat_out = Path(feat_dir) / (sha + ".json")
    if feat_out.exists():
        rec["features"] = "already there"
    else:
        try:
            facts = C.extract_features(sha, "benign", data)
            tmp = feat_out.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(C._json_safe(facts), indent=2),
                           encoding="utf-8")
            tmp.replace(feat_out)            # ecriture atomique
            rec["features"] = "ok"
        except Exception as exc:
            # pe_parsed reste faux et l'echantillon est trace : un PE illisible
            # est un fait a consigner, pas un fichier a faire disparaitre
            rec["features"] = "error"
            rec["error"] = (str(exc) or exc.__class__.__name__)[:300]
            return rec

    # --- sortie 2 : vote de packing et capa
    if faire_controle:
        try:
            rec.update(C.check_sample(chemin))
            rec["status"] = "ok"
        except Exception as exc:
            rec["status"] = "check error"
            rec["error"] = (str(exc) or exc.__class__.__name__)[:300]
    else:
        rec["status"] = "features only"
    return rec


# --------------------------------------------------------------- principal

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", type=Path, default=Path("benign_collect/pe"),
                    help="dossier des PE, nommes <sha256>.bin")
    ap.add_argument("--features-out", type=Path,
                    default=Path("benign_collect/features"))
    ap.add_argument("--check-out", type=Path,
                    default=Path("benign_collect/check/results.jsonl.gz"))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--shard", default="",
                    help="k/n : traite un echantillon sur n, par pas et non "
                         "par blocs, pour que chaque tache voie le meme melange")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-check", action="store_true",
                    help="features seulement, sans vote de packing ni capa")
    ap.add_argument("--no-capa", action="store_true")
    ap.add_argument("--no-yara", action="store_true")
    ap.add_argument("--manalyze", default=os.environ.get("MANALYZE_CMD",
                                                         "manalyze"))
    ap.add_argument("--capa-cmd", default=os.environ.get("CAPA_CMD", "capa"))
    ap.add_argument("--capa-rules", default=os.environ.get("CAPA_RULES", ""))
    ap.add_argument("--capa-sigs", default=os.environ.get("CAPA_SIGS", ""))
    ap.add_argument("--capa-timeout", type=int, default=600)
    ap.add_argument("--tool-timeout", type=int, default=300)
    ap.add_argument("--only-verdict", default="",
                   help="ne traiter que les fichiers dont le verdict Hybrid "
                        "Analysis figure dans cette liste, ex: clean. Un "
                        "fichier PAS ENCORE verifie est saute, pas rejete : il "
                        "sera pris au passage suivant, une fois son verdict "
                        "connu.")
    ap.add_argument("--verdicts", type=Path,
                   default=Path("benign_collect/ha_pe.jsonl"),
                   help="fichier de verdicts produit par verify_pe_ha.py")
    ap.add_argument("--progress-every", type=int, default=100)
    ap.add_argument("--match-manifest",
                    help="manifeste du run malware. Le script refuse de "
                         "demarrer si ses options produiraient des colonnes "
                         "differentes.")
    args = ap.parse_args()

    if not args.store.is_dir():
        sys.exit("dossier introuvable : %s" % args.store)

    # --- concordance avec le cote malware --------------------------------
    # Lancer les deux moities avec des drapeaux differents ne produit AUCUNE
    # erreur : simplement deux vocabulaires de colonnes sous un meme schema.
    # L'erreur a ete faite pendant la mise au point, elle n'a ete vue qu'en
    # comparant les blocs a la main.
    if args.match_manifest:
        try:
            ref = json.loads(Path(args.match_manifest).read_text(encoding="utf-8"))
        except Exception as exc:
            sys.exit("manifeste de reference illisible : %s" % exc)

        ecarts = []
        if bool(ref.get("yara_enabled")) != (not args.no_yara):
            ecarts.append("yara : malware=%s, ici=%s"
                          % (ref.get("yara_enabled"), not args.no_yara))
        if bool(ref.get("capa_enabled")) != (not args.no_capa):
            ecarts.append("capa : malware=%s, ici=%s"
                          % (ref.get("capa_enabled"), not args.no_capa))

        ref_lief = (ref.get("tool_versions") or {}).get("lief")
        ici_lief = getattr(C.lief, "__version__", None)
        if ref_lief and ici_lief and ref_lief != ici_lief:
            ecarts.append("lief : malware=%s, ici=%s" % (ref_lief, ici_lief))

        if ecarts:
            print("REFUS : les deux moities du corpus n'auraient pas les memes")
            print("colonnes. Ecarts constates :")
            for e in ecarts:
                print("   " + e)
            print("")
            print("Aligne les options, ou retire --match-manifest si la")
            print("difference est voulue et documentee.")
            sys.exit(2)
        print("concordance : options alignees sur %s" % args.match_manifest)

    # --- configuration des modules importes -----------------------------
    # On regle les globales de cluster_all_in_one comme le ferait son propre
    # main(). Les modifier ici plutot que de reimplementer garantit que les deux
    # cotes du corpus passent par le meme code.
    C.MANALYZE_CMD = args.manalyze.split()
    C.CAPA_CMD = args.capa_cmd.split()
    C.CAPA_RULES = args.capa_rules
    C.CAPA_SIGS = args.capa_sigs
    C.CAPA_TIMEOUT = args.capa_timeout
    C.TOOL_TIMEOUT = args.tool_timeout
    C.CAPA_ENABLED = not args.no_capa
    C.NO_YARA = args.no_yara

    faire_controle = not args.no_check

    if faire_controle:
        manquants = []
        for nom in C.VOTERS:
            cmd = C.MANALYZE_CMD[0] if nom == "manalyze" else nom
            if not (shutil.which(cmd) or Path(cmd).exists()):
                manquants.append("%s (%s)" % (nom, cmd))
        if manquants:
            sys.exit("outils introuvables : " + ", ".join(manquants))
        if C.CAPA_ENABLED and not (shutil.which(C.CAPA_CMD[0])
                                   or Path(C.CAPA_CMD[0]).exists()):
            sys.exit("capa introuvable : %s" % C.CAPA_CMD[0])

    # --- regles YARA -----------------------------------------------------
    if args.no_yara:
        C._yara_rules = None
        print("yara       : DESACTIVE (--no-yara)")
    elif C.yara_manager:
        try:
            regles = C.yara_manager.setup_yara_rules()
            regles.save(C.YARA_COMPILED)
            C._yara_rules = C.yara.load(C.YARA_COMPILED)
            print("yara       : regles compilees")
        except Exception as exc:
            print("yara       : indisponible (%s)" % exc)
    else:
        print("yara       : yara_manager absent")

    print("capa       : %s" % (C.CAPA_CMD[0] if C.CAPA_ENABLED
                               else "DESACTIVE (--no-capa)"))
    if faire_controle:
        print("votants    : %s   regle : un seul oui suffit"
              % ", ".join(C.VOTERS))
    else:
        print("controle   : DESACTIVE (--no-check)")

    # --- inventaire ------------------------------------------------------
    args.features_out.mkdir(parents=True, exist_ok=True)
    writer = Writer(args.check_out) if faire_controle else None

    fichiers = sorted(p for p in args.store.iterdir()
                      if p.is_file() and p.suffix == ".bin")

    if args.shard:
        k, n = (int(x) for x in args.shard.split("/"))
        # par pas et non par blocs : la liste est triee par hachage, donc un
        # bloc contigu donnerait a chaque tache une population differente
        fichiers = fichiers[k::n]

    if faire_controle:
        deja = writer.done()
        todo = [p for p in fichiers if p.stem not in deja]
    else:
        todo = [p for p in fichiers
                if not (args.features_out / (p.stem + ".json")).exists()]

    # Filtre sur le verdict. Un fichier sans verdict n'est PAS rejete : il est
    # simplement saute, et la boucle le reprendra une fois verifie. Confondre
    # "pas encore mesure" et "rejete" ferait disparaitre definitivement des
    # fichiers valides.
    verdicts = {}
    n_sans_verdict = 0
    if args.only_verdict:
        garder = {v.strip() for v in args.only_verdict.split(",") if v.strip()}
        if not args.verdicts.exists():
            sys.exit("--only-verdict demande mais %s n'existe pas. Lance "
                     "verify_pe_ha.py d'abord." % args.verdicts)
        with open(args.verdicts, encoding="utf-8") as fh:
            for ligne in fh:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    r = json.loads(ligne)
                    verdicts[r["sha256"]] = r["verdict"]
                except Exception:
                    pass
        avant = len(todo)
        retenus = []
        for p in todo:
            v = verdicts.get(p.stem)
            if v is None:
                n_sans_verdict += 1
            elif v in garder:
                retenus.append(p)
        todo = retenus
        print("filtre     : verdict dans {%s}  ->  %d retenus sur %d"
              % (", ".join(sorted(garder)), len(todo), avant))
        print("             %d pas encore verifies, sautes pour ce passage"
              % n_sans_verdict)

    if args.limit:
        todo = todo[:args.limit]

    print("stock      : %d fichiers%s"
          % (len(fichiers), "  (shard %s)" % args.shard if args.shard else ""))
    print("a traiter  : %d" % len(todo))
    print("features   : %s/<sha256>.json" % args.features_out)
    if faire_controle:
        print("controle   : %s" % args.check_out)
    print("")

    # --- manifeste -------------------------------------------------------
    try:
        manifeste = {
            "role": "extraction des PE benins",
            "shard": args.shard or "1/1",
            "store": str(args.store),
            "n_files": len(fichiers),
            "check_enabled": faire_controle,
            "yara_enabled": not args.no_yara,
            "capa_enabled": bool(C.CAPA_ENABLED),
            "voters": list(C.VOTERS) if faire_controle else [],
            "packing_rule": "any_ge_1" if faire_controle else None,
            "blocks_omitted": [] if not args.no_yara else ["advanced_yara"],
            "tool_versions": {
                "python": sys.version.split()[0],
                "lief": getattr(C.lief, "__version__", None),
                "tlsh": "present" if C.tlsh else "absent",
                "capa_cmd": C.CAPA_CMD[0] if C.CAPA_ENABLED else None,
                "manalyze_cmd": C.MANALYZE_CMD[0],
            },
            "note": ("extract_features et check_sample sont importes de "
                     "cluster_all_in_one.py, pas reimplementes : les deux "
                     "moities du corpus portent donc les memes colonnes."),
        }
        mp = args.features_out / ("_manifest_%s.json"
                                  % (args.shard or "all").replace("/", "of"))
        mp.write_text(json.dumps(manifeste, indent=1, ensure_ascii=False),
                      encoding="utf-8")
        print("manifeste  : %s\n" % mp)
    except Exception as exc:
        print("manifeste  : non ecrit (%s)\n" % exc)

    if not todo:
        return

    # --- traitement ------------------------------------------------------
    compte = Counter()
    fait = 0
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futurs = {pool.submit(traiter, p, args.features_out, faire_controle): p
                  for p in todo}
        for fut in as_completed(futurs):
            p = futurs[fut]
            try:
                rec = fut.result()
            except Exception as exc:
                rec = {"sha256": p.stem, "label": "benign",
                       "features": "crashed",
                       "error": traceback.format_exc(limit=2)[:300]}
            if writer:
                writer.write(rec)
            cle = rec.get("verdict") or rec.get("features") or "?"
            compte[cle] += 1
            fait += 1
            if fait % args.progress_every == 0:
                debit = fait / max(time.time() - t0, 1e-9) * 60
                reste = (len(todo) - fait) / max(debit, 1e-9) / 60
                print("  %d/%d  %s  %.1f/min  ~%.1f h"
                      % (fait, len(todo), dict(compte), debit, reste),
                      flush=True)

    print("")
    print("termine : %s" % dict(compte))
    print("features : %s" % args.features_out)
    if faire_controle:
        print("controle : %s" % args.check_out)


if __name__ == "__main__":
    main()
