# -*- coding: utf-8 -*-
"""
Recalcule `anti_analysis` sur les six mecanismes, packer exclu.

Ce qui etait faux
-----------------
`ajouter_capa.py` ecrivait :

    any(v.startswith('anti-analysis') for v in namespaces)

`anti-analysis/packer` commence par `anti-analysis`, donc un fichier simplement
empaquete devenait positif pour l anti-analyse. Or le packing est une TACHE
SEPAREE de l etude : les deux etiquettes partageaient une partie de leur
definition, et un modele entraine sur l une apprenait en partie l autre.

La regle correcte
-----------------
Les six categories de `CAT`, sans `packer` :

    anti-vm, anti-debugging, anti-forensic, anti-disasm, anti-av, obfuscation

Un empaqueteur n est pas une defense contre l analyse, c est une technique de
distribution. L obfuscation, elle, en est une : elle vise le lecteur.

Effet mesure
------------
    49 284 positifs  ->  28 421

Trois etats, toujours
---------------------
Un fichier sans rapport capa exploitable reste `null`. Un `null` n est pas un
`False` : capa n a pas regarde, il n a pas conclu que le fichier ne fait rien.

  python corriger_anti_analysis.py --donnees "Dataset parquet"
"""
import os, gzip, json, glob, shutil, argparse
import numpy as np, pandas as pd
import pyarrow as pa, pyarrow.parquet as pq

SIX = ('anti-analysis/anti-vm',
       'anti-analysis/anti-debugging',
       'anti-analysis/anti-forensic',
       'anti-analysis/anti-disasm',
       'anti-analysis/anti-av',
       'anti-analysis/obfuscation')


def lire_capa(rep_jsonl):
    """sha256 -> liste de namespaces, pour tout rapport capa exploitable."""
    ns = {}
    fichiers = glob.glob(os.path.join(rep_jsonl, '**', '*.jsonl.gz'), recursive=True)
    for p in fichiers:
        with gzip.open(p, 'rt', encoding='utf-8', errors='replace') as f:
            for ln in f:
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                s, cr = r.get('sha256'), r.get('capa_report')
                if not s or not isinstance(cr, dict) or cr.get('status') != 'ok':
                    continue
                if cr.get('namespaces') is not None:
                    ns[s] = cr['namespaces']
    return ns, len(fichiers)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--jsonl', default=os.path.join('corpus', 'resultats_meta'))
    ap.add_argument('--simuler', action='store_true')
    a = ap.parse_args()

    ns, nf = lire_capa(a.jsonl)
    print('%d fichiers jsonl.gz lus, %d sha256 avec un rapport exploitable' % (nf, len(ns)))

    for nom in ('decoupages.parquet', 'familles.parquet'):
        p = os.path.join(a.donnees, nom)
        if not os.path.exists(p):
            print('absent, ignore : %s' % nom)
            continue
        d = pq.read_table(p).to_pandas()
        if 'anti_analysis' not in d.columns:
            print('pas de colonne anti_analysis dans %s' % nom)
            continue

        avant = d.anti_analysis
        nouveau = []
        for s in d.sha256:
            v = ns.get(s)
            # `null` quand capa n a pas rendu de rapport exploitable. Ne jamais
            # ecrire False par defaut : ce serait affirmer une absence mesuree.
            nouveau.append(None if v is None
                           else any(x.startswith(k) for x in v for k in SIX))
        apres = pd.array(nouveau, dtype='boolean')

        def compte(s):
            return ((s == True).sum(), (s == False).sum(), s.isna().sum())

        va, fa, na = compte(avant)
        vn, fn_, nn = compte(pd.Series(apres))
        print()
        print('%s' % nom)
        print('  avant : True %6d | False %6d | null %6d' % (va, fa, na))
        print('  apres : True %6d | False %6d | null %6d' % (vn, fn_, nn))
        print('  %+d positifs' % (vn - va))

        if a.simuler:
            continue
        sauv = p.replace('.parquet', '_avant_six.parquet')
        if not os.path.exists(sauv):
            shutil.copy2(p, sauv)
            print('  sauvegarde : %s' % os.path.basename(sauv))
        d['anti_analysis'] = apres
        pq.write_table(pa.Table.from_pandas(d, preserve_index=False), p)
        print('  ecrit : %s' % p)

    if a.simuler:
        print('\n--simuler : rien n a ete ecrit')


if __name__ == '__main__':
    main()
