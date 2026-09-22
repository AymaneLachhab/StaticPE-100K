# -*- coding: utf-8 -*-
"""
Remplace les quinze etiquettes de menace par la cartographie tracee.

Ce qui change
-------------
Les etiquettes actuelles viennent de deux fichiers : une table de 306 familles
sans aucune reference, qui fournit 41 006 assignations, et une cartographie
manuelle de 22 familles, sourcee mais ecrasee par la premiere a cause de
l ordre de priorite de `finaliser_etiquettes.py`.

La nouvelle cartographie repose sur trois sources publiques, conserve pour
chaque assignation son URL et la phrase qui l a justifiee, et couvre 60 275
malwares contre 49 845.

Le conflit de priorite est supprime
-----------------------------------
L ancien script faisait primer la table non sourcee sur la recherche manuelle
verifiee : Qakbot perdait `keylogger` et `worm` alors que trois references les
documentaient. Ici il n y a plus de priorite, seulement une union : une
categorie est retenue des qu une source la documente, et toutes les sources
sont conservees dans la trace.

Ce qui ne change pas
--------------------
`packing` et `anti_analysis` sont mesurees sur le fichier et ne dependent
d aucune famille. Elles ne sont pas touchees.

La discipline a trois etats non plus. Un malware sans famille, ou dont la
famille n est dans aucune source, garde `null` sur les quinze colonnes : il
est exclu de la tache, pas compte comme negatif.

  python appliquer_cartographie.py --simuler
  python appliquer_cartographie.py
"""
import os, shutil, argparse
import pandas as pd
import pyarrow as pa, pyarrow.parquet as pq

QUINZE = ['stealer', 'loader', 'banker', 'rat', 'ransomware', 'botnet', 'worm',
          'keylogger', 'miner', 'fileinfector', 'backdoor', 'postexploitation',
          'clipper', 'downloader', 'adware']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--cartographie', default='cartographie.parquet')
    ap.add_argument('--min-sources', type=int, default=1,
                    help='2 ou 3 pour ne garder que les assignations confirmees')
    ap.add_argument('--simuler', action='store_true')
    a = ap.parse_args()

    c = pd.read_parquet(a.cartographie)
    c = c[c.categorie.isin(QUINZE)]
    # Une assignation peut etre soutenue par plusieurs sources. On compte les
    # sources distinctes, ce qui permet d exiger une confirmation croisee.
    n_src = c.groupby(['famille', 'categorie']).source.nunique()
    retenues = n_src[n_src >= a.min_sources].reset_index()
    carte = retenues.groupby('famille').categorie.apply(set).to_dict()
    print('cartographie : %d familles, %d assignations retenues (>= %d source(s))'
          % (len(carte), len(retenues), a.min_sources))

    p = os.path.join(a.donnees, 'familles.parquet')
    f = pq.read_table(p).to_pandas()
    fam = f.family.map(lambda x: str(x).lower() if isinstance(x, str) else None)

    avant = {c_: int((f[c_] == True).sum()) for c_ in f.columns  # noqa: E712
             if c_.startswith('menace_')}

    est_mal = f.label.values == 'malware'
    nouveau = {}
    for cat in QUINZE:
        col = 'menace_' + cat
        v = []
        for i, nom in enumerate(fam):
            # null pour tout ce qui n est pas un malware cartographie : un
            # benin n herite de rien, et un malware dont la famille est
            # inconnue n est pas un negatif, il est non mesure.
            if not est_mal[i] or nom is None or nom not in carte:
                v.append(None)
            else:
                v.append(cat in carte[nom])
        nouveau[col] = pd.array(v, dtype='boolean')

    etq = pd.DataFrame(nouveau).notna().any(axis=1)
    print('malwares portant au moins une etiquette : %d sur %d'
          % (int(etq.sum()), int(est_mal.sum())))
    print()
    print('%-17s %9s %9s %9s' % ('categorie', 'avant', 'apres', 'variation'))
    for cat in QUINZE:
        col = 'menace_' + cat
        av, ap_ = avant.get(col, 0), int((nouveau[col] == True).sum())  # noqa: E712
        print('%-17s %9d %9d %+9d' % (cat, av, ap_, ap_ - av))

    if a.simuler:
        print('\n--simuler : rien n a ete ecrit')
        return

    for col, v in nouveau.items():
        f[col] = v
    # La provenance de l etiquette devient une colonne du corpus : c est ce que
    # l article reproche aux autres jeux de donnees de ne pas publier.
    f['source_comportement'] = [('cartographie' if (est_mal[i] and nom in carte) else None)
                                for i, nom in enumerate(fam)]

    sauve = os.path.join(a.donnees, 'familles_avant_cartographie.parquet')
    if not os.path.exists(sauve):
        shutil.copy2(p, sauve)
        print('\nsauvegarde : %s' % os.path.basename(sauve))
    pq.write_table(pa.Table.from_pandas(f, preserve_index=False), p)
    print('ecrit : %s' % p)

    # decoupages.parquet porte une copie des memes colonnes, lue par l etude.
    p2 = os.path.join(a.donnees, 'decoupages.parquet')
    if os.path.exists(p2):
        d = pq.read_table(p2).to_pandas()
        if 'menace_stealer' in d.columns:
            m = dict(zip(f.sha256, range(len(f))))
            idx = [m.get(s) for s in d.sha256]
            for col in nouveau:
                d[col] = pd.array([nouveau[col][i] if i is not None else None
                                   for i in idx], dtype='boolean')
            sauve2 = os.path.join(a.donnees, 'decoupages_avant_cartographie.parquet')
            if not os.path.exists(sauve2):
                shutil.copy2(p2, sauve2)
            pq.write_table(pa.Table.from_pandas(d, preserve_index=False), p2)
            print('ecrit : %s' % p2)


if __name__ == '__main__':
    main()
