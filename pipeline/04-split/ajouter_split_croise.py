# -*- coding: utf-8 -*-
"""
Ajoute `split_croise` a decoupages.parquet : entrainer sur les EXE, tester sur
les DLL.

Ce qu il teste
--------------
L introduction de l article ouvre sur le type de fichier comme raccourci. Le
corpus le porte encore : 69,6 % des benins sont des DLL contre 22,8 % des
malveillants. Un modele peut donc separer les classes en reconnaissant le type
de fichier, sans rien apprendre du programme.

Ce protocole le met a l epreuve : le modele ne voit que des EXE a l entrainement
et n est juge que sur des DLL. Si son score tenait au type de fichier, il tombe.

La coupure
----------
    train       EXE, 85 %
    validation  EXE, 15 %
    test        toutes les DLL

La validation reste du cote EXE, avec l entrainement. Choisir le seuil sur des
DLL reviendrait a calibrer sur la distribution de test, ce que les trois autres
protocoles s interdisent.

Ce qu il faut ecrire dans l article
-----------------------------------
Le taux de positifs passe de 92,6 % sur les EXE a 61,7 % sur les DLL. Une part
de la chute vient de ce decalage de base, pas du raccourci. Le classifieur
constant doit etre donne des deux cotes, sans quoi la mesure est illisible.

Les fichiers qui ne sont ni EXE ni DLL recoivent `null`, jamais `train`.

  python ajouter_split_croise.py --donnees "Dataset parquet"
"""
import os, shutil, argparse
import numpy as np, pandas as pd
import pyarrow as pa, pyarrow.parquet as pq

GRAINE = 20260908


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--part-val', type=float, default=0.15)
    ap.add_argument('--colonne', default='split_croise')
    ap.add_argument('--simuler', action='store_true')
    a = ap.parse_args()

    p_dec = os.path.join(a.donnees, 'decoupages.parquet')
    dec = pq.read_table(p_dec).to_pandas()
    gi = pq.read_table(os.path.join(a.donnees, 'general_info.parquet'),
                       columns=['sha256', 'general_info__file_type']).to_pandas()

    m = dec[['sha256', 'label']].merge(gi, on='sha256', how='left')
    assert len(m) == len(dec), 'la jointure a change le nombre de lignes'
    t = m.general_info__file_type.astype(str).str.lower()

    s = pd.Series([None] * len(dec), dtype=object)
    est_exe, est_dll = (t == 'exe').values, (t == 'dll').values

    # La validation est tiree parmi les EXE, stratifiee sur la classe, pour que
    # le seuil ne soit pas choisi sur une population plus deseequilibree que
    # celle qui a servi a l entrainement.
    rng = np.random.default_rng(GRAINE)
    idx_exe = np.flatnonzero(est_exe)
    val = np.zeros(len(dec), bool)
    for cls in ('malware', 'benign'):
        ii = idx_exe[(m.label.values[idx_exe] == cls)]
        k = int(round(a.part_val * len(ii)))
        val[rng.choice(ii, size=k, replace=False)] = True

    s[est_exe] = 'train'
    s[val] = 'val'
    s[est_dll] = 'test'

    print('coupure : train + validation sur les EXE, test sur les DLL')
    print()
    for nom in ('train', 'val', 'test'):
        q = (s == nom).values
        n = int(q.sum())
        v = m.label[q].value_counts()
        print('  %-6s %7d fichiers   %5.1f %% de positifs   benin %6d  malware %6d'
              % (nom, n, 100 * (m.label[q] == 'malware').mean(),
                 v.get('benign', 0), v.get('malware', 0)))
        if len(v) < 2:
            raise SystemExit('ARRET : %s ne contient qu une seule classe' % nom)
    ni = int(s.isna().sum())
    print('  %-6s %7d fichiers   ni EXE ni DLL' % ('null', ni))

    if a.simuler:
        print('\n--simuler : rien n a ete ecrit')
        return

    if a.colonne in dec.columns:
        print('\nla colonne %s existe deja, elle est remplacee' % a.colonne)
    dec[a.colonne] = s.values
    sauve = os.path.join(a.donnees, 'decoupages_avant_croise.parquet')
    if not os.path.exists(sauve):
        shutil.copy2(p_dec, sauve)
        print('sauvegarde : %s' % os.path.basename(sauve))
    pq.write_table(pa.Table.from_pandas(dec, preserve_index=False), p_dec)
    print('ecrit : %s  (%d colonnes)' % (p_dec, len(dec.columns)))


if __name__ == '__main__':
    main()
