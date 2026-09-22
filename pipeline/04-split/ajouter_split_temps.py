# -*- coding: utf-8 -*-
"""
Ajoute une colonne `split_temps` a decoupages.parquet : un decoupage hors-temps.

Le principe
-----------
Les trois protocoles existants decoupent le corpus dans l espace : au hasard,
par code compile, par famille. Celui-ci le decoupe dans le TEMPS -- on entraine
sur le passe et on teste sur l avenir, ce qui est la situation reelle d un
antivirus.

Le champ utilise
----------------
`annee_compilation`, l horodatage du lieur. C est le seul champ de date
renseigne pour les deux classes : `date_premiere_vue` couvre 19,7 % des
malwares et 0 % des benins, donc il ne peut pas servir a decouper.

Ce choix a un cout qu il faut ecrire dans l article : l horodatage de
compilation est ECRIT PAR L AUTEUR DU BINAIRE. Un malware peut le falsifier, et
beaucoup le font. C est une garantie temporelle plus faible qu une date de
premiere observation. L etude ecarte d ailleurs ces colonnes des features, pour
cette raison meme ; les utiliser pour DECOUPER est une autre affaire, et c est
ce que fait EMBER.

La coupure
----------
    train       <= 2022
    validation  == 2023
    test        >= 2024

Elle est choisie parce que sa validation est la moins desequilibree des
coupures possibles (86,7 % de positifs, contre 93,9 % pour une coupure en
2021). Le seuil de decision se choisit sur la validation : une validation a
93,9 % de positifs deplacerait le seuil pour toutes les taches.

Les fichiers sans date
----------------------
15 784 fichiers n ont pas d annee de compilation. Ils recoivent `null`, pas
`train` : une date absente n est pas une date ancienne.

  python ajouter_split_temps.py --donnees "Dataset parquet"
"""
import os, shutil, argparse
import numpy as np, pandas as pd
import pyarrow.parquet as pq


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--fin-train', type=int, default=2022)
    ap.add_argument('--annee-val', type=int, default=2023)
    ap.add_argument('--colonne', default='split_temps')
    ap.add_argument('--simuler', action='store_true',
                    help='afficher le resultat sans rien ecrire')
    a = ap.parse_args()

    p_dec = os.path.join(a.donnees, 'decoupages.parquet')
    dec = pq.read_table(p_dec).to_pandas()
    gi = pq.read_table(os.path.join(a.donnees, 'general_info.parquet'),
                       columns=['sha256', 'annee_compilation']).to_pandas()

    # On aligne sur decoupages.parquet, pas l inverse : c est lui qui fixe
    # l ordre des lignes pour toute l etude.
    m = dec[['sha256', 'label']].merge(gi, on='sha256', how='left')
    assert len(m) == len(dec), 'la jointure a change le nombre de lignes'
    an = pd.to_numeric(m.annee_compilation, errors='coerce')

    s = pd.Series([None] * len(dec), dtype=object)
    s[an <= a.fin_train] = 'train'
    s[an == a.annee_val] = 'val'
    s[an > a.annee_val] = 'test'

    print('coupure : train <= %d, validation = %d, test >= %d'
          % (a.fin_train, a.annee_val, a.annee_val + 1))
    print()
    for nom in ('train', 'val', 'test'):
        q = s == nom
        n = int(q.sum())
        pos = float((m.label[q] == 'malware').mean()) if n else float('nan')
        print('  %-6s %7d fichiers   %5.1f %% de positifs' % (nom, n, 100 * pos))
    nul = int(s.isna().sum())
    print('  %-6s %7d fichiers   sans annee de compilation' % ('null', nul))
    print()

    # Un protocole temporel n a de sens que si les deux classes sont des deux
    # cotes ; sinon le modele apprendrait a repondre la classe majoritaire.
    for nom in ('train', 'val', 'test'):
        q = s == nom
        v = m.label[q].value_counts()
        if len(v) < 2:
            raise SystemExit('ARRET : %s ne contient qu une seule classe' % nom)
        print('  %-6s benin %6d   malware %6d' % (nom, v.get('benign', 0), v.get('malware', 0)))

    if a.simuler:
        print('\n--simuler : rien n a ete ecrit')
        return

    if a.colonne in dec.columns:
        print('\nla colonne %s existe deja, elle est remplacee' % a.colonne)
    dec[a.colonne] = s.values

    # Une sauvegarde avant d ecrire : decoupages.parquet est lu par l etude, par
    # le carnet de figures et par la serialisation pour le modele de langue.
    sauve = os.path.join(a.donnees, 'decoupages_avant_temps.parquet')
    if not os.path.exists(sauve):
        shutil.copy2(p_dec, sauve)
        print('sauvegarde : %s' % sauve)
    dec.to_parquet(p_dec, index=False)
    print('ecrit : %s  (%d colonnes)' % (p_dec, len(dec.columns)))


if __name__ == '__main__':
    main()
