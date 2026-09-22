"""
Audit de fuite de provenance, colonne par colonne.

La question
-----------
Une colonne separe malware et benign. Mais separe-t-elle parce que les
programmes sont differents, ou parce que nos deux corpus n'ont pas ete
produits par les memes outils, a la meme epoque, pour la meme architecture ?

La methode
----------
On decoupe le corpus en strates homogenes -- meme type de fichier, meme
architecture, meme technologie (.NET ou natif), meme tranche de quatre ans --
puis on mesure l'AUC de chaque colonne A L'INTERIEUR de chaque strate. Dans une
strate, tous les echantillons partagent le contexte : ce qui reste separable ne
peut plus etre attribue au contexte.

  auc_globale      mesuree sur tout l'ensemble d'entrainement
  auc_conditionnelle  moyenne des AUC par strate, ponderee par la taille
  chute            auc_globale - auc_conditionnelle

Une chute forte veut dire : cette colonne mesurait le groupe, pas la classe.
Une colonne qui garde son pouvoir en strate mesure quelque chose de reel.

Precautions
-----------
  - tout est calcule sur l'ENTRAINEMENT seul ; le test ne participe pas au
    choix des colonnes, sinon le score final est complaisant ;
  - une strate ne compte que si elle contient au moins MIN_STRATE echantillons
    ET les deux classes, sinon l'AUC n'a pas de sens ;
  - on rapporte aussi la couverture : combien d'echantillons ont reellement
    servi a mesurer cette colonne. Une colonne renseignee 200 fois peut
    afficher une AUC flatteuse sans rien valoir.

L'horodatage sert ici a DEFINIR les strates. Il est exclu des features, parce
que la ou il mesure l'epoque, il ne mesure pas le programme ; mais c'est
justement pour cela qu'il fait une bonne variable de stratification.

  python audit.py                 tache malware
  python audit.py --tache packing
"""
import os, json, csv, argparse, datetime, collections
import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import roc_auc_score

RACINE = os.path.dirname(os.path.abspath(__file__))
MIN_STRATE = 300          # en dessous, l'AUC d'une strate est du bruit
MIN_CLASSE = 30           # il faut assez des deux classes
COUVERTURE_MIN = 0.10     # une colonne vue sur moins de 10 % ne se juge pas


def strate(ft, machine, dotnet, ts):
    """Type de fichier x architecture x technologie x tranche de 4 ans."""
    try:
        an = datetime.datetime.utcfromtimestamp(int(ts)).year
        if not (1995 <= an <= 2026):
            an = None
    except Exception:
        an = None
    ere = ('%d-%d' % (4 * (an // 4), 4 * (an // 4) + 3)) if an else 'sans date'
    return '%s|%s|%s|%s' % (ft or '?', machine or '?',
                            'dotnet' if dotnet else 'natif', ere)


def auc_sure(y, x):
    """AUC sur les lignes ou la colonne est renseignee. Renvoie aussi le
    nombre de lignes utilisees : c'est lui qui dit si l'AUC veut dire quelque
    chose."""
    m = np.isfinite(x)
    if m.sum() < MIN_CLASSE * 2:
        return None, int(m.sum())
    yy = y[m]
    if yy.min() == yy.max():
        return None, int(m.sum())
    if int(yy.sum()) < MIN_CLASSE or int((1 - yy).sum()) < MIN_CLASSE:
        return None, int(m.sum())
    try:
        return float(roc_auc_score(yy, x[m])), int(m.sum())
    except Exception:
        return None, int(m.sum())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--racine', default=os.path.join(os.path.dirname(RACINE), 'StaticPE'))
    ap.add_argument('--tache', default='malware', choices=['malware', 'packing'])
    ap.add_argument('--split', default='split_family')
    a = ap.parse_args()

    import taches as T

    t = pq.read_table(os.path.join(a.racine, 'all_features_ml.parquet'))
    dec = pq.read_table(os.path.join(a.racine, 'decoupages.parquet')).to_pydict()
    ordre = {s: i for i, s in enumerate(t.column('sha256').to_pylist())}
    idx = np.array([ordre[s] for s in dec['sha256']])

    X, noms, ecartees = T.matrice(t)
    X = X[idx]
    y = (np.array(dec['label']) == 'malware').astype(int) if a.tache == 'malware' \
        else (np.array(dec['packing']) == 'packed').astype(int)
    tr = np.array(dec[a.split]) == 'train'

    brut = t.select(['sha256', 'general_info__file_type', 'file_header__machine',
                     'dotnet__is_dotnet', 'file_header__time_date_stamp']).to_pydict()
    par_sha = {s: (ft, m, d, ts) for s, ft, m, d, ts in zip(
        brut['sha256'], brut['general_info__file_type'], brut['file_header__machine'],
        brut['dotnet__is_dotnet'], brut['file_header__time_date_stamp'])}
    strates = np.array([strate(*par_sha[s]) for s in dec['sha256']], dtype=object)

    Xtr, ytr, str_tr = X[tr], y[tr], strates[tr]
    n = len(ytr)
    print('tache %s, decoupage %s, entrainement %d echantillons' % (a.tache, a.split, n))

    comptes = collections.Counter(str_tr)
    utiles = []
    for s, k in comptes.items():
        if k < MIN_STRATE:
            continue
        m = str_tr == s
        if int(ytr[m].sum()) < MIN_CLASSE or int((1 - ytr[m]).sum()) < MIN_CLASSE:
            continue
        utiles.append(s)
    couvert = int(sum(comptes[s] for s in utiles))
    print('strates                 : %d au total, %d exploitables' % (len(comptes), len(utiles)))
    print('echantillons dans une strate exploitable : %d (%.1f %%)'
          % (couvert, 100 * couvert / n))
    print()
    print('les 12 plus grosses strates :')
    for s, k in sorted(((s, comptes[s]) for s in utiles), key=lambda x: -x[1])[:12]:
        m = str_tr == s
        print('   %-34s %6d  %5.1f %% positifs' % (s, k, 100 * ytr[m].mean()))
    print()

    masques = {s: (str_tr == s) for s in utiles}
    lignes = []
    for j, nom in enumerate(noms):
        x = Xtr[:, j]
        g, n_g = auc_sure(ytr, x)
        parts, poids = [], []
        for s in utiles:
            m = masques[s]
            v, k = auc_sure(ytr[m], x[m])
            if v is not None:
                parts.append(v)
                poids.append(k)
        if g is None or not parts:
            lignes.append({'feature': nom, 'auc_globale': g, 'auc_conditionnelle': None,
                           'chute': None, 'n_strates': len(parts),
                           'couverture': n_g, 'couverture_strates': int(sum(poids))})
            continue
        cond = float(np.average(parts, weights=poids))
        # une AUC se lit en distance a 0,5 : 0,20 vaut 0,80 a l'envers
        gg, cc = abs(g - 0.5) + 0.5, abs(cond - 0.5) + 0.5
        lignes.append({'feature': nom, 'auc_globale': gg, 'auc_conditionnelle': cc,
                       'chute': gg - cc, 'n_strates': len(parts),
                       'couverture': n_g, 'couverture_strates': int(sum(poids))})
        if (j + 1) % 100 == 0:
            print('  %d / %d colonnes' % (j + 1, len(noms)), flush=True)

    mesurables = [l for l in lignes if l['auc_conditionnelle'] is not None]
    mesurables.sort(key=lambda l: -l['auc_conditionnelle'])

    chemin = os.path.join(a.racine, 'audit_%s.csv' % a.tache)
    with open(chemin, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['feature', 'auc_globale', 'auc_conditionnelle',
                                          'chute', 'n_strates', 'couverture',
                                          'couverture_strates'])
        w.writeheader()
        for l in sorted(lignes, key=lambda l: -(l['auc_conditionnelle'] or 0)):
            w.writerow(l)

    print()
    print('colonnes mesurables : %d / %d' % (len(mesurables), len(noms)))
    print()
    print('=== les 20 qui resistent le mieux a la stratification')
    print('%-52s %8s %8s %8s' % ('colonne', 'globale', 'cond.', 'chute'))
    for l in mesurables[:20]:
        print('%-52s %8.4f %8.4f %+8.4f'
              % (l['feature'][:52], l['auc_globale'], l['auc_conditionnelle'], -l['chute']))
    print()
    print('=== les 20 plus grosses chutes : elles mesuraient le contexte')
    for l in sorted(mesurables, key=lambda l: -l['chute'])[:20]:
        print('%-52s %8.4f %8.4f %+8.4f'
              % (l['feature'][:52], l['auc_globale'], l['auc_conditionnelle'], -l['chute']))
    print()

    ch = [l['chute'] for l in mesurables]
    print('chute : mediane %+.4f, moyenne %+.4f, max %+.4f'
          % (np.median(ch), np.mean(ch), np.max(ch)))
    print('colonnes qui perdent plus de 0,05 : %d' % sum(1 for c in ch if c > 0.05))
    print('colonnes qui perdent plus de 0,10 : %d' % sum(1 for c in ch if c > 0.10))
    print()
    print('ecrit %s' % chemin)

    json.dump({'tache': a.tache, 'split': a.split,
               'strates_exploitables': len(utiles),
               'couverture_strates': couvert,
               'n_entrainement': int(n),
               'colonnes_mesurables': len(mesurables)},
              open(os.path.join(a.racine, 'audit_%s.json' % a.tache), 'w',
                   encoding='utf-8'), indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
