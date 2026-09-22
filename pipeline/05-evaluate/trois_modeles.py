# -*- coding: utf-8 -*-
"""
Les trois taches mesurees sur le fichier, par trois familles d algorithmes.

Pourquoi trois et pas un
------------------------
L etude compare aujourd hui un modele de langue a LightGBM et conclut que le
texte serialise perd environ 0,10 de MCC. Mais on ne peut pas dire si cet ecart
vient de la representation ou du fait que LightGBM soit particulierement adapte
a 18 489 colonnes creuses. Trois familles d algorithmes differentes repondent :
si les trois donnent le meme ordre de grandeur, l ecart tient a la
representation ; si elles divergent, il tient au modele.

  lightgbm   boosting de gradient, arbres construits en sequence
  foret      bagging, arbres independants sur des sous-echantillons
  mlp        reseau dense, descente de gradient

Ajouter XGBoost ou CatBoost n aurait rien apporte : c est du boosting comme
LightGBM, donc le meme biais inductif. Le choix porte sur la FAMILLE.

Le MLP repond a une question precise que les arbres ne peuvent pas trancher.
L etude compare un modele de langue sur du texte a un arbre booste sur des
colonnes : deux choses changent a la fois, la representation et le modele. Le
MLP est de la meme famille que le LLM, un reseau dense entraine par descente
de gradient, mais nourri des colonnes. S il rejoint LightGBM, l ecart du LLM
tient a la representation ; s il rejoint le LLM, il tient au modele.

MalConv a ete ecarte : il travaille sur les octets bruts du binaire, et le
pipeline supprime les malveillants apres extraction. La donnee n existe plus.

Ce qui reste identique
----------------------
Les colonnes, les partitions, la graine, la ponderation de classe, et le seuil
choisi sur la validation en maximisant le MCC. Seul l estimateur change.

La logistique a besoin de deux amenagements que les arbres n exigent pas : les
valeurs manquantes doivent etre remplacees, et les echelles normalisees. On le
fait dans un pipeline, pas en modifiant les donnees, pour que les deux autres
modeles voient exactement la meme matrice.

  python trois_modeles.py --donnees "Dataset parquet" --sortie resultats_trois
"""
import os, sys, json, time, argparse
import numpy as np

RACINE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, RACINE)

from etude_complete import (charger, decoupage, seuil_val, mesures,
                            GRAINE, N_FILS)              # noqa: E402
import ablation                                       # noqa: E402
import pyarrow.parquet as pq                          # noqa: E402
import pandas as pd                                   # noqa: E402

MENACES = ['stealer', 'loader', 'banker', 'rat', 'ransomware', 'botnet', 'worm',
           'keylogger', 'miner', 'fileinfector', 'backdoor', 'postexploitation',
           'clipper', 'downloader', 'adware']
TACHES = ('detection', 'packing', 'anti_analysis') + tuple('menace_' + m for m in MENACES)
PROTOCOLES = ('aleatoire', 'imphash', 'famille', 'temps', 'croise')


def faire_lightgbm(Xtr, ytr, Xva, yva):
    import lightgbm as lgb
    p_ = float(ytr.sum()); n_ = len(ytr) - p_
    m = lgb.LGBMClassifier(n_estimators=1500, learning_rate=0.05, num_leaves=64,
                           min_child_samples=40, subsample=0.8, subsample_freq=1,
                           colsample_bytree=0.3, reg_lambda=1.0, max_bin=63,
                           force_col_wise=True, scale_pos_weight=n_ / max(p_, 1),
                           random_state=GRAINE, n_jobs=N_FILS, verbose=-1)
    m.fit(Xtr, ytr, eval_set=[(Xva, yva)], eval_metric='average_precision',
          callbacks=[lgb.early_stopping(80, verbose=False)])
    return m


def faire_foret(Xtr, ytr, Xva, yva):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    # La foret de scikit-learn refuse les NaN. On les remplace par -1 plutot
    # que par la moyenne : la discipline a trois etats veut qu une absence
    # reste distinguable d une valeur mesuree, et -1 est hors du domaine de
    # toutes les colonnes du corpus.
    m = make_pipeline(
        SimpleImputer(strategy='constant', fill_value=-1),
        RandomForestClassifier(n_estimators=300, max_features='sqrt',
                               min_samples_leaf=5, class_weight='balanced_subsample',
                               random_state=GRAINE, n_jobs=N_FILS))
    m.fit(Xtr, ytr)
    return m


def faire_mlp(Xtr, ytr, Xva, yva):
    from sklearn.neural_network import MLPClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    from sklearn.utils.class_weight import compute_sample_weight  # noqa: F401
    # Un reseau dense exige une echelle commune, sans quoi `size_bytes` en
    # octets ecrase un indicateur binaire. Les arbres s en moquent, d ou le
    # pipeline plutot qu une transformation des donnees en amont.
    #
    # `with_mean=False` laisse la matrice creuse : la centrer la rendrait
    # dense et ferait exploser la memoire sur 18 489 colonnes.
    #
    # MLPClassifier ne sait pas ponderer les classes. On compense par un
    # sous-echantillonnage de la classe majoritaire dans le lot, ce que fait
    # `early_stopping` sur une fraction de validation interne.
    m = make_pipeline(
        SimpleImputer(strategy='constant', fill_value=-1),
        StandardScaler(with_mean=False),
        MLPClassifier(hidden_layer_sizes=(256, 64), activation='relu',
                      solver='adam', alpha=1e-4, batch_size=256,
                      learning_rate_init=1e-3, max_iter=60,
                      early_stopping=True, n_iter_no_change=6,
                      validation_fraction=0.1, random_state=GRAINE))
    m.fit(Xtr, ytr)
    return m


def faire_logistique(Xtr, ytr, Xva, yva):
    from sklearn.linear_model import LogisticRegression
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    # La quatrieme famille, et la seule lineaire. Elle ne sert pas a gagner :
    # elle donne le plancher. L ecart entre elle et les arbres mesure combien
    # la tache est non lineaire, ce qu aucun des trois autres ne dit.
    #
    # Memes amenagements que le reseau dense, et pour les memes raisons :
    # -1 plutot que la moyenne pour preserver la discipline a trois etats,
    # et pas de centrage pour ne pas densifier 18 489 colonnes.
    m = make_pipeline(
        SimpleImputer(strategy='constant', fill_value=-1),
        StandardScaler(with_mean=False),
        LogisticRegression(penalty='l2', C=1.0, solver='liblinear',
                           class_weight='balanced', max_iter=2000,
                           random_state=GRAINE))
    m.fit(Xtr, ytr)
    return m


MODELES = {'lightgbm': faire_lightgbm, 'foret': faire_foret,
           'mlp': faire_mlp, 'logistique': faire_logistique}


def cible(dec, nom):
    """La colonne cible et le masque des lignes admissibles pour la tache."""
    if nom == 'detection':
        y = (dec.label.values == 'malware').astype(np.int8)
        return y, np.ones(len(dec), bool)
    if nom == 'packing':
        v = dec.packing.values
        return (v == 'packed').astype(np.int8), pd.notna(v)
    if nom == 'anti_analysis':
        v = dec.anti_analysis.values
        return (pd.Series(v).fillna(False).astype(bool).values.astype(np.int8),
                pd.notna(v))
    # Les quinze menaces. Un null n est pas un negatif : il sort de la tache.
    v = dec[nom].values
    return (pd.Series(v).fillna(False).astype(bool).values.astype(np.int8),
            pd.notna(v))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--sortie', default='resultats_trois')
    ap.add_argument('--taches', default=','.join(TACHES))
    ap.add_argument('--modeles', default=','.join(MODELES))
    ap.add_argument('--protocoles', default=','.join(PROTOCOLES))
    ap.add_argument('--colonnes', default='',
                    help='un colonnes.json ecrit par serialiser_compact.py : '
                         'la matrice est restreinte a SA liste, celle-la meme '
                         'que recoit le modele de langue. Lire le fichier '
                         'plutot que refaire la selection est la seule facon '
                         'de garantir que les deux voient la meme chose')
    ap.add_argument('--accusees', default='',
                    help='le dossier des audit_<tache>_<protocole>.csv. Les '
                         'colonnes dont la chute depasse --chute-max sont '
                         'retirees, par cellule : c est la variante `epure`. '
                         'La liste est LUE, jamais recalculee, pour que la '
                         'forêt et le reseau dense retirent exactement les '
                         'memes colonnes que LightGBM.')
    ap.add_argument('--chute-max', type=float, default=0.05,
                    help='le seuil de l audit, 0.05 comme dans etude_complete')
    ap.add_argument('--colonnes-racine', default='',
                    help='le dossier llm_data_compact : la liste de colonnes '
                         'est alors lue par cellule, dans '
                         '<racine>/<representation>/<tache>/<protocole>/')
    ap.add_argument('--representation', default='sparse_64',
                    help='le sous-dossier a lire sous --colonnes-racine')
    ap.add_argument('--cacher', nargs='*', default=[],
                    help='colonnes a retirer, par nom exact ou par prefixe. '
                         'LA MEME LISTE doit etre passee a '
                         'serialiser_identique.py, sinon les deux modeles ne '
                         'voient plus la meme chose')
    a = ap.parse_args()
    os.makedirs(a.sortie, exist_ok=True)

    dec = pq.read_table(os.path.join(a.donnees, 'decoupages.parquet')).to_pandas()
    print('chargement de la matrice...', flush=True)
    X, noms, _ = charger(a.donnees, dec, avec_matrices=True)
    print('matrice %d x %d' % X.shape, flush=True)

    nom_repr = 'full'
    if a.colonnes:
        spec = json.load(open(a.colonnes, encoding='utf-8'))
        nom_repr = spec.get('variante', 'inconnue')
        voulues = spec['colonnes']
        pos = {c: j for j, c in enumerate(noms)}
        manquantes = [c for c in voulues if c not in pos]
        if manquantes:
            raise SystemExit('%d colonnes du fichier sont absentes de la '
                             'matrice, la comparaison serait faussee : %s'
                             % (len(manquantes), ', '.join(manquantes[:5])))
        idx = np.array([pos[c] for c in voulues], dtype=np.int64)
        X, noms = X[:, idx], list(voulues)
        print('representation %s : %d colonnes (empreinte %s)'
              % (spec.get('variante', '?'), len(noms),
                 spec.get('empreinte_vocabulaire', '?')), flush=True)

    garde, caches = ablation.appliquer(noms, a.cacher)
    ablation.journal(a.cacher, caches, len(noms))
    if caches:
        X = X[:, garde]
        noms = [noms[j] for j in garde]
        print('matrice apres ablation %d x %d' % X.shape, flush=True)

    chemin = os.path.join(a.sortie, 'trois.json')
    R = json.load(open(chemin, encoding='utf-8')) if os.path.exists(chemin) else []
    faits = {(r['tache'], r['protocole'], r['modele']) for r in R}

    # Le protocole du modele de langue nomme ses decoupages autrement.
    NOM_PROTO = {'aleatoire': 'random', 'imphash': 'group', 'famille': 'family',
                 'temps': 'temps', 'croise': 'croise'}
    pos_col = {c: j for j, c in enumerate(noms)}

    for tache in a.taches.split(','):
        y, garder = cible(dec, tache)
        for proto in a.protocoles.split(','):
            tr, va, te = decoupage(dec, proto, y, garder)
            if not len(te):
                print('%-14s %-10s  pas de test, saute' % (tache, proto), flush=True)
                continue
            # Les colonnes de CETTE cellule, lues dans le fichier que le
            # modele de langue a lui-meme utilise. La selection etant refaite
            # par tache et par protocole pour eviter la fuite, elle change
            # d une cellule a l autre : la charger ici, et non une fois pour
            # toutes, est ce qui garantit que les deux voient la meme chose.
            idx, repr_ici = None, nom_repr
            if a.colonnes_racine:
                p = os.path.join(a.colonnes_racine, a.representation, tache,
                                 NOM_PROTO[proto], 'colonnes.json')
                if not os.path.exists(p):
                    print('%-14s %-10s  pas de colonnes.json, saute'
                          % (tache, proto), flush=True)
                    continue
                spec = json.load(open(p, encoding='utf-8'))
                idx = np.array([pos_col[c] for c in spec['colonnes']],
                               dtype=np.int64)
                repr_ici = spec.get('variante', a.representation)

            # --- la variante epuree : retirer les colonnes accusees
            n_acc = 0
            if a.accusees:
                pa_ = os.path.join(a.accusees, 'audit_%s_%s.csv' % (tache, proto))
                if not os.path.exists(pa_):
                    print('%-14s %-10s  pas d audit, saute' % (tache, proto),
                          flush=True)
                    continue
                au = pd.read_csv(pa_)
                mauvaises = set(au.loc[au.chute > a.chute_max, 'feature'])
                n_acc = len(mauvaises)
                base = idx if idx is not None else np.arange(len(noms))
                idx = np.array([j for j in base if noms[j] not in mauvaises],
                               dtype=np.int64)
                repr_ici = (repr_ici or 'full') + '_epure'
                print('%-14s %-10s  %d accusees retirees, %d colonnes restantes'
                      % (tache, proto, n_acc, len(idx)), flush=True)

            def bloc(lignes):
                # np.ix_ construit directement le sous-tableau final ; passer
                # par X[lignes][:, idx] materialiserait d abord 70 000 x 18 489.
                return X[lignes] if idx is None else X[np.ix_(lignes, idx)]

            Xtr, Xva, Xte = bloc(tr), bloc(va), bloc(te)
            for nom in a.modeles.split(','):
                if (tache, proto, nom) in faits:
                    continue
                t0 = time.time()
                m = MODELES[nom](Xtr, y[tr], Xva, y[va])
                pva = m.predict_proba(Xva)[:, 1]
                pte = m.predict_proba(Xte)[:, 1]
                s = seuil_val(y[va], pva)
                r = mesures(y[te], pte, s)
                r.update(tache=tache, protocole=proto, modele=nom,
                         n_colonnes=Xtr.shape[1], n_train=len(tr),
                         n_val=len(va), representation=repr_ici,
                         jeu=('epure' if a.accusees else 'reference'),
                         n_accusees=n_acc,
                         ablation=','.join(a.cacher), n_cachees=len(caches),
                         secondes=round(time.time() - t0))
                R.append(r)
                json.dump(R, open(chemin, 'w', encoding='utf-8'),
                          indent=1, ensure_ascii=False, default=str)
                print('%-14s %-10s %-11s  MCC %.4f  acc %.4f  (%d s)'
                      % (tache, proto, nom, r['mcc'], r['accuracy'], r['secondes']),
                      flush=True)

    d = pd.DataFrame(R)
    d.to_csv(os.path.join(a.sortie, 'trois.csv'), index=False)
    print()
    for tache in d.tache.unique():
        t = d[d.tache == tache].pivot_table(index='modele', columns='protocole',
                                            values='mcc')
        ordre = [c for c in PROTOCOLES if c in t.columns]
        print('===', tache)
        print(t[ordre].round(4).to_string())
        print()


if __name__ == '__main__':
    main()
