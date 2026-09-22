"""
Le plancher de la detection par le comportement.

Les experiences precedentes ont montre que le modele separe les classes par la
facon dont les fichiers ont ete fabriques et emballes : entropie, checksum,
signature, adresse de chargement, horodatage. Aucune de ces mesures ne dit ce
que le programme fait.

Ce script retire tout cela et ne garde que ce qui decrit une capacite :

  - les noms de fonctions importees (2 000 plus frequentes)
  - les entites extraites des chaines : URL, adresses IP, cles de registre,
    chemins de fichiers, noms de bibliotheques
  - les bibliotheques nommees dans les chaines mais absentes de la table
    d'imports, qui signalent une resolution a l'execution
  - les rappels TLS, qui s'executent avant le point d'entree
  - le niveau d'elevation demande dans le manifeste
  - le nombre d'imports differes

Le score obtenu est le vrai plancher de ce qu'on peut faire en lisant ce que le
programme est capable de faire, plutot que la maniere dont il a ete produit.
"""
import os, json, collections, warnings
import numpy as np
import pyarrow.parquet as pq
import scipy.sparse as sp

warnings.filterwarnings('ignore')
RACINE = os.path.dirname(os.path.abspath(__file__))
# Chemin des donnees. On accepte trois origines, dans cet ordre : la variable
# d'environnement STATICPE_DATA, le dossier publiable a cote du code, puis
# l'ancien emplacement de travail. Ainsi les scripts fonctionnent avant comme
# apres le deplacement, et un relecteur peut pointer ailleurs sans editer le code.
def _dossier_donnees(racine):
    import os
    par_env = os.environ.get('STATICPE_DATA')
    if par_env:
        return par_env
    publiable = os.path.join(os.path.dirname(racine), 'AnlayseStatiqueDataset', 'dataset')
    if os.path.isdir(publiable):
        return publiable
    return os.path.join(racine, 'dataset')


DATA = _dossier_donnees(RACINE)

# Colonnes de core.parquet qui decrivent une capacite du programme.
COMPORTEMENT = [
    'strings_n_urls', 'strings_n_ipv4', 'strings_n_ipv4_plausible',
    'strings_n_registry_paths', 'strings_n_file_paths', 'strings_n_dll_names',
    'orphan_dlls_n_orphans', 'orphan_dlls_n_imported',
    'tls_has_tls', 'tls_callback_count',
    'manifest_has_manifest',
    'misc_structures_delay_import_count',
]
# categorielle : le niveau d'elevation demande
CAT_COMPORTEMENT = ['manifest_requested_execution_level']


def main():
    import experiences as E
    core = pq.read_table(os.path.join(DATA, 'core.parquet'))
    splits = pq.read_table(os.path.join(DATA, 'splits.parquet')).to_pandas()
    ordre = {s: i for i, s in enumerate(core.column('sha256').to_pylist())}
    idx = np.array([ordre[s] for s in splits['sha256']])
    shas = list(splits['sha256'])
    y = (splits['label'] == 'malware').astype(int).values
    s = splits['split_group'].values
    tr, va, te = s == 'train', s == 'val', s == 'test'

    cols, noms = [], []
    for nom in COMPORTEMENT:
        if nom not in core.schema.names:
            print('absent, ignore :', nom); continue
        v = core.column(nom).to_numpy(zero_copy_only=False)
        cols.append(np.asarray(v, dtype=np.float64)[idx]); noms.append(nom)
    for nom in CAT_COMPORTEMENT:
        v = core.column(nom).to_pylist()
        vocab = {x: i for i, x in enumerate(sorted({str(a) for a in v}))}
        cols.append(np.array([vocab[str(a)] for a in v], dtype=np.float64)[idx])
        noms.append(nom + '__cat')
    Xs = np.column_stack(cols)
    print('features de comportement hors imports :', Xs.shape[1])

    Xi, noms_i = E.matrice_imports(shas, tr)
    print('fonctions importees retenues          :', Xi.shape[1])

    jeux = {
        'comportement sans imports': (sp.csr_matrix(Xs), noms),
        'imports seuls': (Xi, noms_i),
        'comportement complet': (sp.hstack([sp.csr_matrix(Xs), Xi]).tocsr(), noms + noms_i),
    }

    sortie = []
    for nom_jeu, (X, nn) in jeux.items():
        m, p = E.entrainer(X[tr], y[tr], X[va], y[va], X[te], y[te], nn)
        r = E.mesures(y[te], p)
        r.update(jeu=nom_jeu, n_features=X.shape[1])
        g = m.booster_.feature_importance('gain')
        tot = g.sum() or 1
        r['top'] = [(a, round(float(100 * b / tot), 2))
                    for a, b in sorted(zip(nn, g), key=lambda x: -x[1])[:20]]
        sortie.append(r)
        print('%-28s %5d features   ROC-AUC %.4f   PR-AUC %.4f   F1 %.4f   rappel %.4f'
              % (nom_jeu, X.shape[1], r['roc_auc'], r['pr_auc'], r['f1'], r['recall']),
              flush=True)

    print()
    for r in sortie:
        print('=== %s : les 15 features les plus utilisees' % r['jeu'])
        for a, b in r['top'][:15]:
            print('   %-52s %5.2f%%' % (a, b))
        print()

    with open(os.path.join(DATA, 'comportement.json'), 'w', encoding='utf-8') as f:
        json.dump(sortie, f, indent=1, ensure_ascii=False)
    print('ecrit dataset/comportement.json')


if __name__ == '__main__':
    main()
