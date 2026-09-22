"""
Fabrique les decoupages train / val / test, une fois pour toutes.

Trois decoupages, du plus optimiste au plus honnete.

  split_random  melange stratifie sur le label. Deux variantes d'une meme
                famille peuvent tomber de part et d'autre, et le modele les
                reconnait de memoire. Publie pour montrer l'ecart, pas pour
                conclure.

  split_group   les echantillons partageant un imphash restent du meme cote.
                Un imphash identique signale la meme table d'imports, donc
                souvent la meme famille.

  split_family  les echantillons d'une meme famille restent du meme cote.
                C'est la notion visee : deux variantes d'Emotet ne doivent
                jamais tomber l'une a l'entrainement et l'autre au test. Sans
                famille connue, on retombe sur la cle par imphash.

Le piege .NET
-------------
Un binaire .NET n'importe qu'une fonction, `mscoree.dll!_CorExeMain`. TOUS les
.NET partagent donc le meme imphash. Regrouper dessus mettrait des milliers
d'echantillons sans aucun lien dans une seule part. On exige donc au moins
trois fonctions importees ; en dessous, l'echantillon forme son propre groupe.
Le compromis est assume et chiffre a l'execution.

Toutes les experiences doivent lire ce fichier plutot que d'en tirer un
nouveau : comparer deux modeles evalues sur deux decoupes differentes ne veut
rien dire.
"""
import os, argparse, collections
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.model_selection import train_test_split, StratifiedGroupKFold

RACINE = os.path.dirname(os.path.abspath(__file__))
GRAINE = 20260908
SEUIL_IMPORTS = 3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--racine', default=os.path.join(os.path.dirname(RACINE), 'StaticPE'))
    a = ap.parse_args()
    ml = os.path.join(a.racine, 'ml_ready')

    etq = pq.read_table(os.path.join(a.racine, 'familles.parquet')).to_pydict()
    sha = np.array(etq['sha256'])
    n = len(sha)
    y = np.array([1 if l == 'malware' else 0 for l in etq['label']])
    familles = np.array([f if f else None for f in etq['family']], dtype=object)

    gi = pq.read_table(os.path.join(ml, 'general_info.parquet'),
                       columns=['sha256', 'general_info__imphash']).to_pydict()
    imph = dict(zip(gi['sha256'], gi['general_info__imphash']))
    imp = pq.read_table(os.path.join(ml, 'imports.parquet'),
                        columns=['sha256', 'imports__n']).to_pydict()
    n_imp = dict(zip(imp['sha256'], imp['imports__n']))
    dn = pq.read_table(os.path.join(ml, 'dotnet.parquet'),
                       columns=['sha256', 'dotnet__is_dotnet']).to_pydict()
    est_dotnet = dict(zip(dn['sha256'], dn['dotnet__is_dotnet']))

    groupes = np.array([
        (imph.get(s) or '') if (imph.get(s) and (n_imp.get(s) or 0) >= SEUIL_IMPORTS)
        else 'seul:' + s for s in sha], dtype=object)
    seuls = int(sum(1 for g in groupes if g.startswith('seul:')))
    ndot = sum(1 for s in sha if est_dotnet.get(s))
    print('echantillons                          : %d' % n)
    print('binaires .NET                         : %d' % ndot)
    print('groupes d un seul element (imphash non discriminant) : %d (%.1f %%)'
          % (seuls, 100 * seuls / n))

    groupes_fam = np.array([('fam:' + f) if f else g
                            for f, g in zip(familles, groupes)], dtype=object)
    nf = int(sum(1 for f in familles if f))
    print('avec famille                          : %d (%.1f %%)' % (nf, 100 * nf / n))
    print('familles distinctes                   : %d' % len({f for f in familles if f}))

    tailles = collections.Counter(groupes_fam)
    print('plus gros groupe                      : %d echantillons' % max(tailles.values()))
    print()

    idx = np.arange(n)
    tr, reste = train_test_split(idx, test_size=0.30, random_state=GRAINE, stratify=y)
    va, te = train_test_split(reste, test_size=0.50, random_state=GRAINE, stratify=y[reste])
    s_rand = np.empty(n, dtype=object)
    s_rand[tr] = 'train'; s_rand[va] = 'val'; s_rand[te] = 'test'

    def par_groupes(cles):
        # 7 plis : un pli vaut ~14 %, on en prend un pour val, un pour test
        sgkf = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=GRAINE)
        plis = [t for _, t in sgkf.split(idx, y, cles)]
        s = np.empty(n, dtype=object)
        for i, p in enumerate(plis):
            s[p] = 'val' if i == 0 else ('test' if i == 1 else 'train')
        return s

    s_grp = par_groupes(groupes)
    s_fam = par_groupes(groupes_fam)

    for nom, cles, s in (('imphash', groupes, s_grp), ('famille', groupes_fam, s_fam)):
        d = collections.defaultdict(set)
        for g, p in zip(cles, s):
            d[g].add(p)
        print('groupes %s a cheval sur deux parts (doit valoir 0) : %d'
              % (nom, sum(1 for v in d.values() if len(v) > 1)))
    print()

    pack = np.array(etq['packing'])
    for nom, s in (('aleatoire', s_rand), ('par imphash', s_grp), ('par famille', s_fam)):
        print('=== %s' % nom)
        print('%-7s %8s %9s %8s %8s %9s' % ('', 'total', 'malware', '% mal', 'packed', '% packed'))
        for part in ('train', 'val', 'test'):
            m = s == part
            nm = int(y[m].sum())
            npk = int((pack[m] == 'packed').sum())
            print('%-7s %8d %9d %7.1f%% %8d %8.1f%%'
                  % (part, m.sum(), nm, 100 * nm / m.sum(), npk, 100 * npk / m.sum()))
        print()

    tbl = pa.table({'sha256': pa.array(sha),
                    'label': pa.array(etq['label']),
                    'packing': pa.array(etq['packing']),
                    'family': pa.array([f for f in familles], type=pa.string()),
                    'groupe': pa.array(list(groupes)),
                    'groupe_famille': pa.array(list(groupes_fam)),
                    'split_random': pa.array(list(s_rand)),
                    'split_group': pa.array(list(s_grp)),
                    'split_family': pa.array(list(s_fam))})
    sortie = os.path.join(a.racine, 'decoupages.parquet')
    pq.write_table(tbl, sortie, compression='zstd')
    print('ecrit %s' % sortie)


if __name__ == '__main__':
    main()
