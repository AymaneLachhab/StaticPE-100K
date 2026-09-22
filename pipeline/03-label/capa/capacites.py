"""
Traduit la table des imports en features de capacite, a partir du jeu de regles
public de capa (mandiant/capa-rules).

Principe. Chaque regle capa porte un `namespace` — la capacite — et liste les
`api:` qui interviennent dedans. On construit la correspondance fonction ->
capacite a partir de ces listes, puis on compte pour chaque echantillon combien
de ses imports tombent dans chaque capacite.

Deux qualites de correspondance sont distinguees, et c'est essentiel.

  directe    la regle est une simple disjonction d'API : `features: - or: [api,
             api, ...]`. Ces API sont des synonymes, chacune suffit. Exemple :
             `send data on socket` = send OU sendto OU WSASend.

  partielle  la regle est une conjonction : elle exige plusieurs conditions
             ensemble. L'API seule ne prouve rien. Exemple : la regle de
             detection de VM demande GetForegroundWindow deux fois ET Sleep ET
             une comparaison ET une boucle. Prise seule, `Sleep` ne veut rien
             dire.

Les deux sont conservees, mais nommees separement. Une colonne `partielle` ne
dit pas « ce programme detecte les VM » : elle dit « ce programme importe une
fonction qui apparait dans les regles anti-VM ». C'est vrai dans tous les cas,
et le modele voit la meme information.
"""
import os, re, json, collections
import numpy as np
import pyarrow as pa, pyarrow.parquet as pq

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
REGLES = os.path.join(RACINE, 'capa-rules')

# une regle est une pure disjonction d'API si son bloc features ne contient
# aucun de ces marqueurs
CONJONCTION = re.compile(r'^\s*-?\s*(and|match|string|substring|count|mnemonic|'
                         r'characteristic|number|bytes|offset|section|export|import|'
                         r'namespace|class|property|instruction|basic block):', re.M)


def lire_regles():
    """fonction -> {capacite: qualite}. La qualite 'directe' l'emporte."""
    corresp = collections.defaultdict(dict)
    stats = collections.Counter()
    for dp, _, fs in os.walk(REGLES):
        chemin = dp.replace(os.sep, '/')
        if '/doc' in chemin or '/.git' in chemin or '/lib' in chemin or '/nursery' in chemin:
            continue
        for f in fs:
            if not f.endswith('.yml'): continue
            txt = open(os.path.join(dp, f), encoding='utf-8', errors='replace').read()
            for bloc in txt.split('rule:')[1:]:
                m = re.search(r'^\s*namespace:\s*(\S+)', bloc, re.M)
                if not m: continue
                ns = m.group(1)
                feat = bloc.split('features:', 1)
                if len(feat) < 2: continue
                feat = feat[1]
                apis = re.findall(r'^\s*-\s*api:\s*(.+?)\s*$', feat, re.M)
                if not apis: continue
                qualite = 'partielle' if CONJONCTION.search(feat) else 'directe'
                stats[qualite] += 1
                for a in apis:
                    a = a.strip().strip('"\'')
                    if '::' in a: continue          # API .NET : autre espace de noms
                    a = a.split('=')[-1].strip()    # 'ws2_32.#19 = send' -> 'send'
                    fn = a.split('.')[-1].lower()
                    if not fn or fn.startswith('#'): continue
                    # une correspondance directe ecrase une partielle
                    if corresp[fn].get(ns) != 'directe':
                        corresp[fn][ns] = qualite
    return corresp, stats


def capacite(ns, profondeur=2):
    """Reduit le namespace a ses deux premiers niveaux : le detail complet
    creerait des centaines de colonnes a un seul echantillon."""
    return '/'.join(ns.split('/')[:profondeur])


def main():
    corresp, stats = lire_regles()
    print('regles retenues : %d directes, %d partielles'
          % (stats['directe'], stats['partielle']))
    print('fonctions dans la correspondance : %d' % len(corresp))

    # fonction -> liste de (capacite, qualite), dedupliquee au niveau 2
    plat = {}
    for fn, d in corresp.items():
        red = {}
        for ns, q in d.items():
            c = capacite(ns)
            if red.get(c) != 'directe': red[c] = q
        plat[fn] = red

    caps_d = sorted({c for d in plat.values() for c, q in d.items() if q == 'directe'})
    caps_p = sorted({c for d in plat.values() for c, q in d.items() if q == 'partielle'})
    print('capacites en correspondance directe   : %d' % len(caps_d))
    print('capacites en correspondance partielle : %d' % len(caps_p))

    colonnes = ([('cap_d:' + c, c, 'directe') for c in caps_d]
                + [('cap_p:' + c, c, 'partielle') for c in caps_p])
    pos = {nom: i for i, (nom, _, _) in enumerate(colonnes)}

    splits = pq.read_table(os.path.join(DATA, 'splits.parquet'),
                           columns=['sha256']).to_pydict()['sha256']
    ligne = {s: i for i, s in enumerate(splits)}
    M = np.zeros((len(splits), len(colonnes)), dtype=np.int32)

    t = pq.read_table(os.path.join(DATA, 'imports.parquet'),
                      columns=['sha256', 'function']).to_pydict()
    touchees = 0
    for s, f in zip(t['sha256'], t['function']):
        i = ligne.get(s)
        if i is None or not f: continue
        d = plat.get(f.lower())
        if not d: continue
        touchees += 1
        for c, q in d.items():
            M[i, pos[('cap_d:' if q == 'directe' else 'cap_p:') + c]] += 1
    print('lignes d imports traduites : %d sur %d (%.1f %%)'
          % (touchees, len(t['function']), 100 * touchees / len(t['function'])))

    tbl = pa.table({'sha256': pa.array(splits),
                    **{nom: pa.array(M[:, i]) for i, (nom, _, _) in enumerate(colonnes)}})
    pq.write_table(tbl, os.path.join(DATA, 'capacites.parquet'), compression='zstd')

    meta = {'colonnes': [{'colonne': n, 'capacite': c, 'qualite': q} for n, c, q in colonnes],
            'regles_directes': stats['directe'], 'regles_partielles': stats['partielle'],
            'fonctions': len(plat)}
    json.dump(meta, open(os.path.join(DATA, 'capacites_meta.json'), 'w', encoding='utf-8'),
              indent=1, ensure_ascii=False)
    print('ecrit dataset/capacites.parquet : %d lignes, %d colonnes'
          % (tbl.num_rows, tbl.num_columns))

    # apercu : prevalence par classe
    lab = pq.read_table(os.path.join(DATA, 'splits.parquet'),
                        columns=['sha256', 'label']).to_pydict()
    y = np.array([1 if l == 'malware' else 0 for l in lab['label']])
    print()
    print('%-46s %8s %8s %8s' % ('capacite', 'malware', 'benign', 'ecart'))
    lignes = []
    for i, (nom, c, q) in enumerate(colonnes):
        pm = 100 * (M[y == 1, i] > 0).mean(); pb = 100 * (M[y == 0, i] > 0).mean()
        lignes.append((abs(pm - pb), nom, pm, pb))
    for e, nom, pm, pb in sorted(lignes, reverse=True)[:18]:
        print('%-46s %7.1f%% %7.1f%% %+7.1f' % (nom, pm, pb, pm - pb))


if __name__ == '__main__':
    main()
