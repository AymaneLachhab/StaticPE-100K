# -*- coding: utf-8 -*-
"""
Transformer chaque binaire PE en un texte court, pour un modele de langue.

Pourquoi ce n est pas evident
-----------------------------
Un arbre boosté lit 18 489 colonnes sans broncher. Un modele de langue lit une
sequence de jetons, et chaque jeton coute. Tout mettre serait a la fois trop
long et inutile : la queue d entropie tient en trois nombres, pas en 256.

Le texte produit garde ce que l etude a montre utile et ce qu un modele de
langue sait exploiter mieux qu un arbre -- les NOMS. Les noms de sections, les
noms de DLL et de fonctions importees, les chaines : autant de suites de
caracteres ou un modele de langue a un avantage reel, parce qu il y reconnait
des motifs qu une colonne binaire `imp:kernel32.dll!createfile` reduit a 0 ou 1.

Ce qui est volontairement exclu
------------------------------
  - les identifiants (md5, sha256, imphash) : ils designent le fichier
  - l horodatage et la version du lieur : ils datent le corpus
  - la famille, l etiquette, le paquet : ce sont les reponses

  python serialiser_llm.py --donnees "Dataset parquet" --sortie llm_data
"""
import os, json, argparse
import numpy as np, pandas as pd
import pyarrow.parquet as pq

# Le modele recevait 40 fonctions importees sur les 228 727 distinctes du
# corpus, la ou LightGBM en lit 6 240 colonnes. Les textes faisaient 50 mots en
# moyenne et 103 au maximum, pour un budget de 512 jetons : le modele etait
# affame, pas trop petit. Ces plafonds sont releves en consequence, et --maxlen
# passe a 768 pour absorber la difference.
MAX_IMPORTS = 120
MAX_SECTIONS = 20
MAX_STRINGS = 12
# Les exports sont la plus grosse famille de colonnes du jeu de donnees --
# 8 349, plus que les imports -- et le texte n en portait aucune. Les noms de
# DLL trouves dans les chaines non plus, alors qu ils revelent une resolution
# a l execution que la table d import ne montre pas.
MAX_EXPORTS = 60
MAX_STR_DLL = 20


def _lire(D, fichier, colonnes=None):
    p = os.path.join(D, fichier + '.parquet')
    if not os.path.exists(p):
        return None
    if colonnes:
        dispo = set(pq.read_schema(p).names)
        colonnes = ['sha256'] + [c for c in colonnes if c in dispo and c != 'sha256']
        return pq.read_table(p, columns=colonnes).to_pandas()
    return pq.read_table(p).to_pandas()


def _nombre(x, dec=0):
    """Un nombre lisible, ou 'na' quand la mesure n a pas ete faite.

    Ecrire 0 a la place de 'na' ferait affirmer au modele une valeur nulle la
    ou il n y a pas de mesure -- la meme discipline a trois etats que dans les
    parquet."""
    if x is None or (isinstance(x, float) and not np.isfinite(x)):
        return 'na'
    return ('%.*f' % (dec, x)).rstrip('0').rstrip('.') if dec else '%d' % int(x)


def construire(D):
    dec = pq.read_table(os.path.join(D, 'decoupages.parquet')).to_pandas()
    ordre = {s: i for i, s in enumerate(dec.sha256)}
    n = len(dec)

    # --- les blocs de valeurs, un par un, en ne lisant que ce qui sert
    gi = _lire(D, 'general_info', ['general_info__file_type', 'general_info__size_bytes'])
    hd = _lire(D, 'header', ['file_header__numberof_sections', 'file_header__machine',
                             'optional_header__subsystem', 'optional_header__sizeof_image',
                             'optional_header__dll_characteristics__n',
                             'checksum_check__checksum_valid'])
    ct = _lire(D, 'content', ['strings__count_total', 'strings__len_mean', 'strings__len_max',
                              'strings__count_utf16', 'strings__urls__n', 'strings__ipv4__n',
                              'byte_features__file_entropy'])
    ms = _lire(D, 'misc', ['resources__max_entropy', 'dotnet__is_dotnet',
                           'digital_signature__verification_flag',
                           'digital_signature__certificates__n'])
    sc = _lire(D, 'sections')
    im = _lire(D, 'imports')
    ex = _lire(D, 'exports')
    # `ct` n a ete lu que sur quelques colonnes ; les `str:` demandent une
    # seconde lecture, restreinte a elles.
    p_ct = os.path.join(D, 'content.parquet')
    cols_str = [c for c in pq.read_schema(p_ct).names if c.startswith('str:')]
    st = pq.read_table(p_ct, columns=['sha256'] + cols_str).to_pandas() if cols_str else None

    def col(t, nom):
        if t is None or nom not in t.columns:
            return np.full(n, np.nan)
        s = pd.Series(np.nan, index=range(n), dtype='float64')
        idx = [ordre[x] for x in t.sha256]
        v = pd.to_numeric(t[nom], errors='coerce').values
        s.iloc[idx] = v
        return s.values

    def col_txt(t, nom):
        if t is None or nom not in t.columns:
            return np.array([None] * n, dtype=object)
        s = np.array([None] * n, dtype=object)
        idx = [ordre[x] for x in t.sha256]
        s[idx] = t[nom].values
        return s

    # --- les noms de sections presentes, tires des colonnes pivotees sec_*_raw
    noms_sec = [c[4:-4] for c in (sc.columns if sc is not None else [])
                if c.startswith('sec_') and c.endswith('_raw')]
    presence = {}
    for nm in noms_sec[:40]:
        presence[nm] = col(sc, 'sec_%s_raw' % nm)

    # --- les imports : une colonne binaire par dll!fonction
    cols_imp = [c for c in (im.columns if im is not None else []) if c.startswith('imp:')]
    IMP = None
    if cols_imp:
        t = im[['sha256'] + cols_imp]
        M = t[cols_imp].fillna(0).values.astype(np.int8)
        IMP = (M, [c[4:] for c in cols_imp], [ordre[x] for x in t.sha256])

    def pivot(t, prefixe, coupe):
        """-> (matrice int8, noms sans prefixe, lignes) ou None."""
        if t is None:
            return None
        cols = [c for c in t.columns if c.startswith(prefixe)]
        if not cols:
            return None
        M = t[cols].fillna(0).values.astype(np.int8)
        return M, [c[coupe:] for c in cols], [ordre[x] for x in t.sha256]

    EXP = pivot(ex, 'exp:', 4)
    STR = pivot(st, 'str:dll_names=', len('str:dll_names='))

    ft = col_txt(gi, 'general_info__file_type')
    # machine, subsystem et le drapeau de signature sont stockes en TEXTE : les
    # passer par to_numeric les aurait tous transformes en 'na'.
    machine = col_txt(hd, 'file_header__machine')
    subsys = col_txt(hd, 'optional_header__subsystem')
    signe = col_txt(ms, 'digital_signature__verification_flag')
    V = {
        'size': col(gi, 'general_info__size_bytes'),
        'nsec': col(hd, 'file_header__numberof_sections'),
        'sizeof_image': col(hd, 'optional_header__sizeof_image'),
        'dllchar': col(hd, 'optional_header__dll_characteristics__n'),
        'checksum_ok': col(hd, 'checksum_check__checksum_valid'),
        'nstr': col(ct, 'strings__count_total'),
        'strmean': col(ct, 'strings__len_mean'),
        'strmax': col(ct, 'strings__len_max'),
        'utf16': col(ct, 'strings__count_utf16'),
        'urls': col(ct, 'strings__urls__n'),
        'ips': col(ct, 'strings__ipv4__n'),
        'entropy': col(ct, 'byte_features__file_entropy'),
        'res_entropy': col(ms, 'resources__max_entropy'),
        'dotnet': col(ms, 'dotnet__is_dotnet'),
        'ncert': col(ms, 'digital_signature__certificates__n'),
    }

    def par_ligne(P, coupe):
        """Les noms retenus, et combien il y en avait avant la coupe.

        Sans ce second retour, un fichier qui importe 400 fonctions et un qui
        en importe 120 produisent exactement la meme ligne : la troncature
        efface une information que le modele ne peut plus reconstruire. Les
        arbres, eux, voient les 17 398 indicateurs et donc le compte exact.
        """
        out = [[] for _ in range(n)]
        total = np.zeros(n, dtype=np.int32)
        if P is None:
            return out, total
        M, noms_, lignes = P
        for k, ligne in enumerate(lignes):
            nz = np.flatnonzero(M[k])
            total[ligne] = len(nz)
            if len(nz):
                out[ligne] = [noms_[j] for j in nz[:coupe]]
        return out, total

    imp_par_ligne, imp_total = par_ligne(IMP, MAX_IMPORTS)
    exp_par_ligne, exp_total = par_ligne(EXP, MAX_EXPORTS)
    str_par_ligne, str_total = par_ligne(STR, MAX_STR_DLL)

    textes = []
    for i in range(n):
        p = []
        p.append('type=%s size=%s sections=%s arch=%s subsystem=%s'
                 % (ft[i] or 'na', _nombre(V['size'][i]), _nombre(V['nsec'][i]),
                    machine[i] or 'na', subsys[i] or 'na'))
        p.append('entropy=%s res_entropy=%s dotnet=%s signed=%s certs=%s checksum_ok=%s'
                 % (_nombre(V['entropy'][i], 2), _nombre(V['res_entropy'][i], 2),
                    _nombre(V['dotnet'][i]), signe[i] or 'na',
                    _nombre(V['ncert'][i]), _nombre(V['checksum_ok'][i])))
        p.append('strings=%s mean_len=%s max_len=%s utf16=%s urls=%s ips=%s'
                 % (_nombre(V['nstr'][i]), _nombre(V['strmean'][i], 1),
                    _nombre(V['strmax'][i]), _nombre(V['utf16'][i]),
                    _nombre(V['urls'][i]), _nombre(V['ips'][i])))
        tous_pres = [nm for nm, v in presence.items()
                     if np.isfinite(v[i]) and v[i] > 0]
        # Les comptes avant troncature, sur leur propre ligne et pres des
        # autres nombres. Dix jetons de plus, et le modele sait enfin ce que
        # les listes coupees lui cachent.
        p.append('n_imports=%d n_exports=%d n_section_names=%d n_dll_in_strings=%d'
                 % (imp_total[i], exp_total[i], len(tous_pres), str_total[i]))
        pres = tous_pres[:MAX_SECTIONS]
        if pres:
            p.append('section_names: ' + ' '.join(pres))
        if imp_par_ligne[i]:
            p.append('imports: ' + ' '.join(imp_par_ligne[i]))
        if exp_par_ligne[i]:
            p.append('exports: ' + ' '.join(exp_par_ligne[i]))
        if str_par_ligne[i]:
            p.append('dll_in_strings: ' + ' '.join(str_par_ligne[i]))
        textes.append('\n'.join(p))

    return dec, textes


def main():
    global MAX_IMPORTS, MAX_SECTIONS, MAX_STRINGS, MAX_EXPORTS, MAX_STR_DLL
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--sortie', default='llm_data')
    # Les plafonds etaient en dur. Les rendre reglables permet de mesurer le
    # texte produit AVANT d engager des heures de GPU : la campagne precedente
    # a ete perdue parce que le texte depassait --maxlen sans qu on le sache.
    ap.add_argument('--max-imports', type=int, default=MAX_IMPORTS)
    ap.add_argument('--max-sections', type=int, default=MAX_SECTIONS)
    ap.add_argument('--max-strings', type=int, default=MAX_STRINGS)
    ap.add_argument('--max-exports', type=int, default=MAX_EXPORTS)
    ap.add_argument('--max-str-dll', type=int, default=MAX_STR_DLL)
    a = ap.parse_args()
    MAX_IMPORTS, MAX_SECTIONS, MAX_STRINGS = a.max_imports, a.max_sections, a.max_strings
    MAX_EXPORTS, MAX_STR_DLL = a.max_exports, a.max_str_dll
    print('plafonds : imports %d  sections %d  strings %d  exports %d  str_dll %d'
          % (MAX_IMPORTS, MAX_SECTIONS, MAX_STRINGS, MAX_EXPORTS, MAX_STR_DLL))
    os.makedirs(a.sortie, exist_ok=True)

    dec, textes = construire(a.donnees)
    lg = [len(t.split()) for t in textes]
    print('%d textes, %d mots en moyenne, %d au maximum'
          % (len(textes), int(np.mean(lg)), max(lg)))
    print('\n--- exemple ---')
    print(textes[0][:600])
    print('---')

    d = pd.DataFrame({
        'sha256': dec.sha256, 'text': textes,
        'label_detection': (dec.label == 'malware').astype(int),
        'label_packing': (dec.packing == 'packed').astype(int),
        'split_random': dec.split_random, 'split_group': dec.split_group,
        'split_family': dec.split_family,
        # Le decoupage temporel est arrive apres les trois autres. Il vaut
        # `null` pour les 15 784 fichiers sans date de compilation ; le script
        # d entrainement filtre sur l egalite, donc ils sont simplement exclus.
        'split_temps': dec.split_temps if 'split_temps' in dec.columns else None,
    })
    p = os.path.join(a.sortie, 'textes.parquet')
    d.to_parquet(p, index=False)
    print('\necrit : %s  (%.1f Mo)' % (p, os.path.getsize(p) / 1e6))
    for c in ('label_detection', 'label_packing'):
        print('  %-18s %d positifs sur %d' % (c, d[c].sum(), len(d)))


if __name__ == '__main__':
    main()
