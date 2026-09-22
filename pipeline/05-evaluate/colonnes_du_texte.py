# Construit la liste des colonnes que LightGBM doit voir pour recevoir
# EXACTEMENT ce que recoit le modele de langue dans le texte lisible.
#
# Pourquoi ce script
# ------------------
# La comparaison publiee jusqu ici est asymetrique : LightGBM lit 18 489
# colonnes, Qwen lit 17 scalaires et quatre listes de noms tronquees. Tant
# qu on ne restreint pas le premier, on ne peut pas ecrire que l ecart vient
# de l architecture plutot que de l information.
#
# Ce script ecrit un colonnes.json au format attendu par
# `trois_modeles.py --colonnes`, contenant :
#   - les 17 scalaires des trois premieres lignes du texte
#   - toutes les colonnes `imp:`, `exp:`, `dll:` et `str:dll_names=`
#   - les colonnes `sec_*_raw`, d ou sont tires les noms de sections
#
# La seule difference qui subsiste avec le texte est la TRONCATURE : le
# texte coupe a 120 imports, 60 exports, 20 sections, 20 dll, alors que la
# matrice les garde tous. L ecart restant est donc une borne SUPERIEURE de
# l avantage de LightGBM, et c est ce qu il faut ecrire.
#
# Les noms exacts viennent d un audit_*.csv, pas d une liste ecrite a la
# main : si une colonne changeait de nom, le script s en apercevrait.
#
#   python corpus/colonnes_du_texte.py results_all/premiere_campagne/audit_detection_aleatoire.csv
import hashlib
import json
import os
import sys

import pandas as pd

# Les trois premieres lignes du texte, dans l ordre ou elles y figurent.
SCALAIRES = [
    'general_info__file_type', 'general_info__size_bytes',
    'file_header__numberof_sections', 'file_header__machine',
    'optional_header__subsystem',
    'byte_features__file_entropy', 'resources__max_entropy',
    'dotnet__is_dotnet', 'digital_signature__verification_flag',
    'digital_signature__certificates__n', 'checksum_check__checksum_valid',
    'strings__count_total', 'strings__len_mean', 'strings__len_max',
    'strings__count_utf16', 'strings__urls__n', 'strings__ipv4__n',
]

# Les quatre listes de noms. Les prefixes sont ceux de serialiser_llm.py :
# c est de la que sortent `imports:`, `exports:` et `dll_in_strings:`.
PREFIXES = ('imp:', 'exp:', 'dll:', 'str:dll_names=')


def construire(chemin_audit):
    noms = list(pd.read_csv(chemin_audit)['feature'])
    connus = set(noms)

    absents = [c for c in SCALAIRES if c not in connus]
    if absents:
        raise SystemExit('scalaires absents de la matrice : %s'
                         % ', '.join(absents))

    # Les noms de sections du texte viennent des colonnes pivotees
    # `sec_<nom>_raw` -- meme source, meme vocabulaire.
    sections = sorted(c for c in noms
                      if c.startswith('sec_') and c.endswith('_raw'))
    listes = sorted(c for c in noms if c.startswith(PREFIXES))

    colonnes = SCALAIRES + sections + listes
    # Une empreinte sur la liste ordonnee : deux runs qui l affichent
    # identique ont vu la meme chose, sans avoir a comparer 15 000 noms.
    empreinte = hashlib.sha256('\n'.join(colonnes).encode()).hexdigest()[:16]
    return {
        'variante': 'texte_lisible',
        'empreinte_vocabulaire': empreinte,
        'colonnes': colonnes,
        'detail': {'scalaires': len(SCALAIRES), 'sections': len(sections),
                   'listes_de_noms': len(listes)},
    }


if __name__ == '__main__':
    audit = sys.argv[1] if len(sys.argv) > 1 else \
        'results_all/premiere_campagne/audit_detection_aleatoire.csv'
    spec = construire(audit)
    sortie = sys.argv[2] if len(sys.argv) > 2 else 'colonnes_texte_lisible.json'
    json.dump(spec, open(sortie, 'w', encoding='utf-8'), indent=1)
    d = spec['detail']
    print('%d colonnes  (%d scalaires, %d sections, %d noms)'
          % (len(spec['colonnes']), d['scalaires'], d['sections'],
             d['listes_de_noms']))
    print('empreinte %s' % spec['empreinte_vocabulaire'])
    print('ecrit : %s' % os.path.abspath(sortie))
