# -*- coding: utf-8 -*-
"""
Cartographie famille -> comportement, a partir de sources citables.

Pourquoi refaire ce travail
---------------------------
La table actuelle attribue 41 006 etiquettes sur 49 845, soit 82 %, et ne
conserve aucune reference : on ne peut pas dire, pour une famille donnee, ce
qui a justifie la decision. Une verification manuelle sur sept familles a
trouve deux sous-etiquetages (emotet perd stealer, zeus perd stealer et
botnet) et un sur-etiquetage (stop porte un stealer que personne ne documente,
parce que Vidar est distribue avec lui).

La methode
----------
On ne demande pas "quelle categorie ?", on pose quinze questions sur des
actions observables. Une categorie est attribuee quand la description contient
un motif qui repond oui, et la phrase qui l a declenche est conservee. Cela
rend chaque etiquette verifiable en ouvrant une URL.

Deux sources
------------
  malpedia  description curee, recuperee par l API publique. 487 familles du
            corpus s y trouvent, 333 avec une description non vide.
  avclass   tags CLASS: et BEH: extraits des noms de detection antivirus,
            agreges par famille. Couvre les familles que Malpedia ignore, au
            prix d une granularite plus grossiere : sa taxonomie ne connait
            ni banker ni loader.

Une categorie est retenue des qu une source la documente. Les deux sources
sont complementaires : Malpedia decrit le programme, AVClass resume ce que les
moteurs ont ecrit sur ses echantillons.

Ce que le resultat n est pas
----------------------------
Une verite terrain. C est une cartographie tracee : chaque ligne porte sa
source, son URL et sa preuve, donc chaque ligne est contestable une par une.
C est precisement ce que la table actuelle ne permet pas.

  python cartographier_familles.py --sortie cartographie.parquet
"""
import os, re, json, io, argparse, collections
import pandas as pd

API = 'https://malpedia.caad.fkie.fraunhofer.de/api/get/families'
URL_FAM = 'https://malpedia.caad.fkie.fraunhofer.de/details/%s'
URL_MS = ('https://www.microsoft.com/en-us/wdsi/threats/'
          'malware-encyclopedia-description?Name=Win32/%s')

# Le prefixe d un nom de menace Microsoft est une classification. Les prefixes
# muets -- Trojan, Program, SoftwareBundler -- sont absents a dessein.
MS_PREFIXE = {
    'ransom': 'ransomware', 'trojandownloader': 'downloader',
    'trojandropper': 'loader', 'backdoor': 'backdoor', 'pws': 'stealer',
    'trojanspy': 'stealer', 'passwordstealer': 'stealer', 'worm': 'worm',
    'virus': 'fileinfector', 'adware': 'adware',
    'browsermodifier': 'adware', 'trojanclicker': 'adware', 'spammer': 'botnet',
    'trojanproxy': 'botnet', 'spyware': 'stealer',
    'ddos': 'botnet', 'coinminer': 'miner', 'remoteaccess': 'rat',
    'hacktool': 'postexploitation', 'exploit': 'postexploitation',
    'monitoringtool': 'keylogger',
}

QUINZE = ['stealer', 'loader', 'banker', 'rat', 'ransomware', 'botnet', 'worm',
          'keylogger', 'miner', 'fileinfector', 'backdoor', 'postexploitation',
          'clipper', 'downloader', 'adware']

# Un motif par question posee. On cherche l action, pas le mot de la taxonomie :
# Malpedia ecrit "encrypts user data through AES-256" sans jamais ecrire
# "ransomware", et une recherche sur le nom de la categorie raterait la famille.
MOTIFS = {
 'ransomware': r'\bransomware\b|\bransom\b|encrypt(s|ing)?\b.{0,30}\b(file|data)'
               r'|file[- ]encrypt|demands? (a )?(ransom|payment)|extortion',
 'stealer':    r'\bstealer\b|steal(s|ing)?\b|info[- ]?steal|exfiltrat|harvest(s|ing)?\b|'
               r'credential|password|browser data|wallet|cookies',
 'banker':     r'\bbanking\b|\bbanker\b|online bank|bank(ing)? (trojan|credential)|'
               r'web ?inject|form ?grab|financial (data|information|institution)',
 'keylogger':  r'\bkeylog|keystroke|key ?logging|records? (user )?input|screenshot|'
               r'screen ?capture',
 'clipper':    r'\bclipper\b|clipboard',
 'loader':     r'\bloader\b|load(s|ing)? (additional|secondary|other|further)|'
               r'install(s|ing)? (the )?(payload|additional|secondary)|drops? and (runs|executes)|'
               r'\bdropper\b|deliver(s|ing)? (additional|secondary|other)',
 'downloader': r'\bdownloader\b|download(s|ing)? (and (execut|run))?|retriev(e|es|ing) '
               r'(additional|the |a )?(payload|malware|module|file)|fetch(es|ing)? (a |the )?payload',
 'backdoor':   r'\bbackdoor\b|persistent access|covert access|remote shell',
 'rat':        r'\bRAT\b|remote[- ]access (tool|trojan)|remote control|remote administration|'
               r'\bVNC\b|control (of )?the (victim|infected|remote) (machine|host|computer)',
 'postexploitation': r'post[- ]?exploitation|post[- ]?compromise|penetration[- ]?testing|'
               r'red[- ]?team|\bC2 framework\b|command[- ]and[- ]control framework|\bbeacon\b',
 'botnet':     r'\bbotnet\b|\bbot\b|peer[- ]to[- ]peer network|enrol|zombie|'
               r'network of (infected|compromised)|\bDDoS\b|\bproxy\b|spam(bot|ming)?',
 'worm':       r'\bworm\b|self[- ]propagat|spread(s|ing)? (itself |automatically |to other)|'
               r'\bEternalBlue\b|removable (drive|media)|copies itself',
 'fileinfector': r'file[- ]?infector|\bfile infect|infect(s|ing)? (existing |other )?(executable|file|PE)|'
               r'appends? itself|prepends? itself|parasitic',
 'miner':      r'\bminer\b|mining|cryptocurrency mining|\bXMRig\b|\bMonero\b|coin ?min',
 'adware':     r'\badware\b|advertis(ing|ement)|\bpop[- ]?up|inject(s|ing)? ads|'
               r'unwanted (software|program)|\bPUP\b|\bPUA\b',
}
MOTIFS = {k: re.compile(v.replace('\n', '').replace('  ', ' '), re.I)
          for k, v in MOTIFS.items()}

# La taxonomie AVClass est plus grossiere que les quinze : elle ne connait ni
# banker ni loader ni postexploitation. On ne traduit que ce qui a un sens.
AVCLASS = {
 'CLASS:ransomware': 'ransomware', 'BEH:filecrypt': 'ransomware',
 'CLASS:downloader': 'downloader', 'BEH:execdownload': 'downloader',
 'CLASS:backdoor': 'backdoor',     'BEH:server': 'backdoor',
 'CLASS:spyware': 'stealer',       'BEH:infosteal': 'stealer',
 'CLASS:worm': 'worm',             'BEH:selfpropagate': 'worm',
 'CLASS:miner': 'miner',           'BEH:mining': 'miner',
 'CLASS:keylogger': 'keylogger',   'BEH:keylogging': 'keylogger',
 'CLASS:virus': 'fileinfector',    'CLASS:infector': 'fileinfector',
 'CLASS:clipper': 'clipper',
 'CLASS:grayware:adware': 'adware',
 'CLASS:bot': 'botnet',            'BEH:ddos': 'botnet', 'BEH:proxy': 'botnet',
 'CLASS:grayware:tool:remoteadmin': 'rat',
}

# Noms que les moteurs posent quand ils ne savent pas. Leur attribuer un
# comportement serait tautologique ou faux.
GENERIQUES = {'wacatac', 'lazy', 'sadenav', 'wingo', 'kykymber', 'zard', 'shyape',
              'pasta', 'minix', 'taskun', 'coinminer', 'clipbanker', 'adware.generic',
              'generic', 'unknown', 'malware', 'trojan', 'coinminer.xmrig'}


def norm(x):
    return re.sub(r'[^a-z0-9]', '', str(x).lower())


def charger_malpedia(cache='malpedia_familles.json'):
    if os.path.exists(cache):
        return json.load(open(cache, encoding='utf-8'))
    import urllib.request
    req = urllib.request.Request(API, headers={'User-Agent': 'PEStatic-research/1.0'})
    M = json.loads(urllib.request.urlopen(req, timeout=120).read().decode('utf-8', 'replace'))
    json.dump(M, open(cache, 'w', encoding='utf-8'), ensure_ascii=False)
    return M


def phrase_autour(texte, m, largeur=160):
    """La phrase qui contient le motif.

    On coupe sur le point ET sur le retour a la ligne : les descriptions
    Malpedia melent de la prose et des chronologies en liste, et ne couper que
    sur le point renvoyait parfois un bloc entier ou le motif se perdait.
    On verifie ensuite que le motif est bien dans ce qu on renvoie, sans quoi
    la preuve montrerait autre chose que ce qui a declenche l etiquette.
    """
    debut = max(texte.rfind('.', 0, m.start()), texte.rfind(chr(10), 0, m.start())) + 1
    fin = min([x for x in (texte.find('.', m.end()), texte.find(chr(10), m.end()))
               if x >= 0] or [len(texte)])
    s = texte[debut:min(fin + 1, len(texte))].strip()
    if m.group(0).lower() not in s.lower():
        s = texte[max(0, m.start() - 70):m.end() + 70].strip()
    return (s[:largeur] + '...') if len(s) > largeur else s


# Une phrase comme "may also lead to ransomware attacks using Ryuk" decrit ce
# que la famille LIVRE, pas ce qu elle fait. C est l erreur STOP/Vidar, et un
# motif nu la reproduit. On ecarte la phrase quand elle porte une de ces
# tournures de livraison a moins que la categorie soit loader ou downloader,
# pour qui livrer EST le comportement.
LIVRAISON = re.compile(r'lead(s|ing)? to|used (by|for) .{0,30}(install|deploy)|'
                       r'deliver(s|ing|ed)?|drops?|distribut|alongside|'
                       r'followed by|precursor|second[- ]stage payload', re.I)


def depuis_malpedia(fam, cle, desc):
    lignes = []
    if not desc:
        return lignes
    for cat, mot in MOTIFS.items():
        for m in mot.finditer(desc):
            ph = phrase_autour(desc, m)
            # On juge le voisinage immediat, pas la phrase entiere : chez
            # Emotet, "organized in a botnet" et "may lead to ransomware
            # attacks" cohabitent dans la meme phrase, et filtrer la phrase
            # supprimait le vrai positif avec le faux.
            avant = desc[max(0, m.start() - 60):m.start()]
            if cat not in ('loader', 'downloader') and LIVRAISON.search(avant):
                continue
            lignes.append({'famille': fam, 'categorie': cat, 'source': 'malpedia',
                           'url': URL_FAM % cle, 'preuve': ph})
            break
    return lignes


def depuis_avclass(chemin_tags, fam_par_sha, min_moteurs=2, min_part=0.30,
                   min_echantillons=5):
    """Agrege les tags par famille. Un tag ne compte que s il est soutenu par
    plusieurs moteurs ET present sur une part non negligeable de la famille :
    un tag vu une fois sur mille echantillons ne caracterise pas la lignee."""
    par_fam = collections.defaultdict(collections.Counter)
    taille = collections.Counter()
    if not os.path.exists(chemin_tags):
        print('absent, ignore : %s' % chemin_tags)
        return []
    with io.open(chemin_tags, encoding='utf-8', errors='replace') as f:
        for ligne in f:
            p = ligne.rstrip('\n').split('\t')
            if len(p) < 3:
                continue
            fam = fam_par_sha.get(p[0].lower())
            if not fam:
                continue
            taille[fam] += 1
            if not p[2]:
                continue
            vus = set()
            for t in p[2].split(','):
                if '|' not in t:
                    continue
                nom, n = t.rsplit('|', 1)
                if nom in AVCLASS and int(n) >= min_moteurs:
                    vus.add(AVCLASS[nom])
            # CLASS:ransomware et BEH:filecrypt designent le meme echantillon :
            # les compter deux fois donnait des parts au-dela de 100 %.
            for cat in vus:
                par_fam[fam][cat] += 1
    lignes = []
    for fam, c in par_fam.items():
        for cat, n in c.items():
            part = n / max(taille[fam], 1)
            # Une proportion seule ne suffit pas : une famille dont un seul
            # echantillon est tagge atteint 100 % sans rien demontrer. On exige
            # donc aussi un nombre absolu.
            if part >= min_part and n >= min_echantillons:
                lignes.append({'famille': fam, 'categorie': cat, 'source': 'avclass',
                               'url': '', 'preuve': '%d of %d samples tagged (%.0f%%)'
                               % (n, taille[fam], 100 * part)})
    return lignes


def depuis_microsoft(chemin, fichiers_par_fam):
    """Les prefixes collectes par microsoft_familles.py. La preuve est le nom
    complet de l entree, qui se verifie en ouvrant l URL de recherche."""
    lignes = []
    if not os.path.exists(chemin):
        print('absent, ignore : %s' % chemin)
        return lignes
    with io.open(chemin, encoding='utf-8') as f:
        for ligne in f:
            try:
                d = json.loads(ligne)
            except Exception:
                continue
            fam = str(d.get('famille', '')).lower()
            # On recalcule depuis les entrees brutes plutot que de lire le
            # champ `categories` du JSONL : celui-ci a ete fige au moment du
            # scrape, avec une table de prefixes qui contenait deux erreurs.
            # Les entrees, elles, sont ce que Microsoft a repondu.
            cats = sorted({MS_PREFIXE[e.split(':')[0].lower()]
                           for e in (d.get('entrees') or [])
                           if e.split(':')[0].lower() in MS_PREFIXE})
            for cat in cats:
                pre = [e for e in (d.get('entrees') or [])
                       if MS_PREFIXE.get(e.split(':')[0].lower()) == cat]
                lignes.append({'famille': fam, 'categorie': cat, 'source': 'microsoft',
                               'url': URL_MS % fam,
                               'preuve': ', '.join(pre[:3]) or 'prefix match'})
    return lignes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--familles', default='familles_toutes.csv')
    ap.add_argument('--tags', default='avclass_tags')
    ap.add_argument('--donnees', default='Dataset parquet')
    ap.add_argument('--microsoft', default='microsoft_prefixes.jsonl')
    ap.add_argument('--sortie', default='cartographie.parquet')
    a = ap.parse_args()

    M = charger_malpedia()
    idx = {}
    for k, v in M.items():
        court = k.split('.', 1)[1] if '.' in k else k
        for n in [court, v.get('common_name') or ''] + (v.get('alt_names') or []):
            if norm(n):
                idx.setdefault(norm(n), k)

    d = pd.read_csv(a.familles, sep=';')
    lignes = []
    vus_malpedia = 0
    for _, r in d.iterrows():
        fam = str(r.famille).lower()
        if fam in GENERIQUES:
            lignes.append({'famille': fam, 'categorie': '(GENERIQUE)', 'source': 'regle',
                           'url': '', 'preuve': 'generic antivirus label, not a family'})
            continue
        cle = idx.get(norm(fam))
        if cle:
            desc = M[cle].get('description') or ''
            n0 = len(lignes)
            lignes += depuis_malpedia(fam, cle, desc)
            if len(lignes) > n0:
                vus_malpedia += 1

    import pyarrow.parquet as pq
    f = pq.read_table(os.path.join(a.donnees, 'familles.parquet'),
                      columns=['sha256', 'family']).to_pandas()
    # AVClass indexe sa sortie par le MD5, pas par le SHA-256 : c est la
    # premiere colonne du rapport VirusTotal qu on lui a donne. Il faut donc
    # la table de correspondance, sinon la jointure ne rend rien du tout.
    g = pq.read_table(os.path.join(a.donnees, 'general_info.parquet'),
                      columns=['sha256', 'general_info__md5']).to_pandas()
    md5_par_sha = {s.lower(): str(m).lower()
                   for s, m in zip(g.sha256, g.general_info__md5) if isinstance(m, str)}
    fam_par_sha = {}
    for s, x in zip(f.sha256, f.family):
        if not isinstance(x, str):
            continue
        fam_par_sha[s.lower()] = str(x).lower()
        m = md5_par_sha.get(s.lower())
        if m:
            fam_par_sha[m] = str(x).lower()
    lignes += depuis_avclass(a.tags, fam_par_sha)
    lignes += depuis_microsoft(a.microsoft, dict(zip(d.famille, d.fichiers)))

    out = pd.DataFrame(lignes)
    if out.empty:
        raise SystemExit('aucune ligne produite')
    out = out.merge(d[['famille', 'fichiers']], on='famille', how='left')
    out = out[['famille', 'fichiers', 'categorie', 'source', 'url', 'preuve']]
    out = out.sort_values(['fichiers', 'famille', 'categorie', 'source'],
                          ascending=[False, True, True, True])
    out.to_parquet(a.sortie, index=False)
    out.to_csv(a.sortie.replace('.parquet', '.csv'), index=False, sep=';', encoding='utf-8')

    vraies = out[~out.categorie.isin(['(GENERIQUE)'])]
    couv = d[d.famille.isin(set(vraies.famille))].fichiers.sum()
    print('lignes produites          : %6d' % len(out))
    print('familles cartographiees   : %6d sur %d' % (vraies.famille.nunique(), len(d)))
    print('malwares couverts         : %6d sur %d  (%.1f %%)'
          % (couv, d.fichiers.sum(), 100 * couv / d.fichiers.sum()))
    print()
    print('par source :')
    print(out.source.value_counts().to_string())
    print()
    print('par categorie :')
    print(vraies.categorie.value_counts().to_string())
    print()
    print('ecrit : %s et %s' % (a.sortie, a.sortie.replace('.parquet', '.csv')))


if __name__ == '__main__':
    main()
