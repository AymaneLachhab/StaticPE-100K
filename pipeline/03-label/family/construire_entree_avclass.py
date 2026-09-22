# -*- coding: utf-8 -*-
"""
Fabrique l entree AVClass a partir des verdicts antivirus deja sur le disque.

Pourquoi
--------
Les quinze etiquettes de menace du corpus sont HERITEES de la famille : on sait
que le fichier est un Dridex, on sait que Dridex est un banker, on ecrit banker
sur le fichier. L etiquette decrit la lignee, pas le binaire.

AVClass sait produire des etiquettes d une autre origine : il lit les NOMS DE
DETECTION que les antivirus ont donnes A CE FICHIER et en extrait des tags de
classe. L affirmation porte alors sur l echantillon.

Ce script rassemble les verdicts disponibles et les met au format qu AVClass
attend, pour que les memes fichiers puissent etre etiquetes des deux facons et
compares.

Les deux sources
----------------
  StaticPE/virusshare_meta.jsonl   9 313 rapports, 22 moteurs en moyenne,
                                   noms de detection complets.
  mb_tags.jsonl                   54 822 hashes uniques, 4.9 noms exploitables
                                   en moyenne. Le champ `vendor` melange de
                                   vrais noms (ReversingLabs, Kaspersky) et des
                                   verdicts sans contenu (Malicious File,
                                   clean1, 3). Les seconds sont ecartes :
                                   AVClass ne peut rien tirer d un mot qui ne
                                   nomme pas une famille.

Ce que le resultat ne sera pas
------------------------------
Une reconstitution de l entree d origine. Celle-ci portait 100 729 rapports et
a disparu. Ici on couvre environ 49 800 fichiers du corpus, soit a peu pres la
meme population que les 49 845 qui portent aujourd hui une etiquette heritee.
C est une coincidence utile : la comparaison se fera a population constante.

  python construire_entree_avclass.py --sortie avclass_entree.jsonl
  avclass -f avclass_entree.jsonl -t -o avclass_tags.tsv
"""
import os, re, json, io, argparse, collections

# Un verdict qui ne nomme rien. AVClass vote sur des noms de familles ; lui
# donner "Malicious File" revient a lui donner du bruit.
VIDE = re.compile(r'^(no threats?( detected)?|nothreats?|clean\d*|malicious( file)?|'
                  r'suspicious|undetected|not (detected|malicious)|benign|unknown|'
                  r'\d+|ok|none|-|timeout|error)$', re.I)


def utile(v):
    return isinstance(v, str) and v.strip() and not VIDE.match(v.strip())


def lire_virusshare(chemin, acc):
    """scans {moteur: nom} -> {moteur: {detected, result}}."""
    n = 0
    if not os.path.exists(chemin):
        print('absent, ignore : %s' % chemin)
        return 0
    with io.open(chemin, encoding='utf-8', errors='replace') as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                d = json.loads(ligne)
            except Exception:
                continue
            sha = (d.get('sha256') or '').lower()
            if not sha:
                continue
            e = acc.setdefault(sha, {'sha256': sha, 'md5': d.get('md5'),
                                     'sha1': d.get('sha1'), 'scans': {}})
            e['md5'] = e['md5'] or d.get('md5')
            for moteur, res in (d.get('scans') or {}).items():
                if isinstance(res, dict):
                    res = res.get('result')
                if utile(res):
                    e['scans'][moteur] = {'detected': True, 'result': res.strip()}
            n += 1
    return n


def lire_malwarebazaar(chemin, acc):
    """vendor et le clamav de intelligence, filtres des verdicts vides."""
    n = 0
    if not os.path.exists(chemin):
        print('absent, ignore : %s' % chemin)
        return 0
    with io.open(chemin, encoding='utf-8', errors='replace') as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                d = json.loads(ligne)
            except Exception:
                continue
            sha = (d.get('sha256') or d.get('sha256_hash') or '').lower()
            if not sha:
                continue
            e = acc.setdefault(sha, {'sha256': sha, 'md5': None,
                                     'sha1': None, 'scans': {}})
            for moteur, res in (d.get('vendor') or {}).items():
                if utile(res):
                    e['scans'].setdefault(moteur, {'detected': True,
                                                   'result': res.strip()})
            # clamav arrive sous forme de liste de signatures
            cl = (d.get('intelligence') or {}).get('clamav')
            if isinstance(cl, list):
                bons = [x for x in cl if utile(x)]
                for i, res in enumerate(bons):
                    e['scans'].setdefault('ClamAV_%d' % i,
                                          {'detected': True, 'result': res.strip()})
            n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--virusshare', default=os.path.join('StaticPE', 'virusshare_meta.jsonl'))
    ap.add_argument('--malwarebazaar', default='mb_tags.jsonl')
    ap.add_argument('--corpus', default=os.path.join('Dataset parquet', 'familles.parquet'),
                    help='ne garder que les hashes du corpus ; vide pour tout garder')
    ap.add_argument('--min-moteurs', type=int, default=2,
                    help='sous ce nombre de noms, AVClass ne vote sur rien')
    ap.add_argument('--sortie', default='avclass_entree.jsonl')
    a = ap.parse_args()

    acc = {}
    print('%6d lignes lues dans virusshare' % lire_virusshare(a.virusshare, acc))
    print('%6d lignes lues dans malwarebazaar' % lire_malwarebazaar(a.malwarebazaar, acc))
    print('%6d hashes distincts' % len(acc))

    garde = None
    if a.corpus and os.path.exists(a.corpus):
        import pyarrow.parquet as pq
        garde = set(x.lower() for x in
                    pq.read_table(a.corpus, columns=['sha256']).column('sha256').to_pylist())
        print('%6d hashes dans le corpus' % len(garde))

    ecrits = trop_peu = hors = 0
    dist = collections.Counter()
    with io.open(a.sortie, 'w', encoding='utf-8') as sortie:
        for sha, e in acc.items():
            if garde is not None and sha not in garde:
                hors += 1
                continue
            if len(e['scans']) < a.min_moteurs:
                trop_peu += 1
                continue
            dist[min(len(e['scans']), 20)] += 1
            # AVClass exige md5, sha1 et sha256 presents, et s en sert pour
            # retirer des noms les jetons qui ressemblent a un hash. Un null le
            # fait planter, une clef absente aussi : on met la chaine vide, qui
            # ne correspondra jamais a un jeton.
            propre = dict(e)
            for cle in ('md5', 'sha1', 'sha256'):
                propre[cle] = propre.get(cle) or ''
            sortie.write(json.dumps(propre, ensure_ascii=False) + '\n')
            ecrits += 1

    print()
    print('ecarte, hors corpus         : %6d' % hors)
    print('ecarte, moins de %d moteurs  : %6d' % (a.min_moteurs, trop_peu))
    print('ecrit dans %-17s : %6d' % (a.sortie, ecrits))
    print()
    print('moteurs par echantillon :')
    for k in sorted(dist):
        print('   %2d%s %6d' % (k, '+' if k == 20 else ' ', dist[k]))
    print()
    print('etape suivante :')
    print('   avclass -f %s -t -o avclass_tags.tsv' % a.sortie)


if __name__ == '__main__':
    main()
