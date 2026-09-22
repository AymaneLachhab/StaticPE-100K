# Figures du papier, en anglais, toutes dans un seul dossier.
#
#   python corpus/figures_papier_en.py
#
# Sortie : papier/figures/  (le dossier declare par \graphicspath dans main.tex)
#
# Ce script ne recalcule rien. Il lit les memes fichiers que la version
# francaise : results_all/ml/<modele>/trois.json pour les tabulaires,
# results_all/llm/1.5B/ et corpus/qwen_releve.json pour Qwen, et
# corpus/lgb_texte_releve.json pour LightGBM restreint aux colonnes du texte.
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SORTIE = os.path.join(RACINE, 'papier', 'figures')

# Les politiques, de la plus permissive a la plus stricte. L ordre porte la
# lecture : ce que la figure doit montrer est la PENTE, pas une valeur.
POLICIES = [('aleatoire', 'Random'), ('imphash', 'Import-hash'),
            ('famille', 'Family'), ('temps', 'Out-of-time'),
            ('croise', 'Cross-type')]

TASKS = [('detection', 'Detection'), ('packing', 'Packing'),
         ('anti_analysis', 'Anti-analysis'),
         ('menace_ransomware', 'Ransomware'), ('menace_banker', 'Banker')]

MODELS = [('lightgbm', 'LightGBM',      '#1f4e79', '-',  'o'),
          ('foret',    'Random forest', '#2e8b57', '-',  's'),
          ('mlp',      'MLP',           '#b8860b', '-',  '^'),
          ('qwen',     'Qwen 1.5B',     '#a03030', '--', 'D')]

# Deux lectures, deux figures.
#
# SERIES_ML : les trois tabulaires sur la matrice complete. Pas de Qwen, donc
# rien a confondre : ce que la figure compare, ce sont des algorithmes.
#
# SERIES_LLM : deux series seulement, et c est le point. LightGBM restreint
# aux colonnes du texte recoit exactement les champs que Qwen lit. L ecart
# qui subsiste ne peut donc plus s expliquer par une difference d information,
# seulement par l architecture. Ajouter LightGBM sur les 18 489 colonnes
# melangerait les deux effets, ce que la comparaison doit precisement eviter.
SERIES_ML = MODELS[:3]
SERIES_LLM = [('lightgbm_texte', 'LightGBM, 15,319 col.', '#1f4e79', '-',  'o'),
              ('qwen',           'Qwen 1.5B, text',       '#a03030', '--', 'D')]

# Les trois representations sur une meme figure. L ecart entre les deux
# premieres mesure ce qu apportent les 3 170 colonnes absentes du texte, a
# modele constant ; l ecart entre la deuxieme et la troisieme mesure l effet
# de l architecture, a contenu constant. Les mettre ensemble permet de
# comparer les deux effets.
SERIES_REP = [('lightgbm',       'LightGBM, 18,489 col.', '#1f4e79', '-',  'o'),
              ('lightgbm_texte', 'LightGBM, 15,319 col.', '#4a90c2', '-',  's'),
              ('qwen',           'Qwen 1.5B, text',       '#a03030', '--', 'D')]

NOM_LLM = {'aleatoire': 'random', 'imphash': 'group', 'famille': 'family',
           'temps': 'temps', 'croise': 'croise'}

# L audit ne porte que sur la detection binaire. Trois series, toutes epurees
# des colonnes accusees : la matrice complete, la matrice restreinte aux
# colonnes du texte, et le texte lui-meme. Les deux dernieres recoivent la
# meme information, la premiere sert de plafond.
SERIES_AUDIT = [
    ('lightgbm_epure',       'LightGBM, 18,489 col.', '#1f4e79', '-',  'o'),
    ('lightgbm_texte_epure', 'LightGBM, 15,319 col.', '#4a90c2', '-',  's'),
    ('qwen_epure',           'Qwen 1.5B, text',       '#a03030', '--', 'D')]


def charger():
    """-> {(modele, tache, politique): cellule}."""
    t = {}
    for court, *_ in MODELS[:3]:
        chemin = os.path.join(RACINE, 'results_all', 'ml', court, 'trois.json')
        for d in json.load(open(chemin, encoding='utf-8')):
            t[(court, d['tache'], d['protocole'])] = d

    for tache, _ in TASKS[:2]:
        for proto, _ in POLICIES:
            f = os.path.join(RACINE, 'results_all', 'llm', '1.5B',
                             'llm_%s_%s.json' % (tache, NOM_LLM[proto]))
            if os.path.exists(f):
                t[('qwen', tache, proto)] = json.load(open(f, encoding='utf-8'))

    for fichier, court in [('qwen_releve.json', 'qwen'),
                           ('lgb_texte_releve.json', 'lightgbm_texte')]:
        releve = json.load(open(os.path.join(RACINE, 'corpus', fichier),
                                encoding='utf-8'))
        for tache, cellules in releve.items():
            if tache.startswith('_'):
                continue
            for proto, c in cellules.items():
                t[(court, tache, proto)] = c

    # La variante epuree sur la matrice complete.
    etude = os.path.join(RACINE, 'results_all', 'premiere_campagne',
                         'etude.json')
    if os.path.exists(etude):
        for d in json.load(open(etude, encoding='utf-8')):
            if d.get('jeu') == 'epure':
                t[('lightgbm_epure', d['tache'], d['protocole'])] = d

    # Les deux series epurees a information comparable.
    f = os.path.join(RACINE, 'corpus', 'epure_releve.json')
    if os.path.exists(f):
        releve = json.load(open(f, encoding='utf-8'))
        for court, taches in releve.items():
            if court.startswith('_'):
                continue
            for tache, cellules in taches.items():
                for proto, c in cellules.items():
                    t[(court, tache, proto)] = c
    return t


def une_ligne(t, taches, series, sortie, largeur=6.9):
    """Une figure, une tache par colonne, le MCC seul.

    Le MCC seul parce que l accuracy ne se lit pas sans son classifieur
    constant, et que cinq panneaux ne laissent pas la place aux deux. Le
    constant reste trace en pointille : sur les taches desequilibrees il
    monte tres haut en accuracy mais vaut zero en MCC, et c est justement ce
    qui rend le MCC lisible ici."""
    n = len(taches)
    fig, axes = plt.subplots(1, n, figsize=(largeur, 2.35), sharey=True)
    if n == 1:
        axes = [axes]
    x = range(len(POLICIES))

    for j, (tache, titre) in enumerate(taches):
        ax = axes[j]
        for court, nom, couleur, style, marque in series:
            y = [t.get((court, tache, p), {}).get('mcc') for p, _ in POLICIES]
            ax.plot(x, y, style, color=couleur, marker=marque, markersize=3.4,
                    linewidth=1.1, label=nom)
        cst = [t.get(('lightgbm', tache, p), {}).get('mcc_constant')
               for p, _ in POLICIES]
        ax.plot(x, cst, ':', color='#888888', linewidth=1.0, label='Constant')

        ax.set_title(titre, fontsize=8, fontweight='bold')
        ax.set_ylim(-0.05, 1.0)
        ax.set_xticks(list(x))
        ax.set_xticklabels([n_ for _, n_ in POLICIES], rotation=45,
                           ha='right', fontsize=6)
        ax.tick_params(axis='y', labelsize=6.5)
        ax.grid(axis='y', linewidth=0.4, color='#dddddd')
        ax.set_axisbelow(True)
        for bord in ('top', 'right'):
            ax.spines[bord].set_visible(False)

    axes[0].set_ylabel('MCC', fontsize=8)
    axes[0].legend(fontsize=6, frameon=False, loc='lower left')
    fig.subplots_adjust(left=0.08, right=0.99, top=0.88, bottom=0.30,
                        wspace=0.12)
    fig.savefig(sortie, format='pdf')
    plt.close(fig)


def panneaux(t, tache, titre, series, sortie):
    """Deux panneaux, MCC puis accuracy, pour une tache et une liste de series.

    La largeur vaut celle d une colonne de texte, pour que LaTeX n ait pas a
    reduire la figure : une reduction ecraserait les polices sous le seuil de
    lisibilite. Le classifieur constant, lu chez LightGBM, est trace en
    pointille ; il ne depend que de la composition du jeu de test, donc il
    vaut pour toutes les series de la cellule."""
    lignes = [('mcc', 'mcc_constant', 'MCC'),
              ('accuracy', 'accuracy_constant', 'Accuracy')]
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.7))
    x = range(len(POLICIES))

    for ax, (cle, cle_cst, nom_y) in zip(axes, lignes):
        for court, nom, couleur, style, marque in series:
            y = [t.get((court, tache, p), {}).get(cle) for p, _ in POLICIES]
            ax.plot(x, y, style, color=couleur, marker=marque, markersize=3.8,
                    linewidth=1.2, label=nom)
        cst = [t.get(('lightgbm', tache, p), {}).get(cle_cst)
               for p, _ in POLICIES]
        ax.plot(x, cst, ':', color='#888888', linewidth=1.1, label='Constant')

        ax.set_ylabel(nom_y, fontsize=8)
        ax.set_xticks(list(x))
        ax.set_xticklabels([n for _, n in POLICIES], rotation=40, ha='right',
                           fontsize=7)
        ax.tick_params(axis='y', labelsize=7)
        ax.grid(axis='y', linewidth=0.4, color='#dddddd')
        ax.set_axisbelow(True)
        for bord in ('top', 'right'):
            ax.spines[bord].set_visible(False)

    axes[0].legend(fontsize=6.5, frameon=False, loc='best')
    fig.suptitle(titre, fontsize=9, fontweight='bold', y=0.99)
    fig.subplots_adjust(left=0.09, right=0.99, top=0.86, bottom=0.26,
                        wspace=0.28)
    fig.savefig(sortie, format='pdf')
    plt.close(fig)


def deux_metriques(t, taches, series, sortie, largeur=3.45):
    """Une tache par rangee, le MCC a gauche et l accuracy a droite.

    Dimensionnee pour UNE colonne d un papier en deux colonnes, soit environ
    3,45 pouces : la figure se declare en \\begin{figure} et non en figure*,
    et peut donc se placer a l endroit du texte qui la cite.

    Les deux metriques cote a cote parce qu elles ne disent pas la meme
    chose : sur les taches desequilibrees l accuracy reste haute quand le
    MCC s effondre, et c est ce decalage qu il faut voir. Le classifieur
    constant est trace en pointille dans les deux colonnes ; a gauche il
    vaut zero partout, a droite il passe parfois au-dessus du modele, ce qui
    est precisement le point."""
    n = len(taches)
    fig, axes = plt.subplots(n, 2, figsize=(largeur, 0.95 * n + 0.75))
    x = range(len(POLICIES))
    traces, noms = [], []

    colonnes = [('mcc', 'mcc_constant', 'MCC', (-0.05, 1.0)),
                ('accuracy', 'accuracy_constant', 'Accuracy', (0.40, 1.03))]

    for i, (tache, titre) in enumerate(taches):
        for j, (cle, cle_cst, nom_y, bornes) in enumerate(colonnes):
            ax = axes[i][j]
            for court, nom, couleur, style, marque in series:
                y = [t.get((court, tache, p), {}).get(cle) for p, _ in POLICIES]
                ln, = ax.plot(x, y, style, color=couleur, marker=marque,
                              markersize=2.6, linewidth=0.9)
                if i == 0 and j == 0:
                    traces.append(ln); noms.append(nom)
            cst = [t.get(('lightgbm', tache, p), {}).get(cle_cst)
                   for p, _ in POLICIES]
            ln, = ax.plot(x, cst, ':', color='#888888', linewidth=0.9)
            if i == 0 and j == 0:
                traces.append(ln); noms.append('Constant')

            ax.set_ylabel(nom_y, fontsize=5.5)
            ax.set_ylim(*bornes)
            ax.set_xticks(list(x))
            if i == n - 1:
                ax.set_xticklabels([m for _, m in POLICIES], rotation=45,
                                   ha='right', fontsize=5)
            else:
                ax.set_xticklabels([])
            ax.tick_params(axis='y', labelsize=5)
            ax.grid(axis='y', linewidth=0.3, color='#dddddd')
            ax.set_axisbelow(True)
            for bord in ('top', 'right'):
                ax.spines[bord].set_visible(False)
        axes[i][0].set_title(titre, fontsize=7, fontweight='bold', loc='left')

    fig.legend(traces, noms, fontsize=5.5, frameon=False,
               ncol=2 if len(noms) > 3 else len(noms),
               loc='lower center', bbox_to_anchor=(0.5, 0.0))
    fig.subplots_adjust(left=0.13, right=0.98, top=0.95, bottom=0.145,
                        wspace=0.40, hspace=0.45)
    fig.savefig(sortie, format='pdf')
    plt.close(fig)


def figure_audit(t, sortie, largeur=3.45):
    """L audit, detection binaire seule : une representation par rangee,
    reference contre epuree.

    Trois panneaux plutot qu un seul avec six courbes : appariees deux a
    deux, les series sont presque confondues, et les superposer toutes
    rendrait illisible ce qu il faut justement voir, a savoir qu elles le
    sont."""
    reps = [('LightGBM, 18,489 col.', 'lightgbm',       'lightgbm_epure'),
            ('LightGBM, 15,319 col.', 'lightgbm_texte', 'lightgbm_texte_epure'),
            ('Qwen 1.5B, text',       'qwen',           'qwen_epure')]
    colonnes = [('mcc', 'mcc_constant', 'MCC', (-0.05, 1.0)),
                ('accuracy', 'accuracy_constant', 'Accuracy', (0.55, 1.02))]
    fig, axes = plt.subplots(len(reps), 2, figsize=(largeur, 3.75))
    x = range(len(POLICIES))
    traces, noms = [], []

    for i, (titre, ref, epu) in enumerate(reps):
        for j, (cle, cle_cst, nom_y, bornes) in enumerate(colonnes):
            ax = axes[i][j]
            for court, nom, couleur, style, marque in [
                    (ref, 'All columns', '#1f4e79', '-',  'o'),
                    (epu, 'Pruned',      '#c0504d', '--', 's')]:
                y = [t.get((court, 'detection', p), {}).get(cle)
                     for p, _ in POLICIES]
                ln, = ax.plot(x, y, style, color=couleur, marker=marque,
                              markersize=2.6, linewidth=0.9)
                if i == 0 and j == 0:
                    traces.append(ln); noms.append(nom)
            cst = [t.get(('lightgbm', 'detection', p), {}).get(cle_cst)
                   for p, _ in POLICIES]
            ln, = ax.plot(x, cst, ':', color='#888888', linewidth=0.9)
            if i == 0 and j == 0:
                traces.append(ln); noms.append('Constant')

            ax.set_ylabel(nom_y, fontsize=5.5)
            ax.set_ylim(*bornes)
            ax.set_xticks(list(x))
            if i == len(reps) - 1:
                ax.set_xticklabels([m for _, m in POLICIES], rotation=45,
                                   ha='right', fontsize=5)
            else:
                ax.set_xticklabels([])
            ax.tick_params(axis='y', labelsize=5)
            ax.grid(axis='y', linewidth=0.3, color='#dddddd')
            ax.set_axisbelow(True)
            for bord in ('top', 'right'):
                ax.spines[bord].set_visible(False)
        axes[i][0].set_title(titre, fontsize=7, fontweight='bold', loc='left')

    fig.legend(traces, noms, fontsize=5.5, frameon=False, ncol=3,
               loc='lower center', bbox_to_anchor=(0.5, 0.0))
    fig.subplots_adjust(left=0.13, right=0.98, top=0.94, bottom=0.20,
                        wspace=0.40, hspace=0.45)
    fig.savefig(sortie, format='pdf')
    plt.close(fig)


def deux_colonnes(t, taches, series, sortie, largeur=6.9):
    """Cinq taches sur une grille deux colonnes par trois rangees.

    Cinq panneaux alignes sur une seule ligne font 1,3 pouce chacun, ce qui
    est illisible. Deux par rangee en font 3,4 : les courbes se distinguent
    et les etiquettes d abscisse tiennent sans rotation extreme. La sixieme
    case reste libre et recoit la legende, ce qui evite de la superposer a
    une courbe."""
    fig, axes = plt.subplots(3, 2, figsize=(largeur, 5.4), sharey=True)
    plats = [axes[i][j] for i in range(3) for j in range(2)]
    x = range(len(POLICIES))
    traces, noms = [], []

    for k, (tache, titre) in enumerate(taches):
        ax = plats[k]
        for court, nom, couleur, style, marque in series:
            y = [t.get((court, tache, p), {}).get('mcc') for p, _ in POLICIES]
            ln, = ax.plot(x, y, style, color=couleur, marker=marque,
                          markersize=4.2, linewidth=1.3)
            if k == 0:
                traces.append(ln); noms.append(nom)
        cst = [t.get(('lightgbm', tache, p), {}).get('mcc_constant')
               for p, _ in POLICIES]
        ln, = ax.plot(x, cst, ':', color='#888888', linewidth=1.1)
        if k == 0:
            traces.append(ln); noms.append('Constant')

        ax.set_title(titre, fontsize=9.5, fontweight='bold')
        ax.set_ylim(-0.05, 1.0)
        ax.set_xticks(list(x))
        ax.set_xticklabels([n for _, n in POLICIES], rotation=30, ha='right',
                           fontsize=7.5)
        ax.tick_params(axis='y', labelsize=7.5)
        ax.grid(axis='y', linewidth=0.4, color='#dddddd')
        ax.set_axisbelow(True)
        for bord in ('top', 'right'):
            ax.spines[bord].set_visible(False)

    for i in (0, 1, 2):
        axes[i][0].set_ylabel('MCC', fontsize=9)

    # La case laissee libre porte la legende.
    for ax in plats[len(taches):]:
        ax.axis('off')
    if len(taches) < len(plats):
        plats[len(taches)].legend(traces, noms, fontsize=8.5, frameon=False,
                                  loc='center')

    fig.subplots_adjust(left=0.09, right=0.99, top=0.95, bottom=0.07,
                        wspace=0.10, hspace=0.55)
    fig.savefig(sortie, format='pdf')
    plt.close(fig)


def grille(t, sortie):
    """Les cinq taches en colonnes, MCC en haut et accuracy en bas.

    L accuracy n a de sens qu accompagnee du classifieur constant, qui monte
    tres haut sur les taches desequilibrees."""
    lignes = [('mcc', 'mcc_constant', 'MCC', (-0.05, 1.0)),
              ('accuracy', 'accuracy_constant', 'Accuracy', (0.40, 1.02))]
    fig, axes = plt.subplots(len(lignes), len(TASKS),
                             figsize=(14.0, 6.4), sharex='col')
    x = range(len(POLICIES))

    for i, (cle, cle_cst, nom_y, bornes) in enumerate(lignes):
        for j, (tache, titre) in enumerate(TASKS):
            ax = axes[i][j]
            for court, nom, couleur, style, marque in MODELS:
                y = [t.get((court, tache, p), {}).get(cle) for p, _ in POLICIES]
                ax.plot(x, y, style, color=couleur, marker=marque,
                        markersize=4.5, linewidth=1.4, label=nom)
            cst = [t.get(('lightgbm', tache, p), {}).get(cle_cst)
                   for p, _ in POLICIES]
            ax.plot(x, cst, ':', color='#888888', linewidth=1.2,
                    label='Constant' if (i == 0 and j == 0) else None)

            if i == 0:
                ax.set_title(titre, fontsize=10.5, fontweight='bold')
            if j == 0:
                ax.set_ylabel(nom_y, fontsize=10)
            ax.set_ylim(*bornes)
            ax.set_xticks(list(x))
            ax.set_xticklabels([n for _, n in POLICIES], rotation=45,
                               ha='right', fontsize=8)
            ax.grid(axis='y', linewidth=0.4, color='#dddddd')
            ax.set_axisbelow(True)
            for bord in ('top', 'right'):
                ax.spines[bord].set_visible(False)

    axes[0][0].legend(fontsize=8, frameon=False, loc='lower left')
    fig.subplots_adjust(left=0.05, right=0.99, top=0.93, bottom=0.11,
                        wspace=0.12, hspace=0.18)
    fig.savefig(sortie, format='pdf')
    plt.close(fig)


if __name__ == '__main__':
    table = charger()
    absentes = [(m, t_, p) for m, *_ in MODELS for t_, _ in TASKS
                for p, _ in POLICIES if (m, t_, p) not in table]
    if absentes:
        print('cellules absentes : %s' % absentes)

    os.makedirs(SORTIE, exist_ok=True)

    p = os.path.join(SORTIE, 'mcc_by_policy.pdf')
    grille(table, p)
    print('ecrit : %s' % p)

    # Les deux figures d ensemble, MCC et accuracy, une tache par rangee.
    p = os.path.join(SORTIE, 'grid_tabular.pdf')
    deux_metriques(table, TASKS, SERIES_ML, p)
    print('ecrit : %s' % p)

    p = os.path.join(SORTIE, 'grid_text.pdf')
    deux_metriques(table, TASKS, SERIES_LLM, p)
    print('ecrit : %s' % p)

    p = os.path.join(SORTIE, 'grid_representations.pdf')
    deux_metriques(table, TASKS, SERIES_REP, p)
    print('ecrit : %s' % p)

    # La variante compacte, MCC seul, deux colonnes par trois rangees.
    p = os.path.join(SORTIE, 'grid_tabular_mcc.pdf')
    deux_colonnes(table, TASKS, SERIES_ML, p)
    print('ecrit : %s' % p)

    p = os.path.join(SORTIE, 'grid_text_mcc.pdf')
    deux_colonnes(table, TASKS, SERIES_LLM, p)
    print('ecrit : %s' % p)

    # L audit : detection binaire seule, une representation par rangee.
    p = os.path.join(SORTIE, 'audit_detection.pdf')
    figure_audit(table, p)
    print('ecrit : %s' % p)

    for tache, titre in TASKS:
        court = tache.replace('menace_', '')
        p = os.path.join(SORTIE, 'tabular_%s.pdf' % court)
        panneaux(table, tache, '%s: tabular models' % titre, SERIES_ML, p)
        print('ecrit : %s' % p)

        p = os.path.join(SORTIE, 'llm_%s.pdf' % court)
        panneaux(table, tache, '%s: comparable information' % titre,
                 SERIES_LLM, p)
        print('ecrit : %s' % p)
