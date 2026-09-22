# -*- coding: utf-8 -*-
"""
Fine-tune a Qwen sequence classifier on serialised PE descriptions.

One run = one task x one split. Six runs cover the experiment:

    detection x {random, group, family}
    packing   x {random, group, family}

Each run can sit on its own GPU, so four of them go in parallel:

    CUDA_VISIBLE_DEVICES=0 python finetune_llm.py --task detection --split random &
    CUDA_VISIBLE_DEVICES=1 python finetune_llm.py --task detection --split group  &
    CUDA_VISIBLE_DEVICES=2 python finetune_llm.py --task detection --split family &
    CUDA_VISIBLE_DEVICES=3 python finetune_llm.py --task packing   --split random &

Why a hand-written loop rather than Trainer
-------------------------------------------
transformers 5.x changed the Trainer API, and the one thing that must not be
wrong here is the threshold protocol: the decision threshold is chosen on the
VALIDATION set and then frozen before the test set is touched. Writing the loop
makes that visible in twenty lines instead of hidden behind a callback.

What the model is allowed to see
--------------------------------
Only the `text` column. The script selects it explicitly rather than dropping
known leaks, so a column added later cannot slip into training. sha256, md5,
imphash, timestamps and family names never reach the tokenizer.

The control that makes the numbers readable
-------------------------------------------
The majority-class baseline is recomputed on each test set rather than assumed.
The three splits do not share a class balance: detection is 83.1 % positive on
the random split, packing only 52.1 % on the family split. Comparing an
accuracy to the wrong baseline is how a useless model looks good.
"""
import os, json, time, argparse, random
import numpy as np, pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_cosine_schedule_with_warmup
from sklearn.metrics import (roc_auc_score, average_precision_score, matthews_corrcoef,
                             precision_recall_fscore_support, confusion_matrix)

SPLIT_COL = {'random': 'split_random', 'group': 'split_group',
             'family': 'split_family', 'temps': 'split_temps',
             'croise': 'split_croise'}
LABEL_COL = {'detection': 'label_detection', 'packing': 'label_packing',
             'menace_ransomware': 'label_menace_ransomware',
             'anti_analysis': 'label_anti_analysis'}

# La consigne prefixee au texte quand --instruction est passe. Elle est fixe,
# ecrite ici et nulle part ailleurs, pour qu un run soit reproductible a la
# lettre. Elle ne nomme jamais la famille ni le verdict d un antivirus : elle
# decrit le comportement recherche, et rien d autre.
INSTRUCTION = {
    'detection': 'Decide whether this Windows PE file is malicious. '
                 'Use only the features below.',
    'packing': 'Decide whether this Windows PE file is packed, that is, '
               'whether its real code is compressed or encrypted and unpacked '
               'at run time. Use only the features below.',
    'anti_analysis': 'Decide whether this Windows PE file has anti-analysis '
                     'capability: detecting a virtual machine, a debugger or '
                     'a sandbox, or resisting disassembly. Use only the '
                     'features below.',
    'menace_ransomware': 'Decide whether this Windows PE file has ransomware '
                         'capability, that is, whether it encrypts the '
                         "victim's files in order to demand a payment. "
                         'Use only the features below.',
}


def graine(g):
    random.seed(g); np.random.seed(g); torch.manual_seed(g); torch.cuda.manual_seed_all(g)


class Textes(Dataset):
    def __init__(self, textes, labels, tok, maxlen):
        self.t, self.y, self.tok, self.maxlen = list(textes), list(labels), tok, maxlen

    def __len__(self):
        return len(self.t)

    def __getitem__(self, i):
        return self.t[i], self.y[i]


def collate(lot, tok, maxlen):
    textes, y = zip(*lot)
    e = tok(list(textes), truncation=True, max_length=maxlen, padding=True, return_tensors='pt')
    e['labels'] = torch.tensor(y, dtype=torch.long)
    return e


@torch.no_grad()
def proba(modele, chargeur, dev):
    modele.eval()
    out = []
    for lot in chargeur:
        lot = {k: v.to(dev, non_blocking=True) for k, v in lot.items()}
        lot.pop('labels', None)
        with torch.autocast('cuda', dtype=torch.bfloat16):
            logits = modele(**lot).logits.float()
        out.append(torch.softmax(logits, -1)[:, 1].cpu())
    p = torch.cat(out).numpy()
    # A NaN here means the run diverged. Better to stop than to write a JSON
    # full of scores computed on garbage.
    if not np.isfinite(p).all():
        raise RuntimeError('%d non-finite probabilities out of %d: the run diverged, '
                           'lower --lr or check the class weights' % ((~np.isfinite(p)).sum(), len(p)))
    return p


def seuil_sur_validation(yva, pva):
    """The threshold is chosen here and nowhere else.

    Ninety-nine candidate cut-points taken from the validation distribution
    itself; the one maximising validation MCC wins. On an 83 % positive task a
    fixed 0.5 would put every prediction on one side and report MCC 0 for a
    model that ranks perfectly well."""
    best, bmcc = 0.5, -1.0
    for t in np.unique(np.quantile(pva, np.linspace(.01, .99, 99))):
        m = matthews_corrcoef(yva, (pva >= t).astype(int))
        if m > bmcc:
            bmcc, best = m, float(t)
    return best, bmcc


def mesurer(yt, p, seuil):
    yp = (p >= seuil).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(yt, yp, average='binary', zero_division=0)
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
    maj = int(yt.mean() >= .5)
    return {
        'n_test': int(len(yt)), 'positive_rate': float(yt.mean()), 'threshold': round(seuil, 6),
        'accuracy': float((tp + tn) / len(yt)),
        'mcc': float(matthews_corrcoef(yt, yp)),
        'roc_auc': float(roc_auc_score(yt, p)) if yt.min() != yt.max() else None,
        'pr_auc': float(average_precision_score(yt, p)),
        'f1': float(f1), 'precision': float(pr), 'recall': float(rc),
        'tp': int(tp), 'tn': int(tn), 'fn': int(fn), 'fp': int(fp),
        # Recomputed per split, never assumed: the three splits differ in balance.
        'majority_accuracy': float(max(yt.mean(), 1 - yt.mean())),
        'majority_mcc': float(matthews_corrcoef(yt, np.full(len(yt), maj))),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--donnees', default=os.path.expanduser('~/llm_data/textes.parquet'))
    ap.add_argument('--sortie', default=os.path.expanduser('~/llm_results'))
    ap.add_argument('--modele', default='Qwen/Qwen2.5-1.5B-Instruct')
    ap.add_argument('--task', required=True, choices=list(LABEL_COL))
    ap.add_argument('--split', required=True, choices=list(SPLIT_COL))
    ap.add_argument('--epochs', type=int, default=2)
    ap.add_argument('--batch', type=int, default=16)
    ap.add_argument('--accum', type=int, default=2)
    ap.add_argument('--lr', type=float, default=1e-5)
    ap.add_argument('--maxlen', type=int, default=512)
    ap.add_argument('--graine', type=int, default=20260908)
    ap.add_argument('--limite', type=int, default=0, help='n lignes seulement, pour un essai')
    ap.add_argument('--instruction', action='store_true',
                    help='prefixer chaque texte par la consigne de la tache. '
                         'Rien d autre ne change : memes partitions, meme '
                         'seuil, memes metriques, donc l ecart mesure ce que '
                         'la consigne apporte, et elle seule')
    a = ap.parse_args()
    os.makedirs(a.sortie, exist_ok=True)
    graine(a.graine)
    dev = 'cuda'

    d = pd.read_parquet(a.donnees)
    sc, lc = SPLIT_COL[a.split], LABEL_COL[a.task]
    # La meme regle que `cible()` cote LightGBM : un fichier dont l etiquette
    # n a pas ete mesuree sort de la tache, il n est pas compte comme negatif.
    # Sans cette ligne, les 21 077 fichiers sans rapport capa deviendraient
    # 21 077 negatifs pour `anti_analysis`, et la comparaison serait faussee.
    avant = len(d)
    d = d[d[lc].notna()]
    if len(d) < avant:
        print('%d fichiers non mesures pour %s, exclus de la tache'
              % (avant - len(d), a.task), flush=True)
    if a.limite:
        d = d.groupby(sc, group_keys=False).head(a.limite // 3)
    # Only `text` is selected. Nothing else can reach the tokenizer.
    # `to_numpy(dtype=int)` et non `.values.astype(int)` : la colonne peut
    # etre un booleen nullable, que numpy refuse de convertir directement.
    # Les nuls ont deja disparu juste au-dessus, la conversion est donc sure.
    textes = d['text'].values
    if a.instruction:
        tete = INSTRUCTION[a.task]
        textes = np.array([tete + '\n' + t for t in textes], dtype=object)
        print('consigne prefixee : %s' % tete, flush=True)
    d = d.assign(text=textes)
    jeux = {p: (d.loc[d[sc] == p, 'text'].values,
                d.loc[d[sc] == p, lc].to_numpy(dtype=int))
            for p in ('train', 'val', 'test')}
    for p, (t, y) in jeux.items():
        print('%-6s %7d lignes, %5.1f %% positifs' % (p, len(t), 100 * y.mean()), flush=True)

    tok = AutoTokenizer.from_pretrained(a.modele)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    # Weights in fp32, compute in bf16 through autocast. Loading the whole
    # model in bf16 and then wrapping it in autocast makes the freshly
    # initialised classification head diverge: its first gradients land below
    # bf16 resolution and the logits go to NaN within one epoch.
    modele = AutoModelForSequenceClassification.from_pretrained(a.modele, num_labels=2)
    # transformers 5.8 allocates the classification head without initialising
    # it: score.weight comes back holding uninitialised memory, a few values of
    # which are NaN. The forward pass then returns NaN before a single gradient
    # step. Initialising it explicitly is the whole fix.
    tete = getattr(modele, 'score', None) or getattr(modele, 'classifier', None)
    if tete is not None:
        torch.nn.init.normal_(tete.weight, mean=0.0, std=0.02)
        if getattr(tete, 'bias', None) is not None:
            torch.nn.init.zeros_(tete.bias)
        assert torch.isfinite(tete.weight).all(), 'classification head still not finite'
        print('classification head re-initialised: %s' % (tuple(tete.weight.shape),), flush=True)
    modele.config.pad_token_id = tok.pad_token_id
    modele.config.use_cache = False          # incompatible with checkpointing
    modele.gradient_checkpointing_enable()
    modele.to(dev)

    col = lambda lot: collate(lot, tok, a.maxlen)
    ch = {p: DataLoader(Textes(*jeux[p], tok, a.maxlen), batch_size=a.batch,
                        shuffle=(p == 'train'), collate_fn=col, num_workers=4,
                        pin_memory=True, drop_last=(p == 'train'))
          for p in jeux}

    # Weighted loss rather than oversampling: an epoch stays defined over the
    # original training corpus, so epochs remain comparable between splits.
    ytr = jeux['train'][1]
    poids = torch.tensor([len(ytr) / (2 * (ytr == 0).sum()),
                          len(ytr) / (2 * (ytr == 1).sum())], dtype=torch.float32, device=dev)
    print('class weights: %.3f / %.3f' % tuple(poids.tolist()), flush=True)
    perte = torch.nn.CrossEntropyLoss(weight=poids)

    opt = torch.optim.AdamW(modele.parameters(), lr=a.lr, weight_decay=.01)
    n_pas = (len(ch['train']) // a.accum) * a.epochs
    sched = get_cosine_schedule_with_warmup(opt, int(.06 * n_pas), n_pas)

    t0 = time.time()
    meilleur = {'mcc': -2, 'etat': None}
    for ep in range(a.epochs):
        modele.train()
        cum = 0.0
        for i, lot in enumerate(ch['train']):
            lot = {k: v.to(dev, non_blocking=True) for k, v in lot.items()}
            y = lot.pop('labels')
            with torch.autocast('cuda', dtype=torch.bfloat16):
                logits = modele(**lot).logits.float()
            L = perte(logits, y) / a.accum
            if not torch.isfinite(L):
                raise RuntimeError('loss went to %s at step %d' % (L.item(), i))
            L.backward()
            cum += L.item() * a.accum
            if (i + 1) % a.accum == 0:
                torch.nn.utils.clip_grad_norm_(modele.parameters(), 1.0)
                opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
            if (i + 1) % 200 == 0:
                print('  epoch %d  %5d/%d  loss %.4f  %.0f s'
                      % (ep + 1, i + 1, len(ch['train']), cum / (i + 1), time.time() - t0),
                      flush=True)
        pva = proba(modele, ch['val'], dev)
        s, mva = seuil_sur_validation(jeux['val'][1], pva)
        print('epoch %d  validation MCC %.4f at threshold %.4f  (%.0f s)'
              % (ep + 1, mva, s, time.time() - t0), flush=True)
        if mva > meilleur['mcc']:
            meilleur = {'mcc': mva, 'seuil': s, 'epoch': ep + 1,
                        'etat': {k: v.detach().cpu().clone() for k, v in modele.state_dict().items()}}

    # The test set is touched once, with the frozen threshold.
    if meilleur['etat'] is not None:
        modele.load_state_dict(meilleur['etat'])
    pte = proba(modele, ch['test'], dev)
    r = mesurer(jeux['test'][1], pte, meilleur['seuil'])
    r.update(task=a.task, split=a.split, model=a.modele, epochs=a.epochs,
             instruction=bool(a.instruction),
             best_epoch=meilleur['epoch'], val_mcc=meilleur['mcc'],
             lr=a.lr, batch=a.batch, accum=a.accum, maxlen=a.maxlen,
             seed=a.graine, n_train=len(jeux['train'][0]), seconds=round(time.time() - t0))

    p = os.path.join(a.sortie, 'llm_%s_%s.json' % (a.task, a.split))
    json.dump(r, open(p, 'w'), indent=1)
    print('\n=== %s / %s' % (a.task, a.split))
    print('accuracy %.4f (majority %.4f)  MCC %.4f (majority %.4f)  ROC-AUC %s  PR-AUC %.4f'
          % (r['accuracy'], r['majority_accuracy'], r['mcc'], r['majority_mcc'],
             ('%.4f' % r['roc_auc']) if r['roc_auc'] else 'na', r['pr_auc']))
    print('tp %d  tn %d  fn %d  fp %d   threshold %.4f   %d s'
          % (r['tp'], r['tn'], r['fn'], r['fp'], r['threshold'], r['seconds']))
    print('written:', p)


if __name__ == '__main__':
    main()
