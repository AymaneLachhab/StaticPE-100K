#!/bin/bash
# Second collecteur benin, en parallele du premier. Meme code, meme magasin
# de PE partage (benign_collect/pe), mais son propre suivi (--out benign_collect2)
# pour ne pas toucher au curseur de la collecte tucows deja en cours.
cd ~/malware_pipeline
source env/env.sh
OUT=benign_collect2
STORE=benign_collect/pe
LOG=logs/benign_harvest2.log
n=0
while [ $n -lt 20 ]; do
  n=$((n+1))
  echo "=== [source2] demarrage #$n a $(date) sur $(hostname)" >> $LOG
  python3 -u collect_benign_multi.py --out $OUT --store $STORE --work /tmp/bwork2 \
    --delay 0.2 discover --source archive --collection open_source_software \
    --max-items 60000 >> $LOG 2>&1
  python3 -u collect_benign_multi.py --out $OUT --store $STORE --work /tmp/bwork2 \
    --delay 0.2 index --source archive >> $LOG 2>&1
  python3 -u collect_benign_multi.py --out $OUT --store $STORE --work /tmp/bwork2 \
    --delay 0.2 harvest --per-unit 30 --max-per-publisher 20 --max-pe-mb 10 \
    --archive-timeout 420 --machines I386,AMD64 >> $LOG 2>&1
  rc=$?
  echo "=== [source2] sortie code $rc a $(date)" >> $LOG
  [ $rc -eq 0 ] && sleep 60 || sleep 60
done
