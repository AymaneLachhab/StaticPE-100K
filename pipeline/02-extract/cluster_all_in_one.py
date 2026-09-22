#!/usr/bin/env python3
"""Cluster : un seul telechargement VirusShare, deux analyses, deux sorties separees.

Meme principe que vm_all_in_one.py, mais la source est VirusShare au lieu de
MalwareBazaar. Les deux quotas sont independants, donc les deux machines peuvent
tourner en parallele sans se gener : VirusShare limite a 4 requetes par minute et
PAR CLE, sans plafond journalier ; MalwareBazaar limite a 2000 par jour et par IP
et par cle.

    telecharge  ->  1. FEATURES  : LIEF + YARA         -> features/<sha256>.json
                ->  2. CONTROLE  : vote packing + capa -> check/results.jsonl.gz
                ->  supprime le binaire, echantillon suivant

Le fichier est autonome. Les parseurs viennent de fetch_and_analyse.py, avec les
corrections deja payees : capa juge sur son JSON et non sur sa prose, le silence de
PEiD compte comme un non, un outil qui plante ne vote pas, et un refus passager
n'ecrit rien plutot que de devenir definitif.

    python3 cluster_all_in_one.py --csv batch_A.csv --keys-file keys_new.txt \
        --capa-cmd capa --capa-rules $CAPA_RULES --manalyze $MANALYZE_CMD \
        --batch 100 --workers 6

Le CSV doit porter une colonne md5 ; les colonnes categories et sha256 sont
utilisees si elles existent. Reprise : relancer la meme commande.
"""
import argparse
import csv as _csv
import gzip
import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import warnings
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("pip install requests")
try:
    import numpy as np
    import lief
except ImportError:
    sys.exit("pip install lief numpy")

try:
    import yara
    import yara_manager
except ImportError:
    yara = None
    yara_manager = None

try:
    import tlsh
except ImportError:
    tlsh = None
try:
    import ssdeep

    def ssdeep_hash(d):
        return ssdeep.hash(d)
except ImportError:
    try:
        import ppdeep

        def ssdeep_hash(d):
            return ppdeep.hash(d)
    except ImportError:
        def ssdeep_hash(d):
            return None

lief.logging.disable()
warnings.filterwarnings("ignore", category=RuntimeWarning)

API_FILE = "https://virusshare.com/apiv2/file"
API_DOWNLOAD = "https://virusshare.com/apiv2/download"
DEFAULT_RATE = 4          # requetes par minute PAR CLE, limite documentee
TOOL_TIMEOUT = 300
VOTERS = ["pypackerdetect", "peid", "manalyze"]

MANALYZE_CMD = ["manalyze"]
CAPA_CMD = ["capa"]
CAPA_ENABLED = True
NO_YARA = False
CAPA_RULES = ""
CAPA_SIGS = ""
CAPA_TIMEOUT = 600
YARA_COMPILED = "compiled_rules.yarc"
_yara_rules = None


# ===========================================================================
# 1. TELECHARGEMENT VIRUSSHARE
# ===========================================================================

class NotAvailable(Exception):
    """L'echantillon n'est pas recuperable."""


class Transient(NotAvailable):
    """Refus passager : 204, 5xx, coupure reseau.

    Un echec transitoire ne doit RIEN ecrire dans le fichier de resultats.
    L'ecrire le rendrait permanent, puisque la reprise saute ce qu'elle y trouve.
    """


class KeyPool:
    """Un minuteur par cle ; on rend celle qui a chome le plus longtemps.

    La limite VirusShare porte sur la CLE, pas sur l'adresse IP. Ajouter des cles
    augmente donc le debit lineairement, et deux machines peuvent utiliser deux
    jeux disjoints sans se gener.
    """

    def __init__(self, path, per_minute=DEFAULT_RATE):
        keys = []
        p = Path(path)
        if p.exists():
            for raw in p.read_text().splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                if "=" in line:
                    line = line.split("=", 1)[1].strip()
                line = line.strip("'\"").strip()
                if len(line) >= 20:
                    keys.append(line)
        if not keys:
            sys.exit(f"aucune cle VirusShare dans {path}")
        self.gap = 60.0 / max(per_minute, 0.1)
        self.last = {k: 0.0 for k in keys}
        self.used = {k: 0 for k in keys}
        self.lock = threading.Lock()
        self.keys = keys

    def acquire(self):
        while True:
            with self.lock:
                key = min(self.last, key=self.last.get)
                wait = self.last[key] + self.gap - time.time()
                if wait <= 0:
                    self.last[key] = time.time()
                    self.used[key] += 1
                    return key
            time.sleep(min(wait, 2.0))

    def report(self):
        return " ".join(f"{k[:8]}={n}" for k, n in self.used.items())


TRANSIENT_RE = re.compile(r"rate limited|request failed|HTTP 5\d\d|timed out|timeout",
                          re.I)


def _download_once(pool, md5, dest, session, timeout=300):
    key = pool.acquire()
    try:
        r = session.get(API_DOWNLOAD, params={"apikey": key, "hash": md5},
                        timeout=timeout, stream=True)
    except Exception as exc:
        return False, f"request failed: {exc}"
    if r.status_code == 404:
        return False, "not in VirusShare"
    if r.status_code == 204:
        return False, "rate limited (204)"
    if r.status_code != 200:
        return False, f"HTTP {r.status_code}"
    # Ecrire uniquement via iter_content. Lire r.raw d'abord desynchronise le
    # decodeur chunked d'urllib3, qui leve ensuite InvalidChunkLength -- et les
    # octets "corrompus" de cette erreur sont simplement la suite de l'en-tete ZIP.
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as fh:
        for chunk in r.iter_content(chunk_size=1 << 16):
            if chunk:
                fh.write(chunk)
    size = dest.stat().st_size
    if size == 0:
        dest.unlink(missing_ok=True)
        return False, "empty response"
    if size < 400 and dest.read_bytes().lstrip().startswith(b"{"):
        body = dest.read_text(errors="replace")[:200]
        dest.unlink(missing_ok=True)
        return False, f"le serveur a renvoye un message, pas un fichier: {body}"
    return True, ""


def vs_download(pool, md5, dest, session, attempts=3):
    """Retente sur un refus passager, en laissant une rotation de cles s'ecouler."""
    last = ""
    for attempt in range(attempts):
        ok, err = _download_once(pool, md5, dest, session)
        if ok:
            return
        if not TRANSIENT_RE.search(err):
            raise NotAvailable(err)
        last = err
        time.sleep(pool.gap * (attempt + 1))
    raise Transient(last or "refus passager")


def extract_if_zip(path, password="infected"):
    """VirusShare livre l'echantillon dans un ZIP protege, mot de passe 'infected'.

    Trois voies, dans cet ordre, car le chiffrement varie : zipfile pour ZipCrypto,
    pyzipper pour AES, puis 7z ou unzip selon ce que le systeme offre.
    """
    with path.open("rb") as fh:
        magic = fh.read(4)
    if magic[:2] != b"PK":
        return path                       # deja un binaire brut

    dest_dir = path.parent / f"{path.name}_x"
    dest_dir.mkdir(exist_ok=True)
    pwd = password.encode()
    first_error = ""

    try:
        import zipfile
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                raise NotAvailable("archive vide")
            zf.setpassword(pwd)
            member = dest_dir / Path(names[0]).name
            member.write_bytes(zf.read(names[0]))
            return member
    except NotAvailable:
        raise
    except Exception as exc:
        first_error = str(exc)

    try:
        import pyzipper
        with pyzipper.AESZipFile(path) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            zf.setpassword(pwd)
            member = dest_dir / Path(names[0]).name
            member.write_bytes(zf.read(names[0]))
            return member
    except ImportError:
        pass
    except Exception as exc:
        first_error += f" | pyzipper: {exc}"

    for cmd in (["7z", "x", f"-p{password}", "-y", f"-o{dest_dir}", str(path)],
                ["unzip", "-o", "-P", password, str(path), "-d", str(dest_dir)]):
        if not shutil.which(cmd[0]):
            continue
        subprocess.run(cmd, capture_output=True, timeout=120)
        files = [p for p in dest_dir.rglob("*") if p.is_file()]
        if files:
            return files[0]

    raise NotAvailable(f"extraction impossible: {first_error}")


# ===========================================================================
# 2. FEATURES STATIQUES (LIEF + YARA)
# ===========================================================================

def safe_str(v):
    if v is None:
        return None
    try:
        return str(v)
    except Exception:
        return None


def _enum_name(v):
    return getattr(v, "name", str(v))


def _serial_hex(s):
    try:
        return bytes(s).hex()
    except Exception:
        return safe_str(s)


def _json_safe(o):
    if o is None or isinstance(o, (str, int, float, bool)):
        return o
    if isinstance(o, dict):
        return {k: _json_safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_json_safe(v) for v in o]
    if isinstance(o, (bytes, bytearray, memoryview)):
        b = bytes(o)
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.hex()
    return str(o)


def shannon_entropy(data):
    if not data:
        return 0.0
    n = len(data)
    h = -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
    return round(h + 0.0, 6)


def _entropy_bin_counts(block, window):
    c = np.bincount(block >> 4, minlength=16)
    p = c.astype(np.float64) / window
    wh = np.nonzero(c)[0]
    H = np.sum(-p[wh] * np.log2(p[wh])) * 2
    hb = int(H * 2)
    return (15 if hb == 16 else hb), c


def byte_entropy_histogram(data, window=2048, step=1024):
    if not data:
        return [0.0] * 256
    a = np.frombuffer(data, dtype=np.uint8)
    out = np.zeros((16, 16), dtype=np.float64)
    if a.shape[0] < window:
        hb, c = _entropy_bin_counts(a, window)
        out[hb, :] += c
    else:
        shape = (a.shape[0] - window + 1, window)
        strides = (a.strides[0], a.strides[0])
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            hb, c = _entropy_bin_counts(block, window)
            out[hb, :] += c
    flat = out.flatten()
    s = flat.sum()
    if s > 0:
        flat = flat / s
    return [round(float(x), 8) for x in flat]



# ---------------------------------------------------------------------------
# Champs structurels ajoutes apres l'audit du corpus. Chacun est un fait de
# structure, jamais une empreinte de chaine de compilation.
# Regle constante : une mesure qui n'a pas pu avoir lieu vaut None, jamais 0.
# ---------------------------------------------------------------------------

def _blob_entropy(b):
    if not b:
        return None                       # pas de donnee : non mesure
    c = Counter(b)
    n = float(len(b))
    return round(-sum((k / n) * math.log2(k / n) for k in c.values()), 6)


def _computed_checksum(data, checksum_offset):
    """Somme de controle PE recalculee. LIEF ne l'expose pas. Somme 16 bits a
    retenue ou les 4 octets du champ comptent pour zero. Un checksum nul ou faux
    signale un binaire modifie apres compilation : indice de trafiquage, pas
    empreinte de compilateur. Verifie sur notepad.exe, valeur exacte."""
    if checksum_offset is None or checksum_offset + 4 > len(data):
        return None
    total = 0
    n = len(data)
    for i in range(0, n - (n % 2), 2):
        if checksum_offset <= i < checksum_offset + 4:
            continue
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if n % 2:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + n) & 0xFFFFFFFF


def _checksum_check(binary, data):
    """Uniquement ce qui est CALCULE, pas ce que l'en-tete declare.

    Tous les champs declares vivent dans optional_header ; les repeter ici
    doublait le bloc pour rien. Ce qui reste est la seule information que LIEF
    n'expose pas : la somme de controle recalculee et son accord avec celle
    inscrite dans le fichier. Un checksum nul ou faux signale un binaire modifie
    apres compilation."""
    oh = binary.optional_header
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        cks_off = e_lfanew + 4 + 20 + 64
    except Exception:
        cks_off = None
    declared = getattr(oh, "checksum", None)
    computed = _computed_checksum(data, cks_off)
    return {
        "checksum_declared": declared,
        "checksum_computed": computed,
        "checksum_valid": (None if (declared is None or computed is None)
                           else int(declared == computed)),
        "checksum_zero": (None if declared is None else int(declared == 0)),
    }


def _entrypoint_section(binary):
    """Point d'entree dans la derniere section, dans une section non executable,
    ou hors de toute section : trois marqueurs de packing classiques."""
    oh = binary.optional_header
    ep = getattr(oh, "addressof_entrypoint", None)
    secs = list(binary.sections)
    out = {"ep_rva": ep, "section_name": None, "section_index": None,
           "in_last_section": None, "in_executable_section": None,
           "outside_sections": None, "section_entropy": None}
    if ep is None or not secs:
        return out
    idx = None
    for i, sec in enumerate(secs):
        start = sec.virtual_address
        end = start + max(sec.virtual_size, sec.sizeof_raw_data)
        if start <= ep < end:
            idx = i
            break
    if idx is None:
        out["outside_sections"] = 1
        return out
    sec = secs[idx]
    out.update({
        "section_name": sec.name,
        "section_index": idx,
        "in_last_section": int(idx == len(secs) - 1),
        "in_executable_section": int(sec.has_characteristic(
            lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)),
        "outside_sections": 0,
        "section_entropy": round(sec.entropy + 0.0, 6),
    })
    return out


def _overlay_full(binary):
    """Taille, position, entropie et signature des premiers octets, en un bloc."""
    out = {"size": 0, "offset": None, "entropy": None, "magic_head": None,
           "sha256": None}
    try:
        out["offset"] = binary.overlay_offset
        raw = bytes(binary.overlay)
        out["size"] = len(raw)
        if raw:
            out["entropy"] = _blob_entropy(raw)
            out["magic_head"] = raw[:16].hex()
            out["sha256"] = hashlib.sha256(raw).hexdigest()
    except Exception:
        return {k: None for k in out}
    return out


def _overlay_extra(binary):
    """La taille seule ne distingue pas une charge chiffree d'une archive
    d'installeur ; l'entropie, si."""
    out = {"entropy": None, "magic_head": None}
    try:
        raw = bytes(binary.overlay)
        if raw:
            out["entropy"] = _blob_entropy(raw)
            out["magic_head"] = raw[:8].hex()
    except Exception:
        pass
    return out


def _debug_info(binary):
    out = {"has_debug": None, "count": None, "types": [], "pdb_path": None}
    try:
        entries = list(getattr(binary, "debug", []) or [])
        out["has_debug"] = int(bool(entries))
        out["count"] = len(entries)
        for d in entries:
            try:
                out["types"].append(_enum_name(d.type))
            except Exception:
                pass
            if out["pdb_path"] is None:
                for attr in ("filename", "pdb_filename", "pdb_path"):
                    v = getattr(d, attr, None)
                    if v:
                        out["pdb_path"] = safe_str(v)
                        break
    except Exception:
        pass
    return out


def _misc_structures(binary):
    out = {}
    try:
        has_rel = bool(getattr(binary, "has_relocations", False))
        out["has_relocations"] = int(has_rel)
        out["relocation_count"] = len(list(binary.relocations)) if has_rel else 0
    except Exception:
        out["has_relocations"] = None
        out["relocation_count"] = None
    try:
        dl = list(getattr(binary, "delay_imports", []) or [])
        out["delay_import_count"] = len(dl)
        out["delay_import_dlls"] = [safe_str(d.name) for d in dl]
    except Exception:
        out["delay_import_count"] = None
        out["delay_import_dlls"] = None
    try:
        out["has_load_configuration"] = int(bool(
            getattr(binary, "has_configuration", False)))
    except Exception:
        out["has_load_configuration"] = None
    return out


def _version_info(binary):
    """Chaines de version des ressources. LIEF 0.17 : resources_manager.version
    est une LISTE, et les chaines sont dans string_file_info.children[].entries.
    Verifie sur notepad.exe et kernel32.dll."""
    out = {"present": None, "company_name": None, "file_description": None,
           "original_filename": None, "product_name": None, "file_version": None,
           "legal_copyright": None, "internal_name": None}
    try:
        items = {}
        versions = binary.resources_manager.version
        if not isinstance(versions, (list, tuple)):
            versions = [versions] if versions is not None else []
        for v in versions:
            sfi = getattr(v, "string_file_info", None)
            if sfi is None:
                continue
            for table in list(getattr(sfi, "children", []) or []):
                for e in list(getattr(table, "entries", []) or []):
                    k = getattr(e, "key", None)
                    val = getattr(e, "value", None)
                    if k is None and isinstance(e, (tuple, list)) and len(e) == 2:
                        k, val = e
                    if k:
                        items[safe_str(k)] = safe_str(val) if val is not None else None
        out["present"] = 1 if items else 0
        out["company_name"] = items.get("CompanyName")
        out["file_description"] = items.get("FileDescription")
        out["original_filename"] = items.get("OriginalFilename")
        out["product_name"] = items.get("ProductName")
        out["file_version"] = items.get("FileVersion")
        out["legal_copyright"] = items.get("LegalCopyright")
        out["internal_name"] = items.get("InternalName")
    except Exception:
        pass                              # reste None : non mesure, pas absent
    return out



def _dos_header(binary, data):
    """En-tete DOS : les 64 premiers octets. LIEF les expose, mais on retombe
    sur une lecture directe si l'attribut manque, plutot que de rendre du vide."""
    out = {}
    dh = getattr(binary, "dos_header", None)
    fields = ("magic", "used_bytes_in_last_page", "file_size_in_pages",
              "numberof_relocation", "header_size_in_paragraphs",
              "minimum_extra_paragraphs", "maximum_extra_paragraphs",
              "initial_relative_ss", "initial_sp", "checksum", "initial_ip",
              "initial_relative_cs", "addressof_relocation_table",
              "overlay_number", "oem_id", "oem_info", "addressof_new_exeheader")
    for f in fields:
        v = getattr(dh, f, None) if dh is not None else None
        out[f] = int(v) if isinstance(v, int) else None

    # e_lfanew relu directement : c'est lui qui sert d'ancre a tout le reste
    try:
        out["e_lfanew_raw"] = int.from_bytes(data[0x3C:0x40], "little")
    except Exception:
        out["e_lfanew_raw"] = None

    # champs reserves : nuls dans un binaire ordinaire, parfois detournes
    try:
        res1 = data[0x1C:0x24]        # e_res[4], 8 octets
        res2 = data[0x28:0x3C]        # e_res2[10], 20 octets
        out["reserved1_hex"] = res1.hex()
        out["reserved2_hex"] = res2.hex()
        out["reserved_nonzero"] = int(any(res1) or any(res2))
    except Exception:
        out["reserved1_hex"] = None
        out["reserved2_hex"] = None
        out["reserved_nonzero"] = None

    # les 64 octets bruts. Les champs nommes ci-dessus en sont une lecture ;
    # garder l'original permet de reposer une question qu'on n'a pas encore
    # pensee, sans retelecharger le fichier.
    try:
        raw = data[0x00:0x40]
        out["raw_hex"] = raw.hex()
        out["raw_size"] = len(raw)
    except Exception:
        out["raw_hex"] = None
        out["raw_size"] = None
    return out


# Stub DOS produit par les editeurs de liens Microsoft. Les 14 premiers octets
# suffisent a le reconnaitre : ils encodent l'instruction qui affiche le message.
_MS_STUB_HEAD = bytes.fromhex("0e1fba0e00b409cd21b8014ccd21")


# Un stub ordinaire fait moins de 300 octets. Au-dela, quelque chose y a ete
# ajoute : du code, une charge, ou le rich header d'un compilateur bavard.
# On garde tout jusqu'a cette borne, et au-dela on garde le hachage et la taille
# exacte plus les deux extremites, pour ne jamais gonfler le JSON sans limite.
_STUB_RAW_CAP = 4096


def _dos_stub(binary, data):
    """Le stub vit entre la fin de l'en-tete DOS (0x40) et e_lfanew. C'est aussi
    la ou se loge le rich header, deja capture a part."""
    out = {"size": None, "entropy": None, "is_standard_ms": None,
           "sha256": None, "head_hex": None, "raw_hex": None,
           "raw_truncated": None, "tail_hex": None,
           "message": None, "message_is_standard": None}
    try:
        start = 0x40
        end = int.from_bytes(data[0x3C:0x40], "little")
        if not (start <= end <= len(data)) or end - start <= 0:
            out["size"] = 0
            return out
        stub = data[start:end]
        out["size"] = len(stub)
        out["entropy"] = _blob_entropy(stub)
        out["sha256"] = hashlib.sha256(stub).hexdigest()
        out["head_hex"] = stub[:16].hex()
        out["is_standard_ms"] = int(stub.startswith(_MS_STUB_HEAD))

        if len(stub) <= _STUB_RAW_CAP:
            out["raw_hex"] = stub.hex()
            out["raw_truncated"] = 0
        else:
            out["raw_hex"] = stub[:_STUB_RAW_CAP].hex()
            out["raw_truncated"] = 1
            out["tail_hex"] = stub[-64:].hex()

        # le message affiche si le binaire est lance sous DOS. Un packer ou un
        # editeur de liens non Microsoft le remplace, et le remplacement se voit.
        txt = "".join(chr(c) if 0x20 <= c < 0x7F else " " for c in stub)
        msg = " ".join(txt.split()).strip()
        out["message"] = msg[:200] if msg else None
        out["message_is_standard"] = int(
            "This program cannot be run in DOS mode" in msg) if msg else 0
    except Exception:
        pass                              # reste None : non mesure
    return out



# Champs qui decrivent la CHAINE DE COMPILATION et non le comportement.
# Enregistres comme faits, mais a ne pas verser dans les features d'un modele
# avant d'avoir mesure leur lift : ils identifient le compilateur, pas l'intention.
TOOLCHAIN_FIELDS = (
    "time_date_stamp", "major_linker_version", "minor_linker_version",
    "major_operating_system_version", "minor_operating_system_version",
    "major_image_version", "minor_image_version",
    "major_subsystem_version", "minor_subsystem_version",
    "win32_version_value",
)


def _file_header(binary):
    """En-tete COFF complet : les 20 octets qui suivent la signature PE."""
    hd = binary.header
    return {
        "machine": _enum_name(hd.machine),
        "numberof_sections": getattr(hd, "numberof_sections", None),
        "time_date_stamp": getattr(hd, "time_date_stamps", None),
        "pointerto_symbol_table": getattr(hd, "pointerto_symbol_table", None),
        "numberof_symbols": getattr(hd, "numberof_symbols", None),
        "sizeof_optional_header": getattr(hd, "sizeof_optional_header", None),
        "characteristics_raw": getattr(hd, "characteristics", None),
        "characteristics": [_enum_name(c) for c in hd.characteristics_list],
    }


def _optional_header(binary):
    """En-tete optionnel complet, PE32 et PE32+.

    baseof_data n'existe qu'en PE32 : absent en 64 bits, il vaut None, ce qui
    veut dire non applicable et non pas zero."""
    oh = binary.optional_header
    out = {
        "magic": _enum_name(getattr(oh, "magic", None)),
        "major_linker_version": getattr(oh, "major_linker_version", None),
        "minor_linker_version": getattr(oh, "minor_linker_version", None),
        "sizeof_code": getattr(oh, "sizeof_code", None),
        "sizeof_initialized_data": getattr(oh, "sizeof_initialized_data", None),
        "sizeof_uninitialized_data": getattr(oh, "sizeof_uninitialized_data", None),
        "addressof_entrypoint": getattr(oh, "addressof_entrypoint", None),
        "baseof_code": getattr(oh, "baseof_code", None),
        "baseof_data": None,
        "imagebase": getattr(oh, "imagebase", None),
        "section_alignment": getattr(oh, "section_alignment", None),
        "file_alignment": getattr(oh, "file_alignment", None),
        "major_operating_system_version": getattr(oh, "major_operating_system_version", None),
        "minor_operating_system_version": getattr(oh, "minor_operating_system_version", None),
        "major_image_version": getattr(oh, "major_image_version", None),
        "minor_image_version": getattr(oh, "minor_image_version", None),
        "major_subsystem_version": getattr(oh, "major_subsystem_version", None),
        "minor_subsystem_version": getattr(oh, "minor_subsystem_version", None),
        "win32_version_value": getattr(oh, "win32_version_value", None),
        "sizeof_image": getattr(oh, "sizeof_image", None),
        "sizeof_headers": getattr(oh, "sizeof_headers", None),
        "checksum": getattr(oh, "checksum", None),
        "subsystem": _enum_name(getattr(oh, "subsystem", None)),
        "dll_characteristics_raw": getattr(oh, "dll_characteristics", None),
        "dll_characteristics": [_enum_name(c) for c in
                                oh.dll_characteristics_lists],
        "sizeof_stack_reserve": getattr(oh, "sizeof_stack_reserve", None),
        "sizeof_stack_commit": getattr(oh, "sizeof_stack_commit", None),
        "sizeof_heap_reserve": getattr(oh, "sizeof_heap_reserve", None),
        "sizeof_heap_commit": getattr(oh, "sizeof_heap_commit", None),
        "loader_flags": getattr(oh, "loader_flags", None),
        "numberof_rva_and_size": getattr(oh, "numberof_rva_and_size", None),
    }
    try:
        if "PLUS" not in str(getattr(oh, "magic", "")):
            out["baseof_data"] = getattr(oh, "baseof_data", None)
    except Exception:
        pass
    return out



# ---------------------------------------------------------------------------
# Chaines de caracteres
# ---------------------------------------------------------------------------

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\]{4,200}", re.I)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DLL_RE = re.compile(r"\b[A-Za-z0-9_\-.]{1,60}\.dll\b", re.I)
_REG_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE|SYSTEM)"
                     r"\\\\?[A-Za-z0-9 _\-.\\]{4,180}")
# Un chemin doit avoir une racine puis au moins deux composants alphanumeriques.
# La version precedente retenait des faux positifs comme "\\\\ZZZ".
_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)"
    r"[A-Za-z0-9_.$-]+(?:\\[A-Za-z0-9 _.$-]+){1,20}")

# Le cap borne la taille du JSON : un echantillon peut contenir des centaines de
# milliers de chaines. Le compte total reste exact, seule la liste est tronquee.
_STR_CAP = 300


def _ip_is_plausible(ip, version_values):
    """Une adresse IP et un numero de version s'ecrivent pareil.

    Sur le premier echantillon reel, les cinq "adresses" trouvees etaient
    toutes des versions : 9.5.2.2 pour le fichier, 1.0.0.0 et 4.0.0.0 pour des
    assemblages .NET. Un label reseau fonde sur la liste brute serait faux sur
    presque tout le corpus."""
    if ip in version_values:
        return False
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(o) != 4 or any(x > 255 for x in o):
        return False
    if o[0] == 0 or o[1:] == [0, 0, 0]:      # 0.x.x.x et 4.0.0.0
        return False
    if o[0] == 127 or o == [255, 255, 255, 255]:
        return False
    if not (1 <= o[0] <= 239):               # multicast et reserve exclus
        return False
    # 2.0.5.0, 1.0.3.0 : un dernier composant nul avec un premier faible est
    # presque toujours une version d'assemblage. 8.8.8.8 et 1.0.0.1, eux, sont
    # de vraies adresses et doivent passer.
    if o[3] == 0 and o[0] <= 32:
        return False
    return True


def _extract_strings(data):
    try:
        ascii_raw = _ASCII_RE.findall(data)
        utf16_raw = _UTF16_RE.findall(data)
    except Exception:
        return {"error": "extraction impossible"}

    ascii_s = [b.decode("ascii", "ignore") for b in ascii_raw]
    utf16_s = [b.decode("utf-16-le", "ignore") for b in utf16_raw]
    alls = ascii_s + utf16_s
    joined = "\n".join(alls)

    def take(rx, lower=False):
        found = rx.findall(joined)
        if lower:
            found = [f.lower() for f in found]
        uniq = sorted(set(found))
        return uniq[:_STR_CAP], len(uniq)

    urls, n_urls = take(_URL_RE)
    ips, n_ips = take(_IPV4_RE)
    dlls, n_dlls = take(_DLL_RE, lower=True)
    regs, n_regs = take(_REG_RE)
    paths, n_paths = take(_PATH_RE)

    total_chars = sum(len(x) for x in alls)
    lengths = [len(x) for x in alls]
    return {
        "count_ascii": len(ascii_s),
        "count_utf16": len(utf16_s),
        "count_total": len(alls),
        "chars_total": total_chars,
        # rapport octets-de-chaines sur taille du fichier : un fichier obfusque
        # ou empaquete tombe tres bas
        "printable_ratio": round(total_chars / len(data), 6) if data else None,
        "len_mean": round(sum(lengths) / len(lengths), 2) if lengths else None,
        "len_max": max(lengths) if lengths else None,
        "urls": urls, "n_urls": n_urls,
        # brut : tout ce qui a la forme d'une adresse, versions comprises
        "ipv4": ips, "n_ipv4": n_ips,
        # filtre, rempli par extract_features une fois version_info connu
        "ipv4_plausible": None, "n_ipv4_plausible": None,
        "dll_names": dlls, "n_dll_names": n_dlls,
        "registry_paths": regs, "n_registry_paths": n_regs,
        "file_paths": paths, "n_file_paths": n_paths,
    }


def _orphan_dlls(strings_block, imports):
    """DLL nommees dans les chaines mais absentes de la table d'import.

    Indicateur direct de resolution dynamique : le fichier connait la
    bibliotheque sans la lier. Calculable sans desassemblage."""
    try:
        named = {i["name"].lower() for i in imports if i.get("name")}
        seen = set(strings_block.get("dll_names") or [])
        orphans = sorted(seen - named)
        return {"orphans": orphans[:100], "n_orphans": len(orphans),
                "n_imported": len(named)}
    except Exception:
        return {"orphans": None, "n_orphans": None, "n_imported": None}


# ---------------------------------------------------------------------------
# Conversion RVA -> offset fichier
# ---------------------------------------------------------------------------

def _rva_to_offset(binary, rva):
    try:
        for sec in binary.sections:
            start = sec.virtual_address
            end = start + max(sec.virtual_size, sec.sizeof_raw_data)
            if start <= rva < end:
                off = getattr(sec, "pointerto_raw_data", None)
                if off is None:
                    off = getattr(sec, "offset", None)
                if off is None:
                    return None
                return off + (rva - start)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# En-tete CLR : beaucoup de malwares recents sont ecrits en .NET
# ---------------------------------------------------------------------------

def _dotnet(binary, data):
    out = {"is_dotnet": 0, "runtime_major": None, "runtime_minor": None,
           "flags": None, "entrypoint_token": None,
           "has_strong_name": None, "il_only": None, "native_entrypoint": None}
    try:
        dd = list(binary.data_directories)
        # index 14 : CLR_RUNTIME_HEADER
        clr = dd[14] if len(dd) > 14 else None
        if clr is None or not clr.rva or not clr.size:
            return out
        off = _rva_to_offset(binary, clr.rva)
        if off is None or off + 72 > len(data):
            return out
        blob = data[off:off + 72]
        gi = lambda a, b: int.from_bytes(blob[a:b], "little")
        out["is_dotnet"] = 1
        out["runtime_major"] = gi(4, 6)
        out["runtime_minor"] = gi(6, 8)
        flags = gi(16, 20)
        out["flags"] = flags
        out["entrypoint_token"] = gi(20, 24)
        out["il_only"] = int(bool(flags & 0x00000001))
        out["native_entrypoint"] = int(bool(flags & 0x00000010))
        sn_rva = gi(32, 36)
        sn_size = gi(36, 40)
        out["has_strong_name"] = int(bool(sn_rva and sn_size))
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Manifeste embarque : le niveau d'elevation demande
# ---------------------------------------------------------------------------

_EXEC_LEVEL_RE = re.compile(r'level\s*=\s*"([^"]+)"', re.I)
_UIACCESS_RE = re.compile(r'uiAccess\s*=\s*"([^"]+)"', re.I)


def _manifest(binary):
    out = {"has_manifest": 0, "requested_execution_level": None,
           "ui_access": None, "size": None}
    try:
        rm = binary.resources_manager
        if not getattr(rm, "has_manifest", False):
            return out
        man = rm.manifest
        if not man:
            return out
        text = man if isinstance(man, str) else str(man)
        out["has_manifest"] = 1
        out["size"] = len(text)
        m = _EXEC_LEVEL_RE.search(text)
        if m:
            out["requested_execution_level"] = m.group(1)
        u = _UIACCESS_RE.search(text)
        if u:
            out["ui_access"] = u.group(1)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Octets au point d'entree : signature de packer sans desassemblage
# ---------------------------------------------------------------------------

def _entrypoint_bytes(binary, data, n=64):
    out = {"offset": None, "hex": None, "entropy": None}
    try:
        ep = binary.optional_header.addressof_entrypoint
        off = _rva_to_offset(binary, ep)
        if off is None or off >= len(data):
            return out
        blob = data[off:off + n]
        out["offset"] = off
        out["hex"] = blob.hex()
        out["entropy"] = _blob_entropy(blob)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Load configuration : cookie de pile, SEH, Control Flow Guard
# ---------------------------------------------------------------------------

def _load_config(binary):
    out = {"present": 0, "security_cookie": None, "se_handler_count": None,
           "guard_cf_function_count": None, "guard_flags": None}
    try:
        if not getattr(binary, "has_configuration", False):
            return out
        lc = binary.load_configuration
        out["present"] = 1
        for src, dst in (("security_cookie", "security_cookie"),
                         ("se_handler_count", "se_handler_count"),
                         ("guard_cf_function_count", "guard_cf_function_count"),
                         ("guard_flags", "guard_flags")):
            v = getattr(lc, src, None)
            if v is not None and not isinstance(v, int):
                v = getattr(v, "value", None)
            out[dst] = int(v) if isinstance(v, int) else None
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# TLS : les adresses des rappels, pas seulement leur nombre
# ---------------------------------------------------------------------------

def _tls_full(binary):
    """Repertoire TLS complet. Les rappels TLS s'executent AVANT le point
    d'entree : c'est un endroit classique pour du code anti-debogage, et leur
    seul nombre ne suffit pas a le voir."""
    out = {"has_tls": 0, "callback_count": 0, "callbacks": None,
           "addressof_callbacks": None, "addressof_index": None,
           "addressof_raw_data_start": None, "addressof_raw_data_end": None,
           "raw_data_size": None, "sizeof_zero_fill": None,
           "characteristics": None, "section": None,
           "data_template_hex": None, "data_template_entropy": None}
    try:
        if not binary.has_tls:
            return out
        t = binary.tls
        out["has_tls"] = 1

        cbs = [int(c) for c in (t.callbacks or [])]
        out["callback_count"] = len(cbs)
        out["callbacks"] = cbs[:64]

        out["addressof_callbacks"] = int(getattr(t, "addressof_callbacks", 0)) or None
        out["addressof_index"] = int(getattr(t, "addressof_index", 0)) or None
        out["sizeof_zero_fill"] = int(getattr(t, "sizeof_zero_fill", 0))
        out["characteristics"] = int(getattr(t, "characteristics", 0))

        raw = getattr(t, "addressof_raw_data", None)
        if raw is not None:
            try:
                a, b = int(raw[0]), int(raw[1])
                out["addressof_raw_data_start"] = a
                out["addressof_raw_data_end"] = b
                out["raw_data_size"] = max(0, b - a)
            except Exception:
                pass

        try:
            sec = getattr(t, "section", None)
            out["section"] = safe_str(sec.name) if sec is not None else None
        except Exception:
            pass

        # le modele de donnees TLS : ce que le chargeur copie pour chaque thread
        try:
            tpl = bytes(getattr(t, "data_template", b"") or b"")
            if tpl:
                out["data_template_hex"] = tpl[:512].hex()
                out["data_template_entropy"] = _blob_entropy(tpl)
        except Exception:
            pass
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Repertoire d'exceptions (.pdata) : nombre de fonctions declarees en x64
# ---------------------------------------------------------------------------

def _exception_dir(binary):
    out = {"rva": None, "size": None, "runtime_function_count": None}
    try:
        dd = list(binary.data_directories)
        ex = dd[3] if len(dd) > 3 else None       # index 3 : EXCEPTION_TABLE
        if ex is None:
            return out
        out["rva"] = ex.rva
        out["size"] = ex.size
        # repertoire absent : zero fonction declaree, pas "non mesure"
        out["runtime_function_count"] = (ex.size // 12) if ex.size else 0
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Controle de coherence de la table des sections
# ---------------------------------------------------------------------------

def _section_layout_qc(binary):
    """Trous et recouvrements : marques de modification apres compilation."""
    out = {"gaps": 0, "overlaps": 0, "zero_raw_size": 0,
           "raw_exceeds_virtual": 0, "unaligned_offset": 0,
           "total_slack_bytes": 0}
    try:
        fa = binary.optional_header.file_alignment or 1
        secs = sorted(binary.sections, key=lambda x: x.virtual_address)
        prev_end = None
        for sec in secs:
            raw = sec.sizeof_raw_data
            off = getattr(sec, "pointerto_raw_data", None)
            if off is None:
                off = getattr(sec, "offset", 0)
            if raw == 0:
                out["zero_raw_size"] += 1
            if raw > sec.virtual_size:
                out["raw_exceeds_virtual"] += 1
                out["total_slack_bytes"] += raw - sec.virtual_size
            if off % fa != 0:
                out["unaligned_offset"] += 1
            start = sec.virtual_address
            if prev_end is not None:
                if start > prev_end:
                    out["gaps"] += 1
                elif start < prev_end:
                    out["overlaps"] += 1
            prev_end = start + max(sec.virtual_size, raw)
    except Exception:
        return {k: None for k in out}
    return out



def _imports_full(binary):
    """Table d'import complete, avec les RVA et les hints."""
    out = []
    try:
        for imp in binary.imports:
            entry = {
                "name": safe_str(imp.name),
                "forwarder_chain": getattr(imp, "forwarder_chain", None),
                "timedatestamp": getattr(imp, "timedatestamp", None),
                "import_address_table_rva": getattr(imp, "import_address_table_rva", None),
                "import_lookup_table_rva": getattr(imp, "import_lookup_table_rva", None),
                "functions": [],
            }
            for e in imp.entries:
                fn = {
                    "is_ordinal": int(bool(e.is_ordinal)),
                    "ordinal": int(e.ordinal) if e.is_ordinal else None,
                    "name": None if e.is_ordinal else safe_str(e.name),
                    "hint": getattr(e, "hint", None),
                    "iat_address": getattr(e, "iat_address", None),
                    "iat_value": getattr(e, "iat_value", None),
                    "data": getattr(e, "data", None),
                }
                entry["functions"].append(fn)
            entry["function_count"] = len(entry["functions"])
            out.append(entry)
    except Exception:
        return None                       # non mesure, pas vide
    return out


def _exports_full(binary):
    """Repertoire d'export complet : metadonnees et entrees detaillees.

    Une entree redirigee (forwarded) ne pointe pas vers du code local mais vers
    une autre DLL. C'est un fait a garder : les DLL de compatibilite Windows en
    sont faites, et certains malwares s'en servent pour du proxying."""
    out = {"present": 0, "name": None, "export_flags": None,
           "timestamp": None, "major_version": None, "minor_version": None,
           "ordinal_base": None, "entry_count": None, "entries": None}
    try:
        if not binary.has_exports:
            return out
        exp = binary.get_export()
        if exp is None:
            return out
        out["present"] = 1
        out["name"] = safe_str(getattr(exp, "name", None))
        out["export_flags"] = getattr(exp, "export_flags", None)
        out["timestamp"] = getattr(exp, "timestamp", None)
        out["major_version"] = getattr(exp, "major_version", None)
        out["minor_version"] = getattr(exp, "minor_version", None)
        out["ordinal_base"] = getattr(exp, "ordinal_base", None)
        entries = []
        for e in exp.entries:
            fwd = getattr(e, "forward_information", None)
            fwd_lib = getattr(fwd, "library", None) if fwd else None
            fwd_fn = getattr(fwd, "function", None) if fwd else None
            entries.append({
                "name": safe_str(getattr(e, "name", None)) or None,
                "ordinal": int(getattr(e, "ordinal", 0)),
                "address": getattr(e, "address", None),
                "is_extern": int(bool(getattr(e, "is_extern", False))),
                "is_forwarded": int(bool(getattr(e, "is_forwarded", False))),
                "forward_library": safe_str(fwd_lib) if fwd_lib else None,
                "forward_function": safe_str(fwd_fn) if fwd_fn else None,
            })
        out["entries"] = entries
        out["entry_count"] = len(entries)
    except Exception:
        return {k: None for k in out}
    return out


def _delay_imports_full(binary):
    """Imports a chargement differe, avec leurs fonctions."""
    out = []
    try:
        for d in (getattr(binary, "delay_imports", []) or []):
            entry = {
                "name": safe_str(getattr(d, "name", None)),
                "attribute": getattr(d, "attribute", None),
                "handle": getattr(d, "handle", None),
                "iat": getattr(d, "iat", None),
                "names_table": getattr(d, "names_table", None),
                "timestamp": getattr(d, "timestamp", None),
                "functions": [],
            }
            for e in getattr(d, "entries", []) or []:
                entry["functions"].append({
                    "is_ordinal": int(bool(getattr(e, "is_ordinal", False))),
                    "ordinal": int(e.ordinal) if getattr(e, "is_ordinal", False) else None,
                    "name": None if getattr(e, "is_ordinal", False) else safe_str(getattr(e, "name", None)),
                    "hint": getattr(e, "hint", None),
                    "iat_value": getattr(e, "iat_value", None),
                })
            entry["function_count"] = len(entry["functions"])
            out.append(entry)
    except Exception:
        return None
    return out


def _resources_full(binary):
    """Parcours complet de l'arbre des ressources : type, identifiant, langue,
    sous-langue, offset, taille, entropie et hachage du contenu."""
    out = {"has_resources": 0, "node_count": 0, "nodes": None,
           "total_size": 0, "max_entropy": None}
    try:
        if not binary.has_resources:
            return out
        out["has_resources"] = 1
        nodes = []
        max_ent = None
        total = 0
        for tnode in binary.resources.childs:
            tname = safe_str(tnode.name) if tnode.has_name else None
            tid = None if tnode.has_name else int(tnode.id)
            for idn in tnode.childs:
                iname = safe_str(idn.name) if idn.has_name else None
                iid = None if idn.has_name else int(idn.id)
                for lang in idn.childs:
                    if not lang.is_data:
                        continue
                    content = bytes(lang.content)
                    ent = _blob_entropy(content)
                    if ent is not None:
                        max_ent = ent if max_ent is None else max(max_ent, ent)
                    total += len(content)
                    nodes.append({
                        "type_name": tname,
                        "type_id": tid,
                        "id_name": iname,
                        "id": iid,
                        "lang": int(getattr(lang, "id", 0)),
                        "offset": getattr(lang, "offset", None),
                        "size": len(content),
                        "entropy": ent,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        # deux premiers octets : reperer un PE ou une archive
                        # embarquee sans stocker le contenu
                        "magic_head": content[:8].hex() if content else None,
                    })
        out["nodes"] = nodes
        out["node_count"] = len(nodes)
        out["total_size"] = total
        out["max_entropy"] = max_ent
    except Exception:
        return {k: None for k in out}
    return out


def _certificates_full(binary):
    """Certificats avec leurs dates de validite et leur empreinte."""
    out = {"signature_present": 0, "verification_flag": "NONE",
           "signature_count": None, "certificates": None}
    try:
        out["signature_present"] = int(binary.has_signatures)
        if not binary.has_signatures:
            # la mesure a eu lieu et rend vide : zero, pas null
            out["certificates"] = []
            out["signature_count"] = 0
            return out
        out["verification_flag"] = _enum_name(binary.verify_signature())
        sigs = list(binary.signatures)
        out["signature_count"] = len(sigs)
        certs = []
        for sig in sigs:
            for c in sig.certificates:
                def when(attr):
                    v = getattr(c, attr, None)
                    if v is None:
                        return None
                    try:
                        return "-".join(str(int(x)) for x in list(v)[:3])
                    except Exception:
                        return safe_str(v)
                certs.append({
                    "version": getattr(c, "version", None),
                    "subject": safe_str(c.subject),
                    "issuer": safe_str(c.issuer),
                    "serial_number": _serial_hex(c.serial_number),
                    "signature_algorithm": safe_str(c.signature_algorithm),
                    "valid_from": when("valid_from"),
                    "valid_to": when("valid_to"),
                    "is_ca": int(bool(getattr(c, "is_ca", False))),
                    "key_usage": [safe_str(k) for k in (getattr(c, "key_usage", None) or [])],
                })
        out["certificates"] = certs
    except Exception:
        return {k: None for k in out}
    return out


def _rich_header_full(binary, data):
    """Rich header : entrees nommees plus les octets bruts du bloc."""
    out = {"has_rich_header": 0, "key": None, "entries": None,
           "raw_hex": None, "raw_offset": None, "raw_size": None,
           "entry_count": None}
    try:
        if not binary.has_rich_header:
            return out
        rh = binary.rich_header
        out["has_rich_header"] = 1
        out["key"] = rh.key
        entries = [{"id": e.id, "build_id": e.build_id, "count": e.count}
                   for e in rh.entries]
        out["entries"] = entries
        out["entry_count"] = len(entries)
        # Le bloc vit dans le stub DOS. Son marqueur de debut "DanS" est
        # chiffre par XOR avec la cle ; seul "Rich" apparait en clair. On part
        # donc de "Rich", on lit la cle qui le suit, et on remonte par pas de
        # 4 octets jusqu'a retrouver "DanS" une fois dechiffre.
        try:
            end = data.find(b"Rich", 0, 0x400)
            if end > 0:
                key = data[end + 4:end + 8]
                dans = bytes(a ^ b for a, b in zip(b"DanS", key))
                start = -1
                pos = end - 4
                while pos >= 0:
                    if data[pos:pos + 4] == dans:
                        start = pos
                        break
                    pos -= 4
                if start >= 0:
                    out["raw_hex"] = data[start:end + 8].hex()
                    out["raw_offset"] = start
                    out["raw_size"] = end + 8 - start
        except Exception:
            pass
    except Exception:
        return {k: None for k in out}
    return out


def _data_directories_full(binary):
    """Les 16 repertoires, avec la section dans laquelle chacun tombe.

    Un repertoire qui pointe hors de toute section, ou dans une section
    inattendue, est une anomalie de structure."""
    out = []
    try:
        secs = list(binary.sections)
        for dd in binary.data_directories:
            where = None
            if dd.rva:
                for sec in secs:
                    st = sec.virtual_address
                    en = st + max(sec.virtual_size, sec.sizeof_raw_data)
                    if st <= dd.rva < en:
                        where = sec.name
                        break
            out.append({
                "name": _enum_name(dd.type),
                "rva": dd.rva,
                "size": dd.size,
                "section": where,
                "outside_sections": int(bool(dd.rva) and where is None),
            })
    except Exception:
        return None
    return out


def extract_features(sha, label, data):
    """Les faits bruts, sans interpretation : le bucketing viendra en phase B."""
    binary = lief.PE.parse(list(data))
    if binary is None:
        raise ValueError("LIEF n'a pas pu parser le fichier PE")

    hist = Counter(data)
    n = len(data)
    facts = {
        "sha256": sha,
        "label": label,
        "pe_parsed": True,
        "general_info": {
            "size_bytes": n,
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "imphash": lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE),
            "tlsh": tlsh.hash(data) if tlsh else None,
            "ssdeep": ssdeep_hash(data),
            "file_type": "dll" if binary.header.has_characteristic(
                lief.PE.Header.CHARACTERISTICS.DLL) else "exe",
        },
        "byte_features": {
            "file_entropy": shannon_entropy(data),
            "byte_histogram_256": [round(hist.get(i, 0) / n, 8) if n else 0.0
                                   for i in range(256)],
            "byte_entropy_histogram_256": byte_entropy_histogram(data),
        },
        "sections": [{
            "name": s.name,
            "virtual_size": s.virtual_size,
            "raw_size": s.sizeof_raw_data,
            # sans les offsets on ne peut detecter ni recouvrement ni trou
            # entre sections, deux marqueurs de modification post-compilation
            "virtual_address": s.virtual_address,
            "pointerto_raw_data": getattr(s, "pointerto_raw_data",
                                          getattr(s, "offset", None)),
            "entropy": round(s.entropy + 0.0, 6),
            "characteristics": s.characteristics,
            "readable": int(s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ)),
            "writable": int(s.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE)),
            "executable": int(s.has_characteristic(
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)),
        } for s in binary.sections],
        "dos_header": _dos_header(binary, data),
        "file_header": _file_header(binary),
        "dotnet": _dotnet(binary, data),
        "imports": _imports_full(binary),
        "exports": _exports_full(binary),
        "delay_imports": _delay_imports_full(binary),
        "resources": _resources_full(binary),
        "digital_signature": _certificates_full(binary),
        "rich_header": _rich_header_full(binary, data),
        "data_directories": _data_directories_full(binary),
        "manifest": _manifest(binary),
        "entrypoint_bytes": _entrypoint_bytes(binary, data),
        "load_config": _load_config(binary),
        "tls": _tls_full(binary),
        "exception_dir": _exception_dir(binary),
        "section_layout_qc": _section_layout_qc(binary),
        "optional_header": _optional_header(binary),
        "dos_stub": _dos_stub(binary, data),
        "checksum_check": _checksum_check(binary, data),
        "entrypoint_section": _entrypoint_section(binary),
        "overlay": _overlay_full(binary),
        "debug": _debug_info(binary),
        "misc_structures": _misc_structures(binary),
        "version_info": _version_info(binary),
    }

    # YARA desactive : on n'ecrit pas le bloc du tout. Repeter
    # {"yara_error": "desactive"} dans 54 841 fichiers ne renseigne personne.
    # L'information est portee une seule fois par le manifeste du run, qui dit
    # quels outils ont tourne. Sans lui, un champ absent serait ambigu :
    # coupe volontairement, ou fichier issu d'une version anterieure ?
    if not NO_YARA:
        facts["advanced_yara"] = (
            yara_manager.yara_features(data, _yara_rules)
            if (_yara_rules and yara_manager)
            else {"yara_error": "regles non chargees"})

    facts["strings"] = _extract_strings(data)

    # Filtrage des fausses adresses IP. Il a besoin de version_info, donc il se
    # fait ici et non dans _extract_strings. La liste brute est conservee ;
    # ipv4_plausible est celle qu'un label reseau doit utiliser.
    try:
        version_values = {str(v) for v in (facts.get("version_info") or {}).values() if v}
        st = facts["strings"]
        plausible = [ip for ip in (st.get("ipv4") or [])
                     if _ip_is_plausible(ip, version_values)]
        st["ipv4_plausible"] = plausible
        st["n_ipv4_plausible"] = len(plausible)
    except Exception:
        pass                              # les deux champs restent absents

    facts["orphan_dlls"] = _orphan_dlls(facts["strings"], facts["imports"])

    return facts


# ===========================================================================
# 3. CONTROLE : DETECTEURS DE PACKING
# ===========================================================================

PACKER_WORD = re.compile(
    r"upx|aspack|themida|vmprotect|petite|pecompact|nspack|mpress|enigma|armadillo|"
    r"molebox|obsidium|execryptor|pespin|yoda|fsg|mew|packman|kkrunchy|rlpack|"
    r"winupack|exestealth|neolite|shrinker|telock|packer|protector|crypter", re.I)

# Un outil qui n'a pas pu tourner ne doit jamais voter. La confusion est surtout
# dangereuse pour la reponse negative : "aucun packer trouve" et "jamais demarre"
# se ressemblent, et le second devient silencieusement un vote "non packe".
BROKEN = re.compile(
    r"error while loading shared libraries|cannot open shared object|"
    r"command not found|Permission denied|Segmentation fault|core dumped|"
    r"Traceback \(most recent call last\)|ImportError|ModuleNotFoundError|"
    r"GLIBC.*not found", re.I)


def sh(cmd, timeout=None, allow_empty=False, check_broken=True):
    """Sortie de l'outil, ou une raison prefixee de \\x00 s'il n'a pas tourne."""
    if timeout is None:
        timeout = TOOL_TIMEOUT
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).replace("\r\n", "\n").replace("\r", "\n")
    except subprocess.TimeoutExpired:
        return "\x00timeout"
    except FileNotFoundError:
        return "\x00not installed"
    except Exception as exc:
        return f"\x00{exc}"
    if not out.strip():
        # Le silence ne veut pas dire la meme chose pour tous : PEiD muet signifie
        # "aucune signature", ce qui est un non valide. Seul l'appelant le sait.
        return "" if allow_empty else "\x00no output"
    if check_broken and BROKEN.search(out):
        return "\x00" + " ".join(out.split())[:1200]
    return out


def ask_pypackerdetect(path):
    out = sh(["pypackerdetect", str(path)])
    if out.startswith("\x00"):
        return None, "did not run", out
    det = re.search(r"Detections?\s*:\s*(\d+)", out, re.I)
    sus = re.search(r"Suspicions?\s*:\s*(\d+)", out, re.I)
    if not (det or sus):
        return None, "unclear output", out
    n_det = int(det.group(1)) if det else 0
    n_sus = int(sus.group(1)) if sus else 0
    if n_det == 0 and n_sus == 0:
        return False, "0 detections, 0 suspicions", out
    found = re.findall(r"\[(?:DETECTION|SUSPICION)\]\s*(.+)", out)
    why = " | ".join(" ".join(f.split())[:80] for f in found[:4])
    return True, f"{n_det} detection(s), {n_sus} suspicion(s)" + (f": {why}" if why else ""), out


def ask_peid(path):
    # PEiD sort 0 et n'imprime rien quand aucune signature ne matche : c'est un non,
    # pas une panne. Environ un echantillon sur cinq sur ce corpus.
    out = sh(["peid", str(path)], allow_empty=True)
    if out.startswith("\x00"):
        return None, "did not run", out
    if not out.strip() or re.search(r"no\s+signature|nothing", out, re.I):
        return False, "no signature matched", out
    lines, seen = [], set()
    for line in out.splitlines():
        line = line.strip()
        if line and line.lower() not in seen:
            seen.add(line.lower())
            lines.append(line[:60])
    if lines and PACKER_WORD.search(out):
        return True, "signature: " + " | ".join(lines[:3]), out
    return False, "no signature matched", out


def ask_manalyze(path):
    """Le plugin packer de Manalyze : un second avis structurel, independant.

    Un objet "Plugins" vide est un non propre, le plugin a tourne et n'a rien
    trouve. Manalyze ecrit aussi des avertissements sur stderr avant le JSON, donc
    l'accolade est localisee plutot que supposee au premier octet.
    """
    out = sh(MANALYZE_CMD + ["--plugins=packer", "--output=json", str(path)])
    if out.startswith("\x00"):
        return None, "did not run", out
    try:
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except Exception:
        return None, "output was not JSON", out

    report = next(iter(data.values()), None) if isinstance(data, dict) else None
    if not isinstance(report, dict) or "Plugins" not in report:
        return None, "unexpected report shape", out

    plug = (report.get("Plugins") or {}).get("packer")
    if not plug:
        return False, "no packer indicator", out

    level = plug.get("level")
    summary = str(plug.get("summary") or "").strip()
    po = plug.get("plugin_output") or {}
    reasons = ([str(v) for _, v in sorted(po.items())] if isinstance(po, dict)
               else [str(x) for x in po])
    why = summary or f"level {level}"
    if reasons:
        why = f"{why}: " + " | ".join(reasons[:3])

    # NO_OPINION 0, SAFE 1, SUSPICIOUS 2, MALICIOUS 3
    if isinstance(level, bool):
        return None, "unexpected level type", out
    if isinstance(level, int):
        return (level >= 2), why, out
    if isinstance(level, str):
        return (level.strip().upper() in ("SUSPICIOUS", "MALICIOUS")), why, out
    return None, "the packer plugin reported no level", out


ASK = {"pypackerdetect": ask_pypackerdetect, "peid": ask_peid, "manalyze": ask_manalyze}


# ===========================================================================
# 4. CONTROLE : CAPA
# ===========================================================================

def capa_args():
    a = []
    if CAPA_RULES:
        a += ["-r", CAPA_RULES]
    if CAPA_SIGS:
        a += ["-s", CAPA_SIGS]
    return a


def parse_capa_text(out):
    """Le listing -v : une ligne qui n'est ni un en-tete ni un couple cle/valeur
    est un nom de capacite, et son namespace suit sur la ligne d'apres."""
    header = {"md5", "sha1", "sha256", "path", "timestamp", "capa version", "os",
              "format", "arch", "analysis", "extractor", "base address", "rules",
              "function count", "library function count", "total feature count"}
    caps, namespaces, pending = [], [], None
    for line in out.splitlines():
        raw = line.rstrip()
        if not raw.strip() or raw.startswith("WARNING") or raw.startswith(" "):
            continue
        low = raw.strip().lower()
        if any(low.startswith(h) for h in header):
            pending = None
            continue
        m = re.match(r"^(namespace|scope|matches|author|att&ck|mbc)\s+(.*)$",
                     raw.strip(), re.I)
        if m:
            if m.group(1).lower() == "namespace" and pending:
                namespaces.append(m.group(2).strip())
            continue
        pending = raw.strip()
        caps.append(pending)
    return caps, namespaces


def parse_capa_json(out):
    """Le rapport -j. Les regles de bibliotheque sont exclues : elles identifient
    du code lie statiquement que l'auteur n'a pas ecrit, et les compter comme un
    comportement de l'echantillon revient a crediter un stub UPX d'implementer
    CRC32."""
    try:
        data = json.loads(out[out.index("{"):])
    except Exception:
        return None
    rules = data.get("rules")
    if not isinstance(rules, dict):
        return None

    caps, namespaces, attack, mbc, lib = [], [], [], [], 0
    for rule_name, v in rules.items():
        meta = v.get("meta") or {}
        if meta.get("lib"):
            lib += 1
            continue
        caps.append(meta.get("name") or rule_name)
        ns = meta.get("namespace") or ""
        if ns:
            namespaces.append(ns)
        for a in meta.get("attack") or []:
            label = "::".join(x for x in [a.get("tactic"), a.get("technique"),
                                          a.get("subtechnique")] if x)
            if a.get("id"):
                label = f"{label} [{a['id']}]" if label else a["id"]
            if label:
                attack.append(label)
        for b in meta.get("mbc") or []:
            label = "::".join(x for x in [b.get("objective"), b.get("behavior"),
                                          b.get("method")] if x)
            if b.get("id"):
                label = f"{label} [{b['id']}]" if label else b["id"]
            if label:
                mbc.append(label)

    analysis = ((data.get("meta") or {}).get("analysis") or {})
    return {"capabilities": caps, "namespaces": namespaces,
            "attack": sorted(set(attack)), "mbc": sorted(set(mbc)),
            "n_library_rules": lib,
            "format": analysis.get("format") or "", "arch": analysis.get("arch") or "",
            "os": analysis.get("os") or ""}


def _capa_pack(namespaces, raw):
    packer_ns = [n for n in namespaces if "anti-analysis/packer" in n.lower()]
    return bool(packer_ns) or "appears to be packed" in raw.lower(), packer_ns


def run_capa(path):
    """JSON d'abord, listing -v en repli.

    Si capa est desactive, le rapport vaut "not run" : non mesure. Ce n'est pas
    un rapport vide, et rien en aval ne doit le lire comme "aucune capacite".

    capa refuse le rapport structure sur un echantillon qu'il juge packe : il sort
    en une seconde sans analyser. Essayer -j en premier est donc presque gratuit,
    et seul l'echec declenche la passe -v, qui est la passe couteuse.
    """
    if not CAPA_ENABLED:
        return {"status": "not run", "seconds": None,
                "excerpt": "capa desactive par --no-capa"}

    t0 = time.perf_counter()

    def elapsed():
        return round(time.perf_counter() - t0, 2)

    out = sh(CAPA_CMD + capa_args() + ["-j", str(path)], timeout=CAPA_TIMEOUT,
             check_broken=False)
    if out.startswith("\x00") and "timeout" in out:
        return {"status": "timeout", "seconds": elapsed(), "excerpt": out[:200]}
    if re.search(r"rules not found|provide your own rule set|no rules selected", out, re.I):
        return {"status": "no rule set", "seconds": elapsed(),
                "excerpt": "capa sans regles : passe --capa-rules"}

    parsed = parse_capa_json(out) if not out.startswith("\x00") else None
    if parsed is not None:
        packed, packer_ns = _capa_pack(parsed["namespaces"], out)
        return {"status": "ok", "mode": "json", "seconds": elapsed(),
                "n_capabilities": len(parsed["capabilities"]),
                "capabilities": parsed["capabilities"],
                "namespaces": sorted(set(parsed["namespaces"])),
                "attack": parsed["attack"], "mbc": parsed["mbc"],
                "n_library_rules": parsed["n_library_rules"],
                "format": parsed["format"], "arch": parsed["arch"], "os": parsed["os"],
                "packer_namespaces": packer_ns, "flagged_packed_by_capa": packed}

    out2 = sh(CAPA_CMD + capa_args() + ["-v", "--color", "never", str(path)],
              timeout=CAPA_TIMEOUT)
    if out2.startswith("\x00"):
        return {"status": "timeout" if "timeout" in out2 else "did not run",
                "seconds": elapsed(), "excerpt": out2[:200]}
    caps, ns = parse_capa_text(out2)
    if not caps and "total feature count" not in out2:
        return {"status": "no usable output", "seconds": elapsed(),
                "excerpt": " ".join(out2.split())[:200]}
    packed, packer_ns = _capa_pack(ns, out + out2)
    return {"status": "ok", "mode": "verbose (json withheld: sample looks packed)",
            "seconds": elapsed(), "n_capabilities": len(caps), "capabilities": caps,
            "namespaces": sorted(set(ns)), "attack": [], "mbc": [],
            "packer_namespaces": packer_ns, "flagged_packed_by_capa": packed}


def check_sample(path):
    """Le vote des trois detecteurs, plus le rapport capa complet."""
    res, yes, no, err = {}, 0, 0, 0
    for name in VOTERS:
        t0 = time.perf_counter()
        answer, reason, raw = ASK[name](path)
        res[name] = {"answer": {True: "yes", False: "no", None: "error"}[answer],
                     "reason": reason,
                     "seconds": round(time.perf_counter() - t0, 2)}
        if answer is None:
            res[name]["detail"] = " ".join(str(raw).replace("\x00", "").split())[:1500]
            err += 1
        elif answer:
            yes += 1
        else:
            no += 1
    n = len(VOTERS)
    # Regle retenue : un seul oui suffit. Rappel parfait, ce qui est la propriete
    # voulue quand l'etiquette sert a isoler un sous-ensemble garanti non packe.
    verdict = "packed" if yes >= 1 else ("not packed" if err == 0 else "undetermined")
    out = {"tools": res, "yes": yes, "no": no, "errors": err,
           "score": f"{yes}/{n}", "verdict": verdict}

    malformed = [k for k, v in res.items()
                 if v["answer"] == "error" and "outside sections" in v.get("detail", "")]
    if malformed:
        out["pe_malformed"] = True
        out["pe_malformed_by"] = malformed

    out["capa_report"] = run_capa(path)
    return out


# ===========================================================================
# 5. ECRITURE DES RESULTATS
# ===========================================================================

def read_records(path):
    """Les enregistrements deja ecrits, en tolerant un fichier encore ouvert."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except (EOFError, OSError, zlib.error):
        return


class ResultWriter:
    """Chaque enregistrement est compresse comme son PROPRE membre gzip puis ajoute.

    gzip accepte une concatenation de membres, donc les lecteurs n'y voient que du
    feu. Mais un flux unique n'est termine qu'a la fermeture du fichier : un run
    interrompu produirait un fichier illisible sur son dernier membre, et c'est
    precisement ce fichier-la que la reprise doit relire.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.fh = None

    def done(self):
        return {r["md5"] for r in read_records(self.path) if r.get("md5")}

    def write(self, rec):
        blob = gzip.compress((json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8"))
        with self.lock:
            if self.fh is None:
                self.fh = self.path.open("ab")
            self.fh.write(blob)
            self.fh.flush()

    def close(self):
        with self.lock:
            if self.fh is not None:
                self.fh.close()
                self.fh = None


# ===========================================================================
# 6. BOUCLE PRINCIPALE
# ===========================================================================

def handle(md5, label, feat_dir, work_dir, pool, session, writer):
    """Un echantillon : telecharge, les deux analyses, puis on jette le binaire."""
    rec = {"md5": md5, "label": label, "source": "virusshare",
           "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    binary = Path(work_dir) / md5
    sample = None
    try:
        vs_download(pool, md5, binary, session)
        sample = extract_if_zip(binary)
        data = sample.read_bytes()
    except Transient as exc:
        # RIEN n'est ecrit : sans enregistrement, la prochaine reprise retentera.
        binary.unlink(missing_ok=True)
        return {"md5": md5, "status": "retry_later", "error": str(exc)}
    except NotAvailable as exc:
        binary.unlink(missing_ok=True)
        rec.update(status="download_failed", error=str(exc))
        writer.write(rec)
        return rec

    sha = hashlib.sha256(data).hexdigest()
    rec["sha256"] = sha
    rec["size"] = len(data)

    # --- sortie 1 : les features statiques
    feat_out = Path(feat_dir) / f"{sha}.json"
    if feat_out.exists():
        rec["features"] = "already there"
    else:
        try:
            facts = extract_features(sha, label, data)
            tmp = feat_out.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(_json_safe(facts), indent=2), encoding="utf-8")
            tmp.replace(feat_out)          # ecriture atomique
            rec["features"] = "ok"
        except Exception as exc:
            rec["features"] = f"failed: {exc!r}"[:200]
            rec["pe_parsed"] = False

    # --- sortie 2 : le controle packing + capa
    try:
        rec.update(check_sample(sample))
        rec["status"] = "ok"
    except Exception as exc:
        rec.update(status="check_failed", error=repr(exc)[:200])
    finally:
        binary.unlink(missing_ok=True)
        if sample is not None and sample != binary:
            shutil.rmtree(sample.parent, ignore_errors=True)

    writer.write(rec)
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True,
                    help="csv avec au moins une colonne md5 ; categories est utilisee "
                         "comme label si elle existe")
    ap.add_argument("--features-out", default="features")
    ap.add_argument("--check-out", default="check/results.jsonl.gz")
    ap.add_argument("--work-dir", default="/tmp/vs_pipeline")
    ap.add_argument("--keys-file", default="keys_new.txt")
    ap.add_argument("--rate", type=float, default=DEFAULT_RATE,
                    help="requetes par minute PAR CLE ; divise par le nombre de runs "
                         "partageant le meme fichier de cles")
    ap.add_argument("--capa-cmd", default=os.environ.get("CAPA_CMD", "capa"))
    ap.add_argument("--capa-rules", default=os.environ.get("CAPA_RULES", ""))
    ap.add_argument("--capa-sigs", default=os.environ.get("CAPA_SIGS", ""))
    ap.add_argument("--capa-timeout", type=int, default=600)
    ap.add_argument("--no-yara", action="store_true",
                    help="ne pas compiler ni executer les regles YARA. Elles se "
                         "declenchent sur presque tout le corpus et ne votent "
                         "pas pour le packing. Le champ vaut alors "
                         "yara_error=desactive : non mesure, pas vide.")
    ap.add_argument("--no-capa", action="store_true",
                    help="ne pas lancer capa. Il coute 2,4 min par "
                         "echantillon, soit 90 %% du temps, pour une "
                         "donnee inutilisee en aval. Le rapport vaut "
                         "alors 'not run' : non mesure, pas vide.")
    ap.add_argument("--tool-timeout", type=int, default=300)
    ap.add_argument("--manalyze", default=os.environ.get("MANALYZE_CMD", "manalyze"))
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--shard", default="",
                    help="traiter une part seulement, sous la forme K/N. "
                         "Chaque shard doit ecrire dans son propre --check-out")
    args = ap.parse_args()

    global MANALYZE_CMD, CAPA_CMD, CAPA_RULES, CAPA_SIGS, CAPA_TIMEOUT, CAPA_ENABLED, NO_YARA
    global TOOL_TIMEOUT, _yara_rules
    MANALYZE_CMD = args.manalyze.split()
    CAPA_CMD = args.capa_cmd.split()
    CAPA_ENABLED = not args.no_capa
    NO_YARA = args.no_yara
    CAPA_RULES = args.capa_rules
    CAPA_SIGS = args.capa_sigs
    CAPA_TIMEOUT = args.capa_timeout
    TOOL_TIMEOUT = args.tool_timeout

    # Tout est verifie ici, pas au premier echantillon : un outil absent doit
    # empecher le demarrage, pas produire des milliers d'erreurs identiques.
    missing = []
    for name in VOTERS:
        cmd = MANALYZE_CMD[0] if name == "manalyze" else name
        if not (shutil.which(cmd) or Path(cmd).exists()):
            missing.append(f"{name} ({cmd})")
    if missing:
        sys.exit("outils introuvables : " + ", ".join(missing))
    if CAPA_ENABLED and not (shutil.which(CAPA_CMD[0]) or Path(CAPA_CMD[0]).exists()):
        sys.exit(f"capa introuvable : {CAPA_CMD[0]}")
    if not CAPA_RULES or not Path(CAPA_RULES).is_dir():
        sys.exit("capa sans regles : passe --capa-rules. Sans elles capa n'analyse "
                 "rien, et ses messages d'erreur ressemblent a des capacites")

    feat_dir = Path(args.features_out)
    feat_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    if NO_YARA:
        # ne rien charger : la compilation des 571 fichiers coute plusieurs
        # secondes au demarrage, et le champ doit valoir "desactive", pas vide
        _yara_rules = None
        print("yara       : DESACTIVE (--no-yara)")
    elif yara_manager:
        try:
            rules = yara_manager.setup_yara_rules()
            rules.save(YARA_COMPILED)
            _yara_rules = yara.load(YARA_COMPILED)
            print(f"yara       : regles compilees -> {YARA_COMPILED}")
        except Exception as exc:
            print(f"yara       : indisponible ({exc}) -- advanced_yara sera vide")
    else:
        print("yara       : yara_manager absent -- advanced_yara sera vide")

    n_rules = len(list(Path(CAPA_RULES).rglob("*.yml")))
    print(f"capa       : {CAPA_CMD[0]}  ({n_rules} regles)"
          if CAPA_ENABLED else "capa       : DESACTIVE (--no-capa)")
    print(f"votants    : {', '.join(VOTERS)}   regle : un seul oui suffit")

    writer = ResultWriter(args.check_out)
    done = writer.done()

    samples = []
    with open(args.csv, encoding="utf-8") as fh:
        rdr = _csv.DictReader(fh)
        if "md5" not in (rdr.fieldnames or []):
            sys.exit(f"{args.csv} n'a pas de colonne md5 (colonnes : {rdr.fieldnames})")
        for row in rdr:
            m = (row.get("md5") or "").strip().lower()
            if m:
                samples.append((m, row.get("categories") or row.get("label") or "unknown"))
    todo = [s for s in samples if s[0] not in done]
    if args.shard:
        try:
            k, nsh = (int(x) for x in args.shard.split("/"))
        except ValueError:
            sys.exit("--shard attend K/N, par exemple 0/4")
        if not 0 <= k < nsh:
            sys.exit(f"--shard {args.shard} : K doit etre entre 0 et {nsh - 1}")
        # pas par blocs mais par pas : chaque tache voit alors le meme melange
        # d'echantillons rapides et lents, et les shards finissent ensemble
        todo = todo[k::nsh]
        print(f"shard      : {k}/{nsh}")
    if args.limit:
        todo = todo[:args.limit]

    pool = KeyPool(args.keys_file, args.rate)
    per_min = args.rate * len(pool.keys)
    print(f"cles VS    : {len(pool.keys)}  ->  ~{per_min:.0f} echantillons/min")
    print(f"csv        : {len(samples):,} echantillons, {len(done):,} deja traites")
    print(f"a traiter  : {len(todo):,}   (~{len(todo)/max(per_min,1e-9)/60:.1f} h au debit des cles)")
    print(f"features   : {feat_dir}/<sha256>.json")
    print(f"controle   : {writer.path}")
    print(f"binaires   : {work_dir}  (supprimes apres analyse)\n")

    # Manifeste du run. Il porte ce qui vaut pour TOUS les echantillons et
    # n'a donc pas sa place dans chacun : quels outils ont tourne, dans quelle
    # version, et quels blocs sont volontairement absents. Sans lui, un champ
    # manquant serait ambigu -- coupe exprès, ou fichier d'une vieille version ?
    try:
        manifest = {
            "shard": args.shard or "1/1",
            "csv": str(args.csv),
            "n_samples_total": len(samples),
            "n_todo_at_start": len(todo),
            "yara_enabled": not NO_YARA,
            "capa_enabled": bool(CAPA_ENABLED),
            "voters": list(VOTERS),
            "packing_rule": "any_ge_1",
            "blocks_omitted": ([] if not NO_YARA else ["advanced_yara"]),
            "tool_versions": {
                "python": sys.version.split()[0],
                "lief": getattr(lief, "__version__", None),
                "tlsh": "present" if tlsh else "absent",
                "capa_cmd": CAPA_CMD[0] if CAPA_ENABLED else None,
                "capa_rules_count": n_rules if CAPA_ENABLED else None,
                "manalyze_cmd": MANALYZE_CMD[0],
            },
        }
        mpath = feat_dir / ("_manifest_%s.json" % (args.shard or "all").replace("/", "of"))
        mpath.write_text(json.dumps(manifest, indent=1, ensure_ascii=False),
                         encoding="utf-8")
        print(f"manifeste  : {mpath}\n")
    except Exception as exc:
        print(f"manifeste  : non ecrit ({exc})\n")

    if not todo:
        return

    session = requests.Session()
    tally = Counter()
    t0 = time.perf_counter()
    nbatch = (len(todo) + args.batch - 1) // args.batch

    for bi in range(nbatch):
        chunk = todo[bi * args.batch:(bi + 1) * args.batch]
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(handle, m, lab, feat_dir, work_dir, pool, session, writer)
                       for m, lab in chunk]
            for fut in as_completed(futures):
                try:
                    rec = fut.result()
                except Exception as exc:
                    tally["crashed"] += 1
                    print(f"    erreur inattendue : {exc!r}", flush=True)
                    continue
                tally[rec.get("verdict") or rec.get("status")] += 1

        n = sum(tally.values())
        el = time.perf_counter() - t0
        rate = n / max(el / 60, 1e-9)
        left = (len(todo) - n) / max(rate, 1e-9) / 60
        state = "  ".join(f"{a} {b:,}" for a, b in sorted(tally.items()))
        print(f"  lot {bi + 1:4}/{nbatch}  {n:6,}/{len(todo):,}  {state}  "
              f"{rate:.1f}/min  ~{left:.1f} h", flush=True)

    writer.close()
    print(f"\ntermine  : {dict(tally)}")
    print(f"cles     : {pool.report()}")
    print(f"features : {feat_dir}/   controle : {writer.path}")


if __name__ == "__main__":
    main()
