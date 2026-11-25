import http.server
import json
import os
import re
import socket
import socketserver
import sqlite3
import sys
import threading
import time
import urllib.parse
import gzip
import zipfile
import tarfile
import bz2
import io
import base64
import datetime
from html.parser import HTMLParser
try:
    import pcap_analyzer
except Exception:
    pcap_analyzer = None
try:
    import pdf_extractor
except Exception:
    pdf_extractor = None

PORT = 8085
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

SERVER_START_TIME = time.time()
DEFAULT_DB_PATH = None
ACTIVE_DB_PATH = None

upload_state = {
    'status': 'idle',
    'fileName': '',
    'clientName': 'Entrust General',
    'clientSlug': 'general',
    'fileSize': 0,
    'progress': 0,
    'linesProcessed': 0,
    'totalErrors': 0,
    'totalWarnings': 0,
    'dbPath': None,
    'error': None
}

pcap_upload_state = {
    'status': 'idle',
    'fileName': '',
    'clientName': 'Entrust General',
    'clientSlug': 'general',
    'packetsProcessed': 0,
    'bytesProcessed': 0,
    'dbPath': None,
    'error': None
}

def get_client_slug(client_name_or_id):
    if not client_name_or_id:
        return 'general'
    slug = re.sub(r'[^a-zA-Z0-9_]', '_', str(client_name_or_id).lower().strip())
    slug = re.sub(r'_+', '_', slug).strip('_')
    # Common mappings
    if 'mercantil' in slug:
        return 'mercantil'
    if 'banesco' in slug:
        return 'banesco'
    if 'bancamiga' in slug:
        return 'bancamiga'
    if 'provincial' in slug or 'bbva' in slug:
        return 'provincial'
    if 'idaas' in slug:
        return 'idaas_cloud'
    return slug or 'general'

def save_active_session(db_path, client_name='General'):
    global ACTIVE_DB_PATH
    if db_path and os.path.exists(db_path):
        ACTIVE_DB_PATH = db_path
        try:
            sess_file = os.path.join(DATA_DIR, 'active_session.json')
            with open(sess_file, 'w', encoding='utf-8') as f:
                json.dump({'activeDbPath': db_path, 'clientName': client_name, 'updatedAt': time.time()}, f)
        except Exception:
            pass

# ==========================================================================
# INDEXADOR FULL-TEXT DE MANUALES OFICIALES ENTRUST (WEBHELP & KB HTML)
# ==========================================================================
MANUALS_INDEX = []
BASE_MANUALS_INDEX = []
MANUALS_INDEX_BUILT = False
MANUALS_INDEX_BUILDING = False
MANUALS_INDEX_LOCK = threading.Lock()
MANUALS_CACHE_PATH = os.path.join(BASE_DIR, 'manuals', 'manuals_index_cache.json.gz')

def _custom_manuals_dir():
    return os.path.join(BASE_DIR, 'manuals', 'custom')

def _custom_pdf_extracted_dir():
    return os.path.join(_custom_manuals_dir(), '.extracted')

def _custom_pdf_codes_path():
    return os.path.join(DATA_DIR, 'custom_pdf_codes.json')

def _custom_metadata_path():
    return os.path.join(_custom_manuals_dir(), '.metadata.json')

CUSTOM_VERSION_SLUGS = {
    'IG 13.0': 'ig_13_0',
    'IG 12.0': 'ig_12_0',
    'IG 11.0': 'ig_11_0',
    'IG 10.0': 'ig_10_0',
    'IG 9.0': 'ig_9_0',
    'IDaaS Cloud': 'idaas',
    'General': 'general',
}
SLUG_TO_CUSTOM_VERSION = {v: k for k, v in CUSTOM_VERSION_SLUGS.items()}
CUSTOM_VERSION_ORDER = ['IG 13.0', 'IG 12.0', 'IG 11.0', 'IG 10.0', 'IG 9.0', 'IDaaS Cloud', 'General']

def _normalize_doc_version(raw_ver='', fallback_filename=''):
    rv = str(raw_ver or '').strip()
    if rv and rv.lower() != 'auto':
        if rv in CUSTOM_VERSION_SLUGS:
            return rv
        rl = rv.lower()
        if rl in SLUG_TO_CUSTOM_VERSION:
            return SLUG_TO_CUSTOM_VERSION[rl]
        if 'idaas' in rl or 'intellitrust' in rl or 'trustedauth' in rl or 'cloud' in rl:
            return 'IDaaS Cloud'
        if re.search(r'(?:ig[_\-\s]*13\d*|v?13(?:\.\d+)?\b)', rl):
            return 'IG 13.0'
        if re.search(r'(?:ig[_\-\s]*12\d*|v?12(?:\.\d+)?\b)', rl):
            return 'IG 12.0'
        if re.search(r'(?:ig[_\-\s]*11\d*|v?11(?:\.\d+)?\b)', rl):
            return 'IG 11.0'
        if re.search(r'(?:ig[_\-\s]*10\d*|v?10(?:\.\d+)?\b)', rl):
            return 'IG 10.0'
        if re.search(r'(?:ig[_\-\s]*9\d*|v?9(?:\.\d+)?\b)', rl):
            return 'IG 9.0'
        if 'general' in rl:
            return 'General'

    fn = str(fallback_filename or '').lower()
    if fn:
        if 'idaas' in fn or 'intellitrust' in fn or 'trustedauth' in fn:
            return 'IDaaS Cloud'
        if re.search(r'(?:ig[_\-\s]*13\d*|identityguard[_\-\s]*13|\bv13(?:\.\d+)?\b|\b13\.\d+\b|(?:^|[_\-\s])130(?:[_\-\s\.]|$))', fn):
            return 'IG 13.0'
        if re.search(r'(?:ig[_\-\s]*12\d*|identityguard[_\-\s]*12|\bv12(?:\.\d+)?\b|\b12\.\d+\b|(?:^|[_\-\s])120(?:[_\-\s\.]|$))', fn):
            return 'IG 12.0'
        if re.search(r'(?:ig[_\-\s]*11\d*|identityguard[_\-\s]*11|\bv11(?:\.\d+)?\b|\b11\.\d+\b|(?:^|[_\-\s])110(?:[_\-\s\.]|$))', fn):
            return 'IG 11.0'
        if re.search(r'(?:ig[_\-\s]*10\d*|identityguard[_\-\s]*10|\bv10(?:\.\d+)?\b|\b10\.\d+\b|(?:^|[_\-\s])10[012](?:[_\-\s\.]|$))', fn):
            return 'IG 10.0'
        if re.search(r'(?:ig[_\-\s]*9\d*|identityguard[_\-\s]*9|\bv9(?:\.\d+)?\b|\b9\.\d+\b|(?:^|[_\-\s])9[0-3](?:[_\-\s\.]|$))', fn):
            return 'IG 9.0'
    return 'General'

def _load_custom_metadata():
    p = _custom_metadata_path()
    if not os.path.isfile(p):
        return {}
    try:
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _save_custom_metadata(meta_dict):
    try:
        _atomic_write_json(_custom_metadata_path(), meta_dict or {})
    except Exception:
        pass

MANUALS_STOP_WORDS = {
    'de', 'la', 'el', 'los', 'las', 'un', 'una', 'unos', 'unas', 'en', 'y', 'o',
    'a', 'por', 'para', 'con', 'sin', 'sobre', 'que', 'como', 'cual', 'cuales',
    'donde', 'cuando', 'es', 'son', 'esta', 'estan', 'hay', 'ser', 'tener',
    'hacer', 'hago', 'puedo', 'debo', 'error', 'errores', 'log', 'logs',
    'the', 'and', 'or', 'for', 'with', 'how', 'what', 'why', 'when', 'where',
    'this', 'that', 'from', 'into', 'your', 'entrust', 'identityguard'
}

def _detect_manual_version(rel_path):
    p = rel_path.lower().replace('\\', '/')
    if 'manuals/custom/' in p:
        sub = p.split('manuals/custom/', 1)[1].split('#', 1)[0]
        parts = [pt for pt in sub.split('/') if pt]
        if len(parts) >= 2 and parts[0] in SLUG_TO_CUSTOM_VERSION:
            ver = SLUG_TO_CUSTOM_VERSION[parts[0]]
        else:
            ver = _normalize_doc_version('auto', parts[-1] if parts else sub)
        if '.pdf' in p or '#page=' in p:
            return f"{ver} (PDF)"
        return f"{ver} (Custom)"
    if 'ig_130' in p or '130' in p:
        return 'IG 13.0'
    if 'ig_120' in p or '120' in p:
        return 'IG 12.0'
    if 'ig_110' in p or '110' in p:
        return 'IG 11.0'
    if 'ig_100' in p or '100' in p:
        return 'IG 10.0'
    if 'ig_90' in p:
        return 'IG 9.0'
    if 'idaas' in p:
        return 'IDaaS Cloud'
    return 'KB Errores'

class _FastTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_skip = 0
        self.in_title = False
        self.in_heading = False
        self.title_parts = []
        self.heading_parts = []
        self.text_parts = []

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t in ('script', 'style'):
            self.in_skip += 1
        elif t == 'title':
            self.in_title = True
        elif t in ('h1', 'h2') and not self.heading_parts:
            self.in_heading = True

    def handle_endtag(self, tag):
        t = tag.lower()
        if t in ('script', 'style') and self.in_skip > 0:
            self.in_skip -= 1
        elif t == 'title':
            self.in_title = False
        elif t in ('h1', 'h2'):
            self.in_heading = False

    def handle_data(self, data):
        if self.in_skip > 0:
            return
        if self.in_title:
            self.title_parts.append(data)
        elif self.in_heading:
            self.heading_parts.append(data)
        self.text_parts.append(data)

def _clean_html_text(raw_html):
    parser = _FastTextExtractor()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:
        pass
    title = ' '.join(parser.title_parts).strip()
    if not title or title.lower() in ('untitled', 'document'):
        title = ' '.join(parser.heading_parts).strip()
    title = re.sub(r'\s+', ' ', title).strip()
    cleaned = re.sub(r'\s+', ' ', ' '.join(parser.text_parts)).strip()
    return title[:180], cleaned

def _atomic_write_bytes(target_path, raw_bytes):
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    tmp_path = f"{target_path}.tmp.{threading.get_ident()}"
    with open(tmp_path, 'wb') as f:
        f.write(raw_bytes)
    os.replace(tmp_path, target_path)

def _atomic_write_json(target_path, payload):
    raw_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
    _atomic_write_bytes(target_path, raw_bytes)

def _load_base_manuals_cache():
    global BASE_MANUALS_INDEX
    if os.path.exists(MANUALS_CACHE_PATH):
        try:
            with gzip.open(MANUALS_CACHE_PATH, 'rt', encoding='utf-8') as f:
                cached = json.load(f)
            if isinstance(cached, list) and len(cached) > 0:
                cleaned = []
                for item in cached:
                    rel_p = str(item.get('path') or '').replace('\\', '/')
                    if rel_p.lower().startswith('manuals/custom/'):
                        continue
                    item['title_lower'] = (item.get('title') or '').lower()
                    item['text_lower'] = (item.get('text') or '').lower()
                    cleaned.append(item)
                BASE_MANUALS_INDEX = cleaned
                return cleaned
        except Exception:
            pass
    return None

def _sidecar_path_for(rel_subpath, legacy_fname=None):
    sidecar_dir = _custom_pdf_extracted_dir()
    primary = os.path.join(sidecar_dir, rel_subpath.replace('/', '__') + '.json')
    if os.path.isfile(primary):
        return primary, primary
    if legacy_fname and '/' not in rel_subpath:
        legacy = os.path.join(sidecar_dir, f"{legacy_fname}.json")
        if os.path.isfile(legacy):
            return legacy, primary
    return primary, primary

def _iter_custom_manual_files():
    """Yield (full_path, fname, rel_subpath, rel_path, doc_version) across root and version subdirs."""
    custom_dir = _custom_manuals_dir()
    if not os.path.isdir(custom_dir):
        return
    meta = _load_custom_metadata()
    seen_rel = set()

    # 1. Root files (100% backward compatible with legacy uploads in manuals/custom/)
    for fname in sorted(os.listdir(custom_dir)):
        if fname.startswith('.'):
            continue
        fpath = os.path.join(custom_dir, fname)
        if not os.path.isfile(fpath):
            continue
        rel_subpath = fname
        rel_path = f"manuals/custom/{rel_subpath}"
        raw_meta_ver = (meta.get(rel_subpath) or {}).get('version') if isinstance(meta.get(rel_subpath), dict) else None
        doc_ver = _normalize_doc_version(raw_meta_ver or 'auto', fallback_filename=fname)
        seen_rel.add(rel_subpath)
        yield (fpath, fname, rel_subpath, rel_path, doc_ver)

    # 2. Version subdirectories (ig_13_0, ig_12_0, ig_11_0, ig_10_0, ig_9_0, idaas, general)
    for ver_label in CUSTOM_VERSION_ORDER:
        slug = CUSTOM_VERSION_SLUGS[ver_label]
        sub_dir = os.path.join(custom_dir, slug)
        if not os.path.isdir(sub_dir):
            continue
        for fname in sorted(os.listdir(sub_dir)):
            if fname.startswith('.'):
                continue
            fpath = os.path.join(sub_dir, fname)
            if not os.path.isfile(fpath):
                continue
            rel_subpath = f"{slug}/{fname}"
            if rel_subpath in seen_rel:
                continue
            rel_path = f"manuals/custom/{rel_subpath}"
            raw_meta_ver = (meta.get(rel_subpath) or {}).get('version') if isinstance(meta.get(rel_subpath), dict) else None
            doc_ver = _normalize_doc_version(raw_meta_ver or ver_label, fallback_filename=fname)
            seen_rel.add(rel_subpath)
            yield (fpath, fname, rel_subpath, rel_path, doc_ver)

def _build_pdf_sidecar_and_index(full_path, fname, rel_subpath=None, doc_version='General'):
    """Return (sidecar_dict, index_entries_list) for a custom PDF in manuals/custom/."""
    rel_subpath = rel_subpath or fname
    rel_path = f"manuals/custom/{rel_subpath}"
    read_sc_path, write_sc_path = _sidecar_path_for(rel_subpath, legacy_fname=fname)
    try:
        fsize = os.path.getsize(full_path)
        fmtime = int(os.path.getmtime(full_path))
    except Exception:
        fsize, fmtime = 0, 0

    sidecar = None
    if os.path.isfile(read_sc_path):
        try:
            with open(read_sc_path, 'r', encoding='utf-8') as f:
                cached_sc = json.load(f)
            if isinstance(cached_sc, dict) and cached_sc.get('fileSize') == fsize and cached_sc.get('fileMtime') == fmtime and isinstance(cached_sc.get('pages'), list):
                sidecar = cached_sc
        except Exception:
            sidecar = None

    if sidecar is None:
        if pdf_extractor is None:
            sidecar = {
                'filename': fname,
                'relSubpath': rel_subpath,
                'path': rel_path,
                'version': doc_version,
                'fileSize': fsize,
                'fileMtime': fmtime,
                'ok': False,
                'engine': 'unavailable',
                'pageCount': 0,
                'totalChars': 0,
                'isScannedOrEmpty': True,
                'warning': 'Módulo pdf_extractor no disponible en el servidor.',
                'pages': [],
                'codes': {}
            }
        else:
            ext_res = pdf_extractor.extract_pdf_text(full_path)
            pages = ext_res.get('pages') or []
            codes = pdf_extractor.extract_entrust_codes_from_pages(pages, fname, rel_path)
            for c_val in codes.values():
                if isinstance(c_val, dict):
                    c_val['docVersion'] = doc_version
            sidecar = {
                'filename': fname,
                'relSubpath': rel_subpath,
                'path': rel_path,
                'version': doc_version,
                'fileSize': fsize,
                'fileMtime': fmtime,
                'ok': bool(ext_res.get('ok')),
                'engine': ext_res.get('engine') or 'stdlib-pdf',
                'pageCount': int(ext_res.get('pageCount') or len(pages) or 0),
                'totalChars': int(ext_res.get('totalChars') or 0),
                'isScannedOrEmpty': bool(ext_res.get('isScannedOrEmpty')),
                'isEncrypted': bool(ext_res.get('isEncrypted')),
                'warning': str(ext_res.get('warning') or ''),
                'pages': pages,
                'codes': codes
            }
            try:
                _atomic_write_json(write_sc_path, sidecar)
            except Exception:
                pass
    else:
        # Ensure docVersion and path stay synced even on legacy/migrated sidecars
        sidecar['version'] = doc_version
        sidecar['relSubpath'] = rel_subpath
        sidecar['path'] = rel_path
        for c_val in (sidecar.get('codes') or {}).values():
            if isinstance(c_val, dict):
                c_val['docVersion'] = doc_version
                pg = c_val.get('page') or 1
                c_val['manualFile'] = f"{rel_path}#page={pg}"

    pages = sidecar.get('pages') or []
    entries = []
    idx_version = f"{doc_version} (PDF)"
    if len(pages) > 200:
        for i in range(0, len(pages), 2):
            p1 = pages[i]
            p2 = pages[i + 1] if i + 1 < len(pages) else None
            p1_num = int(p1.get('page') or 1)
            if p2:
                p2_num = int(p2.get('page') or p1_num)
                title = f"{fname} (Pág. {p1_num}-{p2_num})"
                text_trimmed = (str(p1.get('text') or '') + '\n' + str(p2.get('text') or ''))[:10000]
            else:
                title = f"{fname} (Pág. {p1_num})"
                text_trimmed = str(p1.get('text') or '')[:10000]
            if len(text_trimmed) < 10:
                continue
            entries.append({
                'path': f"{rel_path}#page={p1_num}",
                'version': idx_version,
                'title': title,
                'title_lower': title.lower(),
                'text': text_trimmed,
                'text_lower': text_trimmed.lower()
            })
    else:
        for p in pages:
            p_num = int(p.get('page') or 1)
            text_trimmed = str(p.get('text') or '')[:10000]
            if len(text_trimmed) < 10:
                continue
            title = f"{fname} (Pág. {p_num})"
            entries.append({
                'path': f"{rel_path}#page={p_num}",
                'version': idx_version,
                'title': title,
                'title_lower': title.lower(),
                'text': text_trimmed,
                'text_lower': text_trimmed.lower()
            })

    return sidecar, entries

def _build_text_doc_sidecar_and_index(full_path, fname, rel_subpath=None, doc_version='General', force_rebuild=False):
    """Build or load cached v2 sidecar & full-text index entries for .html/.htm/.md/.txt files."""
    rel_subpath = rel_subpath or fname
    rel_path = f"manuals/custom/{rel_subpath}"
    fl = fname.lower()
    is_html = fl.endswith(('.html', '.htm'))
    read_sc_path, write_sc_path = _sidecar_path_for(rel_subpath, legacy_fname=fname)
    try:
        fsize = os.path.getsize(full_path)
        fmtime = int(os.path.getmtime(full_path))
    except Exception:
        fsize, fmtime = 0, 0

    sidecar = None
    if not force_rebuild and os.path.isfile(read_sc_path):
        try:
            with open(read_sc_path, 'r', encoding='utf-8') as f:
                cached_sc = json.load(f)
            if (
                isinstance(cached_sc, dict)
                and cached_sc.get('extractorVersion') == 2
                and cached_sc.get('fileSize') == fsize
                and cached_sc.get('fileMtime') == fmtime
                and isinstance(cached_sc.get('pages'), list)
            ):
                sidecar = cached_sc
        except Exception:
            sidecar = None

    if sidecar is None:
        if pdf_extractor is not None and hasattr(pdf_extractor, 'extract_html_or_text_document'):
            doc_res = pdf_extractor.extract_html_or_text_document(full_path)
            if doc_res.get('ok'):
                pages = doc_res.get('pages') or []
                codes = pdf_extractor.extract_entrust_codes_from_html_or_text(doc_res, fname, rel_path)
                title = doc_res.get('title') or fname
                engine = doc_res.get('engine') or ('html-parser' if is_html else 'text-parser')
                section_count = int(doc_res.get('sectionCount') or len(pages) or 1)
                total_chars = int(doc_res.get('totalChars') or 0)
            else:
                pages, codes, title, engine, section_count, total_chars = [], {}, fname, 'error', 0, 0
        else:
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    raw = f.read(2000000)
                if is_html:
                    title, text = _clean_html_text(raw)
                else:
                    title, text = fname, re.sub(r'\s+', ' ', raw).strip()
                pages = [{'page': 1, 'text': text[:10000], 'anchor': ''}] if text else []
                codes = {}
                engine = 'fallback-text'
                section_count = len(pages)
                total_chars = len(text)
            except Exception:
                pages, codes, title, engine, section_count, total_chars = [], {}, fname, 'error', 0, 0

        for c_val in codes.values():
            if isinstance(c_val, dict):
                c_val['docVersion'] = doc_version

        sidecar = {
            'extractorVersion': 2,
            'isPdf': False,
            'filename': fname,
            'relSubpath': rel_subpath,
            'path': rel_path,
            'version': doc_version,
            'title': title or fname,
            'fileSize': fsize,
            'fileMtime': fmtime,
            'ok': True,
            'engine': engine,
            'sectionCount': section_count,
            'totalChars': total_chars,
            'pages': pages,
            'codes': codes
        }
        try:
            _atomic_write_json(write_sc_path, sidecar)
        except Exception:
            pass
    else:
        sidecar['version'] = doc_version
        sidecar['relSubpath'] = rel_subpath
        sidecar['path'] = rel_path
        for c_val in (sidecar.get('codes') or {}).values():
            if isinstance(c_val, dict):
                c_val['docVersion'] = doc_version
                anc = str(c_val.get('anchor') or '').strip()
                if not anc and '#' in str(c_val.get('manualFile') or ''):
                    anc = str(c_val['manualFile']).split('#', 1)[1]
                c_val['manualFile'] = f"{rel_path}#{anc}" if anc else rel_path

    pages = sidecar.get('pages') or []
    base_title = sidecar.get('title') or fname
    idx_version = f"{doc_version} (HTML)" if is_html else f"{doc_version} (Doc)"
    entries = []
    for s in pages:
        sec_num = int(s.get('page') or 1)
        text_trimmed = str(s.get('text') or '')[:10000]
        if len(text_trimmed) < 10:
            continue
        anchor = str(s.get('anchor') or '').strip()
        entry_path = f"{rel_path}#{anchor}" if anchor else rel_path
        entry_title = f"{base_title} (Secc. {sec_num})" if len(pages) > 1 else base_title
        entries.append({
            'path': entry_path,
            'version': idx_version,
            'title': entry_title,
            'title_lower': entry_title.lower(),
            'text': text_trimmed,
            'text_lower': text_trimmed.lower()
        })

    return sidecar, entries

def _scan_custom_manuals_and_rebuild_codes():
    custom_entries = []
    consolidated_codes = {}
    codes_by_version = {}
    version_entries_list = []
    versions_count = {}
    custom_files_count = 0

    for full_path, fname, rel_subpath, rel_path, doc_version in _iter_custom_manual_files():
        fl = fname.lower()
        versions_count[doc_version] = versions_count.get(doc_version, 0) + 1
        if fl.endswith('.pdf'):
            custom_files_count += 1
            sidecar, pdf_entries = _build_pdf_sidecar_and_index(full_path, fname, rel_subpath=rel_subpath, doc_version=doc_version)
            custom_entries.extend(pdf_entries)
            ver_map = codes_by_version.setdefault(doc_version, {})
            for code_k, code_v in (sidecar.get('codes') or {}).items():
                if not isinstance(code_v, dict):
                    continue
                enriched = dict(code_v)
                enriched['docVersion'] = doc_version
                if code_k not in ver_map:
                    ver_map[code_k] = enriched
                    version_entries_list.append(enriched)
                if code_k not in consolidated_codes:
                    consolidated_codes[code_k] = enriched
        elif fl.endswith(('.html', '.htm', '.md', '.txt')):
            custom_files_count += 1
            sidecar, doc_entries = _build_text_doc_sidecar_and_index(full_path, fname, rel_subpath=rel_subpath, doc_version=doc_version)
            custom_entries.extend(doc_entries)
            ver_map = codes_by_version.setdefault(doc_version, {})
            for code_k, code_v in (sidecar.get('codes') or {}).items():
                if not isinstance(code_v, dict):
                    continue
                enriched = dict(code_v)
                enriched['docVersion'] = doc_version
                if code_k not in ver_map:
                    ver_map[code_k] = enriched
                    version_entries_list.append(enriched)
                if code_k not in consolidated_codes:
                    consolidated_codes[code_k] = enriched

    codes_payload = {
        'extractorVersion': 2,
        'updatedAt': datetime.datetime.utcnow().isoformat() + 'Z',
        'totalCodes': len(consolidated_codes),
        'totalEntries': len(version_entries_list),
        'filesCount': custom_files_count,
        'versionsCount': versions_count,
        'codes': consolidated_codes,
        'codesByVersion': codes_by_version,
        'entries': version_entries_list
    }
    try:
        _atomic_write_json(_custom_pdf_codes_path(), codes_payload)
    except Exception:
        pass
    return custom_entries, codes_payload

def refresh_custom_manuals_index():
    global MANUALS_INDEX, MANUALS_INDEX_BUILT
    if not BASE_MANUALS_INDEX and os.path.exists(MANUALS_CACHE_PATH):
        _load_base_manuals_cache()
    custom_entries, codes_payload = _scan_custom_manuals_and_rebuild_codes()
    with MANUALS_INDEX_LOCK:
        MANUALS_INDEX = list(BASE_MANUALS_INDEX) + custom_entries
        MANUALS_INDEX_BUILT = True
    return len(MANUALS_INDEX), codes_payload

def build_manuals_index():
    global MANUALS_INDEX, BASE_MANUALS_INDEX, MANUALS_INDEX_BUILT, MANUALS_INDEX_BUILDING
    with MANUALS_INDEX_LOCK:
        if MANUALS_INDEX_BUILT:
            return len(MANUALS_INDEX)
        MANUALS_INDEX_BUILDING = True
    try:
        cached_base = _load_base_manuals_cache()
        if cached_base is not None:
            custom_entries, _ = _scan_custom_manuals_and_rebuild_codes()
            with MANUALS_INDEX_LOCK:
                MANUALS_INDEX = list(BASE_MANUALS_INDEX) + custom_entries
                MANUALS_INDEX_BUILT = True
                MANUALS_INDEX_BUILDING = False
            return len(MANUALS_INDEX)

        manuals_dir = os.path.join(BASE_DIR, 'manuals')
        if not os.path.isdir(manuals_dir):
            custom_entries, _ = _scan_custom_manuals_and_rebuild_codes()
            with MANUALS_INDEX_LOCK:
                MANUALS_INDEX = custom_entries
                MANUALS_INDEX_BUILT = True
                MANUALS_INDEX_BUILDING = False
            return len(MANUALS_INDEX)
        skip_names = {'toc.htm', 'index.htm', 'index_csh.htm', 'reference.htm', 'whskin_'}
        skip_dirs = {'whdata', 'whgdata', 'whxdata', 'template', 'custom'}
        entries = []
        processed_files = 0
        for root, dirs, files in os.walk(manuals_dir):
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs and not d.startswith('.')]
            for fname in files:
                fl = fname.lower()
                is_html = fl.endswith('.htm') or fl.endswith('.html')
                is_text = fl.endswith('.md') or fl.endswith('.txt')
                if not (is_html or is_text):
                    continue
                if any(fl.startswith(s) or fl == s for s in skip_names):
                    continue
                if fl.startswith('wh'):
                    continue
                full_path = os.path.join(root, fname)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        raw = f.read(200000)
                    if len(raw) < 40:
                        continue
                    if is_html:
                        title, text = _clean_html_text(raw)
                    else:
                        title = fname
                        text = re.sub(r'\s+', ' ', raw).strip()
                    if len(text) < 30:
                        continue
                    text_trimmed = text[:10000]
                    rel_path = os.path.relpath(full_path, BASE_DIR).replace('\\', '/')
                    entries.append({
                        'path': rel_path,
                        'version': _detect_manual_version(rel_path),
                        'title': title or fname,
                        'title_lower': (title or fname).lower(),
                        'text': text_trimmed,
                        'text_lower': text_trimmed.lower()
                    })
                    processed_files += 1
                    if processed_files % 25 == 0:
                        time.sleep(0.002)
                except Exception:
                    continue
        try:
            cache_payload = [{'path': e['path'], 'version': e['version'], 'title': e['title'], 'text': e['text']} for e in entries]
            with gzip.open(MANUALS_CACHE_PATH, 'wt', encoding='utf-8') as f:
                json.dump(cache_payload, f)
        except Exception:
            pass
        BASE_MANUALS_INDEX = entries
        custom_entries, _ = _scan_custom_manuals_and_rebuild_codes()
        with MANUALS_INDEX_LOCK:
            MANUALS_INDEX = list(BASE_MANUALS_INDEX) + custom_entries
            MANUALS_INDEX_BUILT = True
            MANUALS_INDEX_BUILDING = False
        return len(MANUALS_INDEX)
    except Exception:
        with MANUALS_INDEX_LOCK:
            MANUALS_INDEX_BUILDING = False
        return 0

def _extract_index_doc_version(ver_str):
    v = str(ver_str or '').strip()
    if not v:
        return 'General'
    vl = v.lower()
    if 'kb error' in vl:
        return 'KB Errores'
    if vl.startswith('general'):
        return 'General'
    if 'idaas' in vl or 'cloud' in vl:
        return 'IDaaS Cloud'
    if '13' in vl:
        return 'IG 13.0'
    if '12' in vl:
        return 'IG 12.0'
    if '11' in vl:
        return 'IG 11.0'
    if '10' in vl:
        return 'IG 10.0'
    if re.search(r'\big\s*9(?:\.\d+)?\b', vl):
        return 'IG 9.0'
    return 'General'

def search_manuals(query_str, version_filter=None, limit=6, prefer_version=None, include_general=False):
    if not MANUALS_INDEX_BUILT:
        if not MANUALS_INDEX_BUILDING:
            threading.Thread(target=build_manuals_index, daemon=True).start()
        return []
    q_raw = (query_str or '').strip()
    if not q_raw:
        return []
    q_lower = q_raw.lower()
    codes = re.findall(r'(?:52\d{4,5}|aud\d+|ora-\d+|s3-404)', q_lower)
    raw_tokens = re.findall(r'[a-z0-9_.\-]{3,}', q_lower)
    tokens = [t for t in raw_tokens if t not in MANUALS_STOP_WORDS]
    if not tokens and codes:
        tokens = codes
    if not tokens:
        tokens = raw_tokens[:4]

    ver_filter_norm = _extract_index_doc_version(version_filter) if version_filter else None
    pref_norm = _extract_index_doc_version(prefer_version) if prefer_version else None

    scored = []
    for doc in MANUALS_INDEX:
        doc_ver_raw = str(doc.get('version') or '')
        doc_ver_low = doc_ver_raw.lower()
        doc_rel = _extract_index_doc_version(doc_ver_raw)
        if version_filter:
            vf_low = version_filter.lower()
            if ver_filter_norm in ('IG 13.0', 'IG 12.0', 'IG 11.0', 'IG 10.0', 'IG 9.0', 'IDaaS Cloud'):
                if include_general:
                    if doc_rel != ver_filter_norm and doc_rel not in ('General', 'KB Errores'):
                        continue
                else:
                    if doc_rel != ver_filter_norm:
                        continue
            elif vf_low not in doc_ver_low:
                continue
        score = 0
        t_low = doc['title_lower']
        b_low = doc['text_lower']
        best_pos = -1

        for c in codes:
            if c in t_low:
                score += 140
            c_idx = b_low.find(c)
            if c_idx != -1:
                score += 75
                if best_pos == -1:
                    best_pos = c_idx

        if len(q_lower) >= 5 and q_lower in t_low:
            score += 90
        elif len(q_lower) >= 5:
            p_idx = b_low.find(q_lower)
            if p_idx != -1:
                score += 40
                if best_pos == -1:
                    best_pos = p_idx

        matched_tokens = 0
        for tok in tokens:
            hit = False
            if tok in t_low:
                score += 28
                hit = True
            idx = b_low.find(tok)
            if idx != -1:
                cnt = min(5, b_low.count(tok))
                score += 8 + (cnt * 2)
                hit = True
                if best_pos == -1:
                    best_pos = idx
            if hit:
                matched_tokens += 1

        if score == 0:
            continue
        if len(tokens) > 1 and matched_tokens >= len(tokens):
            score += 30
        if ver_filter_norm and doc_rel == ver_filter_norm:
            score += 60
        if pref_norm and pref_norm != 'General' and doc_rel == pref_norm:
            score += 45
        elif prefer_version and prefer_version.lower() in doc_ver_low:
            score += 45

        if best_pos == -1:
            snippet = doc['text'][:240]
        else:
            start = max(0, best_pos - 80)
            end = min(len(doc['text']), best_pos + 200)
            snippet = ('...' if start > 0 else '') + doc['text'][start:end].strip() + ('...' if end < len(doc['text']) else '')

        scored.append({
            'title': doc['title'],
            'version': doc['version'],
            'path': doc['path'],
            'score': score,
            'snippet': snippet
        })

    scored.sort(key=lambda x: x['score'], reverse=True)
    return scored[:limit]

def purge_db_files(db_path):
    """Safely removes a SQLite DB file and any -wal/-shm/-journal sidecars, falling back to row wipe if locked."""
    purged = []
    if not db_path:
        return purged
    for cand in (db_path, db_path + '-wal', db_path + '-shm', db_path + '-journal'):
        if os.path.exists(cand):
            removed = False
            for _ in range(3):
                try:
                    os.remove(cand)
                    removed = True
                    purged.append(os.path.basename(cand))
                    break
                except Exception:
                    time.sleep(0.05)
            if not removed and cand == db_path and os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path, timeout=10.0)
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = {r[0] for r in cur.fetchall()}
                    if 'logs' in tables:
                        cur.execute('DELETE FROM logs')
                    if 'server_stats' in tables:
                        cur.execute('DELETE FROM server_stats')
                    conn.commit()
                    cur.execute('VACUUM')
                    conn.close()
                    purged.append(os.path.basename(db_path) + ' (emptied)')
                except Exception:
                    pass
    return purged

def clear_active_session(client_param=None, purge_db=True):
    global ACTIVE_DB_PATH, upload_state
    candidate_paths = []
    norm_client = str(client_param).strip() if client_param is not None else ''
    has_specific_client = bool(norm_client and norm_client.lower() not in ('all', 'none', ''))
    target_slug_name = f"{get_client_slug(norm_client)}_audit.db" if has_specific_client else None

    if has_specific_client:
        candidate_paths.append(os.path.join(DATA_DIR, target_slug_name))

    sess_file = os.path.join(DATA_DIR, 'active_session.json')
    saved_db = None
    if os.path.exists(sess_file):
        try:
            with open(sess_file, 'r', encoding='utf-8') as f:
                sess = json.load(f) or {}
                saved_db = sess.get('activeDbPath')
        except Exception:
            saved_db = None

    if not has_specific_client:
        if ACTIVE_DB_PATH:
            candidate_paths.append(ACTIVE_DB_PATH)
        if saved_db:
            candidate_paths.append(saved_db)
        ACTIVE_DB_PATH = None
        if os.path.exists(sess_file):
            try:
                os.remove(sess_file)
            except Exception:
                pass
    else:
        if ACTIVE_DB_PATH and os.path.basename(ACTIVE_DB_PATH) == target_slug_name:
            candidate_paths.append(ACTIVE_DB_PATH)
            ACTIVE_DB_PATH = None
        if saved_db and os.path.basename(saved_db) == target_slug_name:
            candidate_paths.append(saved_db)
            if os.path.exists(sess_file):
                try:
                    os.remove(sess_file)
                except Exception:
                    pass

    seen_norm = set()
    unique_paths = []
    for p in candidate_paths:
        ap = os.path.abspath(p)
        if ap not in seen_norm:
            seen_norm.add(ap)
            unique_paths.append(ap)

    purged = []
    if purge_db:
        for p in unique_paths:
            purged.extend(purge_db_files(p))

    upload_state['status'] = 'idle'
    upload_state['fileName'] = ''
    upload_state['fileSize'] = 0
    upload_state['progress'] = 0
    upload_state['linesProcessed'] = 0
    upload_state['totalErrors'] = 0
    upload_state['totalWarnings'] = 0
    upload_state['dbPath'] = None
    upload_state['error'] = None

    return {'purgedFiles': purged, 'client': norm_client or None}

def resolve_client_db(client_param=None):
    global ACTIVE_DB_PATH

    if client_param and str(client_param).strip().lower() not in ('all', 'general', 'none', ''):
        cand_db = os.path.join(DATA_DIR, f"{get_client_slug(client_param)}_audit.db")
        if os.path.exists(cand_db):
            return cand_db

    # 1. Check ACTIVE_DB_PATH if set explicitly in current session
    if ACTIVE_DB_PATH and os.path.exists(ACTIVE_DB_PATH):
        return ACTIVE_DB_PATH

    # 2. Check persisted active_session.json ONLY if explicitly activated
    sess_file = os.path.join(DATA_DIR, 'active_session.json')
    if os.path.exists(sess_file):
        try:
            with open(sess_file, 'r', encoding='utf-8') as f:
                sess = json.load(f)
                saved_db = sess.get('activeDbPath')
                if saved_db and os.path.exists(saved_db):
                    ACTIVE_DB_PATH = saved_db
                    return saved_db
        except Exception:
            pass

    return None

def init_db(db_path):
    conn = sqlite3.connect(db_path, timeout=30.0)
    cur = conn.cursor()
    cur.execute('PRAGMA journal_mode = WAL;')
    cur.execute('PRAGMA synchronous = OFF;')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            line_num INTEGER PRIMARY KEY,
            event_time TEXT,
            subject_name TEXT,
            event_type TEXT,
            event_outcome TEXT,
            message TEXT,
            source_ip TEXT,
            raw TEXT
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_outcome ON logs(event_outcome);')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_type ON logs(event_type);')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_time ON logs(event_time);')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_user ON logs(subject_name);')
    conn.commit()
    conn.close()

INVALID_USER_STOPWORDS = {
    'unknown', 'system', 'null', 'none', 'undefined', 'n/a', 'na', 'local', 'database',
    'default', 'true', 'false', 'error', 'errors', 'fail', 'failed', 'failure', 'success',
    'successful', 'info', 'warn', 'warning', 'debug', 'critical', 'fatal', 'decode',
    'encode', 'decoding', 'encoding', 'password', 'passwords', 'passcode', 'pin', 'puk',
    'otp', 'token', 'tokens', 'grid', 'grids', 'card', 'cards', 'qa', 'challenge',
    'challenges', 'response', 'responses', 'request', 'requests', 'authentication',
    'authenticator', 'authenticators', 'authenticated', 'authenticate', 'authenticating',
    'authorization', 'authorized', 'authorize', 'verification', 'verify', 'verified',
    'not', 'no', 'non', 'is', 'was', 'are', 'were', 'be', 'been', 'being', 'has', 'have',
    'had', 'does', 'do', 'did', 'will', 'would', 'can', 'could', 'should', 'shall', 'may',
    'might', 'must', 'cannot', 'cant', 'without', 'within', 'specified', 'unspecified',
    'locked', 'unlocked', 'lock', 'unlock', 'disabled', 'enabled', 'disable', 'enable',
    'expired', 'expire', 'invalid', 'valid', 'found', 'missing', 'exists', 'exist',
    'existing', 'already', 'currently', 'assigned', 'unassigned', 'assign', 'created',
    'create', 'updated', 'update', 'deleted', 'delete', 'removed', 'remove', 'modified',
    'modify', 'migrated', 'migrate', 'migration', 'session', 'sessions', 'account',
    'accounts', 'profile', 'profiles', 'group', 'groups', 'role', 'roles', 'policy',
    'policies', 'service', 'services', 'id', 'ids', 'userid', 'username', 'name', 'names',
    'alias', 'aliases', 'credential', 'credentials', 'certificate', 'certificates',
    'cert', 'certs', 'device', 'devices', 'mobile', 'smart', 'soft', 'hard', 'attempt',
    'attempts', 'sequence', 'state', 'status', 'attribute', 'attributes', 'property',
    'properties', 'repository', 'store', 'directory', 'ldap', 'ad', 'jdbc', 'sql',
    'oracle', 'db', 'table', 'column', 'row', 'blob', 'clob', 'transaction',
    'transactions', 'operation', 'operations', 'action', 'actions', 'event', 'events',
    'audit', 'log', 'logs', 'message', 'messages', 'exception', 'exceptions', 'stack',
    'trace', 'thread', 'pool', 'connection', 'connections', 'timeout', 'timed', 'out',
    'for', 'with', 'from', 'to', 'in', 'on', 'at', 'by', 'of', 'or', 'and', 'the', 'a',
    'an', 'this', 'that', 'these', 'those', 'it', 'its', 'their', 'his', 'her', 'our',
    'your', 'my', 'who', 'whom', 'which', 'what', 'where', 'when', 'why', 'how', 'all',
    'any', 'some', 'each', 'every', 'other', 'another', 'such', 'only', 'own', 'same',
    'so', 'than', 'too', 'very', 'just', 'now', 'then', 'here', 'there', 'into', 'over',
    'after', 'before', 'between', 'under', 'again', 'further', 'once', 'during', 'about',
    'against', 'through', 'above', 'below', 'up', 'down', 'off', 'more', 'most', 'few',
    'both', 'either', 'neither', 'while', 'because', 'until', 'unless', 'since', 'though',
    'although', 'whether', 'if', 'else', 'when', 'where', 'admin_console', 'user_3238',
    'user_8912', 'user_1042', 'user', 'users', 'client', 'server', 'node', 'host', 'ip',
    'port', 'url', 'uri', 'http', 'https', 'api', 'soap', 'rest', 'xml', 'json', 'csv',
    'data', 'value', 'values', 'key', 'keys', 'type', 'types', 'code', 'codes', 'result',
    'results', 'reason', 'details', 'detail', 'description', 'summary', 'count', 'total',
    'number', 'level', 'category', 'source', 'target', 'subject', 'object', 'context',
    'catalina', 'tomcat', 'servlet', 'jsp', 'valve', 'connector', 'coyote', 'jasper',
    'naming', 'wrapper', 'lifecycle', 'protocol', 'standardcontext', 'standardengine',
    'standardhost', 'standardservice', 'standardwrapper', 'ajp', 'nio', 'apr', 'ssl',
    'tls', 'keystore', 'truststore', 'cacerts', 'jvm', 'java', 'jdk', 'jre', 'gc',
    'heap', 'metaspace', 'permgen', 'oom', 'stdout', 'stderr', 'localhost', 'webapps',
    'bootstrap', 'classloader', 'webappclassloader', 'jndi', 'datasource', 'driver',
    'hikari', 'dbcp', 'postgres', 'postgresql', 'sqlserver', 'mysql', 'charset',
    'utf-8', 'iso-8859-1', 'tomcat8', 'tomcat9'
}

def is_valid_user_candidate(cand):
    if not cand or not isinstance(cand, str):
        return False
    c = cand.strip().strip('\'"[](){}<>,.;:!?')
    if len(c) < 2 or len(c) > 75:
        return False
    c_low = c.lower()
    if c_low in INVALID_USER_STOPWORDS:
        return False
    if c[0] in '-.=/\\:;,':
        return False
    if any(c_low.startswith(p) for p in ('com.', 'org.', 'java.', 'javax.', 'net.', 'sun.', 'entrust.', 'ora-', 'aud', 'bulkidentityguard', 'http:', 'https:')):
        return False
    if re.match(r'^520\d{4}$', c) or re.match(r'^\d{4}-\d{2}-\d{2}', c) or re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', c):
        return False
    if any(k in c_low for k in ('exception', 'repository', 'transactionqueue', 'blobaccess', 'authenticator', 'manager', 'handler', 'service', 'controller', 'factory', 'provider')):
        return False
    if not re.search(r'[A-Za-z0-9]', c):
        return False
    return True

def extract_valid_user(line, msg=''):
    text = msg if msg else line
    # 1. Prioritize explicit target user ("for user X", "User X failed/created/...", "username=X") over API actor bracket
    priority_patterns = [
        r'\bfor\s+user\s+[\'"]?([A-Za-z0-9_\-\.\/@]+)[\'"]?',
        r'(?:user\s+name\s+or\s+alias|user\s+name|username|userid|user_id|subjectName|subject|User)\s*(?:=|:)\s*[\'"]?([A-Za-z0-9_\-\.\/@]+)[\'"]?',
        r'(?:user\s+name\s+or\s+alias|user\s+name|username|userid|user_id|subjectName|subject)\s*(?:=|:|\bis\b)?\s*[\'"]([A-Za-z0-9_\-\.\/@]+)[\'"]',
        r'\bUser\s+([A-Za-z0-9_\-\.\/@]+)\s+(?:currently\s+has|has\s+a\s+grid|already\s+has|created|failed|logged|assigned|updated|authenticated|locked|disabled|deleted|modified|migrated)'
    ]
    for pat in priority_patterns:
        for m in re.finditer(pat, text, re.I):
            cand = m.group(1).strip().rstrip('.,;:!?)')
            if is_valid_user_candidate(cand):
                return cand
        if text is not line:
            for m in re.finditer(pat, line, re.I):
                cand = m.group(1).strip().rstrip('.,;:!?)')
                if is_valid_user_candidate(cand):
                    return cand

    # 2. Check [AUDxxx] [username] or [IG.AUDIT] [username]
    m_aud = re.search(r'\[(?:AUD\d+|IG\.AUDIT)\]\s*\[([^\]]+)\]', line)
    if m_aud:
        cand = m_aud.group(1).strip()
        if is_valid_user_candidate(cand):
            return cand

    # 3. Fallback general user mention
    fallback_patterns = [
        r'\b(?:for\s+user|user)\s+[\'"]([A-Za-z0-9_\-\.\/@]+)[\'"]',
        r'\buser\s+([A-Za-z0-9_\-\.\/@]+)'
    ]
    for pat in fallback_patterns:
        for m in re.finditer(pat, text, re.I):
            cand = m.group(1).strip().rstrip('.,;:!?)')
            if is_valid_user_candidate(cand):
                return cand
        if text is not line:
            for m in re.finditer(pat, line, re.I):
                cand = m.group(1).strip().rstrip('.,;:!?)')
                if is_valid_user_candidate(cand):
                    return cand

    return 'system'

TOMCAT_MONTHS = {
    'jan': '01', 'ene': '01', 'feb': '02', 'mar': '03',
    'apr': '04', 'abr': '04', 'may': '05', 'jun': '06',
    'jul': '07', 'aug': '08', 'ago': '08', 'sep': '09', 'sept': '09',
    'oct': '10', 'nov': '11', 'dec': '12', 'dic': '12'
}

_TOMCAT_BANNER_RE = re.compile(
    r'\b(?:Command line argument:|Server version:|Server built:|Server number:|'
    r'OS Name:|OS Version:|Architecture:|Java Home:|JVM Version:|JVM Vendor:|'
    r'CATALINA_BASE:|CATALINA_HOME:|VersionLoggerListener\.log|The Apache Tomcat Native library)\b',
    re.I
)

_TOMCAT_JULI_ONELINE_RE = re.compile(
    r'^(\d{1,2})-([A-Za-z]{3,4})-(\d{4})\s+(\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\s+(.*)$'
)
_TOMCAT_JULI_SIMPLE_RE = re.compile(
    r'^([A-Za-z]{3,4})\s+(\d{1,2}),\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s*(AM|PM|a\.\s*m\.|p\.\s*m\.))?\s+(.*)$',
    re.I
)
_TOMCAT_ISO_LINE_RE = re.compile(
    r'^(\d{4})[-/](\d{2})[-/](\d{2})[\sT](\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?\s+(.*)$'
)
_ENTRUST_SYSLOG_RE = re.compile(
    r'^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$'
)
_TOMCAT_SIMPLE_LEVEL_RE = re.compile(
    r'^(SEVERE|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST|GRAVE|ADVERTENCIA|INFORMACI[OÓ]N):\s*(.*)$'
)
_JAVA_STACK_PATTERNS = (
    re.compile(r'^\s+at\s+[A-Za-z0-9_$.<>\/]+\('),
    re.compile(r'^\s*Caused by:\s+'),
    re.compile(r'^\s*Suppressed:\s+'),
    re.compile(r'^\s*\.\.\.\s+\d+\s+(?:more|common frames omitted)\b'),
    re.compile(
        r'^\s*(?:java|javax|jakarta|sun|com\.sun|org\.apache|com\.entrust|oracle|com\.microsoft|org\.postgresql|org\.hibernate|org\.springframework|net\.sf)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b'
    ),
)

_AUD_FAIL_SET = {'AUD110', 'AUD125', 'AUD126', 'AUD127', 'AUD150', 'AUD153', 'AUD2309', 'AUD4005', 'AUD6002'}
_AUD_WARN_SET = {'AUD151', 'AUD154', 'AUD155', 'AUD6001'}

def is_tomcat_startup_banner(text):
    return bool(text and _TOMCAT_BANNER_RE.search(text))

def parse_tomcat_timestamp(line):
    if not line:
        return None, line, None
    m = _TOMCAT_JULI_ONELINE_RE.match(line)
    if m:
        mon = TOMCAT_MONTHS.get(m.group(2).lower())
        if mon:
            dd = m.group(1).zfill(2)
            return f"{m.group(3)}-{mon}-{dd} {m.group(4)}", m.group(5), 'juli_oneline'

    m = _TOMCAT_JULI_SIMPLE_RE.match(line)
    if m:
        mon = TOMCAT_MONTHS.get(m.group(1).lower())
        if mon:
            dd = m.group(2).zfill(2)
            yyyy = m.group(3)
            hh = int(m.group(4))
            ampm = (m.group(7) or '').lower().replace('.', '').replace(' ', '')
            if ampm == 'am' and hh == 12:
                hh = 0
            elif ampm == 'pm' and hh < 12:
                hh += 12
            return f"{yyyy}-{mon}-{dd} {hh:02d}:{m.group(5)}:{m.group(6)}", m.group(8), 'juli_simple'

    m = _TOMCAT_ISO_LINE_RE.match(line)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}", m.group(5), 'iso'

    m = _ENTRUST_SYSLOG_RE.match(line)
    if m:
        mon = TOMCAT_MONTHS.get(m.group(1).lower())
        if mon:
            dd = m.group(2).zfill(2)
            yr = time.strftime('%Y')
            return f"{yr}-{mon}-{dd} {m.group(3)}", m.group(5), 'syslog'

    return None, line, None

def is_java_stack_continuation(raw_line):
    if not raw_line:
        return False
    return any(p.match(raw_line) for p in _JAVA_STACK_PATTERNS)

def is_tomcat_simple_level_line(raw_line):
    if not raw_line:
        return None
    m = _TOMCAT_SIMPLE_LEVEL_RE.match(raw_line.strip())
    if not m:
        return None
    raw_lvl = m.group(1).upper()
    norm_map = {
        'GRAVE': 'SEVERE',
        'ADVERTENCIA': 'WARNING',
        'INFORMACION': 'INFO',
        'INFORMACIÓN': 'INFO'
    }
    return norm_map.get(raw_lvl, raw_lvl), m.group(2)

def extract_non_version_ip(text):
    if not text:
        return 'local'
    for m in re.finditer(r'(?<![.\d])((?:\d{1,3}\.){3}\d{1,3})(?![.\d])', text):
        ip = m.group(1)
        if ip in ('127.0.0.1', '0.0.0.0') or ip.startswith('255.'):
            continue
        parts = ip.split('.')
        if not all(0 <= int(p) <= 255 for p in parts):
            continue
        prefix = text[max(0, m.start() - 28):m.start()].lower()
        if re.search(r'(?:jdk|java|jre|tomcat|version|server number|built|release)\s*[:=\s/\-]*$', prefix):
            continue
        return ip
    return 'local'

_ENTRUST_NUM_BRACKET_RE = re.compile(r'\[(52\d{4,5}|5[013-9]\d{5})\]')
_ENTRUST_NUM_LABELED_RE = re.compile(
    r'(?:error\s*(?:code)?|err(?:or)?Code|faultCode|statusCode|rc|code)\s*[:=\[\(]\s*(5\d{5,6})\b',
    re.IGNORECASE
)
_ENTRUST_NUM_BARE_RE = re.compile(r'(?<!\d)(520\d{4})(?!\d)')
_USER_CONTEXT_PREFIX_RE = re.compile(
    r'(?:user(?:name|id|_id)?|alias|serial|card|phone|tel|cedula|account|session|target|uid|subject)\s*[:=#]?\s*[\'"]?$',
    re.IGNORECASE
)
_AUD_CODE_RE = re.compile(r'(?:\b|\[)(AUD\d{2,5})(?:\b|\])', re.IGNORECASE)
_ORA_CODE_RE = re.compile(r'\b(ORA-\d{4,5})\b', re.IGNORECASE)
_ENTRUST_BRACKET_FAIL_AUDS = _AUD_FAIL_SET | {'AUD154'}


def is_entrust_numeric_code(code):
    return bool(re.match(r'^5(?:2\d{4,5}|[013-9]\d{5})$', str(code or '').strip()))


def extract_entrust_numeric_code(text):
    if not text:
        return None
    m = _ENTRUST_NUM_BRACKET_RE.search(text)
    if m:
        return m.group(1)
    m = _ENTRUST_NUM_LABELED_RE.search(text)
    if m:
        return m.group(1)
    for m in _ENTRUST_NUM_BARE_RE.finditer(text):
        prefix = text[max(0, m.start() - 28):m.start()]
        if _USER_CONTEXT_PREFIX_RE.search(prefix):
            continue
        return m.group(1)
    return None


def classify_tomcat_java_event(text, base_level='INFO', has_stack=False):
    txt = text or ''
    low = txt.lower()
    base_u = (base_level or 'INFO').upper()
    if base_u == 'GRAVE':
        base_u = 'SEVERE'
    elif base_u == 'ADVERTENCIA':
        base_u = 'WARNING'

    c_ent = extract_entrust_numeric_code(txt)
    if c_ent:
        return (c_ent, 'FAIL', None)

    aud = _AUD_CODE_RE.search(txt)
    if aud:
        aud_code = aud.group(1).upper()
        if aud_code in _AUD_FAIL_SET or base_u in ('ERROR', 'SEVERE', 'FATAL', 'CRITICAL'):
            out = 'FAIL'
        elif aud_code in _AUD_WARN_SET or base_u in ('WARNING', 'WARN'):
            out = 'WARN'
        else:
            out = 'SUCCESS'
        return (aud_code, out, None)

    ora = _ORA_CODE_RE.search(txt)
    if ora:
        return (ora.group(1).upper(), 'FAIL', 'database')

    if re.search(r'(?:ClientAbortException|Broken pipe|Connection reset by peer)', txt, re.I):
        return ('TOMCAT_CLIENT_ABORT', 'INFO', None)

    if re.search(r'(?:OutOfMemoryError|Java heap space|GC overhead limit exceeded|Metaspace|PermGen space|unable to create new native thread)', txt, re.I):
        return ('JVM_OOM', 'FAIL', None)

    if re.search(r'(?:SSLHandshakeException|PKIX path building failed|SunCertPathBuilderException|CertificateExpiredException|CertificateNotYetValidException|KeyStoreException|UnrecoverableKeyException|SSLException|handshake_failure|bad_certificate|certificate_unknown|protocol_version)', txt, re.I):
        return ('TOMCAT_SSL_TLS', 'FAIL', None)

    if re.search(r'(?:SQLException|SQLRecoverableException|SQLTransientConnectionException|SQLNonTransientConnectionException|SQLTimeoutException|CannotGetJdbcConnectionException|HikariPool|BasicDataSource|PoolExhaustedException|CommunicationsException|JdbcCardRepository|BlobAccess|AuditDBLogger|No suitable driver)', txt, re.I):
        return ('JDBC_SQL_EXCEPTION', 'FAIL', 'database')

    if re.search(r'(?:LDAPException|javax\.naming\.CommunicationException|javax\.naming\.AuthenticationException|javax\.naming\.NamingException|PartialResultException|LDAP:\s*error code)', txt, re.I):
        return ('TOMCAT_LDAP_ERROR', 'FAIL', None)

    if re.search(r'(?:BindException|Address already in use|ConnectException|SocketTimeoutException|UnknownHostException|NoRouteToHostException|Port\s+\d+.*already in use)', txt, re.I):
        return ('TOMCAT_NETWORK_ERROR', 'FAIL', None)

    if re.search(r'(?:ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError|LifecycleException|Failed to start component|Error listenerStart|Error filterStart|startup failed)', txt, re.I):
        return ('TOMCAT_DEPLOY_ERROR', 'FAIL', None)

    if re.search(r'(?:StuckThreadDetectionValve|All threads .* are currently busy|maxThreads|RejectedExecutionException|failed to stop thread|memory leak)', txt, re.I):
        out = 'FAIL' if (base_u in ('SEVERE', 'FATAL', 'ERROR', 'CRITICAL') or 'rejectedexecutionexception' in low) else 'WARN'
        return ('TOMCAT_THREAD_POOL', out, None)

    is_err_level = base_u in ('SEVERE', 'FATAL', 'ERROR', 'CRITICAL')
    if (is_err_level or has_stack) and (
        re.search(r'\b[a-z][a-z0-9_.]*\.[A-Z][A-Za-z0-9_]*(?:Exception|Error|Throwable)\b', txt)
        or 'caused by:' in low
    ):
        return ('TOMCAT_JAVA_EXCEPTION', 'FAIL', None)

    if is_err_level:
        return ('TOMCAT_SEVERE', 'FAIL', None)

    if base_u in ('WARNING', 'WARN'):
        return ('TOMCAT_WARN', 'WARN', None)

    if re.search(r'(?:Server startup in|Starting ProtocolHandler|Starting Servlet Engine|Deploying web application|Deployment of web application|Stopping service|Destroying ProtocolHandler|Initialization processed in)', txt, re.I):
        return ('TOMCAT_LIFECYCLE', 'SUCCESS', None)

    return ('TOMCAT_INFO', 'SUCCESS', None)

def parse_line_meta_for_db(line, line_num, last_seen_ts=''):
    if not line:
        return None, {}

    meta = {
        'has_explicit_ts': False,
        'is_tomcat_simple_hdr': False,
        'is_tomcat': False,
        'base_level': 'INFO',
        'locked_code': False
    }

    # 1. Check IDaaS Cloud Migration Tool format: [ERROR] IdentityGuard migration: ...
    if 'IdentityGuard migration:' in line:
        outcome = 'FAIL' if any(k in line for k in ['[ERROR]', 'error', 'fail', 'already']) else 'SUCCESS'
        time_match = re.search(r'\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
        if time_match:
            event_time = time_match.group(0)
            meta['has_explicit_ts'] = True
        else:
            event_time = last_seen_ts or ''

        user = extract_valid_user(line)

        if 'grid already assigned' in line.lower() or 'assignedgrid' in line.lower():
            event_type = 'bulkidentityguard.add.error.assignedgrid'
        elif 'currently has a password' in line.lower() or 'password will not be migrated' in line.lower():
            event_type = 'bulkidentityguard.add.error.password'
        elif 'already has qa' in line.lower() or 'qa in migration file' in line.lower():
            event_type = 'bulkidentityguard.add.error.qa'
        else:
            event_type = 'IDG_MIGRATION_EVENT'

        return (line_num, event_time, user, event_type, outcome, line[:300], 'idaas.entrust.com', line[:500]), meta

    # 1.5. Check IDaaS Cloud CSV / TSV format (strictly validated to avoid matching stack traces or SQL lines)
    if (',' in line or '\t' in line) and not line.startswith('[') and not line.startswith('\t') and not line.startswith('Caused by:'):
        parts = line.split('\t') if '\t' in line else [p.strip().strip('"') for p in line.split(',')]
        if len(parts) >= 8 and parts[0].lower() != 'id':
            col1_is_date = bool(re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}T', parts[1].strip())) if len(parts) > 1 else False
            col8_upper = parts[8].strip().upper() if len(parts) > 8 else ''
            col8_is_outcome = col8_upper in ('SUCCESS', 'FAIL', 'FAILURE', 'ERROR', 'WARNING', 'INFO')
            if col1_is_date and col8_is_outcome:
                event_time = parts[1].replace('T', ' ').replace('Z', '')[:19] if len(parts) > 1 else ''
                meta['has_explicit_ts'] = bool(event_time)
                raw_user = parts[4].strip() if len(parts) > 4 else ''
                user = raw_user if is_valid_user_candidate(raw_user) else 'system'
                event_type = parts[7].strip() if len(parts) > 7 and parts[7].strip() else 'IDaaS.Audit'
                outcome = 'FAIL' if col8_upper in ('FAIL', 'FAILURE', 'ERROR') else 'SUCCESS'
                msg = parts[9].strip() if len(parts) > 9 else event_type
                ip = parts[12].strip() if len(parts) > 12 else ''
                return (line_num, event_time, user, event_type, outcome, msg, ip, line[:500]), meta

    # 2. Check Entrust Bracket format: [timestamp] [thread] [LEVEL] [Category] [520xxx/AUD] Message
    bracket_match = re.match(r'^\[+([^\]]+)\]\s*\[([^\]]*)\]\s*\[([A-Za-z]+)\s*\]\s*\[([^\]]*)\]\s*(.*)$', line)
    if bracket_match:
        event_time = re.sub(r'^(\d{4})[/.](\d{2})[/.](\d{2})', r'\1-\2-\3', bracket_match.group(1)[:19])
        meta['has_explicit_ts'] = bool(re.match(r'^\d{4}[-/.]\d{2}[-/.]\d{2}', event_time))
        level = bracket_match.group(3).upper()
        meta['base_level'] = level
        category = bracket_match.group(4)
        msg = bracket_match.group(5)
        outcome = 'FAIL' if any(k in level for k in ['ERR', 'CRIT', 'FATAL', 'SEVERE']) else ('DEBUG' if level == 'DEBUG' else ('WARN' if 'WARN' in level else 'SUCCESS'))

        c520 = extract_entrust_numeric_code(msg) or extract_entrust_numeric_code(line)
        aud = _AUD_CODE_RE.search(msg) or _AUD_CODE_RE.search(line)
        ora = _ORA_CODE_RE.search(msg) or _ORA_CODE_RE.search(line)

        if c520 or ora or (aud and aud.group(1).upper() in _ENTRUST_BRACKET_FAIL_AUDS):
            outcome = 'FAIL'
        elif aud and aud.group(1).upper() in ('AUD6001', 'AUD2309', 'AUD155', 'AUD151') and outcome != 'FAIL':
            outcome = 'WARN'

        if c520:
            event_type = c520
            meta['locked_code'] = True
        elif aud:
            event_type = aud.group(1).upper()
            meta['locked_code'] = True
        elif ora:
            event_type = ora.group(1).upper()
            meta['locked_code'] = True
        elif category:
            event_type = category.split('.')[-2] if '.' in category else category
        else:
            event_type = 'ENTRUST_LOG'

        user = extract_valid_user(line, msg) if not is_tomcat_startup_banner(line) else 'system'
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
        ip = ip_match.group(0) if ip_match else 'local'

        return (line_num, event_time, user, event_type, outcome, msg, ip, line[:1200]), meta

    # 2.5 Check Entrust Linux Syslog + Apache Tomcat JULI / Catalina formats
    ts, rest, fmt = parse_tomcat_timestamp(line)
    if ts:
        meta['has_explicit_ts'] = True
        if fmt == 'syslog' and (rest.startswith('[') or '520' in rest or 'AUD' in rest or bool(extract_entrust_numeric_code(rest))):
            meta['is_tomcat'] = True
            lvl_m = re.search(r'\[(ERROR|FATAL|SEVERE|CRIT|CRITICAL|WARN|WARNING|INFO|DEBUG)\s*\]', rest, re.I)
            base_level = lvl_m.group(1).upper() if lvl_m else ('ERROR' if 'FAILED' in rest or '[520' in rest or extract_entrust_numeric_code(rest) else 'INFO')
            meta['base_level'] = base_level
            event_type, outcome, ip_ov = classify_tomcat_java_event(line, base_level)
            meta['locked_code'] = is_entrust_numeric_code(event_type) or event_type.startswith('AUD') or event_type.startswith('ORA-')
            msg = rest[:600]
            user = 'system' if is_tomcat_startup_banner(line) else extract_valid_user(line, msg)
            ip = ip_ov or extract_non_version_ip(msg)
            return (line_num, ts, user, event_type, outcome, msg, ip, line[:1200]), meta

        is_iso_tomcat_java = (
            fmt == 'iso'
            and (
                re.search(r'\b(?:SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|GRAVE|ADVERTENCIA)\b', rest)
                or re.search(r'(?:catalina|org\.apache|com\.entrust|Exception|Error|Server startup|Starting ProtocolHandler|HikariPool|ORA-\d{4,5}|5\d{5,6}|AUD\d{2,5})', line)
            )
        )
        if fmt in ('juli_oneline', 'juli_simple') or is_iso_tomcat_java:
            meta['is_tomcat'] = True
            base_level = 'INFO'
            msg = rest
            if fmt == 'juli_oneline':
                m_one = re.match(r'^([A-ZÁÉÍÓÚÑ]+)\s+\[([^\]]*)\]\s+(.*)$', rest)
                if m_one:
                    base_level = m_one.group(1).upper()
                    msg = f"[{m_one.group(2)}] {m_one.group(3)}"
                else:
                    m_lvl = re.match(r'^(SEVERE|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST|GRAVE|ADVERTENCIA)\s+(.*)$', rest, re.I)
                    if m_lvl:
                        base_level = m_lvl.group(1).upper()
                        msg = m_lvl.group(2)
            elif fmt == 'juli_simple':
                meta['is_tomcat_simple_hdr'] = True
                m_lvl = re.search(r'\b(SEVERE|FATAL|ERROR|WARNING|WARN|GRAVE|ADVERTENCIA)\b', rest)
                if m_lvl:
                    base_level = m_lvl.group(1).upper()
            else:
                m_lvl = re.match(r'^[\[\s]*(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|GRAVE|ADVERTENCIA)[\]\s:]+(.*)$', rest, re.I)
                if m_lvl:
                    base_level = m_lvl.group(1).upper()
                    msg = m_lvl.group(2)
                else:
                    m_lvl2 = re.search(r'\b(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG)\b', rest)
                    if m_lvl2:
                        base_level = m_lvl2.group(1).upper()

            meta['base_level'] = base_level
            event_type, outcome, ip_ov = classify_tomcat_java_event(line, base_level)
            meta['locked_code'] = is_entrust_numeric_code(event_type) or event_type.startswith('AUD') or event_type.startswith('ORA-')
            user = 'system' if is_tomcat_startup_banner(line) else extract_valid_user(line, msg)
            ip = ip_ov or extract_non_version_ip(msg)
            return (line_num, ts, user, event_type, outcome, msg[:600], ip, line[:1200]), meta

    # 3. Orphan Java / Oracle exception or stack trace line (no timestamp in line)
    if is_java_stack_continuation(line) or re.search(r'\b(ORA-\d{4,5}|SQLException|OutOfMemoryError|SSLHandshakeException|Exception|Error)\b', line):
        base_lvl = 'INFO' if re.search(r'(?:ClientAbortException|Broken pipe|Connection reset by peer)', line, re.I) else 'ERROR'
        event_type, outcome, ip_ov = classify_tomcat_java_event(line, base_lvl, has_stack=True)
        meta['locked_code'] = is_entrust_numeric_code(event_type) or event_type.startswith('AUD') or event_type.startswith('ORA-')
        user = 'system' if is_tomcat_startup_banner(line) else extract_valid_user(line)
        ip = ip_ov or extract_non_version_ip(line)
        return (line_num, last_seen_ts or '', user, event_type, outcome, line.strip()[:600], ip, line[:1200]), meta

    # 4. Fallback generic line — NEVER omit Entrust/ORA/AUD/SSH error codes in unstructured lines
    low_line = line.lower()
    if any(k in low_line for k in ['error', 'fail', 'crit', 'fatal', 'exception', 'severe']):
        level = 'FAIL'
    elif any(k in low_line for k in ['warn', 'warning']):
        level = 'WARN'
    else:
        level = 'SUCCESS'
    event_time = ts or last_seen_ts or ''
    if ts:
        meta['has_explicit_ts'] = True
    user = 'system' if is_tomcat_startup_banner(line) else extract_valid_user(line)
    ip = extract_non_version_ip(line)

    fb_event_type = 'SYSTEM_LOG'
    c_fb = extract_entrust_numeric_code(line)
    ora_fb = _ORA_CODE_RE.search(line)
    aud_fb = _AUD_CODE_RE.search(line)
    if c_fb:
        fb_event_type = c_fb
        level = 'FAIL'
        meta['locked_code'] = True
    elif ora_fb:
        fb_event_type = ora_fb.group(1).upper()
        level = 'FAIL'
        if ip == 'local':
            ip = 'database'
        meta['locked_code'] = True
    elif aud_fb:
        fb_event_type = aud_fb.group(1).upper()
        meta['locked_code'] = True
        if fb_event_type in _AUD_FAIL_SET:
            level = 'FAIL'
        elif fb_event_type in _AUD_WARN_SET and level != 'FAIL':
            level = 'WARN'
    elif re.search(r'\b(?:sshd|pam_unix|failed password|accepted publickey|accepted password)\b', low_line):
        if level == 'FAIL' or 'failed' in low_line or 'invalid user' in low_line:
            fb_event_type = 'SSH-FAIL'
            level = 'FAIL'
        else:
            fb_event_type = 'SSH-AUTH'

    return (line_num, event_time, user, fb_event_type, level, line[:300], ip, line[:1200]), meta

def parse_line_for_db(line, line_num, last_seen_ts=''):
    parsed, _ = parse_line_meta_for_db(line, line_num, last_seen_ts=last_seen_ts)
    return parsed

def stream_lines_from_archive_or_file(file_path):
    """
    Seamless streaming generator yielding lines from plain text, .gz, .zip, .tar.gz, .tgz, or .bz2
    without generating huge decompressed files on disk.
    """
    lower = file_path.lower()
    if lower.endswith('.gz') and not (lower.endswith('.tar.gz') or lower.endswith('.tgz')):
        with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line
    elif lower.endswith('.bz2'):
        with bz2.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line
    elif lower.endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as z:
            for filename in z.namelist():
                if filename.endswith('/') or filename.startswith('__MACOSX') or filename.startswith('.'):
                    continue
                with z.open(filename, 'r') as zf:
                    with io.TextIOWrapper(zf, encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            yield line
    elif lower.endswith('.tar.gz') or lower.endswith('.tgz') or lower.endswith('.tar'):
        with tarfile.open(file_path, 'r:*') as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        with io.TextIOWrapper(f, encoding='utf-8', errors='ignore') as tf:
                            for line in tf:
                                yield line
    else:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line

def index_batch_in_background(file_paths, client_name='Entrust Client', force_reindex=True):
    global upload_state
    total_files = len(file_paths)
    for idx, fp in enumerate(file_paths):
        append_mode = (idx > 0) or (not force_reindex)
        index_file_in_background(fp, client_name=client_name, append_mode=append_mode)
        if upload_state.get('status') == 'error':
            break
    if upload_state.get('status') != 'error':
        upload_state['fileName'] = f"Lote completo ({total_files} archivo(s))"
        upload_state['status'] = 'ready'
        upload_state['progress'] = 100


def compute_exact_sqlite_distinct_counts(cur):
    """Computes exact 100% distinct valid users, event codes, and source IPs across all rows in SQLite."""
    cur.execute("SELECT DISTINCT subject_name FROM logs WHERE subject_name IS NOT NULL AND subject_name != '' AND subject_name != 'system' AND subject_name != 'unknown'")
    unique_users = sum(1 for (u,) in cur.fetchall() if is_valid_user_candidate(u))
    cur.execute("SELECT COUNT(DISTINCT event_type) FROM logs WHERE event_type IS NOT NULL AND event_type != ''")
    unique_codes = int((cur.fetchone() or [0])[0] or 0)
    cur.execute("SELECT COUNT(DISTINCT source_ip) FROM logs WHERE source_ip IS NOT NULL AND source_ip != '' AND source_ip != 'local'")
    unique_ips = int((cur.fetchone() or [0])[0] or 0)
    return unique_users, unique_codes, unique_ips


def aggregate_sqlite_users(cur, q_filter='', outcome_filter='all'):
    """Aggregates 100% of valid nominal users directly from indexed SQLite logs without artificial truncation."""
    q_low = (q_filter or '').strip().lower()
    flt = (outcome_filter or 'all').strip().lower()
    matched_set = None

    if q_low:
        like_q = f'%{q_low}%'
        cur.execute('''
            SELECT DISTINCT subject_name
            FROM logs
            WHERE subject_name IS NOT NULL AND subject_name != '' AND subject_name != 'system' AND subject_name != 'unknown'
              AND (LOWER(subject_name) LIKE ? OR LOWER(event_type) LIKE ?)
        ''', (like_q, like_q))
        matched_set = {r[0].strip() for r in cur.fetchall() if r[0] and is_valid_user_candidate(r[0].strip())}
        if not matched_set:
            return []

    if matched_set is not None and len(matched_set) <= 400:
        placeholders = ','.join(['?'] * len(matched_set))
        cur.execute(f'''
            SELECT subject_name, event_type, event_outcome, COUNT(1) as cnt,
                   MIN(event_time) as first_t, MAX(event_time) as last_t, MAX(source_ip) as sample_ip
            FROM logs
            WHERE subject_name IN ({placeholders})
            GROUP BY subject_name, event_type, event_outcome
        ''', list(matched_set))
    else:
        cur.execute('''
            SELECT subject_name, event_type, event_outcome, COUNT(1) as cnt,
                   MIN(event_time) as first_t, MAX(event_time) as last_t, MAX(source_ip) as sample_ip
            FROM logs
            WHERE subject_name IS NOT NULL AND subject_name != '' AND subject_name != 'system' AND subject_name != 'unknown'
            GROUP BY subject_name, event_type, event_outcome
        ''')

    users_map = {}
    lock_re = re.compile(r'5205079|5205080|5201053|5203016|5202002|AUD007|AUD6002', re.IGNORECASE)

    for subj, etype, outcome, cnt, first_t, last_t, sample_ip in cur.fetchall():
        subj_str = (subj or '').strip()
        if not subj_str or not is_valid_user_candidate(subj_str):
            continue
        if matched_set is not None and subj_str not in matched_set:
            continue

        code = (etype or 'SYSTEM_LOG').strip()
        out_str = (outcome or 'SUCCESS').upper()
        is_err = ('FAIL' in out_str) or ('ERR' in out_str)

        if subj_str not in users_map:
            users_map[subj_str] = {
                'user': subj_str,
                'total': 0,
                'errors': 0,
                'success': 0,
                'isLocked': False,
                'firstSeen': first_t or '',
                'lastSeen': last_t or '',
                'ips': set(),
                'codes': {}
            }
        u_entry = users_map[subj_str]
        u_entry['total'] += cnt
        if is_err:
            u_entry['errors'] += cnt
        else:
            u_entry['success'] += cnt
        if lock_re.search(code):
            u_entry['isLocked'] = True
        if first_t and (not u_entry['firstSeen'] or first_t < u_entry['firstSeen']):
            u_entry['firstSeen'] = first_t
        if last_t and (not u_entry['lastSeen'] or last_t > u_entry['lastSeen']):
            u_entry['lastSeen'] = last_t
        if sample_ip and sample_ip not in ('local', ''):
            u_entry['ips'].add(sample_ip)

        if code not in u_entry['codes']:
            u_entry['codes'][code] = {'total': 0, 'errors': 0, 'success': 0}
        u_entry['codes'][code]['total'] += cnt
        if is_err:
            u_entry['codes'][code]['errors'] += cnt
        else:
            u_entry['codes'][code]['success'] += cnt

    result = list(users_map.values())
    if flt == 'errors':
        result = [u for u in result if u['errors'] > 0 or u['isLocked']]
    elif flt == 'success':
        result = [u for u in result if u['errors'] == 0 and not u['isLocked']]

    result.sort(
        key=lambda u: (1 if u['isLocked'] else 0, 1 if u['errors'] > 0 else 0, u['errors'], u['total']),
        reverse=True
    )
    return result


def _norm_srv_tag(s):
    return re.sub(r'^(?:🖥️\s*|☁️\s*)', '', str(s or '').strip()).strip().lower()

def _ensure_loaded_file_ranges(cur, loaded_files, fill_dates=False):
    """Ensures every entry in loaded_files has fileId, startLine, endLine and optional dateSpan."""
    if not isinstance(loaded_files, list) or len(loaded_files) == 0:
        return False
    changed = False
    for idx, f in enumerate(loaded_files):
        if isinstance(f, dict) and not f.get('fileId'):
            f['fileId'] = f"legacy_{idx + 1}"
            changed = True

    needs_ranges = any(
        isinstance(f, dict) and (
            'startLine' not in f or 'endLine' not in f
            or f.get('startLine') is None or f.get('endLine') is None
        )
        for f in loaded_files
    )
    if needs_ranges:
        cur.execute('SELECT COALESCE(MAX(line_num), 0) FROM logs')
        max_line = int((cur.fetchone() or [0])[0] or 0)
        total_listed = sum(int(f.get('count', 0) or 0) for f in loaded_files if isinstance(f, dict))
        cursor_line = max(0, max_line - total_listed) if (total_listed > 0 and total_listed < max_line) else 0
        for f in loaded_files:
            if not isinstance(f, dict):
                continue
            cnt = int(f.get('count', 0) or 0)
            f['startLine'] = cursor_line + 1
            f['endLine'] = (cursor_line + cnt) if cnt > 0 else cursor_line
            cursor_line += cnt
            changed = True

    if fill_dates:
        for f in loaded_files:
            if not isinstance(f, dict):
                continue
            if (not f.get('dateSpan') or not f.get('firstTs')) and not f.get('_dateProbed'):
                sl = int(f.get('startLine') or 0)
                el = int(f.get('endLine') or 0)
                if sl > 0 and el >= sl:
                    cur.execute(
                        "SELECT event_time FROM logs WHERE line_num BETWEEN ? AND ? "
                        "AND event_time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*' "
                        "ORDER BY line_num ASC LIMIT 1",
                        (sl, el),
                    )
                    rmin = cur.fetchone()
                    cur.execute(
                        "SELECT event_time FROM logs WHERE line_num BETWEEN ? AND ? "
                        "AND event_time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*' "
                        "ORDER BY line_num DESC LIMIT 1",
                        (sl, el),
                    )
                    rmax = cur.fetchone()
                    if rmin and rmin[0]:
                        t1 = str(rmin[0])
                        t2 = str(rmax[0]) if (rmax and rmax[0]) else t1
                        d1 = t1[:10]
                        d2 = t2[:10]
                        f['firstTs'] = t1
                        f['lastTs'] = t2
                        f['dateSpan'] = d1 if d1 == d2 else f"{d1} → {d2}"
                f['_dateProbed'] = True
                changed = True
    return changed

def recompute_sqlite_stats_obj(cur, target_db, client_name, loaded_files):
    """Recomputes 100% exact cached statistics across all surviving SQLite rows."""
    cur.execute('SELECT COUNT(1) FROM logs')
    total_all = int((cur.fetchone() or [0])[0] or 0)

    cur.execute("SELECT COUNT(1) FROM logs WHERE UPPER(event_outcome) LIKE '%FAIL%' OR UPPER(event_outcome) LIKE '%ERR%'")
    errors_all = int((cur.fetchone() or [0])[0] or 0)

    cur.execute(
        "SELECT COUNT(1) FROM logs WHERE NOT (UPPER(event_outcome) LIKE '%FAIL%' OR UPPER(event_outcome) LIKE '%ERR%') "
        "AND (UPPER(event_outcome) LIKE '%WARN%' OR UPPER(event_type) LIKE 'AUD%')"
    )
    warnings_all = int((cur.fetchone() or [0])[0] or 0)

    exact_unique_users, exact_unique_codes, exact_unique_ips = compute_exact_sqlite_distinct_counts(cur)

    cur.execute(
        "SELECT event_type, COUNT(1) FROM logs WHERE event_type IS NOT NULL AND event_type != '' "
        "GROUP BY event_type ORDER BY COUNT(1) DESC LIMIT 1000"
    )
    event_types_list = [{'code': r[0], 'count': int(r[1] or 0)} for r in cur.fetchall()]
    top_codes_list = list(event_types_list)

    cur.execute(
        "SELECT source_ip, COUNT(1) FROM logs WHERE source_ip IS NOT NULL AND source_ip != '' "
        "AND source_ip != 'local' AND source_ip != '127.0.0.1' "
        "GROUP BY source_ip ORDER BY COUNT(1) DESC LIMIT 150"
    )
    top_ips_list = [{'ip': r[0], 'count': int(r[1] or 0)} for r in cur.fetchall()]

    cur.execute(
        "SELECT SUBSTR(event_time, 1, 13) AS hb, COUNT(1) AS tot, "
        "SUM(CASE WHEN UPPER(event_outcome) LIKE '%FAIL%' OR UPPER(event_outcome) LIKE '%ERR%' THEN 1 ELSE 0 END) AS errs, "
        "SUM(CASE WHEN UPPER(event_outcome) NOT LIKE '%FAIL%' AND UPPER(event_outcome) NOT LIKE '%ERR%' THEN 1 ELSE 0 END) AS inf "
        "FROM logs "
        "WHERE event_time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*' AND LENGTH(event_time) >= 13 "
        "GROUP BY hb ORDER BY hb ASC LIMIT 2000"
    )
    timeline_buckets_list = [
        {'bucket': r[0], 'total': int(r[1] or 0), 'errors': int(r[2] or 0), 'info': int(r[3] or 0)}
        for r in cur.fetchall() if r[0]
    ]

    cur.execute(
        "SELECT subject_name, COUNT(1) FROM logs "
        "WHERE subject_name IS NOT NULL AND subject_name != '' AND subject_name != 'system' AND subject_name != 'unknown' "
        "GROUP BY subject_name ORDER BY COUNT(1) DESC LIMIT 300"
    )
    top_users_list = [
        {'user': r[0], 'count': int(r[1] or 0)}
        for r in cur.fetchall() if r[0] and is_valid_user_candidate(r[0])
    ][:200]

    cur.execute("SELECT 1 FROM logs WHERE LOWER(event_type) LIKE '%bulkidentityguard%' LIMIT 1")
    is_idaas = cur.fetchone() is not None

    prev_raw_total = sum(int(f.get('rawLinesRead', f.get('count', 0)) or 0) for f in (loaded_files or []))
    prev_folded_total = sum(int(f.get('foldedStackLines', 0) or 0) for f in (loaded_files or []))

    return {
        'status': 'ready',
        'totalLogs': total_all,
        'rawLinesRead': prev_raw_total or total_all,
        'foldedStackLines': prev_folded_total,
        'totalErrors': errors_all,
        'totalWarnings': warnings_all,
        'totalSuccess': max(0, total_all - errors_all),
        'totalUniqueCodes': exact_unique_codes or len(top_codes_list),
        'totalUniqueUsers': exact_unique_users,
        'totalUniqueIps': exact_unique_ips or len(top_ips_list),
        'eventTypes': event_types_list,
        'topCodes': top_codes_list,
        'topUsers': top_users_list,
        'topIps': top_ips_list,
        'timelineBuckets': timeline_buckets_list,
        'detectedPlatform': 'Entrust IDaaS Cloud' if is_idaas else 'Entrust IdentityGuard OnPremise',
        'activeDb': os.path.basename(target_db),
        'client': client_name,
        'loadedFiles': loaded_files or []
    }


def index_file_in_background(file_path, client_name='Entrust Client', append_mode=False, server_tag=''):
    global upload_state, ACTIVE_DB_PATH
    client_slug = get_client_slug(client_name)
    db_name = f"{client_slug}_audit.db"
    target_db = os.path.join(DATA_DIR, db_name)

    upload_state['clientName'] = client_name
    upload_state['clientSlug'] = client_slug
    upload_state['fileName'] = os.path.basename(file_path)
    upload_state['status'] = 'indexing'
    upload_state['progress'] = 0
    upload_state['linesProcessed'] = 0
    upload_state['totalErrors'] = 0
    upload_state['error'] = None

    try:
        if not append_mode:
            purge_db_files(target_db)

        init_db(target_db)

        file_size = os.path.getsize(file_path)
        upload_state['fileSize'] = file_size

        import collections
        user_counts = collections.Counter()
        ip_counts = collections.Counter()
        code_counts = collections.Counter()
        type_counts = collections.Counter()
        hour_counts = collections.defaultdict(lambda: {'total': 0, 'errors': 0, 'info': 0})
        is_idaas = False

        line_num = 0
        file_start_line = 1
        prev_total = 0
        prev_errors = 0
        prev_warnings = 0
        existing_files = []

        if append_mode:
            try:
                conn_prev = sqlite3.connect(target_db, timeout=30.0)
                cur_prev = conn_prev.cursor()
                cur_prev.execute('SELECT COALESCE(MAX(line_num), 0) FROM logs')
                line_num = int(cur_prev.fetchone()[0] or 0)
                file_start_line = line_num + 1
                cur_prev.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_stats'")
                if cur_prev.fetchone():
                    cur_prev.execute("SELECT value FROM server_stats WHERE key='stats_json'")
                    row_prev = cur_prev.fetchone()
                    if row_prev and row_prev[0]:
                        existing_stats = json.loads(row_prev[0]) or {}
                        prev_total = int(existing_stats.get('totalLogs', line_num) or 0)
                        prev_errors = int(existing_stats.get('totalErrors', 0) or 0)
                        prev_warnings = int(existing_stats.get('totalWarnings', 0) or 0)
                        existing_files = list(existing_stats.get('loadedFiles') or [])
                        if 'idaas' in str(existing_stats.get('detectedPlatform', '')).lower():
                            is_idaas = True
                        for item in (existing_stats.get('topUsers') or []):
                            if item.get('user'):
                                user_counts[item['user']] += int(item.get('count', 0) or 0)
                        for item in (existing_stats.get('topIps') or []):
                            if item.get('ip'):
                                ip_counts[item['ip']] += int(item.get('count', 0) or 0)
                        for item in (existing_stats.get('topCodes') or []):
                            if item.get('code'):
                                code_counts[item['code']] += int(item.get('count', 0) or 0)
                        for item in (existing_stats.get('eventTypes') or []):
                            if item.get('code'):
                                type_counts[item['code']] += int(item.get('count', 0) or 0)
                        for b in (existing_stats.get('timelineBuckets') or []):
                            bk = b.get('bucket')
                            if bk:
                                hour_counts[bk]['total'] += int(b.get('total', 0) or 0)
                                hour_counts[bk]['errors'] += int(b.get('errors', 0) or 0)
                                hour_counts[bk]['info'] += int(b.get('info', 0) or 0)
                conn_prev.close()
            except Exception as merge_err:
                print(f"Aviso leyendo stats previos para merge: {merge_err}")

        conn = sqlite3.connect(target_db, timeout=30.0)
        cur = conn.cursor()
        cur.execute('PRAGMA synchronous = OFF;')
        cur.execute('PRAGMA journal_mode = WAL;')

        batch = []
        batch_size = 25000
        file_lines = 0
        file_errors = 0
        file_warnings = 0
        raw_lines_read = 0
        folded_stack_lines = 0
        bytes_est = 0
        last_seen_ts = ''
        file_min_ts = ''
        file_max_ts = ''
        pending = None

        def flush_pending():
            nonlocal batch, file_lines, file_errors, file_warnings, pending, file_min_ts, file_max_ts
            if pending is None:
                return

            msg_out = pending['message'] or ''
            raw_out = pending['raw'] or ''
            etype = pending['event_type']
            outcome = pending['outcome']
            ip = pending['ip']

            if pending['stack_frames'] > 0 or pending['causes']:
                combined_txt = msg_out + ' ' + ' '.join(pending['causes'])
                new_etype, new_out, new_ip = classify_tomcat_java_event(
                    combined_txt, pending['base_level'], has_stack=True
                )
                ora_cause = _ORA_CODE_RE.search(' '.join(pending['causes']))
                ent_cause = extract_entrust_numeric_code(' '.join(pending['causes']))

                if pending['locked_code']:
                    # Preserve explicit 5xxxxx / AUDxxx in header unless cause brings a more specific ORA-xxxxx
                    if ora_cause:
                        etype = ora_cause.group(1).upper()
                        outcome = 'FAIL'
                        ip = 'database'
                else:
                    etype = new_etype
                    outcome = new_out
                    if new_ip:
                        ip = new_ip
                    if ent_cause and not is_entrust_numeric_code(etype) and not ora_cause:
                        etype = ent_cause
                        outcome = 'FAIL'

                parts_extra = []
                if pending['causes']:
                    deepest = re.sub(r'^Caused by:\s*', '', pending['causes'][-1], flags=re.I).strip()
                    parts_extra.append(f"Root Cause: {deepest}")
                if pending['entrust_frame']:
                    parts_extra.append(f"Frame: {pending['entrust_frame']}")
                if parts_extra:
                    extra_str = ' | ' + ' | '.join(parts_extra)
                    if len(msg_out) + len(extra_str) > 600:
                        keep_len = max(180, 596 - len(extra_str))
                        msg_out = msg_out[:keep_len].rstrip() + '…' + extra_str
                    else:
                        msg_out = msg_out + extra_str
                msg_out = msg_out[:600]

                if pending['stack_frames'] > 0:
                    suffix = f"\n[+{pending['stack_frames']} stack frames]"
                    raw_out = raw_out[:max(200, 1800 - len(suffix))] + suffix
                raw_out = raw_out[:1800]

            parsed_row = (
                pending['line_num'],
                pending['event_time'],
                pending['user'],
                etype,
                outcome,
                msg_out,
                ip,
                raw_out
            )
            pending = None

            file_lines += 1
            out_u = str(outcome or '').upper()
            etype_u = str(etype or '').upper()
            is_err = 'FAIL' in out_u or 'ERR' in out_u
            is_warn = (not is_err) and ('WARN' in out_u or etype_u.startswith('AUD'))
            if is_err:
                file_errors += 1
            elif is_warn:
                file_warnings += 1

            user = parsed_row[2]
            if user and user not in ['unknown', 'system', '']:
                user_counts[user] += 1

            if ip and ip not in ['local', '127.0.0.1', '']:
                ip_counts[ip] += 1

            if etype:
                type_counts[etype] += 1
                code_counts[etype] += 1
                if 'bulkidentityguard' in etype.lower():
                    is_idaas = True

            t_str = parsed_row[1]
            if t_str and len(t_str) >= 13 and re.match(r'^\d{4}-\d{2}-\d{2}', t_str):
                if not file_min_ts or t_str < file_min_ts:
                    file_min_ts = t_str
                if not file_max_ts or t_str > file_max_ts:
                    file_max_ts = t_str
                h_bucket = t_str[:13]
                hour_counts[h_bucket]['total'] += 1
                if is_err:
                    hour_counts[h_bucket]['errors'] += 1
                else:
                    hour_counts[h_bucket]['info'] += 1

            batch.append(parsed_row)

            if len(batch) >= batch_size:
                cur.executemany('INSERT OR REPLACE INTO logs VALUES (?,?,?,?,?,?,?,?)', batch)
                conn.commit()
                batch = []
                upload_state['linesProcessed'] = prev_total + file_lines
                upload_state['totalErrors'] = prev_errors + file_errors
                upload_state['progress'] = min(99, int((bytes_est / max(1, file_size)) * 100))

        for raw_line in stream_lines_from_archive_or_file(file_path):
            raw_no_nl = raw_line.rstrip('\r\n')
            line_str = raw_no_nl.strip()
            if not line_str:
                continue
            raw_lines_read += 1
            bytes_est += len(raw_line)

            if pending is not None and pending['is_tomcat_simple_hdr']:
                lvl_pair = is_tomcat_simple_level_line(raw_no_nl)
                if lvl_pair:
                    lvl, lvl_msg = lvl_pair
                    pending['base_level'] = lvl
                    pending['is_tomcat_simple_hdr'] = False
                    merged_msg = f"{pending['message']} — {lvl}: {lvl_msg}".strip()
                    pending['message'] = merged_msg[:600]
                    if len(pending['raw']) < 1600:
                        pending['raw'] = (pending['raw'] + '\n' + line_str)[:1600]
                    if not pending['locked_code']:
                        ev_t, ev_o, ev_ip = classify_tomcat_java_event(merged_msg, lvl)
                        pending['event_type'] = ev_t
                        pending['outcome'] = ev_o
                        pending['locked_code'] = is_entrust_numeric_code(ev_t) or ev_t.startswith('AUD') or ev_t.startswith('ORA-')
                        if ev_ip:
                            pending['ip'] = ev_ip
                    folded_stack_lines += 1
                    continue

            if pending is not None and is_java_stack_continuation(raw_no_nl):
                folded_stack_lines += 1
                pending['stack_frames'] += 1
                if (
                    line_str.startswith('Caused by:')
                    or line_str.startswith('Suppressed:')
                    or re.match(r'^(?:java|javax|jakarta|oracle|org\.apache|com\.entrust)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b', line_str)
                    or bool(extract_entrust_numeric_code(line_str))
                    or bool(_ORA_CODE_RE.search(line_str))
                    or bool(_AUD_CODE_RE.search(line_str))
                ):
                    if len(pending['causes']) < 10:
                        pending['causes'].append(line_str[:220])
                if not pending['entrust_frame'] and 'com.entrust.' in line_str:
                    pending['entrust_frame'] = line_str.lstrip('at ').strip()[:140]
                if len(pending['raw']) < 1550:
                    pending['raw'] = (pending['raw'] + '\n' + line_str)[:1600]
                continue

            flush_pending()

            line_num += 1
            parsed, meta = parse_line_meta_for_db(line_str, line_num, last_seen_ts=last_seen_ts)
            if parsed:
                if meta.get('has_explicit_ts') and parsed[1]:
                    last_seen_ts = parsed[1]
                pending = {
                    'line_num': parsed[0],
                    'event_time': parsed[1],
                    'user': parsed[2],
                    'event_type': parsed[3],
                    'outcome': parsed[4],
                    'message': parsed[5],
                    'ip': parsed[6],
                    'raw': parsed[7],
                    'base_level': meta.get('base_level', 'INFO'),
                    'is_tomcat_simple_hdr': meta.get('is_tomcat_simple_hdr', False),
                    'is_tomcat': meta.get('is_tomcat', False),
                    'locked_code': meta.get('locked_code', False),
                    'stack_frames': 0,
                    'causes': [],
                    'entrust_frame': ''
                }

        flush_pending()

        if batch:
            cur.executemany('INSERT OR REPLACE INTO logs VALUES (?,?,?,?,?,?,?,?)', batch)
            conn.commit()

        total_all = prev_total + file_lines
        errors_all = prev_errors + file_errors
        warnings_all = prev_warnings + file_warnings

        clean_tag = (server_tag or '').strip() or 'Servidor Core SQLite'
        clean_tag_plain = re.sub(r'^[^\w\.\-]+', '', clean_tag).strip() or clean_tag
        node_key = 'srv_' + re.sub(r'[^a-z0-9]+', '_', clean_tag_plain.lower()).strip('_')
        node_name = clean_tag if clean_tag.startswith('🖥️') else f'🖥️ {clean_tag_plain}'

        date_span = ''
        if file_min_ts and file_max_ts:
            d1 = file_min_ts[:10]
            d2 = file_max_ts[:10]
            date_span = d1 if d1 == d2 else f"{d1} → {d2}"

        file_entry = {
            'fileId': f"{int(time.time() * 1000)}_{len(existing_files) + 1}",
            'name': os.path.basename(file_path),
            'size': file_size,
            'count': file_lines,
            'startLine': file_start_line,
            'endLine': line_num if file_lines > 0 else (file_start_line - 1),
            'sampleCount': file_lines,
            'rawLinesRead': raw_lines_read,
            'foldedStackLines': folded_stack_lines,
            'realErrors': file_errors,
            'realWarnings': file_warnings,
            'firstTs': file_min_ts,
            'lastTs': file_max_ts,
            'dateSpan': date_span,
            'nodeKey': node_key,
            'nodeName': node_name,
            'serverTag': clean_tag_plain,
            'client': client_name
        }
        if existing_files:
            _ensure_loaded_file_ranges(cur, existing_files, fill_dates=False)
        loaded_files = list(existing_files) + [file_entry]

        if append_mode:
            stats_obj = recompute_sqlite_stats_obj(cur, target_db, client_name, loaded_files)
            total_all = stats_obj['totalLogs']
            errors_all = stats_obj['totalErrors']
        else:
            exact_unique_users, exact_unique_codes, exact_unique_ips = compute_exact_sqlite_distinct_counts(cur)
            prev_raw_total = sum(int(f.get('rawLinesRead', f.get('count', 0)) or 0) for f in loaded_files)
            prev_folded_total = sum(int(f.get('foldedStackLines', 0) or 0) for f in loaded_files)
            event_types_list = [{'code': k, 'count': v} for k, v in type_counts.most_common(1000)]
            top_codes_list = [{'code': k, 'count': v} for k, v in code_counts.most_common(1000)]
            top_users_list = [
                {'user': k, 'count': v}
                for k, v in user_counts.most_common(300) if is_valid_user_candidate(k)
            ][:200]
            top_ips_list = [{'ip': k, 'count': v} for k, v in ip_counts.most_common(150)]
            timeline_buckets_list = [
                {'bucket': k, 'total': v['total'], 'errors': v['errors'], 'info': v['info']}
                for k, v in sorted(hour_counts.items())[:2000]
            ]
            stats_obj = {
                'status': 'ready',
                'totalLogs': total_all,
                'rawLinesRead': prev_raw_total or raw_lines_read,
                'foldedStackLines': prev_folded_total,
                'totalErrors': errors_all,
                'totalWarnings': warnings_all,
                'totalSuccess': max(0, total_all - errors_all),
                'totalUniqueCodes': exact_unique_codes or len(code_counts),
                'totalUniqueUsers': exact_unique_users,
                'totalUniqueIps': exact_unique_ips or len(ip_counts),
                'eventTypes': event_types_list,
                'topCodes': top_codes_list,
                'topUsers': top_users_list,
                'topIps': top_ips_list,
                'timelineBuckets': timeline_buckets_list,
                'detectedPlatform': 'Entrust IDaaS Cloud' if is_idaas else 'Entrust IdentityGuard OnPremise',
                'activeDb': os.path.basename(target_db),
                'client': client_name,
                'loadedFiles': loaded_files
            }
        cur.execute('CREATE TABLE IF NOT EXISTS server_stats (key TEXT PRIMARY KEY, value TEXT)')
        cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('stats_json', json.dumps(stats_obj, ensure_ascii=False)))
        cur.execute("DELETE FROM server_stats WHERE key IN ('forensic_matrix_v2', 'forensic_matrix_v3', 'forensic_matrix_v4', 'forensic_matrix_v5')")
        conn.commit()
        conn.close()

        ACTIVE_DB_PATH = target_db
        save_active_session(target_db, client_name)
        upload_state['dbPath'] = target_db
        upload_state['status'] = 'ready'
        upload_state['progress'] = 100
        upload_state['linesProcessed'] = total_all
        upload_state['totalErrors'] = errors_all
        print(f"Indexación completada: {total_all:,} registros ({file_lines:,} en archivo, {folded_stack_lines:,} líneas trace plegadas), {errors_all:,} errores en {target_db}")
    except Exception as e:
        upload_state['status'] = 'error'
        upload_state['error'] = str(e)
        print(f"Error indexando archivo: {e}")

class DiagnosticRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Hardening: Hide Python & SimpleHTTP version banner from scanners (Banner Grabbing prevention)
    server_version = 'ITServicios-EntrustSuite/2.6'
    sys_version = ''
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        '.pdf': 'application/pdf',
        '.htm': 'text/html; charset=utf-8',
        '.html': 'text/html; charset=utf-8',
    }

    BLOCKED_EXTENSIONS = ('.php', '.php3', '.php4', '.php5', '.phtml', '.phar', '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.pl', '.sh', '.py', '.pyc', '.db', '.sqlite', '.sqlite3', '.env', '.git', '.htaccess', '.htpasswd', '.ini', '.bak', '.sql')
    BLOCKED_PATHS = ('/.git', '/.env', '/data/', '/scripts/', '/server.py', '/sync.sh', '/wp-admin', '/wp-login', '/wp-content', '/phpmyadmin', '/cgi-bin', '/vendor/phpunit', '/etc/passwd', '/proc/self')
    ALLOWED_UPLOAD_EXTS = ('.log', '.out', '.txt', '.csv', '.tsv', '.json', '.xml', '.properties', '.conf', '.pem', '.crt', '.cer', '.dat', '.zip', '.gz', '.tgz', '.bz2', '.tar', '.html', '.htm', '.md', '.pdf', '.db', '.1', '.2', '.3', '.4', '.5')

    def list_directory(self, path):
        # Security Hardening: Disable directory listing completely (CWE-548)
        self.send_error(403, 'Directory listing is forbidden by IT SERVICIOS Security Policy')
        return None

    def is_malicious_request(self, raw_path):
        unquoted = urllib.parse.unquote(raw_path or '').lower()
        if '..' in unquoted or '\x00' in unquoted or '%00' in raw_path.lower():
            return True
        # Block PHP CGI argument injection (CVE-2024-4577 / CVE-2012-1823) and scanner probes
        if any(p in unquoted for p in self.BLOCKED_PATHS):
            return True
        path_only = unquoted.split('?')[0]
        if path_only.endswith(self.BLOCKED_EXTENSIONS):
            return True
        return False

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Access-Control-Allow-Origin', '*')
        # HTTP Security Headers (Hardening & OWASP / ISO 27001 / SUDEBAN Compliance)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('X-Permitted-Cross-Domain-Policies', 'none')
        super().end_headers()

    def do_OPTIONS(self):
        if self.is_malicious_request(self.path):
            self.send_error(403, 'Forbidden by IT SERVICIOS Security Policy')
            return
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_POST(self):
        if self.is_malicious_request(self.path):
            self.send_error(403, 'Forbidden: Blocked executable or probe request')
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == '/api/upload-chunk':
            self.handle_upload_chunk()
        elif path == '/api/ingest-local':
            self.handle_ingest_local()
        elif path == '/api/ingest-batch':
            self.handle_ingest_batch()
        elif path == '/api/clients':
            self.handle_save_clients()
        elif path == '/api/engineers':
            self.handle_save_engineers()
        elif path == '/api/client-config':
            self.handle_save_client_config()
        elif path == '/api/notes':
            self.handle_save_note()
        elif path == '/api/notes/delete':
            self.handle_delete_note()
        elif path == '/api/upload-manual':
            self.handle_upload_manual()
        elif path == '/api/custom-manuals/delete':
            self.handle_delete_custom_manual()
        elif path == '/api/custom-manuals/set-version':
            self.handle_set_custom_manual_version()
        elif path == '/api/pcap-upload':
            self.handle_pcap_upload()
        elif path == '/api/pcap-analyze-server-file':
            self.handle_pcap_analyze_server_file()
        elif path == '/api/session-files/delete':
            self.handle_delete_session_files()
        elif path == '/api/session-files/reassign':
            self.handle_reassign_session_files()
        elif path == '/api/clear-session':
            post_query = urllib.parse.parse_qs(parsed_url.query)
            client_param = post_query.get('client', [None])[0]
            try:
                content_length = int(self.headers.get('Content-Length', 0) or 0)
            except Exception:
                content_length = 0
            if content_length > 0 and content_length < 65536:
                try:
                    raw_body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                    if raw_body.strip():
                        body_json = json.loads(raw_body)
                        if isinstance(body_json, dict) and body_json.get('client'):
                            client_param = client_param or str(body_json.get('client')).strip()
                except Exception:
                    pass
            res = clear_active_session(client_param=client_param, purge_db=True)
            self.send_json({
                'success': True,
                'activeDb': None,
                'purgedFiles': res.get('purgedFiles', []),
                'client': client_param
            })
        else:
            self.send_error(404, 'Endpoint not found')

    def do_GET(self):
        if self.is_malicious_request(self.path):
            self.send_error(403, 'Forbidden: Blocked executable or probe request')
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == '/api/logs':
            self.handle_api_logs(query)
        elif path == '/api/stats':
            self.handle_api_stats(query)
        elif path == '/api/clear-session':
            client_param = query.get('client', [None])[0]
            res = clear_active_session(client_param=client_param, purge_db=True)
            self.send_json({
                'success': True,
                'activeDb': None,
                'purgedFiles': res.get('purgedFiles', []),
                'client': client_param
            })
        elif path == '/api/clients':
            self.handle_get_clients()
        elif path == '/api/engineers':
            self.handle_get_engineers()
        elif path == '/api/version':
            self.handle_get_version()
        elif path == '/api/upload-status':
            self.send_json(upload_state)
        elif path == '/api/list-server-files':
            self.handle_list_server_files()
        elif path == '/api/activate-db':
            self.handle_activate_db(query)
        elif path == '/api/export-errors':
            self.handle_export_errors(query)
        elif path == '/api/forensic-matrix':
            self.handle_forensic_matrix(query)
        elif path == '/api/user-pattern-detail':
            self.handle_user_pattern_detail(query)
        elif path == '/api/users-search':
            self.handle_api_users_search(query)
        elif path == '/api/users-export':
            self.handle_api_users_export(query)
        elif path == '/api/manuals-search':
            self.handle_manuals_search(query)
        elif path == '/api/client-config':
            self.handle_get_client_config(query)
        elif path == '/api/notes':
            self.handle_get_notes(query)
        elif path == '/api/custom-manuals':
            self.handle_list_custom_manuals(query)
        elif path == '/api/custom-codes':
            self.handle_get_custom_codes()
        elif path == '/api/pcap-status':
            self.send_json(pcap_upload_state)
        elif path == '/api/pcap-summary':
            self.handle_pcap_summary(query)
        elif path == '/api/pcap-packets':
            self.handle_pcap_packets(query)
        elif path == '/api/pcap-correlate':
            self.handle_pcap_correlate(query)
        elif path == '/api/pcap-export-csv':
            self.handle_pcap_export_csv(query)
        elif path == '/api/manuals-status':
            if not MANUALS_INDEX_BUILT and not MANUALS_INDEX_BUILDING:
                threading.Thread(target=build_manuals_index, daemon=True).start()
            custom_files = list(_iter_custom_manual_files())
            custom_versions = sorted({dv for _, _, _, _, dv in custom_files}, key=lambda v: CUSTOM_VERSION_ORDER.index(v) if v in CUSTOM_VERSION_ORDER else 99)
            custom_pages = sum(1 for d in MANUALS_INDEX if str(d.get('path') or '').startswith('manuals/custom/'))
            self.send_json({
                'ready': MANUALS_INDEX_BUILT,
                'building': MANUALS_INDEX_BUILDING,
                'indexedPages': len(MANUALS_INDEX),
                'customFilesCount': len(custom_files),
                'customPagesCount': custom_pages,
                'customVersions': custom_versions
            })
        else:
            super().do_GET()

    def handle_get_client_config(self, query):
        cfg_file = os.path.join(DATA_DIR, 'client_configs.json')
        client_id = (query.get('clientId', [''])[0] or '').strip()
        configs = {}
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file, 'r', encoding='utf-8') as f:
                    configs = json.load(f) or {}
            except Exception:
                configs = {}
        if client_id:
            self.send_json({'clientId': client_id, 'config': configs.get(client_id, None)})
        else:
            self.send_json({'configs': configs})

    def handle_save_client_config(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length > 0 else b'{}'
            payload = json.loads(raw.decode('utf-8'))
            client_id = str(payload.get('clientId') or '').strip()
            config_data = payload.get('config')
            if not client_id or not isinstance(config_data, dict):
                self.send_json({'error': 'clientId y config requeridos'}, status=400)
                return
            cfg_file = os.path.join(DATA_DIR, 'client_configs.json')
            configs = {}
            if os.path.exists(cfg_file):
                try:
                    with open(cfg_file, 'r', encoding='utf-8') as f:
                        configs = json.load(f) or {}
                except Exception:
                    configs = {}
            configs[client_id] = config_data
            with open(cfg_file, 'w', encoding='utf-8') as f:
                json.dump(configs, f, ensure_ascii=False, indent=2)
            self.send_json({'success': True, 'clientId': client_id, 'config': config_data})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_upload_manual(self):
        max_bytes = 60 * 1024 * 1024
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
            if length <= 0:
                self.send_json({'error': 'Archivo vacío o Content-Length faltante'}, status=400)
                return
            if length > max_bytes:
                self.send_json({'error': f'El archivo supera el límite máximo de {max_bytes // (1024 * 1024)} MB.'}, status=413)
                return

            raw = self.rfile.read(length)
            ctype = (self.headers.get('Content-Type') or '').split(';')[0].strip().lower()
            is_binary_upload = ctype in ('application/pdf', 'application/octet-stream')
            defer_reindex = str(self.headers.get('X-Defer-Reindex') or '').strip().lower() in ('1', 'true', 'yes')
            raw_ver = ''

            if is_binary_upload:
                raw_fname = urllib.parse.unquote(self.headers.get('X-File-Name') or '').strip()
                raw_ver = urllib.parse.unquote(self.headers.get('X-Manual-Version') or '').strip()
                filename = os.path.basename(raw_fname)
                raw_bytes = raw
            else:
                payload = json.loads(raw.decode('utf-8'))
                filename = os.path.basename(str(payload.get('filename') or '').strip())
                raw_ver = str(payload.get('version') or '').strip()
                if not defer_reindex:
                    defer_reindex = bool(payload.get('deferReindex'))
                encoding_mode = str(payload.get('encoding') or '').strip().lower()
                content = str(payload.get('content') or '')
                if encoding_mode == 'base64':
                    raw_bytes = base64.b64decode(content)
                else:
                    raw_bytes = content.encode('utf-8')

            if not filename or not raw_bytes:
                self.send_json({'error': 'filename y contenido son requeridos'}, status=400)
                return

            ext = os.path.splitext(filename)[1].lower()
            if ext not in ('.pdf', '.html', '.htm', '.md', '.txt'):
                self.send_json({'error': 'Formato no soportado. Permitidos: .pdf, .html, .htm, .md, .txt'}, status=400)
                return

            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', filename).lstrip('.')
            if not safe_name or safe_name == ext or not safe_name.lower().endswith(ext):
                safe_name = f"manual_{int(time.time())}{ext}"

            doc_version = _normalize_doc_version(raw_ver, fallback_filename=safe_name)
            ver_slug = CUSTOM_VERSION_SLUGS.get(doc_version, 'general')
            rel_subpath = f"{ver_slug}/{safe_name}"
            rel_path = f"manuals/custom/{rel_subpath}"

            custom_dir = _custom_manuals_dir()
            ver_dir = os.path.join(custom_dir, ver_slug)
            os.makedirs(ver_dir, exist_ok=True)
            target_path = os.path.join(ver_dir, safe_name)

            if ext == '.pdf':
                if pdf_extractor is None or not pdf_extractor.is_valid_pdf_bytes(raw_bytes):
                    self.send_json({'error': 'El archivo .pdf no tiene una cabecera PDF válida (%PDF-).'}, status=400)
                    return

                _atomic_write_bytes(target_path, raw_bytes)
                ext_res = pdf_extractor.extract_pdf_text(target_path)
                if not ext_res.get('ok'):
                    try:
                        os.remove(target_path)
                    except Exception:
                        pass
                    self.send_json({'error': ext_res.get('error') or 'Error analizando el archivo PDF.'}, status=400)
                    return

                pages = ext_res.get('pages') or []
                codes = pdf_extractor.extract_entrust_codes_from_pages(pages, safe_name, rel_path)
                for c_val in codes.values():
                    if isinstance(c_val, dict):
                        c_val['docVersion'] = doc_version
                try:
                    fsize = os.path.getsize(target_path)
                    fmtime = int(os.path.getmtime(target_path))
                except Exception:
                    fsize, fmtime = len(raw_bytes), int(time.time())

                sidecar = {
                    'filename': safe_name,
                    'relSubpath': rel_subpath,
                    'path': rel_path,
                    'version': doc_version,
                    'fileSize': fsize,
                    'fileMtime': fmtime,
                    'ok': True,
                    'engine': ext_res.get('engine') or 'stdlib-pdf',
                    'pageCount': int(ext_res.get('pageCount') or len(pages) or 0),
                    'totalChars': int(ext_res.get('totalChars') or 0),
                    'isScannedOrEmpty': bool(ext_res.get('isScannedOrEmpty')),
                    'isEncrypted': bool(ext_res.get('isEncrypted')),
                    'warning': str(ext_res.get('warning') or ''),
                    'pages': pages,
                    'codes': codes
                }
                _, write_sc_path = _sidecar_path_for(rel_subpath, legacy_fname=safe_name)
                _atomic_write_json(write_sc_path, sidecar)

                meta = _load_custom_metadata()
                meta[rel_subpath] = {'version': doc_version, 'uploadedAt': datetime.datetime.utcnow().isoformat() + 'Z'}
                _save_custom_metadata(meta)

                if not defer_reindex:
                    refresh_custom_manuals_index()

                sample_codes = list(codes.keys())[:15]
                self.send_json({
                    'success': True,
                    'path': rel_path,
                    'relSubpath': rel_subpath,
                    'filename': safe_name,
                    'version': doc_version,
                    'versionSlug': ver_slug,
                    'isPdf': True,
                    'size': fsize,
                    'engine': sidecar['engine'],
                    'pageCount': sidecar['pageCount'],
                    'totalChars': sidecar['totalChars'],
                    'isScannedOrEmpty': sidecar['isScannedOrEmpty'],
                    'isEncrypted': sidecar['isEncrypted'],
                    'warning': sidecar['warning'],
                    'extractedCodesCount': len(codes),
                    'extractedCodesSample': sample_codes
                })
                return

            _atomic_write_bytes(target_path, raw_bytes)
            sidecar, _ = _build_text_doc_sidecar_and_index(
                target_path, safe_name, rel_subpath=rel_subpath, doc_version=doc_version, force_rebuild=True
            )
            meta = _load_custom_metadata()
            meta[rel_subpath] = {'version': doc_version, 'uploadedAt': datetime.datetime.utcnow().isoformat() + 'Z'}
            _save_custom_metadata(meta)
            if not defer_reindex:
                refresh_custom_manuals_index()
            codes = sidecar.get('codes') or {}
            sample_codes = list(codes.keys())[:15]
            self.send_json({
                'success': True,
                'path': rel_path,
                'relSubpath': rel_subpath,
                'filename': safe_name,
                'version': doc_version,
                'versionSlug': ver_slug,
                'isPdf': False,
                'size': os.path.getsize(target_path),
                'engine': sidecar.get('engine') or 'html-parser',
                'sectionCount': int(sidecar.get('sectionCount') or 1),
                'totalChars': int(sidecar.get('totalChars') or 0),
                'extractedCodesCount': len(codes),
                'extractedCodesSample': sample_codes
            })
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_list_custom_manuals(self, query=None):
        items = []
        versions_summary = {}
        force_reindex = bool(query and str(query.get('reindex', ['0'])[0]).lower() in ('1', 'true', 'yes'))
        need_index_refresh = force_reindex
        for fpath, fname, rel_subpath, rel_path, doc_version in _iter_custom_manual_files():
            fl = fname.lower()
            is_pdf = fl.endswith('.pdf')
            versions_summary[doc_version] = versions_summary.get(doc_version, 0) + 1
            entry = {
                'filename': fname,
                'relSubpath': rel_subpath,
                'path': rel_path,
                'version': doc_version,
                'size': os.path.getsize(fpath),
                'isPdf': is_pdf
            }
            if is_pdf:
                read_sc_path, _ = _sidecar_path_for(rel_subpath, legacy_fname=fname)
                if os.path.isfile(read_sc_path):
                    try:
                        with open(read_sc_path, 'r', encoding='utf-8') as f:
                            sc = json.load(f) or {}
                        entry.update({
                            'pageCount': int(sc.get('pageCount') or 0),
                            'totalChars': int(sc.get('totalChars') or 0),
                            'extractedCodesCount': len(sc.get('codes') or {}),
                            'isScannedOrEmpty': bool(sc.get('isScannedOrEmpty')),
                            'engine': sc.get('engine') or 'stdlib-pdf',
                            'warning': sc.get('warning') or ''
                        })
                    except Exception:
                        pass
            elif fl.endswith(('.html', '.htm', '.md', '.txt')):
                read_sc_path, _ = _sidecar_path_for(rel_subpath, legacy_fname=fname)
                sc = None
                try:
                    fsize = os.path.getsize(fpath)
                    fmtime = int(os.path.getmtime(fpath))
                except Exception:
                    fsize, fmtime = 0, 0
                if os.path.isfile(read_sc_path):
                    try:
                        with open(read_sc_path, 'r', encoding='utf-8') as f:
                            cached = json.load(f) or {}
                        if (
                            isinstance(cached, dict)
                            and cached.get('extractorVersion') == 2
                            and cached.get('fileSize') == fsize
                            and cached.get('fileMtime') == fmtime
                        ):
                            sc = cached
                    except Exception:
                        sc = None
                if sc is None:
                    sc, _ = _build_text_doc_sidecar_and_index(
                        fpath, fname, rel_subpath=rel_subpath, doc_version=doc_version
                    )
                    need_index_refresh = True
                if isinstance(sc, dict):
                    entry.update({
                        'sectionCount': int(sc.get('sectionCount') or len(sc.get('pages') or []) or 1),
                        'totalChars': int(sc.get('totalChars') or 0),
                        'extractedCodesCount': len(sc.get('codes') or {}),
                        'engine': sc.get('engine') or 'html-parser'
                    })
            items.append(entry)
        if need_index_refresh:
            try:
                refresh_custom_manuals_index()
            except Exception:
                pass
        self.send_json({'manuals': items, 'versionsSummary': versions_summary})

    def _resolve_custom_manual_target(self, payload):
        custom_root = os.path.realpath(_custom_manuals_dir())

        def check_sub(sub_cand):
            s = str(sub_cand or '').strip().replace('\\', '/')
            if not s or '\x00' in s or '..' in s:
                return None
            if s.lower().startswith('manuals/custom/'):
                s = s[len('manuals/custom/'):]
            s = s.lstrip('/')
            if not s or s.startswith('.') or ':' in s:
                return None
            parts = [p for p in s.split('/') if p]
            if not parts or any(p.startswith('.') for p in parts):
                return None
            target = os.path.realpath(os.path.join(custom_root, *parts))
            if not (target.startswith(custom_root + os.sep) and os.path.isfile(target)):
                return None
            return target, '/'.join(parts), parts[-1]

        for key in ('path', 'relSubpath'):
            if payload.get(key):
                res = check_sub(payload.get(key))
                if res:
                    return res

        raw_name = str(payload.get('filename') or '').strip()
        if raw_name and '..' not in raw_name and '/' not in raw_name and '\\' not in raw_name:
            safe_base = os.path.basename(raw_name)
            direct = check_sub(safe_base)
            if direct:
                return direct
            for fpath, fname, rel_subpath, _, _ in _iter_custom_manual_files():
                if fname == safe_base:
                    return os.path.realpath(fpath), rel_subpath, fname
        return None

    def handle_delete_custom_manual(self):
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length) if length > 0 else b'{}'
            payload = json.loads(raw.decode('utf-8'))
            resolved = self._resolve_custom_manual_target(payload)
            if not resolved:
                self.send_json({'error': 'Documento personalizado no encontrado'}, status=404)
                return

            target_path, rel_subpath, safe_base = resolved
            os.remove(target_path)

            read_sc_path, write_sc_path = _sidecar_path_for(rel_subpath, legacy_fname=safe_base)
            for sc_p in {read_sc_path, write_sc_path}:
                if sc_p and os.path.isfile(sc_p):
                    try:
                        os.remove(sc_p)
                    except Exception:
                        pass

            # Remove empty version subdirectory if left empty
            custom_root = os.path.realpath(_custom_manuals_dir())
            parent_dir = os.path.dirname(target_path)
            if parent_dir != custom_root and os.path.isdir(parent_dir) and not os.listdir(parent_dir):
                try:
                    os.rmdir(parent_dir)
                except Exception:
                    pass

            meta = _load_custom_metadata()
            if rel_subpath in meta:
                meta.pop(rel_subpath, None)
                _save_custom_metadata(meta)

            refresh_custom_manuals_index()
            self.send_json({'success': True, 'filename': safe_base, 'relSubpath': rel_subpath})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_set_custom_manual_version(self):
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length) if length > 0 else b'{}'
            payload = json.loads(raw.decode('utf-8'))
            resolved = self._resolve_custom_manual_target(payload)
            if not resolved:
                self.send_json({'error': 'Documento personalizado no encontrado'}, status=404)
                return

            old_target, old_rel_subpath, fname = resolved
            new_version = _normalize_doc_version(payload.get('version'), fallback_filename=fname)
            new_slug = CUSTOM_VERSION_SLUGS.get(new_version, 'general')
            new_rel_subpath = f"{new_slug}/{fname}"
            old_rel_path = f"manuals/custom/{old_rel_subpath}"
            new_rel_path = f"manuals/custom/{new_rel_subpath}"

            custom_dir = _custom_manuals_dir()
            new_dir = os.path.join(custom_dir, new_slug)
            os.makedirs(new_dir, exist_ok=True)
            new_target = os.path.realpath(os.path.join(new_dir, fname))

            if new_target != old_target:
                if os.path.exists(new_target):
                    self.send_json({'error': f'Ya existe otro archivo "{fname}" en {new_version}.'}, status=409)
                    return
                os.replace(old_target, new_target)
                custom_root = os.path.realpath(custom_dir)
                old_parent = os.path.dirname(old_target)
                if old_parent != custom_root and os.path.isdir(old_parent) and not os.listdir(old_parent):
                    try:
                        os.rmdir(old_parent)
                    except Exception:
                        pass

            old_sc_read, old_sc_write = _sidecar_path_for(old_rel_subpath, legacy_fname=fname)
            _, new_sc_write = _sidecar_path_for(new_rel_subpath, legacy_fname=fname)
            if os.path.isfile(old_sc_read):
                try:
                    with open(old_sc_read, 'r', encoding='utf-8') as f:
                        sc = json.load(f) or {}
                    sc['version'] = new_version
                    sc['relSubpath'] = new_rel_subpath
                    sc['path'] = new_rel_path
                    for c_val in (sc.get('codes') or {}).values():
                        if isinstance(c_val, dict):
                            c_val['docVersion'] = new_version
                            if fname.lower().endswith('.pdf'):
                                pg = c_val.get('page') or 1
                                c_val['manualFile'] = f"{new_rel_path}#page={pg}"
                            else:
                                anc = str(c_val.get('anchor') or '').strip()
                                if not anc and '#' in str(c_val.get('manualFile') or ''):
                                    anc = str(c_val['manualFile']).split('#', 1)[1]
                                c_val['manualFile'] = f"{new_rel_path}#{anc}" if anc else new_rel_path
                    _atomic_write_json(new_sc_write, sc)
                    for sc_old in {old_sc_read, old_sc_write}:
                        if sc_old != new_sc_write and os.path.isfile(sc_old):
                            try:
                                os.remove(sc_old)
                            except Exception:
                                pass
                except Exception:
                    pass

            meta = _load_custom_metadata()
            meta.pop(old_rel_subpath, None)
            meta[new_rel_subpath] = {'version': new_version, 'updatedAt': datetime.datetime.utcnow().isoformat() + 'Z'}
            _save_custom_metadata(meta)

            refresh_custom_manuals_index()
            self.send_json({
                'success': True,
                'oldPath': old_rel_path,
                'path': new_rel_path,
                'relSubpath': new_rel_subpath,
                'filename': fname,
                'version': new_version
            })
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_get_custom_codes(self):
        codes_path = _custom_pdf_codes_path()
        has_any_custom = any(True for _ in _iter_custom_manual_files())
        data = None
        if os.path.isfile(codes_path):
            try:
                with open(codes_path, 'r', encoding='utf-8') as f:
                    parsed = json.load(f) or {}
                if isinstance(parsed, dict) and 'codesByVersion' in parsed and int(parsed.get('extractorVersion') or 0) >= 2:
                    data = parsed
            except Exception:
                data = None

        if data is None:
            if has_any_custom:
                _, payload = _scan_custom_manuals_and_rebuild_codes()
                self.send_json(payload)
                return
            self.send_json({
                'updatedAt': None,
                'totalCodes': 0,
                'totalEntries': 0,
                'filesCount': 0,
                'versionsCount': {},
                'codes': {},
                'codesByVersion': {},
                'entries': []
            })
            return

        self.send_json({
            'updatedAt': data.get('updatedAt'),
            'totalCodes': int(data.get('totalCodes') or len(data.get('codes') or {})),
            'totalEntries': int(data.get('totalEntries') or len(data.get('entries') or [])),
            'filesCount': int(data.get('filesCount') or 0),
            'versionsCount': data.get('versionsCount') or {},
            'codes': data.get('codes') or {},
            'codesByVersion': data.get('codesByVersion') or {},
            'entries': data.get('entries') or []
        })

    def _load_notes_file(self):
        notes_file = os.path.join(DATA_DIR, 'technical_notes.json')
        if not os.path.exists(notes_file):
            return []
        try:
            with open(notes_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_notes_file(self, notes):
        notes_file = os.path.join(DATA_DIR, 'technical_notes.json')
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(notes_file, 'w', encoding='utf-8') as f:
            json.dump(notes, f, ensure_ascii=False, indent=2)

    def handle_get_notes(self, query):
        notes = self._load_notes_file()
        q = (query.get('q', [''])[0] or '').strip().lower()
        tag = (query.get('tag', [''])[0] or '').strip().lower()
        client_id = (query.get('clientId', [''])[0] or '').strip()

        if client_id:
            notes = [n for n in notes if n.get('clientId') in ('', 'global', None, client_id)]
        if tag:
            notes = [n for n in notes if any(tag in str(t).lower() for t in (n.get('tags') or []))]
        if q:
            notes = [
                n for n in notes
                if q in str(n.get('title', '')).lower()
                or q in str(n.get('content', '')).lower()
                or any(q in str(t).lower() for t in (n.get('tags') or []))
            ]
        self.send_json({'notes': notes})

    def handle_save_note(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length > 0 else b'{}'
            payload = json.loads(raw.decode('utf-8'))
            note = payload.get('note') if isinstance(payload.get('note'), dict) else payload
            if not isinstance(note, dict) or not str(note.get('title') or '').strip():
                self.send_json({'error': 'Título de la nota requerido'}, status=400)
                return

            notes = self._load_notes_file()
            now_iso = datetime.datetime.utcnow().isoformat() + 'Z'
            note_id = str(note.get('id') or '').strip() or f"nt_{int(time.time() * 1000)}"
            tags = note.get('tags') or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',') if t.strip()]

            clean_note = {
                'id': note_id,
                'title': str(note.get('title', '')).strip(),
                'category': str(note.get('category', 'Nota Técnica')).strip() or 'Nota Técnica',
                'tags': [str(t).strip() for t in tags if str(t).strip()],
                'platform': str(note.get('platform', 'Todas')).strip() or 'Todas',
                'clientId': str(note.get('clientId', 'global')).strip() or 'global',
                'clientName': str(note.get('clientName', 'Global (Todos los Clientes)')).strip(),
                'content': str(note.get('content', '')).strip(),
                'author': str(note.get('author', 'Especialista')).strip() or 'Especialista',
                'createdAt': str(note.get('createdAt') or now_iso),
                'updatedAt': now_iso,
            }

            idx = next((i for i, item in enumerate(notes) if item.get('id') == note_id), -1)
            if idx >= 0:
                notes[idx] = clean_note
            else:
                notes.insert(0, clean_note)

            self._save_notes_file(notes)
            self.send_json({'success': True, 'note': clean_note, 'notes': notes})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)


    def handle_delete_note(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length > 0 else b'{}'
            payload = json.loads(raw.decode('utf-8'))
            note_id = str(payload.get('id') or '').strip()
            if not note_id:
                self.send_json({'error': 'id requerido'}, status=400)
                return
            notes = [n for n in self._load_notes_file() if n.get('id') != note_id]
            self._save_notes_file(notes)
            self.send_json({'success': True, 'notes': notes})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)


    def handle_manuals_search(self, query):
        q = query.get('q', [''])[0]
        version = query.get('version', [None])[0]
        prefer_version = query.get('preferVersion', [None])[0]
        include_general = str(query.get('includeGeneral', ['0'])[0]).strip().lower() in ('1', 'true', 'yes')
        try:
            limit = min(15, max(1, int(query.get('limit', ['6'])[0])))
        except Exception:
            limit = 6
        results = search_manuals(
            q,
            version_filter=version,
            limit=limit,
            prefer_version=prefer_version,
            include_general=include_general
        )
        self.send_json({
            'query': q,
            'totalIndexedPages': len(MANUALS_INDEX),
            'results': results
        })

    def handle_activate_db(self, query):
        global ACTIVE_DB_PATH
        target_db = query.get('db', [None])[0]
        client_name = query.get('client', ['Banco Mercantil C.A.'])[0]
        if not target_db:
            self.send_json({'error': 'Parámetro db requerido'}, status=400)
            return

        # Path traversal protection: restrict DB activation strictly to DATA_DIR or BASE_DIR
        safe_db_name = os.path.basename(target_db)
        if not safe_db_name.endswith('.db'):
            self.send_json({'error': 'Solo se permiten archivos de base de datos (.db) válidos'}, status=403)
            return

        full_path = os.path.abspath(os.path.join(DATA_DIR, safe_db_name))
        if not os.path.exists(full_path):
            alt_path = os.path.abspath(os.path.join(BASE_DIR, safe_db_name))
            if os.path.exists(alt_path):
                full_path = alt_path
            else:
                self.send_json({'error': f'Archivo {safe_db_name} no encontrado'}, status=404)
                return

        ACTIVE_DB_PATH = full_path
        save_active_session(full_path, client_name)
        upload_state['dbPath'] = full_path
        upload_state['clientName'] = client_name
        upload_state['clientSlug'] = get_client_slug(client_name)
        upload_state['status'] = 'ready'

        # Get records count
        records = 0
        errors = 0
        try:
            conn = sqlite3.connect(full_path, timeout=30.0)
            cur = conn.cursor()
            cur.execute('SELECT COUNT(1) FROM logs')
            records = cur.fetchone()[0]
            cur.execute('SELECT COUNT(1) FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))
            errors = cur.fetchone()[0]
            conn.close()
        except Exception:
            pass

        self.send_json({
            'success': True,
            'activeDb': os.path.basename(full_path),
            'path': full_path,
            'totalLogs': records,
            'totalErrors': errors,
            'client': client_name
        })

    def handle_get_version(self):
        version_data = {
            'appName': 'IT SERVICIOS — Suite de Diagnóstico Entrust OnPremise & IDaaS Cloud',
            'version': 'v2.5.0',
            'build': 520,
            'gitCommit': '47e2ac8',
            'gitBranch': 'main',
            'buildDate': time.strftime('%Y-%m-%d %H:%M'),
            'releaseChannel': 'Enterprise LTS (Bilingüe / ISO 27001 & SUDEBAN)',
            'engineer': 'Tomás Acosta',
            'organization': 'IT Servicios de Venezuela, S.A.',
            'serverUptimeSeconds': round(time.time() - SERVER_START_TIME, 1) if 'SERVER_START_TIME' in globals() else 0,
            'pythonVersion': sys.version.split()[0],
            'activeDb': os.path.basename(ACTIVE_DB_PATH) if ACTIVE_DB_PATH else 'Ninguna'
        }
        v_file = os.path.join(BASE_DIR, 'version.json')
        if os.path.exists(v_file):
            try:
                with open(v_file, 'r', encoding='utf-8') as f:
                    file_v = json.load(f)
                    version_data.update(file_v)
            except Exception:
                pass
        try:
            import subprocess
            rev_cnt = subprocess.check_output(['git', 'rev-list', '--count', 'HEAD'], cwd=BASE_DIR, stderr=subprocess.DEVNULL).decode('utf-8').strip()
            rev_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=BASE_DIR, stderr=subprocess.DEVNULL).decode('utf-8').strip()
            rev_date = subprocess.check_output(['git', 'log', '-1', '--format=%cd', '--date=format:%Y-%m-%d %H:%M'], cwd=BASE_DIR, stderr=subprocess.DEVNULL).decode('utf-8').strip()
            if rev_cnt:
                version_data['build'] = int(rev_cnt) + 350
                version_data['gitCommit'] = rev_hash
                version_data['buildDate'] = rev_date
        except Exception:
            pass

        self.send_json({'success': True, 'version': version_data})

    def handle_get_clients(self):
        clients_file = os.path.join(DATA_DIR, 'clients.json')
        if os.path.exists(clients_file):
            try:
                with open(clients_file, 'r', encoding='utf-8') as f:
                    clients_data = json.load(f)
                if isinstance(clients_data, list):
                    self.send_json({'success': True, 'clients': clients_data})
                    return
            except Exception as e:
                print(f"Error leyendo clients.json: {e}")

        default_clients = []
        try:
            with open(clients_file, 'w', encoding='utf-8') as f:
                json.dump(default_clients, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        self.send_json({'success': True, 'clients': default_clients})

    def handle_save_clients(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            clients = data.get('clients', data) if isinstance(data, dict) else data

            if isinstance(clients, list):
                clients_file = os.path.join(DATA_DIR, 'clients.json')
                with open(clients_file, 'w', encoding='utf-8') as f:
                    json.dump(clients, f, indent=2, ensure_ascii=False)
                self.send_json({'success': True, 'savedCount': len(clients)})
            else:
                self.send_json({'error': 'Formato inválido: se esperaba un array de clientes'}, status=400)
        except Exception as e:
            self.send_json({'error': f'Error guardando clientes: {e}'}, status=500)

    def handle_get_engineers(self):
        engineers_file = os.path.join(DATA_DIR, 'engineers.json')
        if os.path.exists(engineers_file):
            try:
                with open(engineers_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    changed = False
                    for eng in data:
                        if isinstance(eng, dict) and re.match(r'^IT\s+SERVICIOS\s+V\.?S\.?A\.?$', str(eng.get('organization') or '').strip(), re.IGNORECASE):
                            eng['organization'] = 'IT Servicios de Venezuela, S.A.'
                            changed = True
                    if changed:
                        try:
                            with open(engineers_file, 'w', encoding='utf-8') as fw:
                                json.dump(data, fw, indent=2, ensure_ascii=False)
                        except Exception:
                            pass
                    self.send_json({'success': True, 'engineers': data})
                    return
            except Exception as e:
                print(f"Error leyendo engineers.json: {e}")

        default_engineers = [
            {
                "id": "eng-tomas",
                "name": "Tomás Acosta",
                "title": "Especialista Senior en Seguridad & Identidad Entrust",
                "email": "tacosta@itservicios.com",
                "signature": "Ing. Tomás Acosta",
                "organization": "IT Servicios de Venezuela, S.A.",
                "initials": "TA"
            }
        ]
        try:
            with open(engineers_file, 'w', encoding='utf-8') as f:
                json.dump(default_engineers, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        self.send_json({'success': True, 'engineers': default_engineers})

    def handle_save_engineers(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            engineers = data.get('engineers', data) if isinstance(data, dict) else data

            if isinstance(engineers, list):
                engineers_file = os.path.join(DATA_DIR, 'engineers.json')
                with open(engineers_file, 'w', encoding='utf-8') as f:
                    json.dump(engineers, f, indent=2, ensure_ascii=False)
                self.send_json({'success': True, 'savedCount': len(engineers)})
            else:
                self.send_json({'error': 'Formato inválido: se esperaba un array de ingenieros'}, status=400)
        except Exception as e:
            self.send_json({'error': f'Error guardando ingenieros: {e}'}, status=500)

    def handle_list_server_files(self):
        found_files = []
        scan_dirs = [DATA_DIR, UPLOADS_DIR, BASE_DIR]
        for sdir in scan_dirs:
            if not os.path.exists(sdir):
                continue
            for f in os.listdir(sdir):
                if f.startswith('.'):
                    continue
                full_p = os.path.join(sdir, f)
                if not os.path.isfile(full_p):
                    continue
                try:
                    sz = os.path.getsize(full_p)
                    if f.endswith('.db') and sz > 0 and not f.startswith('pcap_'):
                        records = 0
                        errors = 0
                        try:
                            conn = sqlite3.connect(full_p, timeout=30.0)
                            cur = conn.cursor()
                            cur.execute('SELECT COUNT(1) FROM logs')
                            records = cur.fetchone()[0]
                            cur.execute('SELECT COUNT(1) FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))
                            errors = cur.fetchone()[0]
                            conn.close()
                        except Exception:
                            pass
                        found_files.append({
                            'name': f,
                            'path': full_p,
                            'type': 'database',
                            'sizeBytes': sz,
                            'sizeMb': round(sz / (1024 * 1024), 2),
                            'sizeGb': round(sz / (1024 * 1024 * 1024), 2),
                            'records': records,
                            'errors': errors
                        })
                    elif re.search(r'\.(pcapng|pcap|cap|dmp)(\.gz)?$', f, re.IGNORECASE):
                        found_files.append({
                            'name': f,
                            'path': full_p,
                            'type': 'pcap',
                            'isPcap': True,
                            'sizeBytes': sz,
                            'sizeMb': round(sz / (1024 * 1024), 2),
                            'sizeGb': round(sz / (1024 * 1024 * 1024), 2),
                            'records': 0,
                            'errors': 0
                        })
                    elif re.search(r'\.(csv|log|txt|tsv|out|json)(\.\d+)?$', f, re.IGNORECASE):
                        found_files.append({
                            'name': f,
                            'path': full_p,
                            'type': 'raw_log',
                            'sizeBytes': sz,
                            'sizeMb': round(sz / (1024 * 1024), 2),
                            'sizeGb': round(sz / (1024 * 1024 * 1024), 2),
                            'records': 0,
                            'errors': 0
                        })
                except Exception:
                    pass
        unique_files = list({v['path']: v for v in found_files}.values())
        self.send_json({'files': unique_files})

    def handle_upload_chunk(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 25 * 1024 * 1024:
                self.send_json({'error': 'Chunk excede el límite máximo permitido de 25 MB'}, status=413)
                return
            chunk_data = self.rfile.read(content_length)
            
            chunk_index = int(self.headers.get('X-Chunk-Index', 0))
            total_chunks = int(self.headers.get('X-Total-Chunks', 1))
            file_name = urllib.parse.unquote(self.headers.get('X-File-Name', 'uploaded_log.csv'))
            client_name = urllib.parse.unquote(self.headers.get('X-Client-Name', 'Entrust Client'))

            safe_file_name = re.sub(r'[^a-zA-Z0-9_\.-]', '_', os.path.basename(file_name))
            if safe_file_name.lower().endswith(self.BLOCKED_EXTENSIONS):
                self.send_json({'error': 'Extensión de archivo bloqueada por directiva de seguridad (PHP/Scripts no permitidos)'}, status=403)
                return
            temp_path = os.path.join(UPLOADS_DIR, safe_file_name)

            mode = 'wb' if chunk_index == 0 else 'ab'
            with open(temp_path, mode) as f:
                f.write(chunk_data)

            pct = int(((chunk_index + 1) / total_chunks) * 100)
            upload_state['fileName'] = file_name
            upload_state['clientName'] = client_name
            upload_state['clientSlug'] = get_client_slug(client_name)
            upload_state['status'] = 'uploading'
            upload_state['progress'] = pct

            if chunk_index == total_chunks - 1:
                append_mode = str(self.headers.get('X-Append-Mode', 'false')).lower() == 'true'
                server_tag = urllib.parse.unquote(self.headers.get('X-Server-Tag', '')).strip()
                upload_state['status'] = 'indexing'
                upload_state['progress'] = 0
                upload_state['linesProcessed'] = 0
                upload_state['totalErrors'] = 0
                upload_state['error'] = None
                thread = threading.Thread(target=index_file_in_background, args=(temp_path, client_name, append_mode, server_tag))
                thread.daemon = True
                thread.start()

            self.send_json({'success': True, 'chunkIndex': chunk_index, 'progress': pct})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)


    def handle_ingest_local(self):
        global ACTIVE_DB_PATH
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body_data = self.rfile.read(content_length).decode('utf-8')
            payload = json.loads(body_data) if body_data else {}
            
            file_path = payload.get('filePath', '').strip()
            client_name = payload.get('clientName', 'Banco Mercantil C.A.').strip()
            force_reindex = bool(payload.get('forceReindex', False))
            
            if not file_path:
                self.send_json({'error': 'Ruta de archivo no especificada'}, status=400)
                return

            # Security Hardening: Prevent arbitrary Path Traversal and block executable extensions
            safe_basename = os.path.basename(file_path)
            if safe_basename.lower().endswith(self.BLOCKED_EXTENSIONS):
                self.send_json({'error': 'Archivo bloqueado por directiva de seguridad'}, status=403)
                return

            resolved_path = None
            for allowed_dir in (DATA_DIR, UPLOADS_DIR, BASE_DIR):
                cand = os.path.abspath(os.path.join(allowed_dir, safe_basename))
                if os.path.isfile(cand):
                    resolved_path = cand
                    break

            if not resolved_path:
                self.send_json({'error': f'El archivo no existe en las carpetas autorizadas del servidor: {safe_basename}'}, status=404)
                return

            file_path = resolved_path
            
            client_slug = get_client_slug(client_name)
            target_db = os.path.join(DATA_DIR, f"{client_slug}_audit.db")
            
            # If DB already exists and has records (and forceReindex is not requested), activate immediately
            if not force_reindex and os.path.exists(target_db) and os.path.getsize(target_db) > 1024 * 1024:
                try:
                    conn = sqlite3.connect(target_db, timeout=30.0)
                    cur = conn.cursor()
                    cur.execute('SELECT COUNT(1) FROM logs')
                    records = cur.fetchone()[0]
                    cur.execute('SELECT COUNT(1) FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))
                    errors = cur.fetchone()[0]
                    conn.close()
                    
                    if records > 0:
                        ACTIVE_DB_PATH = target_db
                        save_active_session(target_db, client_name)
                        upload_state['dbPath'] = target_db
                        upload_state['clientName'] = client_name
                        upload_state['clientSlug'] = client_slug
                        upload_state['fileName'] = os.path.basename(file_path)
                        upload_state['status'] = 'ready'
                        upload_state['progress'] = 100
                        upload_state['linesProcessed'] = records
                        upload_state['totalErrors'] = errors
                        upload_state['error'] = None
                        
                        self.send_json({
                            'success': True,
                            'status': 'ready',
                            'alreadyIndexed': True,
                            'dbPath': target_db,
                            'totalLogs': records,
                            'totalErrors': errors,
                            'client': client_name
                        })
                        return
                except Exception:
                    pass

            upload_state['status'] = 'indexing'
            upload_state['progress'] = 0
            upload_state['fileName'] = os.path.basename(file_path)
            upload_state['clientName'] = client_name
            upload_state['clientSlug'] = client_slug
            upload_state['linesProcessed'] = 0
            upload_state['totalErrors'] = 0
            upload_state['error'] = None

            thread = threading.Thread(target=index_file_in_background, args=(file_path, client_name))
            thread.daemon = True
            thread.start()

            self.send_json({
                'success': True,
                'status': 'indexing',
                'filePath': file_path,
                'client': client_name
            })
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_ingest_batch(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body_data = self.rfile.read(content_length).decode('utf-8')
            payload = json.loads(body_data) if body_data else {}

            raw_paths = payload.get('filePaths') or []
            ingest_all = bool(payload.get('ingestAll', False))
            client_name = payload.get('clientName', 'Banco Mercantil C.A.').strip() or 'Banco Mercantil C.A.'
            force_reindex = bool(payload.get('forceReindex', True))

            resolved_paths = []
            if ingest_all and not raw_paths:
                for sdir in (UPLOADS_DIR, DATA_DIR):
                    if not os.path.exists(sdir):
                        continue
                    for f in sorted(os.listdir(sdir)):
                        if f.startswith('.'):
                            continue
                        full_p = os.path.join(sdir, f)
                        if os.path.isfile(full_p) and re.search(r'\.(csv|log|txt|tsv|out|json)(\.\d+)?$', f, re.IGNORECASE):
                            if not f.lower().endswith(self.BLOCKED_EXTENSIONS):
                                resolved_paths.append(full_p)
            else:
                for p in raw_paths:
                    safe_basename = os.path.basename(str(p).strip())
                    if not safe_basename or safe_basename.lower().endswith(self.BLOCKED_EXTENSIONS):
                        continue
                    for allowed_dir in (DATA_DIR, UPLOADS_DIR, BASE_DIR):
                        cand = os.path.abspath(os.path.join(allowed_dir, safe_basename))
                        if os.path.isfile(cand):
                            resolved_paths.append(cand)
                            break

            resolved_paths = list(dict.fromkeys(resolved_paths))
            if not resolved_paths:
                self.send_json({'error': 'No se encontraron archivos válidos para indexar en el servidor.'}, status=404)
                return

            client_slug = get_client_slug(client_name)
            upload_state['status'] = 'indexing'
            upload_state['progress'] = 0
            upload_state['fileName'] = f"Lote de {len(resolved_paths)} archivo(s)"
            upload_state['clientName'] = client_name
            upload_state['clientSlug'] = client_slug
            upload_state['linesProcessed'] = 0
            upload_state['totalErrors'] = 0
            upload_state['error'] = None

            thread = threading.Thread(
                target=index_batch_in_background,
                args=(resolved_paths, client_name, force_reindex)
            )
            thread.daemon = True
            thread.start()

            self.send_json({
                'success': True,
                'status': 'indexing',
                'totalFiles': len(resolved_paths),
                'client': client_name
            })
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)


    def handle_api_stats(self, query):
        client_param = query.get('client', [None])[0]
        db = resolve_client_db(client_param)
        
        if not db or not os.path.exists(db):
            self.send_json({
                'status': 'empty',
                'totalLogs': 0,
                'totalErrors': 0,
                'totalSuccess': 0,
                'eventTypes': [],
                'topUsers': [],
                'topIps': [],
                'activeDb': None,
                'client': client_param
            }, status=200)
            return

        try:
            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()
            
            # Fast Check: cached stats in server_stats table (< 0.5 ms)
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_stats'")
            if cur.fetchone():
                cur.execute("SELECT value FROM server_stats WHERE key='stats_json'")
                row = cur.fetchone()
                if row and row[0]:
                    stats_cached = json.loads(row[0])
                    stats_cached['activeDb'] = os.path.basename(db)
                    stats_cached['client'] = client_param or os.path.basename(db).replace('_audit.db', '')
                    stats_dirty = False
                    if isinstance(stats_cached.get('loadedFiles'), list) and len(stats_cached['loadedFiles']) > 0:
                        if _ensure_loaded_file_ranges(cur, stats_cached['loadedFiles'], fill_dates=True):
                            stats_dirty = True
                    if (int(stats_cached.get('totalLogs', 0) or 0) > 200 and int(stats_cached.get('totalUniqueUsers', 0) or 0) <= 200) or 'totalUniqueUsers' not in stats_cached:
                        ex_u, ex_c, ex_ip = compute_exact_sqlite_distinct_counts(cur)
                        stats_cached['totalUniqueUsers'] = ex_u
                        stats_cached['totalUniqueCodes'] = ex_c
                        stats_cached['totalUniqueIps'] = ex_ip
                        stats_dirty = True
                    if stats_dirty:
                        try:
                            cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('stats_json', json.dumps(stats_cached, ensure_ascii=False)))
                            conn.commit()
                        except Exception:
                            pass
                    if 'topUsers' in stats_cached and isinstance(stats_cached['topUsers'], list):
                        stats_cached['topUsers'] = [u for u in stats_cached['topUsers'] if is_valid_user_candidate(u.get('user', ''))]
                    conn.close()
                    self.send_json(stats_cached)
                    return

            cur.execute('SELECT COUNT(1) FROM logs')
            total = cur.fetchone()[0]

            cur.execute('SELECT COUNT(1) FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))
            errors = cur.fetchone()[0]

            # 1. Agrupación precisa de tipos de eventos
            cur.execute('SELECT event_type, COUNT(1) FROM logs GROUP BY event_type ORDER BY COUNT(1) DESC LIMIT 1000')
            types = [{'code': r[0], 'count': r[1]} for r in cur.fetchall()]

            # 2. Agrupación forense de códigos de error exactos ([520xxx], [521xxx], bulkidentityguard.*, ORA-*, TOMCAT_*, etc.)
            cur.execute('''
                SELECT
                    CASE
                        WHEN event_type != '' AND event_type != 'SYSTEM_LOG' AND event_type != 'ENTRUST_LOG' THEN event_type
                        WHEN message LIKE '%assignedgrid%' THEN 'bulkidentityguard.add.error.assignedgrid'
                        WHEN message LIKE '%bulkidentityguard.add.error.qa%' OR message LIKE '%qa_already_exists%' THEN 'bulkidentityguard.add.error.qa'
                        WHEN message LIKE '%bulkidentityguard.add.error.password%' OR message LIKE '%password_already_exists%' THEN 'bulkidentityguard.add.error.password'
                        WHEN message LIKE '%ORA-01555%' OR message LIKE '%snapshot too old%' THEN 'ORA-01555'
                        WHEN message LIKE '%ORA-%' THEN SUBSTR(message, INSTR(message, 'ORA-'), 9)
                        WHEN message LIKE '%520%' THEN SUBSTR(message, INSTR(message, '520'), 7)
                        WHEN message LIKE '%AUD%' THEN SUBSTR(message, INSTR(message, 'AUD'), 7)
                        WHEN message LIKE '%TransactionQueue%' THEN 'TransactionQueue.API'
                        WHEN message != '' THEN SUBSTR(message, 1, 60)
                        ELSE event_type
                    END as err_code,
                    COUNT(1) as cnt
                FROM logs
                WHERE event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%'
                GROUP BY err_code
                ORDER BY cnt DESC
                LIMIT 1000
            ''')
            top_codes = [{'code': r[0], 'count': r[1]} for r in cur.fetchall()]

            # 3. Usuarios más activos / afectados (filtrando falsos positivos / palabras reservadas)
            cur.execute('SELECT subject_name, COUNT(1) FROM logs WHERE subject_name != "unknown" AND subject_name != "system" AND subject_name != "" GROUP BY subject_name ORDER BY COUNT(1) DESC LIMIT 80')
            raw_top_users = cur.fetchall()
            top_users = [{'user': r[0], 'count': r[1]} for r in raw_top_users if is_valid_user_candidate(r[0])][:20]

            # 4. IPs de origen
            cur.execute('SELECT source_ip, COUNT(1) FROM logs WHERE source_ip != "" AND source_ip != "local" GROUP BY source_ip ORDER BY COUNT(1) DESC LIMIT 20')
            top_ips = [{'ip': r[0], 'count': r[1]} for r in cur.fetchall()]

            # 5. Timeline Heatmap por fecha y hora (Panorama 100% Completo)
            cur.execute('''
                SELECT 
                    SUBSTR(event_time, 1, 13) as hour_bucket,
                    COUNT(1) as total_events,
                    SUM(CASE WHEN event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%' THEN 1 ELSE 0 END) as error_events,
                    SUM(CASE WHEN event_outcome = 'SUCCESS' OR event_outcome = 'INFO' THEN 1 ELSE 0 END) as info_events
                FROM logs
                WHERE event_time IS NOT NULL AND event_time != ''
                GROUP BY hour_bucket
                ORDER BY hour_bucket ASC
                LIMIT 2000
            ''')
            timeline_buckets = [{'bucket': r[0], 'total': r[1], 'errors': r[2] or 0, 'info': r[3] or 0} for r in cur.fetchall()]

            # 6. Detección automática de entorno (IDaaS Cloud vs OnPremise)
            cur.execute("SELECT 1 FROM logs WHERE event_type LIKE '%Bulkidentityguard%' OR message LIKE '%bulkidentityguard%' LIMIT 1")
            is_idaas = cur.fetchone() is not None
            detected_platform = 'Entrust IDaaS Cloud' if is_idaas else 'Entrust IdentityGuard OnPremise'

            exact_u, exact_c, exact_ip = compute_exact_sqlite_distinct_counts(cur)

            conn.close()
            self.send_json({
                'status': 'ready',
                'totalLogs': total,
                'totalErrors': errors,
                'totalWarnings': 0,
                'totalSuccess': total - errors,
                'totalUniqueCodes': exact_c,
                'totalUniqueUsers': exact_u,
                'totalUniqueIps': exact_ip,
                'eventTypes': types,
                'topCodes': top_codes,
                'topUsers': top_users,
                'topIps': top_ips,
                'timelineBuckets': timeline_buckets,
                'detectedPlatform': detected_platform,
                'activeDb': os.path.basename(db),
                'client': client_param or os.path.basename(db).replace('_audit.db', '')
            })
        except Exception as e:
            self.send_json({'error': str(e), 'totalLogs': 0, 'totalErrors': 0}, status=500)

    def handle_delete_session_files(self):
        global upload_state
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length).decode('utf-8', errors='ignore') if length > 0 else '{}'
            payload = json.loads(raw) if raw.strip() else {}
            client_param = (payload.get('client') or '').strip() or None
            id_set = {str(x) for x in (payload.get('fileIds') or []) if x}
            idx_set = set()
            for x in (payload.get('fileIndices') or []):
                try:
                    idx_set.add(int(x))
                except Exception:
                    pass
            norm_srv = _norm_srv_tag(payload.get('serverTag'))

            db = resolve_client_db(client_param)
            if not db or not os.path.exists(db):
                self.send_json({'error': 'No existe base de datos SQLite activa para este cliente'}, status=404)
                return

            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_stats'")
            if not cur.fetchone():
                conn.close()
                self.send_json({'error': 'La sesión no contiene metadatos de archivos cargados'}, status=400)
                return

            cur.execute("SELECT value FROM server_stats WHERE key='stats_json'")
            row = cur.fetchone()
            if not row or not row[0]:
                conn.close()
                self.send_json({'error': 'No se encontraron estadísticas de archivos en server_stats'}, status=400)
                return

            stats_cached = json.loads(row[0]) or {}
            loaded_files = list(stats_cached.get('loadedFiles') or [])
            if not loaded_files:
                conn.close()
                self.send_json({'error': 'Lista de archivos vacía en esta sesión'}, status=400)
                return

            _ensure_loaded_file_ranges(cur, loaded_files, fill_dates=False)

            to_remove = []
            remaining = []
            for idx, f in enumerate(loaded_files):
                fid = str(f.get('fileId') or '')
                f_srv = _norm_srv_tag(f.get('serverTag') or f.get('nodeName'))
                matched = (fid and fid in id_set) or (idx in idx_set) or (bool(norm_srv) and f_srv == norm_srv)
                if matched:
                    to_remove.append(f)
                else:
                    remaining.append(f)

            if not to_remove:
                conn.close()
                self.send_json({'error': 'Ningún archivo coincidente para eliminar'}, status=400)
                return

            if len(remaining) == 0:
                conn.close()
                clear_active_session(client_param=client_param, purge_db=True)
                self.send_json({
                    'success': True,
                    'status': 'empty',
                    'deletedCount': len(to_remove),
                    'remainingFiles': 0,
                    'totalLogs': 0,
                    'totalErrors': 0
                })
                return

            for f in to_remove:
                sl = int(f.get('startLine') or 0)
                el = int(f.get('endLine') or 0)
                if sl > 0 and el >= sl:
                    cur.execute('DELETE FROM logs WHERE line_num BETWEEN ? AND ?', (sl, el))
            conn.commit()

            client_display = stats_cached.get('client') or client_param or 'Entrust Client'
            stats_obj = recompute_sqlite_stats_obj(cur, db, client_display, remaining)
            cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('stats_json', json.dumps(stats_obj, ensure_ascii=False)))
            cur.execute("DELETE FROM server_stats WHERE key IN ('forensic_matrix_v2', 'forensic_matrix_v3', 'forensic_matrix_v4', 'forensic_matrix_v5')")
            conn.commit()
            conn.close()

            upload_state['linesProcessed'] = stats_obj['totalLogs']
            upload_state['totalErrors'] = stats_obj['totalErrors']
            upload_state['totalWarnings'] = stats_obj['totalWarnings']

            self.send_json({
                'success': True,
                'status': 'ready',
                'deletedCount': len(to_remove),
                'remainingFiles': len(remaining),
                'totalLogs': stats_obj['totalLogs'],
                'totalErrors': stats_obj['totalErrors'],
                'stats': stats_obj
            })
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_reassign_session_files(self):
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(length).decode('utf-8', errors='ignore') if length > 0 else '{}'
            payload = json.loads(raw) if raw.strip() else {}
            client_param = (payload.get('client') or '').strip() or None
            id_set = {str(x) for x in (payload.get('fileIds') or []) if x}
            idx_set = set()
            for x in (payload.get('fileIndices') or []):
                try:
                    idx_set.add(int(x))
                except Exception:
                    pass
            node_key = str(payload.get('nodeKey') or '').strip()
            node_name = str(payload.get('nodeName') or '').strip()
            server_tag = str(payload.get('serverTag') or '').strip()

            db = resolve_client_db(client_param)
            if not db or not os.path.exists(db):
                self.send_json({'error': 'Base de datos SQLite no encontrada'}, status=404)
                return

            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='server_stats'")
            if not cur.fetchone():
                conn.close()
                self.send_json({'error': 'Tabla server_stats no existe'}, status=400)
                return
            cur.execute("SELECT value FROM server_stats WHERE key='stats_json'")
            row = cur.fetchone()
            if not row or not row[0]:
                conn.close()
                self.send_json({'error': 'Metadatos de sesión vacíos'}, status=400)
                return

            stats_cached = json.loads(row[0]) or {}
            loaded_files = list(stats_cached.get('loadedFiles') or [])
            _ensure_loaded_file_ranges(cur, loaded_files, fill_dates=False)

            updated = 0
            for idx, f in enumerate(loaded_files):
                fid = str(f.get('fileId') or '')
                if (fid and fid in id_set) or (idx in idx_set):
                    if node_key:
                        f['nodeKey'] = node_key
                    if node_name:
                        f['nodeName'] = node_name
                    if server_tag:
                        f['serverTag'] = server_tag
                    updated += 1

            if updated > 0:
                stats_cached['loadedFiles'] = loaded_files
                cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('stats_json', json.dumps(stats_cached, ensure_ascii=False)))
                conn.commit()
            conn.close()
            self.send_json({'success': True, 'updatedCount': updated, 'loadedFiles': loaded_files})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_api_logs(self, query):
        client_param = query.get('client', [None])[0]
        db = resolve_client_db(client_param)
        
        if not db or not os.path.exists(db):
            self.send_json({'status': 'empty', 'logs': [], 'totalMatching': 0, 'totalPages': 0, 'page': 1, 'limit': 50}, status=200)
            return

        try:
            page = max(1, int(query.get('page', ['1'])[0]))
            limit = min(25000, max(10, int(query.get('limit', ['50'])[0])))
            offset = (page - 1) * limit
            search = query.get('search', [''])[0].strip()
            outcome = query.get('outcome', ['ALL'])[0].strip().upper()
            event_type = query.get('type', ['ALL'])[0].strip()

            conditions = []
            params = []

            if outcome in ['FAIL', 'ERROR']:
                conditions.append('(event_outcome LIKE ? OR event_outcome LIKE ?)')
                params.extend(['%FAIL%', '%ERR%'])
            elif outcome in ['WARN', 'WARNING']:
                conditions.append("(event_outcome LIKE ? OR event_type IN ('AUD6001', 'AUD2309', 'AUD155'))")
                params.append('%WARN%')
            elif outcome == 'AUD':
                conditions.append('event_type LIKE ?')
                params.append('AUD%')
            elif outcome in ['SUCCESS', 'INFO']:
                conditions.append('event_outcome = ?')
                params.append('SUCCESS')

            if event_type and event_type != 'ALL':
                conditions.append('event_type = ?')
                params.append(event_type)

            if search:
                conditions.append('(message LIKE ? OR subject_name LIKE ? OR source_ip LIKE ? OR event_type LIKE ? OR raw LIKE ?)')
                term = f'%{search}%'
                params.extend([term, term, term, term, term])

            where_clause = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()

            cur.execute(f'SELECT COUNT(1) FROM logs {where_clause}', params)
            total_matching = cur.fetchone()[0]

            query_sql = f'SELECT line_num, event_time, subject_name, event_type, event_outcome, message, source_ip, raw FROM logs {where_clause} ORDER BY line_num ASC LIMIT ? OFFSET ?'
            cur.execute(query_sql, params + [limit, offset])

            rows = cur.fetchall()
            conn.close()

            resolved_client_name = client_param or os.path.basename(db).replace('_audit.db', '').replace('_', ' ').title()
            logs = []
            for r in rows:
                etype = str(r[3] or '')
                etype_u = etype.upper()
                outcome_str = str(r[4] or '')
                msg_str = str(r[5] or '')
                is_err = (
                    'FAIL' in outcome_str.upper()
                    or 'ERR' in outcome_str.upper()
                    or is_entrust_numeric_code(etype)
                    or etype_u in _ENTRUST_BRACKET_FAIL_AUDS
                    or etype_u.startswith('ORA-')
                    or etype_u in (
                        'JDBC_SQL_EXCEPTION', 'JVM_OOM', 'TOMCAT_SSL_TLS',
                        'TOMCAT_LDAP_ERROR', 'TOMCAT_NETWORK_ERROR', 'TOMCAT_DEPLOY_ERROR',
                        'TOMCAT_JAVA_EXCEPTION', 'TOMCAT_SEVERE', 'SSH-FAIL'
                    )
                )
                is_warn = (not is_err) and (
                    'WARN' in outcome_str.upper()
                    or etype_u in ('AUD6001', 'AUD2309', 'AUD155', 'AUD151', 'TOMCAT_WARN', 'TOMCAT_THREAD_POOL')
                )
                level = 'ERROR' if is_err else ('WARN' if is_warn else 'INFO')
                svc = 'IG.AUDIT' if etype.upper().startswith('AUD') else ('IDaaS Cloud' if 'bulkidentityguard' in etype.lower() else ('Tomcat Catalina' if etype.upper().startswith(('TOMCAT_', 'JVM_')) else ('Oracle / JDBC' if (etype.upper().startswith('ORA-') or etype == 'JDBC_SQL_EXCEPTION') else 'IG.SYSTEM')))
                display_msg = msg_str if (f'[{etype}]' in msg_str or not etype) else f'[{etype}] {msg_str}'
                logs.append({
                    'id': f'log-{r[0]}',
                    'lineNum': r[0],
                    'timestamp': r[1],
                    'user': r[2],
                    'service': svc,
                    'entrustCode': etype,
                    'type': etype,
                    'level': level,
                    'outcome': outcome_str,
                    'message': display_msg,
                    'clientIp': r[6],
                    'raw': r[7],
                    'client': resolved_client_name,
                    'node': '🖥️ Servidor Core SQLite'
                })

            total_pages = max(1, (total_matching + limit - 1) // limit)
            self.send_json({
                'status': 'ready',
                'page': page,
                'limit': limit,
                'totalMatching': total_matching,
                'totalPages': total_pages,
                'logs': logs
            })
        except Exception as e:
            self.send_json({'error': str(e), 'logs': [], 'totalMatching': 0, 'totalPages': 0}, status=500)

    def handle_export_errors(self, query):
        client_param = query.get('client', [None])[0]
        db = resolve_client_db(client_param)
        
        if not db or not os.path.exists(db):
            self.send_error(404, 'No hay base de datos indexada para este cliente')
            return

        conn = sqlite3.connect(db, timeout=30.0)
        cur = conn.cursor()
        err_where = '''
            WHERE UPPER(event_outcome) LIKE '%FAIL%'
               OR UPPER(event_outcome) LIKE '%ERR%'
               OR UPPER(event_outcome) LIKE '%WARN%'
               OR event_type GLOB '5[0-9][0-9][0-9][0-9][0-9]*'
               OR UPPER(event_type) IN (
                   'AUD110', 'AUD125', 'AUD126', 'AUD127', 'AUD150', 'AUD151',
                   'AUD153', 'AUD154', 'AUD155', 'AUD2309', 'AUD4005', 'AUD6001', 'AUD6002',
                   'JDBC_SQL_EXCEPTION', 'SQL_EXCEPTION', 'JVM_OOM', 'TOMCAT_SSL_TLS',
                   'TOMCAT_LDAP_ERROR', 'TOMCAT_NETWORK_ERROR', 'TOMCAT_DEPLOY_ERROR',
                   'TOMCAT_JAVA_EXCEPTION', 'TOMCAT_SEVERE', 'TOMCAT_THREAD_POOL',
                   'TOMCAT_WARN', 'SSH-FAIL'
               )
               OR UPPER(event_type) LIKE 'ORA-%'
               OR LOWER(message) LIKE '%failed%'
               OR LOWER(message) LIKE '%locked%'
               OR LOWER(message) LIKE '%error%'
        '''
        cur.execute(f'SELECT COUNT(1) FROM logs {err_where}')
        err_count = cur.fetchone()[0] or 0

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="Errores_y_Alertas_AuditEvents_Export.csv"')
        self.end_headers()

        header = '\ufefflineNum,eventTime,user,eventType,outcome,message,ip,raw\n'
        self.wfile.write(header.encode('utf-8'))

        if err_count > 0:
            cur.execute(f'SELECT line_num, event_time, subject_name, event_type, event_outcome, message, source_ip, raw FROM logs {err_where} ORDER BY line_num ASC')
        else:
            cur.execute('SELECT line_num, event_time, subject_name, event_type, event_outcome, message, source_ip, raw FROM logs ORDER BY line_num ASC LIMIT 10000')

        while True:
            batch = cur.fetchmany(5000)
            if not batch:
                break
            lines = []
            for r in batch:
                clean_msg = (r[5] or '').replace('"', '""')
                clean_raw = (r[7] or '').replace('"', '""')
                lines.append(f'{r[0]},"{r[1]}","{r[2]}","{r[3]}","{r[4]}","{clean_msg}","{r[6]}","{clean_raw}"\n')
            self.wfile.write(''.join(lines).encode('utf-8'))

        conn.close()

    def handle_user_pattern_detail(self, query):
        client_param = query.get('client', [None])[0]
        target_user = query.get('user', [''])[0].strip()
        db = resolve_client_db(client_param)
        if not db or not os.path.exists(db) or not target_user:
            self.send_json({'status': 'empty', 'user': target_user, 'events': [], 'summary': None}, status=200)
            return

        try:
            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()

            # Aggregate 100% summary across all rows for target_user (not truncated by 1,000-event preview cap)
            cur.execute('''
                SELECT event_type, event_outcome, COUNT(1), MIN(event_time), MAX(event_time), MAX(source_ip)
                FROM logs
                WHERE subject_name = ?
                GROUP BY event_type, event_outcome
            ''', (target_user,))
            agg_summary_rows = cur.fetchall()

            sum_total = 0
            sum_errors = 0
            sum_success = 0
            first_seen = ''
            last_seen = ''
            ips_set = set()
            codes_simple = {}
            codes_detail = {}
            is_locked = False
            lock_re = re.compile(r'5205079|5205080|5201053|5203016|5202002|AUD007|AUD6002', re.IGNORECASE)

            for r_code, r_out, r_cnt, r_first, r_last, r_ip in agg_summary_rows:
                code_lbl = (r_code or 'SYSTEM_LOG').strip()
                out_up = (r_out or 'SUCCESS').upper()
                is_err = ('FAIL' in out_up) or ('ERR' in out_up)
                cnt_int = int(r_cnt or 0)
                sum_total += cnt_int
                if is_err:
                    sum_errors += cnt_int
                else:
                    sum_success += cnt_int
                if lock_re.search(code_lbl):
                    is_locked = True
                if r_first and (not first_seen or r_first < first_seen):
                    first_seen = r_first
                if r_last and (not last_seen or r_last > last_seen):
                    last_seen = r_last
                if r_ip and r_ip not in ('local', ''):
                    ips_set.add(r_ip)
                codes_simple[code_lbl] = codes_simple.get(code_lbl, 0) + cnt_int
                if code_lbl not in codes_detail:
                    codes_detail[code_lbl] = {'total': 0, 'errors': 0, 'success': 0}
                codes_detail[code_lbl]['total'] += cnt_int
                if is_err:
                    codes_detail[code_lbl]['errors'] += cnt_int
                else:
                    codes_detail[code_lbl]['success'] += cnt_int

            cur.execute('''
                SELECT line_num, event_time, subject_name, event_type, event_outcome, message, source_ip, raw
                FROM logs
                WHERE subject_name = ?
                ORDER BY line_num ASC
                LIMIT 1000
            ''', (target_user,))
            rows = cur.fetchall()
            conn.close()

            events = []
            for idx, r in enumerate(rows):
                is_err = 'FAIL' in (r[4] or '').upper() or 'ERR' in (r[4] or '').upper()
                events.append({
                    'step': idx + 1,
                    'lineNum': r[0],
                    'timestamp': r[1] or 'Sin Timestamp',
                    'user': r[2],
                    'code': r[3] or 'SYSTEM_LOG',
                    'outcome': 'FAIL' if is_err else 'SUCCESS',
                    'level': 'ERROR' if is_err else 'INFO',
                    'message': r[5] or '',
                    'ip': r[6] or 'local',
                    'raw': r[7] or ''
                })

            summary = {
                'user': target_user,
                'total': sum_total,
                'errors': sum_errors,
                'success': sum_success,
                'isLocked': is_locked,
                'firstSeen': first_seen,
                'lastSeen': last_seen,
                'ips': sorted(ips_set)[:10],
                'codes': codes_simple,
                'codesDetail': codes_detail
            }

            self.send_json({
                'status': 'ready',
                'user': target_user,
                'totalReturned': len(events),
                'summary': summary,
                'events': events
            })
        except Exception as e:
            self.send_json({'error': str(e), 'user': target_user, 'events': [], 'summary': None}, status=500)

    def handle_api_users_search(self, query):
        client_param = query.get('client', [None])[0]
        q_filter = query.get('q', [''])[0].strip()
        outcome_filter = query.get('filter', ['all'])[0].strip().lower()
        page = max(1, int(query.get('page', ['1'])[0]))
        limit = min(500, max(10, int(query.get('limit', ['100'])[0])))
        db = resolve_client_db(client_param)

        if not db or not os.path.exists(db):
            self.send_json({'status': 'empty', 'totalMatching': 0, 'page': 1, 'totalPages': 0, 'users': []})
            return

        try:
            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()
            users_all = aggregate_sqlite_users(cur, q_filter=q_filter, outcome_filter=outcome_filter)
            conn.close()

            total_matching = len(users_all)
            total_pages = max(1, (total_matching + limit - 1) // limit)
            offset = (page - 1) * limit
            page_users = []
            for u in users_all[offset:offset + limit]:
                page_users.append({
                    'user': u['user'],
                    'total': u['total'],
                    'errors': u['errors'],
                    'success': u['success'],
                    'isLocked': u['isLocked'],
                    'firstSeen': u['firstSeen'],
                    'lastSeen': u['lastSeen'],
                    'ips': sorted(u['ips'])[:5],
                    'codes': u['codes']
                })

            self.send_json({
                'status': 'ready',
                'totalMatching': total_matching,
                'page': page,
                'totalPages': total_pages,
                'limit': limit,
                'users': page_users
            })
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error', 'totalMatching': 0, 'users': []}, status=500)

    def handle_api_users_export(self, query):
        import csv
        client_param = query.get('client', [None])[0]
        q_filter = query.get('q', [''])[0].strip()
        outcome_filter = query.get('filter', ['all'])[0].strip().lower()
        db = resolve_client_db(client_param)

        if not db or not os.path.exists(db):
            self.send_json({'error': 'Base de datos SQLite no encontrada'}, status=404)
            return

        try:
            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()
            users_all = aggregate_sqlite_users(cur, q_filter=q_filter, outcome_filter=outcome_filter)
            conn.close()

            slug = get_client_slug(client_param or os.path.basename(db).replace('_audit.db', ''))
            buf = io.StringIO()
            buf.write('\ufeff')
            writer = csv.writer(buf)
            writer.writerow([
                'Usuario', 'Total_Interacciones', 'Exitos', 'Fallas',
                'Porcentaje_Falla', 'Estado_Seguridad', 'Primera_Actividad',
                'Ultima_Actividad', 'IPs', 'Codigos_e_Interacciones'
            ])
            for u in users_all:
                err_pct = f"{round((u['errors'] / max(1, u['total'])) * 100, 1)}%"
                state_str = 'BLOQUEADO' if u['isLocked'] else ('CON_FALLAS' if u['errors'] > 0 else 'EXITOSO')
                ips_str = '; '.join(sorted(u['ips']))
                codes_str = '; '.join(
                    f"{k}({v['total']})"
                    for k, v in sorted(u['codes'].items(), key=lambda x: x[1]['total'], reverse=True)
                )
                writer.writerow([
                    u['user'],
                    u['total'],
                    u['success'],
                    u['errors'],
                    err_pct,
                    state_str,
                    u['firstSeen'],
                    u['lastSeen'],
                    ips_str,
                    codes_str
                ])

            csv_bytes = buf.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="Censo_Completo_100pct_{slug}.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(csv_bytes)
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error'}, status=500)

    def handle_forensic_matrix(self, query):
        client_param = query.get('client', [None])[0]
        refresh = query.get('refresh', ['0'])[0] == '1'
        db = resolve_client_db(client_param)

        if not db or not os.path.exists(db):
            self.send_json({
                'status': 'empty',
                'totalLogs': 0,
                'totalErrors': 0,
                'uniqueValidUsers': 0,
                'filteredNoiseUsers': 0,
                'usersList': [],
                'patternClusters': [],
                'codeMatrix': [],
                'dbHealth': None,
                'postMortem': None
            }, status=200)
            return

        try:
            conn = sqlite3.connect(db, timeout=30.0)
            cur = conn.cursor()

            cur.execute('CREATE TABLE IF NOT EXISTS server_stats (key TEXT PRIMARY KEY, value TEXT)')
            if not refresh:
                cur.execute("SELECT value FROM server_stats WHERE key='forensic_matrix_v5'")
                cached_row = cur.fetchone()
                if cached_row and cached_row[0]:
                    cached_payload = json.loads(cached_row[0])
                    cached_payload['activeDb'] = os.path.basename(db)
                    cached_payload['dbSizeMb'] = round(os.path.getsize(db) / (1024 * 1024), 2)
                    conn.close()
                    self.send_json(cached_payload)
                    return

            cur.execute('SELECT COUNT(1) FROM logs')
            total_logs = cur.fetchone()[0] or 0

            cur.execute("SELECT COUNT(1) FROM logs WHERE event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%'")
            total_errors = cur.fetchone()[0] or 0

            # 1. Aggregated (subject_name, event_type, event_outcome) across the DB
            cur.execute('''
                SELECT subject_name, event_type, event_outcome, COUNT(1) as cnt,
                       MIN(event_time) as first_t, MAX(event_time) as last_t, MAX(source_ip) as sample_ip
                FROM logs
                GROUP BY subject_name, event_type, event_outcome
            ''')
            agg_rows = cur.fetchall()

            import collections
            users_map = {}
            code_map = {}
            cat_users = {
                'audit': set(),
                '520': set(),
                'idaas': set(),
                'system': set(),
                'traffic': set(),
                'errors_all': set()
            }
            filtered_noise_users = set()
            filtered_noise_events = 0

            for subj, etype, outcome, cnt, first_t, last_t, sample_ip in agg_rows:
                code = (etype or 'SYSTEM_LOG').strip()
                out_str = (outcome or 'SUCCESS').upper()
                is_err = ('FAIL' in out_str) or ('ERR' in out_str)

                if code not in code_map:
                    kind = 'SYSTEM_EVENT'
                    if is_entrust_numeric_code(code):
                        kind = 'ERROR_520'
                    elif re.match(r'^AUD\d{2,5}$', code, re.IGNORECASE) or 'AUDIT' in code.upper():
                        kind = 'AUDIT_AUD'
                    elif code.startswith('ORA-') or 'SQL' in code.upper() or 'JDBC' in code.upper():
                        kind = 'DATABASE_ORA'
                    elif code.startswith('TOMCAT_') or code.startswith('JVM_'):
                        kind = 'TOMCAT_JVM'
                    elif 'bulkidentityguard' in code.lower() or 'migration' in code.lower() or 'idaas' in code.lower():
                        kind = 'IDAAS_MIGRATION'
                    code_map[code] = {
                        'code': code,
                        'kind': kind,
                        'totalInteractions': 0,
                        'failCount': 0,
                        'successCount': 0,
                        'systemOnlyCount': 0,
                        'usersDict': {}
                    }

                c_entry = code_map[code]
                c_entry['totalInteractions'] += cnt
                if is_err:
                    c_entry['failCount'] += cnt
                else:
                    c_entry['successCount'] += cnt

                subj_str = (subj or '').strip()
                if is_valid_user_candidate(subj_str):
                    cat_users['traffic'].add(subj_str)
                    if is_err:
                        cat_users['errors_all'].add(subj_str)
                    if c_entry['kind'] == 'AUDIT_AUD':
                        cat_users['audit'].add(subj_str)
                    elif c_entry['kind'] == 'ERROR_520':
                        cat_users['520'].add(subj_str)
                    elif c_entry['kind'] == 'IDAAS_MIGRATION':
                        cat_users['idaas'].add(subj_str)
                    elif c_entry['kind'] in ('SYSTEM_EVENT', 'DATABASE_ORA', 'TOMCAT_JVM'):
                        cat_users['system'].add(subj_str)

                    if subj_str not in users_map:
                        users_map[subj_str] = {
                            'user': subj_str,
                            'total': 0,
                            'errors': 0,
                            'success': 0,
                            'firstSeen': first_t or '',
                            'lastSeen': last_t or '',
                            'ips': set(),
                            'codes': {}
                        }
                    u_entry = users_map[subj_str]
                    u_entry['total'] += cnt
                    if is_err:
                        u_entry['errors'] += cnt
                    else:
                        u_entry['success'] += cnt
                    if first_t and (not u_entry['firstSeen'] or first_t < u_entry['firstSeen']):
                        u_entry['firstSeen'] = first_t
                    if last_t and (not u_entry['lastSeen'] or last_t > u_entry['lastSeen']):
                        u_entry['lastSeen'] = last_t
                    if sample_ip and sample_ip not in ('local', ''):
                        u_entry['ips'].add(sample_ip)

                    if code not in u_entry['codes']:
                        u_entry['codes'][code] = {'total': 0, 'errors': 0, 'success': 0}
                    u_entry['codes'][code]['total'] += cnt
                    if is_err:
                        u_entry['codes'][code]['errors'] += cnt
                    else:
                        u_entry['codes'][code]['success'] += cnt

                    if subj_str not in c_entry['usersDict']:
                        c_entry['usersDict'][subj_str] = {'user': subj_str, 'count': 0, 'errors': 0, 'success': 0, 'lastSeen': last_t or ''}
                    c_entry['usersDict'][subj_str]['count'] += cnt
                    if is_err:
                        c_entry['usersDict'][subj_str]['errors'] += cnt
                    else:
                        c_entry['usersDict'][subj_str]['success'] += cnt
                    if last_t and last_t > c_entry['usersDict'][subj_str]['lastSeen']:
                        c_entry['usersDict'][subj_str]['lastSeen'] = last_t
                else:
                    c_entry['systemOnlyCount'] += cnt
                    if subj_str and subj_str.lower() not in ('system', 'unknown', ''):
                        filtered_noise_users.add(subj_str)
                        filtered_noise_events += cnt

            # 2. Sort top 600 valid users (prioritizing users with errors or high interaction volume)
            sorted_users = sorted(
                users_map.values(),
                key=lambda u: (1 if u['errors'] > 0 else 0, u['errors'], u['total']),
                reverse=True
            )
            top_users_subset = sorted_users[:600]
            top_usernames = [u['user'] for u in top_users_subset]

            # 3. Reconstruct exact chronological request sequences (Patrón de Solicitudes por Usuario)
            user_sequences = collections.defaultdict(list)
            if top_usernames:
                chunk_sz = 200
                for i in range(0, len(top_usernames), chunk_sz):
                    batch_names = top_usernames[i:i + chunk_sz]
                    placeholders = ','.join(['?'] * len(batch_names))
                    cur.execute(f'''
                        SELECT subject_name, event_type, event_outcome, event_time, source_ip, line_num, SUBSTR(message, 1, 140)
                        FROM logs
                        WHERE subject_name IN ({placeholders})
                        ORDER BY line_num ASC
                    ''', batch_names)
                    for r_subj, r_type, r_out, r_time, r_ip, r_line, r_msg in cur.fetchall():
                        seq_list = user_sequences[r_subj]
                        if len(seq_list) < 40:
                            is_e = 'FAIL' in (r_out or '').upper() or 'ERR' in (r_out or '').upper()
                            seq_list.append({
                                'step': len(seq_list) + 1,
                                'code': r_type or 'SYSTEM_LOG',
                                'outcome': 'FAIL' if is_e else 'SUCCESS',
                                'timestamp': r_time or '',
                                'ip': r_ip or 'local',
                                'lineNum': r_line,
                                'msg': r_msg or ''
                            })

            # 4. Classify each user's behavioral pattern and build Pattern Clusters
            pattern_clusters_map = {}
            users_list_out = []

            for u in top_users_subset:
                uname = u['user']
                seq = user_sequences.get(uname, [])
                if not seq:
                    for c_k, c_v in sorted(u['codes'].items(), key=lambda x: x[1]['total'], reverse=True):
                        seq.append({
                            'step': len(seq) + 1,
                            'code': c_k,
                            'outcome': 'FAIL' if c_v['errors'] > 0 else 'SUCCESS',
                            'timestamp': u['lastSeen'],
                            'ip': next(iter(u['ips']), 'local'),
                            'lineNum': 0,
                            'msg': c_k
                        })

                rle_steps = []
                norm_steps = []
                for s in seq:
                    c_label = s['code']
                    o_label = s['outcome']
                    if rle_steps and rle_steps[-1]['code'] == c_label and rle_steps[-1]['outcome'] == o_label:
                        rle_steps[-1]['repeat'] += 1
                    else:
                        rle_steps.append({'code': c_label, 'outcome': o_label, 'repeat': 1})
                        if len(norm_steps) < 6:
                            norm_steps.append(f"{c_label} ({'FALLO' if o_label == 'FAIL' else 'ÉXITO'})")

                compressed_parts = []
                for st in rle_steps[:8]:
                    rep_str = f" x{st['repeat']}" if st['repeat'] > 1 else ""
                    state_str = "FALLO" if st['outcome'] == 'FAIL' else "ÉXITO"
                    compressed_parts.append(f"{st['code']} ({state_str}{rep_str})")
                compressed_pattern = ' ➔ '.join(compressed_parts)
                if len(rle_steps) > 8:
                    compressed_pattern += f" ➔ ... (+{len(rle_steps) - 8} etapas)"

                normalized_sig = ' ➔ '.join(norm_steps) if norm_steps else 'OPERACIÓN_UNICA'

                codes_keys_lower = ' '.join(u['codes'].keys()).lower()
                if any(k in codes_keys_lower for k in ('ora-', 'sql_exception', 'jdbccardrepository', 'transactionqueue', 'blobaccess')):
                    pattern_category = '🗄️ Fallo Inducido por Base de Datos (ORA / JDBC)'
                    pattern_root_cause = 'Las solicitudes del usuario fueron abortadas por una excepción de persistencia o bloqueo en la base de datos (ej. ORA-01555 / SQLException), no por error humano de credenciales.'
                elif 'bulkidentityguard' in codes_keys_lower or 'migration' in codes_keys_lower:
                    pattern_category = '☁️ Colisión de Migración IDaaS (Grid / Password / QA)'
                    pattern_root_cause = 'El usuario ya posee un autenticador activo (Grid Card, Password o Q&A) en el destino o la política del grupo restringe la sobreescritura durante la migración masiva.'
                elif u['errors'] > 0 and u['success'] > 0:
                    last_outcome = seq[-1]['outcome'] if seq else 'FAIL'
                    if last_outcome == 'SUCCESS':
                        pattern_category = '🔁 Auto-Recuperación (Fallo ➔ Éxito)'
                        pattern_root_cause = 'El usuario experimentó fricción inicial de autenticación (OTP/Password vencido o mal digitado) pero logró autenticarse exitosamente en un intento posterior.'
                    else:
                        pattern_category = '📉 Degradación de Sesión (Éxito ➔ Fallo)'
                        pattern_root_cause = 'El usuario operaba normalmente y comenzó a presentar rechazos consecutivos (posible bloqueo de cuenta 5201053, desincronización de Token o expiración de credencial).'
                elif u['errors'] >= 3 and u['success'] == 0:
                    pattern_category = '🚨 Ráfaga de Bloqueo / Fuerza Bruta Persistente'
                    pattern_root_cause = 'Múltiples intentos fallidos consecutivos sin ningún éxito registrado. Alto riesgo de bloqueo de cuenta (Lockout 5201053) o script automatizado con credenciales obsoletas.'
                elif u['errors'] > 0 and u['success'] == 0:
                    pattern_category = '⚠️ Fricción de Autenticación sin Recuperación'
                    pattern_root_cause = 'El usuario intentó autenticarse o enrolarse sin éxito y abandonó el flujo sin completar una transacción válida.'
                elif any(k.startswith('aud') for k in u['codes'].keys()):
                    pattern_category = '🛡️ Secuencia de Auditoría / Gestión Nominal'
                    pattern_root_cause = 'Trazas de auditoría administrativa o verificaciones nominales completadas sin errores.'
                else:
                    pattern_category = '✅ Operación Nominal Limpia (100% Éxito)'
                    pattern_root_cause = 'Todas las solicitudes registradas para este usuario finalizaron con estado SUCCESS.'

                cluster_key = f"{pattern_category}||{normalized_sig}"
                if cluster_key not in pattern_clusters_map:
                    pattern_clusters_map[cluster_key] = {
                        'signature': normalized_sig,
                        'category': pattern_category,
                        'rootCause': pattern_root_cause,
                        'userCount': 0,
                        'totalEvents': 0,
                        'errorEvents': 0,
                        'sampleUsers': []
                    }
                cl = pattern_clusters_map[cluster_key]
                cl['userCount'] += 1
                cl['totalEvents'] += u['total']
                cl['errorEvents'] += u['errors']
                if len(cl['sampleUsers']) < 30:
                    cl['sampleUsers'].append({
                        'user': uname,
                        'total': u['total'],
                        'errors': u['errors'],
                        'success': u['success']
                    })

                users_list_out.append({
                    'user': uname,
                    'total': u['total'],
                    'errors': u['errors'],
                    'success': u['success'],
                    'firstSeen': u['firstSeen'],
                    'lastSeen': u['lastSeen'],
                    'ips': list(u['ips'])[:5],
                    'codes': u['codes'],
                    'patternCategory': pattern_category,
                    'compressedPattern': compressed_pattern,
                    'normalizedSignature': normalized_sig,
                    'rootCause': pattern_root_cause,
                    'sequence': seq[:25]
                })

            pattern_clusters = sorted(
                pattern_clusters_map.values(),
                key=lambda c: (1 if c['errorEvents'] > 0 else 0, c['userCount'], c['totalEvents']),
                reverse=True
            )

            # 5. Finalize Code & Audit Pattern Matrix (Code <-> Users & Interactions)
            code_matrix = []
            for c_key, c_val in code_map.items():
                sorted_c_users = sorted(
                    c_val['usersDict'].values(),
                    key=lambda x: (x['count'], x['errors']),
                    reverse=True
                )
                code_matrix.append({
                    'code': c_val['code'],
                    'kind': c_val['kind'],
                    'totalInteractions': c_val['totalInteractions'],
                    'failCount': c_val['failCount'],
                    'successCount': c_val['successCount'],
                    'systemOnlyCount': c_val['systemOnlyCount'],
                    'uniqueUsersCount': len(sorted_c_users),
                    'users': sorted_c_users[:150]
                })
            code_matrix.sort(key=lambda x: (1 if x['failCount'] > 0 else 0, x['totalInteractions']), reverse=True)

            # 6. Database Health & Oracle/JDBC/SQLite Diagnostic
            cur.execute('''
                SELECT
                    SUM(CASE WHEN event_type = 'ORA-01555' OR message LIKE '%ORA-01555%' OR message LIKE '%snapshot too old%' THEN 1 ELSE 0 END) as ora_01555,
                    SUM(CASE WHEN event_type = 'ORA-00001' OR message LIKE '%ORA-00001%' OR message LIKE '%unique constraint%' THEN 1 ELSE 0 END) as ora_00001,
                    SUM(CASE WHEN event_type IN ('ORA-01000', 'ORA-02391') OR message LIKE '%ORA-01000%' OR message LIKE '%open cursors%' THEN 1 ELSE 0 END) as ora_01000,
                    SUM(CASE WHEN event_type IN ('ORA-03113', 'ORA-03114', 'ORA-12170', 'ORA-12514', 'ORA-12541') OR message LIKE '%ORA-03113%' OR message LIKE '%ORA-12170%' THEN 1 ELSE 0 END) as ora_net,
                    SUM(CASE WHEN event_type IN ('ORA-00060', 'ORA-00054') OR message LIKE '%ORA-00060%' OR message LIKE '%deadlock%' THEN 1 ELSE 0 END) as ora_lock,
                    SUM(CASE WHEN message LIKE '%JdbcCardRepository%' OR message LIKE '%BlobAccess%' THEN 1 ELSE 0 END) as jdbc_blob,
                    SUM(CASE WHEN event_type IN ('SQL_EXCEPTION', 'JDBC_SQL_EXCEPTION') OR message LIKE '%SQLException%' OR message LIKE '%HikariPool%' OR message LIKE '%Connection timed out%' THEN 1 ELSE 0 END) as sql_exc,
                    SUM(CASE WHEN message LIKE '%TransactionQueue%' THEN 1 ELSE 0 END) as tx_queue
                FROM logs
                WHERE event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%'
            ''')
            db_row = cur.fetchone() or (0, 0, 0, 0, 0, 0, 0, 0)
            ora_01555, ora_00001, ora_01000, ora_net, ora_lock, jdbc_blob, sql_exc, tx_queue = [int(x or 0) for x in db_row]
            total_db_incidents = ora_01555 + ora_00001 + ora_01000 + ora_net + ora_lock + jdbc_blob + sql_exc + tx_queue

            cur.execute('''
                SELECT line_num, event_time, subject_name, event_type, SUBSTR(message, 1, 220)
                FROM logs
                WHERE (event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%')
                  AND (event_type LIKE 'ORA-%' OR event_type IN ('SQL_EXCEPTION', 'JDBC_SQL_EXCEPTION') OR message LIKE '%ORA-%' OR message LIKE '%SQLException%' OR message LIKE '%JdbcCardRepository%' OR message LIKE '%TransactionQueue%')
                ORDER BY line_num ASC
                LIMIT 15
            ''')
            db_samples = [
                {'lineNum': r[0], 'timestamp': r[1], 'user': r[2], 'code': r[3], 'message': r[4]}
                for r in cur.fetchall()
            ]

            cur.execute('PRAGMA journal_mode;')
            wal_mode = (cur.fetchone() or ['unknown'])[0]

            db_health = {
                'status': 'CRITICAL' if (ora_01555 + ora_00001 + ora_01000 + ora_net + ora_lock + jdbc_blob + sql_exc) > 0 else ('WARNING' if tx_queue > 0 else 'HEALTHY'),
                'totalDbIncidents': total_db_incidents,
                'indicators': [
                    {
                        'code': 'ORA-01555 (Snapshot Too Old)',
                        'count': ora_01555,
                        'severity': 'CRÍTICO' if ora_01555 > 0 else 'OK',
                        'diagnosis': 'Agotamiento de UNDO Tablespace en Oracle durante lecturas largas de BLOB/Grid o backups concurrentes.' if ora_01555 > 0 else 'Sin errores de consistencia de lectura (UNDO saludable).',
                        'remediation': 'Incrementar UNDO_RETENTION (>= 3600s), ampliar UNDO Tablespace y evitar expurgos masivos en horario pico.'
                    },
                    {
                        'code': 'JdbcCardRepository / BlobAccess',
                        'count': jdbc_blob,
                        'severity': 'CRÍTICO' if jdbc_blob > 0 else 'OK',
                        'diagnosis': 'Fallo al deserializar o leer tarjetas Grid (BLOB) desde la base de datos de IdentityGuard.' if jdbc_blob > 0 else 'Lectura de objetos BLOB / Grid Cards sin anomalías.',
                        'remediation': 'Verificar integridad de columnas BLOB en tabla de tarjetas y descartar truncamiento de red JDBC.'
                    },
                    {
                        'code': 'SQLException / Pool JDBC',
                        'count': sql_exc,
                        'severity': 'ALTO' if sql_exc > 0 else 'OK',
                        'diagnosis': 'Excepciones SQL generales o agotamiento del pool de conexiones JDBC hacia el motor relacional.' if sql_exc > 0 else 'Pool de conexiones JDBC operando dentro de parámetros nominales.',
                        'remediation': 'Revisar maxPoolSize, connectionTimeout y latencia de red entre nodos Entrust y el servidor de BD.'
                    },
                    {
                        'code': 'ORA-00001 (Unique Constraint)',
                        'count': ora_00001,
                        'severity': 'MEDIO' if ora_00001 > 0 else 'OK',
                        'diagnosis': 'Intento de inserción duplicada de llave primaria/única (colisión de usuario, alias o serie de token).' if ora_00001 > 0 else 'Sin violaciones de unicidad detectadas.',
                        'remediation': 'Validar pre-existencia del registro o activar manejo idempotente antes de re-ejecutar lotes.'
                    },
                    {
                        'code': 'ORA-01000 / ORA-02391 (Cursores / Sesiones)',
                        'count': ora_01000,
                        'severity': 'ALTO' if ora_01000 > 0 else 'OK',
                        'diagnosis': 'Límite de cursores abiertos (OPEN_CURSORS) o sesiones concurrentes excedido en Oracle.' if ora_01000 > 0 else 'Consumo de cursores y sesiones dentro del límite.',
                        'remediation': 'Ajustar parámetro OPEN_CURSORS en Oracle y verificar cierre de PreparedStatements.'
                    },
                    {
                        'code': 'ORA-03113 / ORA-12170 (Corte de Red TNS)',
                        'count': ora_net,
                        'severity': 'CRÍTICO' if ora_net > 0 else 'OK',
                        'diagnosis': 'Desconexión abrupta del canal TCP/TNS con Oracle (Firewall timeout o caída de instancia).' if ora_net > 0 else 'Enlace de red hacia la base de datos estable.',
                        'remediation': 'Habilitar SQLNET.EXPIRE_TIME (Dead Connection Detection) y validación testOnBorrow en el pool.'
                    },
                    {
                        'code': 'ORA-00060 / ORA-00054 (Deadlock / Lock)',
                        'count': ora_lock,
                        'severity': 'ALTO' if ora_lock > 0 else 'OK',
                        'diagnosis': 'Bloqueo mutuo (Deadlock) o contención de filas por transacciones concurrentes sobre el mismo usuario.' if ora_lock > 0 else 'Sin bloqueos transaccionales (Deadlocks) en base de datos.',
                        'remediation': 'Serializar actualizaciones por usuario en procesos batch y reducir el tiempo de transacción abierta.'
                    },
                    {
                        'code': 'TransactionQueue.API (Cola Asíncrona)',
                        'count': tx_queue,
                        'severity': 'ADVERTENCIA' if tx_queue > 0 else 'OK',
                        'diagnosis': 'Encolamiento o retraso en el vaciado asíncrono de auditoría hacia la base de datos.' if tx_queue > 0 else 'Cola de transacciones de auditoría sin retrasos.',
                        'remediation': 'Revisar IOPS de almacenamiento en tablas de auditoría e índices asociados.'
                    }
                ],
                'sqliteEngine': {
                    'dbFile': os.path.basename(db),
                    'dbPath': db,
                    'sizeMb': round(os.path.getsize(db) / (1024 * 1024), 2),
                    'totalRowsIndexed': total_logs,
                    'totalErrorsIndexed': total_errors,
                    'journalMode': wal_mode,
                    'uniqueValidUsers': len(users_map),
                    'filteredNoiseTokens': len(filtered_noise_users),
                    'filteredNoiseEvents': filtered_noise_events,
                    'sampleNoiseTokens': sorted(list(filtered_noise_users))[:20]
                },
                'evidenceSamples': db_samples
            }

            # 6.5 Tomcat / Catalina / JVM Health (exact counts from indexed events)
            cur.execute('''
                SELECT
                    SUM(CASE WHEN event_type = 'JVM_OOM' THEN 1 ELSE 0 END) as jvm_oom,
                    SUM(CASE WHEN event_type = 'TOMCAT_SSL_TLS' THEN 1 ELSE 0 END) as ssl_tls,
                    SUM(CASE WHEN event_type = 'TOMCAT_LDAP_ERROR' THEN 1 ELSE 0 END) as ldap_err,
                    SUM(CASE WHEN event_type = 'TOMCAT_DEPLOY_ERROR' THEN 1 ELSE 0 END) as deploy_err,
                    SUM(CASE WHEN event_type = 'TOMCAT_NETWORK_ERROR' THEN 1 ELSE 0 END) as net_err,
                    SUM(CASE WHEN event_type = 'TOMCAT_THREAD_POOL' THEN 1 ELSE 0 END) as thread_pool,
                    SUM(CASE WHEN event_type = 'TOMCAT_CLIENT_ABORT' THEN 1 ELSE 0 END) as client_abort,
                    SUM(CASE WHEN event_type = 'TOMCAT_JAVA_EXCEPTION' THEN 1 ELSE 0 END) as java_exc,
                    SUM(CASE WHEN event_type = 'TOMCAT_SEVERE' THEN 1 ELSE 0 END) as tomcat_severe,
                    SUM(CASE WHEN event_type = 'TOMCAT_WARN' THEN 1 ELSE 0 END) as tomcat_warn,
                    SUM(CASE WHEN event_type = 'TOMCAT_LIFECYCLE' THEN 1 ELSE 0 END) as tomcat_lifecycle
                FROM logs
            ''')
            tc_row = cur.fetchone() or (0,) * 11
            (
                tc_oom, tc_ssl, tc_ldap, tc_deploy, tc_net,
                tc_pool, tc_abort, tc_java, tc_severe, tc_warn, tc_lifecycle
            ) = [int(x or 0) for x in tc_row]
            total_tomcat_errors = tc_oom + tc_ssl + tc_ldap + tc_deploy + tc_net + tc_java + tc_severe + (
                sum(c['failCount'] for c in code_matrix if c['code'] == 'TOMCAT_THREAD_POOL')
            )
            total_tomcat_incidents = total_tomcat_errors + tc_warn + tc_abort + tc_lifecycle

            cur.execute('''
                SELECT line_num, event_time, event_type, event_outcome, SUBSTR(message, 1, 240)
                FROM logs
                WHERE event_type LIKE 'TOMCAT_%' OR event_type LIKE 'JVM_%' OR event_type = 'JDBC_SQL_EXCEPTION'
                ORDER BY CASE
                    WHEN event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%' THEN 0
                    WHEN event_outcome LIKE '%WARN%' THEN 1
                    ELSE 2
                END, line_num ASC
                LIMIT 15
            ''')
            tc_samples = [
                {'lineNum': r[0], 'timestamp': r[1], 'code': r[2], 'outcome': r[3], 'message': r[4]}
                for r in cur.fetchall()
            ]

            tomcat_health = {
                'status': 'CRITICAL' if (tc_oom + tc_ssl + tc_deploy + tc_net + tc_ldap) > 0 else ('WARNING' if (total_tomcat_errors + tc_warn) > 0 else 'HEALTHY'),
                'totalTomcatIncidents': total_tomcat_incidents,
                'totalTomcatErrors': total_tomcat_errors,
                'clientAbortsIgnored': tc_abort,
                'indicators': [
                    {'code': 'JVM_OOM (Heap / Metaspace / GC)', 'count': tc_oom, 'severity': 'CRÍTICO' if tc_oom > 0 else 'OK'},
                    {'code': 'TOMCAT_SSL_TLS (Keystore / PKIX / Handshake)', 'count': tc_ssl, 'severity': 'CRÍTICO' if tc_ssl > 0 else 'OK'},
                    {'code': 'TOMCAT_LDAP_ERROR (Directorio JNDI / LDAPS)', 'count': tc_ldap, 'severity': 'ALTO' if tc_ldap > 0 else 'OK'},
                    {'code': 'TOMCAT_DEPLOY_ERROR (Lifecycle / listenerStart / JARs)', 'count': tc_deploy, 'severity': 'CRÍTICO' if tc_deploy > 0 else 'OK'},
                    {'code': 'TOMCAT_NETWORK_ERROR (Bind / SocketTimeout / Connect)', 'count': tc_net, 'severity': 'ALTO' if tc_net > 0 else 'OK'},
                    {'code': 'TOMCAT_THREAD_POOL (StuckThread / maxThreads)', 'count': tc_pool, 'severity': 'ADVERTENCIA' if tc_pool > 0 else 'OK'},
                    {'code': 'TOMCAT_JAVA_EXCEPTION (Excepciones Java)', 'count': tc_java, 'severity': 'ALTO' if tc_java > 0 else 'OK'},
                    {'code': 'TOMCAT_SEVERE (Otros errores SEVERE)', 'count': tc_severe, 'severity': 'ALTO' if tc_severe > 0 else 'OK'},
                    {'code': 'TOMCAT_WARN (Advertencias Catalina)', 'count': tc_warn, 'severity': 'ADVERTENCIA' if tc_warn > 0 else 'OK'},
                    {'code': 'TOMCAT_CLIENT_ABORT (Cierre cliente HTTP, no error servidor)', 'count': tc_abort, 'severity': 'INFO'},
                    {'code': 'TOMCAT_LIFECYCLE (Arranque / Parada servidor)', 'count': tc_lifecycle, 'severity': 'INFO'}
                ],
                'evidenceSamples': tc_samples
            }

            # 7. Automated Post-Mortem Forensic Summary
            cur.execute('''
                SELECT MIN(event_time), MAX(event_time)
                FROM logs
                WHERE event_time IS NOT NULL AND event_time != ''
            ''')
            t_bounds = cur.fetchone() or ('N/A', 'N/A')

            cur.execute('''
                SELECT SUBSTR(event_time, 1, 13) as hr, COUNT(1) as err_cnt
                FROM logs
                WHERE (event_outcome LIKE '%FAIL%' OR event_outcome LIKE '%ERR%')
                  AND event_time IS NOT NULL AND event_time != ''
                GROUP BY hr
                ORDER BY err_cnt DESC
                LIMIT 5
            ''')
            peak_hours = [{'hour': r[0], 'errors': r[1]} for r in cur.fetchall()]

            migration_errors = sum(c['failCount'] for c in code_matrix if c['kind'] == 'IDAAS_MIGRATION')
            auth_520_errors = sum(c['failCount'] for c in code_matrix if c['kind'] == 'ERROR_520')
            tomcat_jvm_errors = sum(c['failCount'] for c in code_matrix if c['kind'] == 'TOMCAT_JVM')

            if tomcat_jvm_errors > max(total_db_incidents, migration_errors, auth_520_errors) and tomcat_jvm_errors > 0:
                primary_vector = 'SERVIDOR DE APLICACIONES TOMCAT / JVM (catalina.out)'
                executive_verdict = (
                    f'La mayor concentración de fallos proviene del contenedor Apache Tomcat / JVM '
                    f'({tomcat_jvm_errors:,} incidentes clasificados tras agrupar stack traces Java, '
                    f'con {total_db_incidents:,} incidentes BD/JDBC y {auth_520_errors:,} eventos 520xxx).'
                )
            elif total_db_incidents > max(migration_errors, auth_520_errors) and total_db_incidents > 0:
                primary_vector = 'INFRAESTRUCTURA / BASE DE DATOS (Oracle / JDBC)'
                executive_verdict = f'Se confirmó que la causa primaria de degradación proviene de la capa de Base de Datos ({total_db_incidents:,} incidentes de persistencia/ORA detectados). Los fallos de usuarios asociados son síntoma secundario de interrupción de lectura/escritura en BD.'
            elif migration_errors > 0 and migration_errors >= auth_520_errors:
                primary_vector = 'COLISIÓN DE MIGRACIÓN / APROVISIONAMIENTO (IDaaS / BulkIG)'
                executive_verdict = f'No se detecta corrupción en la base de datos local ({total_db_incidents:,} errores ORA críticos). El {round((migration_errors / max(1, total_errors)) * 100, 1)}% de los errores ({migration_errors:,} eventos) responde a colisiones de objetos preexistentes durante la migración (Grid Cards asignadas, Passwords o Q&A).'
            elif auth_520_errors > 0:
                primary_vector = 'FRICCIÓN DE AUTENTICACIÓN Y BLOQUEO DE CUENTAS (Códigos 520xxx)'
                executive_verdict = f'La base de datos opera estable ({total_db_incidents:,} errores de BD). Los rechazos se concentran en validaciones de credenciales y bloqueos preventivos de seguridad ({auth_520_errors:,} eventos 520xxx sobre {len(users_map):,} usuarios únicos).'
            else:
                primary_vector = 'OPERACIÓN NOMINAL / EVENTOS ADMINISTRATIVOS'
                executive_verdict = f'Operación general estable sobre {total_logs:,} registros analizados y {len(users_map):,} usuarios nominales identificados.'

            post_mortem = {
                'startTime': t_bounds[0] or 'N/A',
                'endTime': t_bounds[1] or 'N/A',
                'peakHours': peak_hours,
                'primaryVector': primary_vector,
                'executiveVerdict': executive_verdict,
                'breakdown': {
                    'databaseIncidents': total_db_incidents,
                    'tomcatJvmErrors': tomcat_jvm_errors,
                    'migrationCollisions': migration_errors,
                    'authentication520Errors': auth_520_errors,
                    'otherSystemErrors': max(0, total_errors - (total_db_incidents + migration_errors + auth_520_errors + tomcat_jvm_errors))
                },
                'officialPortals': [
                    {
                        'name': 'Entrust TrustedCare Portal (Knowledge Base & Support Cases)',
                        'url': 'https://trustedcare.entrust.com',
                        'description': 'Portal oficial de soporte técnico Entrust, boletines de seguridad, parches de IdentityGuard / IDaaS y resolución de códigos ORA / 520xxx.'
                    },
                    {
                        'name': 'Entrust Identity as a Service (IDaaS) & IdentityGuard Documentation',
                        'url': 'https://docs.trustedauth.com',
                        'description': 'Documentación técnica oficial de APIs, Bulk Migration Tool, códigos de auditoría AUD y matrices de autenticación.'
                    }
                ]
            }

            volumetry_by_kind = {}
            for c_item in code_matrix:
                ck = c_item.get('kind') or 'SYSTEM_EVENT'
                if ck not in volumetry_by_kind:
                    volumetry_by_kind[ck] = {'uniqueCodes': 0, 'totalInteractions': 0, 'failCount': 0, 'successCount': 0}
                volumetry_by_kind[ck]['uniqueCodes'] += 1
                volumetry_by_kind[ck]['totalInteractions'] += int(c_item.get('totalInteractions', 0) or 0)
                volumetry_by_kind[ck]['failCount'] += int(c_item.get('failCount', 0) or 0)
                volumetry_by_kind[ck]['successCount'] += int(c_item.get('successCount', 0) or 0)

            volumetry_summary = {
                'totalUniqueCodes': len(code_matrix),
                'errorCodeTypes': sum(1 for c in code_matrix if c.get('failCount', 0) > 0 or c.get('kind') in ('ERROR_520', 'DATABASE_ORA')),
                'byKind': volumetry_by_kind
            }

            result_payload = {
                'status': 'ready',
                'activeDb': os.path.basename(db),
                'dbSizeMb': round(os.path.getsize(db) / (1024 * 1024), 2),
                'totalLogs': total_logs,
                'totalErrors': total_errors,
                'totalSuccess': max(0, total_logs - total_errors),
                'uniqueValidUsers': len(users_map),
                'usersWithErrors': sum(1 for u in users_map.values() if u['errors'] > 0),
                'usersClean': sum(1 for u in users_map.values() if u['errors'] == 0),
                'categoryUniqueUsers': {
                    'audit': len(cat_users['audit']),
                    '520': len(cat_users['520']),
                    'idaas': len(cat_users['idaas']),
                    'system': len(cat_users['system']),
                    'traffic': len(cat_users['traffic']),
                    'errorsAll': len(cat_users['errors_all']),
                    'all': len(users_map)
                },
                'volumetrySummary': volumetry_summary,
                'filteredNoiseUsers': len(filtered_noise_users),
                'filteredNoiseEvents': filtered_noise_events,
                'usersList': users_list_out,
                'patternClusters': pattern_clusters,
                'codeMatrix': code_matrix,
                'dbHealth': db_health,
                'tomcatHealth': tomcat_health,
                'postMortem': post_mortem
            }

            try:
                cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('forensic_matrix_v5', json.dumps(result_payload, ensure_ascii=False)))
                conn.commit()
            except Exception:
                pass

            conn.close()
            self.send_json(result_payload)
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error'}, status=500)

    def _resolve_pcap_db(self, client_param=None):
        slug = get_client_slug(client_param) if client_param else 'general'
        cand = os.path.join(DATA_DIR, f'pcap_{slug}.db')
        if os.path.exists(cand):
            return cand
        if not client_param and ACTIVE_DB_PATH:
            active_base = os.path.basename(ACTIVE_DB_PATH).replace('_audit.db', '')
            cand2 = os.path.join(DATA_DIR, f'pcap_{active_base}.db')
            if os.path.exists(cand2):
                return cand2
        return cand

    def _run_pcap_job_in_background(self, file_path, client_name):
        global pcap_upload_state
        if pcap_analyzer is None:
            pcap_upload_state['status'] = 'error'
            pcap_upload_state['error'] = 'Módulo pcap_analyzer no disponible en el servidor.'
            return
        client_slug = get_client_slug(client_name)
        target_pcap_db = os.path.join(DATA_DIR, f'pcap_{client_slug}.db')
        pcap_upload_state['status'] = 'analyzing'
        pcap_upload_state['fileName'] = os.path.basename(file_path)
        pcap_upload_state['clientName'] = client_name
        pcap_upload_state['clientSlug'] = client_slug
        pcap_upload_state['packetsProcessed'] = 0
        pcap_upload_state['bytesProcessed'] = 0
        pcap_upload_state['error'] = None
        pcap_upload_state['dbPath'] = target_pcap_db

        def _on_prog(pkts, bts):
            pcap_upload_state['packetsProcessed'] = pkts
            pcap_upload_state['bytesProcessed'] = bts

        try:
            summary = pcap_analyzer.analyze_pcap_to_sqlite(file_path, target_pcap_db, progress_callback=_on_prog)
            pcap_upload_state['packetsProcessed'] = summary.get('totalPackets', 0)
            pcap_upload_state['bytesProcessed'] = summary.get('totalBytes', 0)
            pcap_upload_state['status'] = 'ready'
        except Exception as e:
            pcap_upload_state['status'] = 'error'
            pcap_upload_state['error'] = str(e)
            print(f'Error analizando PCAP {file_path}: {e}')

    def handle_pcap_upload(self):
        try:
            if pcap_analyzer is None:
                self.send_json({'error': 'Módulo pcap_analyzer no disponible'}, status=500)
                return
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 25 * 1024 * 1024:
                self.send_json({'error': 'Chunk PCAP excede el límite máximo permitido de 25 MB'}, status=413)
                return
            chunk_data = self.rfile.read(content_length)
            chunk_index = int(self.headers.get('X-Chunk-Index', 0))
            total_chunks = int(self.headers.get('X-Total-Chunks', 1))
            file_name = urllib.parse.unquote(self.headers.get('X-File-Name', 'capture.pcap'))
            client_name = urllib.parse.unquote(self.headers.get('X-Client-Name', 'Entrust Client'))

            safe_file_name = re.sub(r'[^a-zA-Z0-9_\.-]', '_', os.path.basename(file_name))
            if not safe_file_name or safe_file_name.lower().endswith(self.BLOCKED_EXTENSIONS):
                self.send_json({'error': 'Extensión de archivo bloqueada por directiva de seguridad'}, status=403)
                return
            temp_path = os.path.join(UPLOADS_DIR, safe_file_name)
            mode = 'wb' if chunk_index == 0 else 'ab'
            with open(temp_path, mode) as f:
                f.write(chunk_data)

            pct = int(((chunk_index + 1) / max(1, total_chunks)) * 100)
            pcap_upload_state['fileName'] = file_name
            pcap_upload_state['clientName'] = client_name
            pcap_upload_state['clientSlug'] = get_client_slug(client_name)
            pcap_upload_state['status'] = 'uploading'
            pcap_upload_state['error'] = None

            if chunk_index >= total_chunks - 1:
                pcap_upload_state['status'] = 'analyzing'
                thread = threading.Thread(target=self._run_pcap_job_in_background, args=(temp_path, client_name))
                thread.daemon = True
                thread.start()

            self.send_json({'success': True, 'chunkIndex': chunk_index, 'progress': pct})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_pcap_analyze_server_file(self):
        try:
            if pcap_analyzer is None:
                self.send_json({'error': 'Módulo pcap_analyzer no disponible'}, status=500)
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
            payload = json.loads(body_data) if body_data else {}
            raw_path = str(payload.get('filePath', '')).strip()
            client_name = str(payload.get('clientName', 'Banco Mercantil C.A.')).strip() or 'Banco Mercantil C.A.'
            safe_basename = os.path.basename(raw_path)
            if not safe_basename or safe_basename.lower().endswith(self.BLOCKED_EXTENSIONS):
                self.send_json({'error': 'Nombre o extensión de captura inválida.'}, status=403)
                return

            resolved = None
            for d in (UPLOADS_DIR, DATA_DIR, BASE_DIR):
                cand = os.path.abspath(os.path.join(d, safe_basename))
                if cand.startswith(os.path.abspath(d) + os.sep) and os.path.isfile(cand):
                    resolved = cand
                    break
            if not resolved:
                self.send_json({'error': f'Archivo PCAP no encontrado en uploads/data: {safe_basename}'}, status=404)
                return

            thread = threading.Thread(target=self._run_pcap_job_in_background, args=(resolved, client_name))
            thread.daemon = True
            thread.start()
            self.send_json({'success': True, 'status': 'analyzing', 'fileName': safe_basename})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_pcap_summary(self, query):
        if pcap_analyzer is None:
            self.send_json({'error': 'Módulo pcap_analyzer no disponible', 'status': 'error'}, status=500)
            return
        client_param = query.get('client', [None])[0]
        pcap_db = self._resolve_pcap_db(client_param)
        try:
            self.send_json(pcap_analyzer.query_pcap_summary(pcap_db))
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error'}, status=500)

    def handle_pcap_packets(self, query):
        if pcap_analyzer is None:
            self.send_json({'error': 'Módulo pcap_analyzer no disponible', 'status': 'error'}, status=500)
            return
        client_param = query.get('client', [None])[0]
        page = max(1, int(query.get('page', ['1'])[0]))
        limit = min(500, max(10, int(query.get('limit', ['100'])[0])))
        q_str = query.get('q', [''])[0].strip()
        proto = query.get('proto', ['ALL'])[0].strip()
        severity = query.get('severity', ['ALL'])[0].strip()
        flow = query.get('flow', [''])[0].strip()
        pcap_db = self._resolve_pcap_db(client_param)
        try:
            self.send_json(pcap_analyzer.query_pcap_packets(pcap_db, page=page, limit=limit, q=q_str, proto=proto, severity=severity, flow=flow))
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error', 'packets': []}, status=500)

    def handle_pcap_correlate(self, query):
        if pcap_analyzer is None:
            self.send_json({'error': 'Módulo pcap_analyzer no disponible', 'status': 'error'}, status=500)
            return
        client_param = query.get('client', [None])[0]
        window_sec = max(1, min(300, int(query.get('window', ['5'])[0])))
        pcap_db = self._resolve_pcap_db(client_param)
        logs_db = resolve_client_db(client_param)
        try:
            self.send_json(pcap_analyzer.correlate_pcap_with_entrust_logs(pcap_db, logs_db, window_sec=window_sec))
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error', 'correlations': []}, status=500)

    def handle_pcap_export_csv(self, query):
        if pcap_analyzer is None:
            self.send_json({'error': 'Módulo pcap_analyzer no disponible'}, status=500)
            return
        client_param = query.get('client', [None])[0]
        exp_type = query.get('type', ['anomalies'])[0].strip().lower()
        pcap_db = self._resolve_pcap_db(client_param)
        try:
            csv_bytes = pcap_analyzer.export_pcap_csv(pcap_db, export_type=exp_type)
            slug = get_client_slug(client_param or 'capture')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="PCAP_{exp_type}_{slug}.csv"')
            self.send_header('Content-Length', str(len(csv_bytes)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(csv_bytes)
        except Exception as e:
            self.send_json({'error': str(e), 'status': 'error'}, status=500)

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

class ReusableHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                pass
        super().server_bind()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--ingest':
        if len(sys.argv) < 3:
            print("Uso: python server.py --ingest <ruta_archivo> [--client <nombre_cliente>]")
            sys.exit(1)
        file_to_ingest = sys.argv[2]
        c_name = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == '--client' else 'Entrust Client'
        print(f"Indexando archivo: {file_to_ingest} para cliente: {c_name}...")
        index_file_in_background(file_to_ingest, c_name)
        sys.exit(0)

    # Liberar puerto 8085 si quedó ocupado por un proceso zombie
    if sys.platform != 'win32':
        os.system(f'fuser -k {PORT}/tcp 2>/dev/null || kill -9 $(lsof -t -i:{PORT} 2>/dev/null) 2>/dev/null || true')
        time.sleep(0.5)

    http.server.HTTPServer.allow_reuse_address = True
    
    server = None
    for attempt in range(5):
        try:
            server = ReusableHTTPServer(('0.0.0.0', PORT), DiagnosticRequestHandler)
            threading.Thread(target=build_manuals_index, daemon=True).start()
            print(f'✅ Servidor API & Dashboard ACTIVO en http://0.0.0.0:{PORT}')
            server.serve_forever()
            break
        except OSError as e:
            if 'Address already in use' in str(e) or getattr(e, 'errno', None) == 98:
                if attempt < 4:
                    print(f"⚠️ Puerto {PORT} ocupado. Liberando puerto automáticamente (intento {attempt + 1}/5)...")
                    if sys.platform != 'win32':
                        os.system(f'fuser -k {PORT}/tcp 2>/dev/null || kill -9 $(lsof -t -i:{PORT} 2>/dev/null) 2>/dev/null || true')
                    time.sleep(1)
                else:
                    print(f"ℹ️ El puerto {PORT} ya se encuentra activo y atendiendo solicitudes en segundo plano.")
                    print(f"🌐 Puedes abrir el navegador en: http://10.16.13.175:{PORT}")
                    sys.exit(0)
            else:
                raise e
