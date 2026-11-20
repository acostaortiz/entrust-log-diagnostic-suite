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
from html.parser import HTMLParser

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
MANUALS_INDEX_BUILT = False
MANUALS_INDEX_BUILDING = False
MANUALS_INDEX_LOCK = threading.Lock()
MANUALS_CACHE_PATH = os.path.join(BASE_DIR, 'manuals', 'manuals_index_cache.json.gz')

MANUALS_STOP_WORDS = {
    'de', 'la', 'el', 'los', 'las', 'un', 'una', 'unos', 'unas', 'en', 'y', 'o',
    'a', 'por', 'para', 'con', 'sin', 'sobre', 'que', 'como', 'cual', 'cuales',
    'donde', 'cuando', 'es', 'son', 'esta', 'estan', 'hay', 'ser', 'tener',
    'hacer', 'hago', 'puedo', 'debo', 'error', 'errores', 'log', 'logs',
    'the', 'and', 'or', 'for', 'with', 'how', 'what', 'why', 'when', 'where',
    'this', 'that', 'from', 'into', 'your', 'entrust', 'identityguard'
}

def _detect_manual_version(rel_path):
    p = rel_path.lower()
    if 'ig_130' in p or '130' in p:
        return 'IG 13.0'
    if 'ig_120' in p or '120' in p:
        return 'IG 12.0'
    if 'ig_110' in p or '110' in p:
        return 'IG 11.0'
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

def build_manuals_index():
    global MANUALS_INDEX, MANUALS_INDEX_BUILT, MANUALS_INDEX_BUILDING
    with MANUALS_INDEX_LOCK:
        if MANUALS_INDEX_BUILT:
            return len(MANUALS_INDEX)
        MANUALS_INDEX_BUILDING = True
    try:
        if os.path.exists(MANUALS_CACHE_PATH):
            try:
                with gzip.open(MANUALS_CACHE_PATH, 'rt', encoding='utf-8') as f:
                    cached = json.load(f)
                if isinstance(cached, list) and len(cached) > 0:
                    for item in cached:
                        item['title_lower'] = (item.get('title') or '').lower()
                        item['text_lower'] = (item.get('text') or '').lower()
                    with MANUALS_INDEX_LOCK:
                        MANUALS_INDEX = cached
                        MANUALS_INDEX_BUILT = True
                        MANUALS_INDEX_BUILDING = False
                    return len(MANUALS_INDEX)
            except Exception:
                pass

        manuals_dir = os.path.join(BASE_DIR, 'manuals')
        if not os.path.isdir(manuals_dir):
            with MANUALS_INDEX_LOCK:
                MANUALS_INDEX_BUILT = True
                MANUALS_INDEX_BUILDING = False
            return 0
        skip_names = {'toc.htm', 'index.htm', 'index_csh.htm', 'reference.htm', 'whskin_'}
        skip_dirs = {'whdata', 'whgdata', 'whxdata', 'template'}
        entries = []
        processed_files = 0
        for root, dirs, files in os.walk(manuals_dir):
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
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
        with MANUALS_INDEX_LOCK:
            MANUALS_INDEX = entries
            MANUALS_INDEX_BUILT = True
            MANUALS_INDEX_BUILDING = False
        return len(MANUALS_INDEX)
    except Exception:
        with MANUALS_INDEX_LOCK:
            MANUALS_INDEX_BUILDING = False
        return 0

def search_manuals(query_str, version_filter=None, limit=6):
    if not MANUALS_INDEX_BUILT:
        if not MANUALS_INDEX_BUILDING:
            threading.Thread(target=build_manuals_index, daemon=True).start()
        return []
    q_raw = (query_str or '').strip()
    if not q_raw:
        return []
    q_lower = q_raw.lower()
    codes = re.findall(r'(?:520\d{4}|aud\d+|ora-\d+|s3-404)', q_lower)
    raw_tokens = re.findall(r'[a-z0-9_.\-]{3,}', q_lower)
    tokens = [t for t in raw_tokens if t not in MANUALS_STOP_WORDS]
    if not tokens and codes:
        tokens = codes
    if not tokens:
        tokens = raw_tokens[:4]

    scored = []
    for doc in MANUALS_INDEX:
        if version_filter and version_filter.lower() not in doc['version'].lower():
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
        if doc['version'] in ('IG 13.0', 'KB Errores', 'IDaaS Cloud'):
            score += 5

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

def clear_active_session():
    global ACTIVE_DB_PATH
    ACTIVE_DB_PATH = None
    sess_file = os.path.join(DATA_DIR, 'active_session.json')
    if os.path.exists(sess_file):
        try:
            os.remove(sess_file)
        except Exception:
            pass

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
    'number', 'level', 'category', 'source', 'target', 'subject', 'object', 'context'
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

def parse_line_for_db(line, line_num):
    if not line:
        return None
    
    # 1. Check IDaaS Cloud Migration Tool format: [ERROR] IdentityGuard migration: ...
    if 'IdentityGuard migration:' in line:
        outcome = 'FAIL' if any(k in line for k in ['[ERROR]', 'error', 'fail', 'already']) else 'SUCCESS'
        event_time = time.strftime('%Y-%m-%d %H:%M:%S')
        time_match = re.search(r'\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
        if time_match:
            event_time = time_match.group(0)
        
        user = extract_valid_user(line)
            
        if 'grid already assigned' in line.lower() or 'assignedgrid' in line.lower():
            event_type = 'bulkidentityguard.add.error.assignedgrid'
        elif 'currently has a password' in line.lower() or 'password will not be migrated' in line.lower():
            event_type = 'bulkidentityguard.add.error.password'
        elif 'already has qa' in line.lower() or 'qa in migration file' in line.lower():
            event_type = 'bulkidentityguard.add.error.qa'
        else:
            event_type = 'IDG_MIGRATION_EVENT'
            
        return (line_num, event_time, user, event_type, outcome, line[:300], 'idaas.entrust.com', line[:500])

    # 1.5. Check IDaaS Cloud CSV / TSV format (strictly validated to avoid matching stack traces or SQL lines)
    if (',' in line or '\t' in line) and not line.startswith('[') and not line.startswith('\t') and not line.startswith('Caused by:'):
        parts = line.split('\t') if '\t' in line else [p.strip().strip('"') for p in line.split(',')]
        if len(parts) >= 8 and parts[0].lower() != 'id':
            col1_is_date = bool(re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}T', parts[1].strip())) if len(parts) > 1 else False
            col8_upper = parts[8].strip().upper() if len(parts) > 8 else ''
            col8_is_outcome = col8_upper in ('SUCCESS', 'FAIL', 'FAILURE', 'ERROR', 'WARNING', 'INFO')
            if col1_is_date and col8_is_outcome:
                event_time = parts[1].replace('T', ' ').replace('Z', '')[:19] if len(parts) > 1 else ''
                raw_user = parts[4].strip() if len(parts) > 4 else ''
                user = raw_user if is_valid_user_candidate(raw_user) else 'system'
                event_type = parts[7].strip() if len(parts) > 7 and parts[7].strip() else 'IDaaS.Audit'
                outcome = 'FAIL' if col8_upper in ('FAIL', 'FAILURE', 'ERROR') else ('SUCCESS' if col8_upper else 'SUCCESS')
                msg = parts[9].strip() if len(parts) > 9 else event_type
                ip = parts[12].strip() if len(parts) > 12 else ''
                return (line_num, event_time, user, event_type, outcome, msg, ip, line[:500])

    # 2. Check Entrust Bracket format: [timestamp] [thread] [LEVEL] [Category] [520xxx/AUD] Message
    bracket_match = re.match(r'^\[([^\]]+)\]\s*\[([^\]]*)\]\s*\[([A-Za-z]+)\s*\]\s*\[([^\]]*)\]\s*(.*)$', line)
    if bracket_match:
        event_time = bracket_match.group(1)[:19]
        level = bracket_match.group(3).upper()
        category = bracket_match.group(4)
        msg = bracket_match.group(5)
        outcome = 'FAIL' if any(k in level for k in ['ERR', 'CRIT', 'FATAL']) else ('DEBUG' if level == 'DEBUG' else 'SUCCESS')
        
        c520 = re.search(r'520\d{4}', msg) or re.search(r'520\d{4}', line)
        aud = re.search(r'AUD\d{3,4}', msg) or re.search(r'AUD\d{3,4}', line)
        ora = re.search(r'ORA-\d{5}', msg) or re.search(r'ORA-\d{5}', line)

        if c520 or ora or (aud and aud.group(0).upper() in ('AUD150', 'AUD154', 'AUD6002')):
            outcome = 'FAIL'
        elif aud and aud.group(0).upper() in ('AUD6001', 'AUD2309', 'AUD155') and outcome != 'FAIL':
            outcome = 'WARN'

        if c520:
            event_type = c520.group(0)
        elif aud:
            event_type = aud.group(0)
        elif ora:
            event_type = ora.group(0)
        elif category:
            event_type = category.split('.')[-2] if '.' in category else category
        else:
            event_type = 'ENTRUST_LOG'
        
        user = extract_valid_user(line, msg)
        
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
        ip = ip_match.group(0) if ip_match else 'local'
        
        return (line_num, event_time, user, event_type, outcome, msg, ip, line[:500])

    # 3. Check for SQL Exception / ORA Error Stack Trace lines
    ora_match = re.search(r'ORA-\d{5}', line)
    is_stack = line.startswith('\tat ') or line.startswith('Caused by:') or 'SQLException' in line or ora_match
    if is_stack:
        ora_code = ora_match.group(0) if ora_match else 'SQL_EXCEPTION'
        return (line_num, time.strftime('%Y-%m-%d %H:%M:%S'), 'system', ora_code, 'FAIL', line.strip()[:300], 'database', line[:500])

    # 4. Fallback generic line
    level = 'FAIL' if any(k in line.lower() for k in ['error', 'fail', 'crit', 'fatal', 'exception']) else 'SUCCESS'
    time_match = re.search(r'\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
    event_time = time_match.group(0) if time_match else time.strftime('%Y-%m-%d %H:%M:%S')
    user = extract_valid_user(line)
    return (line_num, event_time, user, 'SYSTEM_LOG', level, line[:200], 'local', line[:500])

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
        if not append_mode and os.path.exists(target_db):
            try:
                os.remove(target_db)
            except Exception:
                pass

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
        bytes_est = 0

        for line in stream_lines_from_archive_or_file(file_path):
            line_str = line.strip()
            if not line_str:
                continue
            line_num += 1
            file_lines += 1
            bytes_est += len(line)

            parsed = parse_line_for_db(line_str, line_num)
            if parsed:
                outcome = str(parsed[4] or '')
                etype = str(parsed[3] or '')
                is_err = 'FAIL' in outcome or 'ERR' in outcome
                is_warn = (not is_err) and ('WARN' in outcome or etype.upper().startswith('AUD'))
                if is_err:
                    file_errors += 1
                elif is_warn:
                    file_warnings += 1

                # In-memory streaming aggregation (0 cost)
                user = parsed[2]
                if user and user not in ['unknown', 'system', '']:
                    user_counts[user] += 1

                ip = parsed[6]
                if ip and ip not in ['local', '127.0.0.1', '']:
                    ip_counts[ip] += 1

                if etype:
                    type_counts[etype] += 1
                    code_counts[etype] += 1
                    if 'bulkidentityguard' in etype.lower():
                        is_idaas = True

                t_str = parsed[1]
                if t_str and len(t_str) >= 13:
                    h_bucket = t_str[:13]
                    hour_counts[h_bucket]['total'] += 1
                    if is_err:
                        hour_counts[h_bucket]['errors'] += 1
                    else:
                        hour_counts[h_bucket]['info'] += 1

                batch.append(parsed)

            if len(batch) >= batch_size:
                cur.executemany('INSERT OR REPLACE INTO logs VALUES (?,?,?,?,?,?,?,?)', batch)
                conn.commit()
                batch = []
                upload_state['linesProcessed'] = prev_total + file_lines
                upload_state['totalErrors'] = prev_errors + file_errors
                upload_state['progress'] = min(99, int((bytes_est / max(1, file_size)) * 100))

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

        file_entry = {
            'name': os.path.basename(file_path),
            'size': file_size,
            'count': file_lines,
            'sampleCount': file_lines,
            'realErrors': file_errors,
            'realWarnings': file_warnings,
            'nodeKey': node_key,
            'nodeName': node_name,
            'serverTag': clean_tag_plain,
            'client': client_name
        }
        loaded_files = [
            f for f in existing_files
            if not (f.get('name') == file_entry['name'] and (f.get('serverTag') or clean_tag_plain) == clean_tag_plain)
        ]
        loaded_files.append(file_entry)

        # Compute exact 100% distinct counts across the full SQLite table (not capped by append merge)
        exact_unique_users, exact_unique_codes, exact_unique_ips = compute_exact_sqlite_distinct_counts(cur)

        # Build instant cached stats object (< 0.1 ms)
        stats_obj = {
            'status': 'ready',
            'totalLogs': total_all,
            'totalErrors': errors_all,
            'totalWarnings': warnings_all,
            'totalSuccess': max(0, total_all - errors_all),
            'totalUniqueCodes': exact_unique_codes or len(code_counts),
            'totalUniqueUsers': exact_unique_users,
            'totalUniqueIps': exact_unique_ips or len(ip_counts),
            'eventTypes': [{'code': k, 'count': v} for k, v in type_counts.most_common(100)],
            'topCodes': [{'code': k, 'count': v} for k, v in code_counts.most_common(100)],
            'topUsers': [{'user': k, 'count': v} for k, v in user_counts.most_common(200)],
            'topIps': [{'ip': k, 'count': v} for k, v in ip_counts.most_common(50)],
            'timelineBuckets': [{'bucket': k, 'total': v['total'], 'errors': v['errors'], 'info': v['info']} for k, v in sorted(hour_counts.items())[:200]],
            'detectedPlatform': 'Entrust IDaaS Cloud' if is_idaas else 'Entrust IdentityGuard OnPremise',
            'activeDb': os.path.basename(target_db),
            'client': client_name,
            'loadedFiles': loaded_files
        }
        cur.execute('CREATE TABLE IF NOT EXISTS server_stats (key TEXT PRIMARY KEY, value TEXT)')
        cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('stats_json', json.dumps(stats_obj, ensure_ascii=False)))
        cur.execute("DELETE FROM server_stats WHERE key IN ('forensic_matrix_v2', 'forensic_matrix_v3')")
        conn.commit()
        conn.close()

        ACTIVE_DB_PATH = target_db
        save_active_session(target_db, client_name)
        upload_state['dbPath'] = target_db
        upload_state['status'] = 'ready'
        upload_state['progress'] = 100
        upload_state['linesProcessed'] = total_all
        upload_state['totalErrors'] = errors_all
        print(f"Indexación completada: {total_all:,} registros ({file_lines:,} en archivo), {errors_all:,} errores en {target_db}")
    except Exception as e:
        upload_state['status'] = 'error'
        upload_state['error'] = str(e)
        print(f"Error indexando archivo: {e}")

class DiagnosticRequestHandler(http.server.SimpleHTTPRequestHandler):
    # Hardening: Hide Python & SimpleHTTP version banner from scanners (Banner Grabbing prevention)
    server_version = 'ITServicios-EntrustSuite/2.6'
    sys_version = ''

    BLOCKED_EXTENSIONS = ('.php', '.php3', '.php4', '.php5', '.phtml', '.phar', '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.pl', '.sh', '.py', '.pyc', '.db', '.sqlite', '.sqlite3', '.env', '.git', '.htaccess', '.htpasswd', '.ini', '.bak', '.sql')
    BLOCKED_PATHS = ('/.git', '/.env', '/data/', '/scripts/', '/server.py', '/sync.sh', '/wp-admin', '/wp-login', '/wp-content', '/phpmyadmin', '/cgi-bin', '/vendor/phpunit', '/etc/passwd', '/proc/self')
    ALLOWED_UPLOAD_EXTS = ('.log', '.txt', '.csv', '.tsv', '.json', '.xml', '.properties', '.conf', '.pem', '.crt', '.cer', '.dat', '.zip', '.gz', '.tgz', '.bz2', '.tar', '.html', '.htm', '.db', '.1', '.2', '.3', '.4', '.5')

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
        elif path == '/api/clear-session':
            clear_active_session()
            self.send_json({'success': True, 'activeDb': None})
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
            clear_active_session()
            self.send_json({'success': True, 'activeDb': None})
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
            self.handle_list_custom_manuals()
        elif path == '/api/manuals-status':
            if not MANUALS_INDEX_BUILT and not MANUALS_INDEX_BUILDING:
                threading.Thread(target=build_manuals_index, daemon=True).start()
            self.send_json({'ready': MANUALS_INDEX_BUILT, 'building': MANUALS_INDEX_BUILDING, 'indexedPages': len(MANUALS_INDEX)})
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
        global MANUALS_INDEX_BUILT
        try:
            length = int(self.headers.get('Content-Length', 0))
            raw = self.rfile.read(length) if length > 0 else b'{}'
            payload = json.loads(raw.decode('utf-8'))
            filename = os.path.basename(str(payload.get('filename') or '').strip())
            content = str(payload.get('content') or '')
            if not filename or not content:
                self.send_json({'error': 'filename y content requeridos'}, status=400)
                return
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ('.html', '.htm', '.md', '.txt'):
                self.send_json({'error': 'Formato permitido: .html, .htm, .md, .txt'}, status=400)
                return
            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
            custom_dir = os.path.join(BASE_DIR, 'manuals', 'custom')
            os.makedirs(custom_dir, exist_ok=True)
            target_path = os.path.join(custom_dir, safe_name)
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(content)
            MANUALS_INDEX_BUILT = False
            threading.Thread(target=build_manuals_index, daemon=True).start()
            self.send_json({'success': True, 'path': f'manuals/custom/{safe_name}', 'filename': safe_name})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_list_custom_manuals(self):
        custom_dir = os.path.join(BASE_DIR, 'manuals', 'custom')
        items = []
        if os.path.isdir(custom_dir):
            for fname in sorted(os.listdir(custom_dir)):
                fpath = os.path.join(custom_dir, fname)
                if os.path.isfile(fpath):
                    items.append({
                        'filename': fname,
                        'path': f'manuals/custom/{fname}',
                        'size': os.path.getsize(fpath)
                    })
        self.send_json({'manuals': items})

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
        try:
            limit = min(15, max(1, int(query.get('limit', ['6'])[0])))
        except Exception:
            limit = 6
        results = search_manuals(q, version_filter=version, limit=limit)
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
                    if f.endswith('.db') and sz > 0:
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
                    if (int(stats_cached.get('totalLogs', 0) or 0) > 200 and int(stats_cached.get('totalUniqueUsers', 0) or 0) <= 200) or 'totalUniqueUsers' not in stats_cached:
                        ex_u, ex_c, ex_ip = compute_exact_sqlite_distinct_counts(cur)
                        stats_cached['totalUniqueUsers'] = ex_u
                        stats_cached['totalUniqueCodes'] = ex_c
                        stats_cached['totalUniqueIps'] = ex_ip
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
            cur.execute('SELECT event_type, COUNT(1) FROM logs GROUP BY event_type ORDER BY COUNT(1) DESC LIMIT 20')
            types = [{'code': r[0], 'count': r[1]} for r in cur.fetchall()]

            # 2. Agrupación forense de códigos de error exactos ([520xxx], bulkidentityguard.add.error.*, ORA-01555, etc.)
            cur.execute('''
                SELECT 
                    CASE 
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
                LIMIT 20
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
                LIMIT 100
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
                outcome_str = str(r[4] or '')
                msg_str = str(r[5] or '')
                is_err = ('FAIL' in outcome_str.upper() or 'ERR' in outcome_str.upper() or etype in ('AUD150', 'AUD154', 'AUD6002') or etype.startswith('520') or etype.startswith('ORA-'))
                is_warn = (not is_err) and ('WARN' in outcome_str.upper() or etype in ('AUD6001', 'AUD2309', 'AUD155'))
                level = 'ERROR' if is_err else ('WARN' if is_warn else 'INFO')
                svc = 'IG.AUDIT' if etype.upper().startswith('AUD') else ('IDaaS Cloud' if 'bulkidentityguard' in etype.lower() else 'IG.SYSTEM')
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
            WHERE event_outcome LIKE '%FAIL%'
               OR event_outcome LIKE '%ERR%'
               OR event_type LIKE '520%'
               OR event_type IN ('AUD6001', 'AUD6002', 'AUD2309')
               OR event_type LIKE 'ORA-%'
               OR message LIKE '%failed%'
               OR message LIKE '%locked%'
               OR message LIKE '%error%'
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
                cur.execute("SELECT value FROM server_stats WHERE key='forensic_matrix_v3'")
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
                'traffic': set()
            }
            filtered_noise_users = set()
            filtered_noise_events = 0

            for subj, etype, outcome, cnt, first_t, last_t, sample_ip in agg_rows:
                code = (etype or 'SYSTEM_LOG').strip()
                out_str = (outcome or 'SUCCESS').upper()
                is_err = ('FAIL' in out_str) or ('ERR' in out_str)

                if code not in code_map:
                    kind = 'SYSTEM_EVENT'
                    if re.match(r'^520\d{4}$', code):
                        kind = 'ERROR_520'
                    elif re.match(r'^AUD\d{2,5}$', code, re.IGNORECASE) or 'AUDIT' in code.upper():
                        kind = 'AUDIT_AUD'
                    elif code.startswith('ORA-') or 'SQL' in code.upper() or 'JDBC' in code.upper():
                        kind = 'DATABASE_ORA'
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
                    if c_entry['kind'] == 'AUDIT_AUD':
                        cat_users['audit'].add(subj_str)
                    elif c_entry['kind'] == 'ERROR_520':
                        cat_users['520'].add(subj_str)
                    elif c_entry['kind'] == 'IDAAS_MIGRATION':
                        cat_users['idaas'].add(subj_str)
                    elif c_entry['kind'] in ('SYSTEM_EVENT', 'DATABASE_ORA'):
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
                    SUM(CASE WHEN event_type = 'SQL_EXCEPTION' OR message LIKE '%SQLException%' OR message LIKE '%HikariPool%' OR message LIKE '%Connection timed out%' THEN 1 ELSE 0 END) as sql_exc,
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
                  AND (event_type LIKE 'ORA-%' OR event_type = 'SQL_EXCEPTION' OR message LIKE '%ORA-%' OR message LIKE '%SQLException%' OR message LIKE '%JdbcCardRepository%' OR message LIKE '%TransactionQueue%')
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

            if total_db_incidents > max(migration_errors, auth_520_errors) and total_db_incidents > 0:
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
                    'migrationCollisions': migration_errors,
                    'authentication520Errors': auth_520_errors,
                    'otherSystemErrors': max(0, total_errors - (total_db_incidents + migration_errors + auth_520_errors))
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
                    'all': len(users_map)
                },
                'filteredNoiseUsers': len(filtered_noise_users),
                'filteredNoiseEvents': filtered_noise_events,
                'usersList': users_list_out,
                'patternClusters': pattern_clusters,
                'codeMatrix': code_matrix,
                'dbHealth': db_health,
                'postMortem': post_mortem
            }

            try:
                cur.execute('INSERT OR REPLACE INTO server_stats VALUES (?, ?)', ('forensic_matrix_v3', json.dumps(result_payload, ensure_ascii=False)))
                conn.commit()
            except Exception:
                pass

            conn.close()
            self.send_json(result_payload)
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
