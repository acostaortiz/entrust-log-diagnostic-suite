import http.server
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.parse

PORT = 8085
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

DEFAULT_DB_PATH = os.path.join(DATA_DIR, 'mercantil_audit.db')
ACTIVE_DB_PATH = DEFAULT_DB_PATH if os.path.exists(DEFAULT_DB_PATH) else os.path.join(DATA_DIR, 'active_audit.db')

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
    'dbPath': ACTIVE_DB_PATH,
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

def resolve_client_db(client_param=None):
    global ACTIVE_DB_PATH
    if client_param and str(client_param) not in ['ALL', 'all', 'undefined', 'null', '']:
        slug = get_client_slug(client_param)
        candidate_names = [
            f"{slug}_audit.db",
            f"{slug}.db",
            f"{str(client_param).strip().lower()}_audit.db",
            f"{str(client_param).strip().lower()}.db"
        ]
        for name in candidate_names:
            target = os.path.join(DATA_DIR, name)
            if os.path.exists(target):
                return target
        
        # Search for any db starting with slug
        if os.path.exists(DATA_DIR):
            for f in os.listdir(DATA_DIR):
                if f.lower().startswith(slug) and f.endswith('.db'):
                    return os.path.join(DATA_DIR, f)
        
        return os.path.join(DATA_DIR, f"{slug}_audit.db")

    if os.path.exists(ACTIVE_DB_PATH):
        return ACTIVE_DB_PATH
    if os.path.exists(DEFAULT_DB_PATH):
        return DEFAULT_DB_PATH
    
    # Return any available db in data dir
    if os.path.exists(DATA_DIR):
        for f in os.listdir(DATA_DIR):
            if f.endswith('_audit.db'):
                return os.path.join(DATA_DIR, f)
    return None

def init_db(db_path):
    conn = sqlite3.connect(db_path)
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

def parse_line_for_db(line, line_num):
    if not line:
        return None
    
    # 1. Check IDaaS Cloud CSV format
    if (',' in line or '\t' in line) and not line.startswith('['):
        parts = line.split('\t') if '\t' in line else [p.strip().strip('"') for p in line.split(',')]
        if len(parts) >= 8 and parts[0].lower() != 'id':
            event_time = parts[1].replace('T', ' ').replace('Z', '')[:19] if len(parts) > 1 else ''
            user = parts[4] if len(parts) > 4 else 'unknown'
            event_type = parts[7] if len(parts) > 7 else 'IDaaS.Audit'
            outcome = parts[8].upper() if len(parts) > 8 else 'SUCCESS'
            msg = parts[9] if len(parts) > 9 else event_type
            ip = parts[12] if len(parts) > 12 else ''
            return (line_num, event_time, user, event_type, outcome, msg, ip, line[:500])

    # 2. Check Entrust Bracket format: [timestamp] [thread] [LEVEL] [Category] [520xxx/AUD] Message
    bracket_match = re.match(r'^\[([^\]]+)\]\s*\[([^\]]*)\]\s*\[([A-Za-z]+)\s*\]\s*\[([^\]]*)\]\s*(.*)$', line)
    if bracket_match:
        event_time = bracket_match.group(1)[:19]
        level = bracket_match.group(3).upper()
        category = bracket_match.group(4)
        msg = bracket_match.group(5)
        outcome = 'FAIL' if any(k in level for k in ['ERR', 'CRIT', 'FATAL']) else ('DEBUG' if level == 'DEBUG' else 'SUCCESS')
        
        c520 = re.search(r'520\d{4}', msg)
        aud = re.search(r'AUD\d{3,4}', msg)
        ora = re.search(r'ORA-\d{5}', msg) or re.search(r'ORA-\d{5}', line)
        
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
        
        user_match = re.search(r'(?:user|for user|alias)\s+[\'"]?([A-Za-z0-9_\-\.\/@]+(?:\/[A-Za-z0-9_\-\.\/@]+)?)', msg, re.I)
        user = user_match.group(1) if user_match else 'system'
        
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
    return (line_num, event_time, 'unknown', 'SYSTEM_LOG', level, line[:200], 'local', line[:500])

def index_file_in_background(file_path, client_name='Entrust Client'):
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
        if os.path.exists(target_db):
            try:
                os.remove(target_db)
            except Exception:
                pass
        
        init_db(target_db)
        
        file_size = os.path.getsize(file_path)
        upload_state['fileSize'] = file_size
        
        conn = sqlite3.connect(target_db)
        cur = conn.cursor()
        cur.execute('PRAGMA synchronous = OFF;')
        cur.execute('PRAGMA journal_mode = WAL;')
        
        batch = []
        batch_size = 25000
        line_num = 0
        total_errors = 0
        bytes_read = 0
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                line_num += 1
                bytes_read += len(line)
                
                parsed = parse_line_for_db(line_str, line_num)
                if parsed:
                    if 'FAIL' in parsed[4] or 'ERR' in parsed[4]:
                        total_errors += 1
                    batch.append(parsed)
                
                if len(batch) >= batch_size:
                    cur.executemany('INSERT INTO logs VALUES (?,?,?,?,?,?,?,?)', batch)
                    conn.commit()
                    batch = []
                    upload_state['linesProcessed'] = line_num
                    upload_state['totalErrors'] = total_errors
                    upload_state['progress'] = min(99, int((bytes_read / max(1, file_size)) * 100))
        
        if batch:
            cur.executemany('INSERT INTO logs VALUES (?,?,?,?,?,?,?,?)', batch)
            conn.commit()
            
        conn.close()
        
        ACTIVE_DB_PATH = target_db
        upload_state['dbPath'] = target_db
        upload_state['status'] = 'ready'
        upload_state['progress'] = 100
        upload_state['linesProcessed'] = line_num
        upload_state['totalErrors'] = total_errors
        print(f"Indexación completada: {line_num:,} registros, {total_errors:,} errores en {target_db}")
    except Exception as e:
        upload_state['status'] = 'error'
        upload_state['error'] = str(e)
        print(f"Error indexando archivo: {e}")

class DiagnosticRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == '/api/upload-chunk':
            self.handle_upload_chunk()
        elif path == '/api/ingest-local':
            self.handle_ingest_local()
        else:
            self.send_error(404, 'Endpoint not found')

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == '/api/logs':
            self.handle_api_logs(query)
        elif path == '/api/stats':
            self.handle_api_stats(query)
        elif path == '/api/upload-status':
            self.send_json(upload_state)
        elif path == '/api/list-server-files':
            self.handle_list_server_files()
        elif path == '/api/export-errors':
            self.handle_export_errors(query)
        else:
            super().do_GET()

    def handle_ingest_local(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
            file_path = data.get('filePath', '').strip()
            client_name = data.get('clientName', 'Entrust Client').strip()

            if not file_path or not os.path.exists(file_path):
                self.send_json({'error': f'El archivo no existe en el servidor: {file_path}'}, status=400)
                return

            upload_state['fileName'] = os.path.basename(file_path)
            upload_state['clientName'] = client_name
            upload_state['clientSlug'] = get_client_slug(client_name)
            upload_state['status'] = 'indexing'
            upload_state['progress'] = 0

            thread = threading.Thread(target=index_file_in_background, args=(file_path, client_name))
            thread.daemon = True
            thread.start()

            self.send_json({'success': True, 'message': f'Indexación iniciada para {file_path}'})
        except Exception as e:
            self.send_json({'error': str(e)}, status=500)

    def handle_list_server_files(self):
        found_files = []
        scan_dirs = [DATA_DIR, UPLOADS_DIR, BASE_DIR]
        for sdir in scan_dirs:
            if not os.path.exists(sdir):
                continue
            for f in os.listdir(sdir):
                if f.endswith(('.csv', '.log', '.txt', '.tsv')) and not f.startswith('.'):
                    full_p = os.path.join(sdir, f)
                    try:
                        sz = os.path.getsize(full_p)
                        found_files.append({
                            'name': f,
                            'path': full_p,
                            'sizeBytes': sz,
                            'sizeMb': round(sz / (1024 * 1024), 2),
                            'sizeGb': round(sz / (1024 * 1024 * 1024), 2)
                        })
                    except Exception:
                        pass
        unique_files = list({v['path']: v for v in found_files}.values())
        self.send_json({'files': unique_files})

    def handle_upload_chunk(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            chunk_data = self.rfile.read(content_length)
            
            chunk_index = int(self.headers.get('X-Chunk-Index', 0))
            total_chunks = int(self.headers.get('X-Total-Chunks', 1))
            file_name = urllib.parse.unquote(self.headers.get('X-File-Name', 'uploaded_log.csv'))
            client_name = urllib.parse.unquote(self.headers.get('X-Client-Name', 'Entrust Client'))

            safe_file_name = re.sub(r'[^a-zA-Z0-9_\.-]', '_', file_name)
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
                upload_state['status'] = 'indexing'
                upload_state['progress'] = 0
                thread = threading.Thread(target=index_file_in_background, args=(temp_path, client_name))
                thread.daemon = True
                thread.start()

            self.send_json({'success': True, 'chunkIndex': chunk_index, 'progress': pct})
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
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            cur.execute('SELECT COUNT(1) FROM logs')
            total = cur.fetchone()[0]

            cur.execute('SELECT COUNT(1) FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))
            errors = cur.fetchone()[0]

            cur.execute('SELECT event_type, COUNT(1) FROM logs GROUP BY event_type ORDER BY COUNT(1) DESC LIMIT 20')
            types = [{'code': r[0], 'count': r[1]} for r in cur.fetchall()]

            cur.execute('SELECT subject_name, COUNT(1) FROM logs WHERE subject_name != "unknown" GROUP BY subject_name ORDER BY COUNT(1) DESC LIMIT 20')
            top_users = [{'user': r[0], 'count': r[1]} for r in cur.fetchall()]

            cur.execute('SELECT source_ip, COUNT(1) FROM logs WHERE source_ip != "" AND source_ip != "local" GROUP BY source_ip ORDER BY COUNT(1) DESC LIMIT 20')
            top_ips = [{'ip': r[0], 'count': r[1]} for r in cur.fetchall()]

            conn.close()
            self.send_json({
                'status': 'ready',
                'totalLogs': total,
                'totalErrors': errors,
                'totalSuccess': total - errors,
                'eventTypes': types,
                'topUsers': top_users,
                'topIps': top_ips,
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
            page = int(query.get('page', ['1'])[0])
            limit = min(200, max(10, int(query.get('limit', ['50'])[0])))
            offset = (page - 1) * limit
            search = query.get('search', [''])[0].strip()
            outcome = query.get('outcome', ['ALL'])[0].strip().upper()
            event_type = query.get('type', ['ALL'])[0].strip()

            conditions = []
            params = []

            if outcome in ['FAIL', 'ERROR']:
                conditions.append('event_outcome LIKE ?')
                params.append('%FAIL%')
            elif outcome in ['SUCCESS', 'INFO']:
                conditions.append('event_outcome = ?')
                params.append('SUCCESS')

            if event_type and event_type != 'ALL':
                conditions.append('event_type = ?')
                params.append(event_type)

            if search:
                conditions.append('(message LIKE ? OR subject_name LIKE ? OR source_ip LIKE ? OR event_type LIKE ?)')
                term = f'%{search}%'
                params.extend([term, term, term, term])

            where_clause = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

            conn = sqlite3.connect(db)
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
                is_err = 'FAIL' in (r[4] or '')
                logs.append({
                    'id': f'log-{r[0]}',
                    'lineNum': r[0],
                    'timestamp': r[1],
                    'user': r[2],
                    'service': 'Administration Portal',
                    'entrustCode': r[3],
                    'level': 'ERROR' if is_err else 'INFO',
                    'outcome': r[4],
                    'message': f'[{r[3]}] {r[5]} (Outcome: {r[4]})',
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

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="Errores_AuditEvents_Export.csv"')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        header = 'lineNum,eventTime,user,eventType,outcome,message,ip,raw\n'
        self.wfile.write(header.encode('utf-8'))

        conn = sqlite3.connect(db)
        cur = conn.cursor()
        cur.execute('SELECT line_num, event_time, subject_name, event_type, event_outcome, message, source_ip, raw FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))

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

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

class ReusableHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

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
            print(f'✅ Servidor API & Dashboard ACTIVO en http://0.0.0.0:{PORT}')
            server.serve_forever()
            break
        except OSError as e:
            if 'Address already in use' in str(e) or getattr(e, 'errno', None) == 98:
                print(f"⚠️ Puerto {PORT} ocupado. Liberando puerto automáticamente (intento {attempt + 1}/5)...")
                if sys.platform != 'win32':
                    os.system(f'fuser -k {PORT}/tcp 2>/dev/null || kill -9 $(lsof -t -i:{PORT} 2>/dev/null) 2>/dev/null || true')
                time.sleep(1)
            else:
                raise e
