import http.server
import json
import os
import sqlite3
import urllib.parse

PORT = 8085
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'mercantil_audit.db')

class DiagnosticRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        if path == '/api/logs':
            self.handle_api_logs(query)
        elif path == '/api/stats':
            self.handle_api_stats()
        elif path == '/api/export-errors':
            self.handle_export_errors()
        else:
            super().do_GET()

    def handle_api_stats(self):
        if not os.path.exists(DB_PATH):
            self.send_json({'error': 'DB not ready'}, status=503)
            return

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT COUNT(1) FROM logs')
        total = cur.fetchone()[0]

        cur.execute('SELECT COUNT(1) FROM logs WHERE event_outcome LIKE ?', ('%FAIL%',))
        errors = cur.fetchone()[0]

        cur.execute('SELECT event_type, COUNT(1) FROM logs GROUP BY event_type ORDER BY COUNT(1) DESC')
        types = [{'code': r[0], 'count': r[1]} for r in cur.fetchall()]

        conn.close()
        self.send_json({
            'totalLogs': total,
            'totalErrors': errors,
            'totalSuccess': total - errors,
            'eventTypes': types
        })

    def handle_api_logs(self, query):
        if not os.path.exists(DB_PATH):
            self.send_json({'error': 'DB not ready'}, status=503)
            return

        page = int(query.get('page', ['1'])[0])
        limit = min(200, max(10, int(query.get('limit', ['50'])[0])))
        offset = (page - 1) * limit
        search = query.get('search', [''])[0].strip()
        outcome = query.get('outcome', ['ALL'])[0].strip().upper()
        event_type = query.get('type', ['ALL'])[0].strip()

        conditions = []
        params = []

        if outcome == 'FAIL' or outcome == 'ERROR':
            conditions.append('event_outcome LIKE ?')
            params.append('%FAIL%')
        elif outcome == 'SUCCESS' or outcome == 'INFO':
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

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute(f'SELECT COUNT(1) FROM logs {where_clause}', params)
        total_matching = cur.fetchone()[0]

        query_sql = f'SELECT line_num, event_time, subject_name, event_type, event_outcome, message, source_ip, raw FROM logs {where_clause} ORDER BY line_num ASC LIMIT ? OFFSET ?'
        cur.execute(query_sql, params + [limit, offset])

        rows = cur.fetchall()
        conn.close()

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
                'client': 'Banco Mercantil C.A. (IDaaS Cloud)',
                'node': '☁️ IDaaS Cloud Core'
            })

        total_pages = max(1, (total_matching + limit - 1) // limit)
        self.send_json({
            'page': page,
            'limit': limit,
            'totalMatching': total_matching,
            'totalPages': total_pages,
            'logs': logs
        })

    def handle_export_errors(self):
        if not os.path.exists(DB_PATH):
            self.send_error(503, 'DB not ready')
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="Errores_BancoMercantil_AuditEvents.csv"')
        self.end_headers()

        header = 'lineNum,eventTime,user,eventType,outcome,message,ip,raw\n'
        self.wfile.write(header.encode('utf-8'))

        conn = sqlite3.connect(DB_PATH)
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

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', PORT), DiagnosticRequestHandler)
    print(f'Servidor API & Dashboard activo en http://0.0.0.0:{PORT}')
    server.serve_forever()
