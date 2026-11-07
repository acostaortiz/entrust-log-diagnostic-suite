// Global HTML sanitizer
if (typeof window !== 'undefined' && !window.escapeHtml) {
  window.escapeHtml = function(text) {
    if (text === null || text === undefined) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
}
if (typeof escapeHtml === 'undefined') {
  var escapeHtml = window.escapeHtml;
}

/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - WEB WORKER MULTIHILO ULTRA-RÁPIDO (v77.0)
   Procesamiento asíncrono en segundo plano (350.000+ líneas/segundo)
   ========================================================================== */

self.onmessage = async function (e) {
  const { file, rawContent, clientId, mode } = e.data;

  // MODO 1: Archivo Gigante Streaming (File / Blob hasta 10 GB+)
  if (file || mode === 'fileBlob') {
    await processGiantFileStream(file, clientId);
    return;
  }

  // MODO 2: Contenido en Memoria (Texto directo)
  if (!rawContent) {
    self.postMessage({ type: 'complete', parsedLogs: [] });
    return;
  }

  const lines = rawContent.split(/\r?\n/);
  const total = lines.length;
  const parsedLogs = [];
  const chunkSize = 25000;

  for (let i = 0; i < total; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    let parsed = parseSingleLineFast(line, i);
    if (parsed) {
      if (clientId) parsed.client = clientId;
      parsedLogs.push(parsed);
    }

    if (i % chunkSize === 0 || i === total - 1) {
      const pct = Math.round(((i + 1) / total) * 100);
      self.postMessage({ type: 'progress', current: i + 1, total, pct });
    }
  }

  self.postMessage({ type: 'complete', parsedLogs });
};

async function processGiantFileStream(file, clientId) {
  const fileSize = file.size;
  const chunkSize = 8 * 1024 * 1024; // 8 MB chunks
  let offset = 0;
  let leftover = '';
  let lineCount = 0;
  let totalErrors = 0;
  let totalWarnings = 0;

  // Agregadores Globales para el Panorama Completo (100% de los 9.7 GB)
  const userCounter = {};
  const userDetails = {};
  const ipCounter = {};
  const codeCounter = {};
  const timeBuckets = {};

  // Buffer de visualización interactiva en UI (máximo 35.000 registros para evitar OOM)
  const displayLogs = [];
  const MAX_DISPLAY_LOGS = 35000;
  let displayErrorCount = 0;

  let lastProgressReportTime = 0;

  while (offset < fileSize) {
    const slice = file.slice(offset, Math.min(offset + chunkSize, fileSize));
    const chunkText = await slice.text();
    offset += chunkSize;

    const fullText = leftover + chunkText;
    const lines = fullText.split(/\r?\n/);

    if (offset < fileSize) {
      leftover = lines.pop() || '';
    } else {
      leftover = '';
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      lineCount++;

      const parsed = parseSingleLineFast(line, lineCount);
      if (parsed) {
        if (clientId) parsed.client = clientId;

        const isError = parsed.level === 'ERROR' || parsed.level === 'CRITICAL';
        const isWarn = parsed.level === 'WARN';

        if (isError) totalErrors++;
        if (isWarn) totalWarnings++;

        // 1. Agregación de Códigos / Eventos
        const codeKey = parsed.entrustCode || parsed.service || 'UNKNOWN';
        codeCounter[codeKey] = (codeCounter[codeKey] || 0) + 1;

        // 2. Agregación de Usuarios Nominales con detalles forenses
        if (parsed.user && parsed.user !== 'unknown' && parsed.user !== 'N/A') {
          const u = parsed.user;
          userCounter[u] = (userCounter[u] || 0) + 1;
          if (!userDetails[u] && Object.keys(userDetails).length < 5000) {
            userDetails[u] = { count: 0, errors: 0, codes: {}, firstSeen: parsed.timestamp || '', lastSeen: parsed.timestamp || '' };
          }
          if (userDetails[u]) {
            userDetails[u].count++;
            if (isError || isWarn || parsed.entrustCode === 'AUD6001' || parsed.entrustCode === 'AUD6002') {
              userDetails[u].errors++;
            }
            if (parsed.entrustCode) {
              userDetails[u].codes[parsed.entrustCode] = (userDetails[u].codes[parsed.entrustCode] || 0) + 1;
            }
            if (parsed.timestamp) userDetails[u].lastSeen = parsed.timestamp;
          }
        }

        // 3. Agregación de IPs
        if (parsed.clientIp && parsed.clientIp !== 'N/A') {
          ipCounter[parsed.clientIp] = (ipCounter[parsed.clientIp] || 0) + 1;
        }

        // 4. Agregación de Tiempos (Día / Hora / Minutos)
        let dateBucket = (parsed.timestamp || '').substring(0, 16); // 'YYYY-MM-DD HH:mm'
        if (!dateBucket || dateBucket.length < 10) {
          dateBucket = (parsed.timestamp || '').substring(0, 13);
        }
        if (dateBucket && dateBucket.length >= 10) {
          if (!timeBuckets[dateBucket]) timeBuckets[dateBucket] = { total: 0, critical: 0, warn: 0 };
          timeBuckets[dateBucket].total++;
          if (isError) timeBuckets[dateBucket].critical++;
          if (isWarn) timeBuckets[dateBucket].warn++;
        }

        // 5. Muestreo Seguro con tope estricto de memoria (prioriza Errores, Alertas y Eventos AUD/ Usuarios)
        const isPriority = isError || isWarn || (parsed.entrustCode && /^AUD/i.test(parsed.entrustCode)) || (parsed.user && parsed.user !== 'N/A');
        if (isPriority && displayErrorCount < 25000) {
          displayErrorCount++;
          displayLogs.push(parsed);
        } else if (displayLogs.length < MAX_DISPLAY_LOGS && (lineCount % 100 === 0 || displayLogs.length < 5000)) {
          displayLogs.push(parsed);
        }
      }
    }

    const now = Date.now();
    if (now - lastProgressReportTime > 250 || offset >= fileSize) {
      lastProgressReportTime = now;
      const pct = Math.min(99, Math.round((Math.min(offset, fileSize) / fileSize) * 100));
      const mbProcessed = (Math.min(offset, fileSize) / (1024 * 1024)).toFixed(0);
      const totalMb = (fileSize / (1024 * 1024)).toFixed(0);

      self.postMessage({
        type: 'progress',
        current: Math.min(offset, fileSize),
        total: fileSize,
        pct: pct,
        mbProcessed: mbProcessed,
        totalMb: totalMb,
        lineCount: lineCount,
        totalErrors: totalErrors
      });
    }

    await new Promise(r => setTimeout(r, 0));
  }

  if (leftover && leftover.trim()) {
    lineCount++;
    const parsed = parseSingleLineFast(leftover.trim(), lineCount);
    if (parsed) {
      if (clientId) parsed.client = clientId;
      displayLogs.push(parsed);
    }
  }

  // Ordenar y recortar Top Usuarios (hasta 2500) y Top IPs
  const topUsers = Object.entries(userCounter)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2500)
    .map(([user, count]) => ({
      user,
      count,
      errors: userDetails[user]?.errors || 0,
      codes: userDetails[user]?.codes || {},
      firstSeen: userDetails[user]?.firstSeen || '',
      lastSeen: userDetails[user]?.lastSeen || ''
    }));

  const topIps = Object.entries(ipCounter)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 200)
    .map(([ip, count]) => ({ ip, count }));

  const topCodes = Object.entries(codeCounter)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 150)
    .map(([code, count]) => ({ code, count }));

  self.postMessage({
    type: 'complete',
    parsedLogs: displayLogs.slice(-MAX_DISPLAY_LOGS),
    totalLinesProcessed: lineCount,
    totalErrors: totalErrors,
    totalWarnings: totalWarnings,
    globalMetrics: {
      totalLogs: lineCount,
      totalErrors: totalErrors,
      totalWarnings: totalWarnings,
      topUsers: topUsers,
      topIps: topIps,
      topCodes: topCodes,
      timeBuckets: timeBuckets
    }
  });
}

function parseSingleLineFast(line, lineNum) {
  // 1. Formato IdentityGuard OnPremise Bracket: [2026-09-08 10:15:23] [http-nio-8443-exec-12] [ERROR] ...
  if (line.charCodeAt(0) === 91) {
    const p1 = line.indexOf(']', 1);
    if (p1 > 8 && p1 < 36) {
      const timestamp = line.substring(1, p1);

      const p2Start = line.indexOf('[', p1 + 1);
      const p2End = p2Start !== -1 ? line.indexOf(']', p2Start + 1) : -1;
      const thread = p2End !== -1 ? line.substring(p2Start + 1, p2End) : 'main';

      const p3Start = p2End !== -1 ? line.indexOf('[', p2End + 1) : -1;
      const p3End = p3Start !== -1 ? line.indexOf(']', p3Start + 1) : -1;
      const rawLevel = p3End !== -1 ? line.substring(p3Start + 1, p3End).trim() : 'INFO';

      const p4Start = p3End !== -1 ? line.indexOf('[', p3End + 1) : -1;
      const p4End = p4Start !== -1 ? line.indexOf(']', p4Start + 1) : -1;
      const category = p4End !== -1 ? line.substring(p4Start + 1, p4End).trim() : 'IG.SYSTEM';

      const message = p4End !== -1 ? line.substring(p4End + 1).trim() : line.substring(p1 + 1).trim();

      let level = 'INFO';
      if (rawLevel.includes('ERR') || rawLevel.includes('CRIT') || rawLevel.includes('FATAL')) {
        level = 'ERROR';
      } else if (rawLevel.includes('WARN')) {
        level = 'WARN';
      }

      let entrustCode = null;
      const c520Idx = line.indexOf('520');
      if (c520Idx !== -1 && /520\d{4}/.test(line.substring(c520Idx, c520Idx + 7))) {
        entrustCode = line.substring(c520Idx, c520Idx + 7);
        level = 'ERROR';
      } else {
        const audIdx = line.indexOf('AUD');
        if (audIdx !== -1 && /AUD\d{3,4}/i.test(line.substring(audIdx, audIdx + 7))) {
          entrustCode = line.substring(audIdx, audIdx + 7).replace(/[^A-Za-z0-9]/g, '').toUpperCase();
          if (entrustCode === 'AUD6001' || entrustCode === 'AUD6002' || entrustCode === 'AUD2309') {
            if (level === 'INFO') level = 'WARN';
          }
        }
      }

      let user = extractUser(line);
      let clientIp = extractClientIp(line);

      return {
        id: `worker-log-${lineNum}-${Date.now()}`,
        lineNum: lineNum + 1,
        type: 'Entrust IdentityGuard',
        timestamp: timestamp,
        level: level,
        hostname: 'localhost',
        service: category,
        message: message,
        raw: line,
        user: user,
        clientIp: clientIp,
        entrustCode: entrustCode
      };
    }
  }

  // 1.5. Parser Entrust IdentityGuard Migration Tool / IDaaS Import Logs
  if (line.includes('IdentityGuard migration:')) {
    let level = 'INFO';
    if (/\[ERROR\]/i.test(line) || /error|fail|already/i.test(line)) level = 'ERROR';
    else if (/\[WARN\]/i.test(line)) level = 'WARN';

    let entrustCode = 'IDG-MIGRATION-EVENT';
    let service = 'Entrust IDaaS Migration Engine';
    let user = 'N/A';

    const userMatch = line.match(/user\s+([0-9A-Za-z_\.\-]+)/i);
    if (userMatch) user = userMatch[1];

    if (/grid already assigned/i.test(line) || /assignedgrid/i.test(line)) {
      entrustCode = 'bulkidentityguard.add.error.assignedgrid';
      service = 'IDaaS Bulk Grid Engine';
    } else if (/currently has a password|Password will not be migrated|password/i.test(line)) {
      entrustCode = 'bulkidentityguard.add.error.password';
      service = 'IDaaS Bulk Password Engine';
    } else if (/already/i.test(line) || /qa|question/i.test(line)) {
      entrustCode = 'bulkidentityguard.add.error.qa';
      service = 'IDaaS Bulk Q&A Engine';
    }

    const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
    const timestamp = timestampMatch ? timestampMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);

    return {
      id: `worker-log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Entrust IDaaS Cloud (Migration Tool)',
      timestamp: timestamp,
      level: level,
      hostname: 'idaas.entrust.com',
      service: service,
      message: line,
      raw: line,
      user: user,
      clientIp: 'local',
      entrustCode: entrustCode
    };
  }

  // 2. Parser Entrust IDaaS Cloud TSV / CSV Audit Trail Export (Logs_AuditEvents-*.csv)
  if (line.includes('AuthenticationTokenPush') || line.includes('Bulkidentityguard') || line.includes('UsersAdd') || line.includes('Authorizationgroups') || line.includes('AuditDetails') || (line.includes('Event') && (line.includes('SUCCESS') || line.includes('FAILURE') || line.includes('FAIL')))) {
    const isTab = line.includes('\t');
    const parts = isTab ? line.split('\t') : splitCsvLine(line);
    if (parts.length >= 8 && parts[0].toLowerCase() !== 'id') {
      const rawTime = parts[1] || '';
      const subjectName = parts[4] || '';
      const eventCategory = parts[6] || 'IDaaS.Audit';
      const eventType = parts[7] || '';
      const eventOutcome = (parts[8] || 'SUCCESS').toUpperCase();
      const eventMessage = parts[9] || '';
      const resourceName = parts[11] || 'Administration Portal';
      const sourceIp = parts[12] || '';
      const entityAction = parts[21] || '';
      const entityName = parts[23] || '';

      let level = 'INFO';
      if (eventOutcome.includes('FAIL') || eventOutcome.includes('ERROR') || eventOutcome.includes('DENIED')) {
        level = 'ERROR';
      } else if (eventOutcome.includes('WARN')) {
        level = 'WARN';
      }

      let formattedTime = rawTime.replace('T', ' ').replace('Z', '').substring(0, 19);
      if (!formattedTime) formattedTime = new Date().toISOString().replace('T', ' ').substring(0, 19);

      let summaryMsg = `[${eventType}] ${eventMessage || eventType}`;
      if (entityName) summaryMsg += ` (Entidad: ${entityName} ${entityAction})`;

      return {
        id: `worker-log-${lineNum}-${Date.now()}`,
        lineNum: lineNum + 1,
        type: 'IDaaS Cloud Audit',
        timestamp: formattedTime,
        level: level,
        hostname: 'idaas-cloud-latam',
        service: resourceName || eventCategory,
        message: summaryMsg,
        raw: line,
        user: subjectName || 'unknown',
        clientIp: sourceIp || null,
        entrustCode: eventType
      };
    }
  }

  // Fallback
  let level = 'INFO';
  if (/emergency|alert|critical|fatal|panic/i.test(line)) level = 'CRITICAL';
  else if (/error|failed|exception/i.test(line)) level = 'ERROR';
  else if (/warning|warn/i.test(line)) level = 'WARN';

  let entrustCode = null;
  let service = 'Entrust Core';

  if (/grid already assigned/i.test(line) || /assignedgrid/i.test(line)) {
    entrustCode = 'bulkidentityguard.add.error.assignedgrid';
    service = 'IDaaS Bulk Grid Engine';
    level = 'ERROR';
  } else if (/currently has a password|Password will not be migrated|password/i.test(line)) {
    entrustCode = 'bulkidentityguard.add.error.password';
    service = 'IDaaS Bulk Password Engine';
    level = 'ERROR';
  } else if (/already/i.test(line) || /qa|question/i.test(line)) {
    entrustCode = 'bulkidentityguard.add.error.qa';
    service = 'IDaaS Bulk Q&A Engine';
    level = 'ERROR';
  } else {
    const c520 = line.match(/520\d{4}/);
    const aud = line.match(/AUD\d{3,4}/i);
    const ora = line.match(/ORA-\d{5}/);
    if (c520) { entrustCode = c520[0]; service = 'IdentityGuard Server'; level = 'ERROR'; }
    else if (aud) { entrustCode = aud[0].toUpperCase(); service = 'IdentityGuard Audit'; }
    else if (ora) { entrustCode = ora[0]; service = 'Oracle Database'; level = 'ERROR'; }
  }

  const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
  const timestamp = timestampMatch ? timestampMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);

  return {
    id: `worker-log-${lineNum}-${Date.now()}`,
    lineNum: lineNum + 1,
    type: 'System',
    timestamp: timestamp,
    level: level,
    hostname: 'localhost',
    service: service,
    message: line,
    raw: line,
    user: extractUser(line),
    clientIp: extractClientIp(line),
    entrustCode: entrustCode
  };
}

function splitCsvLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current.trim());
  return result;
}

function extractUser(line) {
  if (!line || typeof line !== 'string') return null;

  const isValidUser = (cand) => {
    if (!cand || typeof cand !== 'string') return false;
    const clean = cand.trim().replace(/^['"\[\]().,;:!?]+|['"\[\]().,;:!?]+$/g, '');
    if (clean.length < 2 || clean.length > 75) return false;
    const low = clean.toLowerCase();
    const stopWords = new Set([
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
      'so', 'than', 'too', 'very', 'just', 'now', 'then', 'here', 'there', 'calling', 'main',
      'type', 'user', 'users', 'admin_console', 'user_3238', 'user_8912', 'user_1042'
    ]);
    if (stopWords.has(low)) return false;
    if (/^[-.=/\\:;,]/.test(clean)) return false;
    if (/^(com\.|org\.|java\.|javax\.|net\.|sun\.|entrust\.|ora-|aud\d|bulkidentityguard|http)/i.test(low)) return false;
    if (/^520\d{4}$/.test(clean) || /^\d{4}-\d{2}-\d{2}/.test(clean)) return false;
    if (/(exception|repository|transactionqueue|blobaccess|authenticator|manager|handler|controller|factory|provider)/i.test(low)) return false;
    return /[A-Za-z0-9]/.test(clean);
  };

  const forUserMatch = line.match(/\bfor\s+user\s+(['"]?)([A-Za-z0-9_\-\.\/@]+)\1/i);
  if (forUserMatch && isValidUser(forUserMatch[2])) return forUserMatch[2].trim();

  const userActionMatch = line.match(/\bUser\s+([A-Za-z0-9_\-\.\/@]+)\s+(?:currently\s+has|has\s+a\s+grid|already\s+has|created|failed|logged|assigned|updated|deleted|authenticated|locked|disabled|migrated)/i);
  if (userActionMatch && isValidUser(userActionMatch[1])) return userActionMatch[1].trim();

  const bracketUserMatch = line.match(/\[(?:AUD\d+|IG\.AUDIT)\]\s*\[([A-Za-z0-9_\-\.\/@]+)\]/i);
  if (bracketUserMatch && isValidUser(bracketUserMatch[1])) return bracketUserMatch[1].trim();

  const bcMatch = line.match(/\b(BCClientes[A-Za-z0-9_\-\.\/@]+|BCMercantil[A-Za-z0-9_\-\.\/@]+|BC[A-Za-z0-9_\-\.\/@]+)\b/i);
  if (bcMatch && isValidUser(bcMatch[1])) return bcMatch[1].trim();

  const emailMatch = line.match(/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/i);
  if (emailMatch && isValidUser(emailMatch[1])) return emailMatch[1].trim();

  const match = line.match(/(?:for\s+user|user:?|subjectName:?|user\s*=|username\s*=)\s+(['"]?)([A-Za-z0-9_\-\.\/@]+)\1/i);
  if (match && isValidUser(match[2])) {
    return match[2].trim();
  }
  return null;
}

function extractClientIp(line) {
  if (!line || typeof line !== 'string') return null;
  if (line.includes('jasperreports') || line.includes('TLS_DHE') || line.includes('virtualizer') || line.includes('delete.on.exit')) {
    return null;
  }
  const matches = line.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g);
  if (!matches) return null;

  const validIp = matches.find(ip => {
    if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip.startsWith('255.')) return false;
    const parts = ip.split('.').map(Number);
    return parts.every(p => !isNaN(p) && p >= 0 && p <= 255);
  });
  return validIp || null;
}
