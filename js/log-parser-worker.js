/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - WEB WORKER MULTIHILO ULTRA-RÁPIDO (v77.0)
   Procesamiento asíncrono en segundo plano (350.000+ líneas/segundo)
   ========================================================================== */

self.onmessage = function (e) {
  const { rawContent, clientId } = e.data;
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

function parseSingleLineFast(line, lineNum) {
  if (line.charCodeAt(0) === 91) { // '['
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

  // Fallback
  let level = 'INFO';
  if (/emergency|alert|critical|fatal|panic/i.test(line)) level = 'CRITICAL';
  else if (/error|failed|exception/i.test(line)) level = 'ERROR';
  else if (/warning|warn/i.test(line)) level = 'WARN';

  const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
  const timestamp = timestampMatch ? timestampMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);

  return {
    id: `worker-log-${lineNum}-${Date.now()}`,
    lineNum: lineNum + 1,
    type: 'System',
    timestamp: timestamp,
    level: level,
    hostname: 'localhost',
    service: 'Entrust Core',
    message: line,
    raw: line,
    user: extractUser(line),
    clientIp: extractClientIp(line)
  };
}

function extractUser(line) {
  if (!line || typeof line !== 'string') return null;
  const bcMatch = line.match(/\b(BCClientes[A-Za-z0-9_\-\.\/@]+|BCMercantil[A-Za-z0-9_\-\.\/@]+|BC[A-Za-z0-9_\-\.\/@]+)\b/i);
  if (bcMatch) return bcMatch[1];

  const emailMatch = line.match(/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/i);
  if (emailMatch) return emailMatch[1];

  const match = line.match(/(?:for\s+user|user:?|subjectName:?|user\s*=|username\s*=)\s+(['"]?)([A-Za-z0-9_\-\.\/@]+)\1/i);
  if (match) {
    const candidate = match[2].trim();
    const blacklist = ['calling', 'info', 'debug', 'warn', 'warning', 'error', 'critical', 'fatal', 'trace', 'main', 'false', 'true', 'null', 'undefined', 'n/a', 'none'];
    if (!blacklist.includes(candidate.toLowerCase()) && !candidate.startsWith('net.sf.') && !candidate.startsWith('org.apache.') && !candidate.startsWith('java.')) {
      return candidate;
    }
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
