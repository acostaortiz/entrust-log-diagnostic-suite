/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - WEB WORKER MULTIHILO (v62.0)
   Procesamiento asíncrono en segundo plano para logs gigantes de 200MB+
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
  const chunkSize = 2500;

  for (let i = 0; i < total; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    let parsed = parseSingleLine(line, i);
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

function parseSingleLine(line, lineNum) {
  let level = 'INFO';
  if (/emergency|alert|critical|fatal|panic/i.test(line)) level = 'CRITICAL';
  else if (/error|failed|exception/i.test(line)) level = 'ERROR';
  else if (/warning|warn/i.test(line)) level = 'WARN';

  const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
  const timestamp = timestampMatch ? timestampMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);

  const serviceMatch = line.match(/\[([A-Za-z0-9_.\-$]+)\]/);
  const service = serviceMatch ? serviceMatch[1] : 'Entrust Core';

  const user = extractUser(line);
  const clientIp = extractClientIp(line);

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
    user: user,
    clientIp: clientIp
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
