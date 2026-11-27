// Global HTML sanitizer (safe in Web Worker where `window` is undefined)
(function (root) {
  const escFn = function(text) {
    if (text === null || text === undefined) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };
  if (root && !root.escapeHtml) {
    root.escapeHtml = escFn;
  }
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : globalThis));
if (typeof escapeHtml === 'undefined') {
  var escapeHtml = (typeof self !== 'undefined' && self.escapeHtml)
    ? self.escapeHtml
    : ((typeof window !== 'undefined' && window.escapeHtml) ? window.escapeHtml : (t => String(t ?? '')));
}

/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - WEB WORKER MULTIHILO ULTRA-RÁPIDO (v77.0)
   Procesamiento asíncrono en segundo plano (350.000+ líneas/segundo)
   ========================================================================== */

const TOMCAT_MONTHS = {
  jan: '01', ene: '01', feb: '02', mar: '03',
  apr: '04', abr: '04', may: '05', jun: '06',
  jul: '07', aug: '08', ago: '08', sep: '09', sept: '09',
  oct: '10', nov: '11', dec: '12', dic: '12'
};

const RE_TOMCAT_BANNER = /\b(?:Command line argument:|Server version:|Server built:|Server number:|OS Name:|OS Version:|Architecture:|Java Home:|JVM Version:|JVM Vendor:|CATALINA_BASE:|CATALINA_HOME:|VersionLoggerListener\.log|The Apache Tomcat Native library)\b/i;
const RE_JULI_ONELINE = /^(\d{1,2})-([A-Za-z]{3,4})-(\d{4})\s+(\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\s+(.*)$/;
const RE_JULI_SIMPLE = /^([A-Za-z]{3,4})\s+(\d{1,2}),\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s*(AM|PM|a\.\s*m\.|p\.\s*m\.))?\s+(.*)$/i;
const RE_ISO_LINE = /^(\d{4})[-/](\d{2})[-/](\d{2})[\sT](\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?\s+(.*)$/;
const RE_ENTRUST_SYSLOG = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/;
const RE_SIMPLE_LEVEL_LINE = /^(SEVERE|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST|GRAVE|ADVERTENCIA|INFORMACI[OÓ]N):\s*(.*)$/;
const JAVA_STACK_PATTERNS = [
  /^\s+at\s+[A-Za-z0-9_$.<>\/]+\(/,
  /^\s*Caused by:\s+/,
  /^\s*Suppressed:\s+/,
  /^\s*\.\.\.\s+\d+\s+(?:more|common frames omitted)\b/,
  /^\s*(?:java|javax|jakarta|sun|com\.sun|org\.apache|com\.entrust|oracle|com\.microsoft|org\.postgresql|org\.hibernate|org\.springframework|net\.sf)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/
];
const AUD_FAIL_SET = new Set(['AUD110', 'AUD125', 'AUD126', 'AUD127', 'AUD150', 'AUD153', 'AUD2309', 'AUD4005', 'AUD6002']);
const AUD_WARN_SET = new Set(['AUD151', 'AUD154', 'AUD155', 'AUD6001']);
const WORKER_ENTRUST_NUM_BRACKET_RE = /\[(5(?:2\d{4,5}|[013-9]\d{5}))\]/;
const WORKER_ENTRUST_NUM_LABELED_RE = /(?:error\s*(?:code)?|err(?:or)?Code|faultCode|statusCode|rc|code)\s*[:=\[\(]\s*(5\d{5,6})\b/i;
const WORKER_ENTRUST_USER_CTX_RE = /(?:user(?:name|id|_id)?|for\s+user(?:\s+[^\s]+)?|alias|serial(?:\s*number)?|token|grid|card|phone|tel|cedula|rif|dni|account|session|target|uid|subject|group|ref(?:erence)?|tx(?:id|n)?|trace|req(?:uest)?id|corr(?:elation)?|pid|tid|port|thread|dn|cn|ou)\s*[:=#\/\s(]*['"]?$/i;
const WORKER_ENTRUST_BARE_ERROR_CTX_RE = /(?:error|fail(?:ed|ure)?|exception|fault|invalid|denied|locked|expired|reject(?:ed)?|cannot|unable|entrust|identityguard|severe|critical|fatal)/i;

function workerExtractEntrustNumericCode(text) {
  if (!text) return null;
  const mb = text.match(WORKER_ENTRUST_NUM_BRACKET_RE);
  if (mb) return mb[1];
  const ml = text.match(WORKER_ENTRUST_NUM_LABELED_RE);
  if (ml) return ml[1];
  const stripped = text.trim();
  const hasErrCtx = WORKER_ENTRUST_BARE_ERROR_CTX_RE.test(text);
  const bareRe = /(?:^|[^A-Za-z0-9_\/@\\.-])(520\d{4})(?![A-Za-z0-9_\/@\\.-])/g;
  let bm;
  while ((bm = bareRe.exec(text)) !== null) {
    const code = bm[1];
    if (stripped !== code) {
      if (!hasErrCtx) continue;
      const idx = bm.index + bm[0].indexOf(code);
      const prefix = text.slice(Math.max(0, idx - 40), idx);
      if (WORKER_ENTRUST_USER_CTX_RE.test(prefix)) continue;
    }
    return code;
  }
  return null;
}

function isTomcatStartupBanner(text) {
  return Boolean(text && RE_TOMCAT_BANNER.test(text));
}

function parseTomcatTimestamp(line) {
  if (!line) return { ts: null, rest: line, fmt: null };
  let m = line.match(RE_JULI_ONELINE);
  if (m) {
    const mon = TOMCAT_MONTHS[m[2].toLowerCase()];
    if (mon) {
      const dd = m[1].padStart(2, '0');
      return { ts: `${m[3]}-${mon}-${dd} ${m[4]}`, rest: m[5], fmt: 'juli_oneline' };
    }
  }
  m = line.match(RE_JULI_SIMPLE);
  if (m) {
    const mon = TOMCAT_MONTHS[m[1].toLowerCase()];
    if (mon) {
      const dd = m[2].padStart(2, '0');
      let hh = parseInt(m[4], 10);
      const ampm = (m[7] || '').toLowerCase().replace(/[\s.]/g, '');
      if (ampm === 'am' && hh === 12) hh = 0;
      else if (ampm === 'pm' && hh < 12) hh += 12;
      return { ts: `${m[3]}-${mon}-${dd} ${String(hh).padStart(2, '0')}:${m[5]}:${m[6]}`, rest: m[8], fmt: 'juli_simple' };
    }
  }
  m = line.match(RE_ISO_LINE);
  if (m) {
    return { ts: `${m[1]}-${m[2]}-${m[3]} ${m[4]}`, rest: m[5], fmt: 'iso' };
  }
  m = line.match(RE_ENTRUST_SYSLOG);
  if (m) {
    const mon = TOMCAT_MONTHS[m[1].toLowerCase()];
    if (mon) {
      const dd = m[2].padStart(2, '0');
      const yr = new Date().getFullYear();
      return { ts: `${yr}-${mon}-${dd} ${m[3]}`, rest: m[5], fmt: 'syslog' };
    }
  }
  return { ts: null, rest: line, fmt: null };
}

function isJavaStackContinuation(rawLine) {
  if (!rawLine) return false;
  return JAVA_STACK_PATTERNS.some(re => re.test(rawLine));
}

function isTomcatSimpleLevelLine(rawLine) {
  if (!rawLine) return null;
  const m = rawLine.trim().match(RE_SIMPLE_LEVEL_LINE);
  if (!m) return null;
  const u = m[1].toUpperCase();
  const lvl = u === 'GRAVE' ? 'SEVERE' : (u === 'ADVERTENCIA' ? 'WARNING' : ((u === 'INFORMACION' || u === 'INFORMACIÓN') ? 'INFO' : u));
  return { level: lvl, msg: m[2] };
}

function extractNonVersionIp(text) {
  if (!text) return null;
  if (text.includes('jasperreports') || text.includes('TLS_DHE') || text.includes('virtualizer') || text.includes('delete.on.exit')) {
    return null;
  }
  const re = /(?:^|[^.\d])((?:\d{1,3}\.){3}\d{1,3})(?![.\d])/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const ip = m[1];
    if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip.startsWith('255.')) continue;
    const parts = ip.split('.').map(Number);
    if (!parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) continue;
    const prefix = text.slice(Math.max(0, m.index - 28), m.index).toLowerCase();
    if (/(?:jdk|java|jre|tomcat|version|server number|built|release)\s*[:=\s/\-]*$/.test(prefix)) continue;
    return ip;
  }
  return null;
}

function classifyTomcatJavaEvent(text, baseLevel = 'INFO', hasStack = false) {
  const txt = text || '';
  const low = txt.toLowerCase();
  let baseU = (baseLevel || 'INFO').toUpperCase();
  if (baseU === 'GRAVE') baseU = 'SEVERE';
  else if (baseU === 'ADVERTENCIA') baseU = 'WARNING';

  const c520 = workerExtractEntrustNumericCode(txt);
  if (c520) return { code: c520, level: 'ERROR', service: 'IG.SYSTEM' };

  const aud = txt.match(/(?:\b|\[)(AUD\d{3,4})(?:\b|\])/i);
  if (aud) {
    const audCode = aud[1].toUpperCase();
    let lvl = 'INFO';
    if (AUD_FAIL_SET.has(audCode) || baseU === 'ERROR' || baseU === 'SEVERE' || baseU === 'FATAL' || baseU === 'CRITICAL') lvl = 'ERROR';
    else if (AUD_WARN_SET.has(audCode) || baseU === 'WARNING' || baseU === 'WARN') lvl = 'WARN';
    return { code: audCode, level: lvl, service: 'IG.AUDIT' };
  }

  const ora = txt.match(/\b(ORA-\d{5})\b/i);
  if (ora) return { code: ora[1].toUpperCase(), level: 'CRITICAL', service: 'Oracle Database' };

  if (/(?:ClientAbortException|Broken pipe|Connection reset by peer)/i.test(txt)) {
    return { code: 'TOMCAT_CLIENT_ABORT', level: 'INFO', service: 'Tomcat HTTP ClientAbort' };
  }
  if (/(?:OutOfMemoryError|Java heap space|GC overhead limit exceeded|Metaspace|PermGen space|unable to create new native thread)/i.test(txt)) {
    return { code: 'JVM_OOM', level: 'CRITICAL', service: 'Tomcat JVM Memory' };
  }
  if (/(?:SSLHandshakeException|PKIX path building failed|SunCertPathBuilderException|CertificateExpiredException|CertificateNotYetValidException|KeyStoreException|UnrecoverableKeyException|SSLException|handshake_failure|bad_certificate|certificate_unknown|protocol_version)/i.test(txt)) {
    return { code: 'TOMCAT_SSL_TLS', level: 'ERROR', service: 'Tomcat TLS / Keystore' };
  }
  if (/(?:SQLException|SQLRecoverableException|SQLTransientConnectionException|SQLNonTransientConnectionException|SQLTimeoutException|CannotGetJdbcConnectionException|HikariPool|BasicDataSource|PoolExhaustedException|CommunicationsException|JdbcCardRepository|BlobAccess|AuditDBLogger|No suitable driver)/i.test(txt)) {
    return { code: 'JDBC_SQL_EXCEPTION', level: 'ERROR', service: 'Tomcat JDBC Pool' };
  }
  if (/(?:LDAPException|javax\.naming\.CommunicationException|javax\.naming\.AuthenticationException|javax\.naming\.NamingException|PartialResultException|LDAP:\s*error code)/i.test(txt)) {
    return { code: 'TOMCAT_LDAP_ERROR', level: 'ERROR', service: 'Tomcat LDAP / JNDI' };
  }
  if (/(?:BindException|Address already in use|ConnectException|SocketTimeoutException|UnknownHostException|NoRouteToHostException|Port\s+\d+.*already in use)/i.test(txt)) {
    return { code: 'TOMCAT_NETWORK_ERROR', level: 'ERROR', service: 'Tomcat Network / Socket' };
  }
  if (/(?:ClassNotFoundException|NoClassDefFoundError|UnsatisfiedLinkError|LifecycleException|Failed to start component|Error listenerStart|Error filterStart|startup failed)/i.test(txt)) {
    return { code: 'TOMCAT_DEPLOY_ERROR', level: 'CRITICAL', service: 'Tomcat Lifecycle / Deploy' };
  }
  if (/(?:StuckThreadDetectionValve|All threads .* are currently busy|maxThreads|RejectedExecutionException|failed to stop thread|memory leak)/i.test(txt)) {
    const isErr = baseU === 'SEVERE' || baseU === 'FATAL' || baseU === 'ERROR' || baseU === 'CRITICAL' || low.includes('rejectedexecutionexception');
    return { code: 'TOMCAT_THREAD_POOL', level: isErr ? 'ERROR' : 'WARN', service: 'Tomcat Executor / Threads' };
  }

  const isErrLvl = baseU === 'SEVERE' || baseU === 'FATAL' || baseU === 'ERROR' || baseU === 'CRITICAL';
  if ((isErrLvl || hasStack) && (/\b[a-z][a-z0-9_.]*\.[A-Z][A-Za-z0-9_]*(?:Exception|Error|Throwable)\b/.test(txt) || low.includes('caused by:'))) {
    return { code: 'TOMCAT_JAVA_EXCEPTION', level: 'ERROR', service: 'Tomcat JVM Exception' };
  }
  if (isErrLvl) return { code: 'TOMCAT_SEVERE', level: 'ERROR', service: 'Tomcat Catalina' };
  if (baseU === 'WARNING' || baseU === 'WARN') return { code: 'TOMCAT_WARN', level: 'WARN', service: 'Tomcat Catalina' };
  if (/(?:Server startup in|Starting ProtocolHandler|Starting Servlet Engine|Deploying web application|Deployment of web application|Stopping service|Destroying ProtocolHandler|Initialization processed in)/i.test(txt)) {
    return { code: 'TOMCAT_LIFECYCLE', level: 'INFO', service: 'Tomcat Catalina' };
  }
  return { code: 'TOMCAT_INFO', level: 'INFO', service: 'Tomcat Catalina' };
}

function finalizePendingEvent(pending) {
  if (!pending) return null;
  const meta = pending._meta || {};
  if (meta.stackFrames > 0 || (meta.causes && meta.causes.length > 0)) {
    const combined = `${pending.message || ''} ${meta.causes.join(' ')}`;
    const cls = classifyTomcatJavaEvent(combined, meta.baseLevel || 'INFO', true);
    const oraCause = meta.causes.join(' ').match(/\b(ORA-\d{5})\b/i);
    if (meta.lockedCode) {
      if (oraCause) {
        pending.entrustCode = oraCause[1].toUpperCase();
        pending.level = 'CRITICAL';
        pending.service = 'Oracle Database';
      }
    } else {
      pending.entrustCode = cls.code;
      pending.level = cls.level;
      pending.service = cls.service;
    }
    const extraParts = [];
    if (meta.causes.length > 0) {
      extraParts.push('Root Cause: ' + meta.causes[meta.causes.length - 1].replace(/^Caused by:\s*/i, '').trim());
    }
    if (meta.entrustFrame) {
      extraParts.push('Frame: ' + meta.entrustFrame);
    }
    if (extraParts.length > 0) {
      const extraStr = ' | ' + extraParts.join(' | ');
      const baseMsg = String(pending.message || '');
      pending.message = (baseMsg.length + extraStr.length > 600)
        ? (baseMsg.slice(0, Math.max(180, 596 - extraStr.length)).trimEnd() + '…' + extraStr).slice(0, 600)
        : (baseMsg + extraStr);
    }
    if (meta.stackFrames > 0) {
      const suffix = `\n[+${meta.stackFrames} stack frames]`;
      const baseRaw = String(pending.raw || '');
      pending.raw = (baseRaw.slice(0, Math.max(200, 1800 - suffix.length)) + suffix).slice(0, 1800);
    }
  }
  delete pending._meta;
  return pending;
}

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
  let lastSeenTs = '';
  let pending = null;
  let eventIdx = 0;

  for (let i = 0; i < total; i++) {
    const rawLine = lines[i].replace(/\r$/, '');
    const line = rawLine.trim();
    if (!line) continue;

    if (pending && pending._meta && pending._meta.isTomcatSimpleHdr) {
      const lvlPair = isTomcatSimpleLevelLine(rawLine);
      if (lvlPair) {
        pending._meta.baseLevel = lvlPair.level;
        pending._meta.isTomcatSimpleHdr = false;
        const mergedMsg = `${pending.message} — ${lvlPair.level}: ${lvlPair.msg}`.trim();
        pending.message = mergedMsg.slice(0, 600);
        if (pending.raw.length < 1600) pending.raw = (pending.raw + '\n' + line).slice(0, 1600);
        if (!pending._meta.lockedCode) {
          const cls = classifyTomcatJavaEvent(mergedMsg, lvlPair.level);
          pending.entrustCode = cls.code;
          pending.level = cls.level;
          pending.service = cls.service;
          pending._meta.lockedCode = /^(?:520\d{4}|AUD\d+|ORA-)/i.test(cls.code);
        }
        continue;
      }
    }

    if (pending && isJavaStackContinuation(rawLine)) {
      const m = pending._meta;
      m.stackFrames++;
      if (/^(?:Caused by:|Suppressed:)|^(?:java|javax|jakarta|oracle|org\.apache|com\.entrust)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/.test(line)) {
        if (m.causes.length < 6) m.causes.push(line.slice(0, 220));
      }
      if (!m.entrustFrame && line.includes('com.entrust.')) {
        m.entrustFrame = line.replace(/^at\s+/, '').trim().slice(0, 140);
      }
      if (pending.raw.length < 1550) pending.raw = (pending.raw + '\n' + line).slice(0, 1600);
      continue;
    }

    if (pending) {
      const doneEv = finalizePendingEvent(pending);
      if (doneEv) {
        if (clientId) doneEv.client = clientId;
        parsedLogs.push(doneEv);
      }
      pending = null;
    }

    eventIdx++;
    const nextEv = parseSingleLineFast(line, eventIdx - 1, lastSeenTs);
    if (nextEv) {
      if (nextEv._meta && nextEv._meta.hasExplicitTs && nextEv.timestamp) {
        lastSeenTs = nextEv.timestamp;
      }
      pending = nextEv;
    }

    if (i % chunkSize === 0 || i === total - 1) {
      const pct = Math.round(((i + 1) / total) * 100);
      self.postMessage({ type: 'progress', current: i + 1, total, pct });
    }
  }

  if (pending) {
    const doneEv = finalizePendingEvent(pending);
    if (doneEv) {
      if (clientId) doneEv.client = clientId;
      parsedLogs.push(doneEv);
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
  let rawLinesRead = 0;
  let foldedStackLines = 0;
  let totalErrors = 0;
  let totalWarnings = 0;
  let lastSeenTs = '';
  let pending = null;

  // Agregadores Globales para el Panorama Completo (100% de los 9.7 GB)
  const userCounter = {};
  const userDetails = {};
  const ipCounter = {};
  const codeCounter = {};
  const timeBuckets = {};

  // Buffer de visualización interactiva en UI (máximo 150.000 registros por archivo para evitar OOM)
  const displayLogs = [];
  const MAX_DISPLAY_LOGS = 150000;
  let displayErrorCount = 0;

  let lastProgressReportTime = 0;

  const commitEvent = (ev) => {
    const parsed = finalizePendingEvent(ev);
    if (!parsed) return;
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
    if (dateBucket && /^\d{4}-\d{2}-\d{2}/.test(dateBucket) && dateBucket.length >= 10) {
      if (!timeBuckets[dateBucket]) timeBuckets[dateBucket] = { total: 0, critical: 0, warn: 0 };
      timeBuckets[dateBucket].total++;
      if (isError) timeBuckets[dateBucket].critical++;
      if (isWarn) timeBuckets[dateBucket].warn++;
    }

    // 5. Retención amplia hasta 150k registros (prioriza Errores, Alertas, AUD y Usuarios)
    const isPriority = isError || isWarn || (parsed.entrustCode && /^AUD/i.test(parsed.entrustCode)) || (parsed.user && parsed.user !== 'N/A');
    if (isPriority && displayErrorCount < 100000) {
      displayErrorCount++;
      displayLogs.push(parsed);
    } else if (displayLogs.length < MAX_DISPLAY_LOGS && (displayLogs.length < 50000 || lineCount % 10 === 0)) {
      displayLogs.push(parsed);
    }
  };

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
      const rawLine = lines[i].replace(/\r$/, '');
      const line = rawLine.trim();
      if (!line) continue;
      rawLinesRead++;

      if (pending && pending._meta && pending._meta.isTomcatSimpleHdr) {
        const lvlPair = isTomcatSimpleLevelLine(rawLine);
        if (lvlPair) {
          pending._meta.baseLevel = lvlPair.level;
          pending._meta.isTomcatSimpleHdr = false;
          const mergedMsg = `${pending.message} — ${lvlPair.level}: ${lvlPair.msg}`.trim();
          pending.message = mergedMsg.slice(0, 600);
          if (pending.raw.length < 1600) pending.raw = (pending.raw + '\n' + line).slice(0, 1600);
          if (!pending._meta.lockedCode) {
            const cls = classifyTomcatJavaEvent(mergedMsg, lvlPair.level);
            pending.entrustCode = cls.code;
            pending.level = cls.level;
            pending.service = cls.service;
            pending._meta.lockedCode = /^(?:520\d{4}|AUD\d+|ORA-)/i.test(cls.code);
          }
          foldedStackLines++;
          continue;
        }
      }

      if (pending && isJavaStackContinuation(rawLine)) {
        const m = pending._meta;
        m.stackFrames++;
        foldedStackLines++;
        if (/^(?:Caused by:|Suppressed:)|^(?:java|javax|jakarta|oracle|org\.apache|com\.entrust)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/.test(line)) {
          if (m.causes.length < 6) m.causes.push(line.slice(0, 220));
        }
        if (!m.entrustFrame && line.includes('com.entrust.')) {
          m.entrustFrame = line.replace(/^at\s+/, '').trim().slice(0, 140);
        }
        if (pending.raw.length < 1550) pending.raw = (pending.raw + '\n' + line).slice(0, 1600);
        continue;
      }

      if (pending) {
        commitEvent(pending);
        pending = null;
      }

      lineCount++;
      const parsed = parseSingleLineFast(line, lineCount, lastSeenTs);
      if (parsed) {
        if (parsed._meta && parsed._meta.hasExplicitTs && parsed.timestamp) {
          lastSeenTs = parsed.timestamp;
        }
        pending = parsed;
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
    const rawLine = leftover.replace(/\r$/, '');
    const line = rawLine.trim();
    rawLinesRead++;
    if (pending && pending._meta && pending._meta.isTomcatSimpleHdr) {
      const lvlPair = isTomcatSimpleLevelLine(rawLine);
      if (lvlPair) {
        pending._meta.baseLevel = lvlPair.level;
        pending._meta.isTomcatSimpleHdr = false;
        const mergedMsg = `${pending.message} — ${lvlPair.level}: ${lvlPair.msg}`.trim();
        pending.message = mergedMsg.slice(0, 600);
        if (!pending._meta.lockedCode) {
          const cls = classifyTomcatJavaEvent(mergedMsg, lvlPair.level);
          pending.entrustCode = cls.code;
          pending.level = cls.level;
          pending.service = cls.service;
        }
        foldedStackLines++;
      } else if (isJavaStackContinuation(rawLine)) {
        pending._meta.stackFrames++;
        foldedStackLines++;
      } else {
        commitEvent(pending);
        pending = null;
        lineCount++;
        pending = parseSingleLineFast(line, lineCount, lastSeenTs);
      }
    } else if (pending && isJavaStackContinuation(rawLine)) {
      pending._meta.stackFrames++;
      foldedStackLines++;
    } else {
      if (pending) commitEvent(pending);
      lineCount++;
      pending = parseSingleLineFast(line, lineCount, lastSeenTs);
    }
  }

  if (pending) {
    commitEvent(pending);
    pending = null;
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
      rawLinesRead: rawLinesRead,
      foldedStackLines: foldedStackLines,
      totalErrors: totalErrors,
      totalWarnings: totalWarnings,
      topUsers: topUsers,
      topIps: topIps,
      topCodes: topCodes,
      timeBuckets: timeBuckets
    }
  });
}

function parseSingleLineFast(line, lineNum, lastSeenTs = '') {
  // 1. Formato IdentityGuard OnPremise Bracket: [2026-09-08 10:15:23] [http-nio-8443-exec-12] [ERROR] ...
  if (line.charCodeAt(0) === 91) {
    const tsStart = line.charCodeAt(1) === 91 ? 2 : 1;
    const p1 = line.indexOf(']', tsStart);
    if (p1 > 8 && p1 < 38) {
      const timestamp = line.substring(tsStart, p1).slice(0, 19);

      const p2Start = line.indexOf('[', p1 + 1);
      const p2End = p2Start !== -1 ? line.indexOf(']', p2Start + 1) : -1;
      const category_or_thread = p2End !== -1 ? line.substring(p2Start + 1, p2End) : 'main';

      const p3Start = p2End !== -1 ? line.indexOf('[', p2End + 1) : -1;
      const p3End = p3Start !== -1 ? line.indexOf(']', p3Start + 1) : -1;
      const rawLevel = p3End !== -1 ? line.substring(p3Start + 1, p3End).trim() : 'INFO';

      const p4Start = p3End !== -1 ? line.indexOf('[', p3End + 1) : -1;
      const p4End = p4Start !== -1 ? line.indexOf(']', p4Start + 1) : -1;
      const category = p4End !== -1 ? line.substring(p4Start + 1, p4End).trim() : category_or_thread;

      const message = p4End !== -1 ? line.substring(p4End + 1).trim() : line.substring(p1 + 1).trim();

      let level = 'INFO';
      if (rawLevel.includes('ERR') || rawLevel.includes('CRIT') || rawLevel.includes('FATAL') || rawLevel.includes('SEVERE')) {
        level = 'ERROR';
      } else if (rawLevel.includes('WARN')) {
        level = 'WARN';
      }

      let entrustCode = null;
      let lockedCode = false;
      const c520 = workerExtractEntrustNumericCode(line);
      if (c520) {
        entrustCode = c520;
        level = 'ERROR';
        lockedCode = true;
      } else {
        const audIdx = line.indexOf('AUD');
        if (audIdx !== -1 && /AUD\d{3,4}/i.test(line.substring(audIdx, audIdx + 7))) {
          entrustCode = line.substring(audIdx, audIdx + 7).replace(/[^A-Za-z0-9]/g, '').toUpperCase();
          lockedCode = true;
          if (AUD_FAIL_SET.has(entrustCode)) level = 'ERROR';
          else if (AUD_WARN_SET.has(entrustCode) && level === 'INFO') level = 'WARN';
        } else {
          const oraM = line.match(/\b(ORA-\d{5})\b/i);
          if (oraM) {
            entrustCode = oraM[1].toUpperCase();
            level = 'CRITICAL';
            lockedCode = true;
          }
        }
      }

      const user = isTomcatStartupBanner(line) ? null : extractUser(line);
      const clientIp = extractClientIp(line);

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
        entrustCode: entrustCode,
        _meta: {
          hasExplicitTs: /^\d{4}[-/.]\d{2}[-/.]\d{2}/.test(timestamp),
          isTomcatSimpleHdr: false,
          baseLevel: rawLevel.toUpperCase(),
          lockedCode: lockedCode,
          stackFrames: 0,
          causes: [],
          entrustFrame: ''
        }
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
    } else if (/currently has a password|Password will not be migrated/i.test(line)) {
      entrustCode = 'bulkidentityguard.add.error.password';
      service = 'IDaaS Bulk Password Engine';
    } else if (/already has QA|QA in migration file/i.test(line)) {
      entrustCode = 'bulkidentityguard.add.error.qa';
      service = 'IDaaS Bulk Q&A Engine';
    }

    const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
    const timestamp = timestampMatch ? timestampMatch[1] : (lastSeenTs || '');

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
      entrustCode: entrustCode,
      _meta: { hasExplicitTs: Boolean(timestampMatch), isTomcatSimpleHdr: false, baseLevel: level, lockedCode: true, stackFrames: 0, causes: [], entrustFrame: '' }
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
      if (!formattedTime) formattedTime = lastSeenTs || '';

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
        entrustCode: eventType,
        _meta: { hasExplicitTs: Boolean(rawTime), isTomcatSimpleHdr: false, baseLevel: level, lockedCode: true, stackFrames: 0, causes: [], entrustFrame: '' }
      };
    }
  }

  // 2.5 Entrust Linux Syslog + Apache Tomcat JULI / Catalina
  const { ts, rest, fmt } = parseTomcatTimestamp(line);
  if (ts) {
    if (fmt === 'syslog' && (rest.startsWith('[') || rest.includes('[520') || rest.includes('AUD') || Boolean(workerExtractEntrustNumericCode(rest)))) {
      const lvlM = rest.match(/\[(ERROR|FATAL|SEVERE|CRIT|CRITICAL|WARN|WARNING|INFO|DEBUG)\s*\]/i);
      const baseLvl = lvlM ? lvlM[1].toUpperCase() : ((rest.includes('FAILED') || rest.includes('[520') || Boolean(workerExtractEntrustNumericCode(rest))) ? 'ERROR' : 'INFO');
      const cls = classifyTomcatJavaEvent(line, baseLvl);
      const lockedCode = /^(?:520\d{4}|AUD\d+|ORA-)/i.test(cls.code);
      return {
        id: `worker-log-${lineNum}-${Date.now()}`,
        lineNum: lineNum + 1,
        type: 'Entrust Syslog / Catalina',
        timestamp: ts,
        level: cls.level,
        hostname: 'localhost',
        service: cls.service,
        message: rest.slice(0, 600),
        raw: line,
        user: isTomcatStartupBanner(line) ? null : extractUser(line),
        clientIp: extractNonVersionIp(rest),
        entrustCode: cls.code,
        _meta: { hasExplicitTs: true, isTomcatSimpleHdr: false, baseLevel: baseLvl, lockedCode: lockedCode, stackFrames: 0, causes: [], entrustFrame: '' }
      };
    }

    const isIsoTomcatJava = (fmt === 'iso') && (
      /\b(?:SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|GRAVE|ADVERTENCIA)\b/.test(rest) ||
      /(?:catalina|org\.apache|com\.entrust|Exception|Error|Server startup|Starting ProtocolHandler|HikariPool|ORA-\d{5}|520\d{4}|AUD\d{3,4})/.test(line)
    );
    if (fmt === 'juli_oneline' || fmt === 'juli_simple' || isIsoTomcatJava) {
      let baseLvl = 'INFO';
      let msg = rest;
      let isSimpleHdr = false;
      if (fmt === 'juli_oneline') {
        const mOne = rest.match(/^([A-ZÁÉÍÓÚÑ]+)\s+\[([^\]]*)\]\s+(.*)$/);
        if (mOne) {
          baseLvl = mOne[1].toUpperCase();
          msg = `[${mOne[2]}] ${mOne[3]}`;
        } else {
          const mLvl = rest.match(/^(SEVERE|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST|GRAVE|ADVERTENCIA)\s+(.*)$/i);
          if (mLvl) {
            baseLvl = mLvl[1].toUpperCase();
            msg = mLvl[2];
          }
        }
      } else if (fmt === 'juli_simple') {
        isSimpleHdr = true;
        const mLvl = rest.match(/\b(SEVERE|FATAL|ERROR|WARNING|WARN|GRAVE|ADVERTENCIA)\b/);
        if (mLvl) baseLvl = mLvl[1].toUpperCase();
      } else {
        const mLvl = rest.match(/^[\[\s]*(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|GRAVE|ADVERTENCIA)[\]\s:]+(.*)$/i)
          || rest.match(/\b(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG)\b/);
        if (mLvl) {
          baseLvl = mLvl[1].toUpperCase();
          if (mLvl[2]) msg = mLvl[2];
        }
      }
      const cls = classifyTomcatJavaEvent(line, baseLvl);
      const lockedCode = /^(?:520\d{4}|AUD\d+|ORA-)/i.test(cls.code);
      return {
        id: `worker-log-${lineNum}-${Date.now()}`,
        lineNum: lineNum + 1,
        type: 'Tomcat Catalina',
        timestamp: ts,
        level: cls.level,
        hostname: 'idg-tomcat-srv',
        service: cls.service,
        message: msg.slice(0, 600),
        raw: line,
        user: isTomcatStartupBanner(line) ? null : extractUser(line),
        clientIp: extractNonVersionIp(msg),
        entrustCode: cls.code,
        _meta: { hasExplicitTs: true, isTomcatSimpleHdr: isSimpleHdr, baseLevel: baseLvl, lockedCode: lockedCode, stackFrames: 0, causes: [], entrustFrame: '' }
      };
    }
  }

  // 3. Huérfana Java/Oracle sin timestamp
  if (isJavaStackContinuation(line) || /\b(ORA-\d{5}|SQLException|OutOfMemoryError|SSLHandshakeException|Exception|Error)\b/.test(line)) {
    const baseLvl = /(?:ClientAbortException|Broken pipe|Connection reset by peer)/i.test(line) ? 'INFO' : 'ERROR';
    const cls = classifyTomcatJavaEvent(line, baseLvl, true);
    return {
      id: `worker-log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Tomcat Catalina / Java',
      timestamp: lastSeenTs || '',
      level: cls.level,
      hostname: 'idg-tomcat-srv',
      service: cls.service,
      message: line.slice(0, 600),
      raw: line,
      user: isTomcatStartupBanner(line) ? null : extractUser(line),
      clientIp: extractNonVersionIp(line),
      entrustCode: cls.code,
      _meta: { hasExplicitTs: false, isTomcatSimpleHdr: false, baseLevel: baseLvl, lockedCode: false, stackFrames: 0, causes: [], entrustFrame: '' }
    };
  }

  // Fallback OnPremise / SSH / Sistema (Cero contaminación IDaaS)
  let level = 'INFO';
  if (/emergency|alert|critical|fatal|panic/i.test(line)) level = 'CRITICAL';
  else if (/error|failed|exception|invalid|locked|severe/i.test(line)) level = 'ERROR';
  else if (/warning|warn/i.test(line)) level = 'WARN';

  let entrustCode = null;
  let service = 'IdentityGuard OnPremise';
  let typeLabel = 'Entrust IdentityGuard';
  let hostLabel = 'localhost';

  const c520 = workerExtractEntrustNumericCode(line);
  const aud = line.match(/AUD\d{3,4}/i);
  const ora = line.match(/ORA-\d{5}/);
  const sshTarget = line.match(/Target:\s*([^\s]+\:ssh)/i);

  if (c520) {
    entrustCode = c520;
    service = 'IG.SYSTEM';
    level = 'ERROR';
  } else if (aud) {
    entrustCode = aud[0].toUpperCase();
    service = 'IG.AUDIT';
    if (entrustCode === 'AUD6001' || entrustCode === 'AUD6002' || entrustCode === 'AUD2309') {
      if (level === 'INFO') level = 'WARN';
    }
  } else if (ora) {
    entrustCode = ora[0];
    service = 'Oracle Database';
    level = 'ERROR';
  } else if (sshTarget || /\b(?:sshd|pam_unix|sudo)\b/i.test(line) || (line.includes('Origin:') && line.includes('Target:'))) {
    entrustCode = level === 'ERROR' ? 'SSH-FAIL' : 'SSH-AUTH';
    service = 'SSH / PAM OS';
    typeLabel = 'Linux OS / SSHD';
    if (sshTarget) hostLabel = sshTarget[1];
  }

  const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?)/);
  const timestamp = timestampMatch ? timestampMatch[1].replace('T', ' ').substring(0, 19) : (ts || lastSeenTs || '');

  return {
    id: `worker-log-${lineNum}-${Date.now()}`,
    lineNum: lineNum + 1,
    type: typeLabel,
    timestamp: timestamp,
    level: level,
    hostname: hostLabel,
    service: service,
    message: line,
    raw: line,
    user: isTomcatStartupBanner(line) ? null : extractUser(line),
    clientIp: extractNonVersionIp(line),
    entrustCode: entrustCode,
    _meta: { hasExplicitTs: Boolean(timestampMatch || ts), isTomcatSimpleHdr: false, baseLevel: level, lockedCode: Boolean(c520 || aud || ora), stackFrames: 0, causes: [], entrustFrame: '' }
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
      'type', 'user', 'users', 'admin_console', 'user_3238', 'user_8912', 'user_1042',
      'catalina', 'tomcat', 'servlet', 'jsp', 'valve', 'connector', 'coyote', 'jasper',
      'naming', 'wrapper', 'lifecycle', 'protocol', 'standardcontext', 'standardengine',
      'standardhost', 'standardservice', 'standardwrapper', 'ajp', 'nio', 'apr', 'ssl',
      'tls', 'keystore', 'truststore', 'cacerts', 'jvm', 'java', 'jdk', 'jre', 'gc',
      'heap', 'metaspace', 'permgen', 'oom', 'stdout', 'stderr', 'localhost', 'webapps',
      'bootstrap', 'classloader', 'webappclassloader', 'jndi', 'datasource', 'driver',
      'hikari', 'dbcp', 'postgres', 'postgresql', 'sqlserver', 'mysql', 'charset',
      'utf-8', 'iso-8859-1', 'tomcat8', 'tomcat9'
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
