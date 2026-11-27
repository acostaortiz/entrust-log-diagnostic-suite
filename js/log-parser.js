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

/**
 * LOG-PARSER: Motor de Lectura, Extracción y Análisis Multi-Formato
 * Soporta Entrust IdentityGuard OnPremise (Errores 520xxx y Auditoría AUDxxx),
 * Syslog, Auditd, JSON, Nginx/Apache Access Logs y Trazas Distribuidas OpenTelemetry.
 */

const LP_TOMCAT_MONTHS = {
  jan: '01', ene: '01', feb: '02', mar: '03',
  apr: '04', abr: '04', may: '05', jun: '06',
  jul: '07', aug: '08', ago: '08', sep: '09', sept: '09',
  oct: '10', nov: '11', dec: '12', dic: '12'
};
const LP_RE_TOMCAT_BANNER = /\b(?:Command line argument:|Server version:|Server built:|Server number:|OS Name:|OS Version:|Architecture:|Java Home:|JVM Version:|JVM Vendor:|CATALINA_BASE:|CATALINA_HOME:|VersionLoggerListener\.log|The Apache Tomcat Native library)\b/i;
const LP_RE_JULI_ONELINE = /^(\d{1,2})-([A-Za-z]{3,4})-(\d{4})\s+(\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\s+(.*)$/;
const LP_RE_JULI_SIMPLE = /^([A-Za-z]{3,4})\s+(\d{1,2}),\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s*(AM|PM|a\.\s*m\.|p\.\s*m\.))?\s+(.*)$/i;
const LP_RE_ISO_LINE = /^(\d{4})[-/](\d{2})[-/](\d{2})[\sT](\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?\s+(.*)$/;
const LP_RE_ENTRUST_SYSLOG = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/;
const LP_RE_SIMPLE_LEVEL = /^(SEVERE|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST|GRAVE|ADVERTENCIA|INFORMACI[OÓ]N):\s*(.*)$/;
const LP_JAVA_STACK_PATTERNS = [
  /^\s+at\s+[A-Za-z0-9_$.<>\/]+\(/,
  /^\s*Caused by:\s+/,
  /^\s*Suppressed:\s+/,
  /^\s*\.\.\.\s+\d+\s+(?:more|common frames omitted)\b/,
  /^\s*(?:java|javax|jakarta|sun|com\.sun|org\.apache|com\.entrust|oracle|com\.microsoft|org\.postgresql|org\.hibernate|org\.springframework|net\.sf)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/
];
const LP_AUD_FAIL_SET = new Set(['AUD110', 'AUD125', 'AUD126', 'AUD127', 'AUD150', 'AUD153', 'AUD2309', 'AUD4005', 'AUD6002']);
const LP_AUD_WARN_SET = new Set(['AUD151', 'AUD154', 'AUD155', 'AUD6001']);
const LP_ENTRUST_NUM_BRACKET_RE = /\[(5(?:2\d{4,5}|[013-9]\d{5}))\]/;
const LP_ENTRUST_NUM_LABELED_RE = /(?:error\s*(?:code)?|err(?:or)?Code|faultCode|statusCode|rc|code)\s*[:=\[\(]\s*(5\d{5,6})\b/i;
const LP_ENTRUST_USER_CTX_RE = /(?:user(?:name|id|_id)?|for\s+user(?:\s+[^\s]+)?|alias|serial(?:\s*number)?|token|grid|card|phone|tel|cedula|rif|dni|account|session|target|uid|subject|group|ref(?:erence)?|tx(?:id|n)?|trace|req(?:uest)?id|corr(?:elation)?|pid|tid|port|thread|dn|cn|ou)\s*[:=#\/\s(]*['"]?$/i;
const LP_ENTRUST_BARE_ERROR_CTX_RE = /(?:error|fail(?:ed|ure)?|exception|fault|invalid|denied|locked|expired|reject(?:ed)?|cannot|unable|entrust|identityguard|severe|critical|fatal)/i;

function lpIsEntrustNumericCode(code) {
  return /^5(?:2\d{4,5}|[013-9]\d{5})$/.test(String(code || '').trim());
}

function lpExtractEntrustNumericCode(text) {
  if (!text) return null;
  const mb = text.match(LP_ENTRUST_NUM_BRACKET_RE);
  if (mb) return mb[1];
  const ml = text.match(LP_ENTRUST_NUM_LABELED_RE);
  if (ml) return ml[1];
  const stripped = text.trim();
  const hasErrCtx = LP_ENTRUST_BARE_ERROR_CTX_RE.test(text);
  const bareRe = /(?:^|[^A-Za-z0-9_\/@\\.-])(520\d{4})(?![A-Za-z0-9_\/@\\.-])/g;
  let bm;
  while ((bm = bareRe.exec(text)) !== null) {
    const code = bm[1];
    if (stripped !== code) {
      if (!hasErrCtx) continue;
      const idx = bm.index + bm[0].indexOf(code);
      const prefix = text.slice(Math.max(0, idx - 40), idx);
      if (LP_ENTRUST_USER_CTX_RE.test(prefix)) continue;
    }
    return code;
  }
  return null;
}

class LogParser {
  constructor() {
    this.severityLevels = ['EMERGENCY', 'CRITICAL', 'ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG'];
  }

  _parseTomcatTimestamp(line) {
    if (!line) return { ts: null, rest: line, fmt: null };
    let m = line.match(LP_RE_JULI_ONELINE);
    if (m) {
      const mon = LP_TOMCAT_MONTHS[m[2].toLowerCase()];
      if (mon) return { ts: `${m[3]}-${mon}-${m[1].padStart(2, '0')} ${m[4]}`, rest: m[5], fmt: 'juli_oneline' };
    }
    m = line.match(LP_RE_JULI_SIMPLE);
    if (m) {
      const mon = LP_TOMCAT_MONTHS[m[1].toLowerCase()];
      if (mon) {
        let hh = parseInt(m[4], 10);
        const ampm = (m[7] || '').toLowerCase().replace(/[\s.]/g, '');
        if (ampm === 'am' && hh === 12) hh = 0;
        else if (ampm === 'pm' && hh < 12) hh += 12;
        return { ts: `${m[3]}-${mon}-${m[2].padStart(2, '0')} ${String(hh).padStart(2, '0')}:${m[5]}:${m[6]}`, rest: m[8], fmt: 'juli_simple' };
      }
    }
    m = line.match(LP_RE_ISO_LINE);
    if (m) return { ts: `${m[1]}-${m[2]}-${m[3]} ${m[4]}`, rest: m[5], fmt: 'iso' };
    m = line.match(LP_RE_ENTRUST_SYSLOG);
    if (m) {
      const mon = LP_TOMCAT_MONTHS[m[1].toLowerCase()];
      if (mon) return { ts: `${new Date().getFullYear()}-${mon}-${m[2].padStart(2, '0')} ${m[3]}`, rest: m[5], fmt: 'syslog' };
    }
    return { ts: null, rest: line, fmt: null };
  }

  _isJavaStackContinuation(rawLine) {
    return Boolean(rawLine && LP_JAVA_STACK_PATTERNS.some(re => re.test(rawLine)));
  }

  _isTomcatSimpleLevelLine(rawLine) {
    if (!rawLine) return null;
    const m = rawLine.trim().match(LP_RE_SIMPLE_LEVEL);
    if (!m) return null;
    const u = m[1].toUpperCase();
    const lvl = u === 'GRAVE' ? 'SEVERE' : (u === 'ADVERTENCIA' ? 'WARNING' : ((u === 'INFORMACION' || u === 'INFORMACIÓN') ? 'INFO' : u));
    return { level: lvl, msg: m[2] };
  }

  _isTomcatStartupBanner(text) {
    return Boolean(text && LP_RE_TOMCAT_BANNER.test(text));
  }

  _extractNonVersionIp(text) {
    if (!text) return null;
    if (text.includes('jasperreports') || text.includes('TLS_DHE') || text.includes('virtualizer') || text.includes('delete.on.exit')) return null;
    const re = /(?:^|[^.\d])((?:\d{1,3}\.){3}\d{1,3})(?![.\d])/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const ip = m[1];
      if (ip === '127.0.0.1' || ip === '0.0.0.0' || ip.startsWith('255.')) continue;
      if (!ip.split('.').every(p => { const n = Number(p); return !isNaN(n) && n >= 0 && n <= 255; })) continue;
      const prefix = text.slice(Math.max(0, m.index - 28), m.index).toLowerCase();
      if (/(?:jdk|java|jre|tomcat|version|server number|built|release)\s*[:=\s/\-]*$/.test(prefix)) continue;
      return ip;
    }
    return null;
  }

  _classifyTomcatJavaEvent(text, baseLevel = 'INFO', hasStack = false) {
    const txt = text || '';
    const low = txt.toLowerCase();
    let baseU = (baseLevel || 'INFO').toUpperCase();
    if (baseU === 'GRAVE') baseU = 'SEVERE';
    else if (baseU === 'ADVERTENCIA') baseU = 'WARNING';

    const c520 = lpExtractEntrustNumericCode(txt);
    if (c520) return { code: c520, level: 'ERROR', service: 'IG.SYSTEM' };

    const aud = txt.match(/(?:\b|\[)(AUD\d{2,5})(?:\b|\])/i);
    if (aud) {
      const audCode = aud[1].toUpperCase();
      let lvl = 'INFO';
      if (LP_AUD_FAIL_SET.has(audCode) || baseU === 'ERROR' || baseU === 'SEVERE' || baseU === 'FATAL' || baseU === 'CRITICAL') lvl = 'ERROR';
      else if (LP_AUD_WARN_SET.has(audCode) || baseU === 'WARNING' || baseU === 'WARN') lvl = 'WARN';
      return { code: audCode, level: lvl, service: 'IG.AUDIT' };
    }

    const ora = txt.match(/\b(ORA-\d{4,5})\b/i);
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

  _parseSingleEventRecord(line, index, lastSeenTs = '') {
    let parsed = this.tryParseEntrustMigrationLog(line, index, lastSeenTs);
    if (!parsed) parsed = this.fastParseEntrustBracket(line, index);
    if (!parsed) parsed = this.tryParseEntrustIdentityGuard(line, index, lastSeenTs);
    if (!parsed) parsed = this.tryParseSoapWebService(line, index, lastSeenTs);
    if (!parsed) parsed = this.tryParseTomcatCatalina(line, index, lastSeenTs);
    if (!parsed) parsed = this.tryParseEntrustIdaasAuditTsv(line, index);
    if (!parsed) parsed = this.tryParseCsv(line, index, lastSeenTs);
    if (!parsed) parsed = this.tryParseJson(line, index);
    if (!parsed) parsed = this.tryParseAuditd(line, index);
    if (!parsed) parsed = this.tryParseSyslog(line, index);
    if (!parsed) parsed = this.tryParseWebAccess(line, index);
    if (!parsed) parsed = this.fallbackParse(line, index, lastSeenTs);
    return parsed;
  }

  _applyFoldedStack(parsed, slot) {
    if (!parsed || (!slot.stackFrames && slot.causes.length === 0)) return parsed;
    const combined = `${parsed.message || ''} ${slot.causes.join(' ')}`;
    const cls = this._classifyTomcatJavaEvent(combined, slot.baseLevel || parsed.level || 'INFO', true);
    const causesTxt = slot.causes.join(' ');
    const oraCause = causesTxt.match(/\b(ORA-\d{4,5})\b/i);
    const entCause = lpExtractEntrustNumericCode(causesTxt);
    if (slot.lockedCode) {
      if (oraCause) {
        parsed.entrustCode = oraCause[1].toUpperCase();
        parsed.level = 'CRITICAL';
        parsed.service = 'Oracle Database';
      }
    } else {
      parsed.entrustCode = cls.code;
      parsed.level = cls.level;
      parsed.service = cls.service;
      if (entCause && !lpIsEntrustNumericCode(parsed.entrustCode) && !oraCause) {
        parsed.entrustCode = entCause;
        parsed.level = 'ERROR';
      }
    }
    const extraParts = [];
    if (slot.causes.length > 0) {
      extraParts.push('Root Cause: ' + slot.causes[slot.causes.length - 1].replace(/^Caused by:\s*/i, '').trim());
    }
    if (slot.entrustFrame) {
      extraParts.push('Frame: ' + slot.entrustFrame);
    }
    if (extraParts.length > 0) {
      const extraStr = ' | ' + extraParts.join(' | ');
      const baseMsg = String(parsed.message || '');
      parsed.message = (baseMsg.length + extraStr.length > 600)
        ? (baseMsg.slice(0, Math.max(180, 596 - extraStr.length)).trimEnd() + '…' + extraStr).slice(0, 600)
        : (baseMsg + extraStr);
    }
    if (slot.stackFrames > 0) {
      const suffix = `\n[+${slot.stackFrames} stack frames]`;
      parsed.raw = (String(slot.raw || parsed.raw || '').slice(0, Math.max(200, 1800 - suffix.length)) + suffix).slice(0, 1800);
    }
    return parsed;
  }

  _foldLinesArray(lines) {
    const slots = [];
    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i].replace(/\r$/, '');
      const trimmed = rawLine.trim();
      if (!trimmed) continue;

      const prev = slots.length > 0 ? slots[slots.length - 1] : null;
      if (/^\[5(?:2\d{4,5}|[013-9]\d{5})\]/.test(trimmed) && prev) {
        prev.line = prev.line + ' \n ' + trimmed;
        prev.raw = (prev.raw + '\n' + trimmed).slice(0, 1600);
      } else if (prev && prev.isTomcatSimpleHdr && this._isTomcatSimpleLevelLine(rawLine)) {
        const lvlPair = this._isTomcatSimpleLevelLine(rawLine);
        prev.isTomcatSimpleHdr = false;
        prev.baseLevel = lvlPair.level;
        prev.line = `${prev.line} — ${lvlPair.level}: ${lvlPair.msg}`;
        prev.raw = (prev.raw + '\n' + trimmed).slice(0, 1600);
      } else if (prev && this._isJavaStackContinuation(rawLine)) {
        prev.stackFrames++;
        if (
          /^(?:Caused by:|Suppressed:)|^(?:java|javax|jakarta|oracle|org\.apache|com\.entrust)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/.test(trimmed) ||
          Boolean(lpExtractEntrustNumericCode(trimmed)) ||
          /\b(?:ORA-\d{4,5}|AUD\d{2,5})\b/i.test(trimmed)
        ) {
          if (prev.causes.length < 10) prev.causes.push(trimmed.slice(0, 220));
        }
        if (!prev.entrustFrame && trimmed.includes('com.entrust.')) {
          prev.entrustFrame = trimmed.replace(/^at\s+/, '').trim().slice(0, 140);
        }
        if (prev.raw.length < 1550) prev.raw = (prev.raw + '\n' + trimmed).slice(0, 1600);
      } else {
        slots.push({
          line: trimmed,
          raw: trimmed,
          isTomcatSimpleHdr: LP_RE_JULI_SIMPLE.test(trimmed),
          baseLevel: 'INFO',
          lockedCode: /^(?:5(?:2\d{4,5}|[013-9]\d{5})|AUD\d+|ORA-)/i.test(trimmed),
          stackFrames: 0,
          causes: [],
          entrustFrame: ''
        });
      }
    }
    return slots;
  }

  /**
   * Parsea un texto masivo de logs y devuelve una lista estructurada de eventos de log
   * @param {string} rawContent 
   * @returns {Array<Object>}
   */
  parseLogs(rawContent) {
    if (!rawContent || typeof rawContent !== 'string') return [];

    const lines = rawContent.split(/\r?\n/);
    const parsedEntries = [];
    const slots = this._foldLinesArray(lines);
    let lastSeenTs = '';

    slots.forEach((slot, index) => {
      const parsed = this._parseSingleEventRecord(slot.line, index, lastSeenTs);
      if (parsed.timestamp && /^\d{4}-\d{2}-\d{2}/.test(parsed.timestamp)) {
        lastSeenTs = parsed.timestamp;
      }
      slot.lockedCode = Boolean(parsed.entrustCode && (lpIsEntrustNumericCode(parsed.entrustCode) || /^(?:AUD\d+|ORA-|bulkidentityguard)/i.test(parsed.entrustCode)));
      this._applyFoldedStack(parsed, slot);

      // Enriquecer con el motor de Base de Conocimientos
      if (window.knowledgeBaseEngine) {
        parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLog(parsed.message || parsed.raw, parsed.entrustCode || '');
      }

      parsedEntries.push(parsed);
    });

    return parsedEntries;
  }

  /**
   * Parsea logs de forma asíncrona en bloques (chunking) para liberar el hilo principal del navegador.
   * Evita congelamientos y la advertencia "La página no responde".
   * @param {string} rawContent 
   * @param {function(number, number, string): void} onProgress 
   * @param {number} chunkSize 
   * @returns {Promise<Array<Object>>}
   */
  async parseLogsAsync(rawContent, onProgress, chunkSize = 2500) {
    if (!rawContent || typeof rawContent !== 'string') return [];
    chunkSize = Math.min(chunkSize || 2500, 2500);

    const startTime = performance.now();
    const lines = rawContent.split(/\r?\n/);
    const totalLines = lines.length;
    const slots = [];

    // Pre-procesamiento de combinación multi-línea y plegado de stack traces asíncrono
    for (let i = 0; i < totalLines; i++) {
      const rawLine = lines[i].replace(/\r$/, '');
      const trimmed = rawLine.trim();
      if (!trimmed) continue;

      const prev = slots.length > 0 ? slots[slots.length - 1] : null;
      if (/^\[5(?:2\d{4,5}|[013-9]\d{5})\]/.test(trimmed) && prev) {
        prev.line = prev.line + ' \n ' + trimmed;
        prev.raw = (prev.raw + '\n' + trimmed).slice(0, 1600);
      } else if (prev && prev.isTomcatSimpleHdr && this._isTomcatSimpleLevelLine(rawLine)) {
        const lvlPair = this._isTomcatSimpleLevelLine(rawLine);
        prev.isTomcatSimpleHdr = false;
        prev.baseLevel = lvlPair.level;
        prev.line = `${prev.line} — ${lvlPair.level}: ${lvlPair.msg}`;
        prev.raw = (prev.raw + '\n' + trimmed).slice(0, 1600);
      } else if (prev && this._isJavaStackContinuation(rawLine)) {
        prev.stackFrames++;
        if (
          /^(?:Caused by:|Suppressed:)|^(?:java|javax|jakarta|oracle|org\.apache|com\.entrust)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/.test(trimmed) ||
          Boolean(lpExtractEntrustNumericCode(trimmed)) ||
          /\b(?:ORA-\d{4,5}|AUD\d{2,5})\b/i.test(trimmed)
        ) {
          if (prev.causes.length < 10) prev.causes.push(trimmed.slice(0, 220));
        }
        if (!prev.entrustFrame && trimmed.includes('com.entrust.')) {
          prev.entrustFrame = trimmed.replace(/^at\s+/, '').trim().slice(0, 140);
        }
        if (prev.raw.length < 1550) prev.raw = (prev.raw + '\n' + trimmed).slice(0, 1600);
      } else {
        slots.push({
          line: trimmed,
          raw: trimmed,
          isTomcatSimpleHdr: LP_RE_JULI_SIMPLE.test(trimmed),
          baseLevel: 'INFO',
          lockedCode: false,
          stackFrames: 0,
          causes: [],
          entrustFrame: ''
        });
      }

      if (i % (chunkSize * 2) === 0) {
        const elapsedSec = (performance.now() - startTime) / 1000;
        const currentSpeed = Math.round((i + 1) / (elapsedSec || 0.001));
        const pct = Math.round((i / (totalLines * 2)) * 100);
        if (onProgress) onProgress(i, totalLines, `⚡ Pre-procesando trazas... (${pct}%) • Velocidad: ${currentSpeed.toLocaleString()} líneas/s`, { pct, speed: currentSpeed, elapsed: elapsedSec });
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    const totalMerged = slots.length;
    const parsedEntries = [];
    let lastSeenTs = '';

    for (let i = 0; i < totalMerged; i++) {
      const slot = slots[i];
      const parsed = this._parseSingleEventRecord(slot.line, i, lastSeenTs);
      if (parsed.timestamp && /^\d{4}-\d{2}-\d{2}/.test(parsed.timestamp)) {
        lastSeenTs = parsed.timestamp;
      }
      slot.lockedCode = Boolean(parsed.entrustCode && (lpIsEntrustNumericCode(parsed.entrustCode) || /^(?:AUD\d+|ORA-|bulkidentityguard)/i.test(parsed.entrustCode)));
      this._applyFoldedStack(parsed, slot);

      // Fast-path: Diagnóstico profundo solo para eventos con indicadores de error o auditoría
      const hasDiagKeyword = /(5(?:2\d{4,5}|[013-9]\d{5})|AUD\d+|TOMCAT_|JVM_OOM|JDBC_SQL|ORA-|error|critical|fatal|warn|fail|exception|oom|kill|timeout|disconnect|broken|unauthorized|denied|fault|severe)/i.test((parsed.entrustCode || '') + ' ' + slot.line + ' ' + (parsed.message || ''));
      if (hasDiagKeyword && window.knowledgeBaseEngine) {
        parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLogWithCli 
          ? window.knowledgeBaseEngine.diagnoseLogWithCli(parsed.message || parsed.raw)
          : window.knowledgeBaseEngine.diagnoseLog(parsed.message || parsed.raw, parsed.entrustCode || '');
      } else {
        parsed.diagnostic = {
          matched: false,
          ruleId: 'KB-INFO-000',
          title: 'Evento Operativo Normal',
          category: 'Informativo',
          severity: 'INFO',
          attribution: '✅ Operación Normal',
          meaning: 'Registro de actividad nominal.',
          rootCause: 'Ejecución regular sin incidencias.',
          remediation: 'No requiere acción.',
          riskLevel: 'Bajo',
          manualVersion: 'vEntrust',
          sectionId: 'sec-aud-codes',
          sectionTitle: 'Manual Operativo'
        };
      }

      parsedEntries.push(parsed);

      if (i % (chunkSize * 2) === 0 || i === totalMerged - 1) {
        const elapsedSec = (performance.now() - startTime) / 1000;
        const processedTotal = totalLines + i;
        const currentSpeed = Math.round(processedTotal / (elapsedSec || 0.001));
        const pct = Math.min(100, Math.round(50 + (i / totalMerged) * 50));
        const remainingItems = totalMerged - i;
        const etaSec = Math.max(0, Math.round(remainingItems / (currentSpeed || 1)));
        if (onProgress) onProgress(i + 1, totalMerged, `🚀 Indexando eventos... (${pct}%) • Velocidad: ${currentSpeed.toLocaleString()} líneas/s • ETA: ~${etaSec}s`, { pct, speed: currentSpeed, elapsed: elapsedSec, eta: etaSec });
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    this.correlateAutoHealing(parsedEntries);

    const totalElapsed = ((performance.now() - startTime) / 1000).toFixed(2);
    const avgSpeed = Math.round((totalLines + totalMerged) / (parseFloat(totalElapsed) || 1));
    if (onProgress) onProgress(totalMerged, totalMerged, `✅ 100% Finalizado (${totalMerged.toLocaleString()} eventos indexados en ${totalElapsed}s a ${avgSpeed.toLocaleString()} l/s)`, { pct: 100, speed: avgSpeed, elapsed: totalElapsed });
    return parsedEntries;
  }

  async parseLogsWithWorker(rawContent, clientId, onProgress) {
    if (window.Worker) {
      return new Promise((resolve) => {
        try {
          const worker = new Worker('js/log-parser-worker.js?v=624.0');
          worker.postMessage({ rawContent, clientId });

          worker.onmessage = (e) => {
            const { type, current, total, pct, parsedLogs } = e.data;
            if (type === 'progress') {
              if (onProgress) onProgress(current, total, `⚡ [Web Worker Multihilo]: Procesando logs... (${pct}%)`);
            } else if (type === 'complete') {
              worker.terminate();
              this.correlateAutoHealing(parsedLogs);
              if (onProgress) onProgress(total, total, '100% Finalizado (Web Worker)');
              resolve(parsedLogs);
            }
          };

          worker.onerror = (err) => {
            console.warn('Worker error fallback to parseLogsAsync:', err);
            worker.terminate();
            resolve(this.parseLogsAsync(rawContent, onProgress, 20000));
          };
        } catch(e) {
          console.warn('Worker init fallback:', e);
          resolve(this.parseLogsAsync(rawContent, onProgress, 20000));
        }
      });
    } else {
      return this.parseLogsAsync(rawContent, onProgress, 20000);
    }
  }

  // DELEGACIÓN MULTIHILO WEB WORKER PARA ARCHIVOS DE 10 GB+ (HILO PRINCIPAL LIBRE AL 100%)
  async parseLargeFileWithWorker(file, clientId, onProgress) {
    if (window.Worker) {
      return new Promise((resolve) => {
        try {
          const worker = new Worker('js/log-parser-worker.js?v=624.0');
          worker.postMessage({ file: file, clientId: clientId, mode: 'fileBlob' });

          worker.onmessage = (e) => {
            const data = e.data;
            if (data.type === 'progress') {
              if (onProgress) {
                onProgress(
                  data.current,
                  data.total,
                  `⚡ Streaming Multihilo: ${data.mbProcessed} MB / ${data.totalMb} MB (${data.pct}%) — ${(data.lineCount || 0).toLocaleString()} eventos | ${data.totalErrors || 0} errores`
                );
              }
            } else if (data.type === 'complete' || data.type === 'done') {
              worker.terminate();
              if (onProgress) onProgress(file.size, file.size, `✅ 100% Completado (${(data.totalLinesProcessed || 0).toLocaleString()} eventos procesados)`);
              this.correlateAutoHealing(data.parsedLogs);
              resolve({
                parsedLogs: data.parsedLogs || [],
                totalLinesProcessed: data.totalLinesProcessed || (data.parsedLogs ? data.parsedLogs.length : 0),
                totalErrors: data.totalErrors || 0,
                totalWarnings: data.totalWarnings || 0,
                globalMetrics: data.globalMetrics || null
              });
            } else if (data.type === 'error') {
              worker.terminate();
              console.warn('Worker reported error, fallback streaming:', data.error);
              this.parseFileStreaming(file, clientId, onProgress).then(resolve).catch(() => {
                resolve({ parsedLogs: [], totalLinesProcessed: 0, totalErrors: 0, totalWarnings: 0 });
              });
            }
          };

          worker.onerror = (err) => {
            console.error('Worker error fallback:', err);
            worker.terminate();
            this.parseFileStreaming(file, clientId, onProgress).then(resolve).catch(() => {
              resolve({ parsedLogs: [], totalLinesProcessed: 0, totalErrors: 0, totalWarnings: 0 });
            });
          };
        } catch (e) {
          console.warn('Worker init error, fallback streaming:', e);
          this.parseFileStreaming(file, clientId, onProgress).then(resolve).catch(() => {
            resolve({ parsedLogs: [], totalLinesProcessed: 0, totalErrors: 0, totalWarnings: 0 });
          });
        }
      });
    } else {
      return this.parseFileStreaming(file, clientId, onProgress);
    }
  }

  // MOTOR STREAMING POR BLOQUES PARA ARCHIVOS GIGANTES (10 GB+ / Sin desbordar memoria)
  async parseLargeFileInChunks(file, onProgress, chunkSize = 32 * 1024 * 1024) {
    const fileSize = file.size;
    let offset = 0;
    let leftover = '';
    let totalLinesProcessed = 0;
    const allParsed = [];
    const maxEntriesToRetainInSession = 300000; // Mantiene los más recientes para rendimiento ultra-rápido en UI

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
        totalLinesProcessed++;
        const parsed = this.parseLine(line, totalLinesProcessed);
        if (parsed) {
          allParsed.push(parsed);
        }
      }

      const pct = Math.min(99, Math.round((Math.min(offset, fileSize) / fileSize) * 100));
      const mbProcessed = (Math.min(offset, fileSize) / (1024 * 1024)).toFixed(0);
      const totalMb = (fileSize / (1024 * 1024)).toFixed(0);

      if (onProgress) {
        onProgress(
          Math.min(offset, fileSize),
          fileSize,
          `⚡ Streaming: ${mbProcessed} MB / ${totalMb} MB (${pct}%) — ${totalLinesProcessed.toLocaleString()} eventos analizados...`
        );
      }

      // Ceder el hilo de ejecución para que la interfaz se refresque suavemente
      await new Promise(resolve => setTimeout(resolve, 0));
    }

    if (leftover && leftover.trim()) {
      totalLinesProcessed++;
      const parsed = this.parseLine(leftover.trim(), totalLinesProcessed);
      if (parsed) allParsed.push(parsed);
    }

    this.correlateAutoHealing(allParsed);

    if (onProgress) {
      onProgress(fileSize, fileSize, `✅ 100% Completado: ${totalLinesProcessed.toLocaleString()} eventos procesados`);
    }

    // Si el conjunto supera el límite en memoria de UI, conservamos una muestra de alta resolución
    if (allParsed.length > maxEntriesToRetainInSession) {
      return allParsed.slice(-maxEntriesToRetainInSession);
    }

    return allParsed;
  }

  // ALGORITMO O(N) LINEAL DE ALTA VELOCIDAD (Resuelve en <20ms para 5M+ logs)
  correlateAutoHealing(parsedEntries) {
    if (!parsedEntries || parsedEntries.length === 0) return;
    const pendingErrorsByUser = new Map();

    for (let i = 0; i < parsedEntries.length; i++) {
      const entry = parsedEntries[i];
      const u = entry.user;
      if (!u) continue;

      if (entry.level === 'ERROR' || entry.level === 'CRITICAL') {
        if (!pendingErrorsByUser.has(u)) pendingErrorsByUser.set(u, []);
        pendingErrorsByUser.get(u).push(entry);
      } else if (entry.level === 'INFO' || (entry.message && /(200 OK|AuthenticationSuccessful|AUD2300|success)/i.test(entry.message))) {
        const errors = pendingErrorsByUser.get(u);
        if (errors && errors.length > 0) {
          for (let k = 0; k < errors.length; k++) {
            const err = errors[k];
            err.recovered = true;
            err.recoveredAt = entry.timestamp;
            if (err.diagnostic) {
              err.diagnostic.title = `[REINTENTO RECUPERADO CON ÉXITO] ${err.diagnostic.title}`;
              err.diagnostic.meaning += ` (El usuario logró autenticarse exitosamente a las ${entry.timestamp}).`;
            }
          }
          pendingErrorsByUser.delete(u);
        }
      }
    }
  }

  // PARSER ULTRA-RÁPIDO POR INDEXACIÓN DE CORCHETES (350.000+ líneas por segundo)
  fastParseEntrustBracket(line, lineNum) {
    if (!line || line.length < 15) return null;
    if (line.charCodeAt(0) !== 91) return null; // Debe comenzar con '['

    const tsStart = line.charCodeAt(1) === 91 ? 2 : 1;
    const p1 = line.indexOf(']', tsStart);
    if (p1 <= 8 || p1 >= 38) return null;
    const timestamp = line.substring(tsStart, p1).slice(0, 19);

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

    // Normalizar nivel
    let level = 'INFO';
    if (rawLevel.includes('ERR') || rawLevel.includes('CRIT') || rawLevel.includes('FATAL') || rawLevel.includes('SEVERE')) {
      level = 'ERROR';
    } else if (rawLevel.includes('WARN')) {
      level = 'WARN';
    } else if (rawLevel.includes('DEBUG') || rawLevel.includes('TRACE')) {
      level = 'DEBUG';
    }

    // Código 5xxxxx / 520xxx, AUDxxx o ORA-
    let entrustCode = lpExtractEntrustNumericCode(line);
    if (entrustCode) {
      level = 'ERROR';
    } else {
      const audM = line.match(/(?:\b|\[)(AUD\d{2,5})(?:\b|\])/i);
      if (audM) {
        entrustCode = audM[1].toUpperCase();
        if (LP_AUD_FAIL_SET.has(entrustCode)) level = 'ERROR';
        else if (LP_AUD_WARN_SET.has(entrustCode) && level === 'INFO') level = 'WARN';
      } else {
        const oraM = line.match(/\b(ORA-\d{4,5})\b/i);
        if (oraM) {
          entrustCode = oraM[1].toUpperCase();
          level = 'CRITICAL';
        }
      }
    }

    // Extracción de usuario rápida y precisa
    const user = this._isTomcatStartupBanner(line) ? null : this.extractUser(line);

    return {
      id: `entrust-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Entrust IdentityGuard',
      timestamp: timestamp,
      level: level,
      hostname: 'localhost',
      service: category,
      message: message,
      raw: line,
      user: user,
      clientIp: this.extractClientIp(line),
      entrustCode: entrustCode
    };
  }

  /**
   * Parser especializado para Entrust IDaaS Cloud / Migration Tool (IMPORT_IDENTITYGUARD-*.txt)
   */
  tryParseEntrustMigrationLog(line, lineNum) {
    if (!line || typeof line !== 'string') return null;
    if (!line.includes('IdentityGuard migration:')) return null;

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
    const timestamp = timestampMatch ? timestampMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);

    return {
      id: `migration-${lineNum}-${Date.now()}`,
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

  /**
   * Parser especializado para Web Services SOAP de Entrust IdentityGuard OnPremise
   * Endpoints: /idgserv/services/AuthenticationService, /AdministrationService, /IdentityRepositoryService
   * Payload: SOAP Envelope, SOAP Faults, WS-Security Headers
   */
  tryParseSoapWebService(line, lineNum) {
    const isSoapPattern = /(soapenv:|SOAPFault|wsse:|AuthenticationService|AdministrationService|IdentityRepositoryService|\/services\/[A-Za-z]+Service)/i.test(line);
    if (!isSoapPattern) return null;

    const entrustNum = lpExtractEntrustNumericCode(line);
    const codeMatch = line.match(/(AUD\d{2,5}|ORA-\d{4,5}|wsse:\w+|soapenv:\w+)/i);
    const dateMatch = line.match(/^\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\]?/) ||
                      line.match(/\[?(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})/);

    let level = 'INFO';
    if (entrustNum || /(Fault|Exception|FailedAuthentication|ERROR|CRITICAL|500)/i.test(line)) {
      level = 'ERROR';
    }

    let serviceName = 'Entrust IDG SOAP WebService';
    const soapServiceMatch = line.match(/(AuthenticationService|AdministrationService|IdentityRepositoryService|ParmsService)/i);
    if (soapServiceMatch) {
      serviceName = `IDG SOAP [${soapServiceMatch[1]}]`;
    }

    return {
      id: `soap-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Entrust SOAP WebService',
      timestamp: dateMatch ? dateMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19),
      level: level,
      hostname: 'idg-soap-endpoint',
      service: serviceName,
      message: line,
      raw: line,
      entrustCode: entrustNum || (codeMatch ? codeMatch[1] : null)
    };
  }

  /**
   * Parser especializado para Tomcat / Catalina (Entrust IdentityGuard Application Server) y Syslog Entrust
   */
  tryParseTomcatCatalina(line, lineNum, lastSeenTs = '') {
    if (!line || typeof line !== 'string') return null;
    const { ts, rest, fmt } = this._parseTomcatTimestamp(line);
    const hasStackKeyword = this._isJavaStackContinuation(line) || /\b(ORA-\d{4,5}|SQLException|OutOfMemoryError|SSLHandshakeException|ClientAbortException)\b/.test(line);
    const isIsoTomcatJava = (fmt === 'iso') && (
      /\b(?:SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|GRAVE|ADVERTENCIA)\b/.test(rest) ||
      /(?:catalina|org\.apache|com\.entrust|Exception|Error|Server startup|Starting ProtocolHandler|HikariPool|ORA-\d{4,5}|5\d{5,6}|AUD\d{2,5})/.test(line)
    );
    const isEntrustSyslog = (fmt === 'syslog') && (rest.startsWith('[') || rest.includes('520') || rest.includes('AUD') || Boolean(lpExtractEntrustNumericCode(rest)));

    if (!ts && !hasStackKeyword) return null;
    if (fmt === 'iso' && !isIsoTomcatJava) return null;
    if (fmt === 'syslog' && !isEntrustSyslog) return null;

    let baseLevel = 'INFO';
    let msg = rest;
    if (fmt === 'syslog') {
      const lvlM = rest.match(/\[(ERROR|FATAL|SEVERE|CRIT|CRITICAL|WARN|WARNING|INFO|DEBUG)\s*\]/i);
      baseLevel = lvlM ? lvlM[1].toUpperCase() : ((rest.includes('FAILED') || rest.includes('[520') || Boolean(lpExtractEntrustNumericCode(rest))) ? 'ERROR' : 'INFO');
    } else if (fmt === 'juli_oneline') {
      const mOne = rest.match(/^([A-ZÁÉÍÓÚÑ]+)\s+\[([^\]]*)\]\s+(.*)$/);
      if (mOne) {
        baseLevel = mOne[1].toUpperCase();
        msg = `[${mOne[2]}] ${mOne[3]}`;
      } else {
        const mLvl = rest.match(/^(SEVERE|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST|GRAVE|ADVERTENCIA)\s+(.*)$/i);
        if (mLvl) {
          baseLevel = mLvl[1].toUpperCase();
          msg = mLvl[2];
        }
      }
    } else if (fmt === 'juli_simple') {
      const mLvl = rest.match(/\b(SEVERE|FATAL|ERROR|WARNING|WARN|GRAVE|ADVERTENCIA)\b/);
      if (mLvl) baseLevel = mLvl[1].toUpperCase();
    } else if (fmt === 'iso') {
      const mLvl = rest.match(/^[\[\s]*(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG|GRAVE|ADVERTENCIA)[\]\s:]+(.*)$/i)
        || rest.match(/\b(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|DEBUG)\b/);
      if (mLvl) {
        baseLevel = mLvl[1].toUpperCase();
        if (mLvl[2]) msg = mLvl[2];
      }
    } else {
      baseLevel = /(?:ClientAbortException|Broken pipe|Connection reset by peer)/i.test(line) ? 'INFO' : 'ERROR';
    }

    const cls = this._classifyTomcatJavaEvent(line, baseLevel, !ts && hasStackKeyword);
    const timestamp = ts || lastSeenTs || '';

    return {
      id: `tomcat-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: fmt === 'syslog' ? 'Entrust Syslog / Catalina' : 'Tomcat Catalina',
      timestamp: timestamp,
      level: cls.level,
      hostname: fmt === 'syslog' ? 'localhost' : 'idg-tomcat-srv',
      service: cls.service,
      message: msg.slice(0, 600),
      raw: line,
      user: this._isTomcatStartupBanner(line) ? null : this.extractUser(line),
      clientIp: this._extractNonVersionIp(msg),
      entrustCode: cls.code
    };
  }

  /**
   * Parser especializado para archivos CSV / TSV exportados por Entrust IDaaS Cloud
   */
  tryParseCsv(line, lineNum) {
    if (!line.includes(',') && !line.includes(';') && !line.includes('\t')) return null;

    let delimiter = ',';
    if (line.includes('\t')) delimiter = '\t';
    else if (line.includes(';') && !line.includes(',')) delimiter = ';';

    const fields = line.split(delimiter === '\t' ? '\t' : new RegExp(`${delimiter}(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)`))
                       .map(f => f.replace(/^"|"$/g, '').trim());

    if (fields.length < 3) return null;

    if (/(id|eventTime|accountId|subjectName|eventType|eventOutcome|sourceIp)/i.test(line) && lineNum === 0) {
      return {
        id: `csv-header-${Date.now()}`,
        lineNum: 1,
        type: 'IDaaS TSV/CSV Header',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        level: 'INFO',
        hostname: 'idaas-cloud',
        service: 'CSV/TSV Import Engine',
        message: `Encabezado Entrust IDaaS Cloud Detectado (${fields.length} columnas)`,
        raw: line,
        isHeader: true
      };
    }

    let timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    let level = 'INFO';
    let user = 'N/A';
    let service = 'Entrust IDaaS Cloud';
    let message = line;
    let entrustCode = null;
    let clientIp = 'N/A';
    let eventOutcome = 'SUCCESS';

    if (fields.length >= 10 && (fields[1]?.includes('T') || fields[8] === 'SUCCESS' || fields[8] === 'FAIL')) {
      timestamp = fields[1] || timestamp;
      user = fields[4] || fields[3] || 'N/A';
      eventOutcome = fields[8] || 'SUCCESS';
      level = eventOutcome === 'FAIL' ? 'ERROR' : 'INFO';
      const eventTypeStr = fields[7] || 'Event';
      const msgStr = fields[9] || '';
      const appStr = fields[11] || 'Administration Portal';
      clientIp = fields[12] || 'N/A';
      const tokenType = fields[14] || '';

      service = `IDaaS REST API [${eventTypeStr}]`;
      message = `[${eventOutcome}] ${msgStr} - App: ${appStr}${tokenType ? ' - Token: ' + tokenType : ''} - User: ${user}`;
      entrustCode = msgStr.split('.').pop() || eventTypeStr;
    } else {
      fields.forEach(field => {
        if (/^\d{4}[-/.]\d{2}[-/.]\d{2}/.test(field) || /^\d{2}:[0-5]\d:[0-5]\d/.test(field)) {
          timestamp = field;
        } else if (/^(CRITICAL|ERROR|SEVERE|FAIL|FAILED|WARN|WARNING|INFO|DEBUG)$/i.test(field)) {
          level = this.normalizeLevel(field);
        } else if (/(5(?:2\d{4,5}|[013-9]\d{5})|AUD\d+|SAML|MFA|OIDC|OAUTH)/i.test(field)) {
          entrustCode = field;
        } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(field)) {
          clientIp = field;
        } else if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(field) || /^(user|admin|mrodriguez|jperez|acosta)/i.test(field)) {
          user = field;
        }
      });

      const codeInLine = lpExtractEntrustNumericCode(line) || line.match(/(AUD\d{2,5}|ORA-\d{4,5}|SAML_\w+|MFA_\w+|Authentication\w+Event)/i)?.[1];
      if (codeInLine) entrustCode = codeInLine;

      if (/(fail|error|denied|invalid|expired|locked)/i.test(line) && level === 'INFO') {
        level = 'ERROR';
      }
    }

    return {
      id: `csv-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Entrust IDaaS Cloud (API REST)',
      timestamp: timestamp,
      level: level,
      hostname: 'idaas.entrust.com',
      service: service,
      message: message,
      raw: line,
      user: user,
      clientIp: clientIp,
      entrustCode: entrustCode
    };
  }

  /**
   * Parser especializado para Entrust IdentityGuard OnPremise
   * Formato: [YYYY-MM-DD HH:mm:ss,SSS] [Thread] [LEVEL] [Category] [AUDxxx/API] [User/Context] Message...
   */
  tryParseEntrustIdentityGuard(line, lineNum) {
    const sanitizedLine = line.replace(/(\?|&)[^=\s]+=[^&\s]*/g, '');
    const numericEntrust = lpExtractEntrustNumericCode(sanitizedLine);
    if (!line.includes('[IG.') && !numericEntrust && !/AUD\d+/i.test(sanitizedLine) && !/\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(line)) {
      return null;
    }

    const dateMatch = line.match(/^\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\]?/);
    const levelMatch = line.match(/\[?(INFO|ERROR|WARN|WARNING|CRITICAL|FATAL|DEBUG)\]?/i);
    const code520Match = numericEntrust ? [numericEntrust, numericEntrust] : null;
    const audMatch = sanitizedLine.match(/(?:\[|\b)(AUD\d{2,5})(?:\]|\b)/i);
    const categoryMatch = line.match(/\[?(IG\.[A-Z0-9\._]+)\]?/i);

    if (!dateMatch && !code520Match && !audMatch && !categoryMatch) {
      return null;
    }

    const timestamp = dateMatch ? dateMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);
    const rawLevel = levelMatch ? levelMatch[1].toUpperCase() : (code520Match ? 'ERROR' : 'INFO');
    const level = this.normalizeLevel(rawLevel);
    
    let serviceName = 'Entrust IdentityGuard';
    if (code520Match) {
      serviceName = `Entrust Error [${code520Match[1]}]`;
    } else if (audMatch) {
      serviceName = `Entrust Audit [${audMatch[1]}]`;
    } else if (categoryMatch) {
      serviceName = categoryMatch[1];
    }

    const extractedUser = this.extractUser(line);
    const extractedIp = this.extractClientIp(line);

    return {
      id: `entrust-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Entrust IdentityGuard',
      timestamp: timestamp,
      level: level,
      hostname: 'idg-onpremise-01',
      service: serviceName,
      message: line,
      raw: line,
      user: extractedUser,
      clientIp: extractedIp,
      entrustCode: code520Match ? code520Match[1] : (audMatch ? audMatch[1] : null)
    };
  }

  tryParseEntrustIdaasAuditTsv(line, lineNum) {
    if (!line || (!line.includes('\t') && !line.includes('AuthenticationTokenPushSuccessEvent') && !line.includes('Bulkidentityguard'))) return null;

    const parts = line.split('\t');
    if (parts.length < 9) return null;

    // Ignorar línea de encabezados
    if (parts[0].toLowerCase() === 'id' && parts[1].toLowerCase() === 'eventtime') return null;

    const id = parts[0] || `idaas-${lineNum}`;
    const rawTime = parts[1] || '';
    const subjectName = parts[4] || '';
    const eventCategory = parts[6] || 'IDaaS.Audit';
    const eventType = parts[7] || '';
    const eventOutcome = (parts[8] || 'SUCCESS').toUpperCase();
    const eventMessage = parts[9] || '';
    const resourceName = parts[11] || 'Administration Portal';
    const sourceIp = parts[12] || '';
    const token = parts[14] || '';
    const adminRole = parts[17] || '';
    const entityType = parts[20] || '';
    const entityAction = parts[21] || '';
    const entityName = parts[23] || '';
    const auditDetails = parts[24] || '';

    let level = 'INFO';
    if (eventOutcome.includes('FAIL') || eventOutcome.includes('ERROR') || eventOutcome.includes('DENIED')) {
      level = 'ERROR';
    } else if (eventOutcome.includes('WARN')) {
      level = 'WARN';
    }

    // Formatear timestamp ISO (2026-09-08T13:44:04Z -> 2026-09-08 13:44:04)
    let formattedTime = rawTime.replace('T', ' ').replace('Z', '').substring(0, 19);
    if (!formattedTime) {
      formattedTime = new Date().toISOString().replace('T', ' ').substring(0, 19);
    }

    let summaryMsg = `[${eventType}] ${eventMessage || eventType}`;
    if (entityName) summaryMsg += ` (Entidad: ${entityName} ${entityAction})`;
    if (token) summaryMsg += ` [Token: ${token}]`;
    if (adminRole) summaryMsg += ` [Rol: ${adminRole}]`;

    return {
      id: `log-${lineNum}-${Date.now()}`,
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
      category: eventCategory,
      auditDetails: auditDetails
    };
  }

  tryParseJson(line, lineNum) {
    if (!line.startsWith('{') || !line.endsWith('}')) return null;
    try {
      const obj = JSON.parse(line);
      const level = (obj.level || obj.severity || obj.logLevel || 'INFO').toUpperCase();
      const message = obj.message || obj.msg || obj.log || JSON.stringify(obj);
      const timestamp = obj.timestamp || obj.time || obj.datetime || new Date().toISOString();
      const service = obj.service || obj.serviceName || obj.app || 'Microservicio';

      return {
        id: `log-${lineNum}-${Date.now()}`,
        lineNum: lineNum + 1,
        type: obj.traceId ? 'Trace' : 'Application',
        timestamp: this.formatTime(timestamp),
        level: this.normalizeLevel(level),
        hostname: obj.hostname || obj.host || 'app-node-01',
        service: service,
        message: message,
        raw: line,
        traceId: obj.traceId || null,
        spanId: obj.spanId || null,
        durationMs: obj.durationMs || null,
        extraData: obj
      };
    } catch (e) {
      return null;
    }
  }

  tryParseAuditd(line, lineNum) {
    if (!line.includes('type=') || !line.includes('msg=audit')) return null;

    const typeMatch = line.match(/type=([A-Z0-9_]+)/);
    const resMatch = line.match(/res=(failed|success|0|1)/);
    const userMatch = line.match(/(?:user|acct|uid)=["']?([a-zA-Z0-9_-]+)["']?/);
    const ipMatch = line.match(/(?:addr|hostname)=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);

    const isFailed = resMatch && (resMatch[1] === 'failed' || resMatch[1] === '0');
    const auditType = typeMatch ? typeMatch[1] : 'AUDIT';

    return {
      id: `log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Audit',
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      level: isFailed ? 'WARN' : 'INFO',
      hostname: 'auditd-kernel',
      service: `auditd [${auditType}]`,
      message: line,
      raw: line,
      user: userMatch ? userMatch[1] : 'unknown',
      sourceIp: ipMatch ? ipMatch[1] : 'local',
      isFailed: isFailed
    };
  }

  tryParseSyslog(line, lineNum) {
    const syslogRegex = /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w\(\)\[\]\/\.-]+):\s+(.*)$/;
    const match = line.match(syslogRegex);

    if (!match) return null;

    const timeStr = match[1];
    const host = match[2];
    const process = match[3];
    const msg = match[4];

    let level = 'INFO';
    if (/kernel|panic|killed process|fatal|oom/i.test(line)) level = 'CRITICAL';
    else if (/error|fail|failed/i.test(line)) level = 'ERROR';
    else if (/warn|warning|dropped/i.test(line)) level = 'WARN';

    return {
      id: `log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'System',
      timestamp: timeStr,
      level: level,
      hostname: host,
      service: process,
      message: msg,
      raw: line
    };
  }

  tryParseWebAccess(line, lineNum) {
    const webRegex = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]+)\s+HTTP\/[^"]+"\s+(\d{3})\s+(\d+)/;
    const match = line.match(webRegex);
    if (!match) return null;

    const ip = match[1];
    const dateStr = match[2];
    const method = match[3];
    const url = match[4];
    const status = parseInt(match[5]);

    let level = 'INFO';
    if (status >= 500) level = 'CRITICAL';
    else if (status >= 400) level = 'WARN';

    return {
      id: `log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'WebAccess',
      timestamp: dateStr,
      level: level,
      hostname: 'nginx-proxy',
      service: `${method} ${url}`,
      message: `HTTP ${status} - IP: ${ip} - Path: ${url}`,
      raw: line,
      statusCode: status,
      clientIp: ip
    };
  }

  fallbackParse(line, lineNum, lastSeenTs = '') {
    let level = 'INFO';
    if (/emergency|alert|critical|fatal|panic/i.test(line)) level = 'CRITICAL';
    else if (/error|failed|exception|invalid|locked|severe/i.test(line)) level = 'ERROR';
    else if (/warning|warn/i.test(line)) level = 'WARN';

    let entrustCode = null;
    let service = 'IdentityGuard OnPremise';
    let typeLabel = 'Entrust IdentityGuard';
    let hostLabel = 'localhost';

    const c520 = lpExtractEntrustNumericCode(line);
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

    const { ts } = this._parseTomcatTimestamp(line);
    const timestampMatch = line.match(/(\d{4}[-/.]\d{2}[-/.]\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?)/);
    const timestamp = ts || (timestampMatch ? timestampMatch[1].replace('T', ' ').substring(0, 19) : (lastSeenTs || ''));

    return {
      id: `log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: typeLabel,
      timestamp: timestamp,
      level: level,
      hostname: hostLabel,
      service: service,
      message: line,
      raw: line,
      user: this._isTomcatStartupBanner(line) ? null : this.extractUser(line),
      clientIp: this._extractNonVersionIp(line),
      entrustCode: entrustCode
    };
  }

  extractUser(line) {
    if (!line || typeof line !== 'string') return null;

    // 1. Usuarios específicos en corchetes de auditoría OnPremise: [AUDxxxx] [default/idgadmin] o [Master1]
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

    // 1. Priorizar usuario objetivo explícito ("for user X", "User X failed/created/...") antes del actor API en corchetes
    const forUserMatch = line.match(/\bfor\s+user\s+(['"]?)([A-Za-z0-9_\-\.\/@]+)\1/i);
    if (forUserMatch && isValidUser(forUserMatch[2])) return forUserMatch[2].trim();

    const userActionMatch = line.match(/\bUser\s+([A-Za-z0-9_\-\.\/@]+)\s+(?:currently\s+has|has\s+a\s+grid|already\s+has|created|failed|logged|assigned|updated|deleted|authenticated|locked|disabled|migrated)/i);
    if (userActionMatch && isValidUser(userActionMatch[1])) return userActionMatch[1].trim();

    // 2. Actor o usuario en corchetes de auditoría: [AUD6001] [bancomercantil/0004861051]
    const bracketUserMatch = line.match(/\[(?:AUD\d+|IG\.AUDIT)\]\s*\[([A-Za-z0-9_\-\.\/@]+)\]/i) ||
                             line.match(/\[([A-Za-z0-9_\-\.\/@]+)\]\s+Administrator logged in/i) ||
                             line.match(/\[([A-Za-z0-9_\-\.\/@]+)\]\s+(?:Login to supersh|User [A-Za-z0-9_\-\.\/@]+ created)/i);
    if (bracketUserMatch && isValidUser(bracketUserMatch[1])) return bracketUserMatch[1].trim();

    // 3. Usuarios de búsqueda / alias: "user name or alias admtemp", "alias 'admtmp'"
    const aliasMatch = line.match(/\b(?:user\s+name\s+or\s+alias|alias)\s+['"]?([A-Za-z0-9_\-\.\/@]+)['"]?/i);
    if (aliasMatch && isValidUser(aliasMatch[1])) return aliasMatch[1].trim();

    // 4. Priorizar usuarios explícitos de Banco del Caribe / Mercantil / Banesco / Grupos
    const bcMatch = line.match(/\b(BCClientes[A-Za-z0-9_\-\.\/@]+|BCMercantil[A-Za-z0-9_\-\.\/@]+|BC[A-Za-z0-9_\-\.\/@]+|Itservicios-group\/[A-Za-z0-9_\-\.\/@]+)\b/i);
    if (bcMatch && isValidUser(bcMatch[1])) return bcMatch[1].trim();

    const emailMatch = line.match(/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/i);
    if (emailMatch && isValidUser(emailMatch[1])) return emailMatch[1].trim();

    const match = line.match(/(?:for\s+user|user:?|subjectName:?|user\s*=|username\s*=)\s+(['"]?)([A-Za-z0-9_\-\.\/@]+)\1/i);
    if (match && isValidUser(match[2])) {
      return match[2].trim();
    }

    return null;
  }

  extractClientIp(line) {
    if (!line || typeof line !== 'string') return null;

    // Descartar líneas de depuración Java (JasperReports, TLS cipher suites, etc.)
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

  normalizeLevel(level) {
    if (!level) return 'INFO';
    const l = level.toUpperCase();
    if (l.includes('FATAL') || l.includes('EMERG') || l.includes('CRIT') || l.includes('PANIC')) return 'CRITICAL';
    if (l.includes('ERR')) return 'ERROR';
    if (l.includes('WARN')) return 'WARN';
    if (l.includes('DEBUG') || l.includes('TRACE')) return 'DEBUG';
    return 'INFO';
  }

  formatTime(isoOrStr) {
    try {
      const d = new Date(isoOrStr);
      if (!isNaN(d.getTime())) {
        return d.toLocaleTimeString('es-ES', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
      }
    } catch (e) {}
    return isoOrStr;
  }

  parseLine(line, lineNum, lastSeenTs = '') {
    if (!line || typeof line !== 'string') {
      return this.fallbackParse('', lineNum || 0, lastSeenTs);
    }

    let parsed = this.tryParseEntrustMigrationLog(line, lineNum || 0);
    if (!parsed) parsed = this.fastParseEntrustBracket(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseEntrustIdentityGuard(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseSoapWebService(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseTomcatCatalina(line, lineNum || 0, lastSeenTs);
    if (!parsed) parsed = this.tryParseEntrustIdaasAuditTsv(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseJson(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseAuditd(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseSyslog(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseWebAccess(line, lineNum || 0);
    if (!parsed) parsed = this.fallbackParse(line, lineNum || 0, lastSeenTs);

    if (window.knowledgeBaseEngine) {
      parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLog(parsed.message || parsed.raw, parsed.entrustCode || '');
    }

    return parsed;
  }

  async parseFileStreaming(file, clientId, onProgress) {
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

    const userCounter = {};
    const ipCounter = {};
    const codeCounter = {};
    const timeBuckets = {};

    const displayLogs = [];
    const MAX_DISPLAY_LOGS = 150000;
    let displayErrorCount = 0;

    const commitSlot = (slot) => {
      if (!slot) return;
      const parsed = this._parseSingleEventRecord(slot.line, lineCount - 1, lastSeenTs);
      if (parsed.timestamp && /^\d{4}-\d{2}-\d{2}/.test(parsed.timestamp)) {
        lastSeenTs = parsed.timestamp;
      }
      slot.lockedCode = Boolean(parsed.entrustCode && (lpIsEntrustNumericCode(parsed.entrustCode) || /^(?:AUD\d+|ORA-|bulkidentityguard)/i.test(parsed.entrustCode)));
      this._applyFoldedStack(parsed, slot);

      if (clientId) parsed.client = clientId;
      const isError = parsed.level === 'ERROR' || parsed.level === 'CRITICAL';
      const isWarn = parsed.level === 'WARN';
      if (isError) totalErrors++;
      if (isWarn) totalWarnings++;

      const codeKey = parsed.entrustCode || parsed.code || parsed.service || 'UNKNOWN';
      codeCounter[codeKey] = (codeCounter[codeKey] || 0) + 1;

      if (parsed.user && parsed.user !== 'unknown' && parsed.user !== 'N/A') {
        userCounter[parsed.user] = (userCounter[parsed.user] || 0) + 1;
      }
      if (parsed.clientIp && parsed.clientIp !== 'N/A') {
        ipCounter[parsed.clientIp] = (ipCounter[parsed.clientIp] || 0) + 1;
      }
      const dateBucket = (parsed.timestamp || '').substring(0, 16);
      if (dateBucket && /^\d{4}-\d{2}-\d{2}/.test(dateBucket)) {
        if (!timeBuckets[dateBucket]) timeBuckets[dateBucket] = { total: 0, critical: 0, warn: 0 };
        timeBuckets[dateBucket].total++;
        if (isError) timeBuckets[dateBucket].critical++;
        if (isWarn) timeBuckets[dateBucket].warn++;
      }

      if (isError && displayErrorCount < 100000) {
        displayErrorCount++;
        displayLogs.push(parsed);
      } else if (!isError && displayLogs.length < MAX_DISPLAY_LOGS && (displayLogs.length < 50000 || lineCount % 10 === 0)) {
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
        const trimmed = rawLine.trim();
        if (!trimmed) continue;
        rawLinesRead++;

        if (pending && /^\[520\d{4}\]/.test(trimmed)) {
          pending.line = pending.line + ' \n ' + trimmed;
          pending.raw = (pending.raw + '\n' + trimmed).slice(0, 1600);
          continue;
        }
        if (pending && pending.isTomcatSimpleHdr && this._isTomcatSimpleLevelLine(rawLine)) {
          const lvlPair = this._isTomcatSimpleLevelLine(rawLine);
          pending.isTomcatSimpleHdr = false;
          pending.baseLevel = lvlPair.level;
          pending.line = `${pending.line} — ${lvlPair.level}: ${lvlPair.msg}`;
          pending.raw = (pending.raw + '\n' + trimmed).slice(0, 1600);
          foldedStackLines++;
          continue;
        }
        if (pending && this._isJavaStackContinuation(rawLine)) {
          pending.stackFrames++;
          foldedStackLines++;
          if (/^(?:Caused by:|Suppressed:)|^(?:java|javax|jakarta|oracle|org\.apache|com\.entrust)\.[A-Za-z0-9_.$]*(?:Exception|Error|Throwable)\b/.test(trimmed)) {
            if (pending.causes.length < 6) pending.causes.push(trimmed.slice(0, 220));
          }
          if (!pending.entrustFrame && trimmed.includes('com.entrust.')) {
            pending.entrustFrame = trimmed.replace(/^at\s+/, '').trim().slice(0, 140);
          }
          if (pending.raw.length < 1550) pending.raw = (pending.raw + '\n' + trimmed).slice(0, 1600);
          continue;
        }

        if (pending) {
          lineCount++;
          commitSlot(pending);
          pending = null;
        }
        pending = {
          line: trimmed,
          raw: trimmed,
          isTomcatSimpleHdr: LP_RE_JULI_SIMPLE.test(trimmed),
          baseLevel: 'INFO',
          lockedCode: false,
          stackFrames: 0,
          causes: [],
          entrustFrame: ''
        };
      }

      if (onProgress) {
        const currentMb = (Math.min(offset, fileSize) / (1024 * 1024)).toFixed(0);
        const totalMb = (fileSize / (1024 * 1024)).toFixed(0);
        const pct = Math.min(99, Math.round((Math.min(offset, fileSize) / fileSize) * 100));
        onProgress(Math.min(offset, fileSize), fileSize, `⚡ Procesando streaming: ${currentMb} MB / ${totalMb} MB (${pct}%) — ${lineCount.toLocaleString()} eventos`);
      }
      await new Promise(r => setTimeout(r, 0));
    }

    if (leftover && leftover.trim()) {
      const rawLine = leftover.replace(/\r$/, '');
      const trimmed = rawLine.trim();
      rawLinesRead++;
      if (pending && pending.isTomcatSimpleHdr && this._isTomcatSimpleLevelLine(rawLine)) {
        const lvlPair = this._isTomcatSimpleLevelLine(rawLine);
        pending.isTomcatSimpleHdr = false;
        pending.baseLevel = lvlPair.level;
        pending.line = `${pending.line} — ${lvlPair.level}: ${lvlPair.msg}`;
        foldedStackLines++;
      } else if (pending && this._isJavaStackContinuation(rawLine)) {
        pending.stackFrames++;
        foldedStackLines++;
      } else {
        if (pending) {
          lineCount++;
          commitSlot(pending);
        }
        pending = {
          line: trimmed,
          raw: trimmed,
          isTomcatSimpleHdr: LP_RE_JULI_SIMPLE.test(trimmed),
          baseLevel: 'INFO',
          lockedCode: false,
          stackFrames: 0,
          causes: [],
          entrustFrame: ''
        };
      }
    }

    if (pending) {
      lineCount++;
      commitSlot(pending);
      pending = null;
    }

    const topUsers = Object.entries(userCounter).sort((a, b) => b[1] - a[1]).slice(0, 50).map(([user, count]) => ({ user, count }));
    const topIps = Object.entries(ipCounter).sort((a, b) => b[1] - a[1]).slice(0, 50).map(([ip, count]) => ({ ip, count }));
    const topCodes = Object.entries(codeCounter).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([code, count]) => ({ code, count }));

    return {
      parsedLogs: displayLogs,
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
        timelineBuckets: Object.entries(timeBuckets).map(([time, data]) => ({ time, ...data }))
      }
    };
  }
}

window.logParser = new LogParser();
window.logParserEngine = window.logParser;

