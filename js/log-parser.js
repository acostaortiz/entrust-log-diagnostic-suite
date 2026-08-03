/**
 * LOG-PARSER: Motor de Lectura, Extracción y Análisis Multi-Formato
 * Soporta Entrust IdentityGuard OnPremise (Errores 520xxx y Auditoría AUDxxx),
 * Syslog, Auditd, JSON, Nginx/Apache Access Logs y Trazas Distribuidas OpenTelemetry.
 */

class LogParser {
  constructor() {
    this.severityLevels = ['EMERGENCY', 'CRITICAL', 'ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG'];
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

    // Pre-procesar para combinar líneas multi-línea de Entrust IdentityGuard ([520xxx])
    const mergedLines = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      // Si la línea actual empieza por un código [520xxxx] y la línea anterior es un header de Entrust IdentityGuard
      if (/^\[520\d{4}\]/.test(line) && mergedLines.length > 0) {
        const lastIndex = mergedLines.length - 1;
        mergedLines[lastIndex] = mergedLines[lastIndex] + ' \n ' + line;
      } else {
        mergedLines.push(line);
      }
    }

    mergedLines.forEach((line, index) => {
      let parsed = this.tryParseEntrustIdentityGuard(line, index);

      if (!parsed) {
        parsed = this.tryParseJson(line, index);
      }
      if (!parsed) {
        parsed = this.tryParseAuditd(line, index);
      }
      if (!parsed) {
        parsed = this.tryParseSyslog(line, index);
      }
      if (!parsed) {
        parsed = this.tryParseWebAccess(line, index);
      }
      if (!parsed) {
        parsed = this.fallbackParse(line, index);
      }

      // Enriquecer con el motor de Base de Conocimientos
      if (window.knowledgeBaseEngine) {
        parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLog(parsed.message || parsed.raw);
      }

      parsedEntries.push(parsed);
    });

    return parsedEntries;
  }

  /**
   * Parser especializado para Entrust IdentityGuard OnPremise
   * Formato: [YYYY-MM-DD HH:mm:ss,SSS] [Thread] [LEVEL] [Category] [AUDxxx/API] [User/Context] Message...
   */
  tryParseEntrustIdentityGuard(line, lineNum) {
    if (!line.includes('[IG.') && !/520\d{4}/.test(line) && !/AUD\d+/i.test(line) && !/\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(line)) {
      return null;
    }

    const dateMatch = line.match(/^\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\]?/);
    const levelMatch = line.match(/\[?(INFO|ERROR|WARN|WARNING|CRITICAL|FATAL|DEBUG)\]?/i);
    const code520Match = line.match(/(?:\[|\b)(520\d{4})(?:\]|\b)/);
    const audMatch = line.match(/(?:\[|\b)(AUD\d+)(?:\]|\b)/i);
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
      entrustCode: code520Match ? code520Match[1] : (audMatch ? audMatch[1] : null)
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

  fallbackParse(line, lineNum) {
    let level = 'INFO';
    if (/emergency|alert|critical|fatal|panic/i.test(line)) level = 'CRITICAL';
    else if (/error|failed|exception/i.test(line)) level = 'ERROR';
    else if (/warning|warn/i.test(line)) level = 'WARN';

    return {
      id: `log-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'System',
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      level: level,
      hostname: 'localhost',
      service: 'syslog',
      message: line,
      raw: line
    };
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

  parseLine(line, lineNum) {
    if (!line || typeof line !== 'string') {
      return this.fallbackParse('', lineNum || 0);
    }

    let parsed = this.tryParseEntrustIdentityGuard(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseJson(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseAuditd(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseSyslog(line, lineNum || 0);
    if (!parsed) parsed = this.tryParseWebAccess(line, lineNum || 0);
    if (!parsed) parsed = this.fallbackParse(line, lineNum || 0);

    if (window.knowledgeBaseEngine) {
      parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLog(parsed.message || parsed.raw);
    }

    return parsed;
  }
}

window.logParser = new LogParser();
window.logParserEngine = window.logParser;

