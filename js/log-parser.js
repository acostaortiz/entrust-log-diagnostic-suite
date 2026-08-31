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
        parsed = this.tryParseSoapWebService(line, index);
      }
      if (!parsed) {
        parsed = this.tryParseTomcatCatalina(line, index);
      }
      if (!parsed) {
        parsed = this.tryParseCsv(line, index);
      }
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
   * Parsea logs de forma asíncrona en bloques (chunking) para liberar el hilo principal del navegador.
   * Evita congelamientos y la advertencia "La página no responde".
   * @param {string} rawContent 
   * @param {function(number, number, string): void} onProgress 
   * @param {number} chunkSize 
   * @returns {Promise<Array<Object>>}
   */
  async parseLogsAsync(rawContent, onProgress, chunkSize = 5000) {
    if (!rawContent || typeof rawContent !== 'string') return [];

    const lines = rawContent.split(/\r?\n/);
    const totalLines = lines.length;
    const mergedLines = [];

    // Pre-procesamiento de combinación multi-línea asíncrono
    for (let i = 0; i < totalLines; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      if (/^\[520\d{4}\]/.test(line) && mergedLines.length > 0) {
        const lastIndex = mergedLines.length - 1;
        mergedLines[lastIndex] = mergedLines[lastIndex] + ' \n ' + line;
      } else {
        mergedLines.push(line);
      }

      if (i % (chunkSize * 2) === 0) {
        const pct = Math.round((i / (totalLines * 2)) * 100);
        if (onProgress) onProgress(i, totalLines, `Pre-procesando trazas... (${pct}%)`);
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    const totalMerged = mergedLines.length;
    const parsedEntries = [];

    for (let i = 0; i < totalMerged; i++) {
      const line = mergedLines[i];
      let parsed = this.tryParseEntrustIdentityGuard(line, i);
      if (!parsed) parsed = this.tryParseSoapWebService(line, i);
      if (!parsed) parsed = this.tryParseTomcatCatalina(line, i);
      if (!parsed) parsed = this.tryParseCsv(line, i);
      if (!parsed) parsed = this.tryParseJson(line, i);
      if (!parsed) parsed = this.tryParseAuditd(line, i);
      if (!parsed) parsed = this.tryParseSyslog(line, i);
      if (!parsed) parsed = this.tryParseWebAccess(line, i);
      if (!parsed) parsed = this.fallbackParse(line, i);

      if (window.knowledgeBaseEngine) {
        parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLogWithCli 
          ? window.knowledgeBaseEngine.diagnoseLogWithCli(parsed.message || parsed.raw)
          : window.knowledgeBaseEngine.diagnoseLog(parsed.message || parsed.raw);
      }

      parsedEntries.push(parsed);

      if (i % chunkSize === 0 || i === totalMerged - 1) {
        const pct = Math.round(50 + (i / totalMerged) * 50);
        if (onProgress) onProgress(i + 1, totalMerged, `Analizando e indexando eventos... (${pct}%)`);
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    this.correlateAutoHealing(parsedEntries);

    if (onProgress) onProgress(totalMerged, totalMerged, '100% Finalizado');
    return parsedEntries;
  }

  async parseLogsWithWorker(rawContent, clientId, onProgress) {
    if (window.Worker) {
      return new Promise((resolve) => {
        try {
          const worker = new Worker('js/log-parser-worker.js');
          worker.postMessage({ rawContent, clientId });

          worker.onmessage = (e) => {
            const { type, current, total, pct, parsedLogs } = e.data;
            if (type === 'progress') {
              if (onProgress) onProgress(current, total, `⚡ [Web Worker Multihilo]: Procesando logs... (${pct}%)`);
            } else if (type === 'complete') {
              worker.terminate();
              if (window.knowledgeBaseEngine) {
                parsedLogs.forEach(l => {
                  l.diagnostic = window.knowledgeBaseEngine.diagnoseLogWithCli 
                    ? window.knowledgeBaseEngine.diagnoseLogWithCli(l.message || l.raw)
                    : window.knowledgeBaseEngine.diagnoseLog(l.message || l.raw);
                });
              }
              this.correlateAutoHealing(parsedLogs);
              if (onProgress) onProgress(total, total, '100% Finalizado (Web Worker)');
              resolve(parsedLogs);
            }
          };

          worker.onerror = (err) => {
            console.warn('Worker error fallback to parseLogsAsync:', err);
            worker.terminate();
            resolve(this.parseLogsAsync(rawContent, clientId, onProgress));
          };
        } catch(e) {
          console.warn('Worker init fallback:', e);
          resolve(this.parseLogsAsync(rawContent, clientId, onProgress));
        }
      });
    } else {
      return this.parseLogsAsync(rawContent, clientId, onProgress);
    }
  }

  correlateAutoHealing(parsedEntries) {
    if (!parsedEntries || parsedEntries.length === 0) return;
    const userEvents = new Map();

    parsedEntries.forEach(entry => {
      if (!entry.user) return;
      if (!userEvents.has(entry.user)) userEvents.set(entry.user, []);
      userEvents.get(entry.user).push(entry);
    });

    userEvents.forEach((events) => {
      for (let i = 0; i < events.length; i++) {
        const current = events[i];
        if (current.level === 'ERROR' || current.level === 'CRITICAL') {
          for (let j = i + 1; j < events.length; j++) {
            const next = events[j];
            if (next.level === 'INFO' || (next.message && /(200 OK|AuthenticationSuccessful|AUD2300|success)/i.test(next.message))) {
              current.recovered = true;
              current.recoveredAt = next.timestamp;
              if (current.diagnostic) {
                current.diagnostic.title = `[REINTENTO RECUPERADO CON ÉXITO] ${current.diagnostic.title}`;
                current.diagnostic.meaning += ` (El usuario logró autenticarse exitosamente a las ${next.timestamp}).`;
              }
              break;
            }
          }
        }
      }
    });
  }

  /**
   * Parser especializado para Web Services SOAP de Entrust IdentityGuard OnPremise
   * Endpoints: /idgserv/services/AuthenticationService, /AdministrationService, /IdentityRepositoryService
   * Payload: SOAP Envelope, SOAP Faults, WS-Security Headers
   */
  tryParseSoapWebService(line, lineNum) {
    const isSoapPattern = /(soapenv:|SOAPFault|wsse:|AuthenticationService|AdministrationService|IdentityRepositoryService|\/services\/[A-Za-z]+Service)/i.test(line);
    if (!isSoapPattern) return null;

    const codeMatch = line.match(/(520\d{4}|AUD\d+|wsse:\w+|soapenv:\w+)/i);
    const dateMatch = line.match(/^\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\]?/) ||
                      line.match(/\[?(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})/);

    let level = 'INFO';
    if (/(Fault|Exception|FailedAuthentication|ERROR|CRITICAL|500)/i.test(line)) {
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
      entrustCode: codeMatch ? codeMatch[1] : null
    };
  }

  /**
   * Parser especializado para Tomcat / Catalina (Entrust IdentityGuard Application Server)
   */
  tryParseTomcatCatalina(line, lineNum) {
    const isCatalinaPattern = /(catalina|org\.apache\.catalina|com\.entrust|OutOfMemoryError|SQLException|SSLHandshakeException|ClientAbortException|NullPointerException|Servlet\.service)/i.test(line);
    const dateMatch = line.match(/^(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)/) ||
                      line.match(/^([A-Za-z]{3}\s+\d{1,2},\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM))/i) ||
                      line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)/);

    const levelMatch = line.match(/\b(SEVERE|FATAL|ERROR|WARNING|WARN|INFO|CONFIG|FINE|FINER|FINEST)\b/i);

    if (!isCatalinaPattern && !dateMatch && !levelMatch) return null;

    let level = 'INFO';
    const isDisconnection = /(ClientAbortException|Broken pipe|ClientAbort|Connection reset)/i.test(line);
    if (isDisconnection) {
      level = 'INFO';
    } else if (levelMatch) {
      level = this.normalizeLevel(levelMatch[1]);
    } else if (/(OutOfMemoryError|SQLException|SSLHandshakeException|FATAL|CRITICAL)/i.test(line)) {
      level = 'CRITICAL';
    } else if (/(Exception|Error|Failed)/i.test(line)) {
      level = 'ERROR';
    }

    const timestamp = dateMatch ? dateMatch[1] : new Date().toISOString().replace('T', ' ').substring(0, 19);

    let service = 'Tomcat Catalina / IDG';
    const exceptionClassMatch = line.match(/\b(java\.[a-zA-Z0-9\._]+Exception|javax\.[a-zA-Z0-9\._]+Exception|java\.lang\.OutOfMemoryError|org\.apache\.[a-zA-Z0-9\._]+)\b/);
    if (exceptionClassMatch) {
      service = `Tomcat [${exceptionClassMatch[1].split('.').pop()}]`;
    }

    const codeMatch = line.match(/(520\d{4}|AUD\d+)/i);

    return {
      id: `tomcat-${lineNum}-${Date.now()}`,
      lineNum: lineNum + 1,
      type: 'Tomcat Catalina',
      timestamp: timestamp,
      level: level,
      hostname: 'idg-tomcat-srv',
      service: service,
      message: line,
      raw: line,
      entrustCode: codeMatch ? codeMatch[1] : null
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
        } else if (/(520\d{4}|AUD\d+|SAML|MFA|OIDC|OAUTH)/i.test(field)) {
          entrustCode = field;
        } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(field)) {
          clientIp = field;
        } else if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(field) || /^(user|admin|mrodriguez|jperez|acosta)/i.test(field)) {
          user = field;
        }
      });

      const codeInLine = line.match(/(520\d{4}|AUD\d+|SAML_\w+|MFA_\w+|Authentication\w+Event)/i)?.[1];
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
    if (!line.includes('[IG.') && !/520\d{4}/.test(sanitizedLine) && !/AUD\d+/i.test(sanitizedLine) && !/\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/.test(line)) {
      return null;
    }

    const dateMatch = line.match(/^\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d{3})?)\]?/);
    const levelMatch = line.match(/\[?(INFO|ERROR|WARN|WARNING|CRITICAL|FATAL|DEBUG)\]?/i);
    const code520Match = sanitizedLine.match(/(?:\[|\b)(520\d{4})(?:\]|\b)/);
    const audMatch = sanitizedLine.match(/(?:\[|\b)(AUD\d+)(?:\]|\b)/i);
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

  extractUser(line) {
    if (!line || typeof line !== 'string') return null;

    // Priorizar usuarios explícitos de Banco del Caribe / Mercantil / Banesco
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

