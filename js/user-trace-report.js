/**
 * ==============================================================================
 * 🏢 IT SERVICIOS DE VENEZUELA, S.A.
 * MÓDULO: INFORME DE TRAZABILIDAD Y SEGURIDAD DE USUARIOS (v470.0)
 * ==============================================================================
 * Censo integral de usuarios, clasificación de fallas vs éxitos, correlación
 * de códigos Entrust/Auditoría, y generación de expedientes técnicos (PDF, DOCX, CSV).
 */

// Global HTML Sanitizer
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

(function(window) {
  'use strict';

  const UserTraceReport = {
    selectedUsers: new Set(),
    cachedStats: {},
    activeFilterTab: 'all', // 'all', 'errors', 'success'

    init() {
      this.bindEvents();
      console.log('✅ [UserTraceReport]: Módulo de Trazabilidad y Seguridad de Usuarios v470 inicializado.');
    },

    bindEvents() {
      // Botón en Menú Exportar
      const btnOpenExport = document.getElementById('btn-open-user-trace-report');
      if (btnOpenExport) {
        btnOpenExport.addEventListener('click', () => this.openModal());
      }

      // Botón en Menú Herramientas
      const btnOpenTools = document.getElementById('btn-tools-user-trace-report');
      if (btnOpenTools) {
        btnOpenTools.addEventListener('click', () => this.openModal());
      }

      // Botón Cerrar Modal
      const btnClose = document.getElementById('btn-close-user-trace-modal');
      const btnCloseBottom = document.getElementById('btn-close-user-trace-modal-bottom');
      const modal = document.getElementById('modal-user-trace-report');

      if (btnClose) btnClose.addEventListener('click', () => this.closeModal());
      if (btnCloseBottom) btnCloseBottom.addEventListener('click', () => this.closeModal());
      if (modal) {
        modal.addEventListener('click', (e) => {
          if (e.target === modal) this.closeModal();
        });
      }

      // Búsqueda en tiempo real de usuarios
      const inputSearch = document.getElementById('user-trace-search-user');
      if (inputSearch) {
        inputSearch.addEventListener('input', (e) => this.filterUserList(e.target.value));
      }

      // Botones de Filtro Rápido en Sidebar
      const btnSelectAll = document.getElementById('btn-trace-select-all');
      if (btnSelectAll) {
        btnSelectAll.addEventListener('click', () => this.selectAllUsers());
      }

      const btnSelectErrors = document.getElementById('btn-trace-select-errors');
      if (btnSelectErrors) {
        btnSelectErrors.addEventListener('click', () => this.selectErrorUsersOnly());
      }

      const btnSelectSuccess = document.getElementById('btn-trace-select-success');
      if (btnSelectSuccess) {
        btnSelectSuccess.addEventListener('click', () => this.selectSuccessUsersOnly());
      }

      const btnClearSelection = document.getElementById('btn-trace-clear-selection');
      if (btnClearSelection) {
        btnClearSelection.addEventListener('click', () => this.clearSelection());
      }

      // Agregar usuario manual
      const btnAddCustomUser = document.getElementById('btn-trace-add-custom-user');
      const inputCustomUser = document.getElementById('input-trace-custom-user');
      if (btnAddCustomUser && inputCustomUser) {
        const handleAdd = () => {
          const val = inputCustomUser.value.trim();
          if (val) {
            this.selectedUsers.add(val);
            if (!this.cachedStats[val]) {
              this.cachedStats[val] = {
                username: val,
                totalEvents: 0,
                errors: 0,
                criticals: 0,
                warnings: 0,
                successes: 0,
                ips: new Set(),
                nodes: new Set(),
                codes: {},
                lastTimestamp: new Date().toISOString()
              };
            }
            inputCustomUser.value = '';
            this.updateLanguageButtons();
      this.renderUserChecklist();
            this.generateReport();
          }
        };
        btnAddCustomUser.addEventListener('click', handleAdd);
        inputCustomUser.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') handleAdd();
        });
      }

      // Botón Generar / Actualizar
      const btnGenerate = document.getElementById('btn-trace-generate-report');
      if (btnGenerate) {
        btnGenerate.addEventListener('click', () => this.generateReport());
      }

      // Exportar PDF, DOCX, CSV, Imprimir, Copiar
            // Selector de idioma User Trace (ES / EN)
      const btnTraceLangEs = document.getElementById('btn-trace-lang-es');
      const btnTraceLangEn = document.getElementById('btn-trace-lang-en');
      if (btnTraceLangEs) {
        btnTraceLangEs.addEventListener('click', () => {
          if (window.setReportLanguageGlobal) window.setReportLanguageGlobal('es');
          this.updateLanguageButtons();
          this.generateReport();
        });
      }
      if (btnTraceLangEn) {
        btnTraceLangEn.addEventListener('click', () => {
          if (window.setReportLanguageGlobal) window.setReportLanguageGlobal('en');
          this.updateLanguageButtons();
          this.generateReport();
        });
      }
      const btnPdf = document.getElementById('btn-trace-export-pdf');
      if (btnPdf) btnPdf.addEventListener('click', () => this.downloadPdf());

      const btnDocx = document.getElementById('btn-trace-export-docx');
      if (btnDocx) btnDocx.addEventListener('click', () => this.downloadDocx());

      const btnCsv = document.getElementById('btn-trace-export-csv');
      if (btnCsv) btnCsv.addEventListener('click', () => this.downloadCsv());

      const btnPrint = document.getElementById('btn-trace-print');
      if (btnPrint) btnPrint.addEventListener('click', () => window.print());

      const btnCopy = document.getElementById('btn-trace-copy');
      if (btnCopy) btnCopy.addEventListener('click', () => this.copyReportText());
    },

    getAllLogs() {
      const st = window.appState || window.state;
      if (st && Array.isArray(st.logs) && st.logs.length > 0) {
        return st.logs;
      }
      return [];
    },

    getClientProfile() {
      if (window.getActiveClientProfileGlobal && typeof window.getActiveClientProfileGlobal === 'function') {
        return window.getActiveClientProfileGlobal();
      }
      if (window.getActiveClientProfile && typeof window.getActiveClientProfile === 'function') {
        return window.getActiveClientProfile();
      }
      const st = window.appState || window.state;
      if (st && st.clientProfiles) {
        return st.clientProfiles.find(c => c.id === st.activeClientId) || st.clientProfiles[0];
      }
      return {
        name: 'Entorno Entrust General / Multi-Nodo',
        platform: 'Entrust IdentityGuard OnPremise',
        version: 'Release 12.0',
        build: 'General'
      };
    },

    updateLanguageButtons() {
      const st = window.appState || window.state;
      const isEn = st && st.reportLanguage === 'en';
      const btnEs = document.getElementById('btn-trace-lang-es');
      const btnEn = document.getElementById('btn-trace-lang-en');
      if (btnEs && btnEn) {
        if (!isEn) {
          btnEs.style.background = '#0284c7';
          btnEs.style.color = '#fff';
          btnEn.style.background = 'transparent';
          btnEn.style.color = 'var(--text-muted)';
        } else {
          btnEn.style.background = '#0284c7';
          btnEn.style.color = '#fff';
          btnEs.style.background = 'transparent';
          btnEs.style.color = 'var(--text-muted)';
        }
      }
    },

    async openModal(initialUsers) {
      const modal = document.getElementById('modal-user-trace-report');
      if (!modal) return;
      modal.style.display = 'flex';

      if (!this.forensicMatrixData && this.getAllLogs().length === 0) {
        await this.fetchForensicMatrix(false);
      }

      this.buildUserStats();

      if (initialUsers) {
        this.selectedUsers.clear();
        if (typeof initialUsers === 'string') {
          this.selectedUsers.add(initialUsers);
        } else if (Array.isArray(initialUsers) || initialUsers instanceof Set) {
          initialUsers.forEach(u => this.selectedUsers.add(u));
        }
      } else {
        // Seleccionar automáticamente todos los usuarios detectados para que el informe nunca abra vacío
        this.selectedUsers.clear();
        Object.keys(this.cachedStats).forEach(u => this.selectedUsers.add(u));
      }

      this.updateSidebarCounters();
      this.updateLanguageButtons();
      this.renderUserChecklist();
      this.generateReport();
    },

    closeModal() {
      const modal = document.getElementById('modal-user-trace-report');
      if (modal) modal.style.display = 'none';
    },

    isValidUserCandidate(cand) {
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
        'client', 'server', 'node', 'host', 'ip', 'port', 'url', 'uri', 'http', 'https',
        'api', 'soap', 'rest', 'xml', 'json', 'csv', 'data', 'value', 'values', 'key', 'keys',
        'code', 'codes', 'result', 'results', 'reason', 'details', 'detail', 'description'
      ]);
      if (stopWords.has(low)) return false;
      if (/^[-.=/\\:;,]/.test(clean)) return false;
      if (/^(com\.|org\.|java\.|javax\.|net\.|sun\.|entrust\.|ora-|aud\d|bulkidentityguard|http)/i.test(low)) return false;
      if (/^520\d{4}$/.test(clean) || /^\d{4}-\d{2}-\d{2}/.test(clean) || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(clean)) return false;
      if (/(exception|repository|transactionqueue|blobaccess|authenticator|manager|handler|controller|factory|provider)/i.test(low)) return false;
      return /[A-Za-z0-9]/.test(clean);
    },

    classifyUserSequence(uStat) {
      const seq = uStat.sequence || [];
      const rleSteps = [];
      const normSteps = [];
      seq.forEach(s => {
        const cLabel = s.code || 'EVENT';
        const oLabel = s.outcome || 'SUCCESS';
        if (rleSteps.length > 0 && rleSteps[rleSteps.length - 1].code === cLabel && rleSteps[rleSteps.length - 1].outcome === oLabel) {
          rleSteps[rleSteps.length - 1].repeat += 1;
        } else {
          rleSteps.push({ code: cLabel, outcome: oLabel, repeat: 1 });
          if (normSteps.length < 6) {
            normSteps.push(`${cLabel} (${oLabel === 'FAIL' ? 'FALLO' : 'ÉXITO'})`);
          }
        }
      });

      const compressedParts = rleSteps.slice(0, 8).map(st => {
        const rep = st.repeat > 1 ? ` x${st.repeat}` : '';
        return `${st.code} (${st.outcome === 'FAIL' ? 'FALLO' : 'ÉXITO'}${rep})`;
      });
      let compressedPattern = compressedParts.join(' ➔ ');
      if (rleSteps.length > 8) {
        compressedPattern += ` ➔ ... (+${rleSteps.length - 8} etapas)`;
      }
      const normalizedSignature = normSteps.length > 0 ? normSteps.join(' ➔ ') : 'OPERACIÓN_UNICA';

      const codesLower = Object.keys(uStat.codes || {}).join(' ').toLowerCase();
      let patternCategory = '✅ Operación Nominal Limpia (100% Éxito)';
      let rootCause = 'Todas las solicitudes registradas para este usuario finalizaron con estado SUCCESS.';

      if (/(ora-|sql_exception|jdbccardrepository|transactionqueue|blobaccess)/i.test(codesLower)) {
        patternCategory = '🗄️ Fallo Inducido por Base de Datos (ORA / JDBC)';
        rootCause = 'Las solicitudes del usuario fueron abortadas por una excepción de persistencia o bloqueo en la base de datos (ej. ORA-01555 / SQLException), no por error humano de credenciales.';
      } else if (/(bulkidentityguard|migration|assignedgrid)/i.test(codesLower)) {
        patternCategory = '☁️ Colisión de Migración IDaaS (Grid / Password / QA)';
        rootCause = 'El usuario ya posee un autenticador activo (Grid Card, Password o Q&A) en el destino o la política del grupo restringe la sobreescritura durante la migración masiva.';
      } else if (uStat.errors > 0 && uStat.successes > 0) {
        const lastOutcome = seq.length > 0 ? seq[seq.length - 1].outcome : 'FAIL';
        if (lastOutcome === 'SUCCESS') {
          patternCategory = '🔁 Auto-Recuperación (Fallo ➔ Éxito)';
          rootCause = 'El usuario experimentó fricción inicial de autenticación (OTP/Password vencido o mal digitado) pero logró autenticarse exitosamente en un intento posterior.';
        } else {
          patternCategory = '📉 Degradación de Sesión (Éxito ➔ Fallo)';
          rootCause = 'El usuario operaba normalmente y comenzó a presentar rechazos consecutivos (posible bloqueo de cuenta 5201053, desincronización de Token o expiración de credencial).';
        }
      } else if (uStat.errors >= 3 && uStat.successes === 0) {
        patternCategory = '🚨 Ráfaga de Bloqueo / Fuerza Bruta Persistente';
        rootCause = 'Múltiples intentos fallidos consecutivos sin ningún éxito registrado. Alto riesgo de bloqueo de cuenta (Lockout 5201053) o script automatizado con credenciales obsoletas.';
      } else if (uStat.errors > 0 && uStat.successes === 0) {
        patternCategory = '⚠️ Fricción de Autenticación sin Recuperación';
        rootCause = 'El usuario intentó autenticarse o enrolarse sin éxito y abandonó el flujo sin completar una transacción válida.';
      } else if (/aud\d/i.test(codesLower)) {
        patternCategory = '🛡️ Secuencia de Auditoría / Gestión Nominal';
        rootCause = 'Trazas de auditoría administrativa o verificaciones nominales completadas sin errores.';
      }

      uStat.compressedPattern = compressedPattern || 'Sin secuencia registrada';
      uStat.normalizedSignature = normalizedSignature;
      uStat.patternCategory = patternCategory;
      uStat.rootCause = rootCause;
    },

    buildUserStats() {
      const logs = this.getAllLogs();
      const stats = {};
      const st = window.appState || window.state;

      for (let idx = 0; idx < logs.length; idx++) {
        const log = logs[idx];
        let user = log.user || log.usuario || log.username;
        const msg = log.raw || log.message || '';

        // Si el log contiene explícitamente "for user <cliente>", priorizar al cliente final sobre cuentas actoras (ej. bmapiuser8)
        if (msg && (msg.includes('for user ') || msg.includes('for user\t') || msg.includes('User '))) {
          const explicitTarget = msg.match(/\bfor\s+user\s+['"]?([A-Za-z0-9_\-\.\/@]+)['"]?/i) ||
                                 msg.match(/\bUser\s+([A-Za-z0-9_\-\.\/@]+)\s+(?:currently\s+has|has\s+a\s+grid|already\s+has|created|failed|logged|assigned|updated|deleted|authenticated|locked|disabled|migrated)/i);
          if (explicitTarget && this.isValidUserCandidate(explicitTarget[1])) {
            user = explicitTarget[1];
          }
        }

        if (!this.isValidUserCandidate(user) && msg) {
          const kvMatch = msg.match(/(?:for\s+user|User:|user\s+name\s+or\s+alias|username|userId|user_id|subjectName)[\s:=]+['"]?([a-zA-Z0-9_\.\@\/\-]+)['"]?/i);
          const audBracket = msg.includes('[') ? msg.match(/\[(?:AUD\d+|IG\.AUDIT)\]\s*\[([^\]]+)\]/i) : null;
          if (kvMatch && this.isValidUserCandidate(kvMatch[1])) {
            user = kvMatch[1];
          } else if (audBracket && this.isValidUserCandidate(audBracket[1])) {
            user = audBracket[1];
          } else {
            user = null;
          }
        }

        if (!this.isValidUserCandidate(user)) continue;
        user = String(user).trim().replace(/^['"\[\]().,;:!?]+|['"\[\]().,;:!?]+$/g, '');

        if (!stats[user]) {
          stats[user] = {
            username: user,
            totalEvents: 0,
            errors: 0,
            criticals: 0,
            warnings: 0,
            successes: 0,
            isLocked: false,
            ips: new Set(),
            nodes: new Set(),
            codes: {},
            codesDetail: {},
            sequence: [],
            sampleLogs: [],
            lastTimestamp: log.timestamp || '',
            firstTimestamp: log.timestamp || ''
          };
        }

        const uStat = stats[user];
        uStat.totalEvents++;
        const lvl = (log.level || '').toUpperCase();
        let code = String(log.code || log.entrustCode || log.type || 'SYS-EVENT');
        // Purgar falsos positivos de IDaaS generados en sesiones previas sobre logs OnPremise
        if (/bulkidentityguard/i.test(code) && !/bulkidentityguard|IdentityGuard migration:/i.test(msg)) {
          const c520 = msg.match(/520\d{4}/);
          const aud = msg.match(/AUD\d{3,4}/i);
          if (c520) code = c520[0];
          else if (aud) code = aud[0].toUpperCase();
          else if (/Target:.*:ssh|sshd|pam_unix/i.test(msg)) code = 'SSH-AUTH';
          else code = 'IG.SYSTEM';
        }

        const isFail = lvl === 'CRITICAL' || lvl === 'FATAL' || lvl === 'ERROR' || (log.outcome && /FAIL|ERR/i.test(log.outcome)) ||
                       /520\d{4}/.test(code) || /AUD6001|AUD6002/i.test(code) || /ORA-/.test(code) || /error/i.test(code) ||
                       /failed authentication|locked out|fail|error|denied|invalid/i.test(msg);

        if (isFail) {
          uStat.errors++;
          if (lvl === 'CRITICAL' || /5201000|5202013|AUD6002|ORA-/.test(code)) {
            uStat.criticals++;
          }
        } else if (lvl === 'WARN' || lvl === 'WARNING' || /AUD002|AUD2309/.test(code)) {
          uStat.warnings++;
        } else {
          uStat.successes++;
        }

        if (/5205079|5205080|5201053|5203016|5202002|AUD007|AUD6002|locked|bloquead/i.test(code) || /locked|bloquead/i.test(msg)) {
          uStat.isLocked = true;
        }

        if (log.ip || log.clientIp) uStat.ips.add(log.ip || log.clientIp);
        if (log.server || log.node || log.sourceFile) uStat.nodes.add(log.server || log.node || log.sourceFile);

        uStat.codes[code] = (uStat.codes[code] || 0) + 1;
        if (!uStat.codesDetail[code]) {
          uStat.codesDetail[code] = { total: 0, errors: 0, success: 0 };
        }
        uStat.codesDetail[code].total++;
        if (isFail) uStat.codesDetail[code].errors++;
        else uStat.codesDetail[code].success++;

        if (uStat.sequence.length < 40) {
          uStat.sequence.push({
            step: uStat.sequence.length + 1,
            code,
            outcome: isFail ? 'FAIL' : 'SUCCESS',
            timestamp: log.timestamp || log.time || '',
            ip: log.clientIp || log.ip || 'local',
            lineNum: log.lineNum || (idx + 1),
            msg: (log.message || log.raw || '').slice(0, 160)
          });
        }

        if (uStat.sampleLogs.length < 15) {
          uStat.sampleLogs.push(log);
        }

        if (log.timestamp) {
          uStat.lastTimestamp = log.timestamp;
          if (!uStat.firstTimestamp) uStat.firstTimestamp = log.timestamp;
        }
      }

      // Integrar usuarios del motor SQLite ÚNICAMENTE si la sesión activa es de servidor SQLite (evita mezclar bases de datos antiguas con archivos locales OnPremise)
      const isServerMode = !!(st && st.isServerApi);
      if (isServerMode && this.forensicMatrixData && Array.isArray(this.forensicMatrixData.usersList)) {
        this.forensicMatrixData.usersList.forEach(su => {
          if (!this.isValidUserCandidate(su.user)) return;
          const codesSimple = {};
          Object.entries(su.codes || {}).forEach(([k, v]) => {
            codesSimple[k] = typeof v === 'object' ? (v.total || 0) : v;
          });
          const isLocked = Object.keys(codesSimple).some(c => /5205079|5205080|5201053|5203016|5202002|AUD007|AUD6002/i.test(c)) ||
                           /Bloqueo|Fuerza Bruta/i.test(su.patternCategory || '');
          const existingSamples = stats[su.user]?.sampleLogs || [];
          stats[su.user] = {
            username: su.user,
            totalEvents: su.total || 0,
            errors: su.errors || 0,
            criticals: su.errors || 0,
            warnings: 0,
            successes: su.success || 0,
            isLocked,
            ips: new Set(su.ips || []),
            nodes: new Set(['🖥️ Motor Core SQLite']),
            codes: codesSimple,
            codesDetail: su.codes || {},
            sequence: su.sequence || [],
            sampleLogs: existingSamples,
            compressedPattern: su.compressedPattern || '',
            normalizedSignature: su.normalizedSignature || '',
            patternCategory: su.patternCategory || '',
            rootCause: su.rootCause || '',
            firstTimestamp: su.firstSeen || '',
            lastTimestamp: su.lastSeen || ''
          };
        });
      }

      // Integrar también usuarios agregados en globalStreamMetrics (Web Worker para archivos de 10-50 MB)
      const isOnPremFile = !(st && (st.loadedFiles || []).some(f => /\.csv|auditevents|import_identityguard|idaas/i.test(f.name || '')));
      if (st && st.globalStreamMetrics && Array.isArray(st.globalStreamMetrics.topUsers)) {
        st.globalStreamMetrics.topUsers.forEach(tu => {
          const uName = tu && tu.user ? String(tu.user).trim() : '';
          if (!this.isValidUserCandidate(uName)) return;
          const rawTuCodes = (tu.codes && Object.keys(tu.codes).length > 0) ? tu.codes : { 'IG.AUDIT': tu.count || 1 };
          const tuCodes = {};
          Object.entries(rawTuCodes).forEach(([rk, rv]) => {
            const cleanKey = (isOnPremFile && /bulkidentityguard/i.test(rk)) ? 'SSH-AUTH' : rk;
            tuCodes[cleanKey] = (tuCodes[cleanKey] || 0) + rv;
          });
          const tuCodesDetail = {};
          Object.entries(tuCodes).forEach(([cKey, cVal]) => {
            const isCError = /^520\d{4}|AUD6001|AUD6002|ORA-|error/i.test(cKey);
            tuCodesDetail[cKey] = { total: cVal, errors: isCError ? cVal : 0, success: isCError ? 0 : cVal };
          });
          const isTuLocked = Object.keys(tuCodes).some(c => /5205079|5205080|5201053|5203016|5202002|AUD007|AUD6002/i.test(c));
          if (!stats[uName]) {
            stats[uName] = {
              username: uName,
              totalEvents: tu.count || 1,
              errors: tu.errors || 0,
              criticals: tu.errors || 0,
              warnings: 0,
              successes: Math.max(0, (tu.count || 1) - (tu.errors || 0)),
              isLocked: isTuLocked,
              ips: new Set(),
              nodes: new Set(['⚡ Stream Worker']),
              codes: tuCodes,
              codesDetail: tuCodesDetail,
              sequence: Object.entries(tuCodes).map(([cKey, cVal], sIdx) => ({
                step: sIdx + 1,
                code: cKey,
                outcome: (/^520\d{4}|AUD6001|AUD6002|ORA-|error/i.test(cKey) ? 'FAIL' : 'SUCCESS'),
                timestamp: tu.lastSeen || '',
                ip: 'local',
                lineNum: 1,
                msg: `${cVal} eventos con código ${cKey}`
              })),
              sampleLogs: [],
              firstTimestamp: tu.firstSeen || '',
              lastTimestamp: tu.lastSeen || ''
            };
          } else {
            if ((tu.count || 0) > stats[uName].totalEvents) {
              stats[uName].totalEvents = tu.count;
            }
            if ((tu.errors || 0) > stats[uName].errors) {
              stats[uName].errors = tu.errors;
            }
            stats[uName].successes = Math.max(0, stats[uName].totalEvents - stats[uName].errors);
            if (isTuLocked) stats[uName].isLocked = true;
            if (tu.codes) {
              Object.entries(tu.codes).forEach(([cKey, cVal]) => {
                if (!stats[uName].codes[cKey] || cVal > stats[uName].codes[cKey]) {
                  stats[uName].codes[cKey] = cVal;
                }
              });
            }
          }
        });
      }

      Object.values(stats).forEach(uStat => {
        if (!uStat.compressedPattern) {
          this.classifyUserSequence(uStat);
        }
      });

      this.cachedStats = stats;
    },

    updateSidebarCounters() {
      const allUsers = Object.values(this.cachedStats);
      const totalCount = allUsers.length;
      const errorCount = allUsers.filter(u => u.errors > 0).length;
      const successCount = allUsers.filter(u => u.errors === 0).length;

      const elAll = document.getElementById('count-all-users');
      const elErr = document.getElementById('count-error-users');
      const elSuc = document.getElementById('count-success-users');

      if (elAll) elAll.textContent = totalCount;
      if (elErr) elErr.textContent = errorCount;
      if (elSuc) elSuc.textContent = successCount;
    },

    renderUserChecklist() {
      const container = document.getElementById('user-trace-checklist-container');
      if (!container) return;

      const userList = Object.values(this.cachedStats).sort((a, b) => {
        if (b.errors !== a.errors) return b.errors - a.errors;
        return b.totalEvents - a.totalEvents;
      });

      if (userList.length === 0) {
        container.innerHTML = `
          <div style="padding:16px; text-align:center; color:var(--text-muted); font-size:0.8rem;">
            No se detectaron usuarios en los logs cargados. Puedes agregar usuarios manualmente arriba.
          </div>
        `;
        return;
      }

      let html = '';
      const displayChecklist = userList.slice(0, 400);
      displayChecklist.forEach(u => {
        const isChecked = this.selectedUsers.has(u.username);
        let errorBadge = '';
        if (u.isLocked) {
          errorBadge = `<span style="background:rgba(225,29,72,0.15); color:#e11d48; border:1px solid rgba(225,29,72,0.3); font-size:0.68rem; font-weight:800; padding:1px 6px; border-radius:10px;">🔒 BLOQUEADO</span>`;
        } else if (u.errors > 0) {
          errorBadge = `<span style="background:rgba(239,68,68,0.15); color:#ef4444; border:1px solid rgba(239,68,68,0.3); font-size:0.68rem; font-weight:800; padding:1px 6px; border-radius:10px;">${u.errors} fallas</span>`;
        } else {
          errorBadge = `<span style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-size:0.68rem; font-weight:700; padding:1px 6px; border-radius:10px;">✅ OK</span>`;
        }

        html += `
          <label class="user-trace-checkbox-item ${isChecked ? 'selected' : ''}" style="display:flex; align-items:center; justify-content:space-between; padding:6px 10px; border-radius:6px; margin-bottom:4px; cursor:pointer; background:${isChecked ? 'rgba(2,132,199,0.12)' : 'var(--bg-primary)'}; border:1px solid ${isChecked ? '#0284c7' : 'var(--border-color)'}; font-size:0.8rem;">
            <div style="display:flex; align-items:center; gap:8px; overflow:hidden;">
              <input type="checkbox" value="${escapeHtml(u.username)}" ${isChecked ? 'checked' : ''} onchange="window.UserTraceReport.toggleUser('${escapeHtml(u.username)}', this.checked)" style="cursor:pointer;">
              <span style="font-weight:700; color:var(--text-main); font-family:'JetBrains Mono', monospace;">${escapeHtml(u.username)}</span>
            </div>
            <div style="display:flex; align-items:center; gap:6px;">
              <span style="font-size:0.7rem; color:var(--text-muted);">${u.totalEvents.toLocaleString()} txs</span>
              ${errorBadge}
            </div>
          </label>
        `;
      });

      if (userList.length > 400) {
        html += `<div style="padding:8px; font-size:0.72rem; color:var(--text-muted); text-align:center;">Mostrando top 400 de ${userList.length.toLocaleString()} usuarios en lista rápida (usa el buscador o exporta CSV para el 100%).</div>`;
      }

      container.innerHTML = html;
    },

    toggleUser(username, isChecked) {
      if (isChecked) {
        this.selectedUsers.add(username);
      } else {
        this.selectedUsers.delete(username);
      }
      this.updateLanguageButtons();
      this.renderUserChecklist();
      this.generateReport();
    },

    filterUserList(query) {
      const q = (query || '').toLowerCase().trim();
      const container = document.getElementById('user-trace-checklist-container');
      if (!container) return;

      const labels = container.querySelectorAll('.user-trace-checkbox-item');
      labels.forEach(lbl => {
        const txt = lbl.innerText.toLowerCase();
        lbl.style.display = txt.includes(q) ? 'flex' : 'none';
      });
    },

    selectAllUsers() {
      this.selectedUsers.clear();
      Object.keys(this.cachedStats).forEach(u => this.selectedUsers.add(u));
      this.updateLanguageButtons();
      this.renderUserChecklist();
      this.generateReport();
    },

    selectErrorUsersOnly() {
      this.selectedUsers.clear();
      Object.values(this.cachedStats).forEach(u => {
        if (u.errors > 0 || u.isLocked) {
          this.selectedUsers.add(u.username);
        }
      });
      this.updateLanguageButtons();
      this.renderUserChecklist();
      this.generateReport();
    },

    selectSuccessUsersOnly() {
      this.selectedUsers.clear();
      Object.values(this.cachedStats).forEach(u => {
        if (u.errors === 0 && !u.isLocked) {
          this.selectedUsers.add(u.username);
        }
      });
      this.updateLanguageButtons();
      this.renderUserChecklist();
      this.generateReport();
    },

    clearSelection() {
      this.selectedUsers.clear();
      this.updateLanguageButtons();
      this.renderUserChecklist();
      this.generateReport();
    },

    generateReport() {
      const container = document.getElementById('user-trace-report-preview');
      if (!container) return;

      const allUsersList = Object.values(this.cachedStats);
      const totalGlobalUsers = allUsersList.length;
      const totalGlobalErrorUsers = allUsersList.filter(u => u.errors > 0).length;
      const totalGlobalSuccessUsers = allUsersList.filter(u => u.errors === 0).length;
      const totalGlobalLockedUsers = allUsersList.filter(u => u.isLocked).length;

      if (this.selectedUsers.size === 0) {
        container.innerHTML = `
          <div style="padding:60px 20px; text-align:center; color:var(--text-muted);">
            <div style="font-size:3rem; margin-bottom:12px;">👥</div>
            <div style="font-size:1.1rem; font-weight:700; color:var(--text-main);">No hay usuarios seleccionados</div>
            <div style="font-size:0.8rem; margin-top:6px;">Usa los botones superiores para seleccionar "Todos", "Con Fallas" o marca usuarios en el panel izquierdo.</div>
            <button class="btn btn-primary" onclick="window.UserTraceReport.selectAllUsers()" style="margin-top:16px; font-size:0.85rem; padding:8px 16px;">🌟 Seleccionar Todos los Usuarios (${totalGlobalUsers})</button>
          </div>
        `;
        return;
      }

      const st = window.appState || window.state;
      const isEn = st && st.reportLanguage === 'en';
      const activeClient = this.getClientProfile();
      const clientLabel = activeClient ? (activeClient.name || 'Entrust General') : 'Entrust General';
      const clientVersion = activeClient ? `${activeClient.platform || 'IdentityGuard'} ${activeClient.version || 'Release 12.0'}` : 'Entrust IdentityGuard';
      const nowFormatted = new Date().toLocaleString(isEn ? 'en-US' : 'es-VE', { dateStyle: 'long', timeStyle: 'medium' });

      const targetUsers = Array.from(this.selectedUsers);

      // Recolectar muestra rápida de eventos de los usuarios seleccionados desde cachedStats (O(1), sin bloquear con 500k logs)
      const userLogs = [];
      for (let i = 0; i < targetUsers.length && userLogs.length < 120; i++) {
        const uStat = this.cachedStats[targetUsers[i]];
        if (!uStat) continue;
        if (Array.isArray(uStat.sampleLogs) && uStat.sampleLogs.length > 0) {
          for (let j = 0; j < uStat.sampleLogs.length && userLogs.length < 120; j++) {
            const sl = uStat.sampleLogs[j];
            userLogs.push({
              timestamp: sl.timestamp || '-',
              user: uStat.username,
              code: sl.code || sl.entrustCode || sl.type || 'SYS-EVENT',
              level: sl.level || 'INFO',
              message: sl.message || sl.raw || '',
              ip: sl.clientIp || sl.ip || 'local'
            });
          }
        } else if (Array.isArray(uStat.sequence)) {
          for (let j = 0; j < uStat.sequence.length && userLogs.length < 120; j++) {
            const sq = uStat.sequence[j];
            userLogs.push({
              timestamp: sq.timestamp || '-',
              user: uStat.username,
              code: sq.code || 'SYS-EVENT',
              level: sq.outcome === 'FAIL' ? 'ERROR' : 'INFO',
              message: sq.msg || `Solicitud #${sq.step} (${sq.outcome})`,
              ip: sq.ip || 'local'
            });
          }
        }
      }

      // Métricas de los usuarios seleccionados
      let totalTx = 0;
      let totalErrors = 0;
      let totalCritical = 0;
      let totalSuccess = 0;
      let selectedLockedCount = 0;
      let selectedErrorUsersCount = 0;
      let selectedSuccessUsersCount = 0;
      const codesSummary = {};
      const uniqueIps = new Set();
      const uniqueNodes = new Set();

      targetUsers.forEach(u => {
        const uStat = this.cachedStats[u];
        if (uStat) {
          totalTx += uStat.totalEvents;
          totalErrors += uStat.errors;
          totalCritical += uStat.criticals;
          totalSuccess += uStat.successes;
          if (uStat.isLocked) selectedLockedCount++;
          if (uStat.errors > 0) selectedErrorUsersCount++;
          else selectedSuccessUsersCount++;
          Array.from(uStat.ips).forEach(ip => uniqueIps.add(ip));
          Array.from(uStat.nodes).forEach(n => uniqueNodes.add(n));
          Object.entries(uStat.codes).forEach(([c, cnt]) => {
            codesSummary[c] = (codesSummary[c] || 0) + cnt;
          });
        }
      });

      const successRate = totalTx > 0 ? ((totalSuccess / totalTx) * 100).toFixed(1) : '100';
      const userSuccessRate = targetUsers.length > 0 ? ((selectedSuccessUsersCount / targetUsers.length) * 100).toFixed(1) : '100';

      // 1. Filas del Censo de Usuarios (top 300 en vista imprimible para máxima fluidez PDF/DOCX; 100% en CSV)
      let userRowsHtml = '';
      const sortedUsers = targetUsers.map(u => this.cachedStats[u] || { username: u, totalEvents: 0, errors: 0, successes: 0, isLocked: false, codes: {}, ips: new Set(), lastTimestamp: '-' })
                                     .sort((a, b) => (b.isLocked ? 1 : 0) - (a.isLocked ? 1 : 0) || b.errors - a.errors || b.totalEvents - a.totalEvents);

      const printableUsers = sortedUsers.slice(0, 300);
      printableUsers.forEach((u, idx) => {
        const errPct = u.totalEvents > 0 ? ((u.errors / u.totalEvents) * 100).toFixed(1) : '0';
        let statusBadge = '';
        if (u.isLocked) {
          statusBadge = '<span style="background:#ffe4e6; color:#e11d48; border:1px solid #fda4af; padding:2px 8px; border-radius:12px; font-weight:800; font-size:0.7rem;">🚨 BLOQUEADO</span>';
        } else if (u.errors > 0) {
          statusBadge = `<span style="background:#fee2e2; color:#b91c1c; border:1px solid #fca5a5; padding:2px 8px; border-radius:12px; font-weight:700; font-size:0.7rem;">⚠️ CON FALLAS (${errPct}%)</span>`;
        } else {
          statusBadge = '<span style="background:#dcfce7; color:#15803d; border:1px solid #86efac; padding:2px 8px; border-radius:12px; font-weight:700; font-size:0.7rem;">✅ 100% EXITOSO</span>';
        }

        const topCodes = Object.entries(u.codes).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([c, n]) => `<span style="background:#f1f5f9; color:#0f172a; border:1px solid #cbd5e1; padding:1px 5px; border-radius:4px; font-family:monospace; font-size:0.68rem;">${escapeHtml(c)} (${n})</span>`).join(' ');
        const ipsStr = Array.from(u.ips).join(', ') || 'Red Interna';

        userRowsHtml += `
          <tr style="border-bottom:1px solid #e2e8f0; background:${idx % 2 === 0 ? '#fff' : '#f8fafc'};">
            <td style="padding:8px 10px; font-family:'JetBrains Mono', monospace; font-weight:bold; color:#0284c7;">${escapeHtml(u.username)}</td>
            <td style="padding:8px 10px; text-align:center; font-weight:700;">${u.totalEvents.toLocaleString()}</td>
            <td style="padding:8px 10px; text-align:center; color:#15803d; font-weight:700;">${u.successes.toLocaleString()}</td>
            <td style="padding:8px 10px; text-align:center; color:${u.errors > 0 ? '#b91c1c' : '#64748b'}; font-weight:700;">${u.errors.toLocaleString()}</td>
            <td style="padding:8px 10px; text-align:center;">${statusBadge}</td>
            <td style="padding:8px 10px; font-size:0.72rem;">${topCodes || '<span style="color:#94a3b8;">Sin códigos de error</span>'}</td>
            <td style="padding:8px 10px; font-size:0.72rem; color:#475569;">${escapeHtml(ipsStr)}</td>
          </tr>
        `;
      });

      // 2. Filas de Códigos y Diagnóstico Oficial
      let codesRowsHtml = '';
      const sortedCodes = Object.entries(codesSummary).sort((a, b) => b[1] - a[1]);
      sortedCodes.forEach(([code, count], idx) => {
        let diag = { title: code, meaning: 'Evento transaccional registrado', severity: 'INFO', rootCause: 'Flujo estándar de autenticación', remediation: 'Operación nominal' };
        if (window.knowledgeBaseEngine) {
          diag = window.knowledgeBaseEngine.diagnoseLog('', code);
        }
        const bDiag = window.getBilingualDiagnosticGlobal ? window.getBilingualDiagnosticGlobal(diag, code, diag.category, isEn) : diag;
        const isAud = code.startsWith('AUD');
        const isErr = diag.severity === 'CRITICAL' || diag.severity === 'ERROR';

        codesRowsHtml += `
          <tr style="border-bottom:1px solid #e2e8f0; background:${idx % 2 === 0 ? '#fff' : '#f8fafc'};">
            <td style="padding:8px 10px; font-family:'JetBrains Mono', monospace; font-weight:bold; color:${isAud ? '#0d9488' : (isErr ? '#dc2626' : '#0284c7')};">${escapeHtml(code)}</td>
            <td style="padding:8px 10px; text-align:center; font-weight:bold;">${count.toLocaleString()}</td>
            <td style="padding:8px 10px;">
              <span style="background:${isErr ? '#fee2e2' : (isAud ? '#ccfbf1' : '#e0f2fe')}; color:${isErr ? '#b91c1c' : (isAud ? '#0f766e' : '#0369a1')}; padding:2px 8px; border-radius:10px; font-weight:800; font-size:0.68rem;">${escapeHtml(diag.severity || 'INFO')}</span>
            </td>
            <td style="padding:8px 10px;">
              <strong>${escapeHtml(bDiag.title || code)}</strong><br>
              <span style="font-size:0.72rem; color:#475569;">${escapeHtml(bDiag.meaning || '')}</span>
            </td>
            <td style="padding:8px 10px; font-size:0.72rem; color:#047857; white-space:pre-line;">
              ${escapeHtml(bDiag.remediation || diag.governanceControl || (isEn ? 'Nominal operation / No corrective action required' : 'No requiere acción correctiva'))}
            </td>
          </tr>
        `;
      });

      // 3. Filas del Registro Forense de Eventos
      let eventRowsHtml = '';
      const displayEvents = userLogs.slice(0, 100); // Muestra de los primeros 100 eventos para agilidad visual
      displayEvents.forEach((l, idx) => {
        const lvl = (l.level || 'INFO').toUpperCase();
        const code = l.code || l.entrustCode || 'SYS-EVENT';
        const isErr = lvl === 'CRITICAL' || lvl === 'ERROR';
        const isAud = String(code).startsWith('AUD');

        eventRowsHtml += `
          <tr style="border-bottom:1px solid #e2e8f0; background:${idx % 2 === 0 ? '#fff' : '#f8fafc'}; font-size:0.74rem;">
            <td style="padding:6px 8px; font-family:monospace; color:#475569; white-space:nowrap;">${escapeHtml(l.timestamp || '-')}</td>
            <td style="padding:6px 8px; font-family:monospace; font-weight:bold; color:#0284c7;">${escapeHtml(l.user || l.usuario || l.username || '-')}</td>
            <td style="padding:6px 8px; font-family:monospace; font-weight:bold; color:${isAud ? '#0d9488' : (isErr ? '#dc2626' : '#334155')};">${escapeHtml(code)}</td>
            <td style="padding:6px 8px; text-align:center;">
              <span style="background:${isErr ? '#fee2e2' : '#e0f2fe'}; color:${isErr ? '#b91c1c' : '#0369a1'}; padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:bold;">${escapeHtml(lvl)}</span>
            </td>
            <td style="padding:6px 8px; color:#334155; max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(l.message || l.raw || '')}</td>
            <td style="padding:6px 8px; font-size:0.7rem; color:#64748b;">${escapeHtml(l.ip || '-')}</td>
          </tr>
        `;
      });

      const reportHtml = `
        <div id="user-trace-printable-document" style="font-family:'Inter', system-ui, sans-serif; color:#0f172a; line-height:1.5; padding:10px;">
          
          <!-- ENCABEZADO OFICIAL CORPORATIVO -->
          <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:3px solid #0a3d6d; padding-bottom:14px; margin-bottom:20px;">
            <div style="display:flex; align-items:center; gap:12px;">
              <div style="background:#0a3d6d; color:#fff; width:48px; height:48px; border-radius:6px; display:flex; align-items:center; justify-content:center; font-weight:900; font-size:22px; position:relative; box-shadow:0 2px 8px rgba(10,61,109,0.3);">
                <div style="position:absolute; top:-4px; left:8px; width:10px; height:8px; background:#e11d48; border-radius:1px;"></div>
                IT
              </div>
              <div>
                <div style="font-size:1.3rem; font-weight:900; color:#0a3d6d; letter-spacing:0.5px;">IT SERVICIOS DE VENEZUELA, S.A.</div>
                <div style="font-size:0.75rem; color:#475569; font-weight:600;">CONSULTORÍA ESPECIALIZADA EN SEGURIDAD DE LA IDENTIDAD &amp; INFRAESTRUCTURA ENTRUST</div>
              </div>
            </div>
            <div style="text-align:right;">
              <span style="background:rgba(2,132,199,0.12); color:#0284c7; border:1px solid #0284c7; font-weight:800; font-size:0.72rem; padding:3px 10px; border-radius:12px; display:inline-block; margin-bottom:4px;">CENSO &amp; TRAZABILIDAD OFICIAL</span>
              <div style="font-size:0.75rem; color:#64748b;">Ref: <strong style="color:#0f172a;">EXP-USER-CENSUS-${Date.now().toString().slice(-6)}</strong></div>
            </div>
          </div>

          <!-- TÍTULO Y METADATOS DEL INFORME -->
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-left:5px solid #0284c7; padding:16px 20px; border-radius:8px; margin-bottom:24px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
              <div>
                <h1 style="font-size:1.35rem; font-weight:800; color:#0a3d6d; margin:0 0 6px 0;">INFORME DE TRAZABILIDAD, SEGURIDAD &amp; CENSO DE USUARIOS</h1>
                <div style="font-size:0.82rem; color:#334155;">Radiografía integral de comportamiento de identidades, usuarios con fallas, bloqueos y registros exitosos</div>
              </div>
              <div style="font-size:0.78rem; text-align:right; color:#475569;">
                <div><strong>Entorno / Cliente:</strong> ${escapeHtml(clientLabel)}</div>
                <div><strong>Ambiente de Operación:</strong> <span style="font-weight:700; color:${(window.state?.activeEnvironment === 'PROD' || !window.state?.activeEnvironment) ? '#15803d' : (window.state?.activeEnvironment === 'QA' ? '#b45309' : '#0284c7')};">${window.state?.activeEnvironment === 'PROD' ? '🟢 Producción (PROD)' : (window.state?.activeEnvironment === 'QA' ? '🟡 Pruebas / QA (STAGING)' : '🔵 Desarrollo (DEV)')}</span></div>
                <div><strong>Plataforma &amp; Versión:</strong> ${escapeHtml(clientVersion)}</div>
                <div><strong>Fecha de Emisión:</strong> ${nowFormatted}</div>
                <div><strong>Auditor Responsable:</strong> ${(typeof window.getActiveEngineerGlobal === 'function') ? escapeHtml(window.getActiveEngineerGlobal().signature || window.getActiveEngineerGlobal().name) : 'Tomás Acosta'} (${(typeof window.getActiveEngineerGlobal === 'function') ? escapeHtml(window.getActiveEngineerGlobal().organization || 'IT Servicios de Venezuela') : 'IT Servicios de Venezuela'})</div>
              </div>
            </div>
          </div>

          <!-- 1. RESUMEN EJECUTIVO (KPIs GLOBALES DEL CENSO) -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:14px;">1. RADIOGRAFÍA Y ESTADÍSTICAS GLOBALES DEL CENSO DE USUARIOS</h2>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:12px;">
              
              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #0284c7; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Total Usuarios</div>
                <div style="font-size:1.6rem; font-weight:800; color:#0284c7; font-family:'JetBrains Mono', monospace; margin:4px 0;">${targetUsers.length.toLocaleString()}</div>
                <div style="font-size:0.68rem; color:#64748b;">Identidades evaluadas</div>
              </div>

              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #10b981; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Usuarios 100% Exitosos</div>
                <div style="font-size:1.6rem; font-weight:800; color:#10b981; font-family:'JetBrains Mono', monospace; margin:4px 0;">${selectedSuccessUsersCount.toLocaleString()}</div>
                <div style="font-size:0.68rem; color:#10b981; font-weight:bold;">${userSuccessRate}% del censo</div>
              </div>

              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #ef4444; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Usuarios con Fallas</div>
                <div style="font-size:1.6rem; font-weight:800; color:#ef4444; font-family:'JetBrains Mono', monospace; margin:4px 0;">${selectedErrorUsersCount.toLocaleString()}</div>
                <div style="font-size:0.68rem; color:#ef4444; font-weight:bold;">${totalErrors.toLocaleString()} errores totales</div>
              </div>

              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #e11d48; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Usuarios Bloqueados</div>
                <div style="font-size:1.6rem; font-weight:800; color:#e11d48; font-family:'JetBrains Mono', monospace; margin:4px 0;">${selectedLockedCount}</div>
                <div style="font-size:0.68rem; color:#64748b;">Políticas de bloqueo</div>
              </div>

              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #0a3d6d; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Total Transacciones</div>
                <div style="font-size:1.6rem; font-weight:800; color:#0a3d6d; font-family:'JetBrains Mono', monospace; margin:4px 0;">${totalTx.toLocaleString()}</div>
                <div style="font-size:0.68rem; color:#64748b;">${successRate}% ratio global</div>
              </div>

            </div>
          </div>

          <!-- 2. CENSO Y ESTADO DETALLADO DE TODOS LOS USUARIOS -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:12px;">2. CENSO Y ESTADO DE SEGURIDAD POR USUARIO (${targetUsers.length} Identidades)</h2>
            <div style="overflow-x:auto;">
              <table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.78rem; background:#fff; border:1px solid #cbd5e1; border-radius:6px;">
                <thead>
                  <tr style="background:#0a3d6d; color:#fff; text-align:left;">
                    <th style="padding:8px 10px;">Usuario / Identidad</th>
                    <th style="padding:8px 10px; text-align:center;">Total Txs</th>
                    <th style="padding:8px 10px; text-align:center;">Éxitos</th>
                    <th style="padding:8px 10px; text-align:center;">Fallas</th>
                    <th style="padding:8px 10px; text-align:center;">Estado de Seguridad</th>
                    <th style="padding:8px 10px;">Códigos Entrust Asociados</th>
                    <th style="padding:8px 10px;">IPs de Origen</th>
                  </tr>
                </thead>
                <tbody>
                  ${userRowsHtml}
                </tbody>
              </table>
            </div>
          </div>

          <!-- 3. MATRIZ DE CÓDIGOS DE ERROR & AUDITORÍA ENTRUST -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:12px;">3. DIAGNÓSTICO TÉCNICO OFICIAL DE CÓDIGOS DETECTADOS</h2>
            <div style="overflow-x:auto;">
              <table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.78rem; background:#fff; border:1px solid #cbd5e1; border-radius:6px;">
                <thead>
                  <tr style="background:#0a3d6d; color:#fff; text-align:left;">
                    <th style="padding:8px 10px;">Código Entrust</th>
                    <th style="padding:8px 10px; text-align:center;">Frecuencia</th>
                    <th style="padding:8px 10px;">Severidad</th>
                    <th style="padding:8px 10px;">Diagnóstico &amp; Significado Oficial</th>
                    <th style="padding:8px 10px;">Acción de Control / Remediación</th>
                  </tr>
                </thead>
                <tbody>
                  ${codesRowsHtml || '<tr><td colspan="5" style="padding:10px; text-align:center; color:#64748b;">No se detectaron códigos de excepción en la muestra.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>

          <!-- 4. LÍNEA DE TIEMPO FORENSE DE TRANSACCIONES AUDITADAS -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:12px;">4. CRONOLOGÍA DETALLADA DE TRANSACCIONES Y EVENTOS (Muestra de Trazas)</h2>
            <div style="overflow-x:auto;">
              <table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.74rem; background:#fff; border:1px solid #cbd5e1; border-radius:6px;">
                <thead>
                  <tr style="background:#0a3d6d; color:#fff; text-align:left;">
                    <th style="padding:6px 8px;">Fecha / Hora</th>
                    <th style="padding:6px 8px;">Usuario</th>
                    <th style="padding:6px 8px;">Código</th>
                    <th style="padding:6px 8px; text-align:center;">Nivel</th>
                    <th style="padding:6px 8px;">Mensaje / Detalle de la Transacción</th>
                    <th style="padding:6px 8px;">IP Origen</th>
                  </tr>
                </thead>
                <tbody>
                  ${eventRowsHtml || '<tr><td colspan="6" style="padding:10px; text-align:center; color:#64748b;">No hay eventos registrados en la sesión.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>

          <!-- DICTAMEN DE CIERRE Y FIRMA -->
          <div style="margin-top:30px; border-top:2px solid #cbd5e1; padding-top:16px; display:flex; justify-content:space-between; align-items:flex-end;">
            <div>
              <div style="font-size:0.8rem; font-weight:800; color:#0a3d6d;">DICTAMEN TÉCNICO PERICIAL CONCLUIDO</div>
              <div style="font-size:0.72rem; color:#64748b;">Informe generado automáticamente bajo estándares de auditoría Entrust IdentityGuard &amp; IDaaS Cloud.</div>
            </div>
            <div style="text-align:right;">
              <div style="font-size:0.82rem; font-weight:bold; color:#0f172a;">${(typeof window.getActiveEngineerGlobal === 'function') ? escapeHtml(window.getActiveEngineerGlobal().signature || window.getActiveEngineerGlobal().name) : 'Tomás Acosta'}</div>
              <div style="font-size:0.72rem; color:#475569;">${(typeof window.getActiveEngineerGlobal === 'function') ? escapeHtml(window.getActiveEngineerGlobal().title || 'Especialista de Seguridad e Infraestructura Entrust') : 'Especialista de Seguridad e Infraestructura Entrust'}</div>
              <div style="font-size:0.72rem; color:#0284c7; font-weight:bold;">${(typeof window.getActiveEngineerGlobal === 'function') ? escapeHtml(window.getActiveEngineerGlobal().organization || 'IT Servicios de Venezuela, S.A.') : 'IT Servicios de Venezuela, S.A.'}</div>
            </div>
          </div>

        </div>
      `;

      container.innerHTML = reportHtml;
    },

    downloadPdf() {
      const el = document.getElementById('user-trace-printable-document');
      if (!el) {
        alert('Por favor selecciona al menos un usuario para generar el informe.');
        return;
      }

      const activeClient = this.getClientProfile();
      const clientLabel = activeClient ? (activeClient.name || 'Entrust General') : 'Entrust General';
      const clientVersion = activeClient ? `${activeClient.platform || 'IdentityGuard'} ${activeClient.version || 'Release 12.0'}` : 'Entrust IdentityGuard';
      const dateStamp = new Date().toLocaleDateString('es-ES');
      const filename = `Informe_Trazabilidad_Usuarios_${clientLabel.replace(/\s+/g, '_')}_${Date.now()}.pdf`;

      // Prevenir cortes de filas en tablas
      const tables = el.querySelectorAll('table, tr, td, th, .report-card, .metric-card, .avoid-break');
      tables.forEach(node => {
        node.style.pageBreakInside = 'avoid';
        node.style.breakInside = 'avoid';
      });

      if (window.html2pdf) {
        const opt = {
          margin: [12, 10, 14, 10],
          filename: filename,
          image: { type: 'jpeg', quality: 0.98 },
          html2canvas: { scale: 2, useCORS: true, logging: false, scrollY: 0 },
          jsPDF: { unit: 'mm', format: 'letter', orientation: 'portrait', compress: true },
          pagebreak: { 
            mode: ['avoid-all', 'css', 'legacy'], 
            avoid: ['tr', 'th', 'td', 'h1', 'h2', 'h3', 'h4', '.report-card', '.metric-card', '.avoid-break', 'div[style*="border"]'] 
          }
        };

        window.html2pdf().set(opt).from(el).toPdf().get('pdf').then(function(pdf) {
          const totalPages = pdf.internal.getNumberOfPages();
          const pageWidth = pdf.internal.pageSize.getWidth();
          const pageHeight = pdf.internal.pageSize.getHeight();

          for (let i = 1; i <= totalPages; i++) {
            pdf.setPage(i);
            
            if (i > 1) {
              pdf.setFontSize(7.5);
              pdf.setTextColor(148, 163, 184);
              pdf.text(`IT SERVICIOS DE VENEZUELA, S.A. | Trazabilidad de Usuario — ${clientLabel} (${clientVersion})`, 10, 7);
              pdf.setDrawColor(226, 232, 240);
              pdf.line(10, 8.5, pageWidth - 10, 8.5);
            }

            pdf.setDrawColor(226, 232, 240);
            pdf.line(10, pageHeight - 9, pageWidth - 10, pageHeight - 9);
            pdf.setFontSize(7.5);
            pdf.setTextColor(100, 116, 139);
            pdf.text(`IT Servicios de Venezuela, S.A. | Trazabilidad de Seguridad | ${clientLabel} (${clientVersion}) | ${dateStamp}`, 10, pageHeight - 5);
            pdf.text(`Página ${i} de ${totalPages}`, pageWidth - 28, pageHeight - 5);
          }
        }).save();
      } else {
        window.print();
      }
    },

    downloadDocx() {
      const el = document.getElementById('user-trace-printable-document');
      if (!el) return;

      const activeClient = this.getClientProfile();
      const filename = `Informe_Trazabilidad_Usuarios_${(activeClient.name || 'Entrust').replace(/\s+/g, '_')}_${Date.now()}.doc`;

      const header = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'><head><meta charset='utf-8'><title>Informe de Trazabilidad de Usuarios</title><style>body { font-family: Calibri, sans-serif; font-size: 11pt; color: #1e293b; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #94a3b8; padding: 6px; } th { background-color: #0a3d6d; color: #ffffff; }</style></head><body>`;
      const footer = "</body></html>";
      const sourceHTML = header + el.innerHTML + footer;

      const blob = new Blob(['\ufeff' + sourceHTML], { type: 'application/msword' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    },

    downloadCsv() {
      const activeClient = this.getClientProfile();
      const filename = `Censo_Usuarios_Trazabilidad_${(activeClient.name || 'Entrust').replace(/\s+/g, '_')}_${Date.now()}.csv`;

      // Exportar todos los usuarios seleccionados o el censo completo si no hay filtro
      const userKeys = this.selectedUsers.size > 0 ? Array.from(this.selectedUsers) : Object.keys(this.cachedStats);
      if (userKeys.length === 0) {
        alert('⚠️ No hay usuarios identificados en la muestra para exportar.');
        return;
      }

      let csv = 'Usuario,Total_Interacciones,Exitos,Fallas,Porcentaje_Falla,Estado_Seguridad,Patron_Comportamiento,Secuencia_Solicitudes,Primera_Actividad,Ultima_Actividad,IPs,Nodos,Codigos_e_Interacciones,Causa_Raiz_Forense\n';
      
      userKeys.forEach(key => {
        const u = this.cachedStats[key];
        if (!u) return;
        const errPct = u.totalEvents > 0 ? ((u.errors / u.totalEvents) * 100).toFixed(1) : '0';
        const stateStr = u.isLocked ? 'BLOQUEADO' : (u.errors > 0 ? 'CON_FALLAS' : 'EXITOSO');
        const patCat = (u.patternCategory || 'Operación Nominal').replace(/"/g, '""');
        const patSeq = (u.compressedPattern || 'N/A').replace(/"/g, '""');
        const ipsStr = Array.from(u.ips || []).join('; ');
        const nodesStr = Array.from(u.nodes || []).join('; ');
        const codesStr = Object.entries(u.codes || {}).map(([c, n]) => `${c}(${n})`).join('; ');
        
        let rootCauseDesc = u.rootCause || 'Operación Nominal';
        if (u.isLocked && !u.rootCause) rootCauseDesc = 'Superado umbral de intentos fallidos / Bloqueo preventivo';
        else if (u.errors > 0 && !u.rootCause) rootCauseDesc = 'Rechazo de credenciales o conflicto de autenticación';

        csv += `"${u.username}",${u.totalEvents},${u.successes},${u.errors},${errPct}%,"${stateStr}","${patCat}","${patSeq}","${u.firstTimestamp || ''}","${u.lastTimestamp || ''}","${ipsStr}","${nodesStr}","${codesStr}","${rootCauseDesc.replace(/"/g, '""')}"\n`;
      });

      const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    copyReportText() {
      const el = document.getElementById('user-trace-printable-document');
      if (!el) return;

      const text = el.innerText;
      navigator.clipboard.writeText(text).then(() => {
        alert('📋 Contenido del Informe copiado al portapapeles con éxito.');
      }).catch(() => {
        alert('No se pudo copiar automáticamente. Puedes seleccionar el texto y copiarlo manualmente.');
      });
    },

    /* ==========================================================================
       ESPACIO DE TRABAJO PRINCIPAL DEL CENSO, PATRONES POR USUARIO, MATRIZ DE
       CÓDIGOS, SALUD DE BASE DE DATOS Y ANÁLISIS POST-MORTEM (BUILD 545)
       ========================================================================== */
    activeTabFilter: 'all',
    activeTabSelectedUser: null,
    activeSubView: 'users', // 'users' | 'patterns' | 'codes' | 'dbhealth' | 'postmortem'
    activeCodeFamilyFilter: 'ALL',
    forensicMatrixData: null,
    isLoadingMatrix: false,
    sqliteUserEventsCache: {},

    async fetchForensicMatrix(forceRefresh = false) {
      if (this.isLoadingMatrix) return this.forensicMatrixData;
      this.isLoadingMatrix = true;
      try {
        const activeClient = this.getClientProfile();
        const clientParam = encodeURIComponent(activeClient?.name || '');
        const refreshParam = forceRefresh ? '&refresh=1' : '';
        const res = await fetch(`/api/forensic-matrix?client=${clientParam}${refreshParam}`);
        if (res.ok) {
          const data = await res.json();
          if (data && data.status === 'ready') {
            this.forensicMatrixData = data;
          } else if (data && data.status === 'empty') {
            this.forensicMatrixData = null;
          }
        }
      } catch (e) {
        console.warn('Info: Modo en memoria local activo para matriz forense:', e);
      } finally {
        this.isLoadingMatrix = false;
      }
      return this.forensicMatrixData;
    },

    buildLocalForensicFallback() {
      const allUsers = Object.values(this.cachedStats);
      const logs = this.getAllLogs();

      // 1. Build Pattern Clusters from cachedStats
      const clusterMap = {};
      allUsers.forEach(u => {
        const sig = u.normalizedSignature || 'OPERACIÓN_UNICA';
        const cat = u.patternCategory || '✅ Operación Nominal Limpia (100% Éxito)';
        const key = `${cat}||${sig}`;
        if (!clusterMap[key]) {
          clusterMap[key] = {
            signature: sig,
            category: cat,
            rootCause: u.rootCause || 'Flujo transaccional estándar.',
            userCount: 0,
            totalEvents: 0,
            errorEvents: 0,
            sampleUsers: []
          };
        }
        clusterMap[key].userCount++;
        clusterMap[key].totalEvents += u.totalEvents;
        clusterMap[key].errorEvents += u.errors;
        if (clusterMap[key].sampleUsers.length < 30) {
          clusterMap[key].sampleUsers.push({
            user: u.username,
            total: u.totalEvents,
            errors: u.errors,
            success: u.successes
          });
        }
      });
      const patternClusters = Object.values(clusterMap).sort((a, b) => (b.errorEvents - a.errorEvents) || (b.userCount - a.userCount));

      // 2. Build Code & Audit Pattern Matrix from logs & cachedStats
      const codeMap = {};
      allUsers.forEach(u => {
        Object.entries(u.codesDetail || {}).forEach(([code, det]) => {
          if (!codeMap[code]) {
            let kind = 'SYSTEM_EVENT';
            if (/^520\d{4}$/.test(code)) kind = 'ERROR_520';
            else if (/^AUD\d+/i.test(code) || /AUDIT/i.test(code)) kind = 'AUDIT_AUD';
            else if (/^ORA-/i.test(code) || /SQL|JDBC/i.test(code)) kind = 'DATABASE_ORA';
            else if (/bulkidentityguard|migration|idaas/i.test(code)) kind = 'IDAAS_MIGRATION';
            codeMap[code] = {
              code,
              kind,
              totalInteractions: 0,
              failCount: 0,
              successCount: 0,
              systemOnlyCount: 0,
              usersDict: {}
            };
          }
          const cEntry = codeMap[code];
          cEntry.totalInteractions += det.total;
          cEntry.failCount += det.errors;
          cEntry.successCount += det.success;
          cEntry.usersDict[u.username] = {
            user: u.username,
            count: det.total,
            errors: det.errors,
            success: det.success,
            lastSeen: u.lastTimestamp || ''
          };
        });
      });

      const codeMatrix = Object.values(codeMap).map(c => {
        const usersArr = Object.values(c.usersDict).sort((a, b) => b.count - a.count);
        return {
          code: c.code,
          kind: c.kind,
          totalInteractions: c.totalInteractions,
          failCount: c.failCount,
          successCount: c.successCount,
          systemOnlyCount: c.systemOnlyCount,
          uniqueUsersCount: usersArr.length,
          users: usersArr
        };
      }).sort((a, b) => (b.failCount - a.failCount) || (b.totalInteractions - a.totalInteractions));

      // 3. Build DB Health from in-memory logs
      let ora01555 = 0, ora00001 = 0, ora01000 = 0, oraNet = 0, oraLock = 0, jdbcBlob = 0, sqlExc = 0, txQueue = 0;
      const dbSamples = [];
      logs.forEach((l, i) => {
        const txt = `${l.entrustCode || ''} ${l.message || ''} ${l.raw || ''}`;
        if (/ORA-01555|snapshot too old/i.test(txt)) ora01555++;
        if (/ORA-00001|unique constraint/i.test(txt)) ora00001++;
        if (/ORA-01000|ORA-02391|open cursors/i.test(txt)) ora01000++;
        if (/ORA-03113|ORA-03114|ORA-12170|ORA-12514/i.test(txt)) oraNet++;
        if (/ORA-00060|ORA-00054|deadlock/i.test(txt)) oraLock++;
        if (/JdbcCardRepository|BlobAccess/i.test(txt)) jdbcBlob++;
        if (/SQLException|SQL_EXCEPTION|HikariPool|Connection timed out/i.test(txt)) sqlExc++;
        if (/TransactionQueue/i.test(txt)) txQueue++;
        if (dbSamples.length < 12 && /ORA-|SQLException|JdbcCardRepository|BlobAccess|TransactionQueue/i.test(txt)) {
          dbSamples.push({
            lineNum: l.lineNum || (i + 1),
            timestamp: l.timestamp || '',
            user: l.user || 'system',
            code: l.entrustCode || 'DB_EVENT',
            message: (l.message || l.raw || '').slice(0, 200)
          });
        }
      });
      const totalDbInc = ora01555 + ora00001 + ora01000 + oraNet + oraLock + jdbcBlob + sqlExc + txQueue;

      const dbHealth = {
        status: (ora01555 + ora00001 + ora01000 + oraNet + oraLock + jdbcBlob + sqlExc) > 0 ? 'CRITICAL' : (txQueue > 0 ? 'WARNING' : 'HEALTHY'),
        totalDbIncidents: totalDbInc,
        indicators: [
          { code: 'ORA-01555 (Snapshot Too Old)', count: ora01555, severity: ora01555 > 0 ? 'CRÍTICO' : 'OK', diagnosis: ora01555 > 0 ? 'Agotamiento de UNDO Tablespace en Oracle durante lecturas largas de BLOB/Grid.' : 'Sin errores de consistencia de lectura (UNDO saludable).', remediation: 'Incrementar UNDO_RETENTION (>= 3600s) y ampliar UNDO Tablespace.' },
          { code: 'JdbcCardRepository / BlobAccess', count: jdbcBlob, severity: jdbcBlob > 0 ? 'CRÍTICO' : 'OK', diagnosis: jdbcBlob > 0 ? 'Fallo al deserializar o leer tarjetas Grid (BLOB) desde la base de datos.' : 'Lectura de objetos BLOB / Grid Cards sin anomalías.', remediation: 'Verificar integridad de columnas BLOB en tabla de tarjetas.' },
          { code: 'SQLException / Pool JDBC', count: sqlExc, severity: sqlExc > 0 ? 'ALTO' : 'OK', diagnosis: sqlExc > 0 ? 'Excepciones SQL o agotamiento del pool de conexiones JDBC.' : 'Pool de conexiones JDBC operando dentro de parámetros nominales.', remediation: 'Revisar maxPoolSize, connectionTimeout y latencia de red hacia la BD.' },
          { code: 'ORA-00001 (Unique Constraint)', count: ora00001, severity: ora00001 > 0 ? 'MEDIO' : 'OK', diagnosis: ora00001 > 0 ? 'Intento de inserción duplicada de llave única.' : 'Sin violaciones de unicidad detectadas.', remediation: 'Validar pre-existencia del registro antes de re-ejecutar lotes.' },
          { code: 'ORA-01000 / ORA-02391 (Cursores / Sesiones)', count: ora01000, severity: ora01000 > 0 ? 'ALTO' : 'OK', diagnosis: ora01000 > 0 ? 'Límite de cursores abiertos o sesiones excedido.' : 'Consumo de cursores y sesiones dentro del límite.', remediation: 'Ajustar OPEN_CURSORS en Oracle.' },
          { code: 'ORA-03113 / ORA-12170 (Corte de Red TNS)', count: oraNet, severity: oraNet > 0 ? 'CRÍTICO' : 'OK', diagnosis: oraNet > 0 ? 'Desconexión abrupta del canal TCP/TNS con Oracle.' : 'Enlace de red hacia la base de datos estable.', remediation: 'Habilitar SQLNET.EXPIRE_TIME y validación testOnBorrow.' },
          { code: 'ORA-00060 / ORA-00054 (Deadlock / Lock)', count: oraLock, severity: oraLock > 0 ? 'ALTO' : 'OK', diagnosis: oraLock > 0 ? 'Bloqueo mutuo (Deadlock) por transacciones concurrentes.' : 'Sin bloqueos transaccionales (Deadlocks) en base de datos.', remediation: 'Serializar actualizaciones por usuario en procesos batch.' },
          { code: 'TransactionQueue.API (Cola Asíncrona)', count: txQueue, severity: txQueue > 0 ? 'ADVERTENCIA' : 'OK', diagnosis: txQueue > 0 ? 'Retraso en el vaciado asíncrono hacia la base de datos.' : 'Cola de transacciones de auditoría sin retrasos.', remediation: 'Revisar IOPS de almacenamiento en tablas de auditoría.' }
        ],
        sqliteEngine: {
          dbFile: 'Modo Memoria del Navegador (Sin archivo .db activo)',
          dbPath: 'RAM Local',
          sizeMb: 0,
          totalRowsIndexed: logs.length,
          totalErrorsIndexed: logs.filter(l => l.level === 'ERROR' || l.level === 'CRITICAL').length,
          journalMode: 'RAM',
          uniqueValidUsers: allUsers.length,
          filteredNoiseTokens: 0,
          filteredNoiseEvents: 0,
          sampleNoiseTokens: []
        },
        evidenceSamples: dbSamples
      };

      const migErrs = codeMatrix.filter(c => c.kind === 'IDAAS_MIGRATION').reduce((a, b) => a + b.failCount, 0);
      const err520 = codeMatrix.filter(c => c.kind === 'ERROR_520').reduce((a, b) => a + b.failCount, 0);
      const audWarns = codeMatrix.filter(c => c.kind === 'AUDIT_AUD').reduce((a, b) => a + b.failCount, 0);
      const totalErrs = logs.filter(l => l.level === 'ERROR' || l.level === 'CRITICAL' || l.level === 'WARN').length;

      const postMortem = {
        startTime: logs[0]?.timestamp || 'N/A',
        endTime: logs[logs.length - 1]?.timestamp || 'N/A',
        peakHours: [],
        primaryVector: totalDbInc > Math.max(migErrs, err520, audWarns) && totalDbInc > 0
          ? 'INFRAESTRUCTURA / BASE DE DATOS (Oracle / JDBC)'
          : (migErrs > 0 && migErrs >= err520 ? 'COLISIÓN DE MIGRACIÓN / APROVISIONAMIENTO (IDaaS / BulkIG)' : 'AUTENTICACIÓN, RETOS Y SEGURIDAD ENTRUST IDENTITYGUARD ONPREMISE [AUD / 520xxx]'),
        executiveVerdict: `Análisis pericial Entrust IdentityGuard OnPremise sobre ${(window.appState?.globalStreamMetrics?.totalLogs || logs.length).toLocaleString()} registros y ${allUsers.length.toLocaleString()} usuarios nominales validados (0 usuarios ficticios). Alertas de Auditoría [AUD6001/AUD6002]: ${audWarns}. Errores 520xxx: ${err520}. Incidentes de Base de Datos: ${totalDbInc}.`,
        breakdown: {
          databaseIncidents: totalDbInc,
          migrationCollisions: migErrs,
          auditAlertsCount: audWarns,
          authentication520Errors: err520,
          otherSystemErrors: Math.max(0, totalErrs - (totalDbInc + migErrs + err520))
        },
        officialPortals: [
          { name: 'Entrust TrustedCare Portal (Knowledge Base & Support Cases)', url: 'https://trustedcare.entrust.com', description: 'Portal oficial de soporte técnico Entrust, boletines de seguridad, parches de IdentityGuard OnPremise y resolución de códigos ORA / 520xxx / AUD.' },
          { name: 'Entrust IdentityGuard Technical Documentation', url: 'https://trustedcare.entrust.com', description: 'Documentación técnica oficial de Entrust IdentityGuard OnPremise: códigos de auditoría AUD, servicios Web Services y matrices de autenticación.' }
        ]
      };

      return { patternClusters, codeMatrix, dbHealth, postMortem };
    },

    async renderTab(containerId, forceRefresh = false) {
      const target = document.getElementById(containerId || 'tab-users-main-container');
      if (!target) return;

      const st = window.appState || window.state;
      const isServerMode = !!(st && st.isServerApi);
      if (!isServerMode) {
        this.forensicMatrixData = null;
      } else if (!this.forensicMatrixData || forceRefresh) {
        target.innerHTML = `
          <div class="glass-card" style="padding:36px; text-align:center; border:1px solid var(--border-color); border-radius:10px;">
            <div style="font-size:2rem; margin-bottom:10px;">🧬</div>
            <div style="font-size:1.05rem; font-weight:800; color:var(--text-main);">Construyendo Matriz Forense de Patrones de Usuario, Códigos y Salud de Base de Datos...</div>
            <div style="font-size:0.82rem; color:var(--text-muted); margin-top:6px;">Consultando motor indexado SQLite y depurando falsos positivos de usuarios...</div>
          </div>
        `;
        await this.fetchForensicMatrix(forceRefresh);
      }

      this.buildUserStats();
      const allUsers = Object.values(this.cachedStats);
      const fm = isServerMode ? this.forensicMatrixData : null;
      const localFallback = this.buildLocalForensicFallback();

      const totalUsers = fm ? (fm.uniqueValidUsers || allUsers.length) : allUsers.length;
      const errorUsers = fm ? (fm.usersWithErrors ?? allUsers.filter(u => u.errors > 0 || u.isLocked).length) : allUsers.filter(u => u.errors > 0 || u.isLocked).length;
      const successUsers = fm ? (fm.usersClean ?? Math.max(0, totalUsers - errorUsers)) : allUsers.filter(u => u.errors === 0 && !u.isLocked).length;
      const lockedUsers = allUsers.filter(u => u.isLocked).length;
      const totalTxs = fm ? (fm.totalLogs || 0) : (st?.globalStreamMetrics?.totalLogs || allUsers.reduce((acc, u) => acc + (u.totalEvents || 0), 0));

      const patternClusters = (fm && fm.patternClusters && fm.patternClusters.length > 0) ? fm.patternClusters : localFallback.patternClusters;
      const codeMatrix = (fm && fm.codeMatrix && fm.codeMatrix.length > 0) ? fm.codeMatrix : localFallback.codeMatrix;
      const dbHealth = (fm && fm.dbHealth) ? fm.dbHealth : localFallback.dbHealth;

      if (!this.activeTabSelectedUser && allUsers.length > 0) {
        const sortedInit = [...allUsers].sort((a, b) => (b.errors - a.errors) || (b.totalEvents - a.totalEvents));
        this.activeTabSelectedUser = sortedInit[0].username;
      }

      const activeClient = this.getClientProfile();
      const clientName = activeClient?.name || (fm && fm.activeDb ? fm.activeDb.replace('_audit.db', '') : 'Entrust General');
      const dbStatusBadge = dbHealth.status === 'CRITICAL'
        ? `<span style="background:rgba(239,68,68,0.15); color:#ef4444; border:1px solid #ef4444; padding:3px 10px; border-radius:999px; font-size:0.72rem; font-weight:800;">🚨 BD CON ALERTAS (${dbHealth.totalDbIncidents})</span>`
        : (dbHealth.status === 'WARNING'
          ? `<span style="background:rgba(245,158,11,0.15); color:#f59e0b; border:1px solid #f59e0b; padding:3px 10px; border-radius:999px; font-size:0.72rem; font-weight:800;">⚠️ BD COLA ASÍNCRONA (${dbHealth.totalDbIncidents})</span>`
          : `<span style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid #10b981; padding:3px 10px; border-radius:999px; font-size:0.72rem; font-weight:800;">✅ BASE DE DATOS SALUDABLE (0 Errores ORA/SQL)</span>`);

      target.innerHTML = `
        <div class="glass-card mb-4" style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px;">
          <!-- Header del Centro Forense -->
          <div class="card-header flex-between" style="border-bottom:1px solid var(--border-color); padding-bottom:14px; margin-bottom:16px; flex-wrap:wrap; gap:12px;">
            <div>
              <div class="card-title text-cyan" style="font-size:1.2rem; font-weight:800; display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                <span>👤</span> Centro Forense: Patrones por Usuario, Matriz de Códigos & Salud de BD
                ${dbStatusBadge}
              </div>
              <div style="font-size:0.78rem; color:var(--text-muted); margin-top:4px; display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                <span>Cliente: <strong>${escapeHtml(clientName)}</strong></span>
                <span>•</span>
                <span>Fuente: <strong>${fm && fm.activeDb ? `SQLite (${escapeHtml(fm.activeDb)} — ${fm.dbSizeMb || 0} MB)` : 'Memoria Activa del Navegador'}</strong></span>
                <span>•</span>
                <a href="https://trustedcare.entrust.com" target="_blank" rel="noopener noreferrer" style="color:#0284c7; font-weight:700; text-decoration:none;">🌐 Portal Oficial Entrust TrustedCare ↗</a>
                <a href="https://docs.trustedauth.com" target="_blank" rel="noopener noreferrer" style="color:#0ea5e9; font-weight:700; text-decoration:none;">📘 Docs TrustedAuth ↗</a>
              </div>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
              <button class="btn btn-primary" onclick="window.UserTraceReport.downloadCsv()" style="background:#0284c7; border:none; font-size:0.78rem; padding:6px 14px; font-weight:700; border-radius:6px; cursor:pointer;" title="Descargar Censo Nominal + Patrones en CSV">
                📥 Exportar Censo & Patrones (.CSV)
              </button>
              <button class="btn" onclick="window.UserTraceReport.openModal()" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); font-size:0.78rem; padding:6px 12px; border-radius:6px; cursor:pointer;" title="Abrir Modal de Expediente Oficial PDF/DOCX">
                📄 Expediente PDF/DOCX
              </button>
              <button class="btn" onclick="window.UserTraceReport.renderTab('tab-users-main-container', true)" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); font-size:0.78rem; padding:6px 12px; border-radius:6px; cursor:pointer;" title="Recalcular matriz forense desde SQLite sin caché">
                🔄 Recalcular Matriz SQLite
              </button>
            </div>
          </div>

          <!-- Tarjetas KPI de Reconciliación Sin Alucinaciones -->
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(185px, 1fr)); gap:12px; margin-bottom:16px;">
            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #0284c7; padding:12px 14px; border-radius:8px;">
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Usuarios Nominales Reales</div>
              <div style="font-size:1.5rem; font-weight:800; color:#0284c7; font-family:'JetBrains Mono', monospace; margin-top:2px;">${totalUsers.toLocaleString()}</div>
              <div style="font-size:0.7rem; color:var(--text-muted); margin-top:2px;">${totalTxs.toLocaleString()} eventos totales analizados</div>
            </div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #8b5cf6; padding:12px 14px; border-radius:8px;">
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Patrones de Flujo Únicos</div>
              <div style="font-size:1.5rem; font-weight:800; color:#8b5cf6; font-family:'JetBrains Mono', monospace; margin-top:2px;">${patternClusters.length.toLocaleString()}</div>
              <div style="font-size:0.7rem; color:var(--text-muted); margin-top:2px;">Secuencias Solicitud 1 ➔ Solicitud N</div>
            </div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #ef4444; padding:12px 14px; border-radius:8px;">
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Usuarios con Errores</div>
              <div style="font-size:1.5rem; font-weight:800; color:#ef4444; font-family:'JetBrains Mono', monospace; margin-top:2px;">${errorUsers.toLocaleString()}</div>
              <div style="font-size:0.7rem; color:#ef4444; font-weight:600; margin-top:2px;">${lockedUsers.toLocaleString()} cuentas con bloqueo detectado</div>
            </div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #10b981; padding:12px 14px; border-radius:8px;">
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Usuarios 100% Exitosos</div>
              <div style="font-size:1.5rem; font-weight:800; color:#10b981; font-family:'JetBrains Mono', monospace; margin-top:2px;">${successUsers.toLocaleString()}</div>
              <div style="font-size:0.7rem; color:#10b981; font-weight:600; margin-top:2px;">${totalUsers > 0 ? ((successUsers / totalUsers) * 100).toFixed(1) : 0}% sin fricción</div>
            </div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #f59e0b; padding:12px 14px; border-radius:8px;">
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Códigos & Patrones AUD</div>
              <div style="font-size:1.5rem; font-weight:800; color:#f59e0b; font-family:'JetBrains Mono', monospace; margin-top:2px;">${codeMatrix.length.toLocaleString()}</div>
              <div style="font-size:0.7rem; color:var(--text-muted); margin-top:2px;">520xxx / AUDxxx / SSH-OS / ORA</div>
            </div>
          </div>

          <!-- Barra de Navegación de Sub-Módulos Forenses -->
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; border-bottom:1px solid var(--border-color); padding-bottom:12px;">
            <button onclick="window.UserTraceReport.switchSubView('users')" style="padding:8px 14px; border-radius:8px; font-size:0.8rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'users' ? '#0284c7' : 'var(--border-color)'}; background:${this.activeSubView === 'users' ? '#0284c7' : 'var(--bg-primary)'}; color:${this.activeSubView === 'users' ? '#fff' : 'var(--text-main)'};">
              👤 1. Censo & Patrón de Solicitudes por Usuario (${allUsers.length})
            </button>
            <button onclick="window.UserTraceReport.switchSubView('patterns')" style="padding:8px 14px; border-radius:8px; font-size:0.8rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'patterns' ? '#8b5cf6' : 'var(--border-color)'}; background:${this.activeSubView === 'patterns' ? '#8b5cf6' : 'var(--bg-primary)'}; color:${this.activeSubView === 'patterns' ? '#fff' : 'var(--text-main)'};">
              🧬 2. Clústeres de Patrones de Comportamiento (${patternClusters.length})
            </button>
            <button onclick="window.UserTraceReport.switchSubView('codes')" style="padding:8px 14px; border-radius:8px; font-size:0.8rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'codes' ? '#f59e0b' : 'var(--border-color)'}; background:${this.activeSubView === 'codes' ? '#f59e0b' : 'var(--bg-primary)'}; color:${this.activeSubView === 'codes' ? '#fff' : 'var(--text-main)'};">
              🔢 3. Matriz de Códigos & Auditoría ➔ Usuarios (${codeMatrix.length})
            </button>
            <button onclick="window.UserTraceReport.switchSubView('dbhealth')" style="padding:8px 14px; border-radius:8px; font-size:0.8rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'dbhealth' ? '#10b981' : 'var(--border-color)'}; background:${this.activeSubView === 'dbhealth' ? '#10b981' : 'var(--bg-primary)'}; color:${this.activeSubView === 'dbhealth' ? '#fff' : 'var(--text-main)'};">
              🗄️ 4. Salud de Base de Datos (Oracle / JDBC / SQLite)
            </button>
            <button onclick="window.UserTraceReport.switchSubView('postmortem')" style="padding:8px 14px; border-radius:8px; font-size:0.8rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'postmortem' ? '#e11d48' : 'var(--border-color)'}; background:${this.activeSubView === 'postmortem' ? '#e11d48' : 'var(--bg-primary)'}; color:${this.activeSubView === 'postmortem' ? '#fff' : 'var(--text-main)'};">
              🕵️ 5. Análisis Forense Post-Mortem & TrustedCare
            </button>
          </div>

          <!-- Contenedor Dinámico del Sub-Módulo Activo -->
          <div id="tab-users-subview-body"></div>
        </div>
      `;

      this.renderActiveSubView();
    },

    switchSubView(viewName, optionalUser = null) {
      this.activeSubView = viewName;
      if (optionalUser) {
        this.activeTabSelectedUser = optionalUser;
      }
      this.renderTab('tab-users-main-container', false);
    },

    renderActiveSubView() {
      const container = document.getElementById('tab-users-subview-body');
      if (!container) return;

      const allUsers = Object.values(this.cachedStats);
      const fm = this.forensicMatrixData;
      const localFallback = this.buildLocalForensicFallback();
      const patternClusters = (fm && fm.patternClusters && fm.patternClusters.length > 0) ? fm.patternClusters : localFallback.patternClusters;
      const codeMatrix = (fm && fm.codeMatrix && fm.codeMatrix.length > 0) ? fm.codeMatrix : localFallback.codeMatrix;
      const dbHealth = (fm && fm.dbHealth) ? fm.dbHealth : localFallback.dbHealth;
      const postMortem = (fm && fm.postMortem) ? fm.postMortem : localFallback.postMortem;

      if (this.activeSubView === 'patterns') {
        this.renderPatternsClusterSubView(container, patternClusters);
        return;
      }
      if (this.activeSubView === 'codes') {
        this.renderCodesMatrixSubView(container, codeMatrix);
        return;
      }
      if (this.activeSubView === 'dbhealth') {
        this.renderDbHealthSubView(container, dbHealth);
        return;
      }
      if (this.activeSubView === 'postmortem') {
        this.renderPostMortemSubView(container, postMortem, dbHealth, codeMatrix, patternClusters);
        return;
      }

      // Default Sub-View 1: Censo & Patrón de Solicitudes por Usuario
      const totalUsers = allUsers.length;
      const errorUsers = allUsers.filter(u => u.errors > 0 || u.isLocked).length;
      const successUsers = allUsers.filter(u => u.errors === 0 && !u.isLocked).length;

      container.innerHTML = `
        <div style="display:grid; grid-template-columns: 350px 1fr; gap:16px; min-height:620px; border:1px solid var(--border-color); border-radius:8px; overflow:hidden; background:var(--bg-secondary);">
          <!-- Columna Izquierda: Buscador & Lista de Usuarios -->
          <div style="background:var(--bg-primary); border-right:1px solid var(--border-color); padding:14px; display:flex; flex-direction:column; gap:10px;">
            <div>
              <label style="font-size:0.78rem; font-weight:700; color:var(--text-muted); display:block; margin-bottom:4px;">🔍 Buscar por Usuario, Cédula o Patrón:</label>
              <input type="text" id="tab-user-search-input" class="form-control" placeholder="Ej: jperez, 1054321, 5202013..." style="font-size:0.8rem; padding:8px 12px; width:100%;" oninput="window.UserTraceReport.filterTabUserList(this.value)">
            </div>

            <div style="display:flex; gap:4px; flex-wrap:wrap;">
              <button class="btn" onclick="window.UserTraceReport.selectTabFilter('all')" id="btn-tab-filter-all" style="background:${this.activeTabFilter === 'all' ? '#0284c7' : 'var(--bg-secondary)'}; color:${this.activeTabFilter === 'all' ? '#fff' : 'var(--text-muted)'}; font-size:0.7rem; font-weight:700; padding:4px 8px; border-radius:4px; border:none; cursor:pointer;">Todos (${totalUsers})</button>
              <button class="btn" onclick="window.UserTraceReport.selectTabFilter('errors')" id="btn-tab-filter-errors" style="background:${this.activeTabFilter === 'errors' ? '#ef4444' : 'rgba(239,68,68,0.12)'}; border:1px solid #ef4444; color:${this.activeTabFilter === 'errors' ? '#fff' : '#ef4444'}; font-size:0.7rem; font-weight:700; padding:4px 8px; border-radius:4px; cursor:pointer;">🚨 Con Fallas (${errorUsers})</button>
              <button class="btn" onclick="window.UserTraceReport.selectTabFilter('success')" id="btn-tab-filter-success" style="background:${this.activeTabFilter === 'success' ? '#10b981' : 'rgba(16,185,129,0.12)'}; border:1px solid #10b981; color:${this.activeTabFilter === 'success' ? '#fff' : '#10b981'}; font-size:0.7rem; font-weight:700; padding:4px 8px; border-radius:4px; cursor:pointer;">✅ Limpios (${successUsers})</button>
            </div>

            <div style="font-size:0.74rem; font-weight:700; color:var(--text-muted); margin-top:2px;">Directorio Nominal (Cero Falsos Positivos):</div>
            <div id="tab-user-items-list" style="flex:1; max-height:520px; overflow-y:auto; display:flex; flex-direction:column; gap:5px; padding-right:4px;"></div>
          </div>

          <!-- Columna Derecha: Expediente & Patrón de Solicitudes del Usuario Activo -->
          <div id="tab-user-detail-pane" style="padding:20px; overflow-y:auto; background:var(--bg-card); display:flex; flex-direction:column; gap:16px;"></div>
        </div>
      `;

      this.renderTabUserList();
      if (allUsers.length > 0) {
        this.renderTabUserDetail(this.activeTabSelectedUser || allUsers[0].username);
      } else {
        const pane = document.getElementById('tab-user-detail-pane');
        if (pane) {
          pane.innerHTML = `<div style="padding:40px; text-align:center; color:var(--text-muted); font-size:0.9rem;">No hay usuarios nominales detectados todavía. Cargue un archivo de log o active una base de datos SQLite en la barra superior.</div>`;
        }
      }
    },

    renderPatternsClusterSubView(container, patternClusters) {
      if (!patternClusters || patternClusters.length === 0) {
        container.innerHTML = `<div style="padding:36px; text-align:center; color:var(--text-muted);">No hay secuencias de solicitudes registradas para agrupar en patrones.</div>`;
        return;
      }

      let rowsHtml = '';
      patternClusters.forEach((cl, idx) => {
        const hasErr = cl.errorEvents > 0;
        const borderCol = hasErr ? '#ef4444' : '#10b981';
        const samplePills = (cl.sampleUsers || []).map(su => `
          <button onclick="window.UserTraceReport.switchSubView('users', '${escapeHtml(su.user)}')" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); border-radius:6px; padding:3px 8px; font-size:0.73rem; font-family:'JetBrains Mono', monospace; cursor:pointer; font-weight:700;" title="Abrir patrón detallado de ${escapeHtml(su.user)}">
            👤 ${escapeHtml(su.user)} <span style="color:${su.errors > 0 ? '#ef4444' : '#10b981'};">(${su.total} reqs / ${su.errors} err)</span>
          </button>
        `).join(' ');

        rowsHtml += `
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid ${borderCol}; border-radius:8px; padding:16px; margin-bottom:12px;">
            <div class="flex-between" style="flex-wrap:wrap; gap:8px; margin-bottom:8px;">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                <span style="background:rgba(139,92,246,0.15); color:#8b5cf6; font-weight:800; font-size:0.74rem; padding:3px 8px; border-radius:4px;">PATRÓN #${idx + 1}</span>
                <span style="font-weight:800; font-size:0.92rem; color:var(--text-main);">${escapeHtml(cl.category)}</span>
              </div>
              <div style="display:flex; gap:10px; align-items:center; font-size:0.78rem; font-family:'JetBrains Mono', monospace;">
                <span style="background:rgba(2,132,199,0.15); color:#0284c7; padding:3px 9px; border-radius:4px; font-weight:800;">👥 ${cl.userCount.toLocaleString()} usuarios</span>
                <span style="background:rgba(15,23,42,0.08); color:var(--text-main); padding:3px 9px; border-radius:4px; font-weight:700;">⚡ ${cl.totalEvents.toLocaleString()} interacciones</span>
                ${hasErr ? `<span style="background:rgba(239,68,68,0.15); color:#ef4444; padding:3px 9px; border-radius:4px; font-weight:800;">🚨 ${cl.errorEvents.toLocaleString()} fallos</span>` : ''}
              </div>
            </div>

            <div style="background:var(--bg-secondary); border:1px solid var(--border-color); padding:10px 12px; border-radius:6px; font-family:'JetBrains Mono', monospace; font-size:0.8rem; color:#0284c7; font-weight:700; margin-bottom:8px; overflow-x:auto;">
              Secuencia Tipo: ${escapeHtml(cl.signature)}
            </div>

            <div style="font-size:0.78rem; color:var(--text-muted); margin-bottom:10px;">
              <strong>Diagnóstico de Comportamiento:</strong> ${escapeHtml(cl.rootCause)}
            </div>

            <div>
              <div style="font-size:0.72rem; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px;">Usuarios Detectados con este Patrón (Clic para abrir expediente):</div>
              <div style="display:flex; flex-wrap:wrap; gap:6px;">${samplePills}</div>
            </div>
          </div>
        `;
      });

      container.innerHTML = `
        <div style="margin-bottom:12px; font-size:0.82rem; color:var(--text-muted);">
          Agrupación automática de usuarios según la secuencia cronológica exacta de sus solicitudes (<strong>Solicitud 1 ➔ Solicitud 2 ➔ ... ➔ Solicitud N</strong>). Haga clic sobre cualquier usuario para inspeccionar su línea de tiempo individual.
        </div>
        ${rowsHtml}
      `;
    },

    filterCodesMatrixFamily(family) {
      this.activeCodeFamilyFilter = family;
      this.renderActiveSubView();
    },

    renderCodesMatrixSubView(container, codeMatrix) {
      const fam = this.activeCodeFamilyFilter || 'ALL';
      const filtered = fam === 'ALL' ? codeMatrix : codeMatrix.filter(c => c.kind === fam);

      const countByKind = (k) => codeMatrix.filter(c => c.kind === k).length;

      let cardsHtml = '';
      if (filtered.length === 0) {
        cardsHtml = `<div style="padding:30px; text-align:center; color:var(--text-muted);">No se detectaron códigos en esta familia para la carga actual.</div>`;
      } else {
        filtered.forEach(item => {
          const diag = window.knowledgeBaseEngine ? window.knowledgeBaseEngine.diagnoseLog(item.code, item.code) : { title: item.code, meaning: '', remediation: '' };
          const isErr = item.failCount > 0 || item.kind === 'ERROR_520' || item.kind === 'DATABASE_ORA' || item.kind === 'IDAAS_MIGRATION';
          const badgeColor = item.kind === 'ERROR_520' ? '#ef4444' : (item.kind === 'AUDIT_AUD' ? '#0284c7' : (item.kind === 'DATABASE_ORA' ? '#e11d48' : (item.kind === 'IDAAS_MIGRATION' ? '#f59e0b' : '#64748b')));

          const allCodeUsers = item.users || [];
          const topCodeUsers = allCodeUsers.slice(0, 60);
          const restCodeUsers = allCodeUsers.slice(60);
          const renderUserPill = (u) => `
            <button onclick="window.UserTraceReport.switchSubView('users', '${escapeHtml(u.user)}')" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); padding:4px 9px; border-radius:6px; font-size:0.73rem; font-family:'JetBrains Mono', monospace; cursor:pointer; display:inline-flex; align-items:center; gap:5px;" title="Ver patrón de solicitudes de ${escapeHtml(u.user)}">
              <strong>${escapeHtml(u.user)}</strong>
              <span style="background:${u.errors > 0 ? 'rgba(239,68,68,0.16)' : 'rgba(16,185,129,0.16)'}; color:${u.errors > 0 ? '#ef4444' : '#10b981'}; padding:1px 5px; border-radius:4px; font-weight:800;">${u.count} int.</span>
            </button>
          `;
          const userPills = topCodeUsers.map(renderUserPill).join(' ');

          cardsHtml += `
            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid ${badgeColor}; border-radius:8px; padding:16px; margin-bottom:12px;">
              <div class="flex-between" style="flex-wrap:wrap; gap:8px; margin-bottom:8px;">
                <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                  <span style="background:${badgeColor}; color:#fff; font-family:'JetBrains Mono', monospace; font-size:0.8rem; font-weight:800; padding:3px 10px; border-radius:5px;">${escapeHtml(item.code)}</span>
                  <span style="font-weight:800; font-size:0.9rem; color:var(--text-main);">${escapeHtml(diag.title || item.code)}</span>
                </div>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; font-family:'JetBrains Mono', monospace; font-size:0.75rem;">
                  <span style="background:rgba(2,132,199,0.12); color:#0284c7; padding:3px 8px; border-radius:4px; font-weight:800;">⚡ ${item.totalInteractions.toLocaleString()} interacciones</span>
                  <span style="background:rgba(139,92,246,0.12); color:#8b5cf6; padding:3px 8px; border-radius:4px; font-weight:800;">👥 ${item.uniqueUsersCount.toLocaleString()} usuarios nominales</span>
                  ${item.failCount > 0 ? `<span style="background:rgba(239,68,68,0.15); color:#ef4444; padding:3px 8px; border-radius:4px; font-weight:800;">🔴 ${item.failCount.toLocaleString()} fallos</span>` : ''}
                  ${item.successCount > 0 ? `<span style="background:rgba(16,185,129,0.15); color:#10b981; padding:3px 8px; border-radius:4px; font-weight:800;">🟢 ${item.successCount.toLocaleString()} éxitos</span>` : ''}
                </div>
              </div>

              <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:10px; margin-bottom:10px; font-size:0.76rem; background:var(--bg-secondary); padding:10px 12px; border-radius:6px; border:1px solid var(--border-color);">
                <div>
                  <strong style="color:#0284c7;">📖 Significado Técnico Oficial:</strong><br>
                  <span style="color:var(--text-main); line-height:1.4;">${escapeHtml(diag.meaning || 'Evento operacional registrado en plataforma Entrust.')}</span>
                </div>
                <div>
                  <strong style="color:#d97706;">🔍 Causa Raíz / Contexto:</strong><br>
                  <span style="color:var(--text-main); line-height:1.4;">${escapeHtml(diag.rootCause || 'Operación estándar del motor de identidad.')}</span>
                </div>
                <div>
                  <strong style="color:#059669;">🛠️ Recomendación / Control:</strong><br>
                  <span style="color:var(--text-main); line-height:1.4; white-space:pre-line;">${escapeHtml(diag.remediation || diag.governanceControl || 'Monitorear volumen transaccional.')}</span>
                  <div style="margin-top:4px; display:flex; gap:10px;">
                    <a href="https://trustedcare.entrust.com" target="_blank" rel="noopener noreferrer" style="color:#0284c7; font-weight:700; text-decoration:none; font-size:0.72rem;">🔗 TrustedCare KB ↗</a>
                    <a href="https://docs.trustedauth.com" target="_blank" rel="noopener noreferrer" style="color:#0ea5e9; font-weight:700; text-decoration:none; font-size:0.72rem;">📘 Docs Oficiales ↗</a>
                  </div>
                </div>
              </div>

              <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:6px; padding:10px;">
                <div style="font-size:0.72rem; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px;">
                  👥 Usuarios Detectados con el Código [${escapeHtml(item.code)}] y Cantidad de Interacciones por Usuario (${item.uniqueUsersCount.toLocaleString()} usuarios):
                </div>
                <div style="display:flex; flex-wrap:wrap; gap:6px; max-height:170px; overflow-y:auto;">
                  ${userPills || `<span style="font-size:0.75rem; color:var(--text-muted);">Evento de capa de sistema / daemon (${item.systemOnlyCount.toLocaleString()} ejecuciones internas sin usuario nominal).</span>`}
                </div>
                ${restCodeUsers.length > 0 ? `
                  <details style="margin-top:8px;">
                    <summary style="cursor:pointer; font-size:0.73rem; font-weight:700; color:#0284c7;">➕ Ver los otros ${restCodeUsers.length.toLocaleString()} usuarios detectados en [${escapeHtml(item.code)}]...</summary>
                    <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; max-height:220px; overflow-y:auto;">
                      ${restCodeUsers.map(renderUserPill).join(' ')}
                    </div>
                  </details>
                ` : ''}
              </div>
            </div>
          `;
        });
      }

      container.innerHTML = `
        <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:14px;">
          <button onclick="window.UserTraceReport.filterCodesMatrixFamily('ALL')" style="padding:5px 11px; border-radius:6px; font-size:0.75rem; font-weight:700; cursor:pointer; border:1px solid var(--border-color); background:${fam === 'ALL' ? '#0284c7' : 'var(--bg-primary)'}; color:${fam === 'ALL' ? '#fff' : 'var(--text-main)'};">Todos (${codeMatrix.length})</button>
          <button onclick="window.UserTraceReport.filterCodesMatrixFamily('ERROR_520')" style="padding:5px 11px; border-radius:6px; font-size:0.75rem; font-weight:700; cursor:pointer; border:1px solid #ef4444; background:${fam === 'ERROR_520' ? '#ef4444' : 'rgba(239,68,68,0.1)'}; color:${fam === 'ERROR_520' ? '#fff' : '#ef4444'};">🚨 Errores 520xxx (${countByKind('ERROR_520')})</button>
          <button onclick="window.UserTraceReport.filterCodesMatrixFamily('AUDIT_AUD')" style="padding:5px 11px; border-radius:6px; font-size:0.75rem; font-weight:700; cursor:pointer; border:1px solid #0284c7; background:${fam === 'AUDIT_AUD' ? '#0284c7' : 'rgba(2,132,199,0.1)'}; color:${fam === 'AUDIT_AUD' ? '#fff' : '#0284c7'};">🛡️ Patrones de Auditoría AUD (${countByKind('AUDIT_AUD')})</button>
          <button onclick="window.UserTraceReport.filterCodesMatrixFamily('SYSTEM_EVENT')" style="padding:5px 11px; border-radius:6px; font-size:0.75rem; font-weight:700; cursor:pointer; border:1px solid #10b981; background:${fam === 'SYSTEM_EVENT' ? '#10b981' : 'rgba(16,185,129,0.1)'}; color:${fam === 'SYSTEM_EVENT' ? '#fff' : '#10b981'};">🖥️ Sistema & SSH/OS (${countByKind('SYSTEM_EVENT')})</button>
          <button onclick="window.UserTraceReport.filterCodesMatrixFamily('DATABASE_ORA')" style="padding:5px 11px; border-radius:6px; font-size:0.75rem; font-weight:700; cursor:pointer; border:1px solid #e11d48; background:${fam === 'DATABASE_ORA' ? '#e11d48' : 'rgba(225,29,72,0.1)'}; color:${fam === 'DATABASE_ORA' ? '#fff' : '#e11d48'};">🗄️ Base de Datos ORA/SQL (${countByKind('DATABASE_ORA')})</button>
          ${countByKind('IDAAS_MIGRATION') > 0 ? `<button onclick="window.UserTraceReport.filterCodesMatrixFamily('IDAAS_MIGRATION')" style="padding:5px 11px; border-radius:6px; font-size:0.75rem; font-weight:700; cursor:pointer; border:1px solid #f59e0b; background:${fam === 'IDAAS_MIGRATION' ? '#f59e0b' : 'rgba(245,158,11,0.1)'}; color:${fam === 'IDAAS_MIGRATION' ? '#fff' : '#f59e0b'};">☁️ Migración (${countByKind('IDAAS_MIGRATION')})</button>` : ''}
        </div>
        ${cardsHtml}
      `;
    },

    renderDbHealthSubView(container, dbHealth) {
      if (!dbHealth) {
        container.innerHTML = `<div style="padding:30px; text-align:center; color:var(--text-muted);">Sin telemetría de base de datos disponible.</div>`;
        return;
      }

      const sq = dbHealth.sqliteEngine || {};
      const indRows = (dbHealth.indicators || []).map(ind => {
        const isCrit = ind.count > 0;
        return `
          <tr style="border-bottom:1px solid var(--border-color); background:${isCrit ? 'rgba(239,68,68,0.06)' : 'transparent'};">
            <td style="padding:10px; font-family:'JetBrains Mono', monospace; font-weight:800; font-size:0.78rem; color:${isCrit ? '#ef4444' : 'var(--text-main)'};">${escapeHtml(ind.code)}</td>
            <td style="padding:10px; font-family:'JetBrains Mono', monospace; font-weight:800; font-size:0.85rem; color:${isCrit ? '#ef4444' : '#10b981'};">${ind.count.toLocaleString()}</td>
            <td style="padding:10px;"><span style="background:${isCrit ? '#ef4444' : 'rgba(16,185,129,0.15)'}; color:${isCrit ? '#fff' : '#10b981'}; padding:2px 8px; border-radius:4px; font-size:0.7rem; font-weight:800;">${escapeHtml(ind.severity)}</span></td>
            <td style="padding:10px; font-size:0.78rem; color:var(--text-main);">${escapeHtml(ind.diagnosis)}</td>
            <td style="padding:10px; font-size:0.76rem; color:var(--text-muted);">${escapeHtml(ind.remediation)}</td>
          </tr>
        `;
      }).join('');

      const sampleRows = (dbHealth.evidenceSamples || []).map(s => `
        <tr style="border-bottom:1px solid var(--border-color);">
          <td style="padding:6px 10px; font-family:monospace; font-size:0.74rem; color:var(--text-muted);">#${s.lineNum}</td>
          <td style="padding:6px 10px; font-family:monospace; font-size:0.74rem;">${escapeHtml(s.timestamp || 'N/A')}</td>
          <td style="padding:6px 10px; font-family:monospace; font-size:0.74rem; color:#ef4444; font-weight:700;">${escapeHtml(s.code || 'ORA')}</td>
          <td style="padding:6px 10px; font-family:monospace; font-size:0.74rem; color:var(--text-main);">${escapeHtml(s.message || '')}</td>
        </tr>
      `).join('');

      container.innerHTML = `
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:16px; margin-bottom:16px;">
          <!-- Estado de la Base de Datos del Cliente (Oracle / SQL Server / JDBC) -->
          <div style="background:var(--bg-primary); border:1.5px solid ${dbHealth.status === 'HEALTHY' ? '#10b981' : '#ef4444'}; border-radius:8px; padding:16px;">
            <div style="font-size:0.95rem; font-weight:800; color:${dbHealth.status === 'HEALTHY' ? '#10b981' : '#ef4444'}; margin-bottom:6px;">
              ${dbHealth.status === 'HEALTHY' ? '✅ Diagnóstico BD Entrust (Oracle / JDBC): SALUDABLE' : `🚨 Diagnóstico BD Entrust (Oracle / JDBC): ${dbHealth.totalDbIncidents.toLocaleString()} INCIDENTES DETECTADOS`}
            </div>
            <div style="font-size:0.8rem; color:var(--text-main); line-height:1.5;">
              ${dbHealth.status === 'HEALTHY'
                ? 'No se detectaron errores ORA-01555, violaciones de restricción única (ORA-00001), caídas de listener TNS (ORA-03113/12170), fallos de lectura BLOB (JdbcCardRepository) ni agotamiento del pool JDBC. Los rechazos observados en el log corresponden a lógica de negocio/migración o credenciales de usuario, NO a corrupción o caída de la Base de Datos.'
                : 'Se detectaron excepciones críticas en la capa de persistencia relacional o en el pool JDBC de IdentityGuard. Revise la tabla inferior para aplicar las acciones correctivas recomendadas por Entrust TrustedCare.'}
            </div>
          </div>

          <!-- Estado del Motor Forense Local SQLite (*_audit.db) -->
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:16px;">
            <div style="font-size:0.95rem; font-weight:800; color:#0284c7; margin-bottom:8px;">
              🗄️ Motor Forense Local SQLite & Filtro Anti-Alucinación
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:0.78rem;">
              <div><strong>Archivo DB Activo:</strong> <span style="font-family:monospace;">${escapeHtml(sq.dbFile || 'N/A')}</span></div>
              <div><strong>Tamaño en Disco:</strong> <span style="font-family:monospace;">${sq.sizeMb || 0} MB (Modo ${escapeHtml(sq.journalMode || 'WAL')})</span></div>
              <div><strong>Registros Indexados:</strong> <span style="font-family:monospace;">${(sq.totalRowsIndexed || 0).toLocaleString()}</span></div>
              <div><strong>Usuarios Reales Validados:</strong> <span style="font-family:monospace; color:#10b981; font-weight:800;">${(sq.uniqueValidUsers || 0).toLocaleString()}</span></div>
              <div style="grid-column:span 2; background:var(--bg-secondary); padding:8px; border-radius:6px; border:1px solid var(--border-color);">
                <strong>🧹 Palabras Falsas / Ruido Purgado Automáticamente:</strong>
                <span style="color:#f59e0b; font-weight:800;"> ${(sq.filteredNoiseTokens || 0).toLocaleString()} tokens descartados</span>
                (${(sq.filteredNoiseEvents || 0).toLocaleString()} líneas donde el parser antiguo confundía palabras en inglés con usuarios:
                <span style="font-family:monospace; font-size:0.72rem; color:var(--text-muted);">${escapeHtml((sq.sampleNoiseTokens || []).join(', ') || 'ninguno')}</span>)
              </div>
            </div>
          </div>
        </div>

        <!-- Tabla de Indicadores de Base de Datos -->
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; margin-bottom:16px; overflow-x:auto;">
          <div style="font-weight:800; font-size:0.88rem; color:var(--text-main); margin-bottom:10px;">📊 Matriz de Salud de Persistencia (Oracle / SQL Server / Pool JDBC / BLOB Grid Cards)</div>
          <table style="width:100%; border-collapse:collapse; text-align:left; font-size:0.78rem;">
            <thead>
              <tr style="background:var(--bg-secondary); color:var(--text-muted); border-bottom:1px solid var(--border-color); font-size:0.72rem; text-transform:uppercase;">
                <th style="padding:8px 10px;">Indicador / Código BD</th>
                <th style="padding:8px 10px;">Ocurrencias</th>
                <th style="padding:8px 10px;">Estado</th>
                <th style="padding:8px 10px;">Diagnóstico Técnico</th>
                <th style="padding:8px 10px;">Acción Correctiva (DBA / Entrust)</th>
              </tr>
            </thead>
            <tbody>${indRows}</tbody>
          </table>
        </div>

        ${sampleRows ? `
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; overflow-x:auto;">
            <div style="font-weight:800; font-size:0.85rem; color:#ef4444; margin-bottom:8px;">🔍 Evidencia Forense de Excepciones de Base de Datos en el Log</div>
            <table style="width:100%; border-collapse:collapse; text-align:left;">
              <thead>
                <tr style="background:var(--bg-secondary); color:var(--text-muted); font-size:0.72rem; text-transform:uppercase;">
                  <th style="padding:6px 10px;">Línea</th>
                  <th style="padding:6px 10px;">Timestamp</th>
                  <th style="padding:6px 10px;">Código</th>
                  <th style="padding:6px 10px;">Traza / Mensaje</th>
                </tr>
              </thead>
              <tbody>${sampleRows}</tbody>
            </table>
          </div>
        ` : ''}
      `;
    },

    renderPostMortemSubView(container, postMortem, dbHealth, codeMatrix, patternClusters) {
      if (!postMortem) {
        container.innerHTML = `<div style="padding:30px; text-align:center; color:var(--text-muted);">No hay datos suficientes para el análisis Post-Mortem.</div>`;
        return;
      }

      const bd = postMortem.breakdown || {};
      const peakHtml = (postMortem.peakHours || []).map(p => `
        <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:6px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
          <span style="font-family:'JetBrains Mono', monospace; font-size:0.8rem; font-weight:700;">🕒 ${escapeHtml(p.hour)}:00 hrs</span>
          <span style="color:#ef4444; font-family:'JetBrains Mono', monospace; font-weight:800; font-size:0.82rem;">🚨 ${(p.errors || 0).toLocaleString()} errores</span>
        </div>
      `).join('');

      const topCodesSummary = (codeMatrix || []).slice(0, 6).map(c => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px dashed var(--border-color); font-size:0.78rem;">
          <span style="font-family:'JetBrains Mono', monospace; font-weight:700; color:#0284c7;">${escapeHtml(c.code)}</span>
          <span><strong>${c.totalInteractions.toLocaleString()}</strong> int. / <strong>${c.uniqueUsersCount.toLocaleString()}</strong> usuarios</span>
        </div>
      `).join('');

      container.innerHTML = `
        <div style="background:rgba(225,29,72,0.06); border:1.5px solid #e11d48; border-radius:10px; padding:18px; margin-bottom:16px;">
          <div style="font-size:0.75rem; font-weight:800; text-transform:uppercase; color:#e11d48; letter-spacing:0.5px;">🕵️ Dictamen Forense Post-Mortem Automatizado (Sin Alucinaciones)</div>
          <div style="font-size:1.1rem; font-weight:800; color:var(--text-main); margin-top:4px;">Vector Primario: ${escapeHtml(postMortem.primaryVector || 'N/A')}</div>
          <div style="font-size:0.85rem; color:var(--text-main); margin-top:8px; line-height:1.55;">
            ${escapeHtml(postMortem.executiveVerdict || '')}
          </div>
          <div style="display:flex; gap:16px; flex-wrap:wrap; margin-top:12px; font-size:0.76rem; color:var(--text-muted); font-family:'JetBrains Mono', monospace;">
            <span>📅 Inicio Ventana: <strong>${escapeHtml(postMortem.startTime)}</strong></span>
            <span>🏁 Fin Ventana: <strong>${escapeHtml(postMortem.endTime)}</strong></span>
          </div>
        </div>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-bottom:16px;">
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); padding:12px; border-radius:8px;">
            <div style="font-size:0.72rem; color:var(--text-muted); font-weight:700;">1. Incidentes de Base de Datos (ORA/JDBC)</div>
            <div style="font-size:1.4rem; font-weight:800; color:${(bd.databaseIncidents || 0) > 0 ? '#ef4444' : '#10b981'}; font-family:monospace; margin-top:4px;">${(bd.databaseIncidents || 0).toLocaleString()}</div>
          </div>
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); padding:12px; border-radius:8px;">
            <div style="font-size:0.72rem; color:var(--text-muted); font-weight:700;">2. Alertas y Fallos de Auditoría [AUD6001 / AUD6002]</div>
            <div style="font-size:1.4rem; font-weight:800; color:#f59e0b; font-family:monospace; margin-top:4px;">${((bd.auditAlertsCount ?? bd.migrationCollisions) || 0).toLocaleString()}</div>
          </div>
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); padding:12px; border-radius:8px;">
            <div style="font-size:0.72rem; color:var(--text-muted); font-weight:700;">3. Rechazos de Autenticación [520xxx]</div>
            <div style="font-size:1.4rem; font-weight:800; color:#ef4444; font-family:monospace; margin-top:4px;">${(bd.authentication520Errors || 0).toLocaleString()}</div>
          </div>
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); padding:12px; border-radius:8px;">
            <div style="font-size:0.72rem; color:var(--text-muted); font-weight:700;">4. Otros Eventos de Sistema / Red</div>
            <div style="font-size:1.4rem; font-weight:800; color:var(--text-main); font-family:monospace; margin-top:4px;">${(bd.otherSystemErrors || 0).toLocaleString()}</div>
          </div>
        </div>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:16px; margin-bottom:16px;">
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px;">
            <div style="font-weight:800; font-size:0.86rem; color:var(--text-main); margin-bottom:10px;">🔥 Horas Pico de Mayor Siniestralidad</div>
            <div style="display:flex; flex-direction:column; gap:6px;">
              ${peakHtml || '<div style="font-size:0.78rem; color:var(--text-muted);">Sin ráfagas horarias críticas registradas.</div>'}
            </div>
          </div>

          <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px;">
            <div style="font-weight:800; font-size:0.86rem; color:var(--text-main); margin-bottom:10px;">📌 Códigos Dominantes en el Incidente</div>
            ${topCodesSummary || '<div style="font-size:0.78rem; color:var(--text-muted);">Sin códigos registrados.</div>'}
          </div>
        </div>

        <!-- Enlaces Oficiales Entrust TrustedCare & Knowledge Base -->
        <div style="background:var(--bg-primary); border:1px solid #0284c7; border-radius:8px; padding:16px;">
          <div style="font-weight:800; font-size:0.9rem; color:#0284c7; margin-bottom:10px;">🌐 Base de Conocimiento Oficial Entrust TrustedCare & Documentación Técnica</div>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:12px;">
            <a href="https://trustedcare.entrust.com" target="_blank" rel="noopener noreferrer" style="display:block; text-decoration:none; background:var(--bg-secondary); border:1px solid var(--border-color); border-left:4px solid #0284c7; padding:12px; border-radius:6px;">
              <div style="font-weight:800; color:#0284c7; font-size:0.85rem;">🛡️ Entrust TrustedCare Portal (https://trustedcare.entrust.com) ↗</div>
              <div style="font-size:0.76rem; color:var(--text-muted); margin-top:4px;">Portal oficial de soporte técnico Entrust, artículos de Knowledge Base (KB) para errores 520xxx / ORA-01555, notas de versión y apertura de tickets de soporte.</div>
            </a>
            <a href="https://docs.trustedauth.com" target="_blank" rel="noopener noreferrer" style="display:block; text-decoration:none; background:var(--bg-secondary); border:1px solid var(--border-color); border-left:4px solid #0ea5e9; padding:12px; border-radius:6px;">
              <div style="font-weight:800; color:#0ea5e9; font-size:0.85rem;">📘 Entrust TrustedAuth Docs (https://docs.trustedauth.com) ↗</div>
              <div style="font-size:0.76rem; color:var(--text-muted); margin-top:4px;">Documentación oficial de Entrust IDaaS e IdentityGuard: guías de Bulk Migration Tool, parámetros de sobreescritura (assignedgrid/password/qa) y eventos AUD.</div>
            </a>
          </div>
        </div>
      `;
    },

    selectTabFilter(type) {
      this.activeTabFilter = type;
      const bAll = document.getElementById('btn-tab-filter-all');
      const bErr = document.getElementById('btn-tab-filter-errors');
      const bSuc = document.getElementById('btn-tab-filter-success');
      
      if (bAll) { bAll.style.background = type === 'all' ? '#0284c7' : 'var(--bg-secondary)'; bAll.style.color = type === 'all' ? '#fff' : 'var(--text-muted)'; }
      if (bErr) { bErr.style.background = type === 'errors' ? '#ef4444' : 'rgba(239,68,68,0.12)'; bErr.style.color = type === 'errors' ? '#fff' : '#ef4444'; }
      if (bSuc) { bSuc.style.background = type === 'success' ? '#10b981' : 'rgba(16,185,129,0.12)'; bSuc.style.color = type === 'success' ? '#fff' : '#10b981'; }

      this.renderTabUserList();
    },

    filterTabUserList(query) {
      const q = (query || '').toLowerCase().trim();
      const container = document.getElementById('tab-user-items-list');
      if (!container) return;
      const items = container.querySelectorAll('.tab-user-list-item');
      items.forEach(it => {
        const uName = (it.getAttribute('data-username') || '').toLowerCase();
        const uPat = (it.getAttribute('data-pattern') || '').toLowerCase();
        it.style.display = (uName.includes(q) || uPat.includes(q)) ? 'flex' : 'none';
      });
    },

    renderTabUserList() {
      const container = document.getElementById('tab-user-items-list');
      if (!container) return;

      let list = Object.values(this.cachedStats);
      if (this.activeTabFilter === 'errors') {
        list = list.filter(u => u.errors > 0 || u.isLocked);
      } else if (this.activeTabFilter === 'success') {
        list = list.filter(u => u.errors === 0 && !u.isLocked);
      }

      list.sort((a, b) => {
        if (b.errors !== a.errors) return b.errors - a.errors;
        return b.totalEvents - a.totalEvents;
      });

      if (list.length === 0) {
        container.innerHTML = '<div style="padding:16px; text-align:center; color:var(--text-muted); font-size:0.8rem;">No hay usuarios nominales que coincidan con este filtro.</div>';
        return;
      }

      let html = '';
      list.forEach(u => {
        const isSelected = u.username === this.activeTabSelectedUser;
        let badge = '<span style="background:rgba(16,185,129,0.15); color:#10b981; font-size:0.68rem; font-weight:700; padding:1px 6px; border-radius:4px;">✅ OK</span>';
        if (u.isLocked) {
          badge = '<span style="background:rgba(225,29,72,0.15); color:#e11d48; font-size:0.68rem; font-weight:800; padding:1px 6px; border-radius:4px;">🔒 LOCK</span>';
        } else if (u.errors > 0) {
          badge = `<span style="background:rgba(239,68,68,0.15); color:#ef4444; font-size:0.68rem; font-weight:800; padding:1px 6px; border-radius:4px;">${u.errors} fallas</span>`;
        }

        const patShort = u.patternCategory || 'Operación Nominal';
        const codesSearch = Object.keys(u.codes || {}).join(' ');

        html += `
          <div class="tab-user-list-item" data-username="${escapeHtml(u.username)}" data-pattern="${escapeHtml(patShort + ' ' + codesSearch)}" onclick="window.UserTraceReport.renderTabUserDetail('${escapeHtml(u.username)}')" style="display:flex; justify-content:space-between; align-items:center; padding:8px 10px; border-radius:6px; cursor:pointer; background:${isSelected ? 'rgba(2,132,199,0.18)' : 'var(--bg-secondary)'}; border:1px solid ${isSelected ? '#0284c7' : 'var(--border-color)'}; margin-bottom:2px; transition:all 0.15s ease;">
            <div style="overflow:hidden; padding-right:6px;">
              <div style="font-weight:700; color:var(--text-main); font-size:0.82rem; font-family:'JetBrains Mono', monospace; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(u.username)}</div>
              <div style="font-size:0.69rem; color:var(--text-muted); margin-top:2px;">${u.totalEvents.toLocaleString()} solicitudes • ${escapeHtml(patShort.slice(0, 28))}</div>
            </div>
            <div style="flex-shrink:0;">${badge}</div>
          </div>
        `;
      });

      container.innerHTML = html;
    },

    async renderTabUserDetail(username) {
      this.activeTabSelectedUser = username;
      this.renderTabUserList();

      const pane = document.getElementById('tab-user-detail-pane');
      if (!pane) return;

      const u = this.cachedStats[username];
      if (!u) {
        pane.innerHTML = '<div style="padding:30px; text-align:center; color:var(--text-muted);">Seleccione un usuario de la lista para ver su patrón de solicitudes y expediente.</div>';
        return;
      }

      // Obtener eventos detallados del usuario desde memoria o bajo demanda desde SQLite (/api/user-pattern-detail)
      const allLogs = this.getAllLogs();
      let userLogs = allLogs.filter(l => {
        const logUser = l.user || l.usuario || l.username;
        return logUser && logUser.toLowerCase() === username.toLowerCase();
      });

      if (userLogs.length === 0 && this.forensicMatrixData && this.forensicMatrixData.activeDb) {
        if (!this.sqliteUserEventsCache[username]) {
          try {
            const activeClient = this.getClientProfile();
            const cParam = encodeURIComponent(activeClient?.name || '');
            const uParam = encodeURIComponent(username);
            const res = await fetch(`/api/user-pattern-detail?user=${uParam}&client=${cParam}`);
            if (res.ok) {
              const d = await res.json();
              if (d && Array.isArray(d.events)) {
                this.sqliteUserEventsCache[username] = d.events;
              }
            }
          } catch (e) {
            console.warn('Error consultando detalle SQLite del usuario:', e);
          }
        }
        if (this.sqliteUserEventsCache[username]) {
          userLogs = this.sqliteUserEventsCache[username].map(ev => ({
            lineNum: ev.lineNum,
            timestamp: ev.timestamp,
            user: ev.user,
            entrustCode: ev.code,
            code: ev.code,
            outcome: ev.outcome,
            level: ev.level,
            message: ev.message || ev.raw,
            clientIp: ev.ip
          }));
        }
      }

      const seqToRender = (userLogs.length > 0 ? userLogs.slice(0, 30).map((l, idx) => ({
        step: idx + 1,
        code: l.entrustCode || l.code || l.type || 'EVENT',
        outcome: (l.level === 'ERROR' || l.level === 'CRITICAL' || /FAIL|ERR/i.test(l.outcome || '')) ? 'FAIL' : 'SUCCESS',
        timestamp: l.timestamp || '',
        ip: l.clientIp || l.ip || 'local'
      })) : (u.sequence || []));

      // Construir Diagrama Visual de Flujo de Solicitudes (Solicitud 1 ➔ Solicitud 2 ➔ ... ➔ Solicitud N)
      let flowStepsHtml = '';
      if (seqToRender.length > 0) {
        seqToRender.slice(0, 18).forEach((st, idx) => {
          const isFail = st.outcome === 'FAIL';
          const bg = isFail ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)';
          const col = isFail ? '#ef4444' : '#10b981';
          flowStepsHtml += `
            <div style="display:inline-flex; align-items:center; gap:6px;">
              <div style="background:${bg}; border:1px solid ${col}; border-radius:6px; padding:5px 9px; font-family:'JetBrains Mono', monospace; font-size:0.73rem;">
                <div style="font-size:0.64rem; color:var(--text-muted); font-weight:700;">SOLICITUD #${idx + 1} ${st.timestamp ? `(${escapeHtml(st.timestamp.slice(11, 19))})` : ''}</div>
                <div style="font-weight:800; color:${col};">${isFail ? '🔴' : '🟢'} ${escapeHtml(st.code)}</div>
              </div>
              ${idx < Math.min(seqToRender.length, 18) - 1 ? '<span style="color:var(--text-muted); font-weight:800; font-size:0.9rem;">➔</span>' : ''}
            </div>
          `;
        });
        if (seqToRender.length > 18) {
          flowStepsHtml += `<span style="font-size:0.74rem; color:var(--text-muted); font-weight:700; padding:4px 8px;">... (+${seqToRender.length - 18} solicitudes adicionales)</span>`;
        }
      } else {
        flowStepsHtml = `<span style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(u.compressedPattern || 'Sin secuencia detallada')}</span>`;
      }

      const successRate = u.totalEvents > 0 ? (((u.totalEvents - u.errors) / u.totalEvents) * 100).toFixed(1) : 100;
      const ipsList = Array.from(u.ips || []).join(', ') || 'local';
      const nodesList = Array.from(u.nodes || []).join(', ') || 'Servidor Core';

      // Tabla de Códigos e Interacciones de este Usuario
      let codesHtml = '';
      Object.entries(u.codes || {}).sort((a, b) => b[1] - a[1]).forEach(([code, cnt]) => {
        const det = (u.codesDetail && u.codesDetail[code]) ? u.codesDetail[code] : null;
        const isErr = (det && det.errors > 0) || /520|ORA|error|fail/i.test(code);
        const subLabel = det ? ` (${det.errors} err / ${det.success} ok)` : '';
        codesHtml += `<span style="background:${isErr ? 'rgba(239,68,68,0.15)' : 'rgba(2,132,199,0.15)'}; color:${isErr ? '#ef4444' : '#0284c7'}; border:1px solid ${isErr ? 'rgba(239,68,68,0.35)' : 'rgba(2,132,199,0.35)'}; font-size:0.75rem; font-family:'JetBrains Mono', monospace; padding:4px 9px; border-radius:5px; font-weight:800; display:inline-block; margin:2px;">${escapeHtml(code)}: ${cnt} int.${escapeHtml(subLabel)}</span> `;
      });

      // Diagnóstico técnico oficial
      let diagResult = { title: 'Operación Nominal', meaning: 'Usuario con flujo de autenticación y aprovisionamiento exitoso.', rootCause: u.rootCause || 'Ninguna anomalía detectada.', remediation: 'Mantener políticas operacionales vigentes.' };
      if (u.errors > 0) {
        const topErr = Object.keys(u.codes || {}).find(c => /520|ORA|assignedgrid|password|qa|error/i.test(c)) || Object.keys(u.codes || {})[0] || '5202013';
        if (window.knowledgeBaseEngine) {
          diagResult = window.knowledgeBaseEngine.diagnoseLog(topErr, topErr);
        }
      }

      // Cascada Cronológica de Solicitudes del Usuario
      let logsRows = '';
      if (userLogs.length > 0) {
        userLogs.slice(0, 150).forEach((l, idx) => {
          const isErr = l.level === 'CRITICAL' || l.level === 'ERROR' || /FAIL|ERR/i.test(l.outcome || '');
          logsRows += `
            <tr style="border-bottom:1px solid var(--border-color); background:${idx % 2 === 0 ? 'transparent' : 'rgba(15,23,42,0.03)'};">
              <td style="padding:6px 10px; font-family:monospace; font-size:0.73rem; font-weight:700; color:#8b5cf6;">#${idx + 1}</td>
              <td style="padding:6px 10px; font-family:monospace; font-size:0.74rem; color:var(--text-muted);">${escapeHtml(l.timestamp || l.time || 'N/A')}</td>
              <td style="padding:6px 10px; font-size:0.74rem; font-weight:bold; color:${isErr ? '#ef4444' : '#10b981'};">${isErr ? '🔴 FALLO' : '🟢 ÉXITO'}</td>
              <td style="padding:6px 10px; font-family:monospace; font-size:0.75rem; color:#0284c7; font-weight:700;">${escapeHtml(l.entrustCode || l.code || l.type || 'EVENT')}</td>
              <td style="padding:6px 10px; font-size:0.75rem; color:var(--text-main); word-break:break-all;">${escapeHtml(l.message || l.raw || '')}</td>
              <td style="padding:6px 10px; font-family:monospace; font-size:0.72rem; color:var(--text-muted);">${escapeHtml(l.clientIp || l.ip || 'Local')}</td>
            </tr>
          `;
        });
      } else {
        logsRows = `
          <tr>
            <td colspan="6" style="padding:14px; text-align:center; color:var(--text-muted); font-size:0.8rem;">
              Patrón consolidado: <strong>${escapeHtml(u.compressedPattern || 'N/A')}</strong> (${u.totalEvents} interacciones registradas).
            </td>
          </tr>
        `;
      }

      pane.innerHTML = `
        <!-- Encabezado de la Ficha del Usuario -->
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:16px;">
          <div class="flex-between mb-2" style="flex-wrap:wrap; gap:8px;">
            <div style="display:flex; align-items:center; gap:10px;">
              <span style="font-size:1.8rem;">👤</span>
              <div>
                <div style="font-size:1.15rem; font-weight:800; color:var(--text-main); font-family:'JetBrains Mono', monospace;">${escapeHtml(username)}</div>
                <div style="font-size:0.75rem; color:#8b5cf6; font-weight:800; margin-top:2px;">Patrón Clasificado: ${escapeHtml(u.patternCategory || 'Operación Nominal')}</div>
              </div>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              ${u.isLocked ? '<span style="background:#ef4444; color:#fff; font-size:0.75rem; font-weight:800; padding:4px 10px; border-radius:6px;">🔴 CUENTA BLOQUEADA</span>' : (u.errors > 0 ? '<span style="background:#f59e0b; color:#fff; font-size:0.75rem; font-weight:800; padding:4px 10px; border-radius:6px;">🟡 CON INCIDENCIAS</span>' : '<span style="background:#10b981; color:#fff; font-size:0.75rem; font-weight:800; padding:4px 10px; border-radius:6px;">🟢 CUENTA ACTIVA / OK</span>')}
            </div>
          </div>

          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap:10px; margin-top:12px; font-size:0.8rem;">
            <div style="background:var(--bg-secondary); padding:8px 10px; border-radius:6px; border:1px solid var(--border-color);">
              <div style="font-size:0.7rem; color:var(--text-muted);">Tasa de Éxito:</div>
              <div style="font-weight:800; color:${parseFloat(successRate) >= 95 ? '#10b981' : '#ef4444'}; font-size:1rem;">${successRate}%</div>
            </div>
            <div style="background:var(--bg-secondary); padding:8px 10px; border-radius:6px; border:1px solid var(--border-color);">
              <div style="font-size:0.7rem; color:var(--text-muted);">Total Interacciones:</div>
              <div style="font-weight:800; color:var(--text-main); font-size:1rem;">${u.totalEvents.toLocaleString()} (${u.errors} err / ${u.successes} ok)</div>
            </div>
            <div style="background:var(--bg-secondary); padding:8px 10px; border-radius:6px; border:1px solid var(--border-color);">
              <div style="font-size:0.7rem; color:var(--text-muted);">Primera / Última Solicitud:</div>
              <div style="font-weight:700; color:#0284c7; font-size:0.73rem; font-family:monospace;">${escapeHtml((u.firstTimestamp || 'N/A').slice(0, 19))} ➔ ${escapeHtml((u.lastTimestamp || 'N/A').slice(11, 19))}</div>
            </div>
            <div style="background:var(--bg-secondary); padding:8px 10px; border-radius:6px; border:1px solid var(--border-color);">
              <div style="font-size:0.7rem; color:var(--text-muted);">IPs / Origen:</div>
              <div style="font-weight:700; color:#0284c7; font-size:0.76rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(ipsList)}</div>
            </div>
          </div>

          <!-- Patrón Secuencial de Solicitudes del Usuario -->
          <div style="margin-top:14px; background:var(--bg-secondary); border:1px solid var(--border-color); border-left:4px solid #8b5cf6; border-radius:6px; padding:12px;">
            <div style="font-size:0.74rem; color:#8b5cf6; font-weight:800; text-transform:uppercase; margin-bottom:6px;">
              🧬 Patrón Secuencial de Solicitudes del Usuario (Flujo Paso a Paso):
            </div>
            <div style="font-family:'JetBrains Mono', monospace; font-size:0.78rem; color:var(--text-main); font-weight:700; margin-bottom:8px;">
              Firma Comprimida: <span style="color:#0284c7;">${escapeHtml(u.compressedPattern || 'N/A')}</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:6px; align-items:center;">
              ${flowStepsHtml}
            </div>
          </div>

          <div style="margin-top:12px;">
            <div style="font-size:0.72rem; color:var(--text-muted); font-weight:700; text-transform:uppercase; margin-bottom:4px;">Códigos Detectados para este Usuario y Cantidad de Interacciones:</div>
            <div>${codesHtml || '<span style="color:var(--text-muted); font-size:0.75rem;">Sin códigos de error reportados.</span>'}</div>
          </div>
        </div>

        <!-- Tarjeta de Diagnóstico Forense y Remediación con Enlace a TrustedCare -->
        <div style="background:${u.errors > 0 ? 'rgba(239,68,68,0.06)' : 'rgba(16,185,129,0.06)'}; border:1.5px solid ${u.errors > 0 ? '#ef4444' : '#10b981'}; border-radius:8px; padding:16px;">
          <div class="flex-between" style="flex-wrap:wrap; gap:8px; margin-bottom:6px;">
            <div style="font-size:0.88rem; font-weight:800; color:${u.errors > 0 ? '#ef4444' : '#10b981'};">
              🎯 ${escapeHtml(diagResult.title || 'Diagnóstico Técnico')}
            </div>
            <div style="display:flex; gap:10px;">
              <a href="https://trustedcare.entrust.com" target="_blank" rel="noopener noreferrer" style="font-size:0.74rem; font-weight:800; color:#0284c7; text-decoration:none;">🛡️ Abrir Base de Conocimiento TrustedCare ↗</a>
              <a href="https://docs.trustedauth.com" target="_blank" rel="noopener noreferrer" style="font-size:0.74rem; font-weight:800; color:#0ea5e9; text-decoration:none;">📘 Docs TrustedAuth ↗</a>
            </div>
          </div>
          <div style="font-size:0.78rem; color:var(--text-main); margin-bottom:6px;">
            <strong>Análisis del Patrón del Usuario:</strong> ${escapeHtml(u.rootCause || diagResult.meaning || 'Operación estándar')}
          </div>
          <div style="font-size:0.78rem; color:var(--text-main); margin-bottom:8px;">
            <strong>Causa Raíz Técnica Oficial:</strong> ${escapeHtml(diagResult.rootCause || 'N/A')}
          </div>
          <div style="font-size:0.78rem; color:#047857; background:rgba(16,185,129,0.1); padding:8px; border-radius:6px; border:1px solid rgba(16,185,129,0.2);">
            <strong>🛠️ Procedimiento de Remediación:</strong> ${escapeHtml(diagResult.remediation || 'Operación normal')}
          </div>
        </div>

        <!-- Cascada Cronológica de Transacciones del Usuario -->
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px;">
          <div class="flex-between mb-2">
            <span style="font-weight:700; color:var(--text-main); font-size:0.85rem;">⏱️ Historial Cronológico Completo de Solicitudes del Usuario:</span>
            <span style="font-size:0.72rem; color:var(--text-muted);">${userLogs.length} solicitudes vinculadas</span>
          </div>
          <div style="max-height:320px; overflow-y:auto; overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; font-size:0.78rem; text-align:left;">
              <thead>
                <tr style="background:var(--bg-secondary); color:var(--text-muted); border-bottom:1px solid var(--border-color); font-size:0.72rem; text-transform:uppercase;">
                  <th style="padding:6px 10px;"># Req</th>
                  <th style="padding:6px 10px;">Timestamp</th>
                  <th style="padding:6px 10px;">Resultado</th>
                  <th style="padding:6px 10px;">Código / Patrón AUD</th>
                  <th style="padding:6px 10px;">Detalle de la Solicitud</th>
                  <th style="padding:6px 10px;">IP Origen</th>
                </tr>
              </thead>
              <tbody>
                ${logsRows}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }
  };

  window.UserTraceReport = UserTraceReport;

  // Auto-inicialización al cargar el DOM
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => UserTraceReport.init());
  } else {
    UserTraceReport.init();
  }

})(window);
