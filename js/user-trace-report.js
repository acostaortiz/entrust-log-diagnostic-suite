/**
 * ==============================================================================
 * 🏢 IT SERVICIOS DE VENEZUELA, S.A.
 * MÓDULO: INFORME DE TRAZABILIDAD Y SEGURIDAD DE USUARIOS (v450.0)
 * ==============================================================================
 * Permite seleccionar uno o múltiples usuarios, aislar su historial completo de
 * transacciones, correlacionar códigos de error y auditoría Entrust, y generar
 * expedientes técnicos de diagnóstico y seguridad listos para exportar (PDF, DOCX, XLSX, CSV).
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

    init() {
      this.bindEvents();
      console.log('✅ [UserTraceReport]: Módulo de Trazabilidad y Seguridad de Usuarios inicializado.');
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

      // Búsqueda en Lista de Usuarios
      const inputSearch = document.getElementById('user-trace-search-user');
      if (inputSearch) {
        inputSearch.addEventListener('input', (e) => this.filterUserList(e.target.value));
      }

      // Acciones de Selección Rápida
      const btnSelectTopErrors = document.getElementById('btn-trace-select-top-errors');
      if (btnSelectTopErrors) {
        btnSelectTopErrors.addEventListener('click', () => this.selectTopErrorUsers(5));
      }

      const btnSelectAll = document.getElementById('btn-trace-select-all');
      if (btnSelectAll) {
        btnSelectAll.addEventListener('click', () => this.selectAllUsers());
      }

      const btnClearSelection = document.getElementById('btn-trace-clear-selection');
      if (btnClearSelection) {
        btnClearSelection.addEventListener('click', () => this.clearSelection());
      }

      // Agregar Usuario Manual
      const btnAddCustomUser = document.getElementById('btn-trace-add-custom-user');
      const inputCustomUser = document.getElementById('input-trace-custom-user');
      if (btnAddCustomUser && inputCustomUser) {
        const addCustom = () => {
          const val = inputCustomUser.value.trim();
          if (val) {
            const users = val.split(/[,;\s]+/).filter(Boolean);
            users.forEach(u => this.selectedUsers.add(u));
            inputCustomUser.value = '';
            this.renderUserChecklist();
            this.generateReport();
          }
        };
        btnAddCustomUser.addEventListener('click', addCustom);
        inputCustomUser.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            addCustom();
          }
        });
      }

      // Botón Generar / Actualizar
      const btnGenerate = document.getElementById('btn-trace-generate-report');
      if (btnGenerate) {
        btnGenerate.addEventListener('click', () => this.generateReport());
      }

      // Botones de Exportación
      const btnPdf = document.getElementById('btn-trace-export-pdf');
      if (btnPdf) btnPdf.addEventListener('click', () => this.downloadPdf());

      const btnDocx = document.getElementById('btn-trace-export-docx');
      if (btnDocx) btnDocx.addEventListener('click', () => this.downloadDocx());

      const btnExcel = document.getElementById('btn-trace-export-excel');
      if (btnExcel) btnExcel.addEventListener('click', () => this.downloadExcel());

      const btnCsv = document.getElementById('btn-trace-export-csv');
      if (btnCsv) btnCsv.addEventListener('click', () => this.downloadCsv());

      const btnPrint = document.getElementById('btn-trace-print');
      if (btnPrint) btnPrint.addEventListener('click', () => this.printReport());

      const btnCopy = document.getElementById('btn-trace-copy');
      if (btnCopy) btnCopy.addEventListener('click', () => this.copyMarkdown());
    },

    getAllLogs() {
      if (window.appState && Array.isArray(window.appState.logs) && window.appState.logs.length > 0) {
        return window.appState.logs;
      }
      if (window.MOCK_BUNDLE_MERCANTIL_10GB && Array.isArray(window.MOCK_BUNDLE_MERCANTIL_10GB.logs)) {
        return window.MOCK_BUNDLE_MERCANTIL_10GB.logs;
      }
      return [];
    },

    getClientProfile() {
      if (window.getActiveClientProfile && typeof window.getActiveClientProfile === 'function') {
        return window.getActiveClientProfile();
      }
      return {
        name: 'Banco Mercantil C.A.',
        type: 'IDaaS Cloud v2026',
        env: 'Producción Bancaria'
      };
    },

    openModal(initialUsers) {
      const modal = document.getElementById('modal-user-trace-report');
      if (!modal) return;

      this.selectedUsers.clear();
      if (initialUsers) {
        if (Array.isArray(initialUsers)) {
          initialUsers.forEach(u => this.selectedUsers.add(u));
        } else if (typeof initialUsers === 'string') {
          this.selectedUsers.add(initialUsers);
        }
      }

      this.buildUserStats();
      this.renderUserChecklist();

      // Si no se pasaron usuarios iniciales, seleccionar automáticamente el top 3 con errores
      if (this.selectedUsers.size === 0) {
        this.selectTopErrorUsers(3, false);
      }

      this.generateReport();
      modal.style.display = 'flex';
      document.body.style.overflow = 'hidden';
    },

    closeModal() {
      const modal = document.getElementById('modal-user-trace-report');
      if (modal) modal.style.display = 'none';
      document.body.style.overflow = '';
    },

    buildUserStats() {
      const logs = this.getAllLogs();
      const stats = {};

      logs.forEach(log => {
        let user = log.user || log.usuario || log.username;
        if (!user && log.message) {
          const match = log.message.match(/User:\s*([a-zA-Z0-9_\.\-]+)/i) || log.message.match(/usuario\s*[:=]\s*([a-zA-Z0-9_\.\-]+)/i);
          if (match) user = match[1];
        }
        if (!user) return;

        user = user.trim();
        if (!stats[user]) {
          stats[user] = {
            username: user,
            totalEvents: 0,
            errors: 0,
            criticals: 0,
            warnings: 0,
            successes: 0,
            ips: new Set(),
            nodes: new Set(),
            codes: {},
            lastTimestamp: log.timestamp || ''
          };
        }

        const uStat = stats[user];
        uStat.totalEvents++;
        const lvl = (log.level || '').toUpperCase();
        if (lvl === 'CRITICAL' || lvl === 'FATAL') {
          uStat.criticals++;
          uStat.errors++;
        } else if (lvl === 'ERROR') {
          uStat.errors++;
        } else if (lvl === 'WARN' || lvl === 'WARNING') {
          uStat.warnings++;
        } else {
          uStat.successes++;
        }

        if (log.ip) uStat.ips.add(log.ip);
        if (log.server || log.node) uStat.nodes.add(log.server || log.node);

        const code = String(log.code || 'SYS-EVENT');
        uStat.codes[code] = (uStat.codes[code] || 0) + 1;
      });

      this.cachedStats = stats;
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
            No se detectaron usuarios explícitos en los logs cargados. Puedes ingresar nombres de usuario manualmente arriba.
          </div>
        `;
        return;
      }

      let html = '';
      userList.forEach(u => {
        const isChecked = this.selectedUsers.has(u.username);
        const errorBadge = u.errors > 0 
          ? `<span style="background:rgba(239,68,68,0.15); color:#ef4444; border:1px solid rgba(239,68,68,0.3); font-size:0.68rem; font-weight:800; padding:1px 6px; border-radius:10px;">${u.errors} fallas</span>`
          : `<span style="background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3); font-size:0.68rem; font-weight:700; padding:1px 6px; border-radius:10px;">OK</span>`;

        html += `
          <label class="user-trace-checkbox-item ${isChecked ? 'selected' : ''}" style="display:flex; align-items:center; justify-content:space-between; padding:6px 10px; border-radius:6px; margin-bottom:4px; cursor:pointer; background:${isChecked ? 'rgba(2,132,199,0.12)' : 'var(--bg-primary)'}; border:1px solid ${isChecked ? '#0284c7' : 'var(--border-color)'}; font-size:0.8rem;">
            <div style="display:flex; align-items:center; gap:8px; overflow:hidden;">
              <input type="checkbox" value="${escapeHtml(u.username)}" ${isChecked ? 'checked' : ''} onchange="window.UserTraceReport.toggleUser('${escapeHtml(u.username)}', this.checked)" style="cursor:pointer;">
              <span style="font-weight:700; color:var(--text-main); font-family:'JetBrains Mono', monospace;">${escapeHtml(u.username)}</span>
            </div>
            <div style="display:flex; align-items:center; gap:6px;">
              <span style="font-size:0.7rem; color:var(--text-muted);">${u.totalEvents} txs</span>
              ${errorBadge}
            </div>
          </label>
        `;
      });

      container.innerHTML = html;
    },

    toggleUser(username, isChecked) {
      if (isChecked) {
        this.selectedUsers.add(username);
      } else {
        this.selectedUsers.delete(username);
      }
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

    selectTopErrorUsers(count = 5, triggerGen = true) {
      this.selectedUsers.clear();
      const sorted = Object.values(this.cachedStats).sort((a, b) => b.errors - a.errors);
      sorted.slice(0, count).forEach(u => this.selectedUsers.add(u.username));
      this.renderUserChecklist();
      if (triggerGen) this.generateReport();
    },

    selectAllUsers() {
      Object.keys(this.cachedStats).forEach(u => this.selectedUsers.add(u));
      this.renderUserChecklist();
      this.generateReport();
    },

    clearSelection() {
      this.selectedUsers.clear();
      this.renderUserChecklist();
      this.generateReport();
    },

    getKbDescription(code) {
      const kb = {
        '5202404': { title: 'Database Pool Exhausted', desc: 'Agotamiento del pool de conexiones en identityguard.properties. El servicio no puede conectar a la BD.', sev: 'CRITICAL' },
        '5205150': { title: 'Client Secret Invalid', desc: 'Fallo de autorización por Client Secret o credencial de API inválida / vencida.', sev: 'CRITICAL' },
        '5202000': { title: 'Authentication Successful', desc: 'Autenticación multifactor o validación de credenciales completada con éxito.', sev: 'INFO' },
        '5202001': { title: 'Invalid Password / Secret', desc: 'Contraseña incorrecta o secreto MFA desincronizado.', sev: 'ERROR' },
        '5202002': { title: 'Account Locked / Disabled', desc: 'Cuenta bloqueada por exceso de intentos fallidos o directiva de seguridad.', sev: 'WARN' },
        'AUD106': { title: 'Administration Pulse OK', desc: 'Chequeo periódico de salud y latido del servicio Entrust Administration.', sev: 'INFO' },
        'AUD101': { title: 'User Account Created', desc: 'Aprovisionamiento de nueva identidad o credencial en el repositorio.', sev: 'INFO' },
        'AUD110': { title: 'User State Changed', desc: 'Modificación de estado, desbloqueo o actualización de token de seguridad.', sev: 'INFO' }
      };
      return kb[code] || { title: 'Evento Entrust General', desc: 'Transacción auditada en el núcleo de autenticación.', sev: 'INFO' };
    },

    generateReport() {
      const container = document.getElementById('user-trace-report-preview');
      if (!container) return;

      if (this.selectedUsers.size === 0) {
        container.innerHTML = `
          <div style="padding:60px 20px; text-align:center; color:var(--text-muted);">
            <div style="font-size:3rem; margin-bottom:12px;">👤</div>
            <div style="font-size:1.1rem; font-weight:700; color:var(--text-main);">Selecciona uno o más usuarios</div>
            <div style="font-size:0.8rem; margin-top:6px;">Utiliza el panel izquierdo para marcar los usuarios que deseas incluir en este informe de trazabilidad y seguridad.</div>
          </div>
        `;
        return;
      }

      const allLogs = this.getAllLogs();
      const targetUsers = Array.from(this.selectedUsers);
      const activeClient = this.getClientProfile();

      // Filtrar logs de los usuarios seleccionados
      const userLogs = allLogs.filter(log => {
        let u = log.user || log.usuario || log.username;
        if (!u && log.message) {
          const match = log.message.match(/User:\s*([a-zA-Z0-9_\.\-]+)/i) || log.message.match(/usuario\s*[:=]\s*([a-zA-Z0-9_\.\-]+)/i);
          if (match) u = match[1];
        }
        return u && targetUsers.includes(u.trim());
      });

      // Calcular métricas consolidadas
      let totalTx = userLogs.length;
      let totalErrors = 0;
      let totalCritical = 0;
      let totalSuccess = 0;
      const uniqueIps = new Set();
      const uniqueNodes = new Set();
      const codesSummary = {};

      userLogs.forEach(l => {
        const lvl = (l.level || '').toUpperCase();
        if (lvl === 'CRITICAL' || lvl === 'FATAL') {
          totalCritical++;
          totalErrors++;
        } else if (lvl === 'ERROR') {
          totalErrors++;
        } else {
          totalSuccess++;
        }
        if (l.ip) uniqueIps.add(l.ip);
        if (l.server || l.node) uniqueNodes.add(l.server || l.node);
        const code = String(l.code || 'SYS-EVENT');
        codesSummary[code] = (codesSummary[code] || 0) + 1;
      });

      const successRate = totalTx > 0 ? ((totalSuccess / totalTx) * 100).toFixed(1) : '100';
      const nowFormatted = new Date().toLocaleString('es-VE', { dateStyle: 'long', timeStyle: 'medium' });

      // Generar HTML del Informe
      let reportHtml = `
        <div id="user-trace-printable-document" style="font-family:'Inter', system-ui, sans-serif; color:#0f172a; line-height:1.5;">
          
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
              <span style="background:rgba(2,132,199,0.12); color:#0284c7; border:1px solid #0284c7; font-weight:800; font-size:0.72rem; padding:3px 10px; border-radius:12px; display:inline-block; margin-bottom:4px;">INFORME TÉCNICO OFICIAL</span>
              <div style="font-size:0.75rem; color:#64748b;">Ref: <strong style="color:#0f172a;">IT-TRACE-${Date.now().toString().slice(-6)}</strong></div>
            </div>
          </div>

          <!-- TÍTULO Y METADATOS DEL INFORME -->
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-left:5px solid #0284c7; padding:16px 20px; border-radius:8px; margin-bottom:24px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
              <div>
                <h1 style="font-size:1.35rem; font-weight:800; color:#0a3d6d; margin:0 0 6px 0;">INFORME DE TRAZABILIDAD Y SEGURIDAD DE USUARIOS</h1>
                <div style="font-size:0.82rem; color:#334155;">Análisis técnico forense, correlación de eventos y diagnóstico de incidentes de autenticación</div>
              </div>
              <div style="font-size:0.78rem; text-align:right; color:#475569;">
                <div><strong>Cliente:</strong> ${escapeHtml(activeClient.name)}</div>
                <div><strong>Entorno:</strong> ${escapeHtml(activeClient.type || 'IDaaS Cloud / OnPremise')}</div>
                <div><strong>Fecha de Emisión:</strong> ${nowFormatted}</div>
                <div><strong>Auditor Responsable:</strong> Tomás Acosta (IT Servicios)</div>
              </div>
            </div>
          </div>

          <!-- RESUMEN EJECUTIVO (KPIs) -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:14px;">1. RESUMEN EJECUTIVO DE TRAZABILIDAD</h2>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:12px;">
              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #0284c7; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Usuarios Analizados</div>
                <div style="font-size:1.6rem; font-weight:800; color:#0284c7; font-family:'JetBrains Mono', monospace; margin:4px 0;">${targetUsers.length}</div>
                <div style="font-size:0.68rem; color:#64748b;">Seleccionados</div>
              </div>
              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #0a3d6d; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Total Transacciones</div>
                <div style="font-size:1.6rem; font-weight:800; color:#0a3d6d; font-family:'JetBrains Mono', monospace; margin:4px 0;">${totalTx}</div>
                <div style="font-size:0.68rem; color:#64748b;">Eventos registrados</div>
              </div>
              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid ${totalErrors > 0 ? '#ef4444' : '#10b981'}; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Fallas / Errores</div>
                <div style="font-size:1.6rem; font-weight:800; color:${totalErrors > 0 ? '#ef4444' : '#10b981'}; font-family:'JetBrains Mono', monospace; margin:4px 0;">${totalErrors}</div>
                <div style="font-size:0.68rem; color:#64748b;">${totalCritical} Críticos</div>
              </div>
              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #10b981; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Tasa de Éxito</div>
                <div style="font-size:1.6rem; font-weight:800; color:#10b981; font-family:'JetBrains Mono', monospace; margin:4px 0;">${successRate}%</div>
                <div style="font-size:0.68rem; color:#64748b;">Conformidad</div>
              </div>
              <div style="background:#fff; border:1px solid #cbd5e1; border-top:3px solid #6366f1; padding:12px; border-radius:6px; text-align:center;">
                <div style="font-size:0.72rem; font-weight:700; color:#64748b; text-transform:uppercase;">Nodos &amp; Servidores</div>
                <div style="font-size:1.6rem; font-weight:800; color:#6366f1; font-family:'JetBrains Mono', monospace; margin:4px 0;">${uniqueNodes.size || 1}</div>
                <div style="font-size:0.68rem; color:#64748b;">${uniqueIps.size} IPs de origen</div>
              </div>
            </div>
          </div>

          <!-- DESGLOSE POR CÓDIGO DE EVENTO -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:12px;">2. MATRIZ DE CÓDIGOS DE AUDITORÍA &amp; ERRORES DETECTADOS</h2>
            <table style="width:100%; border-collapse:collapse; font-size:0.78rem; background:#fff; border:1px solid #cbd5e1; border-radius:6px; overflow:hidden;">
              <thead>
                <tr style="background:#0a3d6d; color:#fff; text-align:left;">
                  <th style="padding:8px 12px;">Código Entrust</th>
                  <th style="padding:8px 12px;">Frecuencia</th>
                  <th style="padding:8px 12px;">Severidad</th>
                  <th style="padding:8px 12px;">Significado Oficial &amp; Diagnóstico</th>
                </tr>
              </thead>
              <tbody>
      `;

      Object.entries(codesSummary).forEach(([code, count], idx) => {
        const kbInfo = this.getKbDescription(code);
        const sevBg = kbInfo.sev === 'CRITICAL' ? '#fee2e2' : kbInfo.sev === 'ERROR' ? '#ffedd5' : kbInfo.sev === 'WARN' ? '#fef3c7' : '#e0f2fe';
        const sevCol = kbInfo.sev === 'CRITICAL' ? '#dc2626' : kbInfo.sev === 'ERROR' ? '#ea580c' : kbInfo.sev === 'WARN' ? '#d97706' : '#0284c7';

        reportHtml += `
          <tr style="border-bottom:1px solid #e2e8f0; background:${idx % 2 === 0 ? '#ffffff' : '#f8fafc'};">
            <td style="padding:8px 12px; font-family:'JetBrains Mono', monospace; font-weight:700; color:#0a3d6d;">${escapeHtml(code)}</td>
            <td style="padding:8px 12px; font-weight:700;">${count} veces</td>
            <td style="padding:8px 12px;">
              <span style="background:${sevBg}; color:${sevCol}; font-weight:700; font-size:0.7rem; padding:2px 8px; border-radius:4px; display:inline-block;">${kbInfo.sev}</span>
            </td>
            <td style="padding:8px 12px;">
              <strong>${escapeHtml(kbInfo.title)}:</strong> <span style="color:#475569;">${escapeHtml(kbInfo.desc)}</span>
            </td>
          </tr>
        `;
      });

      reportHtml += `
              </tbody>
            </table>
          </div>

          <!-- EXPEDIENTE DETALLADO POR USUARIO -->
          <div style="margin-bottom:24px;">
            <h2 style="font-size:1rem; font-weight:800; color:#0a3d6d; border-bottom:1.5px solid #e2e8f0; padding-bottom:6px; margin-bottom:12px;">3. EXPEDIENTES TÉCNICOS INDIVIDUALES</h2>
      `;

      targetUsers.forEach(user => {
        const uStat = this.cachedStats[user] || { totalEvents: 0, errors: 0, criticals: 0, successes: 0, ips: new Set(), nodes: new Set(), codes: {} };
        const userLogsFiltered = userLogs.filter(l => {
          let u = l.user || l.usuario || l.username;
          if (!u && l.message) {
            const match = l.message.match(/User:\s*([a-zA-Z0-9_\.\-]+)/i) || log.message.match(/usuario\s*[:=]\s*([a-zA-Z0-9_\.\-]+)/i);
            if (match) u = match[1];
          }
          return u && u.trim() === user;
        });

        reportHtml += `
          <div style="border:1px solid #cbd5e1; border-radius:8px; margin-bottom:16px; overflow:hidden; background:#fff;">
            <div style="background:#f1f5f9; padding:10px 16px; border-bottom:1px solid #cbd5e1; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
              <div style="display:flex; align-items:center; gap:8px;">
                <span style="background:#0a3d6d; color:#fff; font-size:0.75rem; font-weight:800; padding:2px 8px; border-radius:4px;">USUARIO</span>
                <span style="font-size:1rem; font-weight:800; color:#0a3d6d; font-family:'JetBrains Mono', monospace;">${escapeHtml(user)}</span>
              </div>
              <div style="font-size:0.78rem; color:#475569; display:flex; gap:12px;">
                <span>Total: <strong>${uStat.totalEvents} txs</strong></span>
                <span style="color:${uStat.errors > 0 ? '#ef4444' : '#10b981'}; font-weight:700;">Fallas: <strong>${uStat.errors}</strong></span>
                <span>Nodos: <strong>${Array.from(uStat.nodes).join(', ') || 'Core'}</strong></span>
              </div>
            </div>

            <!-- Tabla de Cronología del Usuario -->
            <div style="padding:12px 16px;">
              <div style="font-size:0.8rem; font-weight:700; color:#334155; margin-bottom:8px;">Cronología de Transacciones e Interacciones:</div>
              <table style="width:100%; border-collapse:collapse; font-size:0.75rem;">
                <thead>
                  <tr style="background:#f8fafc; border-bottom:1.5px solid #cbd5e1; color:#475569; text-align:left;">
                    <th style="padding:6px 10px; width:160px;">Timestamp</th>
                    <th style="padding:6px 10px; width:100px;">Servidor</th>
                    <th style="padding:6px 10px; width:90px;">Código</th>
                    <th style="padding:6px 10px; width:80px;">Nivel</th>
                    <th style="padding:6px 10px;">Mensaje de Diagnóstico</th>
                  </tr>
                </thead>
                <tbody>
        `;

        userLogsFiltered.slice(0, 50).forEach((l, idx) => {
          const lvl = (l.level || 'INFO').toUpperCase();
          const lvlBg = lvl === 'CRITICAL' ? '#fee2e2' : lvl === 'ERROR' ? '#ffedd5' : lvl === 'WARN' ? '#fef3c7' : '#e0f2fe';
          const lvlCol = lvl === 'CRITICAL' ? '#dc2626' : lvl === 'ERROR' ? '#ea580c' : lvl === 'WARN' ? '#d97706' : '#0284c7';

          reportHtml += `
            <tr style="border-bottom:1px solid #f1f5f9; background:${idx % 2 === 0 ? '#ffffff' : '#fafafa'};">
              <td style="padding:6px 10px; font-family:'JetBrains Mono', monospace; color:#64748b;">${escapeHtml(l.timestamp || '-')}</td>
              <td style="padding:6px 10px; font-weight:600; color:#334155;">${escapeHtml(l.server || l.node || 'Primario')}</td>
              <td style="padding:6px 10px; font-family:'JetBrains Mono', monospace; font-weight:700; color:#0a3d6d;">${escapeHtml(l.code || 'AUD')}</td>
              <td style="padding:6px 10px;">
                <span style="background:${lvlBg}; color:${lvlCol}; font-weight:700; font-size:0.68rem; padding:1px 6px; border-radius:3px;">${lvl}</span>
              </td>
              <td style="padding:6px 10px; color:#1e293b;">${escapeHtml(l.message || l.details || '-')}</td>
            </tr>
          `;
        });

        if (userLogsFiltered.length > 50) {
          reportHtml += `
            <tr>
              <td colspan="5" style="padding:8px; text-align:center; color:#64748b; background:#f8fafc; font-style:italic;">
                ... Mostrando las primeras 50 transacciones de un total de ${userLogsFiltered.length} eventos (descargue el CSV/Excel para la totalidad).
              </td>
            </tr>
          `;
        }

        reportHtml += `
                </tbody>
              </table>
            </div>
          </div>
        `;
      });

      // CONCLUSIONES Y PLAN DE ACCIÓN
      reportHtml += `
          </div>

          <!-- CONCLUSIONES Y RECOMENDACIONES -->
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-top:3px solid #0a3d6d; padding:16px 20px; border-radius:8px; margin-top:20px;">
            <h3 style="font-size:0.95rem; font-weight:800; color:#0a3d6d; margin:0 0 8px 0;">4. RECOMENDACIONES TÉCNICAS &amp; PLAN DE ACCIÓN</h3>
            <ul style="font-size:0.8rem; color:#334155; padding-left:20px; line-height:1.6; margin:0;">
              ${totalCritical > 0 ? '<li><strong>Ajuste de Capacidad de Conexiones:</strong> Se detectaron eventos críticos de agotamiento de pool de base de datos (`5202404`). Se recomienda incrementar `maxPoolSize` en `identityguard.properties`.</li>' : ''}
              ${totalErrors > 0 ? '<li><strong>Revalidación de Secretos y Credenciales:</strong> Se registraron fallos de autorización (`5205150`). Verificar la validez de los Client Secrets en la consola IDaaS / API Gateway.</li>' : ''}
              <li><strong>Monitoreo Continuo:</strong> Mantener la escucha activa en el receptor Syslog UDP/WebSocket para auditoría en tiempo real.</li>
              <li><strong>Conformidad Sudeban &amp; ISO 27001:</strong> El presente informe certifica la trazabilidad y no-repudio de las interacciones registradas.</li>
            </ul>
          </div>

          <!-- PIE DE PÁGINA -->
          <div style="margin-top:24px; padding-top:12px; border-top:1px solid #cbd5e1; display:flex; justify-content:space-between; align-items:center; font-size:0.72rem; color:#64748b;">
            <span>IT Servicios de Venezuela, S.A. — www.itservicios-latam.com</span>
            <span>Documento generado para fines de Auditoría y Soporte Técnico Especializado</span>
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

      const htmlContent = `
        <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
        <head>
          <meta charset='utf-8'>
          <title>Informe de Trazabilidad y Seguridad de Usuarios</title>
          <style>
            body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #111827; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #cbd5e1; padding: 6px 10px; font-size: 9.5pt; }
            th { background-color: #0a3d6d; color: #ffffff; }
          </style>
        </head>
        <body>
          ${el.innerHTML}
        </body>
        </html>
      `;

      const blob = new Blob(['\ufeff', htmlContent], { type: 'application/msword' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    downloadExcel() {
      this.downloadCsv();
    },

    downloadCsv() {
      const allLogs = this.getAllLogs();
      const targetUsers = Array.from(this.selectedUsers);
      if (targetUsers.length === 0) {
        alert('Por favor selecciona al menos un usuario.');
        return;
      }

      const userLogs = allLogs.filter(log => {
        let u = log.user || log.usuario || log.username;
        if (!u && log.message) {
          const match = log.message.match(/User:\s*([a-zA-Z0-9_\.\-]+)/i) || log.message.match(/usuario\s*[:=]\s*([a-zA-Z0-9_\.\-]+)/i);
          if (match) u = match[1];
        }
        return u && targetUsers.includes(u.trim());
      });

      let csv = 'Timestamp,Usuario,Servidor,Nivel,Codigo_Entrust,Descripcion_Oficial,Mensaje_Completo\n';
      userLogs.forEach(l => {
        let u = l.user || l.usuario || l.username || '';
        if (!u && l.message) {
          const match = l.message.match(/User:\s*([a-zA-Z0-9_\.\-]+)/i) || log.message.match(/usuario\s*[:=]\s*([a-zA-Z0-9_\.\-]+)/i);
          if (match) u = match[1];
        }
        const kb = this.getKbDescription(String(l.code || ''));
        const cleanMsg = (l.message || l.details || '').replace(/[\r\n]+/g, ' ').replace(/"/g, '""');
        csv += `"${l.timestamp || ''}","${u}","${l.server || l.node || ''}","${l.level || ''}","${l.code || ''}","${kb.title}","${cleanMsg}"\n`;
      });

      const blob = new Blob(['\ufeff', csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Trazabilidad_Usuarios_${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    printReport() {
      const el = document.getElementById('user-trace-printable-document');
      if (!el) return;

      const printWindow = window.open('', '_blank', 'width=900,height=700');
      printWindow.document.write(`
        <html>
        <head>
          <title>Informe de Trazabilidad y Seguridad de Usuarios - IT Servicios</title>
          <style>
            body { font-family: system-ui, sans-serif; padding: 20px; color: #0f172a; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #cbd5e1; padding: 6px 10px; font-size: 11px; }
            th { background: #0a3d6d !important; color: #fff !important; }
            @media print {
              body { padding: 0; }
              @page { margin: 15mm; }
            }
          </style>
        </head>
        <body>
          ${el.innerHTML}
        </body>
        </html>
      `);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
        printWindow.close();
      }, 300);
    },

    copyMarkdown() {
      const el = document.getElementById('user-trace-printable-document');
      if (!el) return;

      const text = el.innerText;
      navigator.clipboard.writeText(text).then(() => {
        alert('📋 ¡Informe de Trazabilidad copiado al portapapeles con éxito!');
      }).catch(() => {
        alert('No se pudo copiar automáticamente.');
      });
    }
  };

  window.UserTraceReport = UserTraceReport;

  // Auto-init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => UserTraceReport.init());
  } else {
    UserTraceReport.init();
  }

})(window);
