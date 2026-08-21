/**
 * APP.JS: Controlador Principal del Dashboard de Diagnóstico de Logs, Auditoría y Manuales
 * Soporta Modo Claro Corporativo / Oscuro, Entrust OnPremise y IDaaS Cloud.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Estado Global
  const state = {
    logs: [],
    filteredLogs: [],
    selectedLog: null,
    isStreaming: false,
    streamInterval: null,
    charts: {},
    currentManualVersion: 'vEntrust',
    activeFilterMode: null,
    theme: localStorage.getItem('app_theme') || 'light',
    clientProfiles: [],
    activeClientId: 'mercantil'
  };

  // Referencias DOM
  const dom = {
    navBtns: document.querySelectorAll('.nav-btn'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    logScrollArea: document.getElementById('log-scroll-area'),
    totalLogsCount: document.getElementById('total-logs-count'),
    criticalCount: document.getElementById('critical-count'),
    warningCount: document.getElementById('warning-count'),
    healthIndex: document.getElementById('health-index'),
    diagnosticCard: document.getElementById('diagnostic-card'),
    searchLogInput: document.getElementById('search-log-input'),
    filterClientSelect: document.getElementById('filter-client-select'),
    filterLevelSelect: document.getElementById('filter-level-select'),
    filterTypeSelect: document.getElementById('filter-type-select'),
    presetSelector: document.getElementById('preset-selector'),
    analysisStatusBar: document.getElementById('analysis-status-bar'),
    analysisStatusText: document.getElementById('analysis-status-text'),
    analysisStatusDetail: document.getElementById('analysis-status-detail'),
    analysisStatusSpinner: document.getElementById('analysis-status-spinner'),
    btnToggleStream: document.getElementById('btn-toggle-stream'),
    btnToggleTheme: document.getElementById('btn-toggle-theme'),
    fileInput: document.getElementById('file-input'),
    btnExportReport: document.getElementById('btn-export-report'),
    btnGenerateExecReport: document.getElementById('btn-generate-exec-report'),
    execReportModal: document.getElementById('exec-report-modal'),
    execReportContainer: document.getElementById('exec-report-container'),
    btnCloseExecReport: document.getElementById('btn-close-exec-report'),
    btnPrintExecReport: document.getElementById('btn-print-exec-report'),
    cardEntrustErrors: document.getElementById('card-entrust-errors'),
    cardAuditAlerts: document.getElementById('card-audit-alerts'),
    cardTotalLogs: document.getElementById('card-total-logs'),
    cardHealth: document.getElementById('card-health'),
    activeFilterBanner: document.getElementById('active-filter-banner'),
    activeFilterText: document.getElementById('active-filter-text'),
    btnClearActiveFilter: document.getElementById('btn-clear-active-filter'),
    entrustErrorsModal: document.getElementById('entrust-errors-modal'),
    entrustErrorsModalList: document.getElementById('entrust-errors-modal-list'),
    btnCloseEntrustModal: document.getElementById('btn-close-entrust-modal'),
    btnCloseEntrustModal2: document.getElementById('btn-close-entrust-modal-2'),
    btnGoToAnalyzer520: document.getElementById('btn-go-to-analyzer-520'),
    manualVersionSelect: document.getElementById('manual-version-select'),
    manualTocList: document.getElementById('manual-toc-list'),
    manualIframe: document.getElementById('manual-iframe'),
    manualSearchInput: document.getElementById('manual-search-input'),
    btnOpenAddManualModal: document.getElementById('btn-open-add-manual'),
    addManualModal: document.getElementById('add-manual-modal'),
    btnCloseAddManual: document.getElementById('btn-close-add-manual'),
    btnSaveCustomManual: document.getElementById('btn-save-custom-manual'),
    kbRulesList: document.getElementById('kb-rules-list'),
    btnOpenAddKbModal: document.getElementById('btn-open-add-kb'),
    addKbModal: document.getElementById('add-kb-modal'),
    btnCloseAddKb: document.getElementById('btn-close-add-kb'),
    btnSaveCustomKb: document.getElementById('btn-save-custom-kb'),
    traceWaterfallContainer: document.getElementById('trace-waterfall-container')
  };

  // Inicialización Segura por Módulos
  try { initTheme(); } catch (e) { console.error('Error al inicializar Tema:', e); }
  try { initClientProfilesModule(); } catch (e) { console.error('Error al inicializar Perfiles de Cliente:', e); }
  try { initNavigation(); } catch (e) { console.error('Error al inicializar Navegación:', e); }
  try { initCharts(); } catch (e) { console.error('Error al inicializar Gráficos:', e); }
  try { initPresets(); } catch (e) { console.error('Error al inicializar Escenarios:', e); }
  try { initManualsModule(); } catch (e) { console.error('Error al inicializar Manuales:', e); }
  try { initKbModule(); } catch (e) { console.error('Error al inicializar KB:', e); }
  try { initMetricCardsInteractivity(); } catch (e) { console.error('Error al inicializar Tarjetas:', e); }
  try { initExecReportModule(); } catch (e) { console.error('Error al inicializar Informe:', e); }
  try { initEventListeners(); } catch (e) { console.error('Error al inicializar EventListeners:', e); }

  // Cargar por defecto el escenario de Entrust IdentityGuard OnPremise
  try { loadPresetScenario('entrust_idg'); } catch (e) { console.error('Error al cargar escenario inicial:', e); }

  /* ==========================================================================
     0.1 GESTIÓN Y REGISTRO DE PERFILES DE CLIENTES & ENTORNOS ENTRUST
     ========================================================================== */
  const defaultClients = [
    {
      id: 'mercantil',
      name: 'Banco Mercantil C.A.',
      platform: 'Entrust IdentityGuard OnPremise',
      version: 'Release 13.0',
      build: '13.0.12.4',
      contact: 'Vicepresidencia de Ciberseguridad & TI',
      engineer: 'Tomás Acosta'
    },
    {
      id: 'banesco',
      name: 'Banesco Banco Universal',
      platform: 'Entrust IdentityGuard OnPremise',
      version: 'Release 12.0',
      build: 'Issue 5 (Build 12.4.0)',
      contact: 'Gerencia de Tecnología & Operaciones',
      engineer: 'Tomás Acosta'
    },
    {
      id: 'idaas_cloud',
      name: 'IDaaS Cloud Latam',
      platform: 'Entrust IDaaS Cloud',
      version: 'IDaaS Cloud v2026',
      build: 'Cloud-Gateway-8921',
      contact: 'Departamento de SSO & Push MFA',
      engineer: 'Tomás Acosta'
    }
  ];

  function loadClientProfiles() {
    try {
      const stored = localStorage.getItem('custom_client_profiles_v3');
      if (stored) {
        state.clientProfiles = JSON.parse(stored);
      } else {
        state.clientProfiles = defaultClients;
        localStorage.setItem('custom_client_profiles_v3', JSON.stringify(defaultClients));
      }
    } catch (e) {
      state.clientProfiles = defaultClients;
    }
    state.activeClientId = state.clientProfiles[0]?.id || 'mercantil';
    populateClientSessionSelectors();
  }

  function getActiveClientProfile() {
    const toolbarVal = dom?.filterClientSelect?.value || document.getElementById('filter-client-select')?.value;
    if (toolbarVal && toolbarVal !== 'ALL') {
      const matchByToolbar = state.clientProfiles.find(c => c.name.toLowerCase() === toolbarVal.toLowerCase());
      if (matchByToolbar) return matchByToolbar;
      return {
        name: toolbarVal,
        platform: 'Entrust IdentityGuard OnPremise',
        version: 'Release 13.0',
        build: 'General',
        contact: 'Departamento de TI',
        engineer: 'Tomás Acosta'
      };
    }

    return state.clientProfiles.find(c => c.id === state.activeClientId) || state.clientProfiles[0] || {
      name: 'Cliente General',
      platform: 'Entrust IdentityGuard OnPremise',
      version: 'Release 13.0',
      build: 'General',
      contact: 'Departamento de TI',
      engineer: 'Tomás Acosta'
    };
  }

  function renderRegisteredClientsList() {
    const listContainer = document.getElementById('registered-clients-list');
    if (!listContainer) return;

    if (!state.clientProfiles || state.clientProfiles.length === 0) {
      listContainer.innerHTML = '<div style="color:var(--text-muted); font-size:0.85rem; padding:8px;">No hay clientes registrados.</div>';
      return;
    }

    let html = '';
    state.clientProfiles.forEach(c => {
      const isActive = c.id === state.activeClientId;
      html += `
        <div style="display:flex; justify-content:space-between; align-items:center; background:${isActive ? 'rgba(56, 189, 248, 0.15)' : 'var(--bg-secondary)'}; border:1px solid ${isActive ? 'var(--it-blue)' : 'var(--border-color)'}; padding:8px 12px; border-radius:6px;">
          <div>
            <span style="font-weight:700; color:var(--text-main);">🏢 ${escapeHtml(c.name)}</span>
            <span style="font-size:0.75rem; color:var(--text-muted); margin-left:8px;">(${escapeHtml(c.platform)} - ${escapeHtml(c.version)})</span>
            ${isActive ? '<span style="font-size:0.7rem; background:#0284c7; color:#fff; padding:2px 6px; border-radius:4px; margin-left:8px; font-weight:600;">ACTIVO</span>' : ''}
          </div>
          <div style="display:flex; gap:6px;">
            <button type="button" class="btn btn-primary" style="padding:2px 8px; font-size:0.75rem;" onclick="window.selectActiveClientGlobal('${c.id}');">Usar</button>
            <button type="button" class="btn" style="padding:2px 8px; font-size:0.75rem; color:#ef4444; border-color:rgba(239, 68, 68, 0.4);" onclick="window.deleteClientProfileGlobal('${c.id}');">🗑️ Eliminar</button>
          </div>
        </div>
      `;
    });
    listContainer.innerHTML = html;
  }

  window.selectActiveClientGlobal = function(clientId) {
    state.activeClientId = clientId;
    const currentClient = getActiveClientProfile();
    populateClientSessionSelectors();
    showAnalysisStatus(false, `🏢 Sesión de Cliente Cambiada: ${currentClient.name}`, `Plataforma: ${currentClient.platform} | Versión: ${currentClient.version} (${currentClient.build})`);
  };

  window.deleteClientProfileGlobal = function(clientId) {
    const clientToDelete = state.clientProfiles.find(c => c.id === clientId);
    if (!clientToDelete) return;

    if (!confirm(`¿Está seguro de que desea eliminar el perfil del cliente "${clientToDelete.name}"?`)) {
      return;
    }

    state.clientProfiles = state.clientProfiles.filter(c => c.id !== clientId);

    if (state.activeClientId === clientId) {
      state.activeClientId = state.clientProfiles[0]?.id || null;
    }

    try {
      localStorage.setItem('custom_client_profiles_v3', JSON.stringify(state.clientProfiles));
    } catch(e) {
      console.warn('LocalStorage error:', e);
    }

    populateClientSessionSelectors();
    showAnalysisStatus(false, `🗑️ Cliente Eliminado: ${clientToDelete.name}`, `El perfil del cliente ha sido removido exitosamente.`);
  };

  function populateClientSessionSelectors() {
    const headerSelect = document.getElementById('active-client-session-select');
    const toolbarSelect = document.getElementById('filter-client-select');

    if (headerSelect) {
      headerSelect.innerHTML = '';
      (state.clientProfiles || []).forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = `🏢 ${c.name} (${c.version})`;
        headerSelect.appendChild(opt);
      });
      if (state.activeClientId) headerSelect.value = state.activeClientId;
    }

    if (toolbarSelect) {
      const currentVal = toolbarSelect.value || 'ALL';
      toolbarSelect.innerHTML = '<option value="ALL">🏢 Todos los Clientes</option>';
      (state.clientProfiles || []).forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.name;
        opt.textContent = `🏢 ${c.name}`;
        toolbarSelect.appendChild(opt);
      });
      toolbarSelect.value = currentVal;
    }

    renderRegisteredClientsList();
  }

  function saveClientProfileGlobal() {
    const nameInput = document.getElementById('client-input-name');
    const platformInput = document.getElementById('client-input-platform');
    const versionInput = document.getElementById('client-input-version');
    const buildInput = document.getElementById('client-input-build');
    const contactInput = document.getElementById('client-input-contact');
    const engineerInput = document.getElementById('client-input-engineer');

    const name = nameInput ? nameInput.value.trim() : '';
    const platform = platformInput ? platformInput.value : 'Entrust IdentityGuard OnPremise';
    const version = versionInput ? versionInput.value : 'Release 13.0';
    const build = (buildInput && buildInput.value.trim()) ? buildInput.value.trim() : 'General';
    const contact = (contactInput && contactInput.value.trim()) ? contactInput.value.trim() : 'Departamento de TI';
    const engineer = (engineerInput && engineerInput.value.trim()) ? engineerInput.value.trim() : 'Tomás Acosta';

    if (!name) {
      alert('Por favor ingrese el nombre del cliente u organización.');
      return;
    }

    const newId = 'client-' + Date.now();
    const newProfile = { id: newId, name, platform, version, build, contact, engineer };

    if (!state.clientProfiles) state.clientProfiles = [];
    state.clientProfiles.push(newProfile);
    state.activeClientId = newId;

    try {
      localStorage.setItem('custom_client_profiles_v3', JSON.stringify(state.clientProfiles));
    } catch(e) {
      console.warn('No se pudo guardar en localStorage:', e);
    }

    populateClientSessionSelectors();

    const modal = document.getElementById('client-modal');
    if (modal) modal.classList.remove('active');

    if (nameInput) nameInput.value = '';
    if (buildInput) buildInput.value = '';
    if (contactInput) contactInput.value = '';

    showAnalysisStatus(false, `✅ ¡Nuevo Perfil de Cliente Registrado!`, `Se configuró a ${name} (${version}) como el cliente activo para análisis e informes.`);
    alert(`¡Perfil de Cliente Creado Exitosamente!\n\nCliente: ${name}\nPlataforma: ${platform}\nVersión: ${version} (${build})\n\nTodos los informes de diagnóstico generados serán dirigidos a este cliente.`);
  }

  window.saveClientProfileGlobal = saveClientProfileGlobal;

  function initClientProfilesModule() {
    loadClientProfiles();

    const headerSelect = document.getElementById('active-client-session-select');
    const btnOpenModal = document.getElementById('btn-open-create-client-modal');
    const btnCloseModal = document.getElementById('btn-close-client-modal');
    const btnSaveClient = document.getElementById('btn-save-client-profile');
    const modal = document.getElementById('client-modal');

    if (headerSelect) {
      headerSelect.addEventListener('change', (e) => {
        state.activeClientId = e.target.value;
        const currentClient = getActiveClientProfile();
        showAnalysisStatus(false, `🏢 Sesión de Cliente Cambiada: ${currentClient.name}`, `Plataforma: ${currentClient.platform} | Versión: ${currentClient.version} (${currentClient.build})`);
      });
    }

    if (btnOpenModal && modal) {
      btnOpenModal.addEventListener('click', () => {
        modal.classList.add('active');
      });
    }

    if (btnCloseModal && modal) {
      btnCloseModal.addEventListener('click', () => {
        modal.classList.remove('active');
      });
    }

    if (btnSaveClient) {
      btnSaveClient.addEventListener('click', saveClientProfileGlobal);
    }
  }

  /* ==========================================================================
     0. CONTROLADOR DE TEMAS (MODO CLARO Y MODO OSCURO)
     ========================================================================== */
  function initTheme() {
    const btn = document.getElementById('btn-toggle-theme');
    applyTheme(state.theme);

    if (btn) {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        state.theme = state.theme === 'light' ? 'dark' : 'light';
        localStorage.setItem('app_theme', state.theme);
        applyTheme(state.theme);
      });
    }
  }

  function applyTheme(theme) {
    const btn = document.getElementById('btn-toggle-theme');
    if (theme === 'dark') {
      document.body.classList.add('dark-theme');
      if (btn) btn.textContent = '🌙 Modo Oscuro';
    } else {
      document.body.classList.remove('dark-theme');
      if (btn) btn.textContent = '☀️ Modo Claro';
    }
  }

  /* ==========================================================================
     1. NAVEGACIÓN POR PESTAÑAS
     ========================================================================== */
  function initNavigation() {
    dom.navBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        switchTab(targetTab);
      });
    });
  }

  function switchTab(targetTab) {
    dom.navBtns.forEach(b => b.classList.remove('active'));
    dom.tabPanes.forEach(p => p.classList.remove('active'));

    const btn = document.querySelector(`.nav-btn[data-tab="${targetTab}"]`);
    if (btn) btn.classList.add('active');

    const activePane = document.getElementById(`tab-${targetTab}`);
    if (activePane) activePane.classList.add('active');

    if (targetTab === 'manuals') {
      loadManual(state.currentManualVersion);
    }
  }

  /* ==========================================================================
     2. GENERADOR DE INFORMES DE DIAGNÓSTICO PRELIMINAR (EXECUTIVE REPORT)
     ========================================================================== */
  function initExecReportModule() {
    const btnGen = document.getElementById('btn-generate-exec-report');
    const btnClose = document.getElementById('btn-close-exec-report');
    const btnPrint = document.getElementById('btn-print-exec-report');
    const btnDownloadPdf = document.getElementById('btn-download-pdf-exec-report');

    if (btnGen) {
      btnGen.addEventListener('click', (e) => {
        e.preventDefault();
        generateExecutiveReport();
      });
    }

    if (btnClose) {
      btnClose.addEventListener('click', () => {
        const modal = document.getElementById('exec-report-modal');
        if (modal) modal.classList.remove('active');
      });
    }

    if (btnDownloadPdf) {
      btnDownloadPdf.addEventListener('click', () => {
        downloadExecutiveReportPdf();
      });
    }

    if (btnPrint) {
      btnPrint.addEventListener('click', () => {
        window.print();
      });
    }
  }

  function downloadExecutiveReportPdf() {
    const element = document.getElementById('exec-report-container');
    if (!element) return;

    const activeClient = getActiveClientProfile();
    const clientSanitized = (activeClient ? activeClient.name : 'Entrust').replace(/[^a-zA-Z0-9]/g, '_');
    const dateStamp = new Date().toISOString().slice(0, 10);

    const opt = {
      margin:       [8, 8, 8, 8],
      filename:     `Informe_Entrust_${clientSanitized}_${dateStamp}.pdf`,
      image:        { type: 'jpeg', quality: 0.98 },
      html2canvas:  { scale: 2, useCORS: true, logging: false, scrollX: 0, scrollY: 0 },
      jsPDF:        { unit: 'mm', format: 'letter', orientation: 'portrait' },
      pagebreak:    { mode: ['css', 'legacy'], avoid: ['tr', 'h3', 'div[style*="border"]'] }
    };

    if (window.html2pdf) {
      window.html2pdf().set(opt).from(element).save();
    } else {
      window.print();
    }
  }

  function generateExecutiveReport(onlyCatalogErrors = false) {
    const container = document.getElementById('exec-report-container');
    const modal = document.getElementById('exec-report-modal');
    if (!container || !modal) return;

    // Resolver de forma estricta el cliente destinatario activo
    const toolbarVal = dom.filterClientSelect?.value;
    let activeClient = null;

    if (toolbarVal && toolbarVal !== 'ALL') {
      activeClient = state.clientProfiles.find(c => c.name.toLowerCase() === toolbarVal.toLowerCase()) || {
        name: toolbarVal,
        platform: 'Entrust IdentityGuard OnPremise',
        version: 'Release 13.0',
        build: 'General',
        contact: 'Departamento de Ciberseguridad & TI',
        engineer: 'Tomás Acosta'
      };
    } else {
      activeClient = getActiveClientProfile();
    }

    const dateStr = new Date().toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'medium' });
    const targetLogs = onlyCatalogErrors 
      ? state.logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR' || /(520\d{4}|AUD\d+|IDaaS|SAML)/i.test(l.message))
      : state.logs;

    const totalCount = targetLogs.length;
    const criticalLogs = targetLogs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR');
    const warningLogs = targetLogs.filter(l => l.level === 'WARN' || l.level === 'WARNING');
    const infoLogs = targetLogs.filter(l => l.level === 'INFO');

    // Cálculo dinámico realista del Índice de Salud
    const critPenalty = criticalLogs.length > 0 ? Math.min(65, Math.max(5, (criticalLogs.length / (totalCount || 1)) * 100 * 5 + criticalLogs.length * 0.2)) : 0;
    const warnPenalty = warningLogs.length > 0 ? Math.min(25, (warningLogs.length / (totalCount || 1)) * 100 * 2 + warningLogs.length * 0.1) : 0;
    const calculatedHealth = Math.max(10, Math.round(100 - critPenalty - warnPenalty));
    const healthValStr = `${calculatedHealth}%`;

    // Formateador preciso de porcentaje
    const formatPctStr = (count, total) => {
      if (!total || total === 0 || !count || count === 0) return '0%';
      const pct = (count / total) * 100;
      if (pct < 0.01) return '<0.01%';
      if (pct < 1) return pct.toFixed(2) + '%';
      return pct.toFixed(1) + '%';
    };

    // Porciones visuales mínimas para el gráfico
    const visualCritPct = criticalLogs.length > 0 ? Math.max(6, (criticalLogs.length / (totalCount || 1)) * 100) : 0;
    const visualWarnPct = warningLogs.length > 0 ? Math.max(5, (warningLogs.length / (totalCount || 1)) * 100) : 0;

    const reportTitleText = onlyCatalogErrors 
      ? 'INFORME DE DIAGNÓSTICO EXCLUSIVO DE ERRORES IDENTITYGUARD [520xxx / IDaaS]'
      : 'INFORME DE DIAGNÓSTICO TÉCNICO DE INCIDENTES & AUDITORÍA ENTRUST';

    const reportScopeText = onlyCatalogErrors
      ? 'Filtro Exclusivo: Catálogo de Errores 520xxx y Fallos IDaaS Detectados'
      : 'Diagnóstico General de Logs e Incidentes';

    // Extraer incidentes para la tabla (Hasta 50 eventos principales)
    let incidentsHtml = '';
    const logsToInclude = criticalLogs.length > 0 ? criticalLogs.slice(0, 50) : targetLogs.slice(0, 25);

    logsToInclude.forEach((log, idx) => {
      const codeInLine = log.message.match(/(520\d{4}|AUD\d+)/)?.[1];
      const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message, codeInLine);

      if (onlyCatalogErrors) {
        incidentsHtml += `
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-left:5px solid #dc2626; border-radius:6px; padding:14px; page-break-inside:avoid; margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
              <div>
                <span style="background:#fee2e2; color:#dc2626; font-weight:bold; font-size:11px; padding:3px 8px; border-radius:4px; font-family:monospace;">${log.level}</span>
                <span style="font-family:monospace; font-size:12px; font-weight:bold; color:#0a3d6d; margin-left:8px;">#${idx + 1} - ${escapeHtml(log.service)}</span>
              </div>
              <span style="font-family:monospace; font-size:11px; color:#64748b;">${escapeHtml(log.timestamp)}</span>
            </div>

            <div style="background:#0f172a; color:#f87171; padding:10px 12px; border-radius:6px; font-family:Consolas, Monaco, monospace; font-size:11px; line-height:1.5; margin-bottom:10px; word-break:break-all;">
              ${escapeHtml(log.raw || log.message)}
            </div>

            <div style="font-size:12px; color:#1e293b; margin-bottom:6px;">
              <strong style="color:#0a3d6d;">Diagnóstico:</strong> ${escapeHtml(diag.meaning)}
            </div>
            <div style="font-size:12px; color:#b91c1c; margin-bottom:6px;">
              <strong style="color:#991b1b;">Causa Raíz:</strong> ${escapeHtml(diag.rootCause)}
            </div>
            <div style="font-size:11px; color:#047857; background:#ecfdf5; padding:8px 10px; border-radius:4px; border:1px solid #a7f3d0; white-space:pre-line;">
              <strong style="color:#065f46;">Remediación Inmediata:</strong><br>${escapeHtml(diag.remediation)}
            </div>
          </div>
        `;
      } else {
        incidentsHtml += `
          <tr style="background:${idx % 2 === 0 ? '#ffffff' : '#f8fafc'}; page-break-inside:avoid; break-inside:avoid;">
            <td style="padding:6px 8px; border:1px solid #cbd5e1; text-align:center;">
              <span style="white-space:nowrap; background:${log.level === 'CRITICAL' || log.level === 'ERROR' ? '#fee2e2' : '#e0f2fe'}; color:${log.level === 'CRITICAL' || log.level === 'ERROR' ? '#dc2626' : '#0284c7'}; padding:2px 6px; border-radius:3px; font-weight:bold; font-size:10px;">#${idx + 1} ${log.level}</span>
            </td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-family:monospace; font-size:10px; color:#0f172a; word-break:break-all;">${escapeHtml(log.service)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1;">
              <strong style="color:#0a3d6d; font-size:11px;">${escapeHtml(diag.title)}</strong><br>
              <span style="font-size:10px; color:#475569; line-height:1.3;">${escapeHtml(diag.meaning)}</span>
            </td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; color:#b91c1c; font-weight:600; line-height:1.3;">${escapeHtml(diag.rootCause)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; color:#047857; line-height:1.3; white-space:pre-line;">${escapeHtml(diag.remediation)}</td>
          </tr>
        `;
      }
    });

    // Frecuencia de códigos de error 520xxx / AUDxxx
    const codeCounts = {};
    targetLogs.forEach(l => {
      const codeMatch = l.message.match(/(520\d{4}|AUD\d+)/i);
      if (codeMatch) {
        const code = codeMatch[1].toUpperCase();
        codeCounts[code] = (codeCounts[code] || 0) + 1;
      }
    });

    let topCodesHtml = '';
    const sortedCodes = Object.entries(codeCounts).sort((a, b) => b[1] - a[1]);

    if (sortedCodes.length > 0) {
      sortedCodes.slice(0, 10).forEach(([code, count]) => {
        const sampleMsg = state.logs.find(l => l.message.includes(code))?.message || '';
        const diag = window.knowledgeBaseEngine.diagnoseLog(sampleMsg, code);
        topCodesHtml += `
          <tr style="page-break-inside:avoid; break-inside:avoid;">
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-family:monospace; font-weight:bold; color:#0a3d6d; text-align:center;">${code}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px;">${escapeHtml(diag.title)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; text-align:center; font-weight:bold; color:#dc2626;">${count} veces</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; color:#475569;">${escapeHtml(diag.rootCause)}</td>
          </tr>
        `;
      });
    } else {
      topCodesHtml = `<tr><td colspan="4" style="padding:10px; text-align:center; color:#64748b;">No se registraron patrones numéricos recurrentes.</td></tr>`;
    }

    const section1Content = onlyCatalogErrors
      ? `<div style="margin-bottom:25px;">${incidentsHtml || '<div style="padding:15px; text-align:center; color:#64748b;">No se detectaron errores de catálogo durante el análisis.</div>'}</div>`
      : `<table class="report-table" style="width:100%; border-collapse:collapse; margin-bottom:25px; font-size:11px; table-layout:fixed; word-wrap:break-word;">
          <thead>
            <tr style="background:#0a3d6d; color:#ffffff; text-align:left;">
              <th style="padding:8px 6px; border:1px solid #0a3d6d; width:10%; text-align:center;">Nivel</th>
              <th style="padding:8px 6px; border:1px solid #0a3d6d; width:14%;">Servicio / API</th>
              <th style="padding:8px 6px; border:1px solid #0a3d6d; width:26%;">Evento & Significado</th>
              <th style="padding:8px 6px; border:1px solid #0a3d6d; width:22%;">Causa Raíz Probable</th>
              <th style="padding:8px 6px; border:1px solid #0a3d6d; width:28%;">Remediación Inmediata</th>
            </tr>
          </thead>
          <tbody>
            ${incidentsHtml || '<tr><td colspan="5" style="padding:15px; text-align:center; color:#64748b;">No se detectaron fallos críticos durante el periodo de análisis.</td></tr>'}
          </tbody>
        </table>`;

    container.innerHTML = `
      <div id="exec-report-document" style="width:100%; box-sizing:border-box; background:#fff; color:#0f172a; padding:20px; font-family:'Segoe UI', Arial, sans-serif; border-radius:8px;">
        <!-- Header Informe -->
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:3px solid #0a3d6d; padding-bottom:15px; margin-bottom:20px;">
          <div>
            <h1 style="color:#0a3d6d; margin:0; font-size:22px; font-weight:bold;">IT SERVICIOS DE VENEZUELA</h1>
            <h3 style="color:#475569; margin:4px 0 0 0; font-size:14px; font-weight:normal;">${reportTitleText}</h3>
          </div>
          <div style="text-align:right; font-size:12px; color:#64748b;">
            <strong>Fecha de Emisión:</strong> ${dateStr}<br>
            <strong>Elaborado por:</strong> ${escapeHtml(activeClient.engineer)} — IT Servicios<br>
            <strong>Estatus:</strong> DOCUMENTO OFICIAL / INFORME EXCLUSIVO
          </div>
        </div>

        <!-- Ficha Técnica del Cliente Destinatario -->
        <div style="background:#f8fafc; border:1px solid #cbd5e1; border-left:5px solid #0a3d6d; padding:14px 18px; margin-bottom:20px; border-radius:6px; display:grid; grid-template-columns: 1fr 1fr; gap:16px; font-size:12px;">
          <div>
            <div style="font-size:10px; text-transform:uppercase; color:#64748b; font-weight:bold;">Cliente Destinatario:</div>
            <div style="font-size:17px; font-weight:bold; color:#0a3d6d; margin-top:2px;">🏢 ${escapeHtml(activeClient.name)}</div>
            <div style="margin-top:4px;"><strong>Dirigido a:</strong> ${escapeHtml(activeClient.contact)}</div>
            <div><strong>Ingeniero Responsable:</strong> ${escapeHtml(activeClient.engineer)} — Soporte IT Servicios</div>
          </div>
          <div>
            <div style="font-size:10px; text-transform:uppercase; color:#64748b; font-weight:bold;">Entorno & Servidor Entrust:</div>
            <div style="font-size:14px; font-weight:bold; color:#0f172a; margin-top:2px;">🛡️ ${escapeHtml(activeClient.platform)}</div>
            <div style="margin-top:4px;"><strong>Versión & Build:</strong> ${escapeHtml(activeClient.version)} (${escapeHtml(activeClient.build)})</div>
            <div><strong>Alcance del Análisis:</strong> <span style="color:#dc2626; font-weight:bold;">${reportScopeText}</span></div>
          </div>
        </div>

        <!-- Resumen Ejecutivo Metrics & Barra de Severidad -->
        <div style="background:#f8fafc; border:1px solid #cbd5e1; padding:16px; border-radius:6px; margin-bottom:22px;">
          <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:12px; margin-bottom:14px;">
            <div style="text-align:center; background:#fff; padding:10px 8px; border-radius:6px; border:1px solid #e2e8f0;">
              <div style="font-size:10px; color:#64748b; text-transform:uppercase; font-weight:bold;">Índice de Salud</div>
              <div style="font-size:22px; font-weight:bold; color:${calculatedHealth < 80 ? '#dc2626' : '#0a3d6d'};">${healthValStr}</div>
            </div>
            <div style="text-align:center; background:#fff; padding:10px 8px; border-radius:6px; border:1px solid #e2e8f0;">
              <div style="font-size:10px; color:#64748b; text-transform:uppercase; font-weight:bold;">Total Eventos</div>
              <div style="font-size:22px; font-weight:bold; color:#0f172a;">${totalCount}</div>
            </div>
            <div style="text-align:center; background:#fff; padding:10px 8px; border-radius:6px; border:1px solid #e2e8f0;">
              <div style="font-size:10px; color:#64748b; text-transform:uppercase; font-weight:bold;">Incidentes Críticos</div>
              <div style="font-size:22px; font-weight:bold; color:#dc2626;">${criticalLogs.length}</div>
            </div>
            <div style="text-align:center; background:#fff; padding:10px 8px; border-radius:6px; border:1px solid #e2e8f0;">
              <div style="font-size:10px; color:#64748b; text-transform:uppercase; font-weight:bold;">Alertas Auditoría</div>
              <div style="font-size:22px; font-weight:bold; color:#d97706;">${warningLogs.length}</div>
            </div>
          </div>

          <!-- Barra de Distribución Porcentual -->
          <div style="background:#fff; border:1px solid #e2e8f0; padding:10px 14px; border-radius:6px;">
            <div style="font-size:10px; font-weight:bold; color:#0a3d6d; text-transform:uppercase; margin-bottom:6px; display:flex; justify-content:space-between;">
              <span>📊 Distribución por Severidad de Eventos</span>
              <span style="color:#64748b; font-weight:normal;">Total Procesados: ${totalCount}</span>
            </div>
            <div style="height:10px; background:#e2e8f0; border-radius:5px; overflow:hidden; display:flex; margin-bottom:8px;">
              <div style="width:${visualCritPct}%; background:#dc2626;" title="CRITICAL/ERROR"></div>
              <div style="width:${visualWarnPct}%; background:#f59e0b;" title="WARN"></div>
              <div style="width:${100 - visualCritPct - visualWarnPct}%; background:#0284c7;" title="INFO"></div>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:10px; color:#334155;">
              <div><span style="display:inline-block; width:8px; height:8px; background:#dc2626; border-radius:2px; margin-right:4px;"></span> <strong>CRITICAL/ERROR:</strong> ${criticalLogs.length} (${formatPctStr(criticalLogs.length, totalCount)})</div>
              <div><span style="display:inline-block; width:8px; height:8px; background:#f59e0b; border-radius:2px; margin-right:4px;"></span> <strong>WARN (Auditoría):</strong> ${warningLogs.length} (${formatPctStr(warningLogs.length, totalCount)})</div>
              <div><span style="display:inline-block; width:8px; height:8px; background:#0284c7; border-radius:2px; margin-right:4px;"></span> <strong>INFO:</strong> ${infoLogs.length} (${formatPctStr(infoLogs.length, totalCount)})</div>
            </div>
          </div>
        </div>

        <!-- Sección I: Hallazgos & Diagnóstico (Formato Fichas o Tabla según modo) -->
        <h3 style="color:#0a3d6d; border-left:4px solid #0a3d6d; padding-left:10px; margin-bottom:12px; font-size:15px; page-break-after:avoid;">
          ${onlyCatalogErrors ? '1. Catálogo Exclusivo de Errores [520xxx / IDaaS] Detectados' : '1. Hallazgos y Diagnóstico Técnico de Errores [520xxx / IDaaS]'} (${logsToInclude.length} registros)
        </h3>
        ${section1Content}

        <!-- Tabla II: Análisis de Frecuencia de Errores -->
        <h3 style="color:#0a3d6d; border-left:4px solid #0a3d6d; padding-left:10px; margin-bottom:12px; font-size:15px; page-break-after:avoid;">2. Análisis Estadístico de Errores Reincidentes (520xxx / AUDxxx)</h3>
        <table class="report-table" style="width:100%; border-collapse:collapse; margin-bottom:25px; font-size:11px; table-layout:fixed; word-wrap:break-word;">
          <thead>
            <tr style="background:#e0f2fe; color:#0a3d6d; text-align:left;">
              <th style="padding:8px 6px; border:1px solid #cbd5e1; width:15%;">Código</th>
              <th style="padding:8px 6px; border:1px solid #cbd5e1; width:35%;">Descripción del Evento</th>
              <th style="padding:8px 6px; border:1px solid #cbd5e1; text-align:center; width:15%;">Reincidencias</th>
              <th style="padding:8px 6px; border:1px solid #cbd5e1; width:35%;">Diagnóstico Frecuente</th>
            </tr>
          </thead>
          <tbody>
            ${topCodesHtml}
          </tbody>
        </table>

        <!-- Sección III: Recomendaciones Técnicas -->
        <h3 style="color:#0a3d6d; border-left:4px solid #0a3d6d; padding-left:10px; margin-bottom:12px; font-size:15px;">3. Recomendaciones Técnicas y Plan de Acción Preventivo (Basado en Diagnóstico)</h3>
        <div style="background:#f8fafc; border:1px solid #cbd5e1; padding:16px; border-radius:6px; font-size:12px; line-height:1.6; margin-bottom:30px;">
          <ul style="margin:0; padding-left:20px; color:#334155;">
            ${generateDynamicRecommendationsHtml(targetLogs, activeClient)}
          </ul>
        </div>

        <!-- Firma y Cierre Oficial -->
        <div style="display:flex; justify-content:space-between; align-items:flex-end; padding-top:20px; border-top:2px solid #0a3d6d;">
          <div>
            <p style="font-size:11px; color:#475569; margin:0;">
              <strong>Suite de Diagnóstico</strong> — Entrust IdentityGuard OnPremise & IDaaS Cloud<br>
              Confidencial — Para uso exclusivo del cliente <strong>${escapeHtml(activeClient.name)}</strong>.
            </p>
          </div>
          <div style="text-align:center; min-width:260px;">
            <div style="border-bottom:1px solid #0f172a; margin-bottom:6px; height:35px;"></div>
            <strong style="font-size:12px; color:#0a3d6d;">Departamento de Soporte IT Servicios de Venezuela</strong><br>
            <span style="font-size:11px; color:#64748b;">Ing. ${escapeHtml(activeClient.engineer)}</span>
          </div>
        </div>
      </div>
    `;

    modal.classList.add('active');
  }

  function generateDynamicRecommendationsHtml(targetLogs, activeClient) {
    const items = [];
    const fullLogText = targetLogs.map(l => l.message).join(' ');

    const hasAuthErrors = /(5202013|5205079|5203016|Invalid user ID|password)/i.test(fullLogText);
    const hasUserNotFound = /(5205139|Unable to find a user)/i.test(fullLogText);
    const hasGridPinErrors = /(5201006|5201007|5201008|5201010|Card does not match|PIN)/i.test(fullLogText);
    const hasClientApiErrors = /(5202340|Authorization Failure)/i.test(fullLogText);
    const hasPoolDbErrors = /(AUD154|AUD155|AUD150|5201000|Connection pool|exhaustion)/i.test(fullLogText);
    const hasSoftTokenPushErrors = /(AUD2309|5209525|Failed delivery|Push)/i.test(fullLogText);
    const hasSamlIdaasErrors = /(SAML|IDaaS|OIDC|OAuth2|EXPIRED)/i.test(fullLogText);

    if (hasAuthErrors) {
      items.push(`<li><strong>Desbloqueo y Gestión de Cuentas LDAP / Active Directory:</strong> Se diagnosticaron reintentos fallidos de autenticación y bloqueos de cuenta (códigos 5202013 / 5205079 / 5203016). Se recomienda verificar las cuentas afectadas en la consola de Entrust y en el directorio LDAP para restablecer vigencias y desbloquear cuentas.</li>`);
    }

    if (hasUserNotFound) {
      items.push(`<li><strong>Sincronización del Repositorio de Usuarios (LDAP/AD):</strong> Se detectaron accesos fallidos por usuarios o alias no registrados (código 5205139). Se sugiere ejecutar un barrido de sincronización de usuarios en la consola de administración de IdentityGuard.</li>`);
    }

    if (hasGridPinErrors) {
      items.push(`<li><strong>Reasignación y Auditoría de Tarjetas Grid / PIN:</strong> Se registraron incoherencias entre los desafíos y las respuestas enviadas (códigos 5201008 / 5201010). Se recomienda validar las series de tarjetas Grid activas asignadas a los usuarios y capacitar en el ingreso de celdas.</li>`);
    }

    if (hasClientApiErrors) {
      items.push(`<li><strong>Auditoría de Canales de Integración Web / API:</strong> Se observaron rechazos en la autorización de aplicaciones cliente (código 5202340). Se sugiere validar la clave compartida (Client Secret) y las direcciones IP permitidas en la política del canal.</li>`);
    }

    if (hasPoolDbErrors) {
      items.push(`<li><strong>Ampliación del Pool de Conexiones a Base de Datos (Connection Pool):</strong> Se detectó alta saturación en las conexiones al repositorio (AUD154 / AUD155). Se recomienda incrementar el número de conexiones en <code>identityguard.properties</code> y ajustar los tiempos de espera (Timeout).</li>`);
    }

    if (hasSoftTokenPushErrors) {
      items.push(`<li><strong>Revisión de Notificaciones Push MFA & Soft Tokens:</strong> Se identificaron fallos en la entrega de detalles de transacciones a tokens de software (AUD2309 / 5209525). Se recomienda comprobar la conectividad del dispositivo móvil del usuario y los certificados Push (APNS/FCM).</li>`);
    }

    if (hasSamlIdaasErrors) {
      items.push(`<li><strong>Verificación de Certificados SAML 2.0 y Tiempo NTP:</strong> Se detectaron aserciones SAML expiradas o firmas inválidas. Se sugiere validar la fecha de vencimiento del certificado de firma X.509 en la Consola Entrust IDaaS y verificar la sincronización del reloj de servidor mediante NTP.</li>`);
    }

    // Recomendación general por versión
    items.push(`<li><strong>Revisión de Parches Oficiales para ${escapeHtml(activeClient.version)}:</strong> Validar la aplicación de los parches e hitos oficializados por Entrust para la versión <strong>${escapeHtml(activeClient.version)} (${escapeHtml(activeClient.build)})</strong> según la documentación técnica oficial.</li>`);

    return items.join('\n');
  }

  /* ==========================================================================
     3. TARJETAS DE MÉTRICAS INTERACTIVAS & MODAL DEDICADO 520XXX
     ========================================================================== */
  function initMetricCardsInteractivity() {
    dom.cardEntrustErrors?.addEventListener('click', () => {
      openEntrust520Modal();
    });

    dom.cardAuditAlerts?.addEventListener('click', () => {
      setFilterMode('AUDIT_ONLY');
      switchTab('analyzer');
    });

    dom.cardTotalLogs?.addEventListener('click', () => {
      clearFilterMode();
      switchTab('analyzer');
    });

    dom.cardHealth?.addEventListener('click', () => {
      switchTab('analyzer');
    });

    dom.btnCloseEntrustModal?.addEventListener('click', () => dom.entrustErrorsModal.classList.remove('active'));
    dom.btnCloseEntrustModal2?.addEventListener('click', () => dom.entrustErrorsModal.classList.remove('active'));

    document.getElementById('btn-gen-report-for-detected-520')?.addEventListener('click', () => {
      if (dom.entrustErrorsModal) dom.entrustErrorsModal.classList.remove('active');
      generateExecutiveReport(true);
    });

    dom.btnGoToAnalyzer520?.addEventListener('click', () => {
      dom.entrustErrorsModal.classList.remove('active');
      setFilterMode('520_ONLY');
      switchTab('analyzer');
    });

    dom.btnClearActiveFilter?.addEventListener('click', () => {
      clearFilterMode();
    });
  }

  function setFilterMode(mode) {
    state.activeFilterMode = mode;
    if (dom.activeFilterBanner) {
      dom.activeFilterBanner.style.display = 'flex';
      if (mode === '520_ONLY') {
        dom.activeFilterText.textContent = 'Filtrando Únicamente: Errores 520xxx / IDaaS de Entrust IdentityGuard';
      } else if (mode === 'AUDIT_ONLY') {
        dom.activeFilterText.textContent = 'Filtrando Únicamente: Eventos de Auditoría (AUDxxx) de Entrust IdentityGuard';
      }
    }
    applyLogFilters();
  }

  function clearFilterMode() {
    state.activeFilterMode = null;
    if (dom.activeFilterBanner) {
      dom.activeFilterBanner.style.display = 'none';
    }
    applyLogFilters();
  }

  function openEntrust520Modal() {
    if (!dom.entrustErrorsModal || !dom.entrustErrorsModalList) return;

    const entrustLogs = state.logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR');

    if (entrustLogs.length === 0) {
      dom.entrustErrorsModalList.innerHTML = `
        <div style="padding:20px; text-align:center; color: var(--text-muted);">
          No se observan errores [520xxx] ni incidentes críticos en la muestra actual de logs.
        </div>`;
    } else {
      let listHtml = '';
      entrustLogs.forEach(log => {
        const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message);
        listHtml += `
          <div style="background:var(--bg-primary); border:1px solid var(--border-color); padding:12px; border-radius:6px; margin-bottom:10px;">
            <div class="flex-between">
              <span class="badge-sev ${log.level}">${log.level}</span>
              <span class="font-mono text-cyan" style="font-size:0.8rem;">#${log.lineNum} - ${log.timestamp}</span>
            </div>
            <div class="font-mono text-danger" style="font-weight:700; margin:6px 0;">${escapeHtml(log.message)}</div>
            <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:4px;">
              <strong>Diagnóstico:</strong> ${escapeHtml(diag.meaning)}
            </div>
            <div style="font-size:0.8rem; color:var(--text-warn);">
              <strong>Causa Raíz:</strong> ${escapeHtml(diag.rootCause)}
            </div>
          </div>
        `;
      });
      dom.entrustErrorsModalList.innerHTML = listHtml;
    }

    dom.entrustErrorsModal.classList.add('active');
  }

  /* ==========================================================================
     4. ANALIZADOR DE LOGS Y MUESTRA
     ========================================================================== */
  function applyLogFilters() {
    let result = [...state.logs];

    if (state.activeFilterMode === '520_ONLY') {
      result = result.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR');
    } else if (state.activeFilterMode === 'AUDIT_ONLY') {
      result = result.filter(l => l.level === 'WARN' || l.level === 'INFO' || /AUD/i.test(l.message));
    }

    const clientVal = dom.filterClientSelect?.value;
    if (clientVal && clientVal !== 'ALL') {
      result = result.filter(l => (l.client || 'Cliente General') === clientVal);
    }

    const searchVal = dom.searchLogInput?.value.toLowerCase().trim();
    if (searchVal) {
      result = result.filter(l =>
        l.message.toLowerCase().includes(searchVal) ||
        l.service.toLowerCase().includes(searchVal) ||
        l.level.toLowerCase().includes(searchVal) ||
        (l.client && l.client.toLowerCase().includes(searchVal)) ||
        (l.diagnostic && l.diagnostic.title.toLowerCase().includes(searchVal))
      );
    }

    const levelVal = dom.filterLevelSelect?.value;
    if (levelVal && levelVal !== 'ALL') {
      result = result.filter(l => l.level === levelVal);
    }

    const typeVal = dom.filterTypeSelect?.value;
    if (typeVal && typeVal !== 'ALL') {
      result = result.filter(l => l.type === typeVal || l.service.toLowerCase().includes(typeVal.toLowerCase()));
    }

    state.filteredLogs = result;
    renderLogTable();
    updateMetricsAndCharts();
  }

  function extractClientFromFilename(filename) {
    if (!filename) return 'Entrust OnPremise';

    let name = filename.replace(/\.[^/.]+$/, "").trim();

    // Si el nombre del archivo empieza con fecha o marca de tiempo (ej. 2025-11-28_20-02-37)
    if (/^\d{4}[-_/.]\d{2}[-_/.]\d{2}/.test(name) || /^\d+$/.test(name) || name.length > 25) {
      return 'Entrust OnPremise';
    }

    let clean = name.replace(/[-_]/g, " ").replace(/\b(log|logs|txt|json|error|errors|520|aud|entrust|server|system)\b/gi, '').trim();

    if (!clean || clean.length < 2 || /^\d+$/.test(clean)) {
      return 'Entrust OnPremise';
    }

    return clean.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
  }

  function renderLogTable() {
    if (!dom.logScrollArea) return;
    dom.logScrollArea.innerHTML = '';

    if (state.filteredLogs.length === 0) {
      dom.logScrollArea.innerHTML = `
        <div style="padding: 30px; text-align: center; color: var(--text-muted);">
          No se encontraron registros de log que coincidan con los filtros aplicados.
        </div>`;
      return;
    }

    const displayLogs = state.filteredLogs.slice(-200);

    displayLogs.forEach(log => {
      const row = document.createElement('div');
      row.className = `log-row ${log.level === 'CRITICAL' || log.level === 'ERROR' ? 'has-critical' : ''}`;
      if (state.selectedLog && state.selectedLog.id === log.id) {
        row.style.background = 'rgba(56, 189, 248, 0.25)';
      }

      const clientName = log.client || 'Entrust OnPremise';

      row.innerHTML = `
        <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">#${log.lineNum}</div>
        <div class="font-mono" style="font-size:0.75rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${log.timestamp}</div>
        <div><span class="badge-sev ${log.level}">${log.level}</span></div>
        <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><span class="badge-client font-mono" style="font-size:0.7rem; background:rgba(99,102,241,0.18); color:#818cf8; padding:2px 6px; border-radius:4px; font-weight:600; border:1px solid rgba(99,102,241,0.35); display:inline-block; max-width:100px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(clientName)}">🏢 ${escapeHtml(clientName)}</span></div>
        <div class="font-mono" style="font-size:0.8rem; color:#38bdf8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(log.service)}</div>
        <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(log.message)}</div>
        <div style="font-size:0.75rem; color:#94a3b8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${log.diagnostic?.matched ? '🧠 Entrust KB' : log.type}</div>
      `;

      row.addEventListener('click', () => selectLog(log));
      dom.logScrollArea.appendChild(row);
    });

    if (state.isStreaming) {
      dom.logScrollArea.scrollTop = dom.logScrollArea.scrollHeight;
    }
  }

  function selectLog(log) {
    state.selectedLog = log;
    renderLogTable();
    renderDiagnosticPanel(log);
  }

  function renderDiagnosticPanel(log) {
    if (!dom.diagnosticCard || !log) return;

    const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message);

    dom.diagnosticCard.innerHTML = `
      <div class="diagnostic-header">
        <div class="diagnostic-title">
          <span>🛡️ Diagnóstico de Seguridad & Auditoría (Entrust Suite)</span>
          <span class="badge-sev ${diag.severity}">${diag.severity}</span>
        </div>
        <span class="text-muted font-mono" style="font-size:0.8rem;">Firma: ${diag.ruleId}</span>
      </div>

      <div class="diag-field">
        <div class="diag-label">Evento u Excepción Observada</div>
        <div class="diag-val font-mono text-cyan" style="font-weight:700;">${escapeHtml(diag.title)}</div>
      </div>

      <div class="diag-field">
        <div class="diag-label">Registro Original de Log / Trazas</div>
        <div class="diag-code">${escapeHtml(log.raw)}</div>
      </div>

      <div class="diag-field">
        <div class="diag-label">Significado del Log (Explicación Entrust)</div>
        <div class="diag-val">${escapeHtml(diag.meaning)}</div>
      </div>

      <div class="diag-field">
        <div class="diag-label">Causa Raíz Probable</div>
        <div class="diag-val text-warn font-mono">${escapeHtml(diag.rootCause)}</div>
      </div>

      <div class="diag-field">
        <div class="diag-label">Recomendación & Pasos de Solución</div>
        <div class="diag-val" style="white-space: pre-line;">${escapeHtml(diag.remediation)}</div>
      </div>

      <div class="flex-between mt-4" style="padding-top:12px; border-top:1px solid var(--border-color);">
        <div>
          <span class="diag-label">Nivel de Riesgo Operativo:</span>
          <span class="text-danger font-mono" style="font-weight:700;">${diag.riskLevel}</span>
        </div>
        <button class="btn btn-primary" id="btn-jump-manual" data-version="${diag.manualVersion}" data-section="${diag.sectionId}">
          📚 Ver Procedimiento en Manual (${diag.manualVersion})
        </button>
      </div>
    `;

    document.getElementById('btn-jump-manual')?.addEventListener('click', (e) => {
      const ver = e.currentTarget.getAttribute('data-version');
      const sec = e.currentTarget.getAttribute('data-section');
      jumpToManualSection(ver, sec);
    });
  }

  function jumpToManualSection(version, sectionId) {
    switchTab('manuals');

    state.currentManualVersion = version;
    if (dom.manualVersionSelect) {
      dom.manualVersionSelect.value = version;
    }

    loadManual(version, sectionId);
  }

  /* ==========================================================================
     5. MÓDULO DE MANUALES ADMINISTRATIVOS HTML
     ========================================================================== */
  function initManualsModule() {
    populateManualVersionSelect();

    dom.manualVersionSelect?.addEventListener('change', (e) => {
      state.currentManualVersion = e.target.value;
      loadManual(e.target.value);
    });

    dom.manualSearchInput?.addEventListener('input', (e) => {
      const query = e.target.value;
      if (query.length >= 2) {
        const results = window.manualsEngine.searchManuals(query);
        renderManualSearchResults(results);
      } else {
        loadManual(state.currentManualVersion);
      }
    });

    document.querySelectorAll('.relnote-quick-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const ver = e.currentTarget.getAttribute('data-ver');
        if (ver) {
          state.currentManualVersion = ver;
          if (dom.manualVersionSelect) dom.manualVersionSelect.value = ver;
          loadManual(ver);
        }
      });
    });

    dom.btnOpenAddManualModal?.addEventListener('click', () => {
      dom.addManualModal.classList.add('active');
    });
    dom.btnCloseAddManual?.addEventListener('click', () => {
      dom.addManualModal.classList.remove('active');
    });

    dom.btnSaveCustomManual?.addEventListener('click', () => {
      const verName = document.getElementById('custom-manual-ver')?.value;
      const title = document.getElementById('custom-manual-title')?.value;
      const htmlContent = document.getElementById('custom-manual-html')?.value;

      if (!verName || !htmlContent) {
        alert('Por favor complete la versión y el contenido HTML.');
        return;
      }

      try {
        const newVerKey = window.manualsEngine.saveCustomManual(verName, title || 'Manual Personalizado', htmlContent);
        populateManualVersionSelect();
        dom.manualVersionSelect.value = newVerKey;
        loadManual(newVerKey);
        renderKbRulesList();
        dom.addManualModal.classList.remove('active');
        alert(`¡Manual ${verName} cargado e indexado automáticamente en la Base de Conocimientos!`);
      } catch (e) {
        alert('Error al guardar manual HTML: ' + e.message);
      }
    });

    // Cargar por defecto la WebHelp Oficial de Entrust v13.0
    state.currentManualVersion = 'v13_0_webhelp';
    if (dom.manualVersionSelect) dom.manualVersionSelect.value = 'v13_0_webhelp';
    loadManual('v13_0_webhelp');
  }

  function populateManualVersionSelect() {
    if (!dom.manualVersionSelect) return;
    const versions = window.manualsEngine.getVersionsList();
    dom.manualVersionSelect.innerHTML = '';
    versions.forEach(v => {
      const opt = document.createElement('option');
      opt.value = v.key;
      opt.textContent = v.title;
      dom.manualVersionSelect.appendChild(opt);
    });
  }

  async function loadManual(version, scrollToSectionId = null) {
    if (!dom.manualIframe) return;

    if (version === 'v13_0_webhelp') {
      dom.manualIframe.src = 'manuals/IG_130_Admin_WebHelp/index.htm';
      renderTocList([
        { id: 'manuals/IG_130_Admin_WebHelp/index.htm', text: '📖 Inicio WebHelp Entrust v13.0', level: 'h2' },
        { id: 'manuals/IG_130_Admin_WebHelp/reference.htm', text: '📘 Referencia General de Administración', level: 'h2' },
        { id: 'manuals/IG_130_Admin_WebHelp/configure_token_authentication.htm', text: '🔑 Configuración de Autenticación de Tokens', level: 'h3' },
        { id: 'manuals/IG_130_Admin_WebHelp/authenticate_with_your_entrust_datacard_ot_token.htm', text: '📲 Autenticación Soft Token / Identity Guard', level: 'h3' }
      ]);
      return;
    }

    if (version === 'v12_0_webhelp') {
      dom.manualIframe.src = 'manuals/IG_120_Admin_WebHelp/index.htm';
      renderTocList([
        { id: 'manuals/IG_120_Admin_WebHelp/index.htm', text: '📖 Inicio WebHelp Entrust v12.0', level: 'h2' },
        { id: 'manuals/IG_120_Admin_WebHelp/reference.htm', text: '📘 Referencia General de Administración v12.0', level: 'h2' },
        { id: 'manuals/IG_120_Admin_WebHelp/configuration_worksheets.htm', text: '📋 Hojas de Configuración v12.0', level: 'h3' },
        { id: 'manuals/IG_120_Admin_WebHelp/authenticate_with_your_entrust_datacard_ot_token.htm', text: '📲 Autenticación Soft Token / Identity Guard', level: 'h3' }
      ]);
      return;
    }

    if (version === 'v11_0_webhelp') {
      dom.manualIframe.src = 'manuals/IG_110_Admin_WebHelp/index.htm';
      renderTocList([
        { id: 'manuals/IG_110_Admin_WebHelp/index.htm', text: '📖 Inicio WebHelp Entrust v11.0', level: 'h2' },
        { id: 'manuals/IG_110_Admin_WebHelp/reference.htm', text: '📘 Referencia General de Administración v11.0', level: 'h2' },
        { id: 'manuals/IG_110_Admin_WebHelp/configuration_worksheets.htm', text: '📋 Hojas de Configuración v11.0', level: 'h3' }
      ]);
      return;
    }

    if (version === 'v13_0_relnotes') {
      dom.manualIframe.src = 'manuals/entrust_ig_130_releasenotes.html';
      renderTocList([
        { id: 'manuals/entrust_ig_130_releasenotes.html', text: '📋 Release Notes v13.0 (Diciembre 2020)', level: 'h2' }
      ]);
      return;
    }

    if (version === 'v12_0_relnotes') {
      dom.manualIframe.src = 'manuals/entrust_ig_120_releasenotes.html';
      renderTocList([
        { id: 'manuals/entrust_ig_120_releasenotes.html', text: '📋 Release Notes v12.0 (Marzo 2017)', level: 'h2' }
      ]);
      return;
    }

    if (version === 'v11_0_relnotes') {
      dom.manualIframe.src = 'manuals/entrust_ig_110_releasenotes.html';
      renderTocList([
        { id: 'manuals/entrust_ig_110_releasenotes.html', text: '📋 Release Notes v11.0 (Noviembre 2015)', level: 'h2' }
      ]);
      return;
    }

    dom.manualIframe.src = 'about:blank';
    const htmlContent = await window.manualsEngine.loadManualHtml(version);

    const doc = dom.manualIframe.contentDocument || dom.manualIframe.contentWindow.document;
    doc.open();
    doc.write(htmlContent);
    doc.close();

    const toc = window.manualsEngine.extractToc(htmlContent);
    renderTocList(toc);

    if (scrollToSectionId) {
      setTimeout(() => {
        const targetEl = doc.getElementById(scrollToSectionId);
        if (targetEl) {
          targetEl.scrollIntoView({ behavior: 'smooth' });
          targetEl.style.background = '#fef08a';
          setTimeout(() => targetEl.style.background = 'transparent', 2500);
        }
      }, 200);
    }
  }

  function renderTocList(toc) {
    if (!dom.manualTocList) return;
    dom.manualTocList.innerHTML = '';

    if (toc.length === 0) {
      dom.manualTocList.innerHTML = '<li class="text-muted" style="padding:10px;">Sin secciones indexadas.</li>';
      return;
    }

    toc.forEach(item => {
      const li = document.createElement('li');
      li.className = 'toc-item';
      if (item.level === 'h3') li.style.paddingLeft = '20px';

      li.textContent = item.text;
      li.addEventListener('click', () => {
        if (state.currentManualVersion === 'v13_0_webhelp') {
          dom.manualIframe.src = item.id;
        } else {
          const doc = dom.manualIframe.contentDocument || dom.manualIframe.contentWindow.document;
          const targetEl = doc.getElementById(item.id) || Array.from(doc.querySelectorAll('h1,h2,h3')).find(h => h.textContent.includes(item.text));
          if (targetEl) {
            targetEl.scrollIntoView({ behavior: 'smooth' });
          }
        }
      });

      dom.manualTocList.appendChild(li);
    });
  }

  function renderManualSearchResults(results) {
    if (!dom.manualTocList) return;
    dom.manualTocList.innerHTML = '<div class="diag-label">Resultados de Búsqueda:</div>';

    if (results.length === 0) {
      dom.manualTocList.innerHTML += '<div class="text-muted" style="padding:10px;">Sin coincidencias.</div>';
      return;
    }

    results.forEach(res => {
      const div = document.createElement('div');
      div.className = 'toc-item';
      div.innerHTML = `<strong class="text-cyan">${res.version}</strong>: ${escapeHtml(res.snippet)}`;
      div.addEventListener('click', () => {
        loadManual(res.version, res.sectionId);
      });
      dom.manualTocList.appendChild(div);
    });
  }

  /* ==========================================================================
     6. MÓDULO DE BASE DE CONOCIMIENTO (KB)
     ========================================================================== */
  function initKbModule() {
    renderKbRulesList();

    dom.btnOpenAddKbModal?.addEventListener('click', () => {
      dom.addKbModal.classList.add('active');
    });
    dom.btnCloseAddKb?.addEventListener('click', () => {
      dom.addKbModal.classList.remove('active');
    });

    dom.btnSaveCustomKb?.addEventListener('click', () => {
      const title = document.getElementById('custom-kb-title')?.value;
      const pattern = document.getElementById('custom-kb-pattern')?.value;
      const meaning = document.getElementById('custom-kb-meaning')?.value;
      const rootCause = document.getElementById('custom-kb-cause')?.value;
      const remediation = document.getElementById('custom-kb-fix')?.value;
      const manualVer = document.getElementById('custom-kb-manual-ver')?.value;

      if (!title || !pattern || !meaning) {
        alert('Por favor complete los campos obligatorios.');
        return;
      }

      window.knowledgeBaseEngine.saveCustomRule({
        title, pattern, meaning, rootCause, remediation, manualVersion: manualVer
      });

      renderKbRulesList();
      dom.addKbModal.classList.remove('active');
      alert('¡Nueva regla de Entrust/Sistema agregada a la Base de Conocimientos!');
    });
  }

  function renderKbRulesList() {
    if (!dom.kbRulesList) return;
    const rules = window.knowledgeBaseEngine.getAllRules();
    dom.kbRulesList.innerHTML = '';

    rules.forEach(rule => {
      const card = document.createElement('div');
      card.className = 'glass-card';
      card.style.marginBottom = '12px';

      card.innerHTML = `
        <div class="flex-between" style="margin-bottom:8px;">
          <h4 class="text-cyan font-mono">${rule.id}: ${escapeHtml(rule.title)}</h4>
          <span class="badge-sev ${rule.severity}">${rule.severity}</span>
        </div>
        <div style="font-size:0.85rem; margin-bottom:6px;"><strong>Categoría:</strong> ${rule.category}</div>
        <div style="font-size:0.9rem; margin-bottom:8px;">${escapeHtml(rule.meaning)}</div>
        <div style="font-size:0.85rem; color:var(--text-warn); margin-bottom:8px;"><strong>Causa Raíz:</strong> ${escapeHtml(rule.rootCause)}</div>
        <div style="font-size:0.85rem; background:var(--bg-primary); padding:8px; border-radius:4px; border:1px solid var(--border-color); white-space:pre-line;">
          <strong>Remediación / Pasos:</strong><br>${escapeHtml(rule.remediation)}
        </div>
      `;
      dom.kbRulesList.appendChild(card);
    });
  }

  /* ==========================================================================
     7. PRESETS DE LOGS & SIMULADOR
     ========================================================================== */
  function initPresets() {
    dom.presetSelector?.addEventListener('change', (e) => {
      loadPresetScenario(e.target.value);
    });
  }

  function loadPresetScenario(scenario) {
    let rawText = '';

    if (scenario === 'entrust_idg') {
      rawText = `
[2026-08-01 10:14:02,112] [main] [INFO ] [IG.AUDIT] [AUD100] First time initialization performed. Initial serial number set to 1001. Maximum number of users set to 5000. License expiry set to 2028-12-31.
[2026-08-01 10:14:05,230] [main] [INFO ] [IG.AUDIT] [AUD106] Entrust IdentityGuard Administration Service started. Version 12.4.0.12
[2026-08-01 10:15:10,402] [http-nio-8080-exec-1] [ERROR] [IG.SYSTEM.SystemContext.API] [5202013] Invalid user ID or password provided for user admtmp (Ref:9812401)
[2026-08-01 10:16:45,889] [http-nio-8080-exec-4] [ERROR] [IG.SYSTEM.UserManagement.API] [5205139] Unable to find a user for user name or alias 'admtmp' (Searchbase: database/LDAP)
[2026-08-01 10:18:22,104] [http-nio-8080-exec-7] [CRITICAL] [IG.SYSTEM.AuthenticationManagement.API] [5203018] Authentication type 'TOKENRO' is not allowed for user 'admtmp' in group 'itservicios-group'
[2026-08-01 10:19:01,005] [audit-thread-2] [WARN ] [IG.AUDIT] [AUD6001] User 'admtmp' failed authentication. Authentication Type: TOKENRO
[2026-08-01 10:20:15,302] [audit-thread-3] [INFO ] [IG.AUDIT] [AUD2300] Token Entrust 87123049 has been assigned to user admtmp.
[2026-08-01 10:22:04,119] [audit-thread-4] [ERROR] [IG.AUDIT] [AUD2309] Failed delivery of transaction details for token Entrust 87123049 for user admtmp. (SNMP Trap Dispatched)
[2026-08-01 10:25:30,900] [audit-thread-5] [WARN ] [IG.AUDIT] [AUD151] Repository PrimaryDB connection failed to URL jdbc:oracle:thin:@db1.itservicios.local:1521/igdb switching to URL jdbc:oracle:thin:@db2.itservicios.local:1521/igdb
[2026-08-01 10:26:10,450] [audit-thread-5] [INFO ] [IG.AUDIT] [AUD152] The primary connection has been restored for repository PrimaryDB to URL jdbc:oracle:thin:@db1.itservicios.local:1521/igdb
[2026-08-01 10:28:14,210] [supersh-exec-1] [INFO ] [IG.AUDIT] [AUD116] Master keys update completed. Reason: Rotacion de claves de cifrado anual IT Servicios
[2026-08-01 10:30:00,000] [supersh-exec-2] [INFO ] [IG.AUDIT] [AUD118] Repository update status: Bulk re-encryption in progress. 45% completed.
      `.trim();
    } else if (scenario === 'entrust_idaas') {
      rawText = `
[2026-08-01 11:00:10,012] [IDaaS-Cloud-Gateway] [INFO ] [IDaaS.AUTH] User user01@itservicios-latam.com requested SAML 2.0 Single Sign-On for Salesforce.
[2026-08-01 11:00:12,450] [IDaaS-Cloud-Gateway] [ERROR] [IDaaS.SAML] [SAML_RESPONSE_EXPIRED] SAML 2.0 assertion NotOnOrAfter timestamp expired. Local NTP skew detected (+120s).
[2026-08-01 11:02:15,880] [IDaaS-MFA-Push] [ERROR] [IDaaS.MFA] [PUSH_NOTIFICATION_FAILED] Mobile Push Notification failed to deliver to device iPhone-EngTomás (Token unreachable).
[2026-08-01 11:05:00,123] [IDaaS-Cloud-Gateway] [INFO ] [IDaaS.AUTH] Fallback to Soft Token OTP successful for user user01@itservicios-latam.com.
      `.trim();
    }

    processLogText(rawText);
  }

  function showAnalysisStatus(isLoading, text, detail) {
    if (!dom.analysisStatusBar) return;
    dom.analysisStatusBar.style.display = 'flex';
    if (dom.analysisStatusText) dom.analysisStatusText.textContent = text;
    if (dom.analysisStatusDetail) dom.analysisStatusDetail.textContent = detail;

    if (dom.analysisStatusSpinner) {
      dom.analysisStatusSpinner.style.background = isLoading ? '#f59e0b' : '#0284c7';
    }
  }

  function populateClientSelector() {
    if (!dom.filterClientSelect) return;
    const currentVal = dom.filterClientSelect.value;
    const uniqueClients = [...new Set(state.logs.map(l => l.client || 'Cliente General'))];

    dom.filterClientSelect.innerHTML = '<option value="ALL">🏢 Todos los Clientes</option>';
    uniqueClients.forEach(client => {
      const opt = document.createElement('option');
      opt.value = client;
      opt.textContent = `🏢 ${client}`;
      dom.filterClientSelect.appendChild(opt);
    });

    if (uniqueClients.includes(currentVal)) {
      dom.filterClientSelect.value = currentVal;
    } else {
      dom.filterClientSelect.value = 'ALL';
    }
  }

  function processLogText(rawText, clientName = 'Entrust OnPremise') {
    const lines = rawText.split('\n').filter(l => l.trim().length > 0);
    const newLogs = lines.map((line, idx) => {
      const parsed = window.logParserEngine.parseLine(line, idx + 1);
      const diagnostic = window.knowledgeBaseEngine.diagnoseLog(parsed.message);
      return {
        ...parsed,
        client: clientName,
        diagnostic: diagnostic
      };
    });

    state.logs = newLogs;
    populateClientSelector();
    applyLogFilters();

    const targetLog = state.logs.find(l => l.level === 'CRITICAL' || l.level === 'ERROR') || state.logs[0];
    if (targetLog) {
      selectLog(targetLog);
    }
  }

  function updateMetricsAndCharts() {
    if (dom.totalLogsCount) dom.totalLogsCount.textContent = state.logs.length;

    const criticals = state.logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR');
    const warnings = state.logs.filter(l => l.level === 'WARN' || l.level === 'WARNING');

    if (dom.criticalCount) dom.criticalCount.textContent = criticals.length;
    if (dom.warningCount) dom.warningCount.textContent = warnings.length;

    if (dom.healthIndex) {
      const total = Math.max(1, state.logs.length);
      const critPenalty = criticals.length > 0 ? Math.min(65, Math.max(5, (criticals.length / total) * 100 * 5 + criticals.length * 0.2)) : 0;
      const warnPenalty = warnings.length > 0 ? Math.min(25, (warnings.length / total) * 100 * 2 + warnings.length * 0.1) : 0;
      const health = Math.max(10, Math.round(100 - critPenalty - warnPenalty));
      dom.healthIndex.textContent = `${health}%`;
    }

    updateTrendChart();
    updateSeverityChart();
  }

  function initCharts() {
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js no disponible en window. Omitiendo renderizado de canvas.');
      return;
    }
    try {
      const trendCanvas = document.getElementById('chart-trend');
      if (trendCanvas) {
        const ctx = trendCanvas.getContext('2d');
      state.charts.trend = new Chart(ctx, {
        type: 'line',
        data: {
          labels: ['10:14', '10:15', '10:16', '10:18', '10:20', '10:22', '10:25', '10:28'],
          datasets: [
            {
              label: 'Errores Entrust [520xxx / IDaaS]',
              data: [0, 1, 1, 1, 0, 1, 0, 0],
              borderColor: '#dc2626',
              backgroundColor: 'rgba(220, 38, 38, 0.1)',
              tension: 0.3,
              fill: true
            },
            {
              label: 'Alertas de Auditoría [AUDxxx]',
              data: [1, 0, 0, 0, 1, 1, 1, 2],
              borderColor: '#0284c7',
              backgroundColor: 'rgba(2, 132, 199, 0.1)',
              tension: 0.3,
              fill: true
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { labels: { color: '#475569', font: { family: 'Inter', weight: '600' } } }
          },
          scales: {
            x: { grid: { color: 'rgba(203, 213, 225, 0.3)' }, ticks: { color: '#64748b' } },
            y: { grid: { color: 'rgba(203, 213, 225, 0.3)' }, ticks: { color: '#64748b' } }
          }
        }
      });
    }

    const severityCanvas = document.getElementById('chart-severity');
    if (severityCanvas) {
      const ctxSev = severityCanvas.getContext('2d');
      state.charts.severity = new Chart(ctxSev, {
        type: 'doughnut',
        data: {
          labels: ['CRITICAL / ERROR', 'WARN (Auditoría)', 'INFO', 'DEBUG'],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [
              '#dc2626',
              '#f59e0b',
              '#0284c7',
              '#8b5cf6'
            ],
            borderWidth: 2,
            borderColor: '#ffffff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#475569', font: { family: 'Inter', weight: '600', size: 11 } }
            }
          }
        }
      });
    }
    } catch(err) {
      console.error('Error al inicializar Chart.js:', err);
    }
  }

  function updateTrendChart() {
    if (!state.charts.trend) return;
    state.charts.trend.update();
  }

  function updateSeverityChart() {
    if (!state.charts.severity) return;

    const criticalCount = state.logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length;
    const warnCount = state.logs.filter(l => l.level === 'WARN' || l.level === 'WARNING').length;
    const infoCount = state.logs.filter(l => l.level === 'INFO').length;
    const debugCount = state.logs.filter(l => l.level === 'DEBUG').length;

    state.charts.severity.data.datasets[0].data = [criticalCount, warnCount, infoCount, debugCount];
    state.charts.severity.update();
  }

  function initEventListeners() {
    dom.searchLogInput?.addEventListener('input', () => applyLogFilters());
    dom.filterClientSelect?.addEventListener('change', () => applyLogFilters());
    dom.filterLevelSelect?.addEventListener('change', () => applyLogFilters());
    dom.filterTypeSelect?.addEventListener('change', () => applyLogFilters());

    dom.btnToggleStream?.addEventListener('click', () => {
      state.isStreaming = !state.isStreaming;
      if (dom.btnToggleStream) {
        dom.btnToggleStream.textContent = state.isStreaming ? '⏸️ Pausar Simulador' : '▶️ Simulador';
      }
      if (state.isStreaming) {
        startStreamingSimulatedLogs();
      } else {
        clearInterval(state.streamInterval);
      }
    });

    dom.fileInput?.addEventListener('change', async (e) => {
      const files = Array.from(e.target.files);
      if (files.length === 0) return;

      showAnalysisStatus(true, `⚙️ Procesando e Indexando ${files.length} archivo(s)...`, 'Analizando estructura...');

      let newLogs = [];
      let fileCount = 0;

      for (const file of files) {
        try {
          const content = await file.text();
          const clientName = extractClientFromFilename(file.name);

          const parsedEntries = window.logParserEngine.parseLogs(content).map((log, idx) => ({
            ...log,
            lineNum: state.logs.length + newLogs.length + idx + 1,
            client: clientName,
            sourceFile: file.name
          }));

          newLogs = newLogs.concat(parsedEntries);
          fileCount++;
        } catch (err) {
          console.error(`Error leyendo archivo ${file.name}:`, err);
        }
      }

      if (newLogs.length > 0) {
        state.logs = state.logs.concat(newLogs);
        clearFilterMode();
        if (dom.filterLevelSelect) dom.filterLevelSelect.value = 'ALL';
        if (dom.filterTypeSelect) dom.filterTypeSelect.value = 'ALL';
        if (dom.filterClientSelect) dom.filterClientSelect.value = 'ALL';
        if (dom.searchLogInput) dom.searchLogInput.value = '';

        populateClientSelector();
        applyLogFilters();

        const targetLog = newLogs.find(l => l.level === 'CRITICAL' || l.level === 'ERROR') || newLogs[0];
        if (targetLog) {
          selectLog(targetLog);
        }

        switchTab('analyzer');

        const uniqueClients = [...new Set(state.logs.map(l => l.client || 'Cliente General'))];
        showAnalysisStatus(false, `✅ ¡Análisis Finalizado Exitosamente!`, `Se procesaron ${fileCount} archivo(s) con ${newLogs.length} registro(s) para ${uniqueClients.length} cliente(s) activo(s).`);
      }
    });
  }

  function startStreamingSimulatedLogs() {
    const samplePool = [
      '[2026-08-01 10:35:12,881] [http-nio-8080-exec-12] [ERROR] [IG.SYSTEM.SystemContext.API] [5202013] Invalid user ID or password provided for user jperez',
      '[2026-08-01 10:36:00,102] [audit-thread-8] [INFO ] [IG.AUDIT] [AUD2300] Token Entrust 88192301 has been assigned to user mrodriguez.',
      '[2026-08-01 10:37:44,512] [audit-thread-9] [ERROR] [IG.AUDIT] [AUD2309] Failed delivery of transaction details for token Entrust 88192301 for user mrodriguez.',
      '[2026-08-01 10:39:10,001] [supersh-exec-4] [INFO ] [IG.AUDIT] [AUD113] Bind key protection file completed successfully.',
      '[2026-08-01 10:40:22,300] [audit-thread-10] [WARN ] [IG.AUDIT] [AUD155] Connection pool to repository PrimaryDB is 80 percent used.'
    ];

    state.streamInterval = setInterval(() => {
      const randomLine = samplePool[Math.floor(Math.random() * samplePool.length)];
      const parsed = window.logParserEngine.parseLine(randomLine, state.logs.length + 1);
      parsed.timestamp = new Date().toLocaleTimeString();
      parsed.diagnostic = window.knowledgeBaseEngine.diagnoseLog(parsed.message);

      state.logs.push(parsed);
      applyLogFilters();
    }, 3500);
  }

  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
