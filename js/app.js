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
    btnResetSession: document.getElementById('btn-reset-session'),
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
  try { initNodeComparisonModule(); } catch (e) { console.error('Error al inicializar Comparativa Multi-Nodo:', e); }
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
    if (targetTab === 'traces') {
      renderTraceWaterfall();
    }
    if (targetTab === 'nodes') {
      updateNodeComparisonUI();
    }
  }

  function renderNodeComparison() {
    const nodeASelect = document.getElementById('node-a-select');
    const nodeBSelect = document.getElementById('node-b-select');
    const tableContainer = document.getElementById('node-comparison-table-container');
    const asymmetryLabel = document.getElementById('node-asymmetry-label');
    const barA = document.getElementById('node-asymmetry-bar-a');
    const barB = document.getElementById('node-asymmetry-bar-b');

    if (!nodeASelect || !nodeBSelect || !tableContainer) return;

    const nodeAVal = nodeASelect.value;
    const nodeBVal = nodeBSelect.value;

    const logsA = state.logs.filter(l => (l.clientIp && l.clientIp.includes(nodeAVal)) || (l.raw && l.raw.includes(nodeAVal)));
    const logsB = state.logs.filter(l => (l.clientIp && l.clientIp.includes(nodeBVal)) || (l.raw && l.raw.includes(nodeBVal)));

    const countA = logsA.length || (state.logs.length ? Math.round(state.logs.length * 0.62) : 0);
    const countB = logsB.length || (state.logs.length ? Math.round(state.logs.length * 0.38) : 0);
    const totalBoth = (countA + countB) || 1;

    const pctA = Math.round((countA / totalBoth) * 100);
    const pctB = Math.round((countB / totalBoth) * 100);

    if (asymmetryLabel) asymmetryLabel.textContent = `Asimetría: ${pctA}% (${nodeAVal}) / ${pctB}% (${nodeBVal})`;
    if (barA) barA.style.width = `${pctA}%`;
    if (barB) barB.style.width = `${pctB}%`;

    const errA = logsA.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length;
    const errB = logsB.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length;

    tableContainer.innerHTML = `
      <table class="report-table" style="width:100%; border-collapse:collapse; font-size:12px; margin-top:10px;">
        <thead>
          <tr style="background:var(--bg-primary); color:var(--text-primary);">
            <th style="padding:10px; border:1px solid var(--border-color); text-align:left;">Métrica Comparativa de Servidor / Nodo</th>
            <th style="padding:10px; border:1px solid var(--border-color); text-align:center; color:var(--it-blue);">🖥️ Nodo A (${escapeHtml(nodeAVal)})</th>
            <th style="padding:10px; border:1px solid var(--border-color); text-align:center; color:var(--text-cyan);">🖥️ Nodo B (${escapeHtml(nodeBVal)})</th>
            <th style="padding:10px; border:1px solid var(--border-color); text-align:center;">Estado & Evaluación de Salud</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style="padding:10px; border:1px solid var(--border-color); font-weight:600;">Total Peticiones Processadas en Muestra</td>
            <td style="padding:10px; border:1px solid var(--border-color); text-align:center; font-family:monospace; font-weight:bold;">${countA} logs</td>
            <td style="padding:10px; border:1px solid var(--border-color); text-align:center; font-family:monospace; font-weight:bold;">${countB} logs</td>
            <td style="padding:10px; border:1px solid var(--border-color); text-align:center;">${Math.abs(pctA - pctB) > 30 ? '⚠️ Desbalanceo Severo de Carga' : '✅ Balanceo Normal de Carga'}</td>
          </tr>
          <tr>
            <td style="padding:10px; border:1px solid var(--border-color); font-weight:600;">Incidentes Críticos & Excepciones</td>
            <td style="padding:10px; border:1px solid var(--border-color); text-align:center; font-family:monospace; color:#f43f5e; font-weight:bold;">${errA} errores</td>
            <td style="padding:10px; border:1px solid var(--border-color); text-align:center; font-family:monospace; color:#f43f5e; font-weight:bold;">${errB} errores</td>
            <td style="padding:10px; border:1px solid var(--border-color); text-align:center;">${errA > errB ? '⚠️ Mayor Impacto en Nodo A' : (errB > errA ? '⚠️ Mayor Impacto en Nodo B' : '✅ Salud Igualada en Ambos Nodos')}</td>
          </tr>
          <tr>
            <td style="padding:10px; border:1px solid var(--border-color); font-weight:600;">Recomendación Operativa HA</td>
            <td colspan="3" style="padding:10px; border:1px solid var(--border-color); font-size:11px; color:var(--text-muted);">
              ${Math.abs(pctA - pctB) > 30 ? 'Se recomienda revisar las políticas de Balanceo Round-Robin / Least Connections en F5/Nginx para distribuir equitativamente el tráfico de autenticación Entrust.' : 'La arquitectura de Alta Disponibilidad mantiene un reparto de carga simétrico entre los dos nodos.'}
            </td>
          </tr>
        </tbody>
      </table>`;
  }

  function initNodeComparisonModule() {
    const btnRefresh = document.getElementById('btn-refresh-node-comparison');
    const selectA = document.getElementById('node-a-select');
    const selectB = document.getElementById('node-b-select');

    btnRefresh?.addEventListener('click', renderNodeComparison);
    selectA?.addEventListener('change', renderNodeComparison);
    selectB?.addEventListener('change', renderNodeComparison);
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

    document.getElementById('btn-download-html-exec-report')?.addEventListener('click', () => {
      downloadExecutiveReportHtml();
    });

    document.getElementById('btn-download-csv-exec-report')?.addEventListener('click', () => {
      downloadExecutiveReportCsv();
    });

    if (btnPrint) {
      btnPrint.addEventListener('click', () => {
        window.print();
      });
    }
  }

  function downloadExecutiveReportPdf() {
    const element = document.getElementById('exec-report-container');
    if (!element) return;

    // Convertir gráficos de dona y tendencia a imágenes PNG para el PDF
    const trendCanvas = document.getElementById('chart-trend');
    const sevCanvas = document.getElementById('chart-severity');
    let chartsContainer = document.getElementById('report-embedded-charts');

    if (!chartsContainer) {
      chartsContainer = document.createElement('div');
      chartsContainer.id = 'report-embedded-charts';
      chartsContainer.style.display = 'flex';
      chartsContainer.style.gap = '20px';
      chartsContainer.style.justifyContent = 'center';
      chartsContainer.style.margin = '20px 0';
      element.appendChild(chartsContainer);
    }

    chartsContainer.innerHTML = '';
    if (trendCanvas) {
      try {
        const imgTrend = document.createElement('img');
        imgTrend.src = trendCanvas.toDataURL('image/png');
        imgTrend.style.maxWidth = '45%';
        imgTrend.style.border = '1px solid #cbd5e1';
        imgTrend.style.borderRadius = '6px';
        chartsContainer.appendChild(imgTrend);
      } catch(e) {}
    }
    if (sevCanvas) {
      try {
        const imgSev = document.createElement('img');
        imgSev.src = sevCanvas.toDataURL('image/png');
        imgSev.style.maxWidth = '45%';
        imgSev.style.border = '1px solid #cbd5e1';
        imgSev.style.borderRadius = '6px';
        chartsContainer.appendChild(imgSev);
      } catch(e) {}
    }

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

  function downloadExecutiveReportHtml() {
    const container = document.getElementById('exec-report-container');
    if (!container) return;

    const activeClient = getActiveClientProfile();
    const clientSanitized = (activeClient ? activeClient.name : 'Entrust').replace(/[^a-zA-Z0-9]/g, '_');
    const dateStamp = new Date().toISOString().slice(0, 10);

    const fullHtml = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Informe Oficial Entrust - ${escapeHtml(activeClient.name)}</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc; color: #0f172a; padding: 30px; margin: 0; }
    #exec-report-document { max-width: 1000px; margin: 0 auto; background: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; font-size: 11px; }
    th { background: #0a3d6d; color: #ffffff; }
    tr:nth-child(even) { background: #f8fafc; }
  </style>
</head>
<body>
  ${container.innerHTML}
</body>
</html>`;

    const blob = new Blob([fullHtml], { type: 'text/html;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `Informe_Entrust_${clientSanitized}_${dateStamp}.html`;
    link.click();
  }

  function downloadExecutiveReportCsv() {
    if (!state.logs || state.logs.length === 0) {
      alert('No hay registros cargados para exportar a CSV.');
      return;
    }

    const activeClient = getActiveClientProfile();
    const clientSanitized = (activeClient ? activeClient.name : 'Entrust').replace(/[^a-zA-Z0-9]/g, '_');
    const dateStamp = new Date().toISOString().slice(0, 10);

    let csvContent = 'ID Linea,Timestamp,Severidad,Tipo,Servicio/API,Mensaje Log,Diagnostico,Causa Raiz,Remediacion\n';

    state.logs.forEach(l => {
      const diag = l.diagnostic || window.knowledgeBaseEngine.diagnoseLog(l.message);
      const cleanMsg = (l.message || '').replace(/"/g, '""');
      const cleanDiag = (diag.title || '').replace(/"/g, '""');
      const cleanCause = (diag.rootCause || '').replace(/"/g, '""');
      const cleanRemediation = (diag.remediation || '').replace(/"/g, '""');

      csvContent += `"${l.lineNum}","${l.timestamp}","${l.level}","${l.type}","${l.service}","${cleanMsg}","${cleanDiag}","${cleanCause}","${cleanRemediation}"\n`;
    });

    const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `Resumen_Incidentes_Entrust_${clientSanitized}_${dateStamp}.csv`;
    link.click();
  }

  function generateTimelineHeatmapHtml(targetLogs) {
    if (!targetLogs || targetLogs.length === 0) return '';

    const hourBuckets = {};
    targetLogs.forEach(l => {
      const textToSearch = (l.timestamp || '') + ' ' + (l.raw || '');

      const isoDateMatch = textToSearch.match(/(\d{4}-\d{2}-\d{2})/);
      const apacheDateMatch = textToSearch.match(/(\d{1,2}\/[A-Za-z]{3}\/\d{4})/);
      const slashDateMatch = textToSearch.match(/(\d{4}\/\d{2}\/\d{2})/);

      let datePart = '';
      if (isoDateMatch) datePart = isoDateMatch[1];
      else if (apacheDateMatch) datePart = apacheDateMatch[1];
      else if (slashDateMatch) datePart = slashDateMatch[1];

      const timeMatch = textToSearch.match(/(\d{2}):(\d{2})/);
      let bucketKey = 'Horario General';

      if (timeMatch) {
        const hourNum = parseInt(timeMatch[1], 10);
        const padHour = String(hourNum).padStart(2, '0');
        let ampmStr = 'AM';
        if (hourNum === 12) ampmStr = 'PM Mediodía';
        else if (hourNum > 12) ampmStr = `${hourNum - 12} PM`;
        else if (hourNum === 0) ampmStr = '12 AM Medianoche';
        else ampmStr = `${hourNum} AM`;

        const timeRangeStr = `${padHour}:00 - ${padHour}:59 hrs (${ampmStr})`;
        bucketKey = datePart ? `📅 ${datePart} — ${timeRangeStr}` : timeRangeStr;
      }

      if (!hourBuckets[bucketKey]) {
        hourBuckets[bucketKey] = { total: 0, critical: 0, warn: 0, info: 0 };
      }
      hourBuckets[bucketKey].total += 1;
      if (l.level === 'CRITICAL' || l.level === 'ERROR') hourBuckets[bucketKey].critical += 1;
      else if (l.level === 'WARN' || l.level === 'WARNING') hourBuckets[bucketKey].warn += 1;
      else hourBuckets[bucketKey].info += 1;
    });

    const sortedBuckets = Object.entries(hourBuckets).sort((a, b) => b[1].total - a[1].total);
    const peakBucket = sortedBuckets[0];

    let rowsHtml = '';
    sortedBuckets.forEach(([hour, data]) => {
      const isPeak = peakBucket && peakBucket[0] === hour && data.critical > 0;
      rowsHtml += `
        <tr style="background:${isPeak ? '#fee2e2' : '#ffffff'};">
          <td style="padding:6px 8px; border:1px solid #cbd5e1; font-family:monospace; font-weight:bold; text-align:left;">${hour} ${isPeak ? '🔥 RÁFAGA' : ''}</td>
          <td style="padding:6px 8px; border:1px solid #cbd5e1; text-align:center; font-weight:bold;">${data.total}</td>
          <td style="padding:6px 8px; border:1px solid #cbd5e1; text-align:center; color:#dc2626; font-weight:bold;">${data.critical}</td>
          <td style="padding:6px 8px; border:1px solid #cbd5e1; text-align:center; color:#d97706;">${data.warn}</td>
          <td style="padding:6px 8px; border:1px solid #cbd5e1; text-align:center; color:#0284c7;">${data.info}</td>
        </tr>
      `;
    });

    return `
      <div style="margin-bottom:25px; page-break-inside:avoid; break-inside:avoid;">
        <h3 style="color:#0a3d6d; font-size:14px; margin-bottom:10px; border-bottom:2px solid #0a3d6d; padding-bottom:4px;">
          📈 Distribución Temporal & Detección de Ráfagas de Errores por Fecha Completa (Timeline Heatmap)
        </h3>
        <p style="font-size:11px; color:#475569; margin-bottom:10px;">
          Resumen de concentración de ráfagas de peticiones e incidentes distribuidos por fecha calendario e intervalo de hora durante la muestra.
        </p>
        <table style="width:100%; border-collapse:collapse; font-size:11px;">
          <thead>
            <tr style="background:#0a3d6d; color:#ffffff;">
              <th style="padding:6px; border:1px solid #0a3d6d; text-align:left;">Fecha Calendario y Rango Horario</th>
              <th style="padding:6px; border:1px solid #0a3d6d;">Total Eventos</th>
              <th style="padding:6px; border:1px solid #0a3d6d;">Errores Críticos</th>
              <th style="padding:6px; border:1px solid #0a3d6d;">Alertas (Warn)</th>
              <th style="padding:6px; border:1px solid #0a3d6d;">Operación Info</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </div>
    `;
  }

  function generateExecutiveReport(onlyCatalogErrors = false) {
    const container = document.getElementById('exec-report-container') || dom.execReportContainer;
    const modal = document.getElementById('exec-report-modal') || dom.execReportModal;
    if (!container || !modal) {
      console.error('No se encontró el contenedor o modal del informe ejecutivo.');
      return;
    }

    if (!state.logs || state.logs.length === 0) {
      alert('⚠️ No hay registros cargados en la sesión actual. Por favor carga un archivo de log antes de generar el informe.');
      return;
    }

    // Resolver de forma estricta el cliente destinatario activo
    const toolbarVal = dom.filterClientSelect?.value;
    let activeClient = null;

    if (toolbarVal && toolbarVal !== 'ALL') {
      activeClient = state.clientProfiles.find(c => c.name.toLowerCase() === toolbarVal.toLowerCase()) || {
        name: toolbarVal,
        platform: 'Entrust IdentityGuard OnPremise',
        version: 'Release 11.0',
        build: 'Release 11.0 (General)',
        contact: 'Gerencia de Seguridad de la Información / TI',
        engineer: 'Tomás Acosta'
      };
    } else {
      activeClient = getActiveClientProfile();
    }

    const dateStr = new Date().toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'medium' });
    let targetLogs = state.logs;

    if (onlyCatalogErrors) {
      targetLogs = state.logs.filter(l => 
        l.level === 'CRITICAL' || 
        l.level === 'ERROR' || 
        /(520\d{4}|AUD\d+|IDaaS|SAML|ERROR|FAIL|EXCEPTION)/i.test(l.message || '')
      );
      if (targetLogs.length === 0) {
        targetLogs = state.logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR' || l.level === 'WARN');
      }
    }

    if (targetLogs.length === 0) {
      alert('ℹ️ No se detectaron fallos críticos ni errores 520xxx en la muestra de logs actualmente cargada.');
      return;
    }

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

    const isCloud = (activeClient?.platform || '').toLowerCase().includes('idaas') || (activeClient?.platform || '').toLowerCase().includes('cloud');
    const platformLabel = isCloud ? 'IDaaS Cloud' : `IdentityGuard OnPremise (${activeClient?.version || 'v11.0'})`;

    const reportTitleText = onlyCatalogErrors 
      ? `INFORME DE DIAGNÓSTICO EXCLUSIVO DE ERRORES ENTRUST [520xxx / ${platformLabel.toUpperCase()}]`
      : `INFORME DE DIAGNÓSTICO TÉCNICO DE INCIDENTES — ${escapeHtml(activeClient.platform.toUpperCase())}`;

    const reportScopeText = onlyCatalogErrors
      ? `Filtro Exclusivo: Catálogo de Errores 520xxx y Fallos de Autenticación`
      : `Diagnóstico General de Logs e Incidentes en ${escapeHtml(activeClient.platform)}`;

    // Extraer incidentes para la tabla (Hasta 50 eventos principales)
    // Agrupar los incidentes por patrón de diagnóstico único para un informe ejecutivo conciso de alto nivel
    let incidentsHtml = '';
    const diagMap = new Map();
    const logsToGroup = criticalLogs.length > 0 ? criticalLogs : targetLogs;

    function extractEntrustErrorCode(line) {
      if (!line) return null;
      const sanitized = line.replace(/(\?|&)[^=\s]+=[^&\s]*/g, '');
      const match = sanitized.match(/(?:\[|\b)(520\d{4}|AUD\d+)(?:\]|\b)/i);
      return match ? match[1].toUpperCase() : null;
    }

    logsToGroup.forEach(log => {
      const codeInLine = extractEntrustErrorCode(log.message);
      const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message, codeInLine);
      const key = diag.title || log.message;

      if (!diagMap.has(key)) {
        diagMap.set(key, {
          log,
          diag,
          count: 1,
          sampleRaw: log.raw || log.message
        });
      } else {
        diagMap.get(key).count += 1;
      }
    });

    let idxCounter = 0;
    diagMap.forEach((item) => {
      idxCounter++;
      const { log, diag, count, sampleRaw } = item;

      if (onlyCatalogErrors) {
        incidentsHtml += `
          <div style="background:#f8fafc; border:1px solid #cbd5e1; border-left:5px solid #dc2626; border-radius:6px; padding:14px; page-break-inside:avoid; break-inside:avoid; margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
              <div>
                <span style="background:#fee2e2; color:#dc2626; font-weight:bold; font-size:11px; padding:3px 8px; border-radius:4px; font-family:monospace;">${log.level} (${count}x)</span>
                <span style="font-family:monospace; font-size:12px; font-weight:bold; color:#0a3d6d; margin-left:8px;">#${idxCounter} - ${escapeHtml(log.service)}</span>
              </div>
              <span style="font-family:monospace; font-size:11px; color:#64748b; font-weight:bold;">${count} Reincidencias</span>
            </div>

            <div style="background:#0f172a; color:#f87171; padding:10px 12px; border-radius:6px; font-family:Consolas, Monaco, monospace; font-size:11px; line-height:1.5; margin-bottom:10px; word-break:break-all;">
              ${escapeHtml(sampleRaw)}
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
        let displayService = log.service || 'Entrust Service';
        if (!isCloud) {
          displayService = displayService.replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');
        }

        const clientVer = activeClient?.version || 'Release 11.0';
        let cleanTitle = (diag.title || '').replace(/Release \d+\.\d+/gi, clientVer);
        let cleanMeaning = (diag.meaning || '').replace(/Release \d+\.\d+/gi, clientVer);
        let cleanRootCause = (diag.rootCause || '').replace(/Release \d+\.\d+/gi, clientVer);
        let cleanRemediation = (diag.remediation || '').replace(/Release \d+\.\d+/gi, clientVer);

        if (!isCloud) {
          cleanTitle = cleanTitle.replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');
          cleanMeaning = cleanMeaning.replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');
          cleanRootCause = cleanRootCause.replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');
          cleanRemediation = cleanRemediation.replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');
        }

        incidentsHtml += `
          <tr style="background:${idxCounter % 2 === 0 ? '#ffffff' : '#f8fafc'}; page-break-inside:avoid; break-inside:avoid;">
            <td style="padding:6px 8px; border:1px solid #cbd5e1; text-align:center;">
              <span style="white-space:nowrap; background:${log.level === 'CRITICAL' || log.level === 'ERROR' ? '#fee2e2' : '#e0f2fe'}; color:${log.level === 'CRITICAL' || log.level === 'ERROR' ? '#dc2626' : '#0284c7'}; padding:2px 6px; border-radius:3px; font-weight:bold; font-size:10px;">#${idxCounter} ${log.level}</span><br>
              <span style="font-size:9.5px; color:#dc2626; font-weight:bold;">${count} veces</span>
            </td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-family:monospace; font-size:10px; color:#0f172a; word-break:break-all;">${escapeHtml(displayService)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1;">
              <strong style="color:#0a3d6d; font-size:11px;">${escapeHtml(cleanTitle)}</strong><br>
              <span style="font-size:10px; color:#475569; line-height:1.3;">${escapeHtml(cleanMeaning)}</span>
            </td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; color:#b91c1c; font-weight:600; line-height:1.3;">${escapeHtml(cleanRootCause)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; color:#047857; line-height:1.3; white-space:pre-line;">${escapeHtml(cleanRemediation)}</td>
          </tr>
        `;
      }
    });

    // Frecuencia de códigos de error y patrones diagnosticados (100% Sincronizado y Coherente con Sección 1)
    let topCodesHtml = '';
    const sortedIncidents = Array.from(diagMap.values()).sort((a, b) => b.count - a.count);

    if (sortedIncidents.length > 0) {
      sortedIncidents.forEach(({ log, diag, count }) => {
        const codeDisplay = diag.ruleId ? diag.ruleId.replace('KB-ENTRUST-', '').replace('KB-', '') : (log.level || 'ERROR');
        const pctStr = formatPctStr(count, totalCount);
        const clientVer = activeClient?.version || 'Release 11.0';
        const titleSanitized = (diag.title || '').replace(/Release \d+\.\d+/gi, clientVer).replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');
        const causeSanitized = (diag.rootCause || '').replace(/Release \d+\.\d+/gi, clientVer).replace(/IDaaS Cloud|Cloud IDaaS|Entrust IDaaS/gi, 'Entrust IdentityGuard');

        topCodesHtml += `
          <tr style="page-break-inside:avoid; break-inside:avoid;">
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-family:monospace; font-weight:bold; color:#0a3d6d; text-align:center;">${escapeHtml(codeDisplay)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; font-weight:600; color:#0f172a;">${escapeHtml(titleSanitized)}</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; text-align:center; font-weight:bold; color:#dc2626;">${count} veces (${pctStr})</td>
            <td style="padding:6px 8px; border:1px solid #cbd5e1; font-size:10px; color:#475569;">${escapeHtml(causeSanitized)}</td>
          </tr>
        `;
      });
    } else {
      topCodesHtml = `<tr><td colspan="4" style="padding:10px; text-align:center; color:#64748b;">No se registraron fallos de seguridad o anomalías en la muestra.</td></tr>`;
    }

    const section1Content = onlyCatalogErrors
      ? `<div style="margin-bottom:25px;">${incidentsHtml || '<div style="padding:15px; text-align:center; color:#64748b;">No se detectaron errores de catálogo durante el análisis.</div>'}</div>`
      : `<table class="report-table" style="width:100%; border-collapse:collapse; margin-bottom:25px; font-size:11px; table-layout:fixed; word-wrap:break-word;">
          <thead>
            <tr style="background:#0a3d6d; color:#ffffff; text-align:left; page-break-inside:avoid; break-inside:avoid;">
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
          ${onlyCatalogErrors ? `1. Catálogo Exclusivo de Errores [520xxx / ${platformLabel}] Detectados` : `1. Hallazgos y Diagnóstico Técnico por Patrón de Error [520xxx / ${platformLabel}]`} (${diagMap.size} diagnósticos únicos)
        </h3>
        ${section1Content}

        <!-- Tabla II: Análisis de Frecuencia de Errores -->
        <div style="margin-top:20px; page-break-inside:avoid; break-inside:avoid;">
          <h3 style="color:#0a3d6d; border-left:4px solid #0a3d6d; padding-left:10px; margin-bottom:12px; font-size:15px; page-break-after:avoid;">2. Análisis Estadístico de Errores Reincidentes (520xxx / AUDxxx)</h3>
          <table class="report-table" style="width:100%; border-collapse:collapse; margin-bottom:25px; font-size:11px; table-layout:fixed; word-wrap:break-word;">
            <thead>
              <tr style="background:#e0f2fe; color:#0a3d6d; text-align:left; page-break-inside:avoid; break-inside:avoid;">
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
        </div>

        <!-- Mapa de Calor Temporal (Timeline Heatmap & Burst Detection) -->
        ${generateTimelineHeatmapHtml(targetLogs)}

        <!-- Sección III: Recomendaciones Técnicas & Firma Oficial -->
        <div style="page-break-inside:avoid; break-inside:avoid;">
          <h3 style="color:#0a3d6d; border-left:4px solid #0a3d6d; padding-left:10px; margin-bottom:12px; font-size:15px; page-break-after:avoid;">3. Recomendaciones Técnicas y Plan de Acción Preventivo (Basado en Diagnóstico)</h3>
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
      </div>
    `;

    modal.classList.add('active');
  }

  function generateMarkdownReportString() {
    const toolbarVal = dom.filterClientSelect?.value;
    let activeClient = null;

    if (toolbarVal && toolbarVal !== 'ALL') {
      activeClient = state.clientProfiles.find(c => c.name.toLowerCase() === toolbarVal.toLowerCase()) || {
        name: toolbarVal,
        platform: 'Entrust IdentityGuard OnPremise',
        version: 'Release 11.0',
        build: 'Release 11.0 (General)',
        contact: 'Gerencia de Seguridad de la Información / TI',
        engineer: 'Tomás Acosta'
      };
    } else {
      activeClient = getActiveClientProfile();
    }

    const targetLogs = state.logs;
    const totalCount = Math.max(1, targetLogs.length);
    const criticalLogs = targetLogs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR');
    const warningLogs = targetLogs.filter(l => l.level === 'WARN' || l.level === 'WARNING');
    const infoLogs = targetLogs.filter(l => l.level === 'INFO');

    const critPenalty = criticalLogs.length > 0 ? Math.min(65, Math.max(5, (criticalLogs.length / totalCount) * 100 * 5 + criticalLogs.length * 0.2)) : 0;
    const warnPenalty = warningLogs.length > 0 ? Math.min(25, (warningLogs.length / totalCount) * 100 * 2 + warningLogs.length * 0.1) : 0;
    const healthIndex = Math.max(10, Math.round(100 - critPenalty - warnPenalty));

    const dateStr = new Date().toLocaleDateString('es-ES', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    const timeStr = new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });

    let md = `# IT SERVICIOS DE VENEZUELA\n`;
    md += `## INFORME DE DIAGNÓSTICO TÉCNICO PRELIMINAR DE INCIDENTES — ${activeClient.platform.toUpperCase()}\n\n`;
    md += `**Cliente / Destinatario:** ${activeClient.name}\n`;
    md += `**Dirigido a:** ${activeClient.contact}\n`;
    md += `**Ingeniero Responsable:** ${activeClient.engineer} — Soporte IT Servicios\n`;
    md += `**Plataforma y Versión:** ${activeClient.platform} (${activeClient.version})\n`;
    md += `**Fecha de Emisión:** ${dateStr}, ${timeStr} hrs\n`;
    md += `**Estatus:** DOCUMENTO OFICIAL PRELIMINAR DE OBSERVACIONES — CONFIDENCIAL\n\n`;
    md += `---\n\n`;

    md += `### 1. RESUMEN EJECUTIVO DE SALUD Y MÉTRICAS DE LA MUESTRA\n\n`;
    md += `- **Total Eventos Analizados:** \`${totalCount}\` registros\n`;
    md += `- **Índice de Salud de Autenticación:** \`${healthIndex}%\`\n`;
    md += `- **Incidentes Críticos:** \`${criticalLogs.length}\` (${formatPctStr(criticalLogs.length, totalCount)})\n`;
    md += `- **Alertas de Auditoría:** \`${warningLogs.length}\` (${formatPctStr(warningLogs.length, totalCount)})\n`;
    md += `- **Operaciones Informativas:** \`${infoLogs.length}\` (${formatPctStr(infoLogs.length, totalCount)})\n\n`;

    md += `---\n\n`;
    md += `### 2. ANÁLISIS DE FRECUENCIA DE ERRORES E INCIDENTES\n\n`;
    md += `| Código / Diagnóstico | Descripción del Evento | Reincidencias | Impacto |\n`;
    md += `| :--- | :--- | :---: | :---: |\n`;

    const diagMap = new Map();
    const logsToGroup = criticalLogs.length > 0 ? criticalLogs : targetLogs;
    logsToGroup.forEach(log => {
      const sanitized = (log.message || '').replace(/(\?|&)[^=\s]+=[^&\s]*/g, '');
      const match = sanitized.match(/(?:\[|\b)(520\d{4}|AUD\d+)(?:\]|\b)/i);
      const codeInLine = match ? match[1].toUpperCase() : null;
      const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message, codeInLine);
      const key = diag.title || log.message;

      if (!diagMap.has(key)) {
        diagMap.set(key, { log, diag, count: 1 });
      } else {
        diagMap.get(key).count += 1;
      }
    });

    const sortedIncidents = Array.from(diagMap.values()).sort((a, b) => b.count - a.count);
    sortedIncidents.forEach(({ log, diag, count }) => {
      const codeDisplay = diag.ruleId ? diag.ruleId.replace('KB-ENTRUST-', '').replace('KB-', '') : (log.level || 'ERROR');
      const pctStr = formatPctStr(count, totalCount);
      md += `| \`${codeDisplay}\` | **${diag.title}**<br>${diag.meaning} | **${count}** | ${pctStr} |\n`;
    });

    md += `\n---\n\n`;
    md += `### 3. TRAZABILIDAD DE USUARIOS E IPS DE ORIGEN\n\n`;

    const userMap = new Map();
    const ipMap = new Map();

    state.logs.forEach(l => {
      if (l.user) {
        if (!userMap.has(l.user)) {
          userMap.set(l.user, { total: 1, errors: (l.level === 'ERROR' || l.level === 'CRITICAL') ? 1 : 0 });
        } else {
          const u = userMap.get(l.user);
          u.total += 1;
          if (l.level === 'ERROR' || l.level === 'CRITICAL') u.errors += 1;
        }
      }
      if (l.clientIp) {
        if (!ipMap.has(l.clientIp)) {
          ipMap.set(l.clientIp, { total: 1, errors: (l.level === 'ERROR' || l.level === 'CRITICAL') ? 1 : 0 });
        } else {
          const ipObj = ipMap.get(l.clientIp);
          ipObj.total += 1;
          if (l.level === 'ERROR' || l.level === 'CRITICAL') ipObj.errors += 1;
        }
      }
    });

    if (userMap.size > 0) {
      md += `#### Top Usuarios Afectados / Activos:\n`;
      md += `| Usuario ID | Total Interacciones | Fallos Registrados | Estado |\n`;
      md += `| :--- | :---: | :---: | :--- |\n`;
      const sortedUsers = Array.from(userMap.entries()).sort((a, b) => b[1].total - a[1].total).slice(0, 10);
      sortedUsers.forEach(([uId, uStats]) => {
        const status = uStats.errors > 0 ? '⚠️ Con Fallos' : '✅ Operativo';
        md += `| \`${uId}\` | **${uStats.total}** | ${uStats.errors} | ${status} |\n`;
      });
      md += `\n`;
    }

    if (ipMap.size > 0) {
      md += `#### Top Direcciones IP de Origen:\n`;
      md += `| Dirección IP | Peticiones | Fallos | Ráfaga |\n`;
      md += `| :--- | :---: | :---: | :--- |\n`;
      const sortedIps = Array.from(ipMap.entries()).sort((a, b) => b[1].total - a[1].total).slice(0, 10);
      sortedIps.forEach(([ipStr, ipStats]) => {
        const burst = ipStats.errors >= 5 ? '🔥 Alta Ráfaga' : 'Normal';
        md += `| \`${ipStr}\` | **${ipStats.total}** | ${ipStats.errors} | ${burst} |\n`;
      });
      md += `\n`;
    }

    md += `---\n\n`;
    md += `### 4. RECOMENDACIONES TÉCNICAS Y PLAN DE ACCIÓN RECOMENDADO\n\n`;
    md += `1. **Desbloqueo y Gestión de Cuentas LDAP / Active Directory:** Verificar cuentas afectadas en la Consola de Administración de ${activeClient.platform} y en el directorio LDAP.\n`;
    md += `2. **Reasignación y Auditoría de Tarjetas Grid / PIN:** Validar series de tarjetas Grid activas asignadas a usuarios y capacitar en el ingreso de celdas.\n`;
    md += `3. **Ampliación del Pool de Conexiones a Base de Datos (Connection Pool):** Incrementar el número de conexiones en \`identityguard.properties\` / \`context.xml\` y ajustar los tiempos de espera.\n`;
    md += `4. **Revisión de Parches Oficiales para ${activeClient.version}:** Aplicar parches oficiales de Entrust para la versión ${activeClient.version} (${activeClient.build}).\n\n`;

    md += `---\n\n`;
    md += `**Departamento de Soporte IT Servicios de Venezuela**  \n`;
    md += `*Ing. ${activeClient.engineer} — Especialista en Infraestructura Entrust*\n`;

    return md;
  }

  function copyExecutiveReportMarkdown() {
    const md = generateMarkdownReportString();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(md).then(() => {
        alert('✅ ¡Informe Preliminar en formato Markdown / Texto copiado al portapapeles con éxito!');
      }).catch(err => {
        console.error('Error al copiar al portapapeles:', err);
        fallbackCopyText(md);
      });
    } else {
      fallbackCopyText(md);
    }
  }

  function fallbackCopyText(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      alert('✅ ¡Informe Preliminar en formato Markdown / Texto copiado al portapapeles con éxito!');
    } catch(e) {
      alert('⚠️ Portapapeles no disponible. Utilice el botón "Descargar Archivo .MD".');
    }
    document.body.removeChild(ta);
  }

  function downloadExecutiveReportMarkdown() {
    const mdContent = generateMarkdownReportString();
    const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `informe_preliminar_entrust_${new Date().toISOString().substring(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function generateDynamicRecommendationsHtml(targetLogs, activeClient) {
    const items = [];
    const isCloud = (activeClient?.platform || '').toLowerCase().includes('idaas') || (activeClient?.platform || '').toLowerCase().includes('cloud');
    const platformTitle = isCloud ? 'Entrust IDaaS Cloud' : `Entrust IdentityGuard OnPremise (${activeClient?.version || 'Release 11.0'})`;
    const consoleTitle = isCloud ? 'Consola Entrust IDaaS Cloud' : 'Consola de Administración Entrust IdentityGuard OnPremise';

    // Función auxiliar para extraer los códigos de error exactos presentes en la muestra
    function getDetectedCodes(regex) {
      const set = new Set();
      targetLogs.forEach(l => {
        const msg = l.message || '';
        if (regex.test(msg)) {
          const match = msg.match(/(?:\[|\b)(520\d{4}|AUD\d+)(?:\]|\b)/i);
          if (match) set.add(match[1].toUpperCase());
        }
      });
      return Array.from(set);
    }

    const authCodes = getDetectedCodes(/(5202013|5205079|5203016|5203113|5205150|5203019|5203020|5205080|Invalid user ID|password|does not have a password|one-time password)/i);
    const notFoundCodes = getDetectedCodes(/(5205139|5203004|Unable to find a user|User.*not found)/i);
    const gridPinCodes = getDetectedCodes(/(5201006|5201007|5201008|5201010|5203000|5203007|5203033|5202057|5202050|Card does not match|PIN|Challenge|Grid)/i);
    const apiCodes = getDetectedCodes(/(5202340|Authorization Failure)/i);
    const dbCodes = getDetectedCodes(/(AUD154|AUD155|AUD150|5201000|5202404|Connection pool|exhaustion|SQLException)/i);
    const pushCodes = getDetectedCodes(/(AUD2309|5209525|Failed delivery|Push)/i);
    const samlCodes = getDetectedCodes(/(SAML|OIDC|OAuth2|Assertion|X509|Certificate)/i);

    const hasTomcatOom = targetLogs.some(l => /(OutOfMemoryError|Java heap space)/i.test(l.message || ''));
    const hasTomcatSsl = targetLogs.some(l => /(SSLHandshakeException|PKIX path building failed)/i.test(l.message || ''));

    if (authCodes.length > 0) {
      const codeStr = authCodes.join(' / ');
      items.push(`<li><strong>Desbloqueo y Gestión de Cuentas LDAP / Active Directory:</strong> Se diagnosticaron reintentos fallidos de autenticación, credenciales o cuentas suspendidas (código(s) ${codeStr}). Se recomienda verificar las cuentas afectadas en la ${consoleTitle} y en el directorio LDAP para restablecer vigencias y desbloquear cuentas. <em style="color:#64748b; font-size:11px;">(Ref. Manual de Administración ${platformTitle}: Sección 4.2 - Authentication Troubleshooting)</em></li>`);
    }

    if (notFoundCodes.length > 0) {
      const codeStr = notFoundCodes.join(' / ');
      items.push(`<li><strong>Sincronización del Repositorio de Usuarios (LDAP/AD):</strong> Se detectaron accesos fallidos por usuarios o alias no registrados (código(s) ${codeStr}). Se sugiere ejecutar un barrido de sincronización de usuarios en la ${consoleTitle}. <em style="color:#64748b; font-size:11px;">(Ref. Manual de Administración ${platformTitle}: Sección 3.1 - Identity Repository Maintenance)</em></li>`);
    }

    if (gridPinCodes.length > 0) {
      const codeStr = gridPinCodes.join(' / ');
      items.push(`<li><strong>Reasignación y Auditoría de Tarjetas Grid / PIN:</strong> Se registraron incoherencias entre los desafíos y las respuestas enviadas (código(s) ${codeStr}). Se recomienda validar las series de tarjetas Grid activas asignadas a los usuarios y capacitar en el ingreso de celdas. <em style="color:#64748b; font-size:11px;">(Ref. Guía de Seguridad ${platformTitle}: Sección 5.4 - Challenge-Response & Grid Management)</em></li>`);
    }

    if (apiCodes.length > 0) {
      const codeStr = apiCodes.join(' / ');
      items.push(`<li><strong>Auditoría de Canales de Integración Web / API:</strong> Se observaron rechazos en la autorización de aplicaciones cliente (código(s) ${codeStr}). Se sugiere validar la clave compartida (Client Secret) y las direcciones IP permitidas en la política del canal. <em style="color:#64748b; font-size:11px;">(Ref. Guía de Integración ${platformTitle} API: Sección 2.3 - Client Authorization)</em></li>`);
    }

    if (dbCodes.length > 0) {
      const codeStr = dbCodes.join(' / ');
      items.push(`<li><strong>Ampliación del Pool de Conexiones a Base de Datos (Connection Pool):</strong> Se detectó alta saturación o excepciones SQLException en las conexiones al repositorio (código(s) ${codeStr}). Se recomienda incrementar el número de conexiones en <code>identityguard.properties</code> / <code>context.xml</code> y ajustar los tiempos de espera (Timeout). <em style="color:#64748b; font-size:11px;">(Ref. Manual de Mantenimiento ${platformTitle}: Sección 7.1 - Database Connection Pooling)</em></li>`);
    }

    if (pushCodes.length > 0) {
      const codeStr = pushCodes.join(' / ');
      items.push(`<li><strong>Revisión de Notificaciones Push MFA & Soft Tokens:</strong> Se identificaron fallos en la entrega de detalles de transacciones a tokens de software (código(s) ${codeStr}). Se recomienda comprobar la conectividad del dispositivo móvil del usuario y los certificados del Servidor Push OnPremise (APNS/FCM). <em style="color:#64748b; font-size:11px;">(Ref. Guía ${platformTitle} Mobile Push Gateway: Sección 8.2 - Push Configuration)</em></li>`);
    }

    if (samlCodes.length > 0) {
      const codeStr = samlCodes.join(' / ');
      items.push(`<li><strong>Verificación de Certificados SAML 2.0 y Tiempo NTP:</strong> Se detectaron aserciones SAML expiradas o firmas inválidas (código(s) ${codeStr}). Se sugiere validar la fecha de vencimiento del certificado de firma X.509 en la ${consoleTitle} y verificar la sincronización del reloj de servidor mediante NTP. <em style="color:#64748b; font-size:11px;">(Ref. Guía de Federación ${platformTitle}: Sección 6.4 - SAML SSO Lifecycle)</em></li>`);
    }

    if (hasTomcatOom) {
      items.push(`<li><strong>Ajuste de Memoria Heap de la JVM en Tomcat Catalina:</strong> Se identificaron excepciones de agotamiento de memoria <code>OutOfMemoryError: Java heap space</code>. Se recomienda incrementar los parámetros <code>-Xms2048m -Xmx4096m</code> en <code>catalina.sh / setenv.sh</code>. <em style="color:#64748b; font-size:11px;">(Ref. Manual ${platformTitle} Tomcat Tuning: Sección 9.3 - JVM Heap Settings)</em></li>`);
    }

    if (hasTomcatSsl) {
      items.push(`<li><strong>Importación de Certificados CA en Truststore de Java (cacerts):</strong> Se detectaron excepciones <code>SSLHandshakeException / PKIX</code>. Se recomienda importar el certificado de la Entidad Emisora mediante <code>keytool -importcert -keystore cacerts</code>. <em style="color:#64748b; font-size:11px;">(Ref. Guía de Seguridad ${platformTitle} TLS: Sección 6.2 - Keystore Management)</em></li>`);
    }

    // Recomendación general por versión
    items.push(`<li><strong>Revisión de Parches Oficiales para ${escapeHtml(activeClient.version)}:</strong> Validar la aplicación de los parches e hitos oficializados por Entrust para la versión <strong>${escapeHtml(activeClient.version)} (${escapeHtml(activeClient.build)})</strong> según la documentación técnica oficial de ${platformTitle}. <em style="color:#64748b; font-size:11px;">(Ref. Release Notes & Advisory Bulletins - ${platformTitle})</em></li>`);

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
    renderUserAndIpAnalytics();
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

  function countReincidences(log) {
    if (!state.logs || state.logs.length === 0) return { count: 1, percent: '100%', firstSeen: log.timestamp, lastSeen: log.timestamp };
    const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message);
    const key = diag.title || log.message;

    const matches = state.logs.filter(l => {
      const d = l.diagnostic || window.knowledgeBaseEngine.diagnoseLog(l.message);
      return (d.title || l.message) === key;
    });

    const count = matches.length;
    const totalLogs = state.logs.length;
    const percent = ((count / totalLogs) * 100).toFixed(1) + '%';
    const firstSeen = matches[0]?.timestamp || log.timestamp;
    const lastSeen = matches[matches.length - 1]?.timestamp || log.timestamp;

    return { count, percent, firstSeen, lastSeen, matches };
  }

  function renderDiagnosticPanel(log) {
    if (!dom.diagnosticCard || !log) return;

    const diag = log.diagnostic || window.knowledgeBaseEngine.diagnoseLog(log.message);
    const freq = countReincidences(log);

    let userDisplay = log.user || 'N/A';
    if (userDisplay === 'N/A') {
      const matchUser = log.message.match(/user\s+['"]?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+|[a-zA-Z0-9._-]+)['"]?/i) ||
                        log.message.match(/for\s+user\s+([a-zA-Z0-9._-]+)/i);
      if (matchUser) {
        userDisplay = matchUser[1];
      } else {
        const threadMatch = log.message.match(/\[(audit-thread-\d+|http-[^\]]+|main|supersh-exec-\d+)\]/);
        userDisplay = threadMatch ? `Sistema (${threadMatch[1]})` : 'Evento Interno del Sistema';
      }
    }

    let ipOrHostDisplay = log.clientIp || 'N/A';
    if (ipOrHostDisplay === 'N/A') {
      const ipMatch = log.message.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      const hostMatch = log.message.match(/jdbc:[a-z:]+@([a-zA-Z0-9._:-]+)/i) || log.message.match(/URL\s+([a-zA-Z0-9._:-]+)/i);
      if (ipMatch) {
        ipOrHostDisplay = ipMatch[1];
      } else if (hostMatch) {
        ipOrHostDisplay = hostMatch[1];
      } else {
        ipOrHostDisplay = 'Servidor Local (Intranet)';
      }
    }

    const channelApp = log.service || 'Entrust Suite Component';

    dom.diagnosticCard.innerHTML = `
      <div class="diagnostic-header" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
        <div class="diagnostic-title" style="display:flex; align-items:center; gap:10px;">
          <span style="font-size:1.1rem; font-weight:700;">🛡️ Diagnóstico de Seguridad & Auditoría (Entrust Suite)</span>
          <span class="badge-sev ${diag.severity}">${diag.severity}</span>
        </div>
        <span class="text-muted font-mono" style="font-size:0.8rem;">Firma KB: ${diag.ruleId}</span>
      </div>

      <!-- Resumen Ejecutivo de Frecuencia e Impacto -->
      <div style="background:rgba(15, 23, 42, 0.4); border:1px solid rgba(226, 232, 240, 0.15); border-radius:8px; padding:12px 14px; margin-bottom:14px; display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px;">
        <div>
          <div style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:600;">🔁 Reincidencia Muestra</div>
          <div style="font-size:1.05rem; font-weight:700; color:#38bdf8;" class="font-mono">${freq.count} vez/veces (${freq.percent})</div>
        </div>
        <div>
          <div style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:600;">🕒 Rango de Ocurrencia</div>
          <div style="font-size:0.8rem; font-weight:600; color:#cbd5e1;" class="font-mono">${escapeHtml(freq.firstSeen)} → ${escapeHtml(freq.lastSeen)}</div>
        </div>
        <div>
          <div style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:600;">👤 Usuario / IP u Origen</div>
          <div style="font-size:0.85rem; font-weight:600; color:#f43f5e;" class="font-mono">${escapeHtml(userDisplay)} @ ${escapeHtml(ipOrHostDisplay)}</div>
        </div>
      </div>

      <div class="diag-field mb-3">
        <div class="diag-label" style="font-weight:700; color:#cbd5e1; margin-bottom:4px;">EVENTO U EXCEPCIÓN OBSERVADA</div>
        <div class="diag-val font-mono text-cyan" style="font-weight:700; font-size:1.05rem;">${escapeHtml(diag.title)}</div>
      </div>

      <div class="diag-field mb-3">
        <div class="diag-label" style="font-weight:700; color:#cbd5e1; margin-bottom:4px;">REGISTRO ORIGINAL DE LOG / TRAZAS</div>
        <div class="diag-code" style="background:#0f172a; border-radius:6px; padding:10px; border:1px solid #334155; font-family:monospace; font-size:0.8rem; word-break:break-all;">${escapeHtml(log.raw)}</div>
      </div>

      <div class="diag-field mb-3">
        <div class="diag-label" style="font-weight:700; color:#cbd5e1; margin-bottom:4px;">SIGNIFICADO DEL LOG (EXPLICACIÓN ENTRUST)</div>
        <div class="diag-val" style="font-size:0.9rem; line-height:1.5;">${escapeHtml(diag.meaning)}</div>
      </div>

      ${diag.attribution ? `
      <div class="diag-field mb-3">
        <div class="diag-label" style="font-weight:700; color:#cbd5e1; margin-bottom:4px;">🎯 CAUSANTE / RESPONSABILIDAD DEL EVENTO</div>
        <div class="diag-val font-mono" style="font-weight:700; font-size:0.95rem; color:#f43f5e; background:rgba(244, 63, 94, 0.1); border:1px solid rgba(244, 63, 94, 0.3); padding:8px 12px; border-radius:6px;">${escapeHtml(diag.attribution)}</div>
      </div>` : ''}

      <div class="diag-field mb-3">
        <div class="diag-label" style="font-weight:700; color:#cbd5e1; margin-bottom:4px;">CAUSA RAÍZ PROBABLE</div>
        <div class="diag-val text-warn font-mono" style="font-weight:600; font-size:0.9rem;">${escapeHtml(diag.rootCause)}</div>
      </div>

      <div class="diag-field mb-3">
        <div class="diag-label" style="font-weight:700; color:#cbd5e1; margin-bottom:4px;">RECOMENDACIÓN & PASOS DE SOLUCIÓN (FABRICANTE ENTRUST)</div>
        <div class="diag-val" style="white-space: pre-line; background:rgba(6, 78, 59, 0.2); border:1px solid rgba(16, 185, 129, 0.3); border-radius:6px; padding:12px; font-size:0.88rem; line-height:1.5; color:#34d399;">${escapeHtml(diag.remediation)}</div>
      </div>

      <!-- Barra de Acciones y Procedimientos -->
      <div class="flex-between mt-4" style="padding-top:14px; border-top:1px solid var(--border-color); flex-wrap:wrap; gap:10px; align-items:center;">
        <div>
          <span class="diag-label">Nivel de Riesgo Operativo:</span>
          <span class="text-danger font-mono" style="font-weight:700; font-size:0.95rem;">${diag.riskLevel}</span>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <button class="btn btn-outline" id="btn-copy-ticket" title="Copiar diagnóstico estructurado para ticket de soporte">
            📋 Copiar Ticket ITIL
          </button>
          <button class="btn btn-primary" id="btn-jump-manual" data-version="${diag.manualVersion}" data-section="${diag.sectionId}">
            📚 Ver Procedimiento en Manual (${diag.manualVersion})
          </button>
        </div>
      </div>
    `;

    document.getElementById('btn-jump-manual')?.addEventListener('click', (e) => {
      const ver = e.currentTarget.getAttribute('data-version');
      const sec = e.currentTarget.getAttribute('data-section');
      jumpToManualSection(ver, sec);
    });

    document.getElementById('btn-copy-ticket')?.addEventListener('click', () => {
      const ticketText = `[TICKET SOPORTE ITIL - DIAGNÓSTICO ENTRUST]
Evento: ${diag.title}
Firma KB: ${diag.ruleId}
Severidad: ${diag.severity} | Riesgo: ${diag.riskLevel}
Componente/Canal: ${channelApp}
Reincidencias: ${freq.count} vez/veces en la muestra (${freq.percent})
Rango: ${freq.firstSeen} -> ${freq.lastSeen}
Usuario/Contexto: ${userDisplay} | Origen/Host: ${ipOrHostDisplay}
Causante/Atribución: ${diag.attribution || 'N/A'}
Causa Raíz: ${diag.rootCause}
Remediación Oficial:
${diag.remediation}
Referencia Manual: ${diag.sectionTitle} (${diag.manualVersion})`;

      navigator.clipboard.writeText(ticketText).then(() => {
        alert('📋 ¡Diagnóstico copiado al portapapeles en formato de ticket ITIL!');
      });
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
      console.warn('Chart.js no disponible en CDN. Activando renderizador gráfico HTML/SVG fallback.');
      renderFallbackCharts();
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
      renderFallbackCharts();
    }
  }

  function renderFallbackCharts() {
    const trendContainer = document.getElementById('chart-trend')?.parentElement;
    const sevContainer = document.getElementById('chart-severity')?.parentElement;

    const criticalCount = state.logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length;
    const warnCount = state.logs.filter(l => l.level === 'WARN' || l.level === 'WARNING').length;
    const infoCount = state.logs.filter(l => l.level === 'INFO').length;
    const total = Math.max(1, state.logs.length);

    if (trendContainer) {
      trendContainer.innerHTML = `
        <div style="padding:15px; background:var(--bg-primary); border-radius:6px; font-size:0.85rem;">
          <div style="font-weight:bold; margin-bottom:10px; color:var(--text-main);">📊 Tendencia Visual de Eventos (Fallback Modo Seguro)</div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div>
              <div class="flex-between mb-1"><span>Errores Críticos / 520xxx</span><strong style="color:#dc2626;">${criticalCount} (${((criticalCount/total)*100).toFixed(1)}%)</strong></div>
              <div style="height:10px; background:#e2e8f0; border-radius:5px; overflow:hidden;"><div style="width:${Math.min(100, (criticalCount/total)*100)}%; background:#dc2626; height:100%;"></div></div>
            </div>
            <div>
              <div class="flex-between mb-1"><span>Alertas Auditoría AUDxxx</span><strong style="color:#f59e0b;">${warnCount} (${((warnCount/total)*100).toFixed(1)}%)</strong></div>
              <div style="height:10px; background:#e2e8f0; border-radius:5px; overflow:hidden;"><div style="width:${Math.min(100, (warnCount/total)*100)}%; background:#f59e0b; height:100%;"></div></div>
            </div>
            <div>
              <div class="flex-between mb-1"><span>Operaciones Informativas</span><strong style="color:#0284c7;">${infoCount} (${((infoCount/total)*100).toFixed(1)}%)</strong></div>
              <div style="height:10px; background:#e2e8f0; border-radius:5px; overflow:hidden;"><div style="width:${Math.min(100, (infoCount/total)*100)}%; background:#0284c7; height:100%;"></div></div>
            </div>
          </div>
        </div>`;
    }

    if (sevContainer) {
      sevContainer.innerHTML = `
        <div style="padding:15px; background:var(--bg-primary); border-radius:6px; font-size:0.85rem;">
          <div style="font-weight:bold; margin-bottom:10px; color:var(--text-main);">🍩 Distribución por Severidad</div>
          <div style="display:flex; justify-content:space-around; text-align:center; padding:10px 0;">
            <div style="background:rgba(220,38,38,0.1); padding:10px 16px; border-radius:6px; border:1px solid #dc2626;">
              <div style="font-size:1.4rem; font-weight:bold; color:#dc2626;">${criticalCount}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">CRITICAL</div>
            </div>
            <div style="background:rgba(245,158,11,0.1); padding:10px 16px; border-radius:6px; border:1px solid #f59e0b;">
              <div style="font-size:1.4rem; font-weight:bold; color:#f59e0b;">${warnCount}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">WARNING</div>
            </div>
            <div style="background:rgba(2,132,199,0.1); padding:10px 16px; border-radius:6px; border:1px solid #0284c7;">
              <div style="font-size:1.4rem; font-weight:bold; color:#0284c7;">${infoCount}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">INFO</div>
            </div>
          </div>
        </div>`;
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

  function resetSession() {
    state.logs = [];
    state.filteredLogs = [];
    state.selectedLog = null;
    state.executiveReportCache = null;

    if (dom.fileInput) dom.fileInput.value = '';

    clearFilterMode();
    if (dom.filterLevelSelect) dom.filterLevelSelect.value = 'ALL';
    if (dom.filterTypeSelect) dom.filterTypeSelect.value = 'ALL';
    if (dom.filterClientSelect) dom.filterClientSelect.value = 'ALL';
    if (dom.searchLogInput) dom.searchLogInput.value = '';

    populateClientSelector();
    applyLogFilters();

    if (dom.diagnosticCard) {
      dom.diagnosticCard.innerHTML = `
        <div style="padding:40px; text-align:center; color: var(--text-muted);">
          <div style="font-size:32px; margin-bottom:10px;">🧹</div>
          <strong style="color:var(--text-primary); font-size:16px;">Sesión Limpiada Exitosamente</strong><br>
          <span style="font-size:13px; color:var(--text-muted);">Se eliminaron todos los registros previos. Cargue un nuevo archivo (.log, .txt, .json, .csv) para iniciar un análisis totalmente limpio.</span>
        </div>`;
    }

    showAnalysisStatus(false, '🧹 Sesión Limpiada', 'Se eliminaron todos los registros y la muestra actual fue reiniciada a cero.');
  }

  function renderUserAndIpAnalytics() {
    const userContainer = document.getElementById('user-analytics-container');
    const ipContainer = document.getElementById('ip-analytics-container');
    const userBadge = document.getElementById('user-count-badge');
    const ipBadge = document.getElementById('ip-count-badge');

    if (!userContainer || !ipContainer) return;

    const userMap = new Map();
    const ipMap = new Map();
    const ipUserSet = new Map();

    const logsToAnalyze = state.filteredLogs && state.filteredLogs.length > 0 ? state.filteredLogs : state.logs;

    logsToAnalyze.forEach(l => {
      const u = l.user;
      const ip = l.clientIp;

      if (u) {
        if (!userMap.has(u)) {
          userMap.set(u, { total: 1, errors: (l.level === 'ERROR' || l.level === 'CRITICAL') ? 1 : 0 });
        } else {
          const item = userMap.get(u);
          item.total += 1;
          if (l.level === 'ERROR' || l.level === 'CRITICAL') item.errors += 1;
        }
      }

      if (ip) {
        if (!ipMap.has(ip)) {
          ipMap.set(ip, { total: 1, errors: (l.level === 'ERROR' || l.level === 'CRITICAL') ? 1 : 0 });
        } else {
          const item = ipMap.get(ip);
          item.total += 1;
          if (l.level === 'ERROR' || l.level === 'CRITICAL') item.errors += 1;
        }

        if (u) {
          if (!ipUserSet.has(ip)) ipUserSet.set(ip, new Set());
          ipUserSet.get(ip).add(u);
        }
      }
    });

    if (userBadge) userBadge.textContent = `${userMap.size} Usuarios Únicos`;
    if (ipBadge) ipBadge.textContent = `${ipMap.size} IPs Únicas`;

    // Detección de Password Spraying (1 IP probando múltiples usuarios)
    let sprayingDetected = false;
    ipUserSet.forEach((userSet, ipAddr) => {
      if (userSet.size >= 3) {
        sprayingDetected = true;
      }
    });

    // Renderizar Usuarios
    if (userMap.size > 0) {
      const sortedUsers = Array.from(userMap.entries()).sort((a, b) => b[1].total - a[1].total);
      let userHtml = `<table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.8rem;">
        <thead>
          <tr style="background:var(--bg-secondary); color:var(--text-main); text-align:left;">
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color);">Usuario / Identificador</th>
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color); text-align:center;">Interacciones</th>
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color); text-align:center;">Fallos</th>
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color); text-align:center;">Filtrar</th>
          </tr>
        </thead>
        <tbody>`;

      sortedUsers.forEach(([uId, uStats]) => {
        userHtml += `
          <tr style="border-bottom:1px solid var(--border-color);">
            <td style="padding:6px 8px; font-family:monospace; font-weight:bold; color:var(--it-blue); word-break:break-all;">${escapeHtml(uId)}</td>
            <td style="padding:6px 8px; text-align:center; font-weight:bold;">${uStats.total}</td>
            <td style="padding:6px 8px; text-align:center; font-weight:bold; color:${uStats.errors > 0 ? '#dc2626' : '#047857'};">${uStats.errors}</td>
            <td style="padding:6px 8px; text-align:center;">
              <button class="btn" style="padding:2px 8px; font-size:0.7rem; background:#0284c7; color:#fff;" onclick="window.filterLogByUserGlobal('${escapeHtml(uId)}')">🔍 Ver</button>
            </td>
          </tr>`;
      });
      userHtml += `</tbody></table>`;
      userContainer.innerHTML = userHtml;
    } else {
      userContainer.innerHTML = `<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:0.85rem;">No se detectaron identificadores de usuario explícitos en las trazas actuales.</div>`;
    }

    // Renderizar IPs
    if (ipMap.size > 0) {
      const sortedIps = Array.from(ipMap.entries()).sort((a, b) => b[1].total - a[1].total);
      let ipHtml = `<table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.8rem;">
        <thead>
          <tr style="background:var(--bg-secondary); color:var(--text-main); text-align:left;">
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color);">Dirección IP de Origen</th>
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color); text-align:center;">Peticiones</th>
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color); text-align:center;">Fallos</th>
            <th style="padding:6px 8px; border-bottom:1px solid var(--border-color); text-align:center;">Filtrar</th>
          </tr>
        </thead>
        <tbody>`;

      sortedIps.forEach(([ipStr, ipStats]) => {
        const isHighVolume = ipStats.errors >= 5;
        ipHtml += `
          <tr style="border-bottom:1px solid var(--border-color);">
            <td style="padding:6px 8px; font-family:monospace; font-weight:bold; color:var(--text-main); word-break:break-all;">
              ${escapeHtml(ipStr)} ${isHighVolume ? '<span style="background:#fee2e2; color:#dc2626; padding:1px 4px; border-radius:3px; font-size:0.7rem;">🔥 ALTA RÁFAGA</span>' : ''}
            </td>
            <td style="padding:6px 8px; text-align:center; font-weight:bold;">${ipStats.total}</td>
            <td style="padding:6px 8px; text-align:center; font-weight:bold; color:${ipStats.errors > 0 ? '#dc2626' : '#047857'};">${ipStats.errors}</td>
            <td style="padding:6px 8px; text-align:center;">
              <button class="btn" style="padding:2px 8px; font-size:0.7rem; background:#0284c7; color:#fff;" onclick="window.filterLogByIpGlobal('${escapeHtml(ipStr)}')">🔍 Ver</button>
            </td>
          </tr>`;
      });
      ipHtml += `</tbody></table>`;
      ipContainer.innerHTML = ipHtml;
    } else {
      ipContainer.innerHTML = `<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:0.85rem;">No se detectaron direcciones IP explícitas en las trazas actuales.</div>`;
    }
  }

  window.filterLogByUserGlobal = function(uId) {
    if (dom.searchLogInput) {
      dom.searchLogInput.value = uId;
      applyLogFilters();
    }
  };

  window.filterLogByIpGlobal = function(ipStr) {
    if (dom.searchLogInput) {
      dom.searchLogInput.value = ipStr;
      applyLogFilters();
    }
  };

  function initNodeComparisonModule() {
    const fileInputA = document.getElementById('node-a-file-input');
    const fileInputB = document.getElementById('node-b-file-input');
    const selectA = document.getElementById('node-a-select');
    const selectB = document.getElementById('node-b-select');
    const btnRefresh = document.getElementById('btn-refresh-node-comparison');

    fileInputA?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      showAnalysisStatus(true, `⚙️ Procesando Log Nodo A: ${file.name}...`, 'Analizando registros...');
      const content = await file.text();
      state.nodeALogs = await window.logParserEngine.parseLogsAsync(content, null);
      updateNodeComparisonUI(file.name, null);
      showAnalysisStatus(false, `✅ Log Nodo A Cargado: ${file.name}`, `${state.nodeALogs.length} registros analizados`);
    });

    fileInputB?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      showAnalysisStatus(true, `⚙️ Procesando Log Nodo B: ${file.name}...`, 'Analizando registros...');
      const content = await file.text();
      state.nodeBLogs = await window.logParserEngine.parseLogsAsync(content, null);
      updateNodeComparisonUI(null, file.name);
      showAnalysisStatus(false, `✅ Log Nodo B Cargado: ${file.name}`, `${state.nodeBLogs.length} registros analizados`);
    });

    btnRefresh?.addEventListener('click', () => {
      updateNodeComparisonUI();
    });

    selectA?.addEventListener('change', () => updateNodeComparisonUI());
    selectB?.addEventListener('change', () => updateNodeComparisonUI());

    updateNodeComparisonUI();
  }

  function updateNodeComparisonUI(fileNameA, fileNameB) {
    const summaryA = document.getElementById('node-a-summary');
    const summaryB = document.getElementById('node-b-summary');
    const barA = document.getElementById('node-asymmetry-bar-a');
    const barB = document.getElementById('node-asymmetry-bar-b');
    const labelAsym = document.getElementById('node-asymmetry-label');
    const containerTable = document.getElementById('node-comparison-table-container');

    let logsA = state.nodeALogs || [];
    let nameA = fileNameA || 'Nodo A (SACVWIG07 / 192.168.11.48)';
    if (logsA.length === 0 && state.logs.length > 0) {
      logsA = state.logs;
      nameA = 'Nodo A (Muestra Actual)';
    }

    let logsB = state.nodeBLogs || [];
    let nameB = fileNameB || 'Nodo B (SACVWIG08 / 192.168.11.60)';
    if (logsB.length === 0 && state.logs.length > 0) {
      logsB = state.logs.filter((l, idx) => idx % 2 === 0);
      nameB = 'Nodo B (Simulación Respaldo)';
    }

    const countA = logsA.length;
    const countB = logsB.length;
    const errA = logsA.filter(l => l.level === 'ERROR' || l.level === 'CRITICAL').length;
    const errB = logsB.filter(l => l.level === 'ERROR' || l.level === 'CRITICAL').length;

    if (summaryA) {
      summaryA.innerHTML = `<strong>${escapeHtml(nameA)}</strong><br>Total Registros: <strong>${countA}</strong> | Errores 520xxx: <strong style="color:#dc2626;">${errA}</strong>`;
    }
    if (summaryB) {
      summaryB.innerHTML = `<strong>${escapeHtml(nameB)}</strong><br>Total Registros: <strong>${countB}</strong> | Errores 520xxx: <strong style="color:#dc2626;">${errB}</strong>`;
    }

    const total = Math.max(1, countA + countB);
    const pctA = Math.round((countA / total) * 100);
    const pctB = 100 - pctA;

    if (barA) barA.style.width = `${pctA}%`;
    if (barB) barB.style.width = `${pctB}%`;
    if (labelAsym) {
      const isAsymmetric = Math.abs(pctA - pctB) > 25;
      labelAsym.textContent = isAsymmetric 
        ? `⚠️ ASIMETRÍA ALTA (Nodo A: ${pctA}% vs Nodo B: ${pctB}%)`
        : `✅ CARGA BALANCEADA (Nodo A: ${pctA}% vs Nodo B: ${pctB}%)`;
    }

    if (containerTable) {
      containerTable.innerHTML = `
        <table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.85rem; margin-top:10px;">
          <thead>
            <tr style="background:var(--bg-secondary); color:var(--text-main); text-align:left;">
              <th style="padding:8px; border-bottom:2px solid var(--border-color);">Métrica / Indicador</th>
              <th style="padding:8px; border-bottom:2px solid var(--border-color); text-align:center; color:var(--it-blue);">🖥️ ${escapeHtml(nameA)}</th>
              <th style="padding:8px; border-bottom:2px solid var(--border-color); text-align:center; color:var(--text-cyan);">🖥️ ${escapeHtml(nameB)}</th>
              <th style="padding:8px; border-bottom:2px solid var(--border-color); text-align:center;">Diagnóstico de Simetría</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style="padding:8px; font-weight:bold;">Total Transacciones / Logs</td>
              <td style="padding:8px; text-align:center; font-weight:bold;">${countA}</td>
              <td style="padding:8px; text-align:center; font-weight:bold;">${countB}</td>
              <td style="padding:8px; text-align:center;">${Math.abs(countA - countB) < 50 ? '✅ Simétrico' : '⚠️ Desbalance de Carga'}</td>
            </tr>
            <tr>
              <td style="padding:8px; font-weight:bold;">Errores Críticos / 520xxx</td>
              <td style="padding:8px; text-align:center; font-weight:bold; color:#dc2626;">${errA}</td>
              <td style="padding:8px; text-align:center; font-weight:bold; color:#dc2626;">${errB}</td>
              <td style="padding:8px; text-align:center;">${errA === errB ? '✅ Mismo comportamiento' : (errA > errB ? '⚠️ Mayor falla en Nodo A' : '⚠️ Mayor falla en Nodo B')}</td>
            </tr>
            <tr>
              <td style="padding:8px; font-weight:bold;">Índice de Salud Calculado</td>
              <td style="padding:8px; text-align:center; font-weight:bold; color:#0284c7;">${Math.max(10, Math.round(100 - (errA / Math.max(1, countA)) * 100 * 5))}%</td>
              <td style="padding:8px; text-align:center; font-weight:bold; color:#0284c7;">${Math.max(10, Math.round(100 - (errB / Math.max(1, countB)) * 100 * 5))}%</td>
              <td style="padding:8px; text-align:center;">${Math.abs(errA - errB) === 0 ? '✅ Salud Paritaria' : '🔍 Revisar nodo con mayor falla'}</td>
            </tr>
          </tbody>
        </table>
      `;
    }
  }

  function renderTraceWaterfall() {
    const container = document.getElementById('trace-waterfall-container');
    if (!container) return;

    const sampleSpans = [
      { name: '1. HTTP Request (WSO2 API Gateway)', duration: '18 ms', pct: 15, status: 'OK', color: '#0284c7' },
      { name: '2. Entrust Auth Context Lookup (HTTPS 8443)', duration: '115 ms', pct: 40, status: 'OK', color: '#06b6d4' },
      { name: '3. LDAP / Active Directory Password Validation', duration: '240 ms', pct: 75, status: 'OK', color: '#10b981' },
      { name: '4. Grid Card Challenge Validation (SOAP Service)', duration: '85 ms', pct: 30, status: 'OK', color: '#8b5cf6' },
      { name: '5. Notification Dispatch (SMS / Email Gateway)', duration: '3.420 ms', pct: 95, status: 'WARN', color: '#f59e0b' }
    ];

    let html = `<div style="display:flex; flex-direction:column; gap:12px;">`;
    sampleSpans.forEach(span => {
      html += `
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); padding:10px 14px; border-radius:6px;">
          <div class="flex-between mb-1" style="font-size:0.85rem;">
            <span style="font-weight:600; color:var(--text-main);">${escapeHtml(span.name)}</span>
            <span class="font-mono" style="color:var(--text-cyan); font-weight:700;">${span.duration} (${span.status})</span>
          </div>
          <div style="height:8px; background:#1e293b; border-radius:4px; overflow:hidden;">
            <div style="width:${span.pct}%; background:${span.color}; height:100%; transition:width 0.5s;"></div>
          </div>
        </div>`;
    });
    html += `</div>`;
    container.innerHTML = html;
  }

  function initEventListeners() {
    dom.btnResetSession?.addEventListener('click', () => resetSession());
    document.getElementById('btn-reset-session')?.addEventListener('click', () => resetSession());

    dom.searchLogInput?.addEventListener('input', () => applyLogFilters());
    dom.filterClientSelect?.addEventListener('change', () => applyLogFilters());
    dom.filterLevelSelect?.addEventListener('change', () => applyLogFilters());
    dom.filterTypeSelect?.addEventListener('change', () => applyLogFilters());

    document.getElementById('btn-copy-exec-report-md')?.addEventListener('click', () => copyExecutiveReportMarkdown());
    document.getElementById('btn-download-exec-report-md')?.addEventListener('click', () => downloadExecutiveReportMarkdown());

    // Event Listeners para generación de Informes (Preliminar y Exclusivo de Errores)
    dom.btnGenerateExecReport?.addEventListener('click', () => generateExecutiveReport(false));
    dom.btnExportReport?.addEventListener('click', () => generateExecutiveReport(false));
    document.getElementById('btn-generate-exec-report')?.addEventListener('click', () => generateExecutiveReport(false));
    document.getElementById('btn-export-report')?.addEventListener('click', () => generateExecutiveReport(false));
    document.getElementById('btn-gen-report-for-detected-520')?.addEventListener('click', () => {
      if (dom.entrustErrorsModal) dom.entrustErrorsModal.classList.remove('active');
      generateExecutiveReport(true);
    });

    dom.btnCloseExecReport?.addEventListener('click', () => {
      if (dom.execReportModal) dom.execReportModal.classList.remove('active');
    });

    dom.btnPrintExecReport?.addEventListener('click', () => {
      window.print();
    });

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

      let newLogs = [];
      let fileCount = 0;

      for (let fIdx = 0; fIdx < files.length; fIdx++) {
        const file = files[fIdx];
        try {
          showAnalysisStatus(true, `⚙️ Procesando [${fIdx + 1}/${files.length}]: ${file.name}...`, 'Iniciando lectura asíncrona por bloques...');
          const content = await file.text();
          const clientName = extractClientFromFilename(file.name);

          const rawEntries = await window.logParserEngine.parseLogsAsync(content, (current, total, msg) => {
            showAnalysisStatus(true, `⚙️ [Archivo ${fIdx + 1}/${files.length}] ${file.name}`, `${msg}`);
          }, 5000);

          const parsedEntries = rawEntries.map((log, idx) => ({
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
      }
    });

    document.getElementById('btn-do-import-catalog')?.addEventListener('click', () => {
      const fileInput = document.getElementById('import-catalog-file-input');
      const versionSelect = document.getElementById('import-catalog-version');
      const statusDiv = document.getElementById('import-catalog-status');

      if (!fileInput.files || fileInput.files.length === 0) {
        statusDiv.style.display = 'block';
        statusDiv.style.background = '#fee2e2';
        statusDiv.style.color = '#dc2626';
        statusDiv.innerText = 'Por favor selecciona un archivo HTML, JSON o TXT antes de continuar.';
        return;
      }

      const file = fileInput.files[0];
      const versionLabel = versionSelect.value;
      const reader = new FileReader();

      reader.onload = (e) => {
        const content = e.target.result;
        let count = 0;
        if (file.name.endsWith('.html') || file.name.endsWith('.htm') || content.includes('<html')) {
          count = window.knowledgeBaseEngine.importCatalogFromHtml(content, versionLabel);
        } else if (file.name.endsWith('.json')) {
          try {
            const jsonArr = JSON.parse(content);
            if (Array.isArray(jsonArr)) {
              jsonArr.forEach(item => {
                window.knowledgeBaseEngine.saveCustomRule({
                  ...item,
                  manualVersion: versionLabel
                });
                count++;
              });
            }
          } catch(err) {
            console.error(err);
          }
        }

        statusDiv.style.display = 'block';
        statusDiv.style.background = '#ecfdf5';
        statusDiv.style.color = '#047857';
        statusDiv.innerText = `¡Éxito! Se importaron y sincronizaron ${count} reglas de error oficiales para ${versionLabel}.`;

        setTimeout(() => {
          document.getElementById('import-catalog-modal').classList.remove('active');
          statusDiv.style.display = 'none';
          if (window.renderDashboard) window.renderDashboard();
        }, 2000);
      };

      reader.readAsText(file);
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
