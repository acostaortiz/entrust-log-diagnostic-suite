/* ==========================================================================
   MODULO FORENSE DE RED WIRESHARK / PCAP / TCPDUMP (ZERO-HALLUCINATION)
   Decodificacion binaria deterministica (.pcap, .pcapng, .cap, .gz, tcpdump)
   ========================================================================== */
(function () {
  'use strict';

  function esc(val) {
    if (typeof window.escapeHtml === 'function') return window.escapeHtml(val);
    if (val === null || val === undefined) return '';
    return String(val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatBytes(bytes) {
    const b = Number(bytes || 0);
    if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return b + ' B';
  }

  function getActiveClientName() {
    if (typeof window.getActiveClientProfileGlobal === 'function') {
      const cli = window.getActiveClientProfileGlobal();
      if (cli && cli.name) return String(cli.name).replace(/\.\.+/g, '').trim();
    }
    const st = window.appState || window.state;
    if (st && Array.isArray(st.clientProfiles)) {
      const active = st.clientProfiles.find(c => c.id === st.activeClientId);
      if (active && active.name) return String(active.name).replace(/\.\.+/g, '').trim();
    }
    const sel = document.getElementById('active-client-session-select');
    if (sel && sel.selectedIndex >= 0 && sel.options[sel.selectedIndex]) {
      const val = sel.options[sel.selectedIndex].value || '';
      const txt = sel.options[sel.selectedIndex].textContent || '';
      if (val && val !== '__NEW__' && txt && !/Cargando|Registrar/i.test(txt)) {
        return txt.replace(/\.\.+/g, '').trim();
      }
    }
    return 'Entrust IdentityGuard OnPremise';
  }

  const PcapAnalyzer = {
    containerId: 'tab-pcap-main-container',
    summaryData: null,
    serverPcapFiles: [],
    activeSubView: 'findings', // 'findings' | 'flows' | 'packets' | 'correlate'
    packetState: {
      page: 1,
      limit: 100,
      q: '',
      proto: 'ALL',
      severity: 'ALL',
      flow: ''
    },
    correlationWindowSec: 5,
    correlationData: null,
    isUploading: false,

    async renderTab(containerId) {
      this.containerId = containerId || this.containerId || 'tab-pcap-main-container';
      const target = document.getElementById(this.containerId);
      if (!target) return;

      const clientName = getActiveClientName();
      const qCli = encodeURIComponent(clientName);
      let backendState = 'ok'; // 'ok' | 'stale_server' | 'static_server'
      let runningVersion = '';

      try {
        const [sumRes, filesRes, verRes] = await Promise.all([
          fetch(`/api/pcap-summary?client=${qCli}`).catch(() => null),
          fetch('/api/list-server-files').catch(() => null),
          fetch('/api/version').catch(() => null)
        ]);
        let verOk = false;
        if (verRes && verRes.ok) {
          verOk = true;
          try {
            const vd = await verRes.json();
            runningVersion = (vd && vd.version && vd.version.version) ? String(vd.version.version) : '';
          } catch (e) {}
        }
        if (sumRes && sumRes.ok) {
          this.summaryData = await sumRes.json();
        } else if (verOk && (!sumRes || sumRes.status === 404)) {
          backendState = 'stale_server';
        } else {
          backendState = 'static_server';
        }
        if (filesRes && filesRes.ok) {
          const fd = await filesRes.json();
          this.serverPcapFiles = (fd.files || []).filter(f => f.isPcap || f.type === 'pcap');
        }
      } catch (e) {
        backendState = 'static_server';
      }

      this._renderMainShell(target, clientName, backendState, runningVersion);

      if (this.summaryData && this.summaryData.status === 'ready') {
        this._renderActiveSubView();
      }
    },

    _renderMainShell(target, clientName, backendState, runningVersion = '') {
      const s = this.summaryData;
      const hasData = !!(s && s.status === 'ready');
      const bannerHtml = backendState === 'stale_server' ? `
            <div style="background:rgba(245,158,11,0.12); border:1px solid #f59e0b; border-left:4px solid #f59e0b; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:0.82rem; color:var(--text-main);">
              <strong>🔄 Proceso <code>server.py</code> antiguo en ejecución en RAM${runningVersion ? ` (${esc(runningVersion)})` : ''}:</strong> los archivos web ya se actualizaron, pero el proceso <code>python3 server.py</code> del puerto actual sigue con la versión previa en memoria y aún no expone <code>/api/pcap-*</code> ni el parser nativo de <code>catalina.out</code>. Reinicie el servicio en Linux (<code>pkill -f server.py && nohup python3 server.py &amp;</code> o <code>systemctl restart ...</code>).
            </div>
          ` : (backendState === 'static_server' ? `
            <div style="background:rgba(239,68,68,0.12); border:1px solid #ef4444; border-left:4px solid #ef4444; border-radius:8px; padding:12px 14px; margin-bottom:16px; font-size:0.82rem; color:var(--text-main);">
              <strong>⚠️ Backend API (<code>server.py</code>) no detectado en el puerto actual:</strong> el navegador está conectado a un servidor estático (Nginx/Apache o <code>http.server</code>) sin decodificador binario PCAP ni SQLite. Verifique con <code>ss -tlnp | grep 8085</code> e inicie <code>python3 server.py</code> en el puerto <code>8085</code> (o configure <code>location /api/ { proxy_pass http://127.0.0.1:8085; }</code> en Nginx).
            </div>
          ` : '');
      const serverOptionsHtml = this.serverPcapFiles.map(f =>
        `<option value="${esc(f.name)}">${esc(f.name)} (${f.sizeMb} MB)</option>`
      ).join('');

      const anom = hasData ? (s.anomaliesSummary || {}) : {};
      const tcpIssuesCount = (anom.unansweredSyn || 0) + (anom.tcpRst || 0) + (anom.retransmissions || 0) + (anom.zeroWindow || 0);
      const dnsHttpCount = (anom.dnsErrors || 0) + (anom.httpErrors || 0) + (anom.icmpErrors || 0);
      const rttLabel = (hasData && s.rttStats && s.rttStats.samples > 0)
        ? `${s.rttStats.medianMs} ms`
        : 'N/A';
      const rttSub = (hasData && s.rttStats && s.rttStats.samples > 0)
        ? `min ${s.rttStats.minMs} / máx ${s.rttStats.maxMs} ms (${s.rttStats.samples} flujos)`
        : 'Sin handshake SYN+SYN-ACK completo';

      target.innerHTML = `
        <div class="glass-card mb-4" style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:20px;">
          <!-- Header -->
          <div class="card-header flex-between" style="border-bottom:1px solid var(--border-color); padding-bottom:14px; margin-bottom:16px; flex-wrap:wrap; gap:12px;">
            <div>
              <div class="card-title text-cyan" style="font-size:1.15rem; font-weight:800; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                <span>🌐</span> Analizador Forense Wireshark &amp; <code>tcpdump</code> (Cero Alucinaciones)
                <span style="background:rgba(16,185,129,0.14); color:#10b981; border:1px solid rgba(16,185,129,0.4); font-size:0.7rem; padding:2px 8px; border-radius:999px; font-weight:800;">Decodificación Binaria RFC Exacta</span>
              </div>
              <div style="font-size:0.78rem; color:var(--text-muted); margin-top:4px;">
                Cliente: <strong>${esc(clientName)}</strong> • Soporta <code>.pcap</code>, <code>.pcapng</code> (Wireshark), <code>.cap</code>, <code>.pcap.gz</code> y salida texto de <code>tcpdump -nn</code>.
              </div>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
              <label for="pcap-file-input" class="btn btn-primary" style="background:#0284c7; border:none; font-size:0.78rem; padding:7px 14px; font-weight:700; border-radius:6px; cursor:pointer; display:inline-flex; align-items:center; gap:6px;">
                📤 Subir PCAP / tcpdump
              </label>
              <input type="file" id="pcap-file-input" accept=".pcap,.pcapng,.cap,.dmp,.gz,.txt,.log" style="display:none;" onchange="window.PcapAnalyzer.handleFilePickerChange(this)">
              ${hasData ? `
                <button class="btn" onclick="window.PcapAnalyzer.exportCsv('anomalies')" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); font-size:0.76rem; padding:6px 10px; border-radius:6px; cursor:pointer;">📥 CSV Hallazgos</button>
                <button class="btn" onclick="window.PcapAnalyzer.exportCsv('flows')" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); font-size:0.76rem; padding:6px 10px; border-radius:6px; cursor:pointer;">📥 CSV Flujos</button>
                <button class="btn" onclick="window.PcapAnalyzer.exportCsv('packets')" style="background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main); font-size:0.76rem; padding:6px 10px; border-radius:6px; cursor:pointer;">📥 CSV Paquetes</button>
              ` : ''}
            </div>
          </div>

          ${bannerHtml}

          <!-- Barra de Carga + Selector de Archivos PCAP en uploads/ -->
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:12px; margin-bottom:14px;">
            <div id="pcap-dropzone" style="border:2px dashed var(--border-color); background:var(--bg-primary); border-radius:8px; padding:14px; display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap;"
                 ondragover="event.preventDefault(); this.style.borderColor='#0284c7';"
                 ondragleave="this.style.borderColor='var(--border-color)';"
                 ondrop="event.preventDefault(); this.style.borderColor='var(--border-color)'; if(event.dataTransfer?.files?.length) window.PcapAnalyzer.uploadAndAnalyzeFile(event.dataTransfer.files[0]);">
              <div style="font-size:0.78rem; color:var(--text-muted);">
                <strong style="color:var(--text-main); display:block;">Arrastra tu captura Wireshark / <code>tcpdump</code> aquí</strong>
                Detección por bytes mágicos binarios (Ethernet, VLAN 802.1Q, Linux <code>-i any</code> SLL/SLL2, TLS 1.0–1.3, DNS, HTTP).
              </div>
            </div>

            <div style="border:1px solid var(--border-color); background:var(--bg-primary); border-radius:8px; padding:14px; display:flex; flex-direction:column; gap:6px; justify-content:center;">
              <div style="font-size:0.74rem; font-weight:700; color:var(--text-muted);">📁 Capturas PCAP detectadas en <code>data/uploads/</code> del servidor:</div>
              ${this.serverPcapFiles.length > 0 ? `
                <div style="display:flex; gap:6px;">
                  <select id="pcap-server-file-select" class="form-control" style="flex:1; font-size:0.78rem; padding:5px 8px;">${serverOptionsHtml}</select>
                  <button class="btn btn-primary" style="background:#0a3d6d; border:none; font-size:0.76rem; padding:5px 12px; font-weight:700; border-radius:6px; cursor:pointer;" onclick="window.PcapAnalyzer.analyzeSelectedServerFile()">⚡ Analizar</button>
                </div>
              ` : `
                <div style="font-size:0.74rem; color:var(--text-muted);">No hay archivos <code>.pcap</code>/<code>.pcapng</code> en <code>data/uploads/</code>. Súbelo arriba o cópialo por <code>scp</code> al servidor.</div>
              `}
            </div>
          </div>

          <div id="pcap-progress-box" style="display:none; margin-bottom:14px; padding:10px 14px; background:rgba(2,132,199,0.1); border:1px solid #0284c7; border-radius:8px; font-size:0.8rem; color:var(--text-main);"></div>

          <details style="margin-bottom:16px; background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:10px 14px;">
            <summary style="cursor:pointer; font-size:0.78rem; font-weight:700; color:#0284c7;">💻 Ver comandos exactos de captura <code>tcpdump</code> recomendados para servidores Entrust (copiar y pegar)</summary>
            <div style="margin-top:8px; font-family:'JetBrains Mono', monospace; font-size:0.74rem; background:#020617; color:#a5f3fc; padding:10px 12px; border-radius:6px; line-height:1.6; overflow-x:auto;">
              <div># Captura binaria completa recomendada (Core 8443, LDAPS 636/389, Oracle 1521, DNS 53):</div>
              <div style="color:#fff;">tcpdump -i any -nn -s 0 -w entr_red.pcap 'port 8443 or port 636 or port 389 or port 1521 or port 53 or port 443'</div>
              <div style="margin-top:6px;"># Con rotación en archivos de 50 MB (máx. 5 archivos):</div>
              <div style="color:#fff;">tcpdump -i any -nn -s 0 -C 50 -W 5 -w entr_red.pcap</div>
              <div style="margin-top:6px;"># Si solo puedes guardar texto con fecha completa para correlacionar con logs Entrust:</div>
              <div style="color:#fff;">tcpdump -i any -tttt -nn -c 50000 'port 8443 or port 636 or port 389 or port 1521 or port 53' &gt; entr_red.txt</div>
            </div>
          </details>

          ${hasData ? `
            <!-- Divulgación de alcance estricto -->
            <div style="background:rgba(2,132,199,0.08); border:1px solid rgba(2,132,199,0.35); border-left:4px solid #0284c7; border-radius:8px; padding:10px 14px; margin-bottom:16px; font-size:0.78rem; color:var(--text-main); display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;">
              <div>
                <strong>🔒 Alcance Verificable (${esc(s.captureFormat)}):</strong>
                Archivo <strong>${esc(s.fileName)}</strong> (${s.fileSizeMb} MB) • Enlace: <code>${esc((s.linkTypes || []).join(', '))}</code> •
                Ventana: <code>${esc(s.startTime)}</code> ➔ <code>${esc(s.endTime)}</code> (${s.durationSeconds}s)
                <div style="font-size:0.73rem; color:var(--text-muted); margin-top:3px;">${esc(s.auditDisclosure || '')} Flujos con payload TLS cifrado detectados: <strong>${(s.encryptedFlowsCount || 0).toLocaleString()}</strong>.</div>
              </div>
            </div>

            <!-- 6 Tarjetas KPI -->
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(175px, 1fr)); gap:10px; margin-bottom:16px;">
              <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #0284c7; padding:12px; border-radius:8px;">
                <div style="font-size:0.69rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Paquetes Decodificados</div>
                <div style="font-size:1.45rem; font-weight:800; color:#0284c7; font-family:'JetBrains Mono', monospace;">${(s.totalPackets || 0).toLocaleString()}</div>
                <div style="font-size:0.7rem; color:var(--text-muted);">${formatBytes(s.totalBytes)} totales</div>
              </div>
              <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #8b5cf6; padding:12px; border-radius:8px;">
                <div style="font-size:0.69rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Flujos TCP / UDP</div>
                <div style="font-size:1.45rem; font-weight:800; color:#8b5cf6; font-family:'JetBrains Mono', monospace;">${(s.totalFlows || 0).toLocaleString()}</div>
                <div style="font-size:0.7rem; color:var(--text-muted);">${(s.encryptedFlowsCount || 0).toLocaleString()} con TLS cifrado</div>
              </div>
              <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid ${tcpIssuesCount > 0 ? '#ef4444' : '#10b981'}; padding:12px; border-radius:8px;">
                <div style="font-size:0.69rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Cortes &amp; Fallas TCP</div>
                <div style="font-size:1.45rem; font-weight:800; color:${tcpIssuesCount > 0 ? '#ef4444' : '#10b981'}; font-family:'JetBrains Mono', monospace;">${tcpIssuesCount.toLocaleString()}</div>
                <div style="font-size:0.7rem; color:var(--text-muted);">SYN drop: ${anom.unansweredSyn || 0} | RST: ${anom.tcpRst || 0} | Retr: ${anom.retransmissions || 0}</div>
              </div>
              <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid ${(anom.tlsAlerts || 0) > 0 ? '#ef4444' : '#10b981'}; padding:12px; border-radius:8px;">
                <div style="font-size:0.69rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Alertas TLS / SSL</div>
                <div style="font-size:1.45rem; font-weight:800; color:${(anom.tlsAlerts || 0) > 0 ? '#ef4444' : '#10b981'}; font-family:'JetBrains Mono', monospace;">${(anom.tlsAlerts || 0).toLocaleString()}</div>
                <div style="font-size:0.7rem; color:var(--text-muted);">${(s.tlsSessions || []).length} sesiones TLS vistas</div>
              </div>
              <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid ${dnsHttpCount > 0 ? '#f59e0b' : '#10b981'}; padding:12px; border-radius:8px;">
                <div style="font-size:0.69rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Errores DNS / HTTP / ICMP</div>
                <div style="font-size:1.45rem; font-weight:800; color:${dnsHttpCount > 0 ? '#f59e0b' : '#10b981'}; font-family:'JetBrains Mono', monospace;">${dnsHttpCount.toLocaleString()}</div>
                <div style="font-size:0.7rem; color:var(--text-muted);">DNS: ${anom.dnsErrors || 0} | HTTP: ${anom.httpErrors || 0} | ICMP: ${anom.icmpErrors || 0}</div>
              </div>
              <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #0ea5e9; padding:12px; border-radius:8px;">
                <div style="font-size:0.69rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">RTT Handshake TCP</div>
                <div style="font-size:1.45rem; font-weight:800; color:#0ea5e9; font-family:'JetBrains Mono', monospace;">${esc(rttLabel)}</div>
                <div style="font-size:0.7rem; color:var(--text-muted);">${esc(rttSub)}</div>
              </div>
            </div>

            <!-- Barra Sub-Vistas -->
            <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px; border-bottom:1px solid var(--border-color); padding-bottom:10px;">
              <button onclick="window.PcapAnalyzer.switchSubView('findings')" style="padding:7px 14px; border-radius:7px; font-size:0.78rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'findings' ? '#ef4444' : 'var(--border-color)'}; background:${this.activeSubView === 'findings' ? '#ef4444' : 'var(--bg-primary)'}; color:${this.activeSubView === 'findings' ? '#fff' : 'var(--text-main)'};">
                🚨 1. Hallazgos Verificados (${(s.findings || []).length})
              </button>
              <button onclick="window.PcapAnalyzer.switchSubView('flows')" style="padding:7px 14px; border-radius:7px; font-size:0.78rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'flows' ? '#8b5cf6' : 'var(--border-color)'}; background:${this.activeSubView === 'flows' ? '#8b5cf6' : 'var(--bg-primary)'}; color:${this.activeSubView === 'flows' ? '#fff' : 'var(--text-main)'};">
                🔀 2. Flujos TCP / UDP &amp; TLS (${(s.totalFlows || 0).toLocaleString()})
              </button>
              <button onclick="window.PcapAnalyzer.switchSubView('packets')" style="padding:7px 14px; border-radius:7px; font-size:0.78rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'packets' ? '#0284c7' : 'var(--border-color)'}; background:${this.activeSubView === 'packets' ? '#0284c7' : 'var(--bg-primary)'}; color:${this.activeSubView === 'packets' ? '#fff' : 'var(--text-main)'};">
                📦 3. Inspector Paquete a Paquete (${(s.totalPackets || 0).toLocaleString()})
              </button>
              <button onclick="window.PcapAnalyzer.switchSubView('correlate')" style="padding:7px 14px; border-radius:7px; font-size:0.78rem; font-weight:800; cursor:pointer; border:1px solid ${this.activeSubView === 'correlate' ? '#10b981' : 'var(--border-color)'}; background:${this.activeSubView === 'correlate' ? '#10b981' : 'var(--bg-primary)'}; color:${this.activeSubView === 'correlate' ? '#fff' : 'var(--text-main)'};">
                🔗 4. Correlación con Logs Entrust
              </button>
            </div>

            <div id="pcap-subview-body"></div>
          ` : `
            <div style="padding:36px; text-align:center; background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; color:var(--text-muted); font-size:0.88rem;">
              <div style="font-size:2rem; margin-bottom:8px;">📡</div>
              <strong>Sin captura de red cargada para ${esc(clientName)}.</strong>
              <div style="margin-top:6px;">Sube un archivo <code>.pcap</code>, <code>.pcapng</code> o salida texto <code>tcpdump</code> arriba para auditar paquetes, handshakes TLS, cortes TCP RST/SYN y correlacionarlos con tus logs Entrust sin alucinaciones.</div>
            </div>
          `}
        </div>
      `;
    },

    switchSubView(viewName, optionalFlowKey = null) {
      this.activeSubView = viewName;
      if (optionalFlowKey !== null) {
        this.packetState.flow = optionalFlowKey;
        this.packetState.page = 1;
      }
      const target = document.getElementById(this.containerId);
      if (target) {
        this._renderMainShell(target, getActiveClientName(), false);
        this._renderActiveSubView();
      }
    },

    _renderActiveSubView() {
      const container = document.getElementById('pcap-subview-body');
      if (!container || !this.summaryData) return;

      if (this.activeSubView === 'flows') {
        this._renderFlowsView(container);
      } else if (this.activeSubView === 'packets') {
        this._renderPacketsView(container);
      } else if (this.activeSubView === 'correlate') {
        this._renderCorrelationView(container);
      } else {
        this._renderFindingsView(container);
      }
    },

    _renderFindingsView(container) {
      const findings = this.summaryData.findings || [];
      if (findings.length === 0) {
        container.innerHTML = `<div style="padding:28px; text-align:center; background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.3); border-radius:8px; color:#10b981; font-weight:700;">✅ No se detectaron anomalías TCP (RST / SYN sin respuesta / Retransmisiones), alertas TLS fatales, errores DNS ni errores HTTP 4xx/5xx en esta captura.</div>`;
        return;
      }

      const rows = findings.map(f => {
        const isCrit = f.severity === 'CRITICAL';
        const col = isCrit ? '#ef4444' : '#f59e0b';
        const jsFlow = esc((f.flowKey || '').replace(/'/g, "\\'"));
        return `
          <tr style="border-bottom:1px solid var(--border-color);">
            <td style="padding:8px; font-family:'JetBrains Mono', monospace; font-weight:800; color:#0284c7;">#${f.frameNum}</td>
            <td style="padding:8px;"><span style="background:${isCrit ? 'rgba(239,68,68,0.14)' : 'rgba(245,158,11,0.14)'}; color:${col}; padding:2px 7px; border-radius:4px; font-size:0.7rem; font-weight:800;">${esc(f.severity)}</span></td>
            <td style="padding:8px; font-family:monospace; font-size:0.74rem; color:var(--text-muted);">${esc(f.timestamp || '-')}</td>
            <td style="padding:8px; font-weight:700; font-size:0.76rem; color:var(--text-main);">${esc(f.category)}</td>
            <td style="padding:8px; font-family:monospace; font-size:0.74rem;">${esc(f.src)} ➔ ${esc(f.dst)} <span style="color:#0284c7;">[${esc(f.service || '-')}]</span></td>
            <td style="padding:8px; font-size:0.76rem; color:var(--text-main);">${esc(f.evidence)}</td>
            <td style="padding:8px; text-align:center;">
              <button class="btn" style="padding:3px 8px; font-size:0.71rem; background:var(--bg-secondary); border:1px solid var(--border-color); color:#0284c7; font-weight:700; border-radius:4px; cursor:pointer;" onclick="window.PcapAnalyzer.switchSubView('packets', '${jsFlow}')">📦 Ver Flujo</button>
            </td>
          </tr>
        `;
      }).join('');

      container.innerHTML = `
        <div style="overflow-x:auto; border:1px solid var(--border-color); border-radius:8px;">
          <table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.78rem;">
            <thead>
              <tr style="background:var(--bg-secondary); color:var(--text-main); text-align:left;">
                <th style="padding:8px;">Frame</th>
                <th style="padding:8px;">Severidad</th>
                <th style="padding:8px;">Timestamp Exacto</th>
                <th style="padding:8px;">Categoría RFC</th>
                <th style="padding:8px;">Origen ➔ Destino [Servicio]</th>
                <th style="padding:8px;">Evidencia Literal de Red</th>
                <th style="padding:8px; text-align:center;">Inspeccionar</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    },

    _renderFlowsView(container) {
      const flows = this.summaryData.flows || [];
      if (flows.length === 0) {
        container.innerHTML = `<div style="padding:24px; text-align:center; color:var(--text-muted);">No hay conversaciones IP registradas.</div>`;
        return;
      }

      const rows = flows.map(f => {
        const jsFlow = esc((f.flowKey || '').replace(/'/g, "\\'"));
        const hasErr = f.unansweredSyn || f.rstCount > 0 || (f.tlsAlerts && f.tlsAlerts.length > 0);
        const tlsBadge = f.tlsVersion
          ? `<span style="background:rgba(16,185,129,0.14); color:#10b981; padding:1px 6px; border-radius:4px; font-weight:700; font-size:0.7rem;">🔒 ${esc(f.tlsVersion)}</span>`
          : (f.isEncrypted ? `<span style="background:rgba(16,185,129,0.14); color:#10b981; padding:1px 6px; border-radius:4px; font-weight:700; font-size:0.7rem;">🔒 TLS Cifrado</span>` : '<span style="color:var(--text-muted); font-size:0.7rem;">Texto/Otro</span>');
        const diagBits = [];
        if (f.unansweredSyn) diagBits.push('<span style="color:#ef4444; font-weight:800;">SYN sin respuesta</span>');
        if (f.rstCount > 0) diagBits.push(`<span style="color:#ef4444; font-weight:800;">RST:${f.rstCount}</span>`);
        if (f.retransCount > 0) diagBits.push(`<span style="color:#f59e0b; font-weight:800;">Retr:${f.retransCount}</span>`);
        if (f.tlsAlerts && f.tlsAlerts.length > 0) diagBits.push(`<span style="color:#ef4444; font-weight:800;">${esc(f.tlsAlerts[0])}</span>`);
        if (diagBits.length === 0) diagBits.push('<span style="color:#10b981; font-weight:700;">✅ Limpio</span>');

        return `
          <tr style="border-bottom:1px solid var(--border-color); background:${hasErr ? 'rgba(239,68,68,0.04)' : 'transparent'};">
            <td style="padding:8px; font-family:monospace; font-size:0.74rem; font-weight:700;">${esc(f.srcIp)}:${f.srcPort} ↔ ${esc(f.dstIp)}:${f.dstPort}</td>
            <td style="padding:8px; font-size:0.74rem;"><span style="background:rgba(2,132,199,0.14); color:#0284c7; padding:2px 6px; border-radius:4px; font-weight:700;">${esc(f.service || f.proto)}</span></td>
            <td style="padding:8px; font-family:monospace; text-align:right;">${f.packets.toLocaleString()} / ${formatBytes(f.bytes)}</td>
            <td style="padding:8px; font-family:monospace; text-align:center;">${f.rttMs !== null && f.rttMs !== undefined ? f.rttMs + ' ms' : '-'}</td>
            <td style="padding:8px; font-size:0.72rem;">${tlsBadge}${f.tlsSni ? `<div style="font-family:monospace; color:#0284c7; margin-top:2px;">SNI: ${esc(f.tlsSni)}</div>` : ''}${f.tlsCipher ? `<div style="font-family:monospace; color:var(--text-muted); font-size:0.66rem;">${esc(f.tlsCipher)}</div>` : ''}</td>
            <td style="padding:8px; font-size:0.72rem;">${diagBits.join(' • ')}</td>
            <td style="padding:8px; text-align:center;">
              <button class="btn" style="padding:3px 8px; font-size:0.71rem; background:var(--bg-secondary); border:1px solid var(--border-color); color:#0284c7; font-weight:700; border-radius:4px; cursor:pointer;" onclick="window.PcapAnalyzer.switchSubView('packets', '${jsFlow}')">📦 Paquetes</button>
            </td>
          </tr>
        `;
      }).join('');

      container.innerHTML = `
        <div style="overflow-x:auto; border:1px solid var(--border-color); border-radius:8px;">
          <table class="report-table" style="width:100%; border-collapse:collapse; font-size:0.78rem;">
            <thead>
              <tr style="background:var(--bg-secondary); color:var(--text-main); text-align:left;">
                <th style="padding:8px;">Conversación (4-Tupla)</th>
                <th style="padding:8px;">Servicio</th>
                <th style="padding:8px; text-align:right;">Paquetes / Bytes</th>
                <th style="padding:8px; text-align:center;">RTT Handshake</th>
                <th style="padding:8px;">TLS / SNI / Cifrado</th>
                <th style="padding:8px;">Estado TCP / Alertas</th>
                <th style="padding:8px; text-align:center;">Acción</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    },

    async _renderPacketsView(container) {
      const ps = this.packetState;
      container.innerHTML = `
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; align-items:center;">
          <input type="text" id="pcap-pkt-search" class="form-control" value="${esc(ps.q)}" placeholder="Buscar IP, puerto, SNI, DNS o info..." style="flex:1; min-width:200px; font-size:0.8rem; padding:6px 10px;" onkeyup="if(event.key==='Enter'){ window.PcapAnalyzer.applyPacketFilters(); }">
          <select id="pcap-pkt-proto" class="form-control" style="width:130px; font-size:0.8rem; padding:6px 8px;" onchange="window.PcapAnalyzer.applyPacketFilters()">
            <option value="ALL" ${ps.proto === 'ALL' ? 'selected' : ''}>Todos Protos</option>
            <option value="TCP" ${ps.proto === 'TCP' ? 'selected' : ''}>TCP</option>
            <option value="UDP" ${ps.proto === 'UDP' ? 'selected' : ''}>UDP</option>
            <option value="TLS" ${ps.proto === 'TLS' ? 'selected' : ''}>TLS</option>
            <option value="DNS" ${ps.proto === 'DNS' ? 'selected' : ''}>DNS</option>
            <option value="HTTP" ${ps.proto === 'HTTP' ? 'selected' : ''}>HTTP/SOAP</option>
            <option value="ICMP" ${ps.proto === 'ICMP' ? 'selected' : ''}>ICMP</option>
          </select>
          <select id="pcap-pkt-severity" class="form-control" style="width:135px; font-size:0.8rem; padding:6px 8px;" onchange="window.PcapAnalyzer.applyPacketFilters()">
            <option value="ALL" ${ps.severity === 'ALL' ? 'selected' : ''}>Todas Sev.</option>
            <option value="CRITICAL" ${ps.severity === 'CRITICAL' ? 'selected' : ''}>🚨 CRITICAL</option>
            <option value="WARN" ${ps.severity === 'WARN' ? 'selected' : ''}>⚠️ WARN</option>
            <option value="INFO" ${ps.severity === 'INFO' ? 'selected' : ''}>ℹ️ INFO</option>
          </select>
          <button class="btn btn-primary" style="background:#0284c7; border:none; font-size:0.78rem; padding:6px 12px; border-radius:6px; cursor:pointer;" onclick="window.PcapAnalyzer.applyPacketFilters()">🔍 Filtrar</button>
          ${ps.flow ? `<span style="background:rgba(139,92,246,0.16); color:#8b5cf6; padding:4px 9px; border-radius:6px; font-size:0.72rem; font-family:monospace; font-weight:700;">Flujo: ${esc(ps.flow)} <button onclick="window.PcapAnalyzer.clearFlowFilter()" style="background:none; border:none; color:#ef4444; font-weight:900; cursor:pointer;">✕</button></span>` : ''}
        </div>
        <div id="pcap-packets-table-wrap" style="border:1px solid var(--border-color); border-radius:8px; overflow-x:auto;">
          <div style="padding:24px; text-align:center; color:var(--text-muted);">⏳ Consultando paquetes desde SQLite...</div>
        </div>
      `;
      await this.loadPacketsPage(ps.page);
    },

    applyPacketFilters() {
      this.packetState.q = (document.getElementById('pcap-pkt-search')?.value || '').trim();
      this.packetState.proto = document.getElementById('pcap-pkt-proto')?.value || 'ALL';
      this.packetState.severity = document.getElementById('pcap-pkt-severity')?.value || 'ALL';
      this.loadPacketsPage(1);
    },

    clearFlowFilter() {
      this.packetState.flow = '';
      this._renderActiveSubView();
    },

    async loadPacketsPage(page) {
      this.packetState.page = Math.max(1, page || 1);
      const wrap = document.getElementById('pcap-packets-table-wrap');
      if (!wrap) return;

      const ps = this.packetState;
      const clientName = encodeURIComponent(getActiveClientName());
      const url = `/api/pcap-packets?client=${clientName}&page=${ps.page}&limit=${ps.limit}&q=${encodeURIComponent(ps.q)}&proto=${encodeURIComponent(ps.proto)}&severity=${encodeURIComponent(ps.severity)}&flow=${encodeURIComponent(ps.flow)}`;
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        const pkts = d.packets || [];
        if (pkts.length === 0) {
          wrap.innerHTML = `<div style="padding:24px; text-align:center; color:var(--text-muted);">No hay paquetes que coincidan con los filtros seleccionados.</div>`;
          return;
        }
        const rowsHtml = pkts.map(p => {
          const isCrit = p.severity === 'CRITICAL';
          const isWarn = p.severity === 'WARN';
          const rowBg = isCrit ? 'rgba(239,68,68,0.1)' : (isWarn ? 'rgba(245,158,11,0.08)' : 'transparent');
          const sevBadge = isCrit ? '🔴 CRIT' : (isWarn ? '🟡 WARN' : '🟢 INFO');
          const srcTxt = p.srcPort ? `${p.srcIp}:${p.srcPort}` : p.srcIp;
          const dstTxt = p.dstPort ? `${p.dstIp}:${p.dstPort}` : p.dstIp;
          return `
            <tr style="border-bottom:1px solid var(--border-color); background:${rowBg}; font-family:'JetBrains Mono', monospace; font-size:0.72rem;">
              <td style="padding:6px 8px; font-weight:800; color:#0284c7;">#${p.frameNum}</td>
              <td style="padding:6px 8px; color:var(--text-muted); white-space:nowrap;">${esc(p.timestamp || '-')}</td>
              <td style="padding:6px 8px; font-size:0.68rem;">${sevBadge}</td>
              <td style="padding:6px 8px;">${esc(srcTxt)}</td>
              <td style="padding:6px 8px;">${esc(dstTxt)}</td>
              <td style="padding:6px 8px; font-weight:700;">${esc(p.appProto || p.proto)}</td>
              <td style="padding:6px 8px; color:#8b5cf6;">${esc(p.tcpFlags || '-')}</td>
              <td style="padding:6px 8px; text-align:right;">${p.length}</td>
              <td style="padding:6px 8px; font-family:'Inter', sans-serif; color:var(--text-main); word-break:break-word;">${p.isEncrypted ? '🔒 ' : ''}${esc(p.info)}</td>
            </tr>
          `;
        }).join('');

        wrap.innerHTML = `
          <table class="report-table" style="width:100%; border-collapse:collapse;">
            <thead>
              <tr style="background:var(--bg-secondary); color:var(--text-main); text-align:left; font-size:0.73rem;">
                <th style="padding:7px 8px;">No.</th>
                <th style="padding:7px 8px;">Tiempo</th>
                <th style="padding:7px 8px;">Nivel</th>
                <th style="padding:7px 8px;">Origen</th>
                <th style="padding:7px 8px;">Destino</th>
                <th style="padding:7px 8px;">Protocolo</th>
                <th style="padding:7px 8px;">Flags TCP</th>
                <th style="padding:7px 8px; text-align:right;">Bytes</th>
                <th style="padding:7px 8px;">Información Decodificada</th>
              </tr>
            </thead>
            <tbody>${rowsHtml}</tbody>
          </table>
          <div style="padding:8px 12px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; background:var(--bg-secondary); border-top:1px solid var(--border-color); font-size:0.75rem;">
            <div>Mostrando página <strong>${d.page}</strong> de <strong>${d.totalPages}</strong> (${(d.totalMatching || 0).toLocaleString()} paquetes coincidentes)</div>
            <div style="display:flex; gap:6px;">
              <button class="btn" ${d.page <= 1 ? 'disabled' : ''} onclick="window.PcapAnalyzer.loadPacketsPage(1)" style="padding:3px 9px; font-size:0.72rem;">⏮ Primera</button>
              <button class="btn" ${d.page <= 1 ? 'disabled' : ''} onclick="window.PcapAnalyzer.loadPacketsPage(${d.page - 1})" style="padding:3px 9px; font-size:0.72rem;">◀ Anterior</button>
              <button class="btn" ${d.page >= d.totalPages ? 'disabled' : ''} onclick="window.PcapAnalyzer.loadPacketsPage(${d.page + 1})" style="padding:3px 9px; font-size:0.72rem;">Siguiente ▶</button>
              <button class="btn" ${d.page >= d.totalPages ? 'disabled' : ''} onclick="window.PcapAnalyzer.loadPacketsPage(${d.totalPages})" style="padding:3px 9px; font-size:0.72rem;">Última ⏭</button>
            </div>
          </div>
        `;
      } catch (e) {
        wrap.innerHTML = `<div style="padding:20px; color:#ef4444;">Error cargando paquetes: ${esc(e.message)}</div>`;
      }
    },

    async _renderCorrelationView(container) {
      container.innerHTML = `
        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:12px;">
          <label style="font-size:0.78rem; font-weight:700; color:var(--text-muted);">⏱️ Ventana de Correlación Temporal (Red ↔ Logs Entrust):</label>
          <select id="pcap-corr-window" class="form-control" style="width:140px; font-size:0.78rem; padding:5px 8px;" onchange="window.PcapAnalyzer.correlationWindowSec=Number(this.value); window.PcapAnalyzer.fetchCorrelation();">
            <option value="2" ${this.correlationWindowSec === 2 ? 'selected' : ''}>± 2 segundos</option>
            <option value="5" ${this.correlationWindowSec === 5 ? 'selected' : ''}>± 5 segundos</option>
            <option value="15" ${this.correlationWindowSec === 15 ? 'selected' : ''}>± 15 segundos</option>
            <option value="60" ${this.correlationWindowSec === 60 ? 'selected' : ''}>± 60 segundos</option>
          </select>
          <button class="btn btn-primary" style="background:#10b981; border:none; font-size:0.76rem; padding:5px 12px; font-weight:700; border-radius:6px; cursor:pointer;" onclick="window.PcapAnalyzer.fetchCorrelation()">🔄 Recalcular Correlación</button>
        </div>
        <div id="pcap-correlation-results"><div style="padding:20px; color:var(--text-muted);">⏳ Buscando coincidencias exactas por segundo entre captura PCAP y SQLite de logs...</div></div>
      `;
      await this.fetchCorrelation();
    },

    async fetchCorrelation() {
      const box = document.getElementById('pcap-correlation-results');
      if (!box) return;
      const clientName = encodeURIComponent(getActiveClientName());
      try {
        const res = await fetch(`/api/pcap-correlate?client=${clientName}&window=${this.correlationWindowSec || 5}`);
        const d = await res.json();
        this.correlationData = d;
        const corrs = d.correlations || [];
        if (d.status !== 'ready' || corrs.length === 0) {
          box.innerHTML = `<div style="padding:20px; background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; color:var(--text-muted); font-size:0.82rem;">ℹ️ ${esc(d.message || `0 anomalías de red coincidieron dentro de ±${this.correlationWindowSec}s con eventos ERROR/WARN en los logs SQLite activos.`)}</div>`;
          return;
        }
        box.innerHTML = corrs.map(c => {
          const nf = c.networkFinding;
          const logPills = (c.matchingLogs || []).map(l => `
            <div style="margin-top:6px; padding:6px 10px; background:var(--bg-secondary); border-left:3px solid #ef4444; border-radius:4px; font-size:0.75rem;">
              <span style="font-family:monospace; font-weight:800; color:#ef4444;">Línea #${l.lineNum} [${esc(l.code)}]</span>
              <span style="font-family:monospace; color:var(--text-muted);">(${esc(l.timestamp)} | Δ ${l.deltaSec > 0 ? '+' : ''}${l.deltaSec}s)</span>
              <span style="color:#0284c7; font-weight:700;">👤 ${esc(l.user)}</span> — ${esc(l.message)}
            </div>
          `).join('');
          return `
            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-left:4px solid #8b5cf6; border-radius:8px; padding:12px 14px; margin-bottom:10px;">
              <div style="font-weight:800; font-size:0.82rem; color:var(--text-main);">
                🌐 Frame #${nf.frameNum} (${esc(nf.timestamp)}) — <span style="color:#ef4444;">${esc(nf.category)}</span> • ${esc(nf.src)} ➔ ${esc(nf.dst)}
              </div>
              <div style="font-size:0.76rem; color:var(--text-muted); margin-top:2px;">${esc(nf.evidence)}</div>
              ${logPills}
            </div>
          `;
        }).join('');
      } catch (e) {
        box.innerHTML = `<div style="padding:20px; color:#ef4444;">Error correlacionando captura con logs: ${esc(e.message)}</div>`;
      }
    },

    handleFilePickerChange(inputEl) {
      if (inputEl && inputEl.files && inputEl.files.length > 0) {
        this.uploadAndAnalyzeFile(inputEl.files[0]);
        inputEl.value = '';
      }
    },

    _setProgress(htmlStr) {
      const box = document.getElementById('pcap-progress-box');
      if (box) {
        box.style.display = htmlStr ? 'block' : 'none';
        if (htmlStr) box.innerHTML = htmlStr;
      }
    },

    async uploadAndAnalyzeFile(file) {
      if (!file || this.isUploading) return;
      this.isUploading = true;
      if (!document.getElementById('pcap-progress-box')) {
        await this.renderTab(this.containerId);
      }
      const clientName = getActiveClientName();
      const chunkSize = 10 * 1024 * 1024;
      const totalChunks = Math.max(1, Math.ceil(file.size / chunkSize));

      try {
        for (let i = 0; i < totalChunks; i++) {
          const blob = file.slice(i * chunkSize, Math.min(file.size, (i + 1) * chunkSize));
          const buf = await blob.arrayBuffer();
          this._setProgress(`📤 Subiendo captura <strong>${esc(file.name)}</strong> (${i + 1}/${totalChunks})...`);
          const res = await fetch('/api/pcap-upload', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/octet-stream',
              'X-Chunk-Index': String(i),
              'X-Total-Chunks': String(totalChunks),
              'X-File-Name': encodeURIComponent(file.name),
              'X-Client-Name': encodeURIComponent(clientName)
            },
            body: buf
          });
          if (!res.ok) {
            const errJson = await res.json().catch(() => ({}));
            throw new Error(errJson.error || `HTTP ${res.status} al subir captura PCAP`);
          }
        }
        await this._pollUntilReady(file.name);
        await this.renderTab(this.containerId);
      } catch (e) {
        this._setProgress(`<span style="color:#ef4444; font-weight:700;">❌ Error procesando captura: ${esc(e.message)}</span>`);
      } finally {
        this.isUploading = false;
      }
    },

    async analyzeSelectedServerFile() {
      const sel = document.getElementById('pcap-server-file-select');
      if (!sel || !sel.value) return;
      const fileName = sel.value;
      const clientName = getActiveClientName();
      try {
        this._setProgress(`⚙️ Iniciando decodificación binaria en servidor de <strong>${esc(fileName)}</strong>...`);
        const res = await fetch('/api/pcap-analyze-server-file', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filePath: fileName, clientName })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        await this._pollUntilReady(fileName);
        await this.renderTab(this.containerId);
      } catch (e) {
        this._setProgress(`<span style="color:#ef4444; font-weight:700;">❌ Error: ${esc(e.message)}</span>`);
      }
    },

    async _pollUntilReady(fileName) {
      for (let t = 0; t < 300; t++) {
        await new Promise(r => setTimeout(r, 400));
        const stRes = await fetch('/api/pcap-status');
        if (!stRes.ok) continue;
        const st = await stRes.json();
        if (st.status === 'ready') {
          this._setProgress(`✅ Captura <strong>${esc(fileName)}</strong> decodificada: ${(st.packetsProcessed || 0).toLocaleString()} paquetes.`);
          return st;
        }
        if (st.status === 'error') {
          throw new Error(st.error || 'Error decodificando captura');
        }
        this._setProgress(`🔬 Decodificando paquetes binarios de <strong>${esc(fileName)}</strong>: ${(st.packetsProcessed || 0).toLocaleString()} paquetes (${formatBytes(st.bytesProcessed)})...`);
      }
      throw new Error('Tiempo de espera agotado analizando la captura.');
    },

    exportCsv(exportType) {
      const clientName = encodeURIComponent(getActiveClientName());
      const a = document.createElement('a');
      a.href = `/api/pcap-export-csv?client=${clientName}&type=${encodeURIComponent(exportType || 'anomalies')}`;
      a.download = `PCAP_${exportType || 'anomalies'}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  };

  window.PcapAnalyzer = PcapAnalyzer;
})();
