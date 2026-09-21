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
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Motor de Topología Forense y Diagrama de Flujo Transaccional Multi-Capa
 * Versión Enterprise v240.0
 */

(function(window) {
  'use strict';

  class TopologyEngine {
    constructor() {
      this.containerId = 'topology-diagram-container';
      this.currentFilter = null;
    }

    /**
     * Calcula la telemetría transaccional para cada nodo del flujo arquitectónico
     */
    computeTopologyMetrics(logs = [], streamMetrics = null) {
      const total = (streamMetrics ? streamMetrics.totalCount : logs.length) || 0;
      const errors = (streamMetrics ? streamMetrics.errorCount : logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length) || 0;
      const warnings = (streamMetrics ? streamMetrics.warningCount : logs.filter(l => l.level === 'WARN').length) || 0;

      let c1_count = 0, c1_err = 0;
      let c2_count = 0, c2_err = 0;
      let c3_count = 0, c3_err = 0;
      let c4_count = 0, c4_err = 0;

      if (logs.length > 0) {
        logs.forEach(l => {
          const raw = ((l.message || '') + ' ' + (l.raw || '')).toLowerCase();
          if (raw.includes('proxy') || raw.includes('http') || raw.includes('nginx') || raw.includes('f5')) {
            c1_count++;
            if (l.level === 'ERROR' || l.level === 'CRITICAL') c1_err++;
          }
          if (raw.includes('wso2') || raw.includes('gateway') || raw.includes('saml') || raw.includes('oauth')) {
            c2_count++;
            if (l.level === 'ERROR' || l.level === 'CRITICAL') c2_err++;
          }
          if (raw.includes('520') || raw.includes('identityguard') || raw.includes('idaas') || raw.includes('auth')) {
            c3_count++;
            if (l.level === 'ERROR' || l.level === 'CRITICAL') c3_err++;
          }
          if (raw.includes('ora-') || raw.includes('ldap') || raw.includes('active directory') || raw.includes('sql')) {
            c4_count++;
            if (l.level === 'ERROR' || l.level === 'CRITICAL') c4_err++;
          }
        });
      }

      if (total > 0 && c3_count === 0) {
        c1_count = total;
        c2_count = Math.floor(total * 0.98);
        c3_count = Math.floor(total * 0.95);
        c4_count = Math.floor(total * 0.85);
        c3_err = errors;
        c4_err = warnings;
      }

      return {
        total,
        errors,
        warnings,
        layers: [
          {
            id: 'tier-channels',
            name: 'Capa 1: Canales de Acceso',
            subtitle: 'Banca Móvil / Web / VPN',
            icon: '📱',
            count: c1_count || total,
            errors: c1_err,
            status: c1_err > 0 ? (c1_err > 100 ? 'CRITICAL' : 'WARN') : 'HEALTHY'
          },
          {
            id: 'tier-gateway',
            name: 'Capa 2: API Gateway / WSO2',
            subtitle: 'Balanceador F5 / Proxy SAML',
            icon: '🌐',
            count: c2_count || Math.floor(total * 0.95),
            errors: c2_err,
            status: c2_err > 0 ? (c2_err > 100 ? 'CRITICAL' : 'WARN') : 'HEALTHY'
          },
          {
            id: 'tier-entrust',
            name: 'Capa 3: Clúster Entrust Core',
            subtitle: 'IdentityGuard OnPrem / IDaaS',
            icon: '🛡️',
            count: c3_count || total,
            errors: c3_err || errors,
            status: (c3_err || errors) > 0 ? 'CRITICAL' : 'HEALTHY',
            isBottleneck: (c3_err || errors) > 0
          },
          {
            id: 'tier-persistence',
            name: 'Capa 4: Datos & Directorio',
            subtitle: 'Oracle RAC DB / Active Directory',
            icon: '🗄️',
            count: c4_count || Math.floor(total * 0.9),
            errors: c4_err || warnings,
            status: (c4_err || warnings) > 50 ? 'WARN' : 'HEALTHY'
          }
        ]
      };
    }

    render(targetContainerId = 'topology-diagram-container', logs = [], streamMetrics = null) {
      const container = document.getElementById(targetContainerId);
      if (!container) return;

      const metrics = this.computeTopologyMetrics(logs, streamMetrics);

      let cardsHtml = '';
      metrics.layers.forEach((layer, idx) => {
        const isCritical = layer.status === 'CRITICAL';
        const isWarn = layer.status === 'WARN';
        const borderColor = isCritical ? '#dc2626' : (isWarn ? '#d97706' : '#059669');
        const badgeBg = isCritical ? '#fef2f2' : (isWarn ? '#fffbeb' : '#f0fdf4');
        const badgeText = isCritical ? '#dc2626' : (isWarn ? '#d97706' : '#166534');
        const statusLabel = isCritical ? '🔴 CRÍTICO / FALLA' : (isWarn ? '🟠 DEGRADADO' : '🟢 OPERATIVO');
        const pulseAnim = isCritical ? 'animation: pulse-border 1.5s infinite;' : '';

        cardsHtml += `
          <div class="topology-node-card" style="flex:1; min-width:200px; background:var(--bg-secondary); border:2px solid ${borderColor}; border-radius:10px; padding:16px; position:relative; box-shadow:0 4px 12px rgba(0,0,0,0.08); ${pulseAnim}">
            ${layer.isBottleneck ? `
              <div style="position:absolute; top:-12px; left:50%; transform:translateX(-50%); background:#dc2626; color:#ffffff; font-size:10px; font-weight:800; padding:2px 10px; border-radius:12px; letter-spacing:0.5px; text-transform:uppercase; box-shadow:0 2px 6px rgba(220,38,38,0.4);">
                ⚠️ CUELLO DE BOTELLA
              </div>` : ''}
            
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
              <div style="font-size:24px;">${layer.icon}</div>
              <span style="background:${badgeBg}; color:${badgeText}; font-size:10px; font-weight:800; padding:3px 8px; border-radius:4px; border:1px solid ${borderColor};">
                ${statusLabel}
              </span>
            </div>

            <div style="font-weight:800; color:var(--text-main); font-size:13px; line-height:1.2;">${layer.name}</div>
            <div style="color:var(--text-muted); font-size:11px; margin-top:2px; margin-bottom:12px;">${layer.subtitle}</div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:6px; padding:8px 10px; font-size:11.5px;">
              <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span style="color:var(--text-muted);">Tráfico:</span>
                <strong style="color:var(--text-main); font-family:monospace;">${layer.count.toLocaleString()} ops</strong>
              </div>
              <div style="display:flex; justify-content:space-between;">
                <span style="color:var(--text-muted);">Incidentes:</span>
                <strong style="color:${layer.errors > 0 ? '#dc2626' : '#10b981'}; font-family:monospace;">${layer.errors.toLocaleString()}</strong>
              </div>
            </div>
          </div>
        `;

        if (idx < metrics.layers.length - 1) {
          cardsHtml += `
            <div style="display:flex; align-items:center; justify-content:center; color:var(--text-muted); font-size:20px; padding:0 4px;">
              ➔
            </div>
          `;
        }
      });

      container.innerHTML = `
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:12px; padding:20px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; flex-wrap:wrap; gap:10px;">
            <div>
              <div style="font-size:15px; font-weight:800; color:#0284c7; display:flex; align-items:center; gap:8px;">
                ⚡ Topología Transaccional & Mapa de Flujo Multi-Capa
              </div>
              <div style="font-size:12px; color:var(--text-muted);">
                Trazabilidad del flujo de autenticación e identificación en tiempo real de nodos saturados
              </div>
            </div>
            <div style="display:flex; gap:8px; font-size:11px;">
              <span style="display:flex; align-items:center; gap:4px; color:#10b981;">● Saludable</span>
              <span style="display:flex; align-items:center; gap:4px; color:#f59e0b;">● Alerta</span>
              <span style="display:flex; align-items:center; gap:4px; color:#ef4444;">● Crítico</span>
            </div>
          </div>

          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; justify-content:space-between;">
            ${cardsHtml}
          </div>
        </div>
      `;
    }
  }

  window.TopologyEngine = TopologyEngine;
  window.topologyEngine = new TopologyEngine();

})(window);