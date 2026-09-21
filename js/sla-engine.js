/**
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Motor Calculador de SLA Bancario & Métricas Regulatorias (Sudeban / Basilea III)
 * Versión Enterprise v260.0
 */

(function(window) {
  'use strict';

  class SlaEngine {
    constructor() {
      this.targetSlaTier1 = 99.95; // 99.95% para Banca Digital
      this.targetSlaTier2 = 99.90; // 99.90% para Servicios Auxiliares
    }

    computeSlaMetrics(totalLogs = 0, criticalErrors = 0, warningErrors = 0) {
      const total = totalLogs || 1;
      const uptimePct = parseFloat((((total - criticalErrors) / total) * 100).toFixed(2));
      
      // Minutos estimados de degradación asumiendo intervalo mensual (43,200 min)
      const allowedDowntimeMinMonthly = 21.6; // para 99.95%
      const actualDowntimeMin = parseFloat(((100 - uptimePct) * 432).toFixed(1));
      
      const isCompliantTier1 = uptimePct >= this.targetSlaTier1;
      const isCompliantTier2 = uptimePct >= this.targetSlaTier2;

      let status = 'COMPLIANT';
      let statusLabel = '🟢 SLA CUMPLIDO (Conforme a Sudeban)';
      let statusColor = '#059669';

      if (!isCompliantTier1 && isCompliantTier2) {
        status = 'WARNING';
        statusLabel = '🟡 ADVERTENCIA (Bajo Umbral 99.95%)';
        statusColor = '#d97706';
      } else if (!isCompliantTier2) {
        status = 'BREACH';
        statusLabel = '🔴 RIESGO DE INCUMPLIMIENTO / SANCIÓN';
        statusColor = '#dc2626';
      }

      return {
        total,
        criticalErrors,
        uptimePct,
        targetSlaTier1: this.targetSlaTier1,
        actualDowntimeMin,
        allowedDowntimeMinMonthly,
        status,
        statusLabel,
        statusColor,
        estimatedBlockedUsers: criticalErrors
      };
    }

    render(containerId, totalLogs, criticalErrors, warningErrors) {
      const container = document.getElementById(containerId);
      if (!container) return;

      const m = this.computeSlaMetrics(totalLogs, criticalErrors, warningErrors);

      container.innerHTML = `
        <div style="background:var(--bg-primary); border:1.5px solid ${m.statusColor}; border-radius:10px; padding:18px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;">
            <div>
              <div style="font-size:1.05rem; font-weight:800; color:#0a3d6d;">
                🏦 Calculadora de SLA Bancario & Cumplimiento Regulatorio
              </div>
              <div style="font-size:0.8rem; color:var(--text-muted);">
                Evaluación de disponibilidad técnica conforme a estándares bancarios (Sudeban / ISO 27001)
              </div>
            </div>
            <span style="background:${m.statusColor}15; color:${m.statusColor}; border:1.5px solid ${m.statusColor}; font-weight:900; font-size:0.82rem; padding:4px 12px; border-radius:6px;">
              ${m.statusLabel}
            </span>
          </div>

          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:14px;">
            <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:8px; padding:12px; text-align:center;">
              <div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:bold;">Disponibilidad Real</div>
              <div style="font-size:1.8rem; font-weight:900; color:${m.statusColor}; margin:2px 0;">${m.uptimePct}%</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">Objetivo: ${m.targetSlaTier1}%</div>
            </div>

            <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:8px; padding:12px; text-align:center;">
              <div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:bold;">Indisponibilidad Calculada</div>
              <div style="font-size:1.8rem; font-weight:900; color:${m.actualDowntimeMin > 21.6 ? '#dc2626' : '#059669'}; margin:2px 0;">${m.actualDowntimeMin} min</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">Tolerancia mensual: 21.6 min</div>
            </div>

            <div style="background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:8px; padding:12px; text-align:center;">
              <div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:bold;">Operaciones Afectadas</div>
              <div style="font-size:1.8rem; font-weight:900; color:#dc2626; margin:2px 0;">${m.estimatedBlockedUsers.toLocaleString()}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">Transacciones denegadas</div>
            </div>
          </div>
        </div>
      `;
    }
  }

  window.SlaEngine = SlaEngine;
  window.slaEngine = new SlaEngine();

})(window);