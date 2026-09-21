/**
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Motor Calculador de SLA Bancario & Métricas Regulatorias (Sudeban / Basilea III)
 * Versión Enterprise v300.0
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
      
      const allowedDowntimeMinMonthly = 21.6; // para 99.95% en 43,200 min/mes
      const actualDowntimeMin = parseFloat(((100 - uptimePct) * 432).toFixed(1));
      
      const isCompliantTier1 = uptimePct >= this.targetSlaTier1;
      const isCompliantTier2 = uptimePct >= this.targetSlaTier2;

      let status = 'COMPLIANT';
      let statusLabel = '🟢 SLA CUMPLIDO (Conforme a Sudeban)';
      let statusColor = '#10b981';

      if (!isCompliantTier1 && isCompliantTier2) {
        status = 'WARNING';
        statusLabel = '🟡 ADVERTENCIA (Bajo Umbral 99.95%)';
        statusColor = '#f59e0b';
      } else if (!isCompliantTier2) {
        status = 'BREACH';
        statusLabel = '🔴 RIESGO DE INCUMPLIMIENTO / SANCIÓN SUDEBAN';
        statusColor = '#ef4444';
      }

      return {
        total,
        criticalErrors,
        uptimePct,
        targetSlaTier1: this.targetSlaTier1,
        targetSlaTier2: this.targetSlaTier2,
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
      const isOk = m.status === 'COMPLIANT';
      const isWarn = m.status === 'WARNING';
      const hoursDowntime = (m.actualDowntimeMin / 60).toFixed(1);

      container.innerHTML = `
        <div style="background:var(--bg-card); border:1.5px solid ${m.statusColor}; border-radius:12px; padding:20px; box-shadow:var(--shadow-sm); margin-bottom:20px; position:relative; overflow:hidden;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; flex-wrap:wrap; gap:12px;">
            <div style="display:flex; align-items:center; gap:10px;">
              <div style="width:38px; height:38px; border-radius:8px; background:rgba(2,132,199,0.12); display:flex; align-items:center; justify-content:center; font-size:1.3rem;">
                🏦
              </div>
              <div>
                <div style="font-size:1.05rem; font-weight:800; color:var(--text-main);">
                  Calculadora de SLA Bancario &amp; Cumplimiento Regulatorio
                </div>
                <div style="font-size:0.75rem; color:var(--text-muted);">
                  Evaluación de disponibilidad técnica conforme a estándares bancarios (Sudeban / Basilea III / ISO 27001)
                </div>
              </div>
            </div>
            <span style="background:${m.statusColor}15; color:${m.statusColor}; border:1.5px solid ${m.statusColor}; font-weight:900; font-size:0.78rem; padding:5px 14px; border-radius:20px; letter-spacing:0.5px;">
              ${m.statusLabel}
            </span>
          </div>

          <!-- Barra de Progreso de SLA Visual con Zonas -->
          <div style="margin-bottom:16px;">
            <div class="flex-between mb-1" style="font-size:0.75rem; color:var(--text-muted);">
              <span>Nivel Observado: <strong style="color:${m.statusColor}; font-size:0.85rem;">${m.uptimePct}%</strong></span>
              <span>Meta Tier 1: <strong>99.95%</strong> | Meta Tier 2: <strong>99.90%</strong></span>
            </div>
            <div style="height:10px; width:100%; background:rgba(0,0,0,0.1); border-radius:5px; overflow:hidden; position:relative;">
              <div style="width:${Math.min(100, Math.max(5, m.uptimePct))}%; height:100%; background:linear-gradient(90deg, #ef4444, #f59e0b, #10b981); border-radius:5px; transition:width 1s ease;"></div>
            </div>
          </div>

          <!-- 3 Tarjetas de Métricas Ejecutivas -->
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px;">
            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; text-align:center;">
              <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">DISPONIBILIDAD REAL</div>
              <div style="font-size:2rem; font-weight:900; color:${m.statusColor}; margin:4px 0; font-family:'JetBrains Mono', monospace;">
                ${m.uptimePct}%
              </div>
              <div style="font-size:0.72rem; color:var(--text-muted);">Objetivo Sudeban: <strong>99.95%</strong></div>
            </div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; text-align:center;">
              <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">INDISPONIBILIDAD CALCULADA</div>
              <div style="font-size:2rem; font-weight:900; color:${m.actualDowntimeMin > 21.6 ? '#ef4444' : '#10b981'}; margin:4px 0; font-family:'JetBrains Mono', monospace;">
                ${m.actualDowntimeMin.toLocaleString()} min
              </div>
              <div style="font-size:0.72rem; color:var(--text-muted);">Equivalente a <strong>~${hoursDowntime} horas</strong> (Máx mensual: 21.6 min)</div>
            </div>

            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:8px; padding:14px; text-align:center;">
              <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:0.5px;">OPERACIONES AFECTADAS</div>
              <div style="font-size:2rem; font-weight:900; color:#ef4444; margin:4px 0; font-family:'JetBrains Mono', monospace;">
                ${m.estimatedBlockedUsers.toLocaleString()}
              </div>
              <div style="font-size:0.72rem; color:var(--text-muted);">Transacciones denegadas / Fallos P1-P2</div>
            </div>
          </div>
        </div>
      `;
    }
  }

  window.SlaEngine = SlaEngine;
  window.slaEngine = new SlaEngine();

})(window);
