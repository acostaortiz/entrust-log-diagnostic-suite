/**
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Motor de Detección de Amenazas, Cuentas Críticas & Ataques de Fuerza Bruta
 * Versión Enterprise v300.0
 */

(function(window) {
  'use strict';

  class ThreatRadarEngine {
    constructor() {
      this.thresholdBruteForce = 15;
    }

    /**
     * Analiza los logs para extraer cuentas atacadas y patrones de fuerza bruta
     */
    analyzeThreats(logs = []) {
      const targetLogs = Array.isArray(logs) ? logs : [];

      // Si no hay logs en la sesión actual, retornar estado 100% limpio
      if (!targetLogs || targetLogs.length === 0) {
        return {
          totalFailedAuth: 0,
          topTargetUsers: [],
          topAttackingIPs: [],
          isUnderMassiveAttack: false,
          detectedVictimsCount: 0
        };
      }

      const userMap = new Map();
      const ipMap = new Map();
      let totalFailedAuth = 0;

      // Si no hay logs en la sesión actual, retornar estado limpio
      if (!targetLogs || targetLogs.length === 0) {
        return {
          totalFailedAuth: 0,
          topTargetUsers: [],
          topAttackingIPs: [],
          isUnderMassiveAttack: false,
          detectedVictimsCount: 0
        };
      }

      targetLogs.forEach(l => {
        const msg = (l.message || '') + ' ' + (l.raw || '');
        const isAuthFail = (l.level === 'CRITICAL' || l.level === 'ERROR') ||
                           /(5202013|5205079|5201006|5201007|5201010|5203016|Invalid user ID|password|locked|FAIL|bulkidentityguard\.add\.error)/i.test(msg);

        if (!isAuthFail) return;
        totalFailedAuth++;

        // Extraer usuario
        let user = l.user || l.userId || null;
        if (!user || user === 'unknown' || user === 'system') {
          const userMatch = msg.match(/(?:user|usuario|userId|principal|account)\s*[:=\[]?\s*["']?([a-zA-Z0-9_\-\.\@\/]+)["']?/i) ||
                            msg.match(/\[([VvEeJjGgPp]\-?\d{6,10}|usr_[a-zA-Z0-9_]+|[a-zA-Z0-9_\.\-]+@[a-zA-Z0-9\.\-]+)\]/);
          if (userMatch) user = userMatch[1];
        }

        if (user && user !== 'unknown' && user !== 'system' && user.length > 2) {
          if (!userMap.has(user)) {
            userMap.set(user, {
              user: user,
              attempts: 0,
              codes: new Set(),
              lastSeen: l.timestamp || l.time || 'N/A',
              isLocked: false
            });
          }
          const uEntry = userMap.get(user);
          uEntry.attempts++;
          if (l.entrustCode) uEntry.codes.add(l.entrustCode);
          if (/5205079|locked|bloquead|error\.password/i.test(msg)) uEntry.isLocked = true;
          uEntry.lastSeen = l.timestamp || l.time || uEntry.lastSeen;
        }

        // Extraer IP
        const ip = l.clientIp || l.ip || null;
        if (ip && ip !== '127.0.0.1') {
          ipMap.set(ip, (ipMap.get(ip) || 0) + 1);
        }
      });

      const topTargetUsers = Array.from(userMap.values())
        .sort((a, b) => b.attempts - a.attempts)
        .slice(0, 10)
        .map(u => ({
          ...u,
          codesList: Array.from(u.codes).join(', ') || 'bulkidentityguard.add.error',
          riskLevel: u.attempts >= this.thresholdBruteForce ? 'CRITICAL (Fuerza Bruta)' : (u.attempts >= 5 ? 'HIGH' : 'MEDIUM')
        }));

      const topAttackingIPs = Array.from(ipMap.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count }));

      const isUnderMassiveAttack = topTargetUsers.some(u => u.attempts >= this.thresholdBruteForce) || totalFailedAuth > 500;

      return {
        totalFailedAuth,
        topTargetUsers: topTargetUsers,
        topAttackingIPs,
        isUnderMassiveAttack,
        detectedVictimsCount: userMap.size
      };
    }

    render(containerId, logs = []) {
      const container = document.getElementById(containerId);
      if (!container) return;

      const report = this.analyzeThreats(logs);

      if (!report.topTargetUsers || report.topTargetUsers.length === 0) {
        container.innerHTML = `
          <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
            <div style="font-size: 1.6rem; margin-bottom: 6px;">🛡️</div>
            <strong style="color: var(--text-main); display: block; margin-bottom: 4px;">Sesión Limpia — Sin incidentes de seguridad detectados</strong>
            <span>Cargue un archivo de logs para auditar intentos fallidos de autenticación y patrones de fuerza bruta.</span>
          </div>`;
        return;
      }

      let rowsHtml = '';
      report.topTargetUsers.forEach((u, idx) => {
        const isCrit = u.riskLevel.includes('CRITICAL');
        const badgeBg = isCrit ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)';
        const badgeColor = isCrit ? '#ef4444' : '#f59e0b';

        rowsHtml += `
          <tr style="border-bottom:1px solid var(--border-color); background:${idx % 2 === 0 ? 'transparent' : 'rgba(15,23,42,0.02)'};">
            <td style="padding:10px; font-weight:700; color:var(--text-main); font-family:'JetBrains Mono', monospace; font-size:0.82rem;">
              👤 ${escapeHtml(u.user)} ${u.isLocked ? '<span style="color:#ef4444; font-size:10px; font-weight:800; background:rgba(239,68,68,0.15); padding:1px 6px; border-radius:3px; margin-left:4px;">BLOQUEADO</span>' : ''}
            </td>
            <td style="padding:10px; text-align:center; font-weight:900; color:#ef4444; font-family:'JetBrains Mono', monospace; font-size:0.85rem;">
              ${u.attempts.toLocaleString()}
            </td>
            <td style="padding:10px; font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:#0284c7;">
              ${escapeHtml(u.codesList)}
            </td>
            <td style="padding:10px; font-size:0.75rem; color:var(--text-muted); font-family:monospace;">
              ${escapeHtml(u.lastSeen)}
            </td>
            <td style="padding:10px; text-align:center;">
              <span style="background:${badgeBg}; color:${badgeColor}; padding:3px 8px; border-radius:4px; font-size:10px; font-weight:800; border:1px solid ${badgeColor};">
                ${u.riskLevel}
              </span>
            </td>
          </tr>
        `;
      });

      container.innerHTML = `
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:10px; padding:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; flex-wrap:wrap; gap:10px;">
            <div>
              <div style="font-size:0.95rem; font-weight:800; color:#f43f5e; display:flex; align-items:center; gap:8px;">
                <span>🎯</span> Identidades Bancarias Bajo Ataque Reiterado o Conflicto
              </div>
              <div style="font-size:0.75rem; color:var(--text-muted);">
                Extracción forense de cuentas afectadas por fallos masivos o intentos de autenticación
              </div>
            </div>
            ${report.isUnderMassiveAttack ? `
              <div style="background:rgba(239,68,68,0.12); border:1.5px solid #ef4444; color:#ef4444; padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:900;">
                ⚠️ PATRÓN DE ATAQUE / CONFLICTO DETECTADO
              </div>
            ` : `
              <div style="background:rgba(16,185,129,0.12); border:1px solid #10b981; color:#10b981; padding:4px 10px; border-radius:6px; font-size:0.75rem; font-weight:bold;">
                🟢 Nivel Controlado
              </div>
            `}
          </div>

          <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; text-align:left; font-size:0.8rem; margin-bottom:12px;">
              <thead>
                <tr style="background:var(--bg-secondary); border-bottom:2px solid var(--border-color); color:var(--text-muted); font-size:0.75rem;">
                  <th style="padding:8px 10px;">Cuenta / Identificador</th>
                  <th style="padding:8px 10px; text-align:center;">Intentos Fallidos</th>
                  <th style="padding:8px 10px;">Códigos Registrados</th>
                  <th style="padding:8px 10px;">Último Registro</th>
                  <th style="padding:8px 10px; text-align:center;">Nivel de Riesgo</th>
                </tr>
              </thead>
              <tbody>
                ${rowsHtml}
              </tbody>
            </table>
          </div>

          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; font-size:0.75rem; color:var(--text-muted);">
            <span>Total Transacciones Denegadas: <strong style="color:#ef4444;">${report.totalFailedAuth.toLocaleString()}</strong> | Identidades Únicas: <strong style="color:var(--text-main);">${report.detectedVictimsCount.toLocaleString()}</strong></span>
            <button class="btn btn-primary" id="btn-export-soc-report-mini" style="background:#dc2626; border-color:#dc2626; font-size:0.75rem; padding:4px 10px; border-radius:4px; font-weight:bold; cursor:pointer;">
              📋 Exportar Ficha SOC / Fraude
            </button>
          </div>
        </div>
      `;

      document.getElementById('btn-export-soc-report-mini')?.addEventListener('click', () => {
        const text = `=== DICTAMEN DE INCIDENTE PARA SOC / PREVENCIÓN DE FRAUDE ===\nFecha: ${new Date().toLocaleString('es-VE')}\nIntentos Fallidos Totales: ${report.totalFailedAuth.toLocaleString()}\nCuentas Más Afectadas:\n` +
          report.topTargetUsers.map(u => `- ${u.user}: ${u.attempts.toLocaleString()} intentos (${u.codesList})`).join('\n');
        navigator.clipboard.writeText(text).then(() => {
          alert('✅ Ficha de incidente copiada al portapapeles para el equipo de SOC / Fraude.');
        });
      });
    }

    exportSocReport(logs = [], activeClient = null) {
      const report = this.analyzeThreats(logs);
      const clientName = activeClient ? activeClient.name : 'Entrust General';
      const socData = {
        title: 'Reporte Forense de Amenazas e Identidades Afectadas',
        organization: clientName,
        generationDate: new Date().toISOString(),
        totalFailedAuth: report.totalFailedAuth,
        isUnderMassiveAttack: report.isUnderMassiveAttack,
        topAttackedAccounts: report.topTargetUsers,
        topAttackingIPs: report.topAttackingIPs,
        recommendation: 'Aplicar bloqueo temporal perimetral a IPs agresoras y reiniciar pool de aprovisionamiento IDaaS / AD.'
      };

      const blob = new Blob([JSON.stringify(socData, null, 2)], { type: 'application/json' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = `reporte_soc_amenazas_${clientName.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().slice(0,10)}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    }
  }

  function escapeHtml(text) {
    if (!text) return '';
    return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  window.ThreatRadarEngine = ThreatRadarEngine;
  window.threatRadarEngine = new ThreatRadarEngine();

})(window);
