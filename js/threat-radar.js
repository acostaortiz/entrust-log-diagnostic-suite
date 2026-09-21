/**
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Motor de Detección de Amenazas, Cuentas Críticas & Ataques de Fuerza Bruta
 * Versión Enterprise v260.0
 */

(function(window) {
  'use strict';

  class ThreatRadarEngine {
    constructor() {
      this.thresholdBruteForce = 15; // intentos fallidos en la muestra
    }

    /**
     * Analiza los logs para extraer cuentas atacadas y patrones de fuerza bruta
     */
    analyzeThreats(logs = []) {
      const userMap = new Map();
      const ipMap = new Map();
      let totalFailedAuth = 0;

      logs.forEach(l => {
        const msg = (l.message || '') + ' ' + (l.raw || '');
        const isAuthFail = (l.level === 'CRITICAL' || l.level === 'ERROR') ||
                           /(5202013|5205079|5201006|5201007|5201010|5203016|Invalid user ID|password|locked)/i.test(msg);

        if (!isAuthFail) return;
        totalFailedAuth++;

        // Extraer usuario
        let user = l.user || l.userId || null;
        if (!user || user === 'unknown' || user === 'system') {
          const userMatch = msg.match(/(?:user|usuario|userId|principal|account)\s*[:=\[]?\s*["']?([a-zA-Z0-9_\-\.\@]+)["']?/i) ||
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
          if (/5205079|locked|bloquead/i.test(msg)) uEntry.isLocked = true;
          uEntry.lastSeen = l.timestamp || l.time || uEntry.lastSeen;
        }

        // Extraer IP
        const ipMatch = msg.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (ipMatch && ipMatch[0] !== '127.0.0.1') {
          const ip = ipMatch[0];
          ipMap.set(ip, (ipMap.get(ip) || 0) + 1);
        }
      });

      const topTargetUsers = Array.from(userMap.values())
        .sort((a, b) => b.attempts - a.attempts)
        .slice(0, 10)
        .map(u => ({
          ...u,
          codesList: Array.from(u.codes).join(', ') || '5202013',
          riskLevel: u.attempts >= this.thresholdBruteForce ? 'CRITICAL (Fuerza Bruta)' : (u.attempts >= 5 ? 'HIGH' : 'MEDIUM')
        }));

      const topAttackingIPs = Array.from(ipMap.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count }));

      const isUnderMassiveAttack = topTargetUsers.some(u => u.attempts >= this.thresholdBruteForce) || totalFailedAuth > 500;

      return {
        totalFailedAuth,
        topTargetUsers,
        topAttackingIPs,
        isUnderMassiveAttack,
        detectedVictimsCount: userMap.size
      };
    }

    render(containerId, logs = []) {
      const container = document.getElementById(containerId);
      if (!container) return;

      const report = this.analyzeThreats(logs);

      let rowsHtml = '';
      if (report.topTargetUsers.length === 0) {
        rowsHtml = `<tr><td colspan="5" style="text-align:center; padding:16px; color:var(--text-muted);">No se detectaron patrones de ataques reiterados contra cuentas específicas en la muestra.</td></tr>`;
      } else {
        report.topTargetUsers.forEach((u, idx) => {
          const isCrit = u.riskLevel.includes('CRITICAL');
          const badgeBg = isCrit ? '#fef2f2' : '#fffbeb';
          const badgeColor = isCrit ? '#dc2626' : '#d97706';

          rowsHtml += `
            <tr style="background:${idx % 2 === 0 ? 'var(--bg-primary)' : 'var(--bg-secondary)'};">
              <td style="padding:8px 10px; font-weight:bold; color:var(--text-main); font-family:monospace;">
                👤 ${escapeHtml(u.user)} ${u.isLocked ? '<span style="color:#dc2626; font-size:10px;">[BLOQUEADO]</span>' : ''}
              </td>
              <td style="padding:8px 10px; text-align:center; font-weight:900; color:#dc2626; font-family:monospace;">
                ${u.attempts.toLocaleString()}
              </td>
              <td style="padding:8px 10px; font-family:monospace; font-size:11px; color:#0284c7;">
                ${escapeHtml(u.codesList)}
              </td>
              <td style="padding:8px 10px; font-size:11px; color:var(--text-muted);">
                ${escapeHtml(u.lastSeen)}
              </td>
              <td style="padding:8px 10px; text-align:center;">
                <span style="background:${badgeBg}; color:${badgeColor}; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:800; border:1px solid ${badgeColor};">
                  ${u.riskLevel}
                </span>
              </td>
            </tr>
          `;
        });
      }

      container.innerHTML = `
        <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:10px; padding:18px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; flex-wrap:wrap; gap:10px;">
            <div>
              <div style="font-size:1.05rem; font-weight:800; color:#dc2626; display:flex; align-items:center; gap:8px;">
                🎯 Radar de Amenazas: Cuentas Bajo Ataque & Fuerza Bruta
              </div>
              <div style="font-size:0.8rem; color:var(--text-muted);">
                Identificación de identidades bancarias objetivo de ataques de diccionario o bloqueos masivos
              </div>
            </div>
            ${report.isUnderMassiveAttack ? `
              <div style="background:#fef2f2; border:1.5px solid #ef4444; color:#dc2626; padding:6px 12px; border-radius:6px; font-size:0.8rem; font-weight:900; animation:pulse-border 1.5s infinite;">
                ⚠️ ALERTA: PATRÓN DE FUERZA BRUTA DETECTADO
              </div>
            ` : `
              <div style="background:#f0fdf4; border:1px solid #10b981; color:#166534; padding:4px 10px; border-radius:6px; font-size:0.78rem; font-weight:bold;">
                🟢 Nivel de Amenaza Controlado
              </div>
            `}
          </div>

          <table style="width:100%; border-collapse:collapse; font-size:11.5px; margin-bottom:14px;">
            <thead>
              <tr style="background:#0a3d6d; color:#ffffff; text-align:left;">
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

          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; font-size:11px; color:var(--text-muted);">
            <span>Total Intentos Fallidos Analizados: <strong style="color:#dc2626;">${report.totalFailedAuth.toLocaleString()}</strong> | Identidades Únicas: <strong style="color:var(--text-main);">${report.detectedVictimsCount}</strong></span>
            <button class="btn btn-primary" id="btn-export-soc-report" style="background:#dc2626; border-color:#dc2626; font-size:0.75rem; padding:4px 10px;">📋 Exportar Ficha para SOC / Fraude</button>
          </div>
        </div>
      `;

      document.getElementById('btn-export-soc-report')?.addEventListener('click', () => {
        const text = `DICTAMEN DE INCIDENTE PARA SOC / PREVENCIÓN DE FRAUDE\nFecha: ${new Date().toLocaleString('es-ES')}\nIntentos Fallidos Totales: ${report.totalFailedAuth}\nCuentas Más Atacadas:\n` +
          report.topTargetUsers.map(u => `- ${u.user}: ${u.attempts} intentos (${u.codesList})`).join('\n');
        navigator.clipboard.writeText(text).then(() => {
          alert('✅ Ficha de incidente copiada al portapapeles para envío al equipo de SOC / Fraude.');
        });
      });
    }
  }

  window.ThreatRadarEngine = ThreatRadarEngine;
  window.threatRadarEngine = new ThreatRadarEngine();

})(window);