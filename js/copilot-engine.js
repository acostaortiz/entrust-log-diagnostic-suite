/**
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Entrust Forensics Copilot Engine (Asistente Pericial en Tiempo Real)
 * Versión Enterprise v290.0
 */

(function(window) {
  'use strict';

  class CopilotEngine {
    constructor() {
      this.chatHistory = [];
    }

    ask(query, appState = {}) {
      const q = (query || '').toLowerCase().trim();
      const logs = appState.logs || [];
      const total = logs.length;
      const client = appState.clientProfiles?.find(c => c.id === appState.activeClientId) || { name: 'Entrust General' };
      
      const criticals = logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR');
      const warnings = logs.filter(l => l.level === 'WARN');
      
      let answer = '';
      let confidence = 'Alta (Calculado sobre muestra real)';

      // 1. Pregunta sobre resumen o diagnóstico general
      if (q.includes('resumen') || q.includes('diagnostico') || q.includes('estado') || q.includes('salud') || q.includes('como esta')) {
        const uptime = total > 0 ? (((total - criticals.length) / total) * 100).toFixed(2) : '100.00';
        answer = `📊 **Dictamen de Estado Operativo para ${client.name}**:\n\n` +
                 `• **Total de Transacciones**: ${total.toLocaleString()} eventos auditados.\n` +
                 `• **Incidentes Críticos**: ${criticals.length.toLocaleString()} fallos detectados (${total > 0 ? ((criticals.length/total)*100).toFixed(2) : '0'}% de la muestra).\n` +
                 `• **Índice de Estabilidad**: **${uptime}%** de operaciones completadas sin excepciones críticas.\n` +
                 `• **Veredicto Pericial**: ${criticals.length === 0 ? '🟢 Clúster en condición óptima.' : '⚠️ Se requiere ejecutar el script de Auto-Remediación en Fase I para mitigar fallos detectados.'}`;
      }
      // 2. Pregunta sobre usuarios, cuentas o fuerza bruta
      else if (q.includes('usuario') || q.includes('cuenta') || q.includes('cedula') || q.includes('fuerza bruta') || q.includes('bloque')) {
        const threatReport = window.threatRadarEngine ? window.threatRadarEngine.analyzeThreats(logs) : null;
        if (threatReport && threatReport.topTargetUsers.length > 0) {
          const topList = threatReport.topTargetUsers.slice(0, 5).map((u, i) => `  ${i+1}. **${u.user}**: ${u.attempts} intentos (${u.isLocked ? '🔴 Bloqueada' : '🟡 Activa/Riesgo'})`).join('\n');
          answer = `🎯 **Análisis de Cuentas Afectadas & Amenazas**:\n\n` +
                   `Se detectaron **${threatReport.detectedVictimsCount}** cuentas con intentos denegados en la muestra.\n` +
                   `**Top Cuentas más Atacadas**:\n${topList}\n\n` +
                   `💡 **Recomendación SOC**: Habilitar bloqueo preventivo perimetral para IPs agresoras y aplicar reseteo de credenciales en Active Directory / IDaaS.`;
        } else {
          answer = `🎯 **Threat Radar**: No se observaron patrones reiterados de fuerza bruta contra usuarios específicos en la muestra cargada.`;
        }
      }
      // 3. Pregunta sobre códigos de error más frecuentes (520xxx, ORA, AUD)
      else if (q.includes('codigo') || q.includes('error') || q.includes('520') || q.includes('falla') || q.includes('patron')) {
        const codeMap = new Map();
        criticals.forEach(l => {
          const c = l.entrustCode || 'Fallo General';
          codeMap.set(c, (codeMap.get(c) || 0) + 1);
        });
        const sortedCodes = Array.from(codeMap.entries()).sort((a,b) => b[1] - a[1]).slice(0, 5);
        if (sortedCodes.length > 0) {
          const list = sortedCodes.map(([code, count], i) => `  ${i+1}. **${code}**: ${count.toLocaleString()} eventos (${((count/criticals.length)*100).toFixed(1)}% de los fallos)`).join('\n');
          answer = `🚨 **Códigos de Error Predominantes**:\n\n${list}\n\n` +
                   `💡 Puedes consultar el procedimiento técnico exacto de cada código en la pestaña **Base de Conocimientos (KB)**.`;
        } else {
          answer = `✅ No se han detectado códigos de error crítico en la muestra actual.`;
        }
      }
      // 4. Pregunta sobre nodos y balanceo de carga
      else if (q.includes('nodo') || q.includes('servidor') || q.includes('balance') || q.includes('cluster')) {
        const nodeMap = new Map();
        logs.forEach(l => {
          const node = l.nodeName || l.node || 'Nodo Principal';
          nodeMap.set(node, (nodeMap.get(node) || 0) + 1);
        });
        const nodeList = Array.from(nodeMap.entries()).map(([node, count]) => `  • **${node}**: ${count.toLocaleString()} ops (${((count/total)*100).toFixed(1)}%)`).join('\n');
        answer = `🏢 **Distribución de Carga del Clúster**:\n\n${nodeList || 'Nodo Único Activo'}\n\n` +
                 `💡 Ver detalles completos en la pestaña **Topología Clúster** y **Comparativa Multi-Nodo**.`;
      }
      // 5. Pregunta sobre SLA y Sudeban
      else if (q.includes('sla') || q.includes('sudeban') || q.includes('normativa') || q.includes('regulatorio') || q.includes('basilea')) {
        const sla = window.slaEngine ? window.slaEngine.computeSlaMetrics(total, criticals.length, warnings.length) : {};
        answer = `⚖️ **Evaluación de Disponibilidad & SLA Sudeban**:\n\n` +
                 `• **Disponibilidad Actual**: **${sla.uptimePct}%**\n` +
                 `• **Meta Regulatoria Sudeban**: ${sla.targetSlaTier1}%\n` +
                 `• **Estatus de Conformidad**: **${sla.statusLabel}**\n` +
                 `• **Indisponibilidad Calculada**: ${sla.actualDowntimeMin} minutos (Tolerancia mensual: 21.6 min).\n` +
                 `• **Operaciones Denegadas**: ${sla.estimatedBlockedUsers.toLocaleString()} transacciones.`;
      }
      // Respuesta Inteligente General
      else {
        answer = `🤖 **Entrust Forensics Copilot**:\n\nHe analizado los **${total.toLocaleString()}** registros de **${client.name}**.\n` +
                 `Detecté **${criticals.length.toLocaleString()}** errores críticos y **${warnings.length.toLocaleString()}** eventos de auditoría.\n\n` +
                 `💡 Puedes preguntarme sobre:\n` +
                 `• *"¿Cuáles son las cuentas más atacadas?"*\n` +
                 `• *"¿Qué códigos de error tienen mayor impacto?"*\n` +
                 `• *"¿Cuál es el volumen de errores y distribución?"*\n` +
                 `• *"¿Cómo está distribuida la carga entre los servidores?"*`;
      }

      const interaction = { query, answer, timestamp: new Date().toLocaleTimeString() };
      this.chatHistory.push(interaction);
      return interaction;
    }
  }

  window.CopilotEngine = CopilotEngine;
  window.copilotEngine = new CopilotEngine();
})(window);
