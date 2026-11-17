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
 * Entrust Forensics Copilot Engine v3.0 (KB + Manuales Oficiales + Datos Reales)
 * 100% determinístico, sin alucinaciones: fundamentado en logs cargados, KB y WebHelp v11/v12/v13/IDaaS.
 */
(function(window) {
  'use strict';

  class CopilotEngine {
    constructor() {
      this.chatHistory = [];
      this.manualsCache = new Map();
    }

    _getLiveContext(appState = {}) {
      const logs = appState.logs || [];
      const files = appState.loadedFiles || [];
      const gsm = appState.globalStreamMetrics || null;
      const client = (appState.clientProfiles || []).find(c => c.id === appState.activeClientId) || {
        name: 'Entrust General',
        platform: 'Entrust IdentityGuard OnPremise',
        version: 'Release 13.0'
      };

      const cm = (typeof window.getConsolidatedMetricsGlobal === 'function') ? window.getConsolidatedMetricsGlobal() : null;

      let totalLogs = cm ? cm.totalLogs : (gsm ? (gsm.totalLogs || 0) : 0);
      let totalErrors = cm ? cm.totalErrors : (gsm ? (gsm.totalErrors || 0) : 0);
      let totalWarnings = cm ? cm.totalWarnings : (gsm ? (gsm.totalWarnings || 0) : 0);

      if (!cm && !gsm && files.length > 0) {
        files.forEach(f => {
          totalLogs += Number(f.count || f.linesProcessed || 0);
          totalErrors += Number(f.realErrors || f.errors || 0);
          totalWarnings += Number(f.realWarnings || f.warnings || 0);
        });
      }
      if (totalLogs === 0) totalLogs = logs.length;

      // Consolidar mapa real de códigos desde getConsolidatedMetricsGlobal() o globalStreamMetrics
      const codeCounts = new Map();
      if (cm) {
        [cm.codeMap520, cm.codeMapAud, cm.codeMapOra, cm.codeMapIdaas, cm.codeMapOther].forEach(mapObj => {
          if (!mapObj) return;
          Object.entries(mapObj).forEach(([k, v]) => {
            if (k) codeCounts.set(String(k), (codeCounts.get(String(k)) || 0) + Number(v || 0));
          });
        });
      } else if (gsm && Array.isArray(gsm.topCodes)) {
        gsm.topCodes.forEach(tc => {
          if (tc && tc.code) codeCounts.set(String(tc.code), Number(tc.count || 0));
        });
      }
      if (codeCounts.size === 0 && logs.length > 0) {
        logs.forEach(l => {
          const rawText = (l.message || '') + ' ' + (l.raw || '');
          const c = l.entrustCode || (window.knowledgeBaseEngine ? window.knowledgeBaseEngine.extractErrorCodeFromText(rawText) : null);
          if (c) codeCounts.set(c, (codeCounts.get(c) || 0) + 1);
        });
      }

      let sum520 = 0, sumOra = 0, sumAudCrit = 0, sumAudWarn = 0, sumAudAll = 0;
      codeCounts.forEach((cnt, code) => {
        if (/^520\d{4}/i.test(code)) sum520 += cnt;
        else if (/^ORA-\d+/i.test(code)) sumOra += cnt;
        else if (/^AUD/i.test(code)) {
          sumAudAll += cnt;
          if (/^AUD150|^AUD154/i.test(code)) sumAudCrit += cnt;
          if (/^AUD6001|^AUD6002|^AUD2309|^AUD155/i.test(code)) sumAudWarn += cnt;
        }
      });

      const levelErrors = logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length;
      const levelWarnings = logs.filter(l => l.level === 'WARN').length;
      totalErrors = Math.max(totalErrors, levelErrors, sum520 + sumOra + sumAudCrit);
      totalWarnings = Math.max(totalWarnings, levelWarnings, sumAudWarn);

      const healthPct = totalLogs > 0
        ? parseFloat((((totalLogs - totalErrors) / totalLogs) * 100).toFixed(2))
        : 100;

      // Censo de usuarios + salud BD
      if (window.UserTraceReport && logs.length > 0 && Object.keys(window.UserTraceReport.cachedStats || {}).length === 0) {
        try { window.UserTraceReport.buildUserStats(); } catch (e) {}
      }
      const userStats = window.UserTraceReport ? Object.values(window.UserTraceReport.cachedStats || {}) : [];
      const dbFallback = window.UserTraceReport ? window.UserTraceReport.buildLocalForensicFallback() : { dbHealth: { status: 'HEALTHY', totalDbIncidents: 0, indicators: [] }, codeMatrix: [] };

      const sortedCodes = Array.from(codeCounts.entries()).sort((a, b) => b[1] - a[1]);

      return {
        client,
        logs,
        files,
        totalLogs,
        totalErrors,
        totalWarnings,
        healthPct,
        codeCounts,
        sortedCodes,
        sum520,
        sumOra,
        sumAudAll,
        userStats,
        dbHealth: dbFallback.dbHealth || { status: 'HEALTHY', totalDbIncidents: 0, indicators: [] },
        codeMatrix: dbFallback.codeMatrix || [],
        clientConfig: appState.activeClientConfig || null
      };
    }

    async _searchManualsServer(query, limit = 4) {
      const key = `${query}::${limit}`;
      if (this.manualsCache.has(key)) return this.manualsCache.get(key);
      if (typeof window === 'undefined' || window.location.protocol === 'file:') return [];
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 2200);
        const res = await fetch(`/api/manuals-search?q=${encodeURIComponent(query)}&limit=${limit}`, { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) return [];
        const data = await res.json();
        const list = Array.isArray(data.results) ? data.results : [];
        this.manualsCache.set(key, list);
        return list;
      } catch (e) {
        return [];
      }
    }

    _formatKbMatches(kbMatches, ctx) {
      if (!kbMatches || kbMatches.length === 0) return '';
      return kbMatches.slice(0, 3).map((m, idx) => {
        const occ = ctx.codeCounts.get(m.code) || 0;
        const occBadge = occ > 0
          ? ` — **Detectado en tus logs: ${occ.toLocaleString()} veces**`
          : ' — *(0 ocurrencias en la muestra actual)*';
        const matrixEntry = (ctx.codeMatrix || []).find(cm => cm.code === m.code);
        const usersLine = (matrixEntry && matrixEntry.users && matrixEntry.users.length > 0)
          ? `\n• **Usuarios afectados en sesión:** ${matrixEntry.users.slice(0, 5).map(u => `\`${u.user}\` (${u.count}x)`).join(', ')}`
          : '';
        return (
          `### ${idx + 1}. \`[${m.code}]\` ${m.title}${occBadge}\n` +
          `• **Categoría / Severidad:** ${m.category} (\`${m.severity}\`)\n` +
          `• **Significado Técnico:** ${m.meaning}\n` +
          `• **Causa Raíz:** ${m.rootCause}${usersLine}\n` +
          `• **Solución / Remediación:**\n${m.remediation}`
        );
      }).join('\n\n---\n\n');
    }

    _formatManualCitations(manualResults) {
      if (!manualResults || manualResults.length === 0) return '';
      const lines = manualResults.slice(0, 3).map(r =>
        `• **[${r.version}] ${r.title}**\n  _${r.snippet}_`
      ).join('\n');
      return `\n\n---\n\n### 📚 Referencias en Manuales Oficiales\n${lines}`;
    }

    async askAsync(query, appState = {}) {
      const qRaw = (query || '').trim();
      const q = qRaw.toLowerCase();
      const ctx = this._getLiveContext(appState);

      // Extraer códigos específicos mencionados en la pregunta
      const mentionedCodes = qRaw.match(/(?:520\d{4}|AUD\d+|ORA-\d+|S3-404)/gi) || [];
      const kbMatches = window.knowledgeBaseEngine ? window.knowledgeBaseEngine.searchKnowledgeBase(qRaw, 4) : [];
      const manualResults = await this._searchManualsServer(qRaw, 4);

      let answer = '';
      let suggestedQueries = [];
      let action = null;

      // 0. Generación de Informes Directa desde Entrust Forensics AI
      if (/generar\s+informe|emitir\s+informe|crear\s+informe|abrir\s+informe|exportar\s+errores/i.test(q)) {
        if (ctx.totalLogs === 0) {
          answer = `⚠️ No hay registros cargados todavía para **${ctx.client.name}**. Carga primero tus archivos de logs en el **Analizador** para generar el dictamen.`;
        } else if (q.includes('csv') || q.includes('exportar errores')) {
          action = { type: 'export_errors_csv' };
          answer = `📥 **Exportando CSV de Errores y Alertas para ${ctx.client.name}**\n\n• Eventos consolidados: \`${ctx.totalLogs.toLocaleString()}\`\n• Fallos críticos: \`${ctx.totalErrors.toLocaleString()}\` • Alertas AUD: \`${ctx.totalWarnings.toLocaleString()}\`\n\nDescarga iniciada automáticamente.`;
        } else if (q.includes('usuario') || q.includes('censo')) {
          action = { type: 'exec_report', view: 'users', onlyCatalog: false };
          answer = `👤 **Generando Informe de Censo y Trazas de Usuario para ${ctx.client.name}**\n\n• Usuarios nominales validados: \`${ctx.userStats.length}\`\n• Eventos totales: \`${ctx.totalLogs.toLocaleString()}\`\n\nSe ha abierto el informe enfocado en usuarios.`;
        } else if (q.includes('base de datos') || q.includes('oracle') || q.includes('bd')) {
          action = { type: 'exec_report', view: 'db', onlyCatalog: false };
          answer = `🗄️ **Generando Informe de Salud de Base de Datos para ${ctx.client.name}**\n\n• Incidentes ORA/JDBC detectados: \`${ctx.dbHealth.totalDbIncidents || 0}\`\n• Estado: **${ctx.dbHealth.totalDbIncidents === 0 ? 'SALUDABLE' : 'REQUIERE ATENCIÓN'}**\n\nSe ha abierto la vista de Base de Datos del dictamen.`;
        } else if (q.includes('520') || q.includes('catalogo') || q.includes('solo errores')) {
          action = { type: 'exec_report', view: 'full', onlyCatalog: true };
          answer = `🚨 **Generando Dictamen Exclusivo de Errores Críticos (520xxx / AUD / ORA) para ${ctx.client.name}**\n\n• Fallos críticos: \`${ctx.totalErrors.toLocaleString()}\` (\`${ctx.sum520.toLocaleString()}\` de familia \`520xxx\`).\n\nSe ha abierto el dictamen filtrado.`;
        } else {
          action = { type: 'exec_report', view: 'full', onlyCatalog: false };
          answer = `📄 **Generando Informe Ejecutivo Forense Completo para ${ctx.client.name}**\n\n• **Muestra:** \`${ctx.totalLogs.toLocaleString()}\` eventos en \`${ctx.files.length || 1}\` archivo(s) rotado(s).\n• **Salud:** **${ctx.healthPct}%** | **Errores Críticos:** \`${ctx.totalErrors.toLocaleString()}\`\n\nEl dictamen de 8 secciones ya está abierto en pantalla listo para PDF/Impresión.`;
        }
        suggestedQueries = ['resumen operativo', 'top errores', 'plan de remediacion'];
      }
      // 0.5 Consulta sobre Configuración Real del Cliente (identityguard.properties / server.xml / web.xml / entrusttoken.conf)
      else if (q.includes('config') || q.includes('properties') || q.includes('server.xml') || q.includes('web.xml') || q.includes('entrusttoken') || q.includes('jdbc') || q.includes('maxthreads') || q.includes('keystore')) {
        const cfg = ctx.clientConfig;
        if (cfg && cfg.files && cfg.files.length > 0) {
          const jdbc = cfg.jdbc || {};
          const tok = cfg.token || {};
          const web = cfg.web || {};
          const conns = (cfg.tomcatConnectors || []).map(c => `  • **${c.service || 'Connector'}** puerto \`${c.port}\` — \`maxThreads=${c.maxThreads || '-'}\`, \`acceptCount=${c.acceptCount || '-'}\`, \`clientAuth=${c.clientAuth || 'false'}\`${c.keystoreFile ? `, keystore: \`${c.keystoreFile}\`` : ''}`).join('\n') || '  • Sin conectores Tomcat registrados.';
          answer = `⚙️ **Configuración Real de Plataforma — ${ctx.client.name}** *(extraída de \`${cfg.files.join(', ')}\`)*:\n\n` +
                   `• **Base de Datos JDBC:** \`${jdbc.type || 'N/A'}\` | Usuario: \`${jdbc.user || 'N/A'}\` | Schema: \`${jdbc.schema || 'N/A'}\`\n` +
                   `• **JDBC URL:** \`${jdbc.url || 'N/A'}\`\n` +
                   `• **Admin URL:** \`${(cfg.urls && cfg.urls.webadmin) || 'N/A'}\`\n` +
                   `• **Auth HTTPS URL:** \`${(cfg.urls && cfg.urls.authHttps) || 'N/A'}\`\n` +
                   `• **Tokens (` + '`entrusttoken.conf`' + `):** \`resetEventWindow=${tok.resetEventWindow || '-'}\`, \`maxTimeSteps=${tok.maxTimeSteps || '-'}\`\n` +
                   `• **Session Timeout (` + '`web.xml`' + `):** \`${web.sessionTimeout || 'N/A'} min\`\n\n` +
                   `**Conectores Tomcat (` + '`server.xml`' + `):**\n${conns}`;
        } else {
          answer = `⚙️ No hay archivos de configuración cargados aún para **${ctx.client.name}**.\n\nPara consultar su arquitectura real sin inventar datos, abre **+ Cliente** en la barra superior y sube sus archivos \`identityguard.properties\`, \`server.xml\`, \`web.xml\` o \`entrusttoken.conf\`.`;
        }
        suggestedQueries = ['resumen operativo', 'base de datos oracle', 'generar informe ejecutivo'];
      }
      // 1. Consulta específica de código de error (ej: "520002", "AUD6001", "ORA-01555")
      else if (mentionedCodes.length > 0) {
        if (kbMatches.length > 0) {
          answer = `🔎 **Diagnóstico Pericial de Base de Conocimiento para \`${mentionedCodes.join(', ').toUpperCase()}\`**:\n\n` +
                   this._formatKbMatches(kbMatches, ctx) +
                   this._formatManualCitations(manualResults);
        } else if (manualResults.length > 0) {
          answer = `📚 **Resultados en Manuales Oficiales para \`${mentionedCodes.join(', ').toUpperCase()}\`**:` +
                   this._formatManualCitations(manualResults);
        } else {
          answer = `⚠️ No encontré el código \`${mentionedCodes.join(', ').toUpperCase()}\` en el catálogo actual ni en los manuales indexados. Verifica el número exacto o pega la línea completa del log para analizarla.`;
        }
        suggestedQueries = ['top errores', 'plan de remediacion', 'resumen operativo'];
      }
      // 2. Pregunta sobre archivos cargados y rotación de logs
      else if (q.includes('archivo') || q.includes('rotacion') || q.includes('fuente') || q.includes('.log')) {
        if (ctx.files.length > 0) {
          const filesLines = ctx.files.slice(0, 12).map((f, i) => {
            const errs = Number(f.realErrors || f.errors || 0);
            const lines = Number(f.count || f.linesProcessed || 0);
            return `  ${i + 1}. \`${f.name}\` — **${lines.toLocaleString()}** eventos${errs > 0 ? ` (\`🚨 ${errs.toLocaleString()} errores\`)` : ' (✅ nominal)'}`;
          }).join('\n');
          const more = ctx.files.length > 12 ? `\n  ... y ${ctx.files.length - 12} archivo(s) adicional(es).` : '';
          answer = `📑 **Inventario de Fuentes & Archivos Rotados (${ctx.files.length} archivos | ${ctx.totalLogs.toLocaleString()} eventos)**:\n\n${filesLines}${more}\n\n` +
                   `💡 Puedes ver la tabla completa por capa (SAM / Core / Audit) en la pestaña **Fuentes & Rotaciones** o en la **Sección 2** del Informe Ejecutivo.`;
        } else {
          answer = `📑 No hay archivos cargados en la sesión actual. Carga tus logs rotados desde el botón de ingesta para analizarlos.`;
        }
        suggestedQueries = ['resumen operativo', 'top errores', 'usuarios afectados'];
      }
      // 3. Resumen operativo / estado / salud
      else if (q.includes('resumen') || q.includes('diagnostico') || q.includes('estado') || q.includes('salud') || q.includes('como esta') || q.includes('veredicto')) {
        const top3 = ctx.sortedCodes.slice(0, 3).map(([c, n], i) => `  ${i + 1}. \`${c}\`: **${n.toLocaleString()}** eventos`).join('\n') || '  • Sin códigos anómalos detectados.';
        const lockedCount = ctx.userStats.filter(u => u.isLocked).length;
        answer = `📊 **Dictamen Operativo en Vivo — ${ctx.client.name}**\n\n` +
                 `• **Muestra Auditada:** \`${ctx.totalLogs.toLocaleString()}\` eventos en \`${ctx.files.length || 1}\` archivo(s) rotado(s).\n` +
                 `• **Índice de Salud:** **${ctx.healthPct}%**\n` +
                 `• **Fallos Críticos (520xxx / ORA / Proxy):** \`${ctx.totalErrors.toLocaleString()}\` (de los cuales \`${ctx.sum520.toLocaleString()}\` son \`520xxx\`)\n` +
                 `• **Eventos de Auditoría (AUDxxx):** \`${ctx.sumAudAll.toLocaleString()}\` | **Alertas:** \`${ctx.totalWarnings.toLocaleString()}\`\n` +
                 `• **Base de Datos Oracle/JDBC:** ${ctx.dbHealth.totalDbIncidents === 0 ? '✅ Saludable (0 errores ORA/JDBC)' : `🚨 ${ctx.dbHealth.totalDbIncidents} incidentes`}\n` +
                 `• **Usuarios Nominales:** \`${ctx.userStats.length}\` auditados (${lockedCount} bloqueados)\n\n` +
                 `**Top 3 Códigos por Frecuencia:**\n${top3}`;
        suggestedQueries = ['plan de remediacion', 'archivos rotados', 'usuarios afectados'];
      }
      // 4. Usuarios, cuentas bloqueadas o fuerza bruta
      else if (q.includes('usuario') || q.includes('cuenta') || q.includes('cedula') || q.includes('fuerza bruta') || q.includes('bloque')) {
        const errUsers = ctx.userStats.filter(u => u.errors > 0 || u.isLocked).sort((a, b) => b.errors - a.errors);
        const threatReport = window.threatRadarEngine ? window.threatRadarEngine.analyzeThreats(ctx.logs) : null;
        if (errUsers.length > 0) {
          const topList = errUsers.slice(0, 6).map((u, i) =>
            `  ${i + 1}. \`${u.username}\` — **${u.errors}** fallos / ${u.totalEvents} txs (${u.isLocked ? '🔒 Bloqueada' : '⚠️ Con fricción'})`
          ).join('\n');
          answer = `👤 **Censo de Usuarios con Incidencias (${errUsers.length} de ${ctx.userStats.length} cuentas nominales)**:\n\n${topList}\n\n` +
                   `💡 **Acción recomendada:** Auditar estas cuentas en la consola de Entrust / AD y revisar su secuencia \`Solicitud 1 ➔ Solicitud N\` en la pestaña **Censo & Trazas de Usuario**.`;
        } else if (threatReport && threatReport.topTargetUsers.length > 0) {
          const topList = threatReport.topTargetUsers.slice(0, 5).map((u, i) => `  ${i + 1}. \`${u.user}\`: ${u.attempts} intentos`).join('\n');
          answer = `🎯 **Cuentas con Intentos Denegados:**\n\n${topList}`;
        } else {
          answer = `✅ No se registran usuarios nominales bloqueados ni con fallos reiterados en la muestra actual (${ctx.userStats.length} usuarios auditados).`;
        }
        suggestedQueries = ['AUD6001', 'resumen operativo', 'plan de remediacion'];
      }
      // 5. Base de datos Oracle / JDBC
      else if (q.includes('base de datos') || q.includes('oracle') || q.includes('jdbc') || q.includes('undo') || q.includes('blob') || q.includes('ora')) {
        const dbInc = ctx.dbHealth.totalDbIncidents || 0;
        const inds = (ctx.dbHealth.indicators || []).slice(0, 5).map(ind =>
          `• \`${ind.code}\`: **${ind.count}** (${ind.count === 0 ? '✅ OK' : '🚨 ' + ind.severity}) — ${ind.diagnosis}`
        ).join('\n');
        answer = `🗄️ **Salud de Persistencia & Base de Datos Oracle/JDBC**:\n\n` +
                 `• **Dictamen:** ${dbInc === 0 ? '✅ **SALUDABLE** (0 errores ORA / 0 excepciones JDBC en los archivos auditados)' : `🚨 **ALERTA** (${dbInc} incidentes de BD detectados)`}\n\n` +
                 (inds || '') +
                 this._formatManualCitations(manualResults);
        suggestedQueries = ['ORA-01555', 'resumen operativo', 'plan de remediacion'];
      }
      // 6. Top errores / códigos frecuentes
      else if (q.includes('top error') || q.includes('codigo') || q.includes('error') || q.includes('falla') || q.includes('patron')) {
        const criticalEntries = ctx.sortedCodes.filter(([c]) => /^520|^ORA|^AUD150|^AUD154|^AUD6001|^S3-404/i.test(c));
        const listSource = criticalEntries.length > 0 ? criticalEntries : ctx.sortedCodes;
        if (listSource.length > 0) {
          const list = listSource.slice(0, 6).map(([code, count], i) => {
            const diag = window.knowledgeBaseEngine ? window.knowledgeBaseEngine.diagnoseLog(code, code) : {};
            const title = diag.title || 'Evento registrado';
            return `  ${i + 1}. \`${code}\` (**${count.toLocaleString()}** veces) — ${title}`;
          }).join('\n');
          answer = `🚨 **Ranking Real de Códigos en la Muestra (${ctx.totalLogs.toLocaleString()} eventos)**:\n\n${list}\n\n` +
                   `💡 Escribe cualquier código (ej: *"${listSource[0][0]}"*) para ver su **causa raíz exacta y pasos de solución**.`;
        } else {
          answer = `✅ No se han detectado códigos de error crítico en la muestra actual.`;
        }
        suggestedQueries = listSource.slice(0, 2).map(([c]) => `como resolver ${c}`).concat(['plan de remediacion']);
      }
      // 7. Remediación / qué hacer / soluciones
      else if (q.includes('remedi') || q.includes('solucion') || q.includes('que hago') || q.includes('paso') || q.includes('mitig') || q.includes('plan') || q.includes('corregir')) {
        if (kbMatches.length > 0 && q.split(/\s+/).length > 2) {
          answer = `🛠️ **Procedimiento de Remediación (Base de Conocimiento + Manuales)**:\n\n` +
                   this._formatKbMatches(kbMatches, ctx) +
                   this._formatManualCitations(manualResults);
        } else {
          const topCrit = ctx.sortedCodes.filter(([c]) => /^520|^ORA|^AUD150|^AUD154|^AUD6001/i.test(c)).slice(0, 3);
          const steps = topCrit.map(([code, cnt], idx) => {
            const d = window.knowledgeBaseEngine ? window.knowledgeBaseEngine.diagnoseLog(code, code) : {};
            return `**${idx + 1}. Atender \`${code}\` (${cnt.toLocaleString()} eventos):**\n${d.remediation || 'Revisar trazas del subsistema afectado y validar conectividad con repositorio.'}`;
          }).join('\n\n');
          answer = `🛠️ **Plan de Acción Priorizado (Basado en tus Logs Reales)**:\n\n` +
                   (steps || '• Clúster sin errores críticos activos; mantener monitoreo preventivo y rotación de logs.') +
                   `\n\n• **Portal de Parches:** Verificar boletines aplicables en Entrust TrustedCare (\`trustedcare.entrust.com\`).`;
        }
        suggestedQueries = ['resumen operativo', 'base de datos', 'sla sudeban'];
      }
      // 8. SLA / Sudeban / Normativa
      else if (q.includes('sla') || q.includes('sudeban') || q.includes('normativa') || q.includes('regulatorio') || q.includes('iso')) {
        const sla = window.slaEngine ? window.slaEngine.computeSlaMetrics(ctx.totalLogs, ctx.totalErrors, ctx.totalWarnings) : null;
        if (sla) {
          answer = `⚖️ **Evaluación de Disponibilidad & Cumplimiento Sudeban / ISO 27001**:\n\n` +
                   `• **Disponibilidad Calculada:** **${sla.uptimePct}%**\n` +
                   `• **Meta Regulatoria Tier-1:** ${sla.targetSlaTier1}%\n` +
                   `• **Estatus:** **${sla.statusLabel}**\n` +
                   `• **Indisponibilidad Estimada:** ${sla.actualDowntimeMin} min`;
        } else {
          answer = `⚖️ **Disponibilidad de la muestra:** **${ctx.healthPct}%** (${ctx.totalErrors.toLocaleString()} fallos sobre ${ctx.totalLogs.toLocaleString()} eventos).`;
        }
        suggestedQueries = ['resumen operativo', 'plan de remediacion'];
      }
      // 9. Búsqueda abierta en Base de Conocimiento + Manuales Oficiales
      else {
        if (kbMatches.length > 0 || manualResults.length > 0) {
          answer = `🧠 **Consulta en Base de Conocimiento & Manuales Oficiales**:\n\n` +
                   (kbMatches.length > 0 ? this._formatKbMatches(kbMatches, ctx) : '') +
                   this._formatManualCitations(manualResults);
        } else {
          answer = `🤖 **Entrust Forensics Copilot**:\n\n` +
                   `Tengo cargados **${ctx.totalLogs.toLocaleString()}** eventos en **${ctx.files.length || 1}** archivo(s) para **${ctx.client.name}** (${ctx.totalErrors.toLocaleString()} fallos críticos).\n\n` +
                   `No encontré coincidencias exactas en KB/Manuales para *"${qRaw}"*. Prueba consultando:\n` +
                   `• Un código específico: *"520002"*, *"AUD6001"*, *"ORA-01555"*\n` +
                   `• Tópicos de manual: *"configurar LDAP"*, *"supersh"*, *"pool JDBC"*, *"migracion IDaaS"*\n` +
                   `• Diagnóstico en vivo: *"resumen operativo"*, *"archivos rotados"*, *"plan de remediacion"*`;
        }
        suggestedQueries = ['resumen operativo', 'top errores', 'archivos rotados'];
      }

      const interaction = {
        query: qRaw,
        answer,
        kbMatches,
        manualResults,
        suggestedQueries,
        action,
        timestamp: new Date().toLocaleTimeString()
      };
      this.chatHistory.push(interaction);
      return interaction;
    }

    // Compatibilidad síncrona
    ask(query, appState = {}) {
      const ctx = this._getLiveContext(appState);
      const kbMatches = window.knowledgeBaseEngine ? window.knowledgeBaseEngine.searchKnowledgeBase(query, 3) : [];
      const answer = kbMatches.length > 0
        ? this._formatKbMatches(kbMatches, ctx)
        : `Analizados ${ctx.totalLogs.toLocaleString()} eventos (${ctx.totalErrors.toLocaleString()} fallos críticos).`;
      const interaction = { query, answer, kbMatches, manualResults: [], timestamp: new Date().toLocaleTimeString() };
      this.chatHistory.push(interaction);
      return interaction;
    }
  }

  window.CopilotEngine = CopilotEngine;
  window.copilotEngine = new CopilotEngine();
})(window);
