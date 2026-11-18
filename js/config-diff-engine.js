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
 * Motor Comparador Forense de Configuraciones XML / Properties entre Nodos Entrust
 * Versión Enterprise v290.0
 */

(function(window) {
  'use strict';

  class ConfigDiffEngine {
    constructor() {}

    compareConfigs(textA = '', textB = '', nameA = 'Nodo 01 (Primario)', nameB = 'Nodo 02 (Secundario)') {
      const linesA = textA.split(/\r?\n/);
      const linesB = textB.split(/\r?\n/);
      
      const mapA = this._parseToMap(linesA);
      const mapB = this._parseToMap(linesB);

      const allKeys = Array.from(new Set([...mapA.keys(), ...mapB.keys()])).sort();
      const diffs = [];

      allKeys.forEach(k => {
        const valA = mapA.get(k);
        const valB = mapB.get(k);

        if (valA !== valB) {
          const isCritical = /(db|oracle|url|ldap|port|ssl|timeout|pool|memory|heap|key)/i.test(k);
          diffs.push({
            key: k,
            valA: valA !== undefined ? valA : '[NO DEFINIDO]',
            valB: valB !== undefined ? valB : '[NO DEFINIDO]',
            isCritical,
            impact: isCritical ? '🔴 Alto Riesgo de Desincronización o Fallo Transaccional' : '🟡 Diferencia Menor'
          });
        }
      });

      return {
        nameA,
        nameB,
        totalKeys: allKeys.length,
        diffsCount: diffs.length,
        criticalDiffsCount: diffs.filter(d => d.isCritical).length,
        diffs
      };
    }

    compareMultipleConfigs(nodes = []) {
      const activeNodes = (nodes || []).filter(n => n && (n.text || '').trim().length > 0);
      const targetNodes = activeNodes.length >= 2 ? activeNodes : (nodes || []);
      const maps = targetNodes.map(n => this._parseToMap((n.text || '').split(/\r?\n/)));
      const allKeysSet = new Set();
      maps.forEach(m => m.forEach((_, k) => allKeysSet.add(k)));
      const allKeys = Array.from(allKeysSet).sort();

      const diffs = [];
      allKeys.forEach(k => {
        const vals = maps.map(m => (m.has(k) ? m.get(k) : '[NO DEFINIDO]'));
        const uniqueVals = new Set(vals);
        if (uniqueVals.size > 1) {
          const isCritical = /(db|oracle|jdbc|url|ldap|port|ssl|tls|timeout|pool|maxthreads|acceptcount|memory|heap|key|clientauth|resetevent|maxtimesteps)/i.test(k);
          diffs.push({
            key: k,
            values: vals,
            isCritical,
            impact: isCritical ? '🔴 Alto Riesgo de Desincronización o Fallo Transaccional' : '🟡 Diferencia Menor'
          });
        }
      });

      return {
        names: targetNodes.map(n => n.name || 'Servidor'),
        totalKeys: allKeys.length,
        diffsCount: diffs.length,
        criticalDiffsCount: diffs.filter(d => d.isCritical).length,
        diffs
      };
    }

    _parseToMap(lines) {
      const map = new Map();
      const fullText = lines.join('\n');

      // Parse XML <Connector ...> attributes cleanly
      const connMatches = fullText.match(/<Connector\b[^>]*>/gi) || [];
      connMatches.forEach((tag, cIdx) => {
        const portM = tag.match(/\bport=["']([^"']+)["']/i);
        const prefix = `Connector[${portM ? portM[1] : (cIdx + 1)}]`;
        const attrRe = /([a-zA-Z0-9_:-]+)=["']([^"']*)["']/g;
        let m;
        while ((m = attrRe.exec(tag)) !== null) {
          const ak = m[1];
          let av = m[2];
          if (/pass|secret/i.test(ak)) av = '***REDACTED***';
          map.set(`${prefix}.${ak}`, av);
        }
      });

      const sessMatch = fullText.match(/<session-timeout>\s*([^<\s]+)\s*<\/session-timeout>/i);
      if (sessMatch) map.set('web.xml.session-timeout', sessMatch[1]);

      lines.forEach((line) => {
        const clean = line.trim();
        if (!clean || clean.startsWith('#') || clean.startsWith('//') || clean.startsWith('<!--') || clean.startsWith('<')) return;

        // Properties / conf format: key = value
        if (clean.includes('=')) {
          const eqIdx = clean.indexOf('=');
          const k = clean.slice(0, eqIdx).trim();
          let v = clean.slice(eqIdx + 1).trim();
          if (/password|passwd|secret|passphrase|pin/i.test(k)) v = '***REDACTED***';
          if (k) map.set(k, v);
        }
      });
      return map;
    }
  }

  window.ConfigDiffEngine = ConfigDiffEngine;
  window.configDiffEngine = new ConfigDiffEngine();
})(window);
