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

    _parseToMap(lines) {
      const map = new Map();
      lines.forEach((line, idx) => {
        const clean = line.trim();
        if (!clean || clean.startsWith('#') || clean.startsWith('//') || clean.startsWith('<!--')) return;
        
        // Properties format: key = value
        if (clean.includes('=')) {
          const parts = clean.split('=');
          const k = parts[0].trim();
          const v = parts.slice(1).join('=').trim();
          map.set(k, v);
        }
        // XML attribute format: <property name="foo" value="bar"/>
        else if (clean.includes('name=') && clean.includes('value=')) {
          const nameMatch = clean.match(/name=["']([^"']+)["']/);
          const valMatch = clean.match(/value=["']([^"']+)["']/);
          if (nameMatch && valMatch) {
            map.set(nameMatch[1], valMatch[1]);
          }
        }
      });
      return map;
    }
  }

  window.ConfigDiffEngine = ConfigDiffEngine;
  window.configDiffEngine = new ConfigDiffEngine();
})(window);
