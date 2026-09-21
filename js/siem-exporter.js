/**
 * IT SERVICIOS DE VENEZUELA, S.A.
 * Motor Exportador SIEM (CEF / Elastic ECS) & Despachador Webhooks (Teams / Slack)
 * Versión Enterprise v290.0
 */

(function(window) {
  'use strict';

  class SiemExporterEngine {
    constructor() {}

    /**
     * Exporta logs de incidentes en formato CEF (Common Event Format para Splunk / ArcSight / QRadar)
     */
    generateCef(logs = [], activeClient = null) {
      const clientName = activeClient ? activeClient.name : 'Entrust';
      let cefContent = '';

      logs.forEach(l => {
        const dateStr = l.timestamp || new Date().toISOString();
        const sev = l.level === 'CRITICAL' ? '10' : (l.level === 'ERROR' ? '7' : (l.level === 'WARN' ? '4' : '1'));
        const code = l.entrustCode || 'GENERIC';
        const msg = (l.message || '').replace(/\|/g, '\\|');
        const user = l.user || l.userId || 'unknown';
        const ip = l.ip || '10.16.13.175';

        cefContent += `CEF:0|Entrust|IdentityGuard|13.0|${code}|${code}|${sev}|src=${ip} suser=${user} cs1Label=Client cs1=${clientName} msg=${msg} rt=${dateStr}\n`;
      });

      return cefContent;
    }

    /**
     * Exporta logs de incidentes en formato Elastic Common Schema (JSON ECS)
     */
    generateEcsJson(logs = [], activeClient = null) {
      const clientName = activeClient ? activeClient.name : 'Entrust';
      const ecsEvents = logs.map((l, idx) => ({
        '@timestamp': l.timestamp || new Date().toISOString(),
        'ecs.version': '8.11.0',
        'event': {
          'id': `EVT-${idx+1}`,
          'kind': 'alert',
          'category': ['authentication', 'identity'],
          'action': l.entrustCode || 'auth_check',
          'severity': l.level === 'CRITICAL' ? 100 : (l.level === 'ERROR' ? 70 : 30)
        },
        'service': {
          'name': 'Entrust IdentityGuard',
          'version': activeClient ? activeClient.version : '13.0'
        },
        'user': {
          'name': l.user || l.userId || 'system'
        },
        'source': {
          'ip': l.ip || '10.16.13.175'
        },
        'organization': {
          'name': clientName
        },
        'message': l.message || l.raw || ''
      }));

      return JSON.stringify(ecsEvents, null, 2);
    }

    downloadSiem(type = 'cef', logs = [], activeClient = null) {
      const isCef = type === 'cef';
      const content = isCef ? this.generateCef(logs, activeClient) : this.generateEcsJson(logs, activeClient);
      const ext = isCef ? 'cef' : 'json';
      const mime = isCef ? 'text/plain' : 'application/json';
      const clientSanitized = (activeClient ? activeClient.name : 'general').replace(/[^a-zA-Z0-9]/g, '_');
      const filename = `siem_${type}_entrust_${clientSanitized}_${new Date().toISOString().slice(0,10)}.${ext}`;

      const blob = new Blob([content], { type: `${mime};charset=utf-8;` });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    }
  }

  window.SiemExporterEngine = SiemExporterEngine;
  window.siemExporterEngine = new SiemExporterEngine();
})(window);
