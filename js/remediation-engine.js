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
 * Motor Generador de Scripts de Auto-Remediación (.BAT / .SH)
 * Versión Enterprise v260.0
 */

(function(window) {
  'use strict';

  class RemediationEngine {
    constructor() {}

    /**
     * Genera resumen telemétrico real de fallos para contextualizar los scripts
     */
    _collectTelemetrySummary(logs = []) {
      const m = (typeof window !== 'undefined' && typeof window.getConsolidatedMetricsGlobal === 'function')
        ? window.getConsolidatedMetricsGlobal()
        : null;
      const totalEvents = m ? Number(m.totalLogs || 0) : (logs ? logs.length : 0);
      const totalErrors = m ? Number(m.totalErrors || 0) : (logs ? logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length : 0);
      const count520 = m ? Object.values(m.codeMap520 || {}).reduce((a, b) => a + b, 0) : 0;
      const countTomcat = m ? Object.values(m.codeMapTomcat || {}).reduce((a, b) => a + b, 0) : 0;
      const countOra = m ? Object.values(m.codeMapOra || {}).reduce((a, b) => a + b, 0) : 0;
      const countIdaas = m ? Object.values(m.codeMapIdaas || {}).reduce((a, b) => a + b, 0) : 0;
      return { totalEvents, totalErrors, count520, countTomcat, countOra, countIdaas };
    }

    /**
     * Genera el script de remediación en formato Batch para Windows Server
     */
    generateWindowsBat(logs = [], activeClient = null) {
      const clientName = activeClient ? activeClient.name : 'Entrust General';
      const clientPlatform = activeClient ? (activeClient.platform || 'Entrust IdentityGuard OnPremise') : 'Entrust IdentityGuard OnPremise';
      const clientVer = activeClient ? (activeClient.version || 'Release 12.0') : 'Release 12.0';
      const stats = this._collectTelemetrySummary(logs);
      const dateStr = new Date().toISOString().slice(0, 10);

      let bat = `@echo off\n`;
      bat += `REM ====================================================================\n`;
      bat += `REM IT SERVICIOS DE VENEZUELA, S.A. | SCRIPT DE AUTO-REMEDIACION ENTRUST\n`;
      bat += `REM Cliente: ${clientName} | Plataforma: ${clientPlatform} (${clientVer})\n`;
      bat += `REM Muestra Auditada: ${stats.totalEvents.toLocaleString()} eventos | Fallos: ${stats.totalErrors.toLocaleString()} (520xxx=${stats.count520.toLocaleString()}, Tomcat=${stats.countTomcat.toLocaleString()}, ORA=${stats.countOra.toLocaleString()})\n`;
      bat += `REM Fecha de Generacion: ${dateStr}\n`;
      bat += `REM ====================================================================\n\n`;

      bat += `echo [1/4] Verificando estado de los servicios Entrust IdentityGuard...\n`;
      bat += `sc query "Entrust IdentityGuard Administration Service"\n`;
      bat += `sc query "Entrust IdentityGuard Authentication Service"\n\n`;

      bat += `echo [2/4] Verificando almacen de certificados keystore...\n`;
      bat += `keytool -list -v -keystore "C:\\Program Files\\Entrust\\IdentityGuardServer\\identityguard.keystore" -storepass changeit\n\n`;

      bat += `echo [3/4] Comprobando conectividad y puertos locales 8443 / 8445...\n`;
      bat += `netstat -ano | findstr /R ":8443 :8445"\n\n`;

      bat += `echo [4/4] Diagnostico preventivo y reinicio controlado de servicios...\n`;
      if (stats.countTomcat > 0) {
        bat += `echo [!] Se detectaron ${stats.countTomcat.toLocaleString()} eventos Tomcat/JVM; revise catalina.out antes de reiniciar.\n`;
      }
      bat += `echo Desea reiniciar los servicios ahora? (Presione Ctrl+C para cancelar)\n`;
      bat += `pause\n`;
      bat += `net stop "Entrust IdentityGuard Administration Service"\n`;
      bat += `timeout /t 5\n`;
      bat += `net start "Entrust IdentityGuard Administration Service"\n\n`;

      bat += `echo [OK] Remediacion finalizada con exito.\n`;
      bat += `pause\n`;

      return bat;
    }

    /**
     * Genera el script de remediación en formato Shell para Linux / Ubuntu Server
     */
    generateLinuxSh(logs = [], activeClient = null) {
      const clientName = activeClient ? activeClient.name : 'Entrust General';
      const clientPlatform = activeClient ? (activeClient.platform || 'Entrust IdentityGuard OnPremise') : 'Entrust IdentityGuard OnPremise';
      const clientVer = activeClient ? (activeClient.version || 'Release 12.0') : 'Release 12.0';
      const stats = this._collectTelemetrySummary(logs);
      const dateStr = new Date().toISOString().slice(0, 10);

      let sh = `#!/bin/bash\n`;
      sh += `# ====================================================================\n`;
      sh += `# IT SERVICIOS DE VENEZUELA, S.A. | SCRIPT DE AUTO-REMEDIACION ENTRUST\n`;
      sh += `# Cliente: ${clientName} | Plataforma: ${clientPlatform} (${clientVer})\n`;
      sh += `# Muestra Auditada: ${stats.totalEvents.toLocaleString()} eventos | Fallos: ${stats.totalErrors.toLocaleString()} (520xxx=${stats.count520.toLocaleString()}, Tomcat=${stats.countTomcat.toLocaleString()}, ORA=${stats.countOra.toLocaleString()})\n`;
      sh += `# Fecha de Generacion: ${dateStr}\n`;
      sh += `# ====================================================================\n\n`;

      sh += `echo "=== [1/4] Inspeccionando estado de servicios Entrust / Tomcat ==="\n`;
      sh += `systemctl status entrust-identityguard-admin --no-pager || systemctl status tomcat9 --no-pager || ps -ef | grep -i identityguard\n\n`;

      sh += `echo "=== [2/4] Verificando memoria JVM, flags Heap y pool Tomcat ==="\n`;
      sh += `ps aux | grep -iE "identityguard|catalina" | grep -E "Xms|Xmx|java" || true\n\n`;

      sh += `echo "=== [3/4] Inspeccionando logs recientes de Core / Tomcat (catalina.out) ==="\n`;
      sh += `tail -n 50 /opt/entrust/ig/*/logs/catalina.out 2>/dev/null || echo "Ajuste ruta catalina.out del nodo"\n\n`;

      sh += `echo "=== [4/4] Verificando puertos activos 8443 / 8445 / LDAP 636 ==="\n`;
      sh += `ss -tuln 2>/dev/null | grep -E "8443|8445|636|1521" || netstat -tuln | grep -E "8443|8445|636|1521"\n\n`;

      sh += `echo "=== [OK] Diagnostico y verificacion completados satisfactoriamente ==="\n`;

      return sh;
    }

    downloadScript(type = 'bat', logs = [], activeClient = null) {
      const isBat = type === 'bat';
      const content = isBat ? this.generateWindowsBat(logs, activeClient) : this.generateLinuxSh(logs, activeClient);
      const ext = isBat ? 'bat' : 'sh';
      const mime = isBat ? 'application/x-bat' : 'application/x-sh';
      const filename = `remediacion_entrust_${(activeClient ? activeClient.name : 'general').replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().slice(0,10)}.${ext}`;

      const blob = new Blob([content], { type: mime });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    }
  }

  window.RemediationEngine = RemediationEngine;
  window.remediationEngine = new RemediationEngine();

})(window);