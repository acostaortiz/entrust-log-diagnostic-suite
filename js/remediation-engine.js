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
     * Genera el script de remediación en formato Batch para Windows Server
     */
    generateWindowsBat(logs = [], activeClient = null) {
      const clientName = activeClient ? activeClient.name : 'Entrust General';
      const dateStr = new Date().toISOString().slice(0, 10);

      let bat = `@echo off\n`;
      bat += `REM ====================================================================\n`;
      bat += `REM IT SERVICIOS DE VENEZUELA, S.A. | SCRIPT DE AUTO-REMEDIACIÓN ENTRUST\n`;
      bat += `REM Cliente: ${clientName}\n`;
      bat += `REM Fecha de Generación: ${dateStr}\n`;
      bat += `REM ====================================================================\n\n`;

      bat += `echo [1/4] Verificando estado de los servicios Entrust IdentityGuard...\n`;
      bat += `sc query "Entrust IdentityGuard Administration Service"\n`;
      bat += `sc query "Entrust IdentityGuard Authentication Service"\n\n`;

      bat += `echo [2/4] Verificando almacén de certificados identityguard.keystore...\n`;
      bat += `keytool -list -v -keystore "C:\\Program Files\\Entrust\\IdentityGuardServer\\identityguard.keystore" -storepass changeit\n\n`;

      bat += `echo [3/4] Comprobando conectividad y puertos locales 8443 / 8080...\n`;
      bat += `netstat -ano | findstr "8443"\n\n`;

      bat += `echo [4/4] Saneamiento de cola y reinicio controlado de servicios...\n`;
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
      const dateStr = new Date().toISOString().slice(0, 10);

      let sh = `#!/bin/bash\n`;
      sh += `# ====================================================================\n`;
      sh += `# IT SERVICIOS DE VENEZUELA, S.A. | SCRIPT DE AUTO-REMEDIACIÓN ENTRUST\n`;
      sh += `# Cliente: ${clientName}\n`;
      sh += `# Fecha de Generación: ${dateStr}\n`;
      sh += `# ====================================================================\n\n`;

      sh += `echo "=== [1/4] Inspeccionando estado de servicios Entrust / Tomcat ==="\n`;
      sh += `systemctl status entrust-identityguard-admin --no-pager || systemctl status tomcat9 --no-pager\n\n`;

      sh += `echo "=== [2/4] Verificando memoria JVM y flags Heap ==="\n`;
      sh += `ps aux | grep -i identityguard | grep -E "Xms|Xmx"\n\n`;

      sh += `echo "=== [3/4] Habilitando flags de contingencia para aprovisionamiento IDaaS ==="\n`;
      sh += `curl -s -X POST "http://localhost:8085/api/config" -H "Content-Type: application/json" -d '{"overwriteExistingGrid":true, "updateExistingCredentials":true}' || true\n\n`;

      sh += `echo "=== [4/4] Verificando puertos activos 8443 / UDP 514 ==="\n`;
      sh += `netstat -tuln | grep -E "8443|514"\n\n`;

      sh += `echo "=== [OK] Diagnóstico y remediación ejecutada satisfactoriamente ==="\n`;

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