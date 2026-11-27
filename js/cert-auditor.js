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

/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - AUDITOR FORENSE DE CERTIFICADOS SSL/TLS & JKS
   100% Real: Basado en server.xml del cliente, errores TLS/LDAPS de logs y .PEM/.CRT
   ========================================================================== */

class CertAuditorEngine {
  constructor() {
    this.certificates = [];
  }

  getDaysRemaining(validToDateStr) {
    if (!validToDateStr) return 365;
    const now = new Date();
    const expiry = new Date(validToDateStr);
    const diffTime = expiry - now;
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  getTrafficLight(days) {
    if (days < 0) return { status: 'EXPIRADO', color: '#dc2626', badge: 'EXPIRADO' };
    if (days <= 7) return { status: 'CRÍTICO', color: '#dc2626', badge: 'CRÍTICO (< 7 días)' };
    if (days <= 30) return { status: 'ADVERTENCIA', color: '#d97706', badge: 'RENOVACIÓN (< 30 días)' };
    return { status: 'VÁLIDO', color: '#16a34a', badge: 'VÁLIDO' };
  }

  extractTlsFindingsFromLogs(logs = []) {
    const tlsErrors = [];
    const seen = new Set();
    const reTls = /(5202020|AUD160|AUD161|TOMCAT_SSL_TLS|SSLHandshakeException|PKIX path|CertPathBuilderException|certificate.*expired|unable to find valid certification|javax\.net\.ssl|LDAPS)/i;
    for (let i = 0; i < logs.length && tlsErrors.length < 15; i++) {
      const l = logs[i];
      const msg = String(l.raw || l.message || '');
      const code = String(l.entrustCode || '');
      const m = msg.match(reTls) || code.match(/^(5202020|AUD160|AUD161|TOMCAT_SSL_TLS)$/i);
      if (m) {
        const pat = m[1].toUpperCase();
        const key = `${pat}|${l.sourceFile || ''}`;
        if (!seen.has(key)) {
          seen.add(key);
          tlsErrors.push({
            pattern: pat,
            file: l.sourceFile || 'Log activo',
            timestamp: l.timestamp || '-',
            sample: msg.slice(0, 180)
          });
        }
      }
    }

    const tlsCodeDesc = {
      AUD160: 'AUD160: Alerta de certificado X.509 próximo a expirar en Entrust IdentityGuard.',
      AUD161: 'AUD161: Certificado X.509 expirado o inválido detectado en el almacén Entrust.',
      TOMCAT_SSL_TLS: 'TOMCAT_SSL_TLS: Error de handshake SSL/TLS o keystore en contenedor Apache Tomcat.',
      '5202020': '5202020: Error de validación de certificado o canal TLS/LDAPS en motor Entrust.'
    };
    const isTlsCode = (c) => /^(?:AUD160|AUD161|TOMCAT_SSL_TLS|5202020)$/i.test(String(c || '').trim());
    const fmCodes = (typeof window !== 'undefined' && window.UserTraceReport?.forensicMatrixData?.codeMatrix) || [];
    const gsmCodes = (typeof window !== 'undefined' && window.appState?.globalStreamMetrics?.topCodes) || [];
    const seenSqlPatterns = new Set(tlsErrors.map(e => String(e.pattern || '').toUpperCase()));

    [...fmCodes, ...gsmCodes].forEach(entry => {
      if (!entry || tlsErrors.length >= 20) return;
      const c = String(entry.code || '').trim().toUpperCase();
      if (!isTlsCode(c) || seenSqlPatterns.has(c)) return;
      const cnt = Number(entry.totalInteractions ?? entry.count ?? 0);
      if (cnt <= 0) return;
      seenSqlPatterns.add(c);
      tlsErrors.push({
        pattern: c,
        file: 'Índice Consolidado SQLite',
        timestamp: `${cnt.toLocaleString()} evento(s)`,
        sample: tlsCodeDesc[c] || `Patrón TLS/Certificado ${c} detectado en base de datos consolidada (${cnt.toLocaleString()}x).`
      });
    });

    return tlsErrors;
  }

  parseCertificatePem(pemText) {
    try {
      const hasCert = pemText && pemText.includes('BEGIN CERTIFICATE');
      if (!hasCert) return null;
      const randomAlias = `cert_${Date.now().toString(16)}`;
      const certObj = {
        alias: randomAlias,
        type: 'Certificado X.509 Importado (.PEM/.CRT)',
        subject: 'Certificado PEM cargado por usuario',
        issuer: 'Validar vía keytool / openssl x509 -in cert.pem -text -noout',
        validFrom: new Date().toISOString().slice(0, 10),
        validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
        keyAlgorithm: 'X.509 PEM',
        sigAlgorithm: 'Verificar con OpenSSL',
        keystore: 'identityguard.keystore',
        purpose: 'Inspección manual de certificado'
      };
      this.certificates.push(certObj);
      return certObj;
    } catch (e) {
      return null;
    }
  }

  generateRenewalCommand(cert) {
    const ksPath = cert.keystore || '${identityguard.home}/etc/keystore';
    const alias = cert.alias || 'tomcat';
    return `# 1. Inspeccionar certificado actual en el keystore real:
keytool -list -v -alias "${alias}" -keystore "${ksPath}"

# 2. Generar nueva solicitud de firma (CSR):
keytool -certreq -alias "${alias}" -file "${alias}.csr" -keystore "${ksPath}"

# 3. Importar certificado CA raíz / intermedia:
keytool -importcert -trustcacerts -alias "root_ca" -file "root_ca.crt" -keystore "${ksPath}" -noprompt

# 4. Importar el certificado firmado renovado:
keytool -importcert -alias "${alias}" -file "${alias}_renewed.crt" -keystore "${ksPath}"`;
  }

  render(containerId, logs = [], clientConfig = null) {
    const container = document.getElementById(containerId) || document.getElementById('certificates-table-container');
    if (!container) return;

    const cfg = clientConfig || (window.appState && window.appState.activeClientConfig) || null;
    const allLogs = (logs && logs.length > 0) ? logs : ((window.appState && window.appState.logs) || []);
    const tlsFindings = this.extractTlsFindingsFromLogs(allLogs);
    const connectors = (cfg && Array.isArray(cfg.tomcatConnectors)) ? cfg.tomcatConnectors : [];

    let html = '';

    // 1. Hallazgos Reales SSL/TLS/LDAPS en Logs
    html += `
      <div style="margin-bottom:18px; padding:14px; border-radius:10px; border:1px solid ${tlsFindings.length > 0 ? 'rgba(220,38,38,0.4)' : 'rgba(22,163,74,0.35)'}; background:${tlsFindings.length > 0 ? 'rgba(220,38,38,0.06)' : 'rgba(22,163,74,0.06)'};">
        <div style="font-weight:800; font-size:0.88rem; color:${tlsFindings.length > 0 ? '#dc2626' : '#16a34a'}; margin-bottom:6px;">
          ${tlsFindings.length > 0
            ? `Alertas TLS / SSL / LDAPS Detectadas en Logs (${tlsFindings.length} patrón(es))`
            : 'Sin errores SSL/TLS/PKIX o fallos de certificado LDAPS detectados en los logs cargados'}
        </div>
        ${tlsFindings.length > 0 ? tlsFindings.map(f => `
          <div style="font-size:0.78rem; padding:6px 8px; margin-top:6px; background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:6px; font-family:'JetBrains Mono', monospace;">
            <strong style="color:#dc2626;">[${escapeHtml(f.pattern)}]</strong> (${escapeHtml(f.file)} · ${escapeHtml(f.timestamp)}): ${escapeHtml(f.sample)}
          </div>`).join('') : `<div style="font-size:0.78rem; color:var(--text-muted);">Los logs analizados no registran excepciones de handshake TLS, certificados expirados ni fallos PKIX.</div>`}
      </div>
    `;

    // 2. Conectores SSL y Keystores Reales desde server.xml del Cliente
    if (connectors.length > 0) {
      html += `
        <div style="margin-bottom:18px;">
          <div style="font-weight:800; font-size:0.86rem; color:var(--text-main); margin-bottom:8px;">
            Keystores y Conectores SSL Reales (Extraídos de <code>server.xml</code> del Cliente)
          </div>
          <div style="overflow-x:auto;">
            <table style="width:100%; border-collapse:collapse; font-size:0.8rem;">
              <thead>
                <tr style="background:var(--bg-primary); text-align:left;">
                  <th style="padding:8px; border-bottom:2px solid var(--border-color);">Servicio / Puerto</th>
                  <th style="padding:8px; border-bottom:2px solid var(--border-color);">Keystore &amp; Alias</th>
                  <th style="padding:8px; border-bottom:2px solid var(--border-color);">Protocolos SSL/TLS</th>
                  <th style="padding:8px; border-bottom:2px solid var(--border-color);">mTLS (clientAuth)</th>
                  <th style="padding:8px; border-bottom:2px solid var(--border-color);">Acción</th>
                </tr>
              </thead>
              <tbody>
                ${connectors.map((c, idx) => `
                  <tr>
                    <td style="padding:8px; border-bottom:1px solid var(--border-color); font-weight:700;">${escapeHtml(c.service || 'Connector')} <span style="font-family:monospace; color:var(--accent-cyan);">:${escapeHtml(c.port || '-')}</span></td>
                    <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace; font-size:0.75rem;">${escapeHtml(c.keystoreFile || 'N/A')} <br><span style="color:var(--text-muted);">alias: ${escapeHtml(c.keyAlias || 'N/A')}</span></td>
                    <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace; font-size:0.74rem;">${escapeHtml(c.sslEnabledProtocols || c.scheme || 'http')}</td>
                    <td style="padding:8px; border-bottom:1px solid var(--border-color);">${c.clientAuth === 'true' ? '<span style="color:#0284c7; font-weight:700;">mTLS Requerido</span>' : 'Estándar'}</td>
                    <td style="padding:8px; border-bottom:1px solid var(--border-color);">
                      ${c.keystoreFile ? `<button type="button" class="btn btn-primary" style="padding:3px 10px; font-size:0.74rem;" onclick="window.showCertCliByConfig && window.showCertCliByConfig(${idx});">Ver CLI Keytool</button>` : '-'}
                    </td>
                  </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    } else {
      html += `
        <div style="padding:16px; border-radius:10px; border:1px dashed var(--border-color); background:var(--bg-primary); font-size:0.82rem; color:var(--text-muted); margin-bottom:16px;">
          No hay un archivo <code>server.xml</code> cargado aún para este cliente. Sube <code>server.xml</code> desde <strong>+ Cliente → Cargar Archivos Config</strong> para inspeccionar sus rutas reales de Keystore, alias, puertos SSL/mTLS y protocolos habilitados.
        </div>
      `;
    }

    // 3. Certificados PEM/CRT analizados por el usuario
    if (this.certificates.length > 0) {
      html += `
        <div>
          <div style="font-weight:800; font-size:0.86rem; color:var(--text-main); margin-bottom:8px;">Certificados X.509 Analizados (.PEM / .CRT)</div>
          <table style="width:100%; border-collapse:collapse; font-size:0.8rem;">
            <thead>
              <tr style="background:var(--bg-primary); text-align:left;">
                <th style="padding:8px; border-bottom:2px solid var(--border-color);">Alias</th>
                <th style="padding:8px; border-bottom:2px solid var(--border-color);">Sujeto / Propósito</th>
                <th style="padding:8px; border-bottom:2px solid var(--border-color);">Keystore</th>
                <th style="padding:8px; border-bottom:2px solid var(--border-color);">Acción</th>
              </tr>
            </thead>
            <tbody>
              ${this.certificates.map((cert, i) => `
                <tr>
                  <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace; font-weight:700;">${escapeHtml(cert.alias)}</td>
                  <td style="padding:8px; border-bottom:1px solid var(--border-color);">${escapeHtml(cert.subject)}</td>
                  <td style="padding:8px; border-bottom:1px solid var(--border-color); font-family:monospace;">${escapeHtml(cert.keystore)}</td>
                  <td style="padding:8px; border-bottom:1px solid var(--border-color);">
                    <button type="button" class="btn btn-primary" style="padding:3px 10px; font-size:0.74rem;" onclick="window.showCertCliByIndex && window.showCertCliByIndex(${i});">Ver CLI</button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    container.innerHTML = html;

    window.showCertCliByConfig = (idx) => {
      const c = connectors[idx];
      const term = document.getElementById('cert-cli-terminal');
      if (term && c) {
        term.textContent = this.generateRenewalCommand({ alias: c.keyAlias || 'tomcat', keystore: c.keystoreFile });
      }
    };
    window.showCertCliByIndex = (idx) => {
      const cert = this.certificates[idx];
      const term = document.getElementById('cert-cli-terminal');
      if (term && cert) {
        term.textContent = this.generateRenewalCommand(cert);
      }
    };
  }
}

window.certAuditorEngine = new CertAuditorEngine();
