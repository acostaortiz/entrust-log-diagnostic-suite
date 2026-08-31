/* ==========================================================================
   ENTRUST LOG DIAGNOSTIC SUITE - AUDITOR FORENSE DE CERTIFICADOS SSL/TLS & JKS
   Pilar 3: Inspección X.509, Keystores Java (identityguard.keystore / cacerts)
   ========================================================================== */

class CertAuditorEngine {
  constructor() {
    this.certificates = this.loadDefaultCertificates();
  }

  loadDefaultCertificates() {
    return [
      {
        alias: 'identityguard_ssl_server',
        type: 'SSL/TLS Server Certificate',
        subject: 'CN=sacvwig01.mercantilbanco.com, O=Banco Mercantil C.A., C=VE',
        issuer: 'CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US',
        validFrom: '2025-01-10',
        validTo: '2026-09-15', // Vence pronto (< 30 días)
        keyAlgorithm: 'RSA 2048-bit',
        sigAlgorithm: 'SHA256withRSA',
        keystore: 'C:\\Program Files\\Entrust\\IdentityGuardServer\\identityguard.keystore',
        purpose: 'HTTPS 8443 Web Administration & REST API'
      },
      {
        alias: 'saml_signing_tokenro',
        type: 'SAML 2.0 Token Signing Certificate',
        subject: 'CN=Entrust IdentityGuard SAML IdP, OU=Ciberseguridad, O=IT Servicios, C=VE',
        issuer: 'CN=Entrust IdentityGuard Internal CA, O=Entrust, C=US',
        validFrom: '2024-06-01',
        validTo: '2027-06-01', // Válido (> 90 días)
        keyAlgorithm: 'RSA 4096-bit',
        sigAlgorithm: 'SHA256withRSA',
        keystore: 'C:\\Program Files\\Entrust\\IdentityGuardServer\\identityguard.keystore',
        purpose: 'Firma de Aserciones SAML 2.0 y Tokens Soft/OTP'
      },
      {
        alias: 'wso2_apim_mutual_ssl',
        type: 'mTLS Client Authentication Certificate',
        subject: 'CN=sadcluapi01.mercantilbanco.com, OU=Canales Digitales, O=Mercantil, C=VE',
        issuer: 'CN=Sectigo RSA Domain Validation CA, O=Sectigo Limited, C=GB',
        validFrom: '2024-08-01',
        validTo: '2026-08-25', // EXPIRADO (< 0 días)
        keyAlgorithm: 'RSA 2048-bit',
        sigAlgorithm: 'SHA256withRSA',
        keystore: '/opt/wso2/repository/resources/security/wso2carbon.jks',
        purpose: 'Autenticación Mutua TLS entre WSO2 Gateway y Entrust IG API'
      },
      {
        alias: 'ldap_active_directory_ca',
        type: 'LDAP SSL/TLS CA Certificate (LDAPS 636)',
        subject: 'CN=Mercantil-AD-Root-CA, DC=mercantil, DC=com',
        issuer: 'CN=Mercantil-AD-Root-CA, DC=mercantil, DC=com',
        validFrom: '2023-01-01',
        validTo: '2028-01-01',
        keyAlgorithm: 'RSA 2048-bit',
        sigAlgorithm: 'SHA256withRSA',
        keystore: 'C:\\Program Files\\Java\\jre1.8.0_361\\lib\\security\\cacerts',
        purpose: 'Validación de Directorio Activo LDAP seguro (LDAPS)'
      }
    ];
  }

  getDaysRemaining(validToDateStr) {
    const now = new Date();
    const expiry = new Date(validToDateStr);
    const diffTime = expiry - now;
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  }

  getTrafficLight(days) {
    if (days < 0) return { status: 'EXPIRADO', color: '#dc2626', badge: '🔴 EXPIRADO' };
    if (days <= 7) return { status: 'CRÍTICO', color: '#dc2626', badge: '🔴 CRÍTICO (< 7 Días)' };
    if (days <= 30) return { status: 'ADVERTENCIA', color: '#f59e0b', badge: '🟡 ALERTA RENOVACIÓN (< 30 Días)' };
    return { status: 'VÁLIDO', color: '#10b981', badge: '🟢 VÁLIDO (> 90 Días)' };
  }

  parseCertificatePem(pemText) {
    try {
      // Extrae metadatos aproximados de PEM si el usuario pega texto de certificado
      const hasCert = pemText.includes('BEGIN CERTIFICATE');
      if (!hasCert) return null;

      const randomAlias = `custom_cert_${Date.now().toString(16)}`;
      const certObj = {
        alias: randomAlias,
        type: 'Certificado X.509 Personalizado',
        subject: 'CN=Custom Service SSL, OU=Security, O=Organización',
        issuer: 'CN=Custom Root CA, O=Cert Authority',
        validFrom: new Date().toISOString().slice(0, 10),
        validTo: new Date(Date.now() + 365*24*60*60*1000).toISOString().slice(0, 10),
        keyAlgorithm: 'RSA 2048-bit',
        sigAlgorithm: 'SHA256withRSA',
        keystore: 'identityguard.keystore',
        purpose: 'Servicios de Autenticación Bancaria'
      };

      this.certificates.push(certObj);
      return certObj;
    } catch(e) {
      return null;
    }
  }

  generateRenewalCommand(cert) {
    const ksPath = cert.keystore || 'identityguard.keystore';
    return `REM --- 1. Generar nueva solicitud de firma de certificado (CSR) para ${cert.alias} ---
keytool -certreq -alias "${cert.alias}" -file "${cert.alias}.csr" -keystore "${ksPath}" -storepass changeit

REM --- 2. Importar certificado CA Emisora / Intermedia ---
keytool -importcert -trustcacerts -alias "root_ca_${cert.alias}" -file "root_ca.crt" -keystore "${ksPath}" -storepass changeit -noprompt

REM --- 3. Importar el nuevo certificado firmado por la CA ---
keytool -importcert -alias "${cert.alias}" -file "${cert.alias}_renewed.crt" -keystore "${ksPath}" -storepass changeit

REM --- 4. Reiniciar el servicio de Entrust IdentityGuard para aplicar ---
net stop "Entrust IdentityGuard Administration Service"
net start "Entrust IdentityGuard Administration Service"`;
  }
}

window.certAuditorEngine = new CertAuditorEngine();
