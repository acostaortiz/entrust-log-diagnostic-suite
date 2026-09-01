/**
 * MANUALS-ENGINE: Gestor de Manuales Administrativos por Versión en HTML
 * Soporta Entrust IdentityGuard OnPremise v13.0 WebHelp Oficial, 520xxx, AUDxxx & IDaaS Cloud.
 */

class ManualsEngine {
  constructor() {
    this.storageKey = 'custom_html_manuals_v1';
    this.currentVersion = 'v13_0_webhelp';

    this.manualsMap = {
      'v13_0_webhelp': {
        title: 'Entrust IdentityGuard v13.0 - WebHelp Oficial Completa (Admin Guide)',
        paths: [
          'manuals/IG_130_Admin_WebHelp/index.htm',
          'manuals/IG_130_Admin_WebHelp/reference.htm'
        ],
        type: 'builtin'
      },
      'v12_0_webhelp': {
        title: 'Entrust IdentityGuard v12.0 - WebHelp Oficial Completa (Admin Guide)',
        paths: [
          'manuals/IG_120_Admin_WebHelp/index.htm',
          'manuals/IG_120_Admin_WebHelp/reference.htm'
        ],
        type: 'builtin'
      },
      'v11_0_webhelp': {
        title: 'Entrust IdentityGuard v11.0 - WebHelp Oficial Completa (Admin Guide)',
        paths: [
          'manuals/IG_110_Admin_WebHelp/index.htm',
          'manuals/IG_110_Admin_WebHelp/reference.htm'
        ],
        type: 'builtin'
      },
      'v13_0_relnotes': {
        title: '📋 Release Notes v13.0 - Notas de Lanzamiento Oficiales (Diciembre 2020)',
        paths: ['manuals/entrust_ig_130_releasenotes.html'],
        type: 'builtin'
      },
      'v12_0_relnotes': {
        title: '📋 Release Notes v12.0 - Notas de Lanzamiento Oficiales (Marzo 2017)',
        paths: ['manuals/entrust_ig_120_releasenotes.html'],
        type: 'builtin'
      },
      'v11_0_relnotes': {
        title: '📋 Release Notes v11.0 - Notas de Lanzamiento Oficiales (Noviembre 2015)',
        paths: ['manuals/entrust_ig_110_releasenotes.html'],
        type: 'builtin'
      },
      'vEntrust': {
        title: 'Entrust IdentityGuard OnPremise - Catálogo Rápido 520xxx, AUDxxx & Guía Operativa',
        paths: [
          'manuals/entrust_identityguard_errors.html',
          'manuals/Entrust_IdentityGuard_Errores.html'
        ],
        type: 'builtin'
      },
      'vIDaaS': {
        title: 'Entrust IDaaS Cloud - Troubleshooting SSO, SAML 2.0, OIDC & Push MFA',
        paths: ['manuals/entrust_idaas_errors.html'],
        type: 'builtin'
      }
    };

    this.fallbackManuals = {
      'v13_0_webhelp': `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Entrust IdentityGuard v13.0 WebHelp</title>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; padding: 20px; color: #0a3d6d; }
    iframe { width: 100%; height: 750px; border: none; }
  </style>
</head>
<body>
  <h2>Entrust IdentityGuard v13.0 Administration WebHelp</h2>
  <iframe src="manuals/IG_130_Admin_WebHelp/index.htm"></iframe>
</body>
</html>`,
      'v12_0_webhelp': `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Entrust IdentityGuard v12.0 WebHelp</title>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; padding: 20px; color: #0a3d6d; }
    iframe { width: 100%; height: 750px; border: none; }
  </style>
</head>
<body>
  <h2>Entrust IdentityGuard v12.0 Administration WebHelp</h2>
  <iframe src="manuals/IG_120_Admin_WebHelp/index.htm"></iframe>
</body>
</html>`,
      'v11_0_webhelp': `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Entrust IdentityGuard v11.0 WebHelp</title>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; padding: 20px; color: #0a3d6d; }
    iframe { width: 100%; height: 750px; border: none; }
  </style>
</head>
<body>
  <h2>Entrust IdentityGuard v11.0 Administration WebHelp</h2>
  <iframe src="manuals/IG_110_Admin_WebHelp/index.htm"></iframe>
</body>
</html>`
    };

    this.loadedCache = {};
    this.initCustomManuals();
  }

  initCustomManuals() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const customMap = JSON.parse(stored);
        Object.keys(customMap).forEach(ver => {
          this.manualsMap[ver] = customMap[ver];
        });
      }
    } catch (e) {
      console.warn('Error al cargar manuales personalizados:', e);
    }
  }

  getVersionsList() {
    return Object.keys(this.manualsMap).map(key => ({
      key: key,
      title: this.manualsMap[key].title
    }));
  }

  async loadManualHtml(version) {
    if (!this.manualsMap[version]) {
      version = 'v13_0_webhelp';
    }

    this.currentVersion = version;
    const manualMeta = this.manualsMap[version];

    if (manualMeta.type === 'custom' && manualMeta.content) {
      return manualMeta.content;
    }

    const paths = manualMeta.paths || [manualMeta.path];
    for (const path of paths) {
      try {
        const response = await fetch(path + '?t=' + Date.now());
        if (response.ok) {
          const htmlText = await response.text();
          this.loadedCache[version] = htmlText;
          return htmlText;
        }
      } catch (err) {
        console.warn(`Fetch falló para la ruta ${path}`);
      }
    }

    if (this.fallbackManuals[version]) {
      this.loadedCache[version] = this.fallbackManuals[version];
      return this.fallbackManuals[version];
    }

    return `<div style="padding:20px; color:#ef4444;">
      <h3>Error al cargar el Manual Administrativo (${version})</h3>
      <p>No se pudo recuperar el archivo HTML desde las rutas configuradas.</p>
    </div>`;
  }

  extractToc(htmlContent) {
    if (!htmlContent) return [];

    const parser = new DOMParser();
    const doc = parser.parseFromString(htmlContent, 'text/html');
    const headings = doc.querySelectorAll('h1, h2, h3, a[href]');

    const toc = [];
    headings.forEach((h, idx) => {
      let id = h.getAttribute('id') || h.getAttribute('name');
      if (!id) {
        id = `toc-sec-${idx}`;
      }
      const text = h.textContent.trim();
      if (text.length > 2 && text.length < 80) {
        toc.push({
          id: id,
          text: text,
          level: h.tagName.toLowerCase()
        });
      }
    });

    return toc.slice(0, 40);
  }

  searchManuals(query) {
    if (!query || query.trim().length < 2) return [];

    const cleanQuery = query.toLowerCase().trim();
    const results = [];

    // 1. Buscar en la Base de Conocimientos & Catálogos Importados de Todas las Versiones
    if (window.knowledgeBaseEngine) {
      const kbRules = window.knowledgeBaseEngine.getAllRules() || [];
      kbRules.forEach(rule => {
        const idMatch = (rule.id || '').toLowerCase().includes(cleanQuery);
        const titleMatch = (rule.title || '').toLowerCase().includes(cleanQuery);
        const meaningMatch = (rule.meaning || '').toLowerCase().includes(cleanQuery);
        const causeMatch = (rule.rootCause || '').toLowerCase().includes(cleanQuery);
        const remediationMatch = (rule.remediation || '').toLowerCase().includes(cleanQuery);
        const patternStr = rule.pattern ? (rule.pattern.source || rule.pattern.toString()).toLowerCase() : '';
        const patternMatch = patternStr.includes(cleanQuery);

        if (idMatch || titleMatch || meaningMatch || causeMatch || remediationMatch || patternMatch) {
          results.push({
            type: 'error_rule',
            rule: rule,
            code: (rule.id || '').replace('KB-ENTRUST-', '').replace('KB-', ''),
            title: rule.title || rule.id,
            version: rule.manualVersion || 'Entrust IdentityGuard',
            severity: rule.severity || 'ERROR',
            category: rule.category || 'General',
            snippet: `${rule.title} — ${rule.meaning ? rule.meaning.substring(0, 90) + '...' : ''}`,
            sectionId: rule.sectionId || 'sec-' + (rule.id || '').toLowerCase()
          });
        }
      });
    }

    // 2. Buscar en Manuales WebHelp y Release Notes en Caché
    Object.keys(this.manualsMap).forEach(ver => {
      const content = this.loadedCache[ver] || this.fallbackManuals[ver];
      if (content) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(content, 'text/html');
        const textContent = doc.body.textContent || '';

        if (textContent.toLowerCase().includes(cleanQuery)) {
          const idx = textContent.toLowerCase().indexOf(cleanQuery);
          const start = Math.max(0, idx - 40);
          const end = Math.min(textContent.length, idx + 100);
          const snippet = '...' + textContent.substring(start, end).replace(/\s+/g, ' ') + '...';

          results.push({
            type: 'manual_page',
            version: ver,
            title: this.manualsMap[ver]?.title || ver,
            snippet: snippet,
            sectionId: 'sec-' + cleanQuery
          });
        }
      }
    });

    return results;
  }

  saveCustomManual(verKey, title, htmlContent) {
    const cleanKey = verKey.replace(/[^a-zA-Z0-9_-]/g, '');
    this.manualsMap[cleanKey] = {
      title: title,
      content: htmlContent,
      type: 'custom'
    };

    this.loadedCache[cleanKey] = htmlContent;

    try {
      const customOnly = {};
      Object.keys(this.manualsMap).forEach(k => {
        if (this.manualsMap[k].type === 'custom') {
          customOnly[k] = this.manualsMap[k];
        }
      });
      localStorage.setItem(this.storageKey, JSON.stringify(customOnly));
    } catch (e) {
      console.warn('Error al guardar manual en localStorage:', e);
    }

    return cleanKey;
  }
}

window.manualsEngine = new ManualsEngine();
