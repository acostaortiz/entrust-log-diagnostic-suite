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
   ENTRUST LOG DIAGNOSTIC SUITE - MOTOR DE ALMACENAMIENTO PERSISTENTE INDEXEDDB
   Gestión de Sesiones Masivas (10M+ Líneas) y Casos Históricos de Incidentes
   ========================================================================== */

class StorageEngine {
  constructor() {
    this.dbName = 'ITServicios_Entrust_Diagnostic_DB';
    this.dbVersion = 1;
    this.db = null;
    this.initPromise = this.init();
  }

  async init() {
    if (!window.indexedDB) {
      console.warn('IndexedDB no soportado en este navegador. Se usará memoria volátil.');
      return null;
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);

      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('active_session')) {
          db.createObjectStore('active_session', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('saved_cases')) {
          const caseStore = db.createObjectStore('saved_cases', { keyPath: 'caseId' });
          caseStore.createIndex('clientName', 'clientName', { unique: false });
          caseStore.createIndex('createdAt', 'createdAt', { unique: false });
        }
      };

      request.onsuccess = (e) => {
        this.db = e.target.result;
        resolve(this.db);
      };

      request.onerror = (e) => {
        console.error('Error abriendo IndexedDB:', e);
        resolve(null);
      };
    });
  }

  async saveActiveSession(logsOrPayload, activeClientId, clientProfiles) {
    await this.initPromise;
    if (!this.db) return false;

    const isObjPayload = logsOrPayload && !Array.isArray(logsOrPayload) && typeof logsOrPayload === 'object';
    const record = isObjPayload
      ? {
          id: 'current_session',
          logs: Array.isArray(logsOrPayload.logs) ? logsOrPayload.logs : [],
          loadedFiles: Array.isArray(logsOrPayload.loadedFiles) ? logsOrPayload.loadedFiles : [],
          globalStreamMetrics: logsOrPayload.globalStreamMetrics || null,
          activeClientId: logsOrPayload.activeClientId || activeClientId || 'general',
          clientProfiles: logsOrPayload.clientProfiles || clientProfiles || [],
          updatedAt: new Date().toISOString()
        }
      : {
          id: 'current_session',
          logs: Array.isArray(logsOrPayload) ? logsOrPayload : [],
          loadedFiles: [],
          globalStreamMetrics: null,
          activeClientId: activeClientId || 'general',
          clientProfiles: clientProfiles || [],
          updatedAt: new Date().toISOString()
        };

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('active_session', 'readwrite');
        const store = tx.objectStore('active_session');
        store.put(record);
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => resolve(false);
      } catch(e) {
        console.warn('Error guardando en IndexedDB:', e);
        resolve(false);
      }
    });
  }

  async loadActiveSession() {
    await this.initPromise;
    if (!this.db) return null;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('active_session', 'readonly');
        const store = tx.objectStore('active_session');
        const req = store.get('current_session');
        req.onsuccess = () => {
          const res = req.result || null;
          if (res && res.logs && !Array.isArray(res.logs) && typeof res.logs === 'object') {
            resolve({
              id: 'current_session',
              logs: Array.isArray(res.logs.logs) ? res.logs.logs : [],
              loadedFiles: res.logs.loadedFiles || res.loadedFiles || [],
              globalStreamMetrics: res.logs.globalStreamMetrics || res.globalStreamMetrics || null,
              activeClientId: res.logs.activeClientId || res.activeClientId || 'general',
              clientProfiles: res.clientProfiles || [],
              updatedAt: res.updatedAt
            });
            return;
          }
          resolve(res);
        };
        req.onerror = () => resolve(null);
      } catch(e) {
        resolve(null);
      }
    });
  }

  async saveHistoricalCase(caseTitle, clientName, logs, summaryNotes = '') {
    await this.initPromise;
    if (!this.db) return false;

    const caseId = `case_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const caseRecord = {
      caseId,
      caseTitle: caseTitle || `Incidente ${new Date().toLocaleDateString()}`,
      clientName: clientName || 'Cliente General',
      logsCount: (logs || []).length,
      criticalCount: (logs || []).filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length,
      logs: logs || [],
      summaryNotes,
      createdAt: new Date().toISOString(),
      engineer: 'Tomás Acosta'
    };

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('saved_cases', 'readwrite');
        const store = tx.objectStore('saved_cases');
        store.put(caseRecord);
        tx.oncomplete = () => resolve(caseRecord);
        tx.onerror = () => resolve(false);
      } catch(e) {
        resolve(false);
      }
    });
  }

  async listHistoricalCases() {
    await this.initPromise;
    if (!this.db) return [];

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('saved_cases', 'readonly');
        const store = tx.objectStore('saved_cases');
        const req = store.getAll();
        req.onsuccess = () => {
          const cases = req.result || [];
          cases.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
          resolve(cases);
        };
        req.onerror = () => resolve([]);
      } catch(e) {
        resolve([]);
      }
    });
  }

  async getCaseById(caseId) {
    await this.initPromise;
    if (!this.db) return null;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('saved_cases', 'readonly');
        const store = tx.objectStore('saved_cases');
        const req = store.get(caseId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      } catch(e) {
        resolve(null);
      }
    });
  }

  async deleteCase(caseId) {
    await this.initPromise;
    if (!this.db) return false;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('saved_cases', 'readwrite');
        const store = tx.objectStore('saved_cases');
        store.delete(caseId);
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => resolve(false);
      } catch(e) {
        resolve(false);
      }
    });
  }

  async clearActiveSession() {
    await this.initPromise;
    if (!this.db) return false;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('active_session', 'readwrite');
        const store = tx.objectStore('active_session');
        store.delete('current_session');
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => resolve(false);
      } catch(e) {
        resolve(false);
      }
    });
  }

  async saveClientProfiles(clientProfiles) {
    await this.initPromise;
    if (!this.db) return false;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('active_session', 'readwrite');
        const store = tx.objectStore('active_session');
        store.put({
          id: 'stored_client_profiles',
          profiles: clientProfiles || [],
          updatedAt: new Date().toISOString()
        });
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => resolve(false);
      } catch(e) {
        resolve(false);
      }
    });
  }

  async loadClientProfiles() {
    await this.initPromise;
    if (!this.db) return null;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('active_session', 'readonly');
        const store = tx.objectStore('active_session');
        const req = store.get('stored_client_profiles');
        req.onsuccess = () => resolve(req.result ? req.result.profiles : null);
        req.onerror = () => resolve(null);
      } catch(e) {
        resolve(null);
      }
    });
  }
}

window.storageEngine = new StorageEngine();
