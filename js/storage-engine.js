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

  async saveActiveSession(logs, activeClientId, clientProfiles) {
    await this.initPromise;
    if (!this.db) return false;

    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('active_session', 'readwrite');
        const store = tx.objectStore('active_session');
        store.put({
          id: 'current_session',
          logs: logs || [],
          activeClientId: activeClientId || 'mercantil',
          clientProfiles: clientProfiles || [],
          updatedAt: new Date().toISOString()
        });
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
        req.onsuccess = () => resolve(req.result || null);
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
}

window.storageEngine = new StorageEngine();
