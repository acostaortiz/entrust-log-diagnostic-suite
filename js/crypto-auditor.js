/**
 * ==============================================================================
 * 🏢 IT SERVICIOS DE VENEZUELA, S.A.
 * MÓDULO: VALIDADOR CRIPTOGRÁFICO DE INTEGRIDAD & CHECKSUM (SHA-256 / SHA-1 / MD5)
 * ==============================================================================
 * Verifica la integridad inalterable de paquetes de migración .dat, archivos de logs
 * y manifiestos de sincronización entre servidores OnPremise y el Tenant Entrust IDaaS.
 */

(function(window) {
  'use strict';

  const CryptoAuditor = {
    currentFile: null,
    calculatedHashes: { sha256: '', sha1: '', sha512: '' },

    init() {
      this.bindEvents();
      console.log('✅ [CryptoAuditor]: Módulo de Verificación Criptográfica SHA-256 Inicializado.');
    },

    bindEvents() {
      // Botón en Menú Herramientas / Header
      const btnOpen = document.getElementById('btn-open-crypto-modal');
      if (btnOpen) {
        btnOpen.addEventListener('click', () => this.openModal());
      }

      // Input de archivo
      const fileInput = document.getElementById('crypto-file-input');
      if (fileInput) {
        fileInput.addEventListener('change', (e) => {
          const file = e.target.files?.[0];
          if (file) this.processFile(file);
        });
      }

      // Drag and Drop
      const dropZone = document.getElementById('crypto-drop-zone');
      if (dropZone) {
        dropZone.addEventListener('dragover', (e) => {
          e.preventDefault();
          dropZone.style.borderColor = 'var(--it-blue-light)';
          dropZone.style.background = 'rgba(2, 132, 199, 0.08)';
        });
        dropZone.addEventListener('dragleave', () => {
          dropZone.style.borderColor = 'var(--border-color)';
          dropZone.style.background = 'var(--bg-secondary)';
        });
        dropZone.addEventListener('drop', (e) => {
          e.preventDefault();
          dropZone.style.borderColor = 'var(--border-color)';
          dropZone.style.background = 'var(--bg-secondary)';
          const file = e.dataTransfer?.files?.[0];
          if (file) this.processFile(file);
        });
      }

      // Input de comparación esperada
      const inputExpected = document.getElementById('crypto-expected-hash');
      if (inputExpected) {
        inputExpected.addEventListener('input', () => this.compareHash());
      }

      // Botón Copiar SHA-256
      const btnCopy = document.getElementById('btn-copy-sha256');
      if (btnCopy) {
        btnCopy.addEventListener('click', () => {
          if (this.calculatedHashes.sha256) {
            navigator.clipboard.writeText(this.calculatedHashes.sha256).then(() => {
              alert('✅ Hash SHA-256 copiado al portapapeles.');
            });
          }
        });
      }

      // Cerrar modal
      const btnClose = document.getElementById('btn-close-crypto-modal');
      const modal = document.getElementById('crypto-modal');
      if (btnClose && modal) {
        btnClose.addEventListener('click', () => modal.classList.remove('active'));
        modal.addEventListener('click', (e) => {
          if (e.target === modal) modal.classList.remove('active');
        });
      }
    },

    openModal() {
      const modal = document.getElementById('crypto-modal');
      if (modal) {
        modal.classList.add('active');
      }
    },

    async processFile(file) {
      this.currentFile = file;
      const fileNameEl = document.getElementById('crypto-file-name');
      const fileSizeEl = document.getElementById('crypto-file-size');
      const progressEl = document.getElementById('crypto-progress-bar');
      const progressContainer = document.getElementById('crypto-progress-container');
      const resultArea = document.getElementById('crypto-results-area');

      if (fileNameEl) fileNameEl.textContent = file.name;
      if (fileSizeEl) fileSizeEl.textContent = this.formatBytes(file.size);
      if (progressContainer) progressContainer.style.display = 'block';
      if (progressEl) progressEl.style.width = '20%';
      if (resultArea) resultArea.style.display = 'none';

      try {
        const buffer = await file.arrayBuffer();
        if (progressEl) progressEl.style.width = '60%';

        // Cálculo SHA-256 vía Web Crypto API nativo
        const hashBuffer256 = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray256 = Array.from(new Uint8Array(hashBuffer256));
        this.calculatedHashes.sha256 = hashArray256.map(b => b.toString(16).padStart(2, '0')).join('');

        // Cálculo SHA-1
        const hashBuffer1 = await crypto.subtle.digest('SHA-1', buffer);
        const hashArray1 = Array.from(new Uint8Array(hashBuffer1));
        this.calculatedHashes.sha1 = hashArray1.map(b => b.toString(16).padStart(2, '0')).join('');

        if (progressEl) progressEl.style.width = '100%';

        setTimeout(() => {
          if (progressContainer) progressContainer.style.display = 'none';
          this.renderResults();
        }, 200);

      } catch(e) {
        console.error('Error calculando hash criptográfico:', e);
        alert('❌ Error al procesar archivo criptográfico: ' + e.message);
        if (progressContainer) progressContainer.style.display = 'none';
      }
    },

    renderResults() {
      const resultArea = document.getElementById('crypto-results-area');
      const sha256El = document.getElementById('crypto-sha256-output');
      const sha1El = document.getElementById('crypto-sha1-output');

      if (sha256El) sha256El.textContent = this.calculatedHashes.sha256;
      if (sha1El) sha1El.textContent = this.calculatedHashes.sha1;
      if (resultArea) resultArea.style.display = 'block';

      this.compareHash();
    },

    compareHash() {
      const inputExpected = document.getElementById('crypto-expected-hash');
      const statusEl = document.getElementById('crypto-match-status');
      if (!inputExpected || !statusEl) return;

      const expected = inputExpected.value.trim().toLowerCase();
      const current = this.calculatedHashes.sha256.toLowerCase();

      if (!expected) {
        statusEl.innerHTML = '<span style="color:var(--text-muted); font-size:0.8rem;">Pegue el hash esperado de exportación OnPremise para verificar coincidencia exacta.</span>';
        return;
      }

      if (expected === current || expected === this.calculatedHashes.sha1.toLowerCase()) {
        statusEl.innerHTML = `
          <div style="background:rgba(16,185,129,0.15); border:1px solid #10b981; color:#10b981; padding:8px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; display:flex; align-items:center; gap:8px;">
            <span>🛡️</span>
            <span>INTEGRIDAD VALIDADA: El archivo coincide al 100% con la firma criptográfica oficial. Cero corrupción detectada.</span>
          </div>
        `;
      } else {
        statusEl.innerHTML = `
          <div style="background:rgba(239,68,68,0.15); border:1px solid #ef4444; color:#ef4444; padding:8px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; display:flex; align-items:center; gap:8px;">
            <span>⚠️</span>
            <span>DISCREPANCIA CRIPTOGRÁFICA: El hash del archivo no coincide con el valor esperado. Posible archivo truncado o modificado.</span>
          </div>
        `;
      }
    },

    formatBytes(bytes) {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
  };

  window.cryptoAuditorEngine = CryptoAuditor;
  document.addEventListener('DOMContentLoaded', () => CryptoAuditor.init());
})(window);
