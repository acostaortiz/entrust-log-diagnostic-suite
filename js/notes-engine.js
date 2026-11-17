/**
 * PORTAL DE NOTAS TÉCNICAS & PROCEDIMIENTOS (RUNBOOKS) — IT SERVICIOS
 * Base de conocimiento viva alimentada desde la web e integrada con Entrust Forensics AI.
 */
(function () {
  const STORAGE_KEY = 'entrust_technical_notes_v1';

  class NotesEngine {
    constructor() {
      this.notes = [];
      this.editingId = null;
      this.filterQuery = '';
      this.filterCategory = 'ALL';
      this.filterTag = '';
      this.containerId = 'notes-portal-container';
    }

    _escape(str) {
      return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    _persistLocal() {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(this.notes));
      } catch (e) {}
    }

    _loadLocal() {
      try {
        const raw = localStorage.getItem(STORAGE_KEY);
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        return [];
      }
    }

    async loadNotes() {
      try {
        const resp = await fetch('/api/notes');
        if (resp.ok) {
          const data = await resp.json();
          if (Array.isArray(data.notes)) {
            this.notes = data.notes;
            this._persistLocal();
            return this.notes;
          }
        }
      } catch (e) {}
      this.notes = this._loadLocal();
      return this.notes;
    }

    async saveNote(notePayload) {
      const clean = {
        id: notePayload.id || ('nt_' + Date.now()),
        title: (notePayload.title || '').trim(),
        category: notePayload.category || 'Nota Técnica',
        tags: Array.isArray(notePayload.tags)
          ? notePayload.tags
          : String(notePayload.tags || '').split(',').map(t => t.trim()).filter(Boolean),
        platform: notePayload.platform || 'Todas',
        clientId: notePayload.clientId || 'global',
        clientName: notePayload.clientName || 'Global (Todos los Clientes)',
        content: (notePayload.content || '').trim(),
        author: notePayload.author || 'Especialista',
        createdAt: notePayload.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      try {
        const resp = await fetch('/api/notes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ note: clean })
        });
        if (resp.ok) {
          const data = await resp.json();
          if (Array.isArray(data.notes)) {
            this.notes = data.notes;
            this._persistLocal();
            return data.note || clean;
          }
        }
      } catch (e) {}

      const idx = this.notes.findIndex(n => n.id === clean.id);
      if (idx >= 0) this.notes[idx] = clean;
      else this.notes.unshift(clean);
      this._persistLocal();
      return clean;
    }

    async deleteNote(noteId) {
      if (!noteId) return;
      try {
        const resp = await fetch('/api/notes/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: noteId })
        });
        if (resp.ok) {
          const data = await resp.json();
          if (Array.isArray(data.notes)) {
            this.notes = data.notes;
            this._persistLocal();
            return;
          }
        }
      } catch (e) {}

      this.notes = this.notes.filter(n => n.id !== noteId);
      this._persistLocal();
    }

    searchNotes(query, activeClientId = null) {
      const q = String(query || '').trim().toLowerCase();
      if (!this.notes || this.notes.length === 0) return [];

      const tokens = q.split(/[\s,;:|]+/).filter(t => t.length >= 2);
      const codes = q.match(/(520\d{3,4}|aud\d{3,4}|ora-\d{4,5}|ssh-[a-z]+)/gi) || [];

      const scored = [];
      for (const note of this.notes) {
        if (activeClientId && note.clientId && note.clientId !== 'global' && note.clientId !== activeClientId) {
          continue;
        }
        const titleL = (note.title || '').toLowerCase();
        const contentL = (note.content || '').toLowerCase();
        const tagsL = (note.tags || []).map(t => String(t).toLowerCase());
        const catL = (note.category || '').toLowerCase();

        let score = 0;
        if (!q || q.includes('nota') || q.includes('runbook') || q.includes('procedimiento')) {
          score += 1;
        }
        for (const c of codes) {
          const cl = c.toLowerCase();
          if (tagsL.some(t => t === cl || t.includes(cl))) score += 25;
          if (titleL.includes(cl)) score += 15;
          if (contentL.includes(cl)) score += 10;
        }
        for (const tok of tokens) {
          if (tagsL.some(t => t === tok)) score += 12;
          else if (tagsL.some(t => t.includes(tok))) score += 6;
          if (titleL.includes(tok)) score += 5;
          if (contentL.includes(tok)) score += 3;
          if (catL.includes(tok)) score += 2;
        }
        if (activeClientId && note.clientId === activeClientId) score += 2;
        if (score > 0) scored.push({ note, score });
      }

      scored.sort((a, b) => b.score - a.score);
      return scored.map(s => s.note);
    }

    getAllTags() {
      const counts = {};
      (this.notes || []).forEach(n => {
        (n.tags || []).forEach(t => {
          const key = String(t).trim();
          if (key) counts[key] = (counts[key] || 0) + 1;
        });
      });
      return Object.entries(counts).sort((a, b) => b[1] - a[1]);
    }

    _getActiveAuthor() {
      const sel = document.getElementById('engineer-selector');
      if (sel && sel.options && sel.selectedIndex >= 0) {
        return sel.options[sel.selectedIndex].textContent.trim();
      }
      return 'Tomás Acosta';
    }

    _getActiveClientMeta() {
      const sel = document.getElementById('client-selector');
      const id = sel ? sel.value : 'global';
      const name = (sel && sel.options && sel.selectedIndex >= 0)
        ? sel.options[sel.selectedIndex].textContent.trim()
        : 'Cliente Activo';
      return { id, name };
    }

    _getCategoryStyle(cat) {
      if (cat === 'Procedimiento / Runbook') return { bg: 'rgba(14,165,233,0.12)', color: '#0284c7', border: 'rgba(14,165,233,0.35)' };
      if (cat === 'Incidente Resuelto') return { bg: 'rgba(16,185,129,0.12)', color: '#059669', border: 'rgba(16,185,129,0.35)' };
      if (cat === 'Workaround') return { bg: 'rgba(245,158,11,0.12)', color: '#d97706', border: 'rgba(245,158,11,0.35)' };
      return { bg: 'rgba(99,102,241,0.12)', color: '#4f46e5', border: 'rgba(99,102,241,0.35)' };
    }

    renderPortal(containerId) {
      this.containerId = containerId || this.containerId;
      const container = document.getElementById(this.containerId);
      if (!container) return;

      const editingNote = this.editingId ? this.notes.find(n => n.id === this.editingId) : null;
      const clientMeta = this._getActiveClientMeta();
      const allTags = this.getAllTags();

      const filtered = (this.notes || []).filter(n => {
        if (this.filterCategory !== 'ALL' && n.category !== this.filterCategory) return false;
        if (this.filterTag && !(n.tags || []).some(t => t.toLowerCase() === this.filterTag.toLowerCase())) return false;
        if (this.filterQuery) {
          const q = this.filterQuery.toLowerCase();
          const match = (n.title || '').toLowerCase().includes(q) ||
                        (n.content || '').toLowerCase().includes(q) ||
                        (n.tags || []).some(t => t.toLowerCase().includes(q)) ||
                        (n.author || '').toLowerCase().includes(q);
          if (!match) return false;
        }
        return true;
      });

      const tagsHtml = allTags.length
        ? allTags.slice(0, 20).map(([tag, cnt]) => {
            const active = this.filterTag === tag;
            return `<button type="button" class="btn ${active ? 'btn-primary' : ''}" style="padding:3px 10px; font-size:0.74rem; border-radius:999px; ${active ? '' : 'background:var(--bg-secondary); border:1px solid var(--border-color); color:var(--text-main);'}" onclick="window.notesEngine.toggleTagFilter('${this._escape(tag)}')">#${this._escape(tag)} (${cnt})</button>`;
          }).join(' ')
        : '<span style="font-size:0.78rem; color:var(--text-muted);">Sin etiquetas aún. Agrega etiquetas como <code>520002</code>, <code>ORA-01555</code>, <code>LDAPS</code> al crear una nota.</span>';

      const cardsHtml = filtered.length
        ? filtered.map(n => {
            const st = this._getCategoryStyle(n.category);
            const dateStr = (n.updatedAt || n.createdAt || '').slice(0, 10);
            const scopeLabel = n.clientId === 'global' ? '🌐 Global' : `🏢 ${n.clientName || n.clientId}`;
            const tagsList = (n.tags || []).map(t =>
              `<span onclick="window.notesEngine.toggleTagFilter('${this._escape(t)}')" style="cursor:pointer; background:rgba(14,165,233,0.1); color:#0284c7; border:1px solid rgba(14,165,233,0.25); padding:2px 8px; border-radius:999px; font-size:0.72rem; font-weight:600;">#${this._escape(t)}</span>`
            ).join(' ');

            return `
              <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; padding:14px 16px; margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px; flex-wrap:wrap;">
                  <div>
                    <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:6px;">
                      <span style="background:${st.bg}; color:${st.color}; border:1px solid ${st.border}; padding:2px 8px; border-radius:6px; font-size:0.72rem; font-weight:700;">${this._escape(n.category)}</span>
                      <span style="font-size:0.73rem; color:var(--text-muted);">${this._escape(scopeLabel)} • ${this._escape(n.platform || 'Todas')}</span>
                    </div>
                    <h4 style="margin:0; font-size:0.98rem; color:var(--text-main);">${this._escape(n.title)}</h4>
                  </div>
                  <div style="display:flex; gap:6px; flex-shrink:0;">
                    <button type="button" class="btn" style="padding:4px 9px; font-size:0.74rem; background:rgba(14,165,233,0.12); color:#0284c7; border:1px solid rgba(14,165,233,0.3);" onclick="window.notesEngine.askAiWithNote('${this._escape(n.id)}')">🤖 Consultar IA</button>
                    <button type="button" class="btn" style="padding:4px 9px; font-size:0.74rem; border:1px solid var(--border-color);" onclick="window.notesEngine.startEdit('${this._escape(n.id)}')">✏️ Editar</button>
                    <button type="button" class="btn" style="padding:4px 9px; font-size:0.74rem; color:#dc2626; border:1px solid rgba(220,38,38,0.3);" onclick="window.notesEngine.confirmDelete('${this._escape(n.id)}')">🗑️</button>
                  </div>
                </div>
                <div style="margin:10px 0; font-size:0.84rem; color:var(--text-main); white-space:pre-wrap; line-height:1.45; background:var(--bg-secondary); padding:10px 12px; border-radius:8px; border:1px solid var(--border-color);">${this._escape(n.content)}</div>
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                  <div style="display:flex; gap:6px; flex-wrap:wrap;">${tagsList}</div>
                  <div style="font-size:0.73rem; color:var(--text-muted);">👤 ${this._escape(n.author || 'Especialista')} • 📅 ${this._escape(dateStr)}</div>
                </div>
              </div>`;
          }).join('')
        : `<div style="text-align:center; padding:36px 20px; background:var(--bg-card); border:1px dashed var(--border-color); border-radius:10px; color:var(--text-muted);">
             <div style="font-size:1.6rem; margin-bottom:8px;">📚</div>
             <strong>No hay Notas Técnicas o Procedimientos registrados${this.filterQuery || this.filterTag || this.filterCategory !== 'ALL' ? ' con este filtro' : ''}.</strong><br>
             <span style="font-size:0.82rem;">Crea una nota en el panel izquierdo con etiquetas (ej. <code>520002</code>, <code>ORA-01555</code>, <code>LDAPS</code>) para que <strong>Entrust Forensics AI</strong> la utilice automáticamente en sus análisis.</span>
           </div>`;

      container.innerHTML = `
        <div style="display:grid; grid-template-columns: minmax(320px, 410px) 1fr; gap:18px; align-items:start;">
          <!-- Formulario de Alimentación Web -->
          <div class="card" style="padding:16px; position:sticky; top:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
              <h3 style="margin:0; font-size:1rem; color:var(--text-main);">${editingNote ? '✏️ Editar Nota Técnica' : '➕ Nueva Nota Técnica / Runbook'}</h3>
              ${editingNote ? `<button type="button" class="btn" style="padding:3px 8px; font-size:0.74rem;" onclick="window.notesEngine.cancelEdit()">Cancelar</button>` : ''}
            </div>

            <div style="display:flex; flex-direction:column; gap:10px;">
              <div>
                <label style="display:block; font-size:0.76rem; font-weight:700; margin-bottom:4px;">Título del Procedimiento / Nota *</label>
                <input type="text" id="note-form-title" class="form-control" placeholder="Ej: Solución error 520002 / Pool JDBC Oracle" value="${this._escape(editingNote?.title || '')}">
              </div>

              <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
                <div>
                  <label style="display:block; font-size:0.76rem; font-weight:700; margin-bottom:4px;">Categoría</label>
                  <select id="note-form-category" class="form-control">
                    ${['Nota Técnica', 'Procedimiento / Runbook', 'Incidente Resuelto', 'Workaround'].map(c =>
                      `<option value="${c}" ${editingNote?.category === c ? 'selected' : ''}>${c}</option>`
                    ).join('')}
                  </select>
                </div>
                <div>
                  <label style="display:block; font-size:0.76rem; font-weight:700; margin-bottom:4px;">Plataforma</label>
                  <select id="note-form-platform" class="form-control">
                    ${['Todas', 'IG 11.x', 'IG 12.x', 'IG 13.x', 'IDaaS Cloud', 'Oracle / JDBC', 'Tomcat / TLS'].map(p =>
                      `<option value="${p}" ${editingNote?.platform === p ? 'selected' : ''}>${p}</option>`
                    ).join('')}
                  </select>
                </div>
              </div>

              <div>
                <label style="display:block; font-size:0.76rem; font-weight:700; margin-bottom:4px;">Etiquetas / Códigos vinculados (separados por coma)</label>
                <input type="text" id="note-form-tags" class="form-control" placeholder="520002, ORA-01555, LDAPS, HSM, Tomcat" value="${this._escape((editingNote?.tags || []).join(', '))}">
              </div>

              <div>
                <label style="display:block; font-size:0.76rem; font-weight:700; margin-bottom:4px;">Alcance de Aplicación</label>
                <select id="note-form-scope" class="form-control">
                  <option value="global" ${!editingNote || editingNote.clientId === 'global' ? 'selected' : ''}>🌐 Global (Todos los Clientes)</option>
                  <option value="${this._escape(clientMeta.id)}" ${editingNote && editingNote.clientId === clientMeta.id ? 'selected' : ''}>🏢 Solo ${this._escape(clientMeta.name)}</option>
                </select>
              </div>

              <div>
                <label style="display:block; font-size:0.76rem; font-weight:700; margin-bottom:4px;">Contenido, Diagnóstico y Pasos de Solución *</label>
                <textarea id="note-form-content" class="form-control" rows="7" placeholder="1. Validar parámetro en identityguard.properties...&#10;2. Verificar logs en IG.AUDIT...&#10;3. Acción recomendada...">${this._escape(editingNote?.content || '')}</textarea>
              </div>

              <button type="button" class="btn btn-primary" style="width:100%; font-weight:700;" onclick="window.notesEngine.submitForm()">
                ${editingNote ? '💾 Actualizar Nota en Portal' : '💾 Guardar Nota & Alimentar IA'}
              </button>
            </div>
          </div>

          <!-- Listado y Buscador de Notas -->
          <div>
            <div class="card" style="padding:14px 16px; margin-bottom:14px;">
              <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">
                <input type="text" id="note-search-input" class="form-control" style="flex:1; min-width:200px;" placeholder="🔍 Buscar por título, código, etiqueta o contenido..." value="${this._escape(this.filterQuery)}" oninput="window.notesEngine.onSearchInput(this.value)">
                <select class="form-control" style="width:auto;" onchange="window.notesEngine.onCategoryChange(this.value)">
                  <option value="ALL" ${this.filterCategory === 'ALL' ? 'selected' : ''}>Todas las Categorías</option>
                  <option value="Nota Técnica" ${this.filterCategory === 'Nota Técnica' ? 'selected' : ''}>Nota Técnica</option>
                  <option value="Procedimiento / Runbook" ${this.filterCategory === 'Procedimiento / Runbook' ? 'selected' : ''}>Procedimiento / Runbook</option>
                  <option value="Incidente Resuelto" ${this.filterCategory === 'Incidente Resuelto' ? 'selected' : ''}>Incidente Resuelto</option>
                  <option value="Workaround" ${this.filterCategory === 'Workaround' ? 'selected' : ''}>Workaround</option>
                </select>
                <span style="font-size:0.78rem; color:var(--text-muted); font-weight:700;">${filtered.length} de ${this.notes.length} notas</span>
              </div>
              <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
                <span style="font-size:0.75rem; color:var(--text-muted); font-weight:700;">🏷️ Etiquetas:</span>
                ${tagsHtml}
              </div>
            </div>

            ${cardsHtml}
          </div>
        </div>`;
    }

    async submitForm() {
      const title = document.getElementById('note-form-title')?.value?.trim() || '';
      const category = document.getElementById('note-form-category')?.value || 'Nota Técnica';
      const platform = document.getElementById('note-form-platform')?.value || 'Todas';
      const tagsRaw = document.getElementById('note-form-tags')?.value || '';
      const scopeVal = document.getElementById('note-form-scope')?.value || 'global';
      const content = document.getElementById('note-form-content')?.value?.trim() || '';

      if (!title || !content) {
        alert('Por favor ingresa al menos el Título y el Contenido de la Nota Técnica.');
        return;
      }

      const clientMeta = this._getActiveClientMeta();
      const existing = this.editingId ? this.notes.find(n => n.id === this.editingId) : null;

      await this.saveNote({
        id: existing?.id,
        createdAt: existing?.createdAt,
        title,
        category,
        platform,
        tags: tagsRaw.split(',').map(t => t.trim()).filter(Boolean),
        clientId: scopeVal,
        clientName: scopeVal === 'global' ? 'Global (Todos los Clientes)' : clientMeta.name,
        content,
        author: this._getActiveAuthor()
      });

      this.editingId = null;
      this.renderPortal();
    }

    startEdit(id) {
      this.editingId = id;
      this.renderPortal();
      document.getElementById('note-form-title')?.focus();
    }

    cancelEdit() {
      this.editingId = null;
      this.renderPortal();
    }

    async confirmDelete(id) {
      if (!confirm('¿Eliminar esta Nota Técnica del portal?')) return;
      await this.deleteNote(id);
      if (this.editingId === id) this.editingId = null;
      this.renderPortal();
    }

    toggleTagFilter(tag) {
      this.filterTag = (this.filterTag === tag) ? '' : tag;
      this.renderPortal();
    }

    onSearchInput(val) {
      this.filterQuery = val || '';
      this.renderPortal();
      const inp = document.getElementById('note-search-input');
      if (inp) {
        inp.focus();
        inp.setSelectionRange(inp.value.length, inp.value.length);
      }
    }

    onCategoryChange(val) {
      this.filterCategory = val || 'ALL';
      this.renderPortal();
    }

    askAiWithNote(id) {
      const note = this.notes.find(n => n.id === id);
      if (!note) return;
      const drawer = document.getElementById('copilot-drawer');
      if (drawer && !drawer.classList.contains('open')) {
        drawer.classList.add('open');
      }
      const input = document.getElementById('copilot-input-query');
      const sendBtn = document.getElementById('btn-send-copilot');
      if (input && sendBtn) {
        const tag = (note.tags && note.tags[0]) ? note.tags[0] : note.title;
        input.value = `nota tecnica ${tag}`;
        sendBtn.click();
      }
    }
  }

  window.notesEngine = new NotesEngine();
})();
