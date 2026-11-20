/* Settings -> Email reports: create, edit, import, export and preview report
   templates, and choose the default. Templates are stored in this browser
   (see report_templates.js); the built-in one is read-only but can be copied. */
(() => {
  const R = VeiluxReports;
  const byId = id => document.getElementById(id);
  const editor = byId('report-editor'), list = byId('report-template-list'), status = byId('report-status');
  let editing = null; // the template being edited (a copy), or null

  const say = (text, isError = false) => { status.textContent = text; status.style.color = isError ? 'var(--danger)' : ''; };

  function download(name, text) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const fileName = name => 'veilux-report-' + (name || 'template').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '.json';

  function button(label, className, onClick, extra = {}) {
    const node = Object.assign(document.createElement('button'), { type: 'button', className: 'btn btn-small ' + className, textContent: label, ...extra });
    node.addEventListener('click', onClick);
    return node;
  }

  async function renderList() {
    const { templates, defaultId } = await R.all();
    const select = byId('report-default');
    select.replaceChildren(...templates.map(t => new Option(t.name + (t.builtin ? ' (built-in)' : ''), t.id)));
    select.value = defaultId;
    list.replaceChildren(...templates.map(template => {
      const card = document.createElement('article');
      card.className = 'report-template-card'; card.dataset.templateId = template.id;
      const title = document.createElement('div');
      title.className = 'report-template-title';
      title.textContent = template.name + (template.id === defaultId ? ' · default' : '');
      const meta = document.createElement('div');
      meta.className = 'field-hint';
      meta.textContent = [template.builtin ? 'Built-in, read-only' : 'Your template', template.language,
        template.severities.map(level => level.name).join(' / '), 'Subject: ' + template.subjectPattern].join(' · ');
      const scale = document.createElement('div');
      scale.className = 'report-scale';
      template.severities.forEach(level => {
        const chip = document.createElement('span');
        chip.className = 'report-scale-chip'; chip.textContent = level.name; chip.style.background = level.color;
        scale.append(chip);
      });
      const actions = document.createElement('div');
      actions.className = 'lesson-actions';
      if (!template.builtin) actions.append(button('Edit', 'btn-secondary', () => openEditor(template)));
      actions.append(button(template.builtin ? 'Copy to customize' : 'Duplicate', 'btn-secondary', () =>
        openEditor({ ...template, id: null, builtin: false, name: template.name + ' (copy)' })));
      actions.append(button('Preview', 'btn-secondary', () => showPreview(template, card)));
      if (!template.builtin) {
        actions.append(button('Export', 'btn-secondary', () => download(fileName(template.name), R.exportFile(template))));
        let armed = false;
        const remove = button('Delete', 'btn-danger', async () => {
          if (!armed) { armed = true; remove.textContent = 'Click again to delete'; setTimeout(() => { armed = false; remove.textContent = 'Delete'; }, 4000); return; }
          const { templates: current, defaultId: chosen } = await R.all();
          await R.saveOwn(current.filter(t => t.id !== template.id));
          if (chosen === template.id) await R.setDefault(R.BUILTIN_ID);
          say('Template deleted.');
          if (editing && editing.id === template.id) closeEditor();
          renderList();
        });
        actions.append(remove);
      }
      card.append(title, scale, meta, actions);
      return card;
    }));
  }

  // A sandboxed frame shows the template filled with sample data; scripts never run.
  function showPreview(template, after) {
    let frame = after.querySelector('iframe');
    if (frame) { frame.remove(); return; }
    frame = Object.assign(document.createElement('iframe'), { className: 'report-preview-frame', title: 'Preview of ' + template.name });
    frame.setAttribute('sandbox', '');
    try { frame.srcdoc = R.sample(template).html; after.append(frame); }
    catch (error) { say(error.message, true); }
  }

  // ---- Severity rows ----
  function severityRow(level = { name: '', color: '#64748B' }) {
    const row = document.createElement('div');
    row.className = 'severity-row-edit';
    const name = Object.assign(document.createElement('input'), { type: 'text', value: level.name, placeholder: 'Level name' });
    name.setAttribute('aria-label', 'Severity level name');
    const color = Object.assign(document.createElement('input'), { type: 'color', value: level.color });
    color.setAttribute('aria-label', 'Colour of this level');
    const up = button('↑', 'btn-secondary', () => { if (row.previousElementSibling) row.parentNode.insertBefore(row, row.previousElementSibling); }, { title: 'Move up' });
    up.setAttribute('aria-label', 'Move this level up');
    const remove = button('Remove', 'btn-secondary', () => row.remove());
    row.append(name, color, up, remove);
    return row;
  }
  const readSeverities = () => Array.from(byId('report-severities').children).map(row => {
    const [name, color] = row.querySelectorAll('input');
    return { name: name.value.trim(), color: color.value };
  }).filter(level => level.name);

  function updateFieldsPreview() {
    const draft = { subjectPattern: byId('report-subject').value, html: byId('report-html').value };
    const fields = R.customFields(draft), written = R.aiFields(draft);
    byId('report-fields-preview').textContent = (fields.length
      ? 'Extra fields on the report page: ' + fields.map(R.fieldLabel).join(', ') + '.'
      : 'No extra fields: the report page asks only for title, case ID and severity.')
      + (written.length ? ' Written by the AI: ' + written.map(name => R.fieldLabel(name.slice(3))).join(', ') + '.' : '');
  }

  function fromForm() {
    return R.normalize({ ...editing, name: byId('report-name').value, language: byId('report-language').value,
      severities: readSeverities(), subjectPattern: byId('report-subject').value.trim(),
      caseIdPlaceholder: byId('report-case-placeholder').value, instructions: byId('report-instructions').value,
      html: byId('report-html').value, keepMasked: byId('report-keep-masked').checked });
  }

  function openEditor(template) {
    editing = { ...template };
    byId('report-editor-title').textContent = template.id ? 'Edit template' : 'New template';
    byId('report-name').value = template.name || '';
    byId('report-language').value = template.language || 'English';
    byId('report-severities').replaceChildren(...(template.severities || R.DEFAULT_SEVERITIES).map(severityRow));
    byId('report-subject').value = template.subjectPattern || '';
    byId('report-case-placeholder').value = template.caseIdPlaceholder ?? '[Case ID]';
    byId('report-instructions').value = template.instructions || R.DEFAULT_INSTRUCTIONS;
    byId('report-html').value = template.html || '';
    byId('report-keep-masked').checked = !!template.keepMasked;
    byId('report-preview-frame').hidden = true;
    editor.hidden = false; editor.classList.add('visible');
    updateFieldsPreview();
    byId('report-name').focus();
    editor.scrollIntoView({ block: 'start' });
  }
  function closeEditor() { editing = null; editor.hidden = true; editor.classList.remove('visible'); }

  byId('report-new').addEventListener('click', () => openEditor({ ...R.BUILTIN, id: null, builtin: false, name: '' }));
  byId('report-cancel').addEventListener('click', () => { closeEditor(); say(''); });
  byId('report-add-severity').addEventListener('click', () => {
    const row = severityRow(); byId('report-severities').append(row); row.querySelector('input').focus();
  });
  byId('report-reset-instructions').addEventListener('click', () => { byId('report-instructions').value = R.DEFAULT_INSTRUCTIONS; });
  byId('report-subject').addEventListener('input', updateFieldsPreview);
  byId('report-html').addEventListener('input', updateFieldsPreview);
  byId('report-import-html').addEventListener('click', () => byId('report-import-html-file').click());
  byId('report-import-html-file').addEventListener('change', async event => {
    const file = event.target.files[0]; event.target.value = '';
    if (!file) return;
    if (file.size > R.MAX_TEMPLATE_CHARS * 2) return say('That HTML file is too large for a template.', true);
    byId('report-html').value = await file.text();
    updateFieldsPreview();
    say('HTML imported. Replace the example values in it with placeholders such as {{title}}, then preview.');
  });
  byId('report-preview').addEventListener('click', () => {
    const template = fromForm(), frame = byId('report-preview-frame');
    const problems = R.validate(template);
    if (problems.length) return say(problems.map(p => p[1]).join(' '), true);
    frame.srcdoc = R.sample(template).html; frame.hidden = false;
    say('Preview with sample data. Subject: ' + R.sample(template).subject);
  });
  byId('report-save').addEventListener('click', async () => {
    const template = fromForm();
    const problems = R.validate(template);
    if (problems.length) return say(problems.map(p => p[1]).join(' '), true);
    const { templates } = await R.all();
    const own = templates.filter(t => !t.builtin);
    const index = own.findIndex(t => t.id === template.id);
    if (index >= 0) own[index] = template; else own.push(template);
    await R.saveOwn(own);
    closeEditor();
    say('Template "' + template.name + '" saved.');
    renderList();
  });
  byId('report-default').addEventListener('change', async event => {
    await R.setDefault(event.target.value);
    say('Default template changed.');
    renderList();
  });
  byId('report-import').addEventListener('click', () => byId('report-import-file').click());
  byId('report-import-file').addEventListener('change', async event => {
    const file = event.target.files[0]; event.target.value = '';
    if (!file) return;
    try {
      const template = R.importFile(await file.text());
      const { templates } = await R.all();
      await R.saveOwn(templates.filter(t => !t.builtin).concat([template]));
      say('Imported "' + template.name + '".');
      renderList();
    } catch (error) { say(error.message, true); }
  });
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes.reportTemplates || changes.defaultReportTemplateId)) renderList();
  });
  renderList();
})();
