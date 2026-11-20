/* Settings -> Lessons. Corrections sent from the popup arrive as pending
   lessons; only approved ones are added to AI prompts. The lessons are stored
   by the local backend, so this page reads and changes them through it. */
(() => {
  const byId = id => document.getElementById(id);
  const status = byId('lessons-status');

  async function request(path, options = {}) {
    const response = await VeiluxBackend.fetch(path, {
      headers: { 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(15000), ...options
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'The backend answered HTTP ' + response.status + '.');
    return data;
  }

  // Edited text is protected with the same rules as everything else.
  async function protectionOptions() {
    const stored = await browser.storage.local.get(['customRegexRules', 'heuristicFieldExclusions', 'heuristicSettings']);
    return { custom_regex_rules: stored.customRegexRules || [], heuristic_field_exclusions: stored.heuristicFieldExclusions || [],
      heuristic_settings: stored.heuristicSettings || {} };
  }

  function button(label, className, onClick) {
    const node = document.createElement('button');
    node.type = 'button'; node.className = 'btn btn-small ' + className; node.textContent = label;
    node.addEventListener('click', onClick);
    return node;
  }

  function lessonCard(lesson) {
    const card = document.createElement('article');
    card.className = 'lesson-card'; card.dataset.lessonId = lesson.id; card.dataset.status = lesson.status;
    const text = document.createElement('p');
    text.className = 'lesson-text'; text.textContent = lesson.lesson;
    const meta = document.createElement('p');
    meta.className = 'field-hint';
    meta.textContent = lesson.created ? 'Sent ' + new Date(lesson.created).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
    const actions = document.createElement('div');
    actions.className = 'lesson-actions';
    const approve = lesson.status === 'approved'
      ? button('Stop using', 'btn-secondary', () => change(lesson.id, { status: 'pending' }, 'Lesson moved back to waiting for approval.'))
      : button('Approve', 'btn-primary', () => change(lesson.id, { status: 'approved' }, 'Lesson approved. New analyses will use it.'));
    const edit = button('Edit', 'btn-secondary', () => {
      const field = document.createElement('textarea');
      field.className = 'lesson-edit'; field.value = lesson.lesson; field.setAttribute('aria-label', 'Lesson text');
      const save = button('Save', 'btn-primary', async () => change(lesson.id, { lesson: field.value, ...(await protectionOptions()) }, 'Lesson saved.'));
      const cancel = button('Cancel', 'btn-secondary', render);
      text.replaceWith(field);
      actions.replaceChildren(save, cancel);
      field.focus();
    });
    let armed = false;
    const remove = button('Delete', 'btn-danger', async () => {
      if (!armed) { armed = true; remove.textContent = 'Click again to delete'; setTimeout(() => { armed = false; remove.textContent = 'Delete'; }, 4000); return; }
      try { await request('/lessons/' + encodeURIComponent(lesson.id), { method: 'DELETE' }); status.textContent = 'Lesson deleted.'; await render(); }
      catch (error) { status.textContent = error.message; }
    });
    actions.append(approve, edit, remove);
    card.append(text, meta, actions);
    return card;
  }

  async function change(id, body, done) {
    try {
      await request('/lessons/' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify(body) });
      status.textContent = done;
      await render();
    } catch (error) { status.textContent = error.message; }
  }

  function fill(list, lessons, empty) {
    if (!lessons.length) {
      const note = document.createElement('p');
      note.className = 'field-hint'; note.textContent = empty;
      list.replaceChildren(note);
    } else list.replaceChildren(...lessons.map(lessonCard));
  }

  async function render() {
    try {
      const { lessons, prompt_limit: limit } = await request('/lessons');
      const approved = lessons.filter(lesson => lesson.status === 'approved');
      fill(byId('lessons-pending'), lessons.filter(lesson => lesson.status !== 'approved').reverse(), 'No corrections are waiting.');
      fill(byId('lessons-approved'), approved.slice().reverse(), 'No approved lessons yet. Approved lessons are added to every new analysis.');
      if (approved.length > limit) status.textContent = 'Only the ' + limit + ' most recent approved lessons are used in prompts.';
    } catch (error) {
      const message = error.name === 'TimeoutError' || error instanceof TypeError
        ? 'Could not reach the local backend. Start it with "python server.py", then reload lessons.' : error.message;
      byId('lessons-pending').replaceChildren(); byId('lessons-approved').replaceChildren();
      status.textContent = message;
    }
  }

  byId('lessons-reload').addEventListener('click', () => { status.textContent = ''; render(); });
  render();
})();
