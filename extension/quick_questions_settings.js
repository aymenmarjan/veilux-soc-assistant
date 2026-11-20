/* Settings -> Prompts -> Quick questions for the popup's Ask tab. */
(() => {
  const Q = VeiluxQuickQuestions;
  const box = document.getElementById('quick-questions');
  const status = document.getElementById('quick-questions-status');
  const show = async () => { box.value = (await Q.load()).join('\n'); };
  document.getElementById('quick-questions-save').addEventListener('click', async () => {
    await Q.save(box.value.split('\n'));
    await show();
    status.textContent = 'Quick questions saved.';
  });
  document.getElementById('quick-questions-reset').addEventListener('click', async () => {
    await Q.reset();
    await show();
    status.textContent = 'Default questions restored.';
  });
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes[Q.KEY] && document.activeElement !== box) show();
  });
  show();
})();
