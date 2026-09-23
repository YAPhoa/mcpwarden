(() => {
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const valid = value => ['light', 'dark', 'system'].includes(value) ? value : 'system';
  let preference = 'system';
  try { preference = valid(localStorage.getItem('mcpwarden-theme')); } catch (_) {}
  function apply() {
    document.documentElement.dataset.theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    document.querySelectorAll('[data-theme-picker]').forEach(control => {
      if (control.type === 'radio') control.checked = control.value === preference;
      else control.value = preference;
    });
    const hint=document.getElementById('system-theme-help');if(hint)hint.textContent='System follows your device · '+(media.matches?'Dark':'Light')+'. Preferences are saved only in this browser.';
    document.querySelectorAll('[data-theme-label]').forEach(label => { label.textContent = preference[0].toUpperCase() + preference.slice(1); });
  }
  apply();
  media.addEventListener('change', apply);
  window.addEventListener('storage', event => { if (event.key === 'mcpwarden-theme' || event.key === null) { preference = valid(event.newValue); apply(); } });
  document.addEventListener('DOMContentLoaded', () => {
    apply();
    document.querySelectorAll('[data-theme-picker]').forEach(control => control.addEventListener('change', () => {
      preference = valid(control.value);
      try { localStorage.setItem('mcpwarden-theme', preference); } catch (_) {}
      apply();
    }));
  });
})();
