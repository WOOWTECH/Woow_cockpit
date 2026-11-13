/* Match Cockpit's shell:style preference and OS theme, including live changes.
 * See cockpit/pkg/lib/cockpit-dark-theme.ts (LGPL-2.1-or-later). */
(() => {
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  function applyTheme(override) {
    let preference = override;
    if (!preference) {
      try { preference = localStorage.getItem('shell:style'); } catch { /* use system preference */ }
    }
    preference ||= 'auto';
    document.documentElement.classList.toggle('pf-v6-theme-dark',
      preference === 'dark' || (preference === 'auto' && system.matches));
  }
  window.addEventListener('storage', event => {
    if (event.key === 'shell:style' || event.key === null) applyTheme();
  });
  window.addEventListener('cockpit-style', event => applyTheme(event.detail?.style));
  system.addEventListener('change', () => applyTheme());
  applyTheme();
})();
