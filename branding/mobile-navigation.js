/* Adds a mobile shortcut to Cockpit's existing tools group. */
(() => {
  'use strict';
  const mobile = window.matchMedia('(max-width: 767px)');
  const mdiTune = 'M8 13C6.14 13 4.59 14.28 4.14 16H2V18H4.14C4.59 19.72 6.14 21 8 21S11.41 19.72 11.86 18H22V16H11.86C11.41 14.28 9.86 13 8 13M8 19C6.9 19 6 18.1 6 17C6 15.9 6.9 15 8 15S10 15.9 10 17C10 18.1 9.1 19 8 19M19.86 6C19.41 4.28 17.86 3 16 3S12.59 4.28 12.14 6H2V8H12.14C12.59 9.72 14.14 11 16 11S19.41 9.72 19.86 8H22V6H19.86M16 9C14.9 9 14 8.1 14 7C14 5.9 14.9 5 16 5S18 5.9 18 7C18 8.1 17.1 9 16 9Z';
  let mode = 'system';
  let groupIds;

  function groups() {
    const sections = [...document.querySelectorAll('#host-apps nav.pf-v6-c-nav > section')];
    if (!groupIds && sections.length >= 2) {
      const ids = sections.slice(0, 2).map(section => section.getAttribute('aria-labelledby'));
      if (ids.every(Boolean) && ids[0] !== ids[1]) groupIds = { system: ids[0], tools: ids[1] };
    }
    const found = {};
    for (const section of sections) {
      const id = section.getAttribute('aria-labelledby');
      const kind = groupIds && Object.keys(groupIds).find(key => groupIds[key] === id);
      if (kind) { section.dataset.woowNavGroup = kind; found[kind] = section; }
    }
    return found;
  }
  function selectMode(next) {
    if (mode !== next) {
      const input = document.querySelector('#host-apps .search input');
      if (input?.value) {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, '');
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }
    mode = next;
    const main = document.getElementById('main');
    if (main) main.dataset.woowMenuSection = mode;
    requestAnimationFrame(() => requestAnimationFrame(() => groups()[mode]?.scrollIntoView({ block: 'start', inline: 'nearest', behavior: 'instant' })));
  }
  function syncExpanded() {
    const nav = document.getElementById('nav-system');
    const button = document.getElementById('woow-mobile-tools');
    if (button) button.setAttribute('aria-expanded', String(!!nav && nav.classList.contains('interact') && mode === 'tools'));
  }
  function install() {
    const container = document.getElementById('sidebar-toggle');
    const system = document.getElementById('nav-system-item');
    const nav = document.getElementById('nav-system');
    const available = groups();
    if (!container || !system || !nav || !groupIds) return;
    if (!document.getElementById('woow-mobile-tools')) {
      const tools = available.tools;
      if (!tools) return;
      const button = system.cloneNode(true);
      button.id = 'woow-mobile-tools';
      button.removeAttribute('data-ouia-component-id');
      button.setAttribute('aria-controls', 'nav-system');
      button.setAttribute('aria-expanded', 'false');
      button.querySelector('.pf-v6-c-button__text').textContent = tools.querySelector('h2')?.textContent || 'Tools';
      const icon = button.querySelector('svg');
      icon.setAttribute('viewBox', '0 0 24 24');
      icon.querySelector('path').setAttribute('d', mdiTune);
      button.addEventListener('click', event => {
        event.stopPropagation();
        if (!mobile.matches) return;
        const open = nav.classList.contains('interact');
        if (open && mode === 'tools') { system.click(); return; }
        selectMode('tools');
        if (!open) system.click();
        syncExpanded();
      });
      container.append(button);
      document.getElementById('main')?.setAttribute('data-woow-mobile-tools-ready', '');
      selectMode('system');
    }
    if (!system.dataset.woowMobileListener) {
      system.dataset.woowMobileListener = 'true';
      system.addEventListener('click', event => {
        if (!event.isTrusted || !mobile.matches) return;
        if (nav.classList.contains('interact') && mode === 'tools') {
          event.stopImmediatePropagation();
          selectMode('system');
          syncExpanded();
          return;
        }
        selectMode('system');
      }, true);
    }
    syncExpanded();
  }
  const observer = new MutationObserver(install);
  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });
  install();
})();
