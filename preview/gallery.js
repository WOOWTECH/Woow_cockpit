/* Icons and missing local captures. No remote assets or inline scripts needed. */
document.querySelectorAll('[data-mdi]').forEach(el => {
  const path = window.woowtechMdiPaths?.[el.dataset.mdi];
  if (!path) return;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const shape = document.createElementNS(svg.namespaceURI, 'path');
  shape.setAttribute('d', path);
  svg.append(shape);
  el.append(svg);
});
document.querySelectorAll('figure img').forEach(img => {
  function missing() {
    const figure = img.closest('figure');
    if (figure.querySelector('.missing-shot')) return;
    const note = document.createElement('div');
    note.className = 'missing-shot';
    note.setAttribute('role', 'note');
    note.textContent = '尚未建立此設備的畫面紀錄';
    const link = img.closest('.shot-link');
    if (link) link.hidden = true;
    else img.hidden = true;
    figure.prepend(note);
    figure.querySelectorAll('.open,.preview-note').forEach(el => { el.hidden = true; });
    const state = figure.querySelector('.state');
    if (state) state.textContent = '待擷取';
  }
  img.addEventListener('error', missing);
  if (img.complete && !img.naturalWidth) missing();
});
