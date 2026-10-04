"use strict";
const menu = document.querySelector(".menu-toggle");
if (menu) {
  menu.addEventListener("click", () => {
    const expanded = menu.getAttribute("aria-expanded") !== "true";
    menu.setAttribute("aria-expanded", String(expanded));
    document.body.classList.toggle("nav-open", expanded);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.getAttribute("aria-expanded") === "true") {
      menu.setAttribute("aria-expanded", "false");
      document.body.classList.remove("nav-open");
      menu.focus();
    }
  });
}

const scanProgress = document.querySelector('[data-scan-status-url]');
if (scanProgress) {
  const endpoint = scanProgress.dataset.scanStatusUrl;
  const startingProgress = Number(document.querySelector('#scan-progress').value);
  let failures = 0;
  async function pollScan() {
    try {
      const response = await fetch(endpoint, {headers: {'Accept': 'application/json'}});
      if (!response.ok) throw new Error('Status unavailable');
      const state = await response.json();
      failures = 0;
      document.querySelector('#scan-progress').value = state.progress;
      document.querySelector('#progress-label').textContent = `${state.status} · ${state.progress}%`;
      document.querySelector('#poll-state').textContent = 'UPDATING AUTOMATICALLY';
      if (state.progress !== startingProgress || ['Completed','Failed'].includes(state.status)) {
        window.location.reload();
        return;
      }
    } catch (_) {
      failures += 1;
      document.querySelector('#poll-state').textContent = 'STATUS UNAVAILABLE — RETRYING';
    }
    window.setTimeout(pollScan, Math.min(15000, 1500 * (failures + 1)));
  }
  window.setTimeout(pollScan, 1500);
}

// Keep the submitted button's name/value in the request and prevent duplicate jobs.
document.querySelectorAll('form[method="post"]').forEach((form) => {
  let submitted = false;
  form.addEventListener('submit', (event) => {
    if (event.defaultPrevented) return;
    if (submitted) { event.preventDefault(); return; }
    submitted = true;
    form.setAttribute('aria-busy', 'true');
    const status = document.createElement('p');
    status.className = 'form-progress';
    status.setAttribute('role', 'status');
    status.textContent = 'Processing request…';
    form.appendChild(status);
  });
});
window.addEventListener('pageshow', (event) => {
  if (event.persisted && document.querySelector('form[aria-busy="true"]')) window.location.reload();
});

// Copy trusted solution text as plain text, never interpreted markup.
document.querySelectorAll('[data-copy-solution]').forEach(button => {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copySolution);
    const status = button.closest('.solution-card').querySelector('[data-copy-status]');
    try {
      await navigator.clipboard.writeText(code.textContent);
      status.textContent = 'Code copied. Adapt the example and test it before applying.';
    } catch (_) {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges(); selection.addRange(range);
      status.textContent = 'Code selected. Press Ctrl+C or Command+C to copy.';
    }
  });
});

// Preserve deep links when their destination is inside collapsed evidence.
function revealFindingAnchor() {
  let id;
  try { id = decodeURIComponent(window.location.hash.slice(1)); } catch (_) { return; }
  const target = document.getElementById(id);
  if (!target) return;
  for (let parent = target.parentElement; parent; parent = parent.parentElement) {
    if (parent.tagName === 'DETAILS') parent.open = true;
  }
}
window.addEventListener('hashchange', revealFindingAnchor);
revealFindingAnchor();
