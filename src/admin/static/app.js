/* Capybara_AI Admin — vanilla UI wiring. No frameworks, no animation libraries.
   Handles: theme persistence, mobile sidebar, and toast notifications. All
   visual motion is CSS; this file only toggles classes and inserts nodes. */
(function () {
  'use strict';

  // ── Theme (dark default, persisted light toggle) ──────────────────────
  var KEY = 'capy-theme';
  var root = document.documentElement;
  try {
    if (localStorage.getItem(KEY) === 'light') root.setAttribute('data-theme', 'light');
  } catch (e) { /* storage unavailable — stay on default dark */ }

  function toggleTheme() {
    var light = root.getAttribute('data-theme') === 'light';
    if (light) { root.removeAttribute('data-theme'); persist('dark'); }
    else { root.setAttribute('data-theme', 'light'); persist('light'); }
  }
  function persist(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* ignore */ } }

  // ── Mobile sidebar ────────────────────────────────────────────────────
  function toggleNav() { document.body.classList.toggle('nav-open'); }
  function closeNav() { document.body.classList.remove('nav-open'); }

  document.addEventListener('click', function (e) {
    var t = e.target.closest('[data-action]');
    if (!t) return;
    var a = t.getAttribute('data-action');
    if (a === 'theme') toggleTheme();
    else if (a === 'nav') toggleNav();
    else if (a === 'nav-close') closeNav();
  });

  // ── Toasts ──────────────────────────────────────────────────────────
  var ICONS = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></svg>'
  };

  function toast(type, msg) {
    var box = document.getElementById('toasts');
    if (!box) return;
    type = ICONS[type] ? type : 'success';
    var el = document.createElement('div');
    el.className = 'toast ' + type;
    el.setAttribute('role', 'status');
    el.innerHTML = ICONS[type] + '<div class="msg"></div>';
    el.querySelector('.msg').textContent = msg;
    box.appendChild(el);
    setTimeout(function () {
      el.classList.add('out');
      el.addEventListener('animationend', function () { el.remove(); });
    }, 4200);
  }
  window.capyToast = toast;

  // ── htmx integration (loaded as a global if present) ──────────────────
  document.body.addEventListener('htmx:afterRequest', function (evt) {
    var el = evt.detail.elt;
    var ok = evt.detail.successful;
    var okMsg = el && el.getAttribute('data-toast-success');
    var errMsg = (el && el.getAttribute('data-toast-error')) || 'Aktion fehlgeschlagen.';
    if (ok && okMsg) toast('success', okMsg);
    else if (!ok) toast('error', errMsg);
  });

  // Server-driven toast via response header:  HX-Trigger: {"capy:toast":{"type":"warning","msg":"…"}}
  document.body.addEventListener('capy:toast', function (evt) {
    var d = evt.detail || {};
    toast(d.type || 'success', d.msg || '');
  });

  document.body.addEventListener('htmx:responseError', function () {
    toast('error', 'Serverfehler — bitte erneut versuchen.');
  });
})();
