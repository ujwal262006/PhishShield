/* PhishShield front-end behaviors (dependency-free, progressive enhancement).
   Modules: theme, toasts, sidebar, user menu, indicators, modals, command palette. */
(function () {
  "use strict";

  /* ---------- Theme (dark/light, persisted + system preference) ---------- */
  const THEME_KEY = "phishshield-theme";
  const root = document.documentElement;

  function systemPref() {
    return window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    const icon = document.querySelector("[data-theme-icon]");
    if (icon) icon.textContent = theme === "light" ? "\u263E" : "\u2600"; // moon / sun
  }
  function initTheme() {
    const stored = localStorage.getItem(THEME_KEY);
    applyTheme(stored || systemPref());
  }
  window.PhishShield = window.PhishShield || {};
  window.PhishShield.toggleTheme = function () {
    const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
    toast("Theme set to " + next + " mode", "info");
  };
  window.PhishShield.setTheme = function (theme) {
    localStorage.setItem(THEME_KEY, theme);
    applyTheme(theme);
  };
  initTheme();

  document.addEventListener("click", function (e) {
    const t = e.target.closest("[data-theme-toggle]");
    if (t) { e.preventDefault(); window.PhishShield.toggleTheme(); return; }
    const s = e.target.closest("[data-set-theme]");
    if (s) { e.preventDefault(); window.PhishShield.setTheme(s.getAttribute("data-set-theme")); }
  });

  /* ---------- Toasts ---------- */
  function ensureToastWrap() {
    let w = document.querySelector(".toast-wrap");
    if (!w) { w = document.createElement("div"); w.className = "toast-wrap"; document.body.appendChild(w); }
    return w;
  }
  function toast(message, type) {
    const w = ensureToastWrap();
    const el = document.createElement("div");
    el.className = "toast " + (type || "info");
    el.setAttribute("role", "status");
    el.textContent = message;
    w.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      el.style.transform = "translateY(10px)";
      setTimeout(function () { el.remove(); }, 220);
    }, 4000);
  }
  window.PhishShield.toast = toast;

  // Convert server flash messages (data attributes) into toasts.
  document.querySelectorAll("[data-flash]").forEach(function (n) {
    toast(n.getAttribute("data-flash"), n.getAttribute("data-flash-type") || "info");
  });

  /* ---------- Sidebar (mobile) ---------- */
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-sidebar-toggle]")) {
      document.querySelector(".sidebar") && document.querySelector(".sidebar").classList.toggle("open");
      document.querySelector(".sidebar-backdrop") && document.querySelector(".sidebar-backdrop").classList.toggle("open");
    }
    if (e.target.classList.contains("sidebar-backdrop")) {
      e.target.classList.remove("open");
      document.querySelector(".sidebar").classList.remove("open");
    }
  });

  /* ---------- User menu ---------- */
  document.addEventListener("click", function (e) {
    const trigger = e.target.closest(".usermenu-trigger");
    const panel = document.querySelector(".usermenu-panel");
    if (trigger && panel) { e.stopPropagation(); panel.classList.toggle("open"); return; }
    if (panel && !e.target.closest(".usermenu-panel")) panel.classList.remove("open");
  });

  /* ---------- Expandable indicators ---------- */
  document.addEventListener("click", function (e) {
    const head = e.target.closest(".indicator .head");
    if (head) head.parentElement.classList.toggle("open");
  });

  /* ---------- Confirmation modals ---------- */
  // <form data-confirm="Message"> ... </form>
  document.addEventListener("submit", function (e) {
    const form = e.target.closest("form[data-confirm]");
    if (!form || form.dataset.confirmed === "1") return;
    e.preventDefault();
    showConfirm(form.getAttribute("data-confirm"), function () {
      form.dataset.confirmed = "1";
      form.submit();
    });
  });
  function showConfirm(message, onYes) {
    let backdrop = document.querySelector(".modal-backdrop#confirm-modal");
    if (!backdrop) {
      backdrop = document.createElement("div");
      backdrop.className = "modal-backdrop";
      backdrop.id = "confirm-modal";
      backdrop.innerHTML =
        '<div class="modal" role="dialog" aria-modal="true">' +
        '<h3>Please confirm</h3><p class="modal-msg muted"></p>' +
        '<div class="modal-actions">' +
        '<button class="btn btn-ghost" data-modal-cancel>Cancel</button>' +
        '<button class="btn btn-danger" data-modal-ok>Confirm</button>' +
        "</div></div>";
      document.body.appendChild(backdrop);
    }
    backdrop.querySelector(".modal-msg").textContent = message;
    backdrop.classList.add("open");
    const ok = backdrop.querySelector("[data-modal-ok]");
    const cancel = backdrop.querySelector("[data-modal-cancel]");
    function close() { backdrop.classList.remove("open"); ok.onclick = null; cancel.onclick = null; }
    ok.onclick = function () { close(); onYes(); };
    cancel.onclick = close;
    backdrop.onclick = function (ev) { if (ev.target === backdrop) close(); };
  }
  window.PhishShield.confirm = showConfirm;

  /* ---------- Command palette (Ctrl/Cmd + K) ---------- */
  const paletteData = window.PHISHSHIELD_COMMANDS || [];
  let paletteEl = null, activeIdx = 0, filtered = [];

  function buildPalette() {
    paletteEl = document.createElement("div");
    paletteEl.className = "cmdk-backdrop";
    paletteEl.innerHTML =
      '<div class="cmdk" role="dialog" aria-modal="true" aria-label="Command palette">' +
      '<input type="text" placeholder="Type a command or page..." aria-label="Command search" />' +
      '<div class="cmdk-list"></div></div>';
    document.body.appendChild(paletteEl);
    const input = paletteEl.querySelector("input");
    input.addEventListener("input", function () { renderPalette(input.value); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); activeIdx = Math.min(activeIdx + 1, filtered.length - 1); renderList(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); renderList(); }
      else if (e.key === "Enter") { e.preventDefault(); if (filtered[activeIdx]) window.location.href = filtered[activeIdx].url; }
      else if (e.key === "Escape") { closePalette(); }
    });
    paletteEl.addEventListener("click", function (e) { if (e.target === paletteEl) closePalette(); });
  }
  function renderPalette(q) {
    q = (q || "").toLowerCase();
    filtered = paletteData.filter(function (c) { return c.label.toLowerCase().indexOf(q) !== -1; });
    activeIdx = 0; renderList();
  }
  function renderList() {
    const list = paletteEl.querySelector(".cmdk-list");
    list.innerHTML = filtered.map(function (c, i) {
      return '<div class="cmdk-item ' + (i === activeIdx ? "active" : "") + '" data-url="' + c.url + '">' +
        '<span class="ic">' + (c.icon || "\u2192") + "</span><span>" + c.label + "</span></div>";
    }).join("") || '<div class="cmdk-item">No matches</div>';
    list.querySelectorAll("[data-url]").forEach(function (item) {
      item.addEventListener("click", function () { window.location.href = item.getAttribute("data-url"); });
    });
  }
  function openPalette() {
    if (!paletteData.length) return;
    if (!paletteEl) buildPalette();
    paletteEl.classList.add("open");
    renderPalette("");
    const input = paletteEl.querySelector("input");
    input.value = ""; input.focus();
  }
  function closePalette() { if (paletteEl) paletteEl.classList.remove("open"); }

  document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); openPalette(); }
  });
  document.querySelectorAll("[data-cmdk-open]").forEach(function (b) {
    b.addEventListener("click", function (e) { e.preventDefault(); openPalette(); });
  });

  /* ---------- Scanner form: real loading state ---------- */
  const scanForm = document.querySelector("form[data-scan-form]");
  if (scanForm) {
    scanForm.addEventListener("submit", function (e) {
      const input = scanForm.querySelector('input[name="url"]');
      if (input && input.value.trim().length > 2048) {
        e.preventDefault(); toast("That URL is too long to analyze (max 2048 characters).", "danger"); return;
      }
      const btn = scanForm.querySelector('button[type="submit"]');
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Analyzing...'; }
    });
  }
})();
