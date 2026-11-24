// Blocking theme initializer + two-state theme toggle + popover fallback for KaiCorp Account.
(function () {
  var KEY = "color-scheme";
  var meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    try {
      var initial = localStorage.getItem(KEY);
      meta.content = (initial === "light" || initial === "dark") ? initial : "light dark";
    } catch (_) {}
  }

  function syncFromStorage() {
    var m = document.querySelector('meta[name="color-scheme"]');
    if (!m) return;
    try {
      var s = localStorage.getItem(KEY);
      m.content = (s === "light" || s === "dark") ? s : "light dark";
    } catch (_) {
      m.content = "light dark";
    }
  }

  function wireControls() {
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.addEventListener("click", function () {
        var m = document.querySelector('meta[name="color-scheme"]');
        var sys = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
        var stored = null;
        try { stored = localStorage.getItem(KEY); } catch (_) {}
        var current = (stored === "light" || stored === "dark") ? stored : sys;
        var target = current === "dark" ? "light" : "dark";
        if (target === sys) {
          try { localStorage.removeItem(KEY); } catch (_) {}
          if (m) m.content = "light dark";
        } else {
          try { localStorage.setItem(KEY, target); } catch (_) {}
          if (m) m.content = target;
        }
      });
    }

    var switcherBtn = document.querySelector('[popovertarget="kc-app-switcher"]');
    var switcherPanel = document.getElementById("kc-app-switcher");
    if (switcherBtn && switcherPanel) {
      var hasPopover = typeof HTMLElement !== "undefined" && Object.hasOwn(HTMLElement.prototype, "popover");
      if (hasPopover) {
        switcherPanel.addEventListener("toggle", function (ev) {
          switcherBtn.setAttribute("aria-expanded", ev.newState === "open" ? "true" : "false");
        });
      } else {
        switcherBtn.addEventListener("click", function (ev) {
          ev.stopPropagation();
          var open = !switcherPanel.classList.contains(":popover-open");
          switcherPanel.classList.toggle(":popover-open", open);
          switcherBtn.setAttribute("aria-expanded", open ? "true" : "false");
        });
        document.addEventListener("click", function (ev) {
          if (switcherPanel.classList.contains(":popover-open") && !switcherPanel.contains(ev.target) && ev.target !== switcherBtn) {
            switcherPanel.classList.remove(":popover-open");
            switcherBtn.setAttribute("aria-expanded", "false");
          }
        });
        document.addEventListener("keydown", function (ev) {
          if (ev.key === "Escape" && switcherPanel.classList.contains(":popover-open")) {
            switcherPanel.classList.remove(":popover-open");
            switcherBtn.setAttribute("aria-expanded", "false");
          }
        });
      }
    }
  }

  window.addEventListener("storage", function (ev) {
    if (ev.key === KEY || ev.key === null) syncFromStorage();
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wireControls);
  } else {
    wireControls();
  }
})();
