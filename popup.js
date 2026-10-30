/* popup.js — логика попапа расширения. Общается с background.js через runtime.sendMessage. */
"use strict";

const $ = (id) => document.getElementById(id);

const STATE_TEXT = {
  running: "Работает",
  stopped: "Остановлен",
  starting: "Запуск…",
  error: "Ошибка",
  external: "Порт занят",
  unknown: "Нет связи"
};

let snap = null;
let formTouched = false;
let logTimer = null;
let busy = false;

/* ------------------------------------------------- тестовый хук (live-check)
 * Не влияет на работу попапа: собирает последние ошибки и снимок состояния,
 * чтобы автоматическая проверка в настоящем Firefox (tests/firefox/live-check.cjs)
 * могла прочитать их через executeScript. В обычном использовании не мешает.
 */
const __byedpiTest = { errors: [], version: "", snap: null, busy: false, rendered: 0 };
window.__byedpiTest = __byedpiTest;
window.addEventListener("error", (e) => {
  __byedpiTest.errors.push(String((e && e.message) || e));
});
window.addEventListener("unhandledrejection", (e) => {
  __byedpiTest.errors.push("promise: " + String((e && e.reason && e.reason.message) || e.reason));
});

/* ------------------------------------------------------------------ обмен */
function bg(type, extra) {
  return browser.runtime.sendMessage(Object.assign({ type: type }, extra || {}))
    .then((resp) => {
      if (!resp) { throw new Error("пустой ответ от фонового скрипта"); }
      if (resp.ok) { return resp.data; }
      throw new Error(resp.error || "ошибка");
    });
}

function setBusy(v) {
  busy = v;
  __byedpiTest.busy = v;
}

function esc(s) {
  return String(s === undefined || s === null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ------------------------------------------------------------------ рендер */
function render(s) {
  if (!s) { return; }
  snap = s;
  __byedpiTest.snap = s;
  __byedpiTest.version = s.version || "";
  __byedpiTest.rendered += 1;
  const st = s.status || {};
  const ps = s.proxyState || "unknown";

  $("dot").className = "dot " + (ps === "running" ? "running" :
    (ps === "error" ? "error" : (ps === "starting" ? "starting" :
      (ps === "external" ? "external" : ""))));
  $("stateText").textContent = STATE_TEXT[ps] || ps;

  const addr = st.address || ((s.settings.host || "127.0.0.1") + ":" + (s.settings.port || 1080));
  $("addr").textContent = addr;
  $("proto").textContent = "SOCKS v" + (s.settings.socks_version || 5);

  const parts = [];
  if (st.pid) { parts.push("pid " + st.pid); }
  if (st.uptime_sec) { parts.push(st.uptime_sec + " с"); }
  if (st.strategy_name) { parts.push(st.strategy_name); }
  $("hostLine").textContent = parts.length ? parts.join(" · ") : "локальный прокси ciadpi";

  /* баннеры: ошибка (красный) или предупреждение при работающем прокси (жёлтый) */
  const banner = $("banner");
  let bannerText = "";
  let warn = false;
  if (s.hostState === "missing" || s.hostState === "error") {
    bannerText = s.hostError || "Нет связи с локальным хостом.";
  } else if (ps === "error" && (st.error || s.lastError)) {
    bannerText = st.error || s.lastError;
  } else if (ps === "external") {
    bannerText = "Порт " + addr + " занят другим процессом. Освободите его или смените порт в настройках.";
  } else if (ps === "running" && (st.error || s.lastError)) {
    // прокси работает, но ciadpi сообщал о проблеме (например, ядро не поддержало
    // выбранную стратегию) — молчать об этом нельзя
    bannerText = "Прокси работает, но ciadpi сообщал о проблеме:\n" + (st.error || s.lastError);
    warn = true;
  }
  banner.hidden = !bannerText;
  banner.textContent = bannerText;
  banner.className = warn ? "banner warn" : "banner";

  const note = $("proxyNote");
  if (s.proxyNote) {
    note.hidden = false;
    note.textContent = s.proxyNote;
  } else {
    note.hidden = true;
  }

  /* главная кнопка */
  const btn = $("btnToggle");
  const running = ps === "running";
  btn.textContent = running ? "Отключить" : "Подключить";
  btn.classList.toggle("stop", running);
  btn.disabled = busy || ps === "starting";
  $("btnRestart").disabled = busy;
  $("btnTest").disabled = busy;

  /* стратегия */
  const sel = $("strategy");
  const strategies = s.strategies || [];
  if (strategies.length && sel.options.length !== strategies.length) {
    sel.innerHTML = "";
    strategies.forEach((it) => {
      const o = document.createElement("option");
      o.value = it.id;
      o.textContent = it.name + (it.supported ? "" : " (не для этой ОС)");
      sel.appendChild(o);
    });
  }
  sel.value = (s.settings && s.settings.strategy) || "recommended";
  const cur = strategies.find((x) => x.id === sel.value);
  $("strategyDesc").textContent = cur ? cur.desc : "";
  const argvEl = $("argv");
  if (cur && cur.args) {
    argvEl.hidden = false;
    argvEl.textContent = "ciadpi -i " + (s.settings.host || "127.0.0.1") +
      " -p " + (s.settings.port || 1080) + (cur.args.length ? " " + cur.args.join(" ") : "");
  } else {
    argvEl.hidden = true;
  }

  /* форма */
  if (!formTouched) {
    $("port").value = s.settings.port || 1080;
    $("host").value = s.settings.host || "127.0.0.1";
    $("custom").value = s.settings.custom_args || "";
    $("applyFirefox").checked = s.settings.apply_firefox_proxy !== false;
    $("proxyDns").checked = s.settings.proxy_dns !== false;
    $("autostart").checked = !!s.settings.autostart;
    $("autoRestart").checked = s.settings.auto_restart !== false;
  }

  /* подвал */
  const info = s.hostInfo || {};
  const bin = info.binary || {};
  if (bin.transport === "tunnel") {
    /* туннель не использует ciadpi: требовать download_ciadpi.py здесь бессмысленно */
    $("binInfo").textContent = !bin.found
      ? "ТУННЕЛЬ НЕ НАЙДЕН — нет каталога tunnel/ рядом с host/"
      : !bin.relay
        ? "туннель · шлюз НЕ УКАЗАН (transport=tunnel, tunnel.relay пуст)"
        : "туннель · " + shortPath(bin.relay) + " · движок " + (bin.engine || "auto");
  } else if (bin.found) {
    $("binInfo").textContent = "ciadpi v" + (bin.version || "?") + " · " + shortPath(bin.path);
  } else {
    $("binInfo").textContent = "ciadpi НЕ НАЙДЕН — выполните: python host/download_ciadpi.py";
  }
  $("cfgInfo").textContent = info.config_path ? "настройки: " + shortPath(info.config_path) : "";
}

function shortPath(p) {
  if (!p) { return ""; }
  const home = p.indexOf("/home/") === 0 || p.indexOf("/Users/") === 0 || p.indexOf("C:\\Users\\") === 0;
  if (home && p.length > 62) { return "…" + p.slice(-60); }
  return p.length > 62 ? "…" + p.slice(-60) : p;
}

function fail(e, where) {
  const box = $("banner");
  box.hidden = false;
  box.textContent = (where ? where + ": " : "") + (e && e.message ? e.message : e);
  setBusy(false);
}

/* ------------------------------------------------------------------ действия */
/* ----------------------------------------------------- форма (для проверки)
 * Заполняет поля настроек и возвращает собранный объект. Используется
 * автоматической live-проверкой в настоящем Firefox и удобно для отладки
 * из консоли попапа: await window.__byedpiSetForm({ strategy: "fake-ttl" }).
 */
window.__byedpiSetForm = function setForm(patch) {
  patch = patch || {};
  if (patch.port !== undefined) { $("port").value = String(patch.port); }
  if (patch.host !== undefined) { $("host").value = String(patch.host); }
  if (patch.custom !== undefined) { $("custom").value = String(patch.custom); }
  if (patch.strategy !== undefined) { $("strategy").value = String(patch.strategy); }
  ["port", "host", "custom"].forEach((id) => {
    $(id).dispatchEvent(new Event("input", { bubbles: true }));
  });
  $("strategy").dispatchEvent(new Event("change", { bubbles: true }));
  return collectSettings();
};

function validateForm() {
  const portRaw = $("port").value.trim();
  const port = parseInt(portRaw, 10);
  if (!portRaw || !Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error("Порт должен быть числом от 1 до 65535 (сейчас: «" + (portRaw || "пусто") + "»).");
  }
  const host = $("host").value.trim();
  if (!host || /\s/.test(host)) {
    throw new Error("Адрес прокси не может быть пустым или содержать пробелы.");
  }
  const strategy = $("strategy").value;
  if (strategy === "custom" && !$("custom").value.trim()) {
    throw new Error("Выбрана стратегия «Свои аргументы», но поле аргументов пустое.");
  }
  return { port: port, host: host, strategy: strategy };
}

function collectSettings() {
  return {
    host: $("host").value.trim() || "127.0.0.1",
    port: parseInt($("port").value, 10) || 1080,
    strategy: $("strategy").value,
    custom_args: $("custom").value,
    apply_firefox_proxy: $("applyFirefox").checked,
    proxy_dns: $("proxyDns").checked,
    autostart: $("autostart").checked,
    auto_restart: $("autoRestart").checked
  };
}

async function doToggle() {
  setBusy(true);
  $("btnToggle").disabled = true;
  try {
    const running = snap && snap.proxyState === "running";
    if (!running) { validateForm(); }
    const settings = collectSettings();
    const data = running ? await bg("stop") : await bg("start", { settings: settings });
    render(data);
    formTouched = false;
    $("saveMsg").className = "saveMsg ok";
    $("saveMsg").textContent = running ? "Прокси остановлен, порт освобождён." : "Прокси запущен.";
  } catch (e) {
    fail(e, "Не удалось изменить состояние");
  } finally {
    setBusy(false);
    $("btnToggle").disabled = false;
  }
}

async function doRestart() {
  setBusy(true);
  try {
    validateForm();
    render(await bg("restart", { settings: collectSettings() }));
    formTouched = false;
    $("saveMsg").className = "saveMsg ok";
    $("saveMsg").textContent = "Перезапущено с новыми параметрами.";
  } catch (e) { fail(e, "Перезапуск"); } finally { setBusy(false); }
}

async function doSave() {
  setBusy(true);
  try {
    validateForm();
    render(await bg("saveSettings", { settings: collectSettings(), apply: true }));
    formTouched = false;
    $("saveMsg").className = "saveMsg ok";
    $("saveMsg").textContent = "Сохранено в config.json и применено.";
  } catch (e) {
    $("saveMsg").className = "saveMsg err";
    $("saveMsg").textContent = e.message;
  } finally { setBusy(false); }
}

async function doTest() {
  const out = $("testOut");
  $("testCard").hidden = false;
  out.textContent = "Проверяю: порт → SOCKS5 handshake → реальный HTTPS-запрос…";
  setBusy(true);
  try {
    const r = await bg("selftest", {});
    const lines = (r.steps || []).map((s) => (s.ok ? "✔" : "✘") + " " + s.name + " — " + s.detail);
    lines.push("");
    lines.push(r.ok ? "ИТОГ: трафик идёт через SOCKS5-прокси." : "ИТОГ: " + (r.detail || "не работает"));
    if (r.fetch && r.fetch.status_line) {
      lines.push(r.fetch.status_line + " за " + r.fetch.elapsed_ms + " мс");
    }
    out.textContent = lines.join("\n");
  } catch (e) {
    out.textContent = "Ошибка проверки: " + e.message;
  } finally { setBusy(false); }
}

async function loadLogs() {
  try {
    const r = await bg("logs", { lines: 150 });
    const el = $("log");
    el.textContent = (r.lines && r.lines.length) ? r.lines.join("\n") : "(пусто)";
    el.scrollTop = el.scrollHeight;
  } catch (e) {
    $("log").textContent = "Журнал недоступен: " + e.message;
  }
}

/* ------------------------------------------------------------------ события */
function wire() {
  $("btnToggle").addEventListener("click", doToggle);
  $("btnRestart").addEventListener("click", doRestart);
  $("btnSave").addEventListener("click", doSave);
  $("btnTest").addEventListener("click", doTest);
  $("btnRefreshLog").addEventListener("click", loadLogs);
  $("btnClearLog").addEventListener("click", async () => {
    $("log").textContent = "(очищено)";
    try { await bg("clearLogs"); } catch (e) { /* журнал не критичен */ }
    loadLogs();
  });
  $("btnHelp").addEventListener("click", () => bg("openHelp").catch(() => {}));
  $("btnWebui").addEventListener("click", async () => {
    try { await bg("openWebui"); } catch (e) { fail(e, "Web-панель"); }
  });
  $("strategy").addEventListener("change", () => {
    formTouched = true;
    if (snap) {
      const cur = (snap.strategies || []).find((x) => x.id === $("strategy").value);
      $("strategyDesc").textContent = cur ? cur.desc : "";
      if (cur && cur.args) {
        $("argv").hidden = false;
        $("argv").textContent = "ciadpi -i " + $("host").value + " -p " + $("port").value +
          (cur.args.length ? " " + cur.args.join(" ") : "");
      }
    }
  });

  ["port", "host", "custom", "applyFirefox", "proxyDns", "autostart", "autoRestart"]
    .forEach((id) => $(id).addEventListener("input", () => { formTouched = true; }));

  const logDetails = $("log").closest("details");
  if (logDetails) {
    logDetails.addEventListener("toggle", () => {
      if (logDetails.open) {
        loadLogs();
        logTimer = setInterval(loadLogs, 2500);
      } else if (logTimer) {
        clearInterval(logTimer);
        logTimer = null;
      }
    });
  }

  browser.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "stateChanged") { render(msg.data); }
  });
}

/* -------------------------------------------------------------------- старт */
document.addEventListener("DOMContentLoaded", async () => {
  wire();
  try {
    render(await bg("getState"));
  } catch (e) {
    fail(e, "Нет связи с фоновым скриптом");
  }
  window.addEventListener("beforeunload", () => {
    if (logTimer) { clearInterval(logTimer); }
  });
});
