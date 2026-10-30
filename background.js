/*
 * background.js — event-page расширения.
 *
 * Задачи:
 *  1. Держать соединение с native-messaging хостом (python host/native_host.py),
 *     который управляет процессом ciadpi через локальный менеджер.
 *  2. Переводить состояние прокси в настройки прокси Firefox (browser.proxy.settings)
 *     и в бейдж на кнопке.
 *  3. Отвечать на команды попапа (start/stop/restart/settings/logs/selftest).
 *
 * Устойчивость: прокси живёт в отдельном процессе-менеджере, поэтому «засыпание»
 * event-page или закрытие попапа не рвёт соединение с интернетом — при возврате
 * мы просто переподключаемся и перечитываем статус.
 */

"use strict";

const NATIVE_HOST = "byedpi.firefox_host";
const REQ_TIMEOUT_MS = 30000;
const KEEPALIVE_ALARM = "byedpi-keepalive";
const VERSION = "1.2.0";   // держим в синхроне с manifest.json и host/client.py

const DEFAULT_SETTINGS = {
  host: "127.0.0.1",
  port: 1080,
  strategy: "recommended",
  custom_args: "",
  autostart: true,
  auto_restart: true,
  apply_firefox_proxy: true,
  proxy_dns: true,
  socks_version: 5,
  passthrough: "localhost, 127.0.0.1, ::1",
  disable_http3_hint: true
};

const state = {
  hostState: "idle",        // idle | connecting | connected | missing | error
  hostError: "",
  proxyState: "unknown",    // running | stopped | starting | error | external | unknown
  status: null,
  settings: Object.assign({}, DEFAULT_SETTINGS),
  strategies: [],
  hostInfo: null,
  lastError: "",
  proxyControlledByUs: false,
  proxyNote: ""
};

let port = null;
let msgId = 0;
const pending = new Map();

/* ---------------------------------------------------------------- native port */

function log(...args) {
  console.log("[byedpi]", ...args);
}

function connectPort() {
  if (port) {
    return;
  }
  state.hostState = "connecting";
  state.hostError = "";
  broadcast();

  let p;
  try {
    p = browser.runtime.connectNative(NATIVE_HOST);
  } catch (e) {
    state.hostState = "error";
    state.hostError = String(e && e.message ? e.message : e);
    broadcast();
    return;
  }
  port = p;

  port.onMessage.addListener(onHostMessage);
  port.onDisconnect.addListener(() => {
    const lastErr = browser.runtime.lastError;
    const message = lastErr && lastErr.message ? lastErr.message : "";
    port = null;
    // Немедленно завершаем все ожидающие запросы: ответов от мёртвого хоста
    // уже не будет. Без этого попап висел бы до полного таймаута (30 с на запрос).
    pending.forEach((entry) => {
      clearTimeout(entry.timer);
      entry.reject(new Error("Соединение с локальным хостом разорвано."));
    });
    pending.clear();
    state.hostState = "missing";
    if (/not found|не найден/i.test(message)) {
      state.hostError =
        "Native-messaging хост не установлен. Откройте терминал в каталоге проекта и выполните: " +
        (navigator.platform.indexOf("Win") === 0
          ? "install.bat  (или python host\\ctl.py install)"
          : "./install.sh  (или python3 host/ctl.py install)") +
        ", затем перезапустите Firefox.";
    } else if (/permission|разрешен/i.test(message)) {
      state.hostError = "Хосту не разрешено подключение: проверьте allowed_extensions в манифесте " +
        "(ID расширения должен совпадать с " + (state.hostInfo ? state.hostInfo.extension_id : "byedpi-control@byedpi.local") + ").";
    } else {
      state.hostError = message || "Соединение с локальным хостом разорвано.";
    }
    state.proxyState = "unknown";
    state.status = null;
    log("host disconnected:", message);
    broadcast();
    updateBadge();
    applyProxyIfNeeded();
    scheduleReconnect();
  });
}

let reconnectTimer = null;
function scheduleReconnect(delayMs = 3000) {
  if (reconnectTimer) {
    return;
  }
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    if (!port) {
      connectPort();
    }
  }, delayMs);
}

function onHostMessage(msg) {
  if (!msg) {
    return;
  }
  if (msg.event) {
    if (msg.event === "status" && msg.data) {
      ingestStatus(msg.data);
    } else if (msg.event === "open_ui_tab") {
      // live-тесты (tests/firefox): WebDriver не умеет сам открывать
      // moz-extension:// — просим расширение открыть панель вкладкой.
      browser.tabs.create({ url: browser.runtime.getURL("popup.html") }).catch(() => {});
    } else if (msg.event === "host" && msg.data) {
      if (msg.data.state === "connected") {
        state.hostState = "connected";
        state.hostError = "";
      } else if (msg.data.state === "no-manager") {
        state.hostState = "error";
        state.hostError = msg.data.error || "Не удалось запустить менеджер прокси.";
      } else if (msg.data.state === "disconnected") {
        state.hostState = "connecting";
      }
      broadcast();
      updateBadge();
    }
    return;
  }
  const id = msg.id;
  const entry = pending.get(id);
  if (!entry) {
    return;
  }
  pending.delete(id);
  clearTimeout(entry.timer);
  if (msg.ok) {
    entry.resolve(msg.data);
  } else {
    entry.reject(new Error(msg.error || "ошибка хоста"));
  }
}

function send(cmd, args) {
  return new Promise((resolve, reject) => {
    if (!port) {
      connectPort();
    }
    if (!port) {
      reject(new Error(state.hostError || "нет соединения с локальным хостом"));
      return;
    }
    msgId += 1;
    const id = msgId;
    const timer = setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error("таймаут ожидания ответа от хоста (" + cmd + ")"));
      }
    }, REQ_TIMEOUT_MS);
    pending.set(id, { resolve, reject, timer });
    try {
      port.postMessage({ id: id, cmd: cmd, args: args || {} });
    } catch (e) {
      pending.delete(id);
      clearTimeout(timer);
      port = null;
      reject(new Error("не удалось отправить сообщение хосту: " + e));
    }
  });
}

/* ------------------------------------------------------------------- статусы */

function ingestStatus(st) {
  state.status = st;
  state.proxyState = st.state || "unknown";
  if (st.settings) {
    state.settings = Object.assign({}, DEFAULT_SETTINGS, st.settings);
  }
  if (st.error) {
    state.lastError = st.error;
  } else if (state.proxyState === "running") {
    state.lastError = "";
  }
  broadcast();
  updateBadge();
  applyProxyIfNeeded();
}

async function refresh() {
  try {
    const st = await send("status");
    ingestStatus(st);
  } catch (e) {
    state.lastError = String(e.message || e);
    broadcast();
  }
  try {
    const info = await send("host_info");
    state.hostInfo = info;
    if (info && info.strategies && info.strategies.length) {
      state.strategies = info.strategies;
    }
    if (info && info.settings) {
      state.settings = Object.assign({}, DEFAULT_SETTINGS, info.settings);
    }
    state.hostState = "connected";
    state.hostError = "";
    broadcast();
  } catch (e) {
    log("host_info failed", e);
  }
  updateBadge();
}

/* ------------------------------------------------------------ прокси Firefox */

function proxyValue(cfg) {
  return {
    proxyType: "manual",
    socks: cfg.host || "127.0.0.1",
    socksPort: Number(cfg.port || 1080),
    socksVersion: Number(cfg.socks_version || 5),
    proxyDNS: cfg.proxy_dns !== false,
    passthrough: cfg.passthrough || "localhost, 127.0.0.1, ::1"
  };
}

async function applyProxyIfNeeded() {
  const cfg = state.settings;
  const wantOn = cfg.apply_firefox_proxy !== false && state.proxyState === "running";

  if (!wantOn) {
    if (state.proxyControlledByUs) {
      try {
        await browser.proxy.settings.clear({ scope: "regular" });
        state.proxyControlledByUs = false;
        state.proxyNote = "Настройки прокси Firefox возвращены к прежним.";
      } catch (e) {
        state.proxyNote = "Не удалось сбросить настройки прокси: " + e.message;
      }
      broadcast();
    }
    return;
  }

  const value = proxyValue(cfg);
  let conflictNote = "";
  try {
    const cur = await browser.proxy.settings.get({});
    if (cur && cur.levelOfControl === "controlled_by_other_extensions") {
      conflictNote = " Другое расширение тоже управляет прокси Firefox — отключите его, " +
        "иначе настройки будут перезаписаны друг другом (см. раздел «Инструкция»).";
    }
  } catch (e) { /* игнорируем */ }

  try {
    await browser.proxy.settings.set({ value: value, scope: "regular" });
    state.proxyControlledByUs = true;
    state.proxyNote = "Firefox направлен через SOCKS5 " + value.socks + ":" + value.socksPort +
      (value.proxyDNS ? " (DNS через прокси)" : "") + "." + conflictNote;
    state.lastError = "";
  } catch (e) {
    state.proxyControlledByUs = false;
    const msg = String((e && e.message) || e);
    if (/private browsing/i.test(msg)) {
      // Firefox требует разрешение «Allow in Private Windows»: настройки прокси
      // влияют и на приватные окна, а у расширения по умолчанию доступа нет.
      state.proxyNote = "Firefox не даёт автоматически прописать прокси: разрешите расширение " +
        "в приватных окнах — about:addons → Byedpi → «Разрешить для приватных окон» " +
        "(Allow in Private Windows), затем нажмите «Перезапуск». Либо пропишите SOCKS5 " +
        value.socks + ":" + value.socksPort + " вручную (см. «Инструкция»).";
    } else {
      state.proxyNote = "Не удалось применить настройки прокси: " + msg +
        " — пропишите SOCKS5 вручную (см. «Инструкция»).";
    }
  }
  broadcast();
}

/* -------------------------------------------------------------------- бейдж */

function updateBadge() {
  const s = state.proxyState;
  let text = "OFF";
  let color = "#5b6472";
  if (s === "running") { text = "ON"; color = "#2ea44f"; }
  else if (s === "starting") { text = "..."; color = "#d4a72c"; }
  else if (s === "error" || state.hostState === "missing") { text = "!"; color = "#d1242f"; }
  else if (s === "external") { text = "EXT"; color = "#8250df"; }

  const title = s === "running"
    ? "Byedpi: работает (" + (state.status ? state.status.address : "") + ")"
    : (state.hostState === "missing"
      ? "Byedpi: native-хост не установлен — откройте попап"
      : "Byedpi: " + s);

  const api = browser.action || browser.browserAction;
  if (!api) { return; }
  api.setBadgeText({ text: text }).catch(() => {});
  api.setBadgeBackgroundColor({ color: color }).catch(() => {});
  api.setTitle({ title: title }).catch(() => {});
}

/* --------------------------------------------------------- рассылка в попап */

const listeners = new Set();

function broadcast() {
  const snapshot = snapshotState();
  listeners.forEach((fn) => {
    try { fn(snapshot); } catch (e) { /* ignore */ }
  });
}

function snapshotState() {
  return {
    version: VERSION,
    hostState: state.hostState,
    hostError: state.hostError,
    proxyState: state.proxyState,
    status: state.status,
    settings: state.settings,
    strategies: state.strategies,
    hostInfo: state.hostInfo,
    lastError: state.lastError,
    proxyNote: state.proxyNote,
    proxyControlledByUs: state.proxyControlledByUs
  };
}

/* ------------------------------------------------------------- сообщения UI */

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg && msg.type) {
        case "getState":
          if (!port) { connectPort(); }
          await refresh();
          sendResponse({ ok: true, data: snapshotState() });
          break;

        case "start":
          await send("start", { settings: msg.settings || undefined });
          await refresh();
          sendResponse({ ok: true, data: snapshotState() });
          break;

        case "stop":
          await send("stop");
          await refresh();
          sendResponse({ ok: true, data: snapshotState() });
          break;

        case "restart":
          await send("restart", { settings: msg.settings || undefined });
          await refresh();
          sendResponse({ ok: true, data: snapshotState() });
          break;

        case "saveSettings":
          await send("settings_set", { settings: msg.settings || {}, apply: msg.apply !== false });
          await refresh();
          sendResponse({ ok: true, data: snapshotState() });
          break;

        case "logs":
          sendResponse({ ok: true, data: await send("logs", { lines: msg.lines || 200 }) });
          break;

        case "clearLogs":
          await send("clear_logs");
          sendResponse({ ok: true, data: await send("logs", { lines: 1 }) });
          break;

        case "version":
          sendResponse({ ok: true, data: { version: VERSION } });
          break;

        case "selftest":
          sendResponse({ ok: true, data: await send("selftest", { url: msg.url || "" }) });
          break;

        case "hostInfo":
          sendResponse({ ok: true, data: await send("host_info") });
          break;

        case "portCheck":
          sendResponse({ ok: true, data: await send("port_check", msg.args || {}) });
          break;

        case "subscribe": {
          const fn = (snap) => {
            try { sender.tab; } catch (e) { /* ignore */ }
            browser.runtime.sendMessage({ type: "stateChanged", data: snap }).catch(() => {});
          };
          listeners.add(fn);
          sendResponse({ ok: true, data: snapshotState() });
          break;
        }

        case "openHelp":
          await browser.tabs.create({ url: browser.runtime.getURL("help.html") });
          sendResponse({ ok: true });
          break;

        case "openWebui":
          try {
            const info = await send("info");
            if (info && info.webui_enabled && info.webui_port) {
              await browser.tabs.create({
                url: "http://127.0.0.1:" + info.webui_port + "/?t=" + encodeURIComponent(info.webui_token || "")
              });
              sendResponse({ ok: true });
            } else {
              sendResponse({ ok: false, error: "web-интерфейс выключен в настройках" });
            }
          } catch (e) {
            sendResponse({ ok: false, error: String(e.message || e) });
          }
          break;

        default:
          sendResponse({ ok: false, error: "неизвестная команда: " + (msg && msg.type) });
      }
    } catch (e) {
      state.lastError = String(e.message || e);
      broadcast();
      sendResponse({ ok: false, error: state.lastError, data: snapshotState() });
    }
  })();
  return true; // асинхронный ответ
});

/* ------------------------------------------------------ жизненный цикл */

browser.runtime.onInstalled.addListener(() => {
  connectPort();
  refresh().then(updateBadge);
});

browser.runtime.onStartup.addListener(() => {
  connectPort();
  refresh().then(updateBadge);
});

browser.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 1 });
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === KEEPALIVE_ALARM) {
    if (!port) {
      connectPort();
    }
    refresh().catch(() => {});
  }
});

/* Очистка прокси-настроек при удалении расширения */
browser.runtime.onSuspend && browser.runtime.onSuspend.addListener(() => {
  listeners.clear();
});

connectPort();
refresh().then(() => {
  updateBadge();
}).catch((e) => {
  log("initial refresh failed:", e);
  updateBadge();
});
