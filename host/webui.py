"""
webui.py — локальный web-интерфейс управления (127.0.0.1), без внешних зависимостей.

Запускается внутри менеджера: python manager.py  ->  http://127.0.0.1:<port>/?t=<token>
Токен обязателен и для страницы, и для API (защита от случайных локальных запросов).
Никаких CDN/внешних ресурсов — всё инлайн, работает офлайн.
"""
from __future__ import annotations

import http.server
import json
import socketserver
import threading
import urllib.parse

PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>byedpi · локальный SOCKS5-прокси</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--fg:#e8eaed;--mut:#9aa4b2;--acc:#4f8cff;--ok:#3ddc84;--err:#ff5c5c;--warn:#ffc857;--bd:#262b36}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:20px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--mut);font-size:12px;margin-bottom:18px}
.wrap{max-width:860px;margin:0 auto;display:grid;gap:14px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.state{display:inline-flex;align-items:center;gap:8px;font-weight:600}
.dot{width:10px;height:10px;border-radius:50%;background:var(--mut);box-shadow:0 0 0 4px rgba(255,255,255,.04)}
.dot.running{background:var(--ok)}.dot.error{background:var(--err)}.dot.starting{background:var(--warn)}
.addr{font-family:ui-monospace,Consolas,monospace;background:#0b0d12;border:1px solid var(--bd);padding:6px 10px;border-radius:8px}
button{background:var(--acc);color:#fff;border:0;padding:9px 16px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:#20252f;color:var(--fg);border:1px solid var(--bd)}
button.danger{background:#3a1f24;color:#ffb4b4;border:1px solid #552b31}
button:disabled{opacity:.45;cursor:not-allowed}
label{display:block;color:var(--mut);font-size:12px;margin:10px 0 4px}
input,select,textarea{width:100%;background:#0b0d12;color:var(--fg);border:1px solid var(--bd);border-radius:8px;padding:8px 10px;font:inherit}
textarea{font-family:ui-monospace,Consolas,monospace;font-size:12px;min-height:64px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.check{display:flex;gap:8px;align-items:center;margin-top:10px;color:var(--fg)}
.check input{width:auto}
pre{background:#0b0d12;border:1px solid var(--bd);border-radius:8px;padding:10px;max-height:260px;overflow:auto;font-size:11.5px;margin:8px 0 0;white-space:pre-wrap;word-break:break-word}
.mut{color:var(--mut);font-size:12px}
.err{color:var(--err);font-size:12.5px;margin-top:8px;white-space:pre-wrap}
.ok{color:var(--ok);font-size:12.5px;margin-top:8px}
details summary{cursor:pointer;color:var(--mut);font-size:12px;margin-top:8px}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div>
    <h1>byedpi · локальный SOCKS5-прокси с обходом DPI</h1>
    <div class="sub" id="subtitle">Управление движком ciadpi (byedpi). Настройка Firefox — во вкладке «Инструкция» ниже.</div>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between">
      <div class="state"><span id="dot" class="dot"></span><span id="stateText">…</span></div>
      <div class="addr" id="addr">127.0.0.1:1080</div>
    </div>
    <div class="row" style="margin-top:14px">
      <button id="btnStart">Запустить</button>
      <button id="btnStop" class="danger">Остановить</button>
      <button id="btnRestart" class="ghost">Перезапустить</button>
      <button id="btnTest" class="ghost">Проверить трафик</button>
    </div>
    <div id="msg"></div>
    <div class="mut" id="meta" style="margin-top:10px"></div>
  </div>

  <div class="card">
    <div class="grid">
      <div>
        <label>Стратегия обхода DPI</label>
        <select id="strategy"></select>
        <div class="mut" id="strategyDesc" style="margin-top:6px"></div>
      </div>
      <div>
        <label>Порт SOCKS5</label>
        <input id="port" type="number" min="1" max="65535" value="1080">
        <label>Адрес</label>
        <input id="host" value="127.0.0.1">
      </div>
    </div>
    <label>Свои аргументы ciadpi (для стратегии «Свои аргументы»)</label>
    <textarea id="custom" placeholder="--disorder 1 --auto=torst --timeout 3 --tlsrec 1+s"></textarea>
    <div class="row">
      <div class="check"><input type="checkbox" id="proxyDns"><label for="proxyDns" style="margin:0">Проксировать DNS в Firefox</label></div>
      <div class="check"><input type="checkbox" id="autostart"><label for="autostart" style="margin:0">Автозапуск прокси</label></div>
      <div class="check"><input type="checkbox" id="autoRestart"><label for="autoRestart" style="margin:0">Автоперезапуск при падении</label></div>
    </div>
    <div class="row" style="margin-top:14px">
      <button id="btnSave">Сохранить и применить</button>
      <span class="mut" id="saveMsg"></span>
    </div>
    <details>
      <summary>Командная строка / путь к бинарнику</summary>
      <pre id="argv">—</pre>
    </details>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between">
      <b>Журнал</b>
      <button id="btnClearLog" class="ghost" style="padding:5px 10px">Очистить</button>
    </div>
    <pre id="log">—</pre>
  </div>

  <div class="card">
    <b>Инструкция: Firefox</b>
    <ol class="mut" style="padding-left:20px">
      <li>Нажмите «Запустить» — прокси поднимется на <span class="addr" id="addr2">127.0.0.1:1080</span>.</li>
      <li>Firefox → Настройки → Основные → Параметры сети → «Настроить…».</li>
      <li>Ручная конфигурация прокси: SOCKS-узел <b>127.0.0.1</b>, порт <b id="portEcho">1080</b>, версия <b>SOCKS v5</b>.</li>
      <li>Обязательно включите «Проксировать DNS при использовании SOCKS v5».</li>
      <li>Если сайты не грузятся: <b>about:config</b> → <code>network.http.http3.enable</code> → <b>false</b> (QUIC обходит SOCKS).</li>
    </ol>
    <div class="mut">Расширение Firefox из каталога <code>addon/</code> умеет прописывать эти настройки автоматически.</div>
  </div>
</div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const $ = id => document.getElementById(id);
let cfg = {}, strategies = [], busy = false;

async function api(cmd, args) {
  const r = await fetch('/api', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({token: TOKEN, cmd, args: args || {}})});
  const j = await r.json();
  if (!j.ok) throw new Error(j.error || 'ошибка');
  return j.data;
}

function setState(st) {
  const s = st.state || 'stopped';
  $('dot').className = 'dot ' + (s === 'running' ? 'running' : (s === 'error' ? 'error' : (s === 'starting' ? 'starting' : '')));
  const names = {running:'Работает', stopped:'Остановлен', starting:'Запуск…', error:'Ошибка', external:'Порт занят другим процессом'};
  $('stateText').textContent = names[s] || s;
  $('addr').textContent = st.address || (cfg.host + ':' + cfg.port);
  $('addr2').textContent = $('addr').textContent;
  $('btnStart').disabled = busy || s === 'running';
  $('btnStop').disabled = busy || s === 'stopped';
  $('btnRestart').disabled = busy;
  const m = [];
  if (st.pid) m.push('pid ' + st.pid);
  if (st.uptime_sec) m.push('аптайм ' + st.uptime_sec + ' с');
  if (isTunnel()) {
    if (st.relay) m.push('шлюз: ' + st.relay);
  } else if (st.strategy_name) {
    m.push('стратегия: ' + st.strategy_name);
  }
  if (st.restarts) m.push('перезапусков: ' + st.restarts);
  if (st.manager_uptime_sec !== undefined) m.push('менеджер: ' + st.manager_uptime_sec + ' с');
  $('meta').textContent = m.join(' · ');
  $('msg').innerHTML = st.error ? '<div class="err">' + esc(st.error) + '</div>' : '';
  if (st.cmdline) $('argv').textContent = st.cmdline;
  if (st.settings) { cfg = st.settings; fillForm(); applyTransportLabels(); }
}

function esc(s) { return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

function fillForm() {
  $('port').value = cfg.port || 1080;
  $('portEcho').textContent = cfg.port || 1080;
  $('host').value = cfg.host || '127.0.0.1';
  $('custom').value = cfg.custom_args || '';
  $('proxyDns').checked = !!cfg.proxy_dns;
  $('autostart').checked = !!cfg.autostart;
  $('autoRestart').checked = !!cfg.auto_restart;
  if (strategies.length && !$('strategy').options.length) {
    for (const s of strategies) {
      const o = document.createElement('option');
      o.value = s.id; o.textContent = s.name + (s.supported ? '' : ' (не для этой ОС)');
      $('strategy').appendChild(o);
    }
  }
  if (cfg.strategy) $('strategy').value = cfg.strategy;
  const cur = strategies.find(s => s.id === $('strategy').value);
  if (cur) {
    $('strategyDesc').textContent = cur.desc + (cur.args && cur.args.length ? '  →  ' + cur.args.join(' ') : '');
  }
}

async function refresh() {
  try {
    const st = await api('status');
    setState(st);
  } catch (e) {
    $('stateText').textContent = 'Менеджер недоступен';
    $('dot').className = 'dot error';
    $('msg').innerHTML = '<div class="err">' + esc(e.message) + '</div>';
  }
}

async function refreshLog() {
  try {
    const r = await api('logs', {lines: 120});
    $('log').textContent = (r.lines && r.lines.length) ? r.lines.join('\\n') : '(пусто)';
    $('log').scrollTop = $('log').scrollHeight;
  } catch (e) {}
}

async function run(cmd, args, okText) {
  if (busy) return;
  busy = true; $('msg').innerHTML = '<div class="mut">выполняю…</div>';
  try {
    const st = await api(cmd, args);
    if (st && st.state !== undefined) setState(st);
    if (okText) $('msg').innerHTML = '<div class="ok">' + esc(okText) + '</div>';
  } catch (e) {
    $('msg').innerHTML = '<div class="err">' + esc(e.message) + '</div>';
  } finally {
    busy = false; refreshLog(); refresh();
  }
}

$('btnStart').onclick = () => run('start', {}, 'Прокси запущен');
$('btnStop').onclick = () => run('stop', {}, 'Прокси остановлен, порт освобождён');
$('btnRestart').onclick = () => run('restart', {}, 'Перезапущено');
$('btnClearLog').onclick = () => run('clear_logs', {}, 'Журнал очищен');
$('strategy').onchange = () => { cfg.strategy = $('strategy').value; fillForm(); };

$('btnSave').onclick = async () => {
  const settings = {
    host: $('host').value.trim() || '127.0.0.1',
    port: parseInt($('port').value, 10) || 1080,
    strategy: $('strategy').value,
    custom_args: $('custom').value,
    proxy_dns: $('proxyDns').checked,
    autostart: $('autostart').checked,
    auto_restart: $('autoRestart').checked
  };
  try {
    const r = await api('settings_set', {settings, apply: true});
    cfg = r.settings; fillForm(); setState(r.status);
    $('saveMsg').innerHTML = '<span class="ok">Сохранено' + (r.restarted ? ', прокси перезапущен' : '') + '</span>';
  } catch (e) {
    $('saveMsg').innerHTML = '<span class="err">' + esc(e.message) + '</span>';
  }
};

$('btnTest').onclick = async () => {
  $('msg').innerHTML = '<div class="mut">Проверяю трафик через прокси…</div>';
  try {
    const r = await api('selftest', {});
    const rows = (r.steps || []).map(s => (s.ok ? '✔' : '✘') + ' ' + s.name + ' — ' + s.detail);
    rows.push(r.ok ? 'ИТОГ: трафик идёт через SOCKS5' : 'ИТОГ: не работает — ' + r.detail);
    $('msg').innerHTML = '<pre>' + esc(rows.join('\\n')) + '</pre>';
  } catch (e) {
    $('msg').innerHTML = '<div class="err">' + esc(e.message) + '</div>';
  }
};

// транспорт берём из конфига: при transport=tunnel ciadpi не запускается вовсе,
// и называть вещи «ciadpi»/«стратегия» было бы неправдой.
function isTunnel() { return (cfg && cfg.transport) === 'tunnel'; }

function applyTransportLabels() {
  const sub = $('subtitle');
  if (!sub) return;
  if (isTunnel()) {
    sub.textContent = 'Транспорт: браузерный туннель — трафик идёт внутри WSS-соединения '
      + 'с сайтом-шлюзом. Настройка Firefox — во вкладке «Инструкция» ниже.';
  } else {
    sub.textContent = 'Управление движком ciadpi (byedpi). Настройка Firefox — во вкладке «Инструкция» ниже.';
  }
}

(async function init() {
  if (!TOKEN) { $('msg').innerHTML = '<div class="err">Нет токена в URL. Откройте ссылку из файла webui.url или вывода менеджера.</div>'; }
  try {
    const info = await api('info');
    strategies = info.strategies || [];
    cfg = info.settings || {};
    fillForm();
    applyTransportLabels();
    if (info.binary && !info.binary.found) {
      const what = isTunnel() ? 'Пакет туннеля' : 'Бинарник ciadpi';
      $('msg').innerHTML = '<div class="err">' + what + ' не найден: ' + esc(info.binary.error || '') + '</div>';
    } else if (info.binary && info.binary.warning) {
      $('msg').innerHTML = '<div class="err">' + esc(info.binary.warning) + '</div>';
    }
  } catch (e) {
    $('msg').innerHTML = '<div class="err">' + esc(e.message) + '</div>';
  }
  await refresh(); await refreshLog();
  setInterval(refresh, 3000);
  setInterval(refreshLog, 4000);
})();
</script>
</body>
</html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "byedpi-webui/1.0"

    def log_message(self, *_args):
        pass

    # ------------------------------------------------------------------ helpers
    def _token(self, query) -> str:
        tok = (query.get("t") or [""])[0]
        return tok or self.headers.get("X-Byedpi-Token", "")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # ------------------------------------------------------------------ routes
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(u.query)
        mgr = self.server.manager
        if self._token(query) != mgr.webui_token:
            return self._send(403, "403 Forbidden: нужен токен (?t=...)".encode("utf-8"),
                              "text/plain; charset=utf-8")
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if u.path == "/api":
            try:
                return self._json({"ok": True, "data": mgr.handle("status", {})})
            except Exception as e:
                return self._json({"ok": False, "error": str(e)})
        return self._send(404, b"404", "text/plain; charset=utf-8")

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        mgr = self.server.manager
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            req = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return self._json({"ok": False, "error": "некорректный JSON"}, 400)
        if req.get("token") != mgr.webui_token:
            return self._json({"ok": False, "error": "неверный токен"}, 403)
        cmd = str(req.get("cmd") or "")
        if cmd in ("shutdown", "stop_manager"):
            return self._json({"ok": False, "error": "команда недоступна из web-интерфейса"}, 403)
        try:
            data = mgr.handle(cmd, req.get("args") or {})
            return self._json({"ok": True, "data": data})
        except Exception as e:
            return self._json({"ok": False, "error": f"{type(e).__name__}: {e}"})


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, manager):
        self.manager = manager
        super().__init__(addr, handler)


def start(manager):
    """Поднимает web-интерфейс в фоне. Возвращает объект сервера (или None)."""
    port = int(getattr(manager, "webui_port", 0) or 0)
    srv = _Server(("127.0.0.1", port), _Handler, manager)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.3},
                         name="webui", daemon=True)
    t.start()
    return srv
