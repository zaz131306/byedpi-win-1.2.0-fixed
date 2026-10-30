#!/usr/bin/env python3
"""
relay.py — сайт-шлюз. Снаружи выглядит обычным HTTPS-сайтом, внутри пересылает байты.

    python3 -m tunnel.relay --cert cert.pem --key key.pem --secret '...' [--port 443]

Что видит провайдер и любой сканер:
  * валидная TLS-сессия с настоящим сертификатом на 443;
  * GET /            -> нормальная HTML-страница;
  * GET /favicon.ico -> 204, GET /robots.txt -> обычный robots;
  * GET /live        -> Upgrade: websocket, то есть WebSocket — вещь для сайтов обыденная
                        (чаты, котировки, уведомления). Без верного ключа в cookie -> 403;
  * всё остальное    -> 404, как у любого сайта.

Релей принципиально написан только на стандартной библиотеке: его же потом переносят
в Cloudflare Worker (там TLS и сертификат даёт Cloudflare, а IP-репутация у него такая,
что блокировать его себе дороже) или ставят за nginx на VPS с сертификатом Let's Encrypt.

БЕЗОПАСНОСТЬ. С верным ключом релей превращается в открытый прокси. Ключ обязателен
(--secret), а список разрешённых направлений (--allow) стоит задать, если шлюз публичный.

Зависимостей нет. Python 3.8+.
"""
from __future__ import annotations

import argparse
import http.server
import secrets
import socket
import socketserver
import ssl
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol as P  # noqa: E402

DEFAULT_WS_PATH = "/live"
COOKIE_NAME = "sid"
MAX_STREAMS_PER_CONN = 512
CONNECT_TIMEOUT = 10.0
PING_INTERVAL = 25.0

LANDING = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Заметки о сетях</title>
<style>
body{margin:0;background:#0f1115;color:#dfe3e8;
font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:44rem;margin:0 auto;padding:3.5rem 1.25rem 5rem}
h1{font-size:1.9rem;line-height:1.25;margin:0 0 .35rem}
p.sub{color:#8b93a1;margin:0 0 2.5rem}
h2{font-size:1.05rem;margin:2.2rem 0 .5rem;color:#fff}
ul{padding-left:1.2rem;color:#b9c0cb}li{margin:.3rem 0}
code{background:#191d24;border:1px solid #262b34;border-radius:4px;padding:.1rem .35rem;
font-size:.9em;color:#e3b341}
footer{margin-top:3.5rem;color:#5f6673;font-size:.85rem;border-top:1px solid #1e232b;padding-top:1.2rem}
a{color:#6ea8fe}
</style></head><body><main>
<h1>Заметки о сетях</h1>
<p class="sub">Личный блокнот: TCP, TLS, HTTP/2 и всё, что между ними.</p>
<h2>Свежее</h2>
<ul>
<li>Почему <code>TLS 1.3</code> убирает лишний round-trip и что стало с 0-RTT</li>
<li>HTTP/2: приоритеты потоков и почему их заменили на Extensible Priorities</li>
<li>Как читать <code>tcpdump</code> руками и не сойти с ума</li>
<li>MTU, MSS и фрагментация: где на самом деле теряются пакеты</li>
</ul>
<h2>Инструменты</h2>
<ul>
<li><code>openssl s_client</code> — первый шаг в любой непонятной ситуации с TLS</li>
<li><code>ss -tin</code> — состояние соединений вместе с окнами и RTT</li>
</ul>
<footer>© 2026 · RSS · Архив · Контакты</footer>
</main></body></html>
"""

ROBOTS = "User-agent: *\nAllow: /\n"


def log(msg: str) -> None:
    print(f"[relay {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# --------------------------------------------------------------------- потоки клиента
class Relay:
    """Одно WSS-соединение и все его TCP-потоки."""

    def __init__(self, peer: P.WsPeer, allow, deny, tag: str):
        self.peer = peer
        self.allow = allow
        self.deny = deny
        self.tag = tag
        self.streams = {}                 # sid -> socket
        self.lock = threading.Lock()
        self.dead = threading.Event()
        self.opened = 0
        self.bytes_out = 0

    # ------------------------------------------------------------------ outbound
    def _allowed(self, host: str, port: int) -> bool:
        if self.deny and any(host == d or host.endswith("." + d) for d in self.deny):
            return False
        if self.allow and not any(host == a or host.endswith("." + a) for a in self.allow):
            return False
        return True

    def _dial(self, sid: int, host: str, port: int) -> None:
        try:
            if not self._allowed(host, port):
                raise OSError(f"направление запрещено политикой: {host}:{port}")
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as e:
            log(f"{self.tag} stream {sid}: не подключиться к {host}:{port} — {e}")
            self._send(P.T_ERR, sid, str(e).encode("utf-8", "replace")[:200])
            return

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(None)
        with self.lock:
            if self.dead.is_set():
                P.close_socket(sock)
                return
            self.streams[sid] = sock
            self.opened += 1
        self._send(P.T_OK, sid)
        threading.Thread(target=self._pump_out, args=(sid, sock),
                         name=f"out-{sid}", daemon=True).start()

    def _pump_out(self, sid: int, sock: socket.socket) -> None:
        """socket -> WebSocket (направление «ответ сайта» -> браузер)."""
        try:
            while not self.dead.is_set():
                data = sock.recv(P.CHUNK)
                if not data:
                    break
                self.bytes_out += len(data)
                self._send(P.T_DATA, sid, data)
        except OSError:
            pass
        finally:
            self._send(P.T_CLOSE, sid)
            self._drop(sid)

    # ------------------------------------------------------------------ запись
    def _send(self, ctype: int, sid: int, payload: bytes = b"") -> None:
        if self.dead.is_set():
            return
        try:
            self.peer.send(P.encode(ctype, sid, payload))
        except (OSError, P.ProtocolError) as e:
            log(f"{self.tag}: запись в сокет не удалась — {e}")
            self.dead.set()

    def _drop(self, sid: int) -> None:
        with self.lock:
            sock = self.streams.pop(sid, None)
        if sock is not None:
            P.close_socket(sock)

    # ------------------------------------------------------------------ главный цикл
    def run(self) -> None:
        threading.Thread(target=self._keepalive, name="ping", daemon=True).start()
        try:
            while not self.dead.is_set():
                opcode, msg = self.peer.recv_message()
                if opcode != P.OP_BINARY:
                    continue                      # текстовые сообщения сайт не ждёт
                try:
                    ctype, sid, payload = P.decode(msg)
                except P.ProtocolError as e:
                    log(f"{self.tag}: {e}")
                    break

                if ctype == P.T_OPEN:
                    with self.lock:
                        busy = len(self.streams)
                    if busy >= MAX_STREAMS_PER_CONN:
                        self._send(P.T_ERR, sid, b"too many streams")
                        continue
                    try:
                        host, port = P.decode_target(payload)
                    except P.ProtocolError as e:
                        self._send(P.T_ERR, sid, str(e).encode())
                        continue
                    threading.Thread(target=self._dial, args=(sid, host, port),
                                     name=f"dial-{sid}", daemon=True).start()
                elif ctype == P.T_DATA:
                    with self.lock:
                        sock = self.streams.get(sid)
                    if sock is None:
                        continue
                    try:
                        sock.sendall(payload)
                    except OSError:
                        self._send(P.T_CLOSE, sid)
                        self._drop(sid)
                elif ctype == P.T_CLOSE:
                    self._send(P.T_CLOSE, sid)
                    self._drop(sid)
                elif ctype == P.T_PING:
                    self._send(P.T_PONG, sid)
        except (ConnectionError, OSError, P.ProtocolError) as e:
            log(f"{self.tag}: соединение закончилось — {e}")
        finally:
            self.dead.set()
            with self.lock:
                sids = list(self.streams)
            for sid in sids:
                self._drop(sid)
            log(f"{self.tag}: закрыто (потоков открыто {self.opened}, "
                f"отдано {self.bytes_out / 1024:.0f} КБ)")

    def _keepalive(self) -> None:
        while not self.dead.wait(PING_INTERVAL):
            self._send(P.T_PING, 0)


# ------------------------------------------------------------------- HTTP/WS сервер
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"
    sys_version = ""            # не светить Python в Server:

    # наследуется из сервера
    secret = ""
    ws_path = DEFAULT_WS_PATH
    landing = LANDING
    allow = ()
    deny = ()
    quiet = False

    def log_message(self, *_a):
        pass

    # ------------------------------------------------------------------ ответы сайта
    def _html(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=300")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _not_found(self) -> None:
        self._html(404, b"<!doctype html><meta charset=utf-8><title>404</title>"
                        b"<h1>404 Not Found</h1>")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self._not_found()

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("/", "/index.html"):
            return self._html(200, self.landing)
        if path == "/robots.txt":
            return self._html(200, ROBOTS.encode(), "text/plain; charset=utf-8")
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path != self.ws_path:
            return self._not_found()

        # ---- здесь начинается туннель ----
        if self.headers.get("Upgrade", "").lower() != "websocket":
            # обычный посетитель, зашедший по прямой: сайт отвечает как сайт
            return self._html(200, self.landing)

        key = self.headers.get("Sec-WebSocket-Key", "")
        version = self.headers.get("Sec-WebSocket-Version", "")
        if not key or version != "13":
            return self._html(400, b"Bad Request: invalid websocket handshake",
                              "text/plain; charset=utf-8")
        if not self._authorized():
            # ничем не отличается от обычного «сюда нельзя»
            return self._html(403, b"<!doctype html><meta charset=utf-8><title>403</title>"
                                   b"<h1>403 Forbidden</h1>")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", P.ws_accept_key(key))
        self.end_headers()

        self.close_connection = True          # больше ничего не парсим
        peer_addr = self.client_address[0]
        tag = f"[{peer_addr}]"
        if not self.quiet:
            log(f"{tag} туннель открыт")
        peer = P.WsPeer(self.connection, mask_out=False)
        Relay(peer, self.allow, self.deny, tag).run()

    def _authorized(self) -> bool:
        if not self.secret:
            return False
        want = self.secret.encode("utf-8")
        # ключ прячем в cookie — так соединение неотличимо от обычного сайта с сессией.
        # Сравниваем байтами: secrets.compare_digest для str требует ASCII-only,
        # а ключ может содержать любые символы (иначе релей упал бы на первом же запросе).
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME and secrets.compare_digest(
                    value.encode("utf-8", "replace"), want):
                return True
        # запасной вариант для клиентов, которые не шлют cookie (например, Worker-сборки)
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return secrets.compare_digest(auth[7:].encode("utf-8", "replace"), want)
        return False


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_landing(path: str) -> bytes:
    if path:
        p = Path(path)
        if p.is_file():
            return p.read_bytes()
        print(f"[relay] [-] файл сайта не найден: {p} — беру встроенную страницу",
              file=sys.stderr)
    return LANDING.encode("utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Сайт-шлюз (HTTPS + WebSocket -> TCP)")
    ap.add_argument("--host", default="0.0.0.0", help="адрес для прослушивания (0.0.0.0 = все)")
    ap.add_argument("--port", type=int, default=443, help="порт (обычно 443)")
    ap.add_argument("--cert", required=True, help="сертификат (PEM), для продакшена — настоящий")
    ap.add_argument("--key", required=True, help="закрытый ключ (PEM)")
    ap.add_argument("--secret", default="", help="общий ключ доступа (cookie sid=...)")
    ap.add_argument("--gen-secret", action="store_true", help="сгенерировать и напечатать ключ")
    ap.add_argument("--ws-path", default=DEFAULT_WS_PATH, help="путь WebSocket-эндпоинта")
    ap.add_argument("--site-file", default="", help="своя HTML-страница вместо встроенной")
    ap.add_argument("--allow", default="", help="разрешённые домены через запятую (пусто = все)")
    ap.add_argument("--deny", default="", help="запрещённые домены через запятую")
    ap.add_argument("--insecure-plain-http", action="store_true",
                    help="без TLS — ТОЛЬКО для локальных тестов")
    ap.add_argument("--quiet", action="store_true", help="не писать про каждое подключение")
    ns = ap.parse_args(argv)

    if ns.gen_secret:
        print(secrets.token_urlsafe(24))
        return 0

    if not ns.secret:
        ap.error("--secret обязателен: без него релей становится открытым прокси. "
                 "Сгенерировать: --gen-secret")

    Handler.secret = ns.secret
    Handler.ws_path = ns.ws_path
    Handler.landing = build_landing(ns.site_file)
    Handler.allow = tuple(x.strip() for x in ns.allow.split(",") if x.strip())
    Handler.deny = tuple(x.strip() for x in ns.deny.split(",") if x.strip())
    Handler.quiet = ns.quiet

    httpd = Server((ns.host, ns.port), Handler)
    scheme = "http"
    if not ns.insecure_plain_http:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(ns.cert, ns.key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS")
        except ssl.SSLError:
            pass
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    log(f"слушаю {scheme}://{ns.host}:{ns.port}  ws={ns.ws_path}  "
        f"allow={list(Handler.allow) or 'все'}  deny={list(Handler.deny) or '—'}")
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        log("остановлен")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
