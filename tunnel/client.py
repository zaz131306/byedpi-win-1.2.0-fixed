#!/usr/bin/env python3
"""
client.py — локальный SOCKS5-прокси, который прячет трафик внутри WSS к сайту-шлюзу.

    python3 -m tunnel.client --relay wss://example.com/live --secret '...' [--port 1080]

Что получается:

    Firefox --SOCKS5--> 127.0.0.1:1080  (этот процесс)
                             |
                             |  одно WSS-соединение, мультиплексирование потоков,
                             |  TLS-отпечаток настоящего Chrome (curl_cffi)
                             v
                        сайт-шлюз:443   (tunnel/relay.py или Cloudflare Worker)
                             |
                             +--> настоящие сайты

Для Firefox и для расширения это ровно тот же контракт, что и у ciadpi: локальный
SOCKS v5 на 127.0.0.1:1080 с DNS через прокси. Поэтому ни расширение, ни менеджер
переделывать не нужно — меняется только процесс, который слушает порт.

Отпечаток TLS
-------------
По умолчанию используется curl_cffi (libcurl + BoringSSL) с impersonate="chrome":
настоящие JA3/JA4, порядок расширений ClientHello, GREASE, ALPN, HTTP-заголовки и их
порядок. Ради этого НЕ нужен сам браузер — весит десятки мегабайт вместо сотен.

Если curl_cffi не установлен, клиент работает на стандартной библиотеке: туннель
поднимется, но TLS-отпечаток будет питоновский. Он честно предупреждает об этом
в логе — для проверки связности годится, для продакшена нет.

Зависимости: только стандартная библиотека; curl_cffi — опционально и рекомендуется.
"""
from __future__ import annotations

import argparse
import base64
import os
import queue
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol as P  # noqa: E402

COOKIE_NAME = "sid"
INBOX_MAX = 512                 # кадров в очереди потока, дальше — естественное торможение
OPEN_TIMEOUT = 20.0
RECV_POLL = 1.0
RECONNECT_MIN, RECONNECT_MAX = 1.0, 30.0

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def log(msg: str) -> None:
    print(f"[tunnel {time.strftime('%H:%M:%S')}] {msg}", flush=True)


class TunnelError(Exception):
    pass


class StreamClosed(Exception):
    pass


# ============================================================ транспорты (WSS)
class SslTransport:
    """Запасной вариант: WebSocket на стандартной библиотеке.

    Работает везде, но TLS-отпечаток — питоновский OpenSSL. Для продакшена
    поставьте curl_cffi.
    """

    name = "stdlib-ssl"
    fingerprint = "python/OpenSSL — НЕ похож на браузер"

    def __init__(self, url: str, secret: str, ca: str = "", insecure: bool = False,
                 headers=None):
        parts = urlsplit(url)
        if parts.scheme not in ("wss", "ws"):
            raise TunnelError(f"нужна схема wss:// (или ws:// для локальных тестов), не {parts.scheme}://")
        self._secure = parts.scheme == "wss"
        self._secret = secret
        self._host = parts.hostname
        self._port = parts.port or (443 if self._secure else 80)
        self._path = parts.path or "/"
        if parts.query:
            self._path += "?" + parts.query
        self._extra_headers = headers or {}

        raw = socket.create_connection((self._host, self._port), timeout=15)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock, rest = self._handshake(raw, parts, ca, insecure)
        self._sock = sock
        self._peer = P.WsPeer(sock, mask_out=True)     # клиент обязан маскировать кадры
        if rest:
            self._peer._buf = rest                     # сервер мог прислать данные сразу

    def _handshake(self, sock, parts, ca: str, insecure: bool):
        """TLS + HTTP Upgrade -> (готовый сокет, остаток буфера).

        Любой сбой закрывает сокет: цикл переподключения повторяет попытки
        вечно, и без этого каждая неудача утекала бы файловым дескриптором.
        Важно закрывать именно текущий объект sock: после wrap_socket()
        исходный сокет уже detached и его close() ничего не освобождает.
        """
        try:
            if self._secure:
                ctx = ssl.create_default_context(cafile=ca or None)
                if insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self._host)

            key = base64.b64encode(os.urandom(16)).decode()
            origin = f"{'https' if self._secure else 'http'}://{parts.netloc}"
            lines = [
                f"GET {self._path} HTTP/1.1",
                f"Host: {parts.netloc}",
                f"User-Agent: {UA}",
                "Accept: */*",
                "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding: gzip, deflate, br",
                "Cache-Control: no-cache",
                "Pragma: no-cache",
                "Connection: Upgrade",
                "Upgrade: websocket",
                f"Origin: {origin}",
                "Sec-WebSocket-Version: 13",
                f"Sec-WebSocket-Key: {key}",
                "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
            ]
            if self._secret:
                lines.append(f"Cookie: {COOKIE_NAME}={self._secret}")
            for k, v in self._extra_headers.items():
                lines.append(f"{k}: {v}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

            # читаем ответ до пустой строки
            buf = b""
            sock.settimeout(15)
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise TunnelError("сервер закрыл соединение во время handshake")
                buf += chunk
                if len(buf) > 65536:
                    raise TunnelError("handshake-ответ подозрительно большой")
            head, _, rest = buf.partition(b"\r\n\r\n")
            status = head.split(b"\r\n", 1)[0].decode("latin-1")
            if "101" not in status:
                raise TunnelError(f"сервер не поднял WebSocket: {status}\n{head.decode('latin-1', 'replace')[:400]}")
            expected = P.ws_accept_key(key)
            if expected.encode() not in head:
                raise TunnelError("Sec-WebSocket-Accept не совпал — это не WebSocket-сервер")

            sock.settimeout(None)
            return sock, rest
        except BaseException:
            P.close_socket(sock)
            raise

    def recv(self, timeout: float):
        self._sock.settimeout(timeout)
        try:
            opcode, msg = self._peer.recv_message()
            return opcode, msg
        except socket.timeout:
            return None
        except ssl.SSLError as e:
            if "timed out" in str(e):
                return None
            raise
        finally:
            try:
                self._sock.settimeout(None)
            except OSError:
                pass

    def send(self, data: bytes) -> None:
        self._peer.send(data, P.OP_BINARY)

    def close(self) -> None:
        self._peer.close_socket()


class CurlTransport:
    """Основной вариант: curl_cffi с настоящим отпечатком Chrome."""

    name = "curl_cffi"

    def __init__(self, url: str, secret: str, ca: str = "", insecure: bool = False,
                 impersonate: str = "chrome", headers=None):
        try:
            from curl_cffi.requests import Session
            from curl_cffi.requests import websockets as cw
        except ImportError as e:
            raise TunnelError(
                "curl_cffi не установлен. Поставьте: pip install curl_cffi\n"
                "Без него туннель работает, но TLS-отпечаток будет питоновский "
                "(--transport stdlib-ssl, чтобы не видеть эту ошибку).") from e

        self._cw = cw
        self.fingerprint = f"curl_cffi impersonate={impersonate}"
        self._session = Session(impersonate=impersonate)
        verify = False if insecure else (ca or True)
        cookies = {COOKIE_NAME: secret} if secret else None
        base = dict(impersonate=impersonate, verify=verify)
        if cookies:
            base["cookies"] = cookies
        rich = dict(base, max_message_size=4 << 20, timeout=(15.0, 120.0))
        if headers:
            rich["headers"] = headers
        try:
            self._ws = self._session.ws_connect(url, **rich)
        except TypeError:
            # старая версия curl_cffi с другим набором параметров — важно НЕ потерять
            # cookie, иначе шлюз ответит 403
            self._ws = self._session.ws_connect(url, **base)
        self._lock = threading.Lock()
        self._frag = bytearray()

    def recv(self, timeout: float):
        cw = self._cw
        cont = getattr(cw.CurlWsFlag, "CONT", 4)
        close = getattr(cw.CurlWsFlag, "CLOSE", 8)
        deadline = time.monotonic() + max(timeout, 0.1) + 30.0
        while True:
            try:
                data, flags = self._ws.recv(timeout=timeout)
            except Exception as e:                      # WebSocketTimeout и прочее
                if type(e).__name__.endswith("Timeout") and not self._frag:
                    return None
                if time.monotonic() > deadline:
                    raise
                continue
            if flags & close:
                raise ConnectionError("сервер закрыл WebSocket")
            self._frag += data or b""
            if flags & cont:
                if time.monotonic() > deadline:
                    raise ConnectionError("не дождались конца фрагментированного сообщения")
                continue
            out = bytes(self._frag)
            self._frag = bytearray()
            return P.OP_BINARY, out

    def send(self, data: bytes) -> None:
        with self._lock:
            self._ws.send(data)

    def close(self) -> None:
        try:
            self._ws.close()
        except Exception:
            pass
        try:
            self._session.close()
        except Exception:
            pass


def make_transport(kind, url, secret, ca, insecure, impersonate):
    if kind == "auto":
        try:
            return CurlTransport(url, secret, ca, insecure, impersonate)
        except TunnelError as e:
            log(f"curl_cffi недоступен ({e}); переключаюсь на стандартную библиотеку")
            kind = "stdlib-ssl"
    if kind == "curl_cffi":
        return CurlTransport(url, secret, ca, insecure, impersonate)
    return SslTransport(url, secret, ca, insecure)


# ================================================================== мультиплексор
class Stream:
    """Одно TCP-соединение браузера внутри общего WSS."""

    def __init__(self, mux, sid):
        self.mux = mux
        self.sid = sid
        self.inbox = queue.Queue(maxsize=INBOX_MAX)
        self.opened = threading.Event()
        self.error = None
        self.dead = False

    def _fail(self, why):
        self.error = self.error or why
        self.dead = True
        self.opened.set()
        try:
            self.inbox.put_nowait(None)       # None = «больше данных не будет»
        except queue.Full:
            pass

    def wait_open(self, timeout=OPEN_TIMEOUT):
        if not self.opened.wait(timeout):
            self._fail("таймаут ожидания ответа шлюза")
            return False
        if self.error:
            return False
        return True

    def recv(self, timeout=RECV_POLL):
        """-> bytes | None (таймаут) | StreamClosed"""
        if self.dead and self.inbox.empty():
            raise StreamClosed(self.error or "поток закрыт")
        try:
            item = self.inbox.get(timeout=timeout)
        except queue.Empty:
            if self.dead:
                raise StreamClosed(self.error or "поток закрыт")
            return None
        if item is None:
            raise StreamClosed(self.error or "поток закрыт")
        return item

    def send(self, data: bytes):
        if self.dead:
            raise StreamClosed(self.error or "поток закрыт")
        self.mux._send(P.T_DATA, self.sid, data)

    def close(self):
        if self.dead:
            return
        self.mux._send(P.T_CLOSE, self.sid)
        self._fail("закрыто локально")
        self.mux._forget(self.sid)


class Multiplexer:
    def __init__(self, transport, verbose=False):
        self.t = transport
        self.verbose = verbose
        self.streams = {}
        self.lock = threading.Lock()
        self._next_sid = 0
        self.stop = threading.Event()
        self.dead = threading.Event()
        self.sent = self.received = 0
        self.opened = 0
        self._reader = threading.Thread(target=self._read_loop, name="ws-reader", daemon=True)
        self._reader.start()

    # ------------------------------------------------------------------ потоки
    def _new_sid(self):
        with self.lock:
            while True:
                self._next_sid = (self._next_sid % P.MAX_SID) + 1
                if self._next_sid not in self.streams:
                    return self._next_sid

    def open_stream(self, host: str, port: int) -> Stream:
        if self.dead.is_set():
            raise TunnelError("туннель не подключён")
        sid = self._new_sid()
        st = Stream(self, sid)
        with self.lock:
            self.streams[sid] = st
            self.opened += 1
        try:
            self._send(P.T_OPEN, sid, P.encode_target(host, port))
        except (OSError, ConnectionError) as e:
            self._forget(sid)
            raise TunnelError(f"не удалось отправить OPEN: {e}") from e
        if not st.wait_open():
            self._forget(sid)
            raise TunnelError(st.error or "шлюз отказался соединять")
        return st

    def _forget(self, sid):
        with self.lock:
            self.streams.pop(sid, None)

    def _send(self, ctype, sid, payload=b""):
        self.t.send(P.encode(ctype, sid, payload))
        self.sent += len(payload)

    def alive_streams(self):
        with self.lock:
            return len(self.streams)

    # ------------------------------------------------------------------ чтение
    def _read_loop(self):
        last_ping = time.monotonic()
        try:
            while not self.stop.is_set():
                item = self.t.recv(RECV_POLL)
                if item is None:
                    # keepalive: не чаще раза в 20 с, иначе туннель сам себя и выдаст
                    if time.monotonic() - last_ping > 20.0:
                        last_ping = time.monotonic()
                        self._send(P.T_PING, 0)
                    continue
                opcode, msg = item
                if opcode != P.OP_BINARY:
                    continue
                try:
                    ctype, sid, payload = P.decode(msg)
                except P.ProtocolError as e:
                    log(f"мусор в кадре: {e}")
                    continue
                self._dispatch(ctype, sid, payload)
        except Exception as e:
            log(f"чтение туннеля закончилось: {type(e).__name__}: {e}")
        finally:
            self.dead.set()
            with self.lock:
                victims = list(self.streams.values())
                self.streams.clear()
            for st in victims:
                st._fail("туннель оборвался")
            # обязательно закрываем транспорт здесь: ClientApp при обрыве создаёт
            # новый Multiplexer, а старый без этого держал бы сокет до сборщика
            # мусора (ResourceWarning + подтекающие fd при частых переподключениях).
            try:
                self.t.close()
            except Exception:
                pass

    def _dispatch(self, ctype, sid, payload):
        if ctype == P.T_DATA:
            with self.lock:
                st = self.streams.get(sid)
            if st is None:
                self._send(P.T_CLOSE, sid)       # поток уже никому не нужен
                return
            self.received += len(payload)
            try:
                st.inbox.put(payload, timeout=30)   # полный ящик = тормозим отправителя
            except queue.Full:
                log(f"поток {sid}: очередь переполнена, закрываю")
                st._fail("очередь переполнена")
                self._send(P.T_CLOSE, sid)
                self._forget(sid)
        elif ctype == P.T_OK:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                st.opened.set()
        elif ctype == P.T_ERR:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                st._fail(payload.decode("utf-8", "replace") or "шлюз отказал")
        elif ctype == P.T_CLOSE:
            with self.lock:
                st = self.streams.get(sid)
            if st:
                st._fail("закрыто шлюзом")
                self._forget(sid)
        elif ctype == P.T_PING:
            self._send(P.T_PONG, sid)
        elif ctype == P.T_PONG:
            pass

    def shutdown(self):
        self.stop.set()
        self.dead.set()
        try:
            self.t.close()
        except Exception:
            pass


# ================================================================= SOCKS5-сервер
class SocksHandler(socketserver.BaseRequestHandler):
    mux_holder = None            # устанавливается из main(): объект с .mux()
    verbose = False

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def handle(self):
        try:
            self._handle()
        except (OSError, StreamClosed, TunnelError) as e:
            if self.verbose:
                log(f"клиент {self.client_address[0]}: {type(e).__name__}: {e}")
        finally:
            # именно shutdown+close: поток upstream() может ещё висеть в recv()
            # на этом же сокете, и простой close() тогда не отправит FIN —
            # браузер будет вечно ждать EOF. См. protocol.close_socket().
            P.close_socket(self.request)

    def _handle(self):
        head = self._read(2)
        if not head or head[0] != 0x05:
            return
        nmethods = head[1]
        methods = self._read(nmethods) or b""
        if 0x00 in methods:
            self.request.sendall(b"\x05\x00")            # без аутентификации
        else:
            self.request.sendall(b"\x05\xFF")            # приемлемых методов нет
            return

        req = self._read(4)
        if not req or req[0] != 0x05:
            return
        # запрос SOCKS5: [0]=ver [1]=cmd [2]=rsv [3]=atyp
        cmd, atyp = req[1], req[3]
        if cmd != 0x01:
            # BIND и UDP ASSOCIATE не поддерживаем: HTTP/3 (QUIC) всё равно отключён,
            # а значит UDP браузеру через этот прокси не нужен.
            self.request.sendall(b"\x05\x07\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            return

        if atyp == 0x01:
            raw = self._read(4)
            host = socket.inet_ntoa(raw) if raw else ""
        elif atyp == 0x03:
            ln = self._read(1)
            if not ln:
                return
            raw = self._read(ln[0])
            # доменное имя в SOCKS5 — байты; idna-кодек не принимает errors=,
            # поэтому ascii, а невалидные байты заменяем и отдаём шлюзу как есть
            host = raw.decode("ascii", "replace") if raw else ""
        elif atyp == 0x04:
            raw = self._read(16)
            host = socket.inet_ntop(socket.AF_INET6, raw) if raw else ""
        else:
            self.request.sendall(b"\x05\x08\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            return
        praw = self._read(2)
        if not host or not praw:
            return
        port = struct.unpack(">H", praw)[0]

        mux = self.mux_holder.mux()
        if mux is None or mux.dead.is_set():
            self.request.sendall(b"\x05\x01\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            return

        try:
            st = mux.open_stream(host, port)
        except (TunnelError, OSError) as e:
            if self.verbose:
                log(f"OPEN {host}:{port} не удался: {e}")
            self.request.sendall(b"\x05\x01\x00\x01" + b"\x00" * 4 + b"\x00\x00")
            return

        # ответ «соединение установлено»; адрес привязки роли не играет
        self.request.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
        if self.verbose:
            log(f"-> {host}:{port}")

        self.request.settimeout(None)
        sock = self.request

        def upstream():
            """браузер -> туннель"""
            try:
                while True:
                    data = sock.recv(P.CHUNK)
                    if not data:
                        break
                    st.send(data)
            except (OSError, StreamClosed):
                pass
            finally:
                st.close()

        up = threading.Thread(target=upstream, name=f"up-{st.sid}", daemon=True)
        up.start()
        try:
            while True:
                data = st.recv(1.0)
                if data is None:
                    if up.is_alive() is False:
                        break
                    continue
                sock.sendall(data)
        except (OSError, StreamClosed):
            pass
        finally:
            st.close()
            # upstream() почти наверняка висит в блокирующем recv() на этом же
            # сокете. shutdown() будит его (recv вернёт b""), и join завершается
            # сразу; без этого мы ждали бы весь таймаут, а вторая сторона не
            # увидела бы EOF ещё секунду.
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            up.join(timeout=1.0)


class SocksServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


# ======================================================================== главный
class ClientApp:
    """Держит живое WSS-соединение и переподключается, когда оно рвётся."""

    def __init__(self, ns):
        self.ns = ns
        self.bound_port = ns.port
        self._mux = None
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def mux(self):
        with self._lock:
            return self._mux if (self._mux and not self._mux.dead.is_set()) else None

    def stop(self):
        """Останавливает переподключение и рвёт текущий туннель."""
        self._stop.set()
        with self._lock:
            mux, self._mux = self._mux, None
        if mux:
            mux.shutdown()

    def _connect(self):
        t = make_transport(self.ns.transport, self.ns.relay, self.ns.secret,
                           self.ns.ca, self.ns.insecure, self.ns.impersonate)
        log(f"туннель установлен: {self.ns.relay}  [{t.name} · {t.fingerprint}]")
        return Multiplexer(t, verbose=self.ns.verbose)

    def run(self) -> int:
        ns = self.ns
        SocksHandler.mux_holder = self
        SocksHandler.verbose = ns.verbose

        # 1) порт свободен? Проверяем заранее: незачем подключаться к шлюзу,
        #    если слушать всё равно негде.
        if ns.port:
            fam = socket.AF_INET6 if ":" in str(ns.host) else socket.AF_INET
            probe = socket.socket(fam)
            try:
                # SO_REUSEADDR — ровно как у SocksServer(allow_reuse_address=True).
                # Без него пробный bind строже настоящего: порт в TIME_WAIT выглядел
                # бы занятым, хотя слушать на нём можно, и мы отказались бы стартовать.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind((ns.host, int(ns.port)))
            except OSError as e:
                log(f"[!] не могу слушать {ns.host}:{ns.port} — {e}")
                log("    порт занят? проверить: python3 host/ctl.py status")
                return 2
            finally:
                probe.close()

        # 2) сперва поднимаем туннель, и только потом открываем SOCKS-порт.
        #    Хост считает прокси запущенным по факту слушания порта; открой мы
        #    порт раньше, расширение показало бы «работает», а соединения
        #    отбивались с кодом 1, пока WSS ещё не установлен.
        backoff = RECONNECT_MIN
        mux = None
        while not self._stop.is_set():
            try:
                mux = self._connect()
                break
            except Exception as e:
                log(f"[!] не подключиться к шлюзу: {type(e).__name__}: {e}")
                log(f"    повтор через {backoff:.0f} с")
                if self._stop.wait(backoff):
                    return 0
                backoff = min(backoff * 2, RECONNECT_MAX)
        if self._stop.is_set() or mux is None:
            return 0

        # 3) туннель живой — можно принимать браузер
        try:
            server = SocksServer((ns.host, ns.port), SocksHandler)
        except OSError as e:
            log(f"[!] не могу слушать {ns.host}:{ns.port} — {e}")
            mux.shutdown()
            return 2
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2},
                         name="socks", daemon=True).start()
        # порт мог быть 0 («выбери сам») — сообщаем фактический, его же читает менеджер
        self.bound_port = server.server_address[1]
        log(f"SOCKS5 слушает {ns.host}:{self.bound_port}  ->  {ns.relay}")

        with self._lock:
            self._mux = mux
        backoff = RECONNECT_MIN
        stats_at = time.monotonic()

        while not self._stop.is_set():
            while not mux.dead.is_set() and not self._stop.is_set():
                self._stop.wait(1.0)
                if ns.verbose and time.monotonic() - stats_at > 60:
                    stats_at = time.monotonic()
                    log(f"статус: потоков {mux.alive_streams()}, всего открыто {mux.opened}, "
                        f"отдано {mux.received / 1048576:.1f} МБ")
            if self._stop.is_set():
                break
            with self._lock:
                self._mux = None
            log("туннель оборвался — переподключаюсь")
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, RECONNECT_MAX)
            try:
                mux = self._connect()
            except Exception as e:
                log(f"[!] не подключиться к шлюзу: {type(e).__name__}: {e}")
                continue
            with self._lock:
                self._mux = mux
            backoff = RECONNECT_MIN

        with self._lock:
            mux, self._mux = self._mux, None
        if mux:
            mux.shutdown()
        server.shutdown()
        server.server_close()
        return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Локальный SOCKS5-прокси, туннелирующий трафик через WSS к сайту-шлюзу")
    ap.add_argument("--relay", required=True, help="адрес шлюза, напр. wss://example.com/live")
    ap.add_argument("--secret", default=os.environ.get("TUNNEL_SECRET", ""),
                    help="общий ключ (cookie sid=...); можно задать TUNNEL_SECRET в окружении")
    ap.add_argument("--host", default="127.0.0.1", help="адрес SOCKS5-слушателя")
    ap.add_argument("--port", type=int, default=1080, help="порт SOCKS5 (обычно 1080)")
    ap.add_argument("--transport", default="auto",
                    choices=("auto", "curl_cffi", "stdlib-ssl"),
                    help="auto = curl_cffi, если установлен (настоящий отпечаток Chrome)")
    ap.add_argument("--impersonate", default="chrome",
                    help="отпечаток для curl_cffi: chrome, chrome131, safari, edge, firefox…")
    ap.add_argument("--ca", default="", help="свой CA-файл (PEM) для проверки сертификата")
    ap.add_argument("--insecure", action="store_true",
                    help="не проверять сертификат — ТОЛЬКО для локальных тестов")
    ap.add_argument("--verbose", action="store_true", help="писать про каждое соединение")
    ns = ap.parse_args(argv)

    if not ns.secret:
        log("[!] --secret не задан: шлюз без ключа отвечать не будет")

    try:
        return ClientApp(ns).run()
    except KeyboardInterrupt:
        log("остановлен")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
