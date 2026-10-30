"""
protocol.py — протокол туннеля и каркас WebSocket (RFC 6455) на стандартной библиотеке.

Зачем это нужно
---------------
Идея: трафик браузера прячется ВНУТРЬ настоящего HTTPS-соединения с обычным сайтом.
Провайдер видит валидную TLS-сессию и WebSocket к реальному домену — то есть
обычный веб-сёрфинг, а не VPN. Релей на том конце просто пересылает байты дальше.

Поверх ОДНОГО WSS-соединения мультиплексируется много TCP-потоков, поэтому на все
вкладки браузера приходится одна TLS-сессия (ровно как у настоящего сайта).

Формат кадра
------------
Каждый кадр — одно бинарное WebSocket-сообщение:

    байт 0      тип
    байты 1-2   id потока (uint16, big-endian)
    остальное   полезная нагрузка

    OPEN   клиент -> релей   host\0port   «соедини меня с этим адресом»
    OK     релей -> клиент    —            соединение установлено
    ERR    релей -> клиент    текст        не удалось (текст уходит в лог, не в браузер)
    DATA   в обе стороны      байты потока
    CLOSE  в обе стороны      —            поток закрыт
    PING / PONG               —            keepalive

id потока назначает клиент; релей их только повторяет. 0 — служебный.

WebSocket-каркас здесь свой, потому что релей обязан работать без зависимостей:
его же потом переносят в Cloudflare Worker или на nginx+любой язык. Клиент при
этом по умолчанию ходит через curl_cffi (настоящий отпечаток Chrome), а этот
каркас использует как запасной вариант.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
import threading

# --------------------------------------------------------------------- типы кадров
T_OPEN = 0x01
T_DATA = 0x02
T_CLOSE = 0x03
T_OK = 0x04
T_ERR = 0x05
T_PING = 0x06
T_PONG = 0x07

TYPE_NAMES = {T_OPEN: "OPEN", T_DATA: "DATA", T_CLOSE: "CLOSE",
              T_OK: "OK", T_ERR: "ERR", T_PING: "PING", T_PONG: "PONG"}

MAX_SID = 0xFFFF
# Сколько байт потока кладем в один кадр. Меньше MTU-агрегации не нужно, больше —
# увеличивает задержку для соседних потоков (head-of-line blocking).
CHUNK = 16384
HEADER_LEN = 3

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# WebSocket-opcodes
OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class ProtocolError(Exception):
    """Пришёл мусор, который не разбирается как кадр туннеля."""


# --------------------------------------------------------------------- кодирование
def encode(ctype: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack(">BH", ctype, sid & MAX_SID) + payload


def decode(buf: bytes):
    """-> (тип, id потока, полезная нагрузка)"""
    if len(buf) < HEADER_LEN:
        raise ProtocolError(f"кадр короче {HEADER_LEN} байт: {len(buf)}")
    ctype, sid = struct.unpack(">BH", buf[:HEADER_LEN])
    return ctype, sid, buf[HEADER_LEN:]


def encode_target(host: str, port: int) -> bytes:
    """Адрес назначения для OPEN. Хост — домен или IP, всегда UTF-8."""
    return host.encode("utf-8") + b"\x00" + struct.pack(">H", port & 0xFFFF)


def decode_target(payload: bytes):
    """-> (host, port)

    Разделитель — ПЕРВЫЙ нулевой байт: в имени хоста нулей не бывает, а вот
    старший байт порта при port < 256 равен 0x00, поэтому искать надо с начала.
    """
    if b"\x00" not in payload:
        raise ProtocolError("в OPEN нет разделителя адреса")
    raw, _, praw = payload.partition(b"\x00")
    if len(praw) != 2:
        raise ProtocolError(f"в OPEN неверная длина порта: {len(praw)}")
    host = raw.decode("utf-8", "replace")
    port = struct.unpack(">H", praw)[0]
    if not host or not (0 < port < 65536):
        raise ProtocolError(f"бессмысленный адрес в OPEN: {host!r}:{port}")
    return host, port


# ------------------------------------------------------------------------- сокеты
def close_socket(sock) -> None:
    """Закрывает сокет так, чтобы вторая сторона гарантированно увидела EOF.

    Один только ``sock.close()`` НЕ отправляет FIN, если в другом потоке на этом
    же сокете висит блокирующий ``recv()``: закрытие откладывается до возврата
    из чтения, и вторая сторона ждёт конца данных вечно (у нас это выглядело как
    ``TimeoutError`` вместо аккуратного ``b""``). ``shutdown(SHUT_RDWR)`` будит
    заблокированное чтение и отправляет FIN сразу, поэтому сначала shutdown,
    потом close. Ошибки глотаются: сокет может быть уже закрыт с двух сторон.
    """
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# ------------------------------------------------------------------------- WebSocket
def ws_accept_key(key: str) -> str:
    """Sec-WebSocket-Accept из Sec-WebSocket-Key клиента (RFC 6455 §4.2.2)."""
    return base64.b64encode(hashlib.sha1(key.strip().encode() + WS_GUID).digest()).decode()


def _apply_mask(data: bytes, mask: bytes) -> bytes:
    """Симметричная операция: и маскирует, и размаскивает."""
    if not data:
        return data
    if len(data) >= 4:
        # быстро: XOR целыми числами
        reps = (len(data) + 3) // 4
        keystream = int.from_bytes(mask * reps, "big") >> (8 * (reps * 4 - len(data)))
        return (int.from_bytes(data, "big") ^ keystream).to_bytes(len(data), "big")
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data))


class WsPeer:
    """Чтение и запись WebSocket-сообщений поверх уже установленного сокета.

    Используется и релеем (серверная сторона, исходящие кадры без маски),
    и запасным клиентом (клиентская сторона, mask_out=True — клиенты обязаны
    маскировать кадры, иначе сервер их отвергнет).
    """

    def __init__(self, sock, mask_out: bool = False, max_message: int = 8 << 20):
        self._sock = sock
        self._mask_out = mask_out
        self._max_message = max_message
        self._buf = b""
        self._frag = bytearray()
        self._frag_op = None
        self.closed = False
        self._send_lock = threading.Lock()

    # ------------------------------------------------------------------ чтение
    def _exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                self.closed = True
                raise ConnectionError("соединение закрыто второй стороной")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_message(self):
        """-> (opcode, payload) для ПОЛНОГО сообщения.

        Контрольные кадры (ping/pong/close) и фрагментацию обрабатывает сама,
        наружу отдаёт только собранные текстовые/бинарные сообщения.
        """
        while True:
            b0, b1 = self._exact(2)
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._exact(8))[0]
            if length > self._max_message:
                raise ProtocolError(f"сообщение слишком большое: {length}")
            mask = self._exact(4) if masked else None
            data = self._exact(length) if length else b""
            if mask:
                data = _apply_mask(data, mask)

            if opcode == OP_CLOSE:
                self.closed = True
                raise ConnectionError("получен close-кадр")
            if opcode == OP_PING:
                self.send(data, OP_PONG)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CONT:
                self._frag += data
                if len(self._frag) > self._max_message:
                    raise ProtocolError("фрагментированное сообщение слишком большое")
                if fin:
                    out, op = bytes(self._frag), self._frag_op
                    self._frag = bytearray()
                    self._frag_op = None
                    return op, out
                continue

            if fin:
                return opcode, data
            self._frag = bytearray(data)
            self._frag_op = opcode

    # ------------------------------------------------------------------ запись
    def send(self, payload: bytes, opcode: int = OP_BINARY) -> None:
        n = len(payload)
        head = bytearray((0x80 | opcode,))
        mbit = 0x80 if self._mask_out else 0
        if n < 126:
            head.append(mbit | n)
        elif n < 65536:
            head.append(mbit | 126)
            head += struct.pack(">H", n)
        else:
            head.append(mbit | 127)
            head += struct.pack(">Q", n)
        if self._mask_out:
            mask = os.urandom(4)
            head += mask
            payload = _apply_mask(payload, mask)
        with self._send_lock:
            self._sock.sendall(bytes(head) + payload)

    def close_socket(self) -> None:
        close_socket(self._sock)
        self.closed = True
