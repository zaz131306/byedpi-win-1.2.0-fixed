"""tunnel — транспорт «трафик внутри настоящего HTTPS-соединения с сайтом-шлюзом».

Состав:
    protocol.py   мультиплексирование потоков + каркас WebSocket (RFC 6455), без зависимостей
    relay.py      сайт-шлюз: HTTPS на 443, страница-заглушка, WebSocket -> TCP
    client.py     локальный SOCKS5 на 1080 -> WSS к шлюзу (отпечаток Chrome через curl_cffi)

Запуск пары локально (проверка связности):
    python3 -m tunnel.relay  --cert cert.pem --key key.pem --port 8443 --secret S
    python3 -m tunnel.client --relay wss://127.0.0.1:8443/live --secret S --port 1080 --insecure
"""
