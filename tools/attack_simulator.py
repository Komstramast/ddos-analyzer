"""
CLI-обёртка для запуска генераторов тестового трафика.

Использование:
    python tools/attack_simulator.py syn --target 192.168.56.1 --port 80 --rate 500 --duration 10
    python tools/attack_simulator.py udp --target 192.168.56.1 --port 9999 --rate 500 --duration 10
    python tools/attack_simulator.py http --url http://192.168.56.1:5000/ --rate 100 --duration 10
"""

import argparse
import sys
from pathlib import Path

# Добавляем корень проекта в sys.path, чтобы работали импорты `tools.*`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tools import attackers
from tools.attackers import _validate_target


def _confirm(target: str):
    """Требует подтверждения перед запуском атаки."""
    print("=" * 70)
    print("  ГЕНЕРАТОР ТЕСТОВОГО ТРАФИКА")
    print("=" * 70)
    print(f"  Цель: {target}")
    print()
    print("  ВНИМАНИЕ: этот скрипт создаёт нагрузку на цель.")
    print("  Запускайте только на свои устройства или изолированные VM.")
    print()
    answer = input("  Введите 'yes' для продолжения: ").strip().lower()
    if answer != "yes":
        print("  Отменено.")
        sys.exit(0)
    print()


def cmd_syn(args):
    try:
        _validate_target(args.target)
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    _confirm(f"{args.target}:{args.port}")
    attackers.syn_flood(
        target=args.target,
        port=args.port,
        rate=args.rate,
        duration=args.duration,
        spoof_src=not args.no_spoof,
    )


def cmd_udp(args):
    try:
        _validate_target(args.target)
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    _confirm(f"{args.target}:{args.port}")
    attackers.udp_flood(
        target=args.target,
        port=args.port,
        rate=args.rate,
        duration=args.duration,
        payload_size=args.payload_size,
    )


def cmd_http(args):
    from urllib.parse import urlparse

    parsed = urlparse(args.url)
    if not parsed.hostname:
        print(f"Ошибка: не удалось разобрать URL: {args.url}")
        sys.exit(1)
    try:
        _validate_target(parsed.hostname)
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    _confirm(args.url)
    attackers.http_flood(
        url=args.url,
        rate=args.rate,
        duration=args.duration,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Генератор тестового трафика для проверки детектора DDoS"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # SYN-flood
    p_syn = sub.add_parser("syn", help="TCP SYN-flood")
    p_syn.add_argument("--target", required=True, help="IP цели")
    p_syn.add_argument("--port", type=int, default=80, help="Порт цели")
    p_syn.add_argument("--rate", type=int, default=500, help="Пакетов в секунду")
    p_syn.add_argument("--duration", type=int, default=10, help="Длительность (сек)")
    p_syn.add_argument(
        "--no-spoof", action="store_true", help="Не подменять IP-источник"
    )
    p_syn.set_defaults(func=cmd_syn)

    # UDP-flood
    p_udp = sub.add_parser("udp", help="UDP-flood")
    p_udp.add_argument("--target", required=True, help="IP цели")
    p_udp.add_argument("--port", type=int, default=9999, help="Порт цели")
    p_udp.add_argument("--rate", type=int, default=500, help="Пакетов в секунду")
    p_udp.add_argument("--duration", type=int, default=10, help="Длительность (сек)")
    p_udp.add_argument(
        "--payload-size", type=int, default=1024, help="Размер payload в байтах"
    )
    p_udp.set_defaults(func=cmd_udp)

    # HTTP-flood
    p_http = sub.add_parser("http", help="HTTP-flood")
    p_http.add_argument("--url", required=True, help="Полный URL цели")
    p_http.add_argument("--rate", type=int, default=100, help="Запросов в секунду")
    p_http.add_argument("--duration", type=int, default=10, help="Длительность (сек)")
    p_http.set_defaults(func=cmd_http)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
