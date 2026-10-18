"""
Точка входа приложения для анализа сетевого трафика.

Поддерживает CLI-аргументы для гибкой настройки.
"""

import argparse
import sys

import config
from analysis.detector import TrafficAggregator
from analysis.features import extract_features
from capture.sniffer import start_sniffing
from storage.database import init_db


def parse_args():
    parser = argparse.ArgumentParser(
        description="DDoS Traffic Analyzer — анализ сетевого трафика",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python main.py
  python main.py --show pps,syn,top
  python main.py --show time,pps,bps --iface "\\Device\\NPF_{...}"
  python main.py --duration 60 --no-save
        """,
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Сетевой интерфейс (по умолчанию — из config.py)",
    )
    parser.add_argument(
        "--show",
        type=str,
        default=None,
        help="Поля через запятую: time,pps,bps,syn,uniq,top,udp",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Длительность захвата в секундах (0 = без ограничения)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Не сохранять захваченные пакеты в pcap",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Печатать каждый захваченный пакет",
    )
    parser.add_argument(
        "--threshold-pps",
        type=int,
        default=None,
        help="Переопределить порог PPS от одного IP",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Переопределяем конфиг на основе аргументов
    if args.iface:
        config.CAPTURE_INTERFACE = args.iface
    if args.threshold_pps:
        config.THRESHOLDS["pps_per_ip"] = args.threshold_pps

    output_fields = None
    if args.show:
        output_fields = [f.strip() for f in args.show.split(",") if f.strip()]
        valid = {"time", "pps", "bps", "syn", "syn_top", "uniq", "top", "udp"}
        unknown = set(output_fields) - valid
        if unknown:
            print(f"Ошибка: неизвестные поля вывода: {unknown}")
            print(f"Допустимые: {sorted(valid)}")
            sys.exit(1)

    print("=" * 78)
    print("  DDoS Traffic Analyzer — этап A: агрегация метрик и детекция")
    print("=" * 78)

    init_db()

    aggregator = TrafficAggregator(output_fields=output_fields)

    def on_packet(packet):
        features = extract_features(packet)
        if features:
            aggregator.add_packet(features)

    aggregator.start()
    print(f"Агрегация запущена. Поля вывода: {', '.join(aggregator.output_fields)}")
    print(f"Индикатор уровня: {'вкл' if config.SHOW_THREAT_LEVEL else 'выкл'}\n")

    save_to = None if args.no_save else "data/capture.pcap"

    try:
        start_sniffing(
            count=0,  # без лимита по пакетам
            duration=args.duration,  # лимит по времени (в секундах)
            save_to=save_to,
            on_packet=on_packet,
            verbose=args.verbose,
        )
    finally:
        print("\nОстанавливаю агрегатор...")
        aggregator.stop()
        print("Готово.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nОстановлено пользователем.")
        sys.exit(0)
