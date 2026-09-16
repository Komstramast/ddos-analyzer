"""
Точка входа приложения для анализа сетевого трафика.

Запускает:
  - фоновую агрегацию метрик;
  - захват пакетов;
  - правила детекции аномалий;
  - запись результатов в SQLite.
"""

import sys

from analysis.detector import TrafficAggregator
from analysis.features import extract_features
from capture.sniffer import start_sniffing
from storage.database import init_db


def main():
    print("=" * 78)
    print("  DDoS Traffic Analyzer — этап A: агрегация метрик и детекция")
    print("=" * 78)

    init_db()

    aggregator = TrafficAggregator()

    def on_packet(packet):
        features = extract_features(packet)
        if features:
            aggregator.add_packet(features)

    aggregator.start()
    print("Агрегация метрик запущена (сводка раз в секунду).\n")

    try:
        start_sniffing(
            count=0,  # бесконечный захват
            save_to="data/capture.pcap",
            on_packet=on_packet,
            verbose=False,  # не печатать каждый пакет
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
