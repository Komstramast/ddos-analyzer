"""
Точка входа приложения для анализа сетевого трафика.
Запускает захват пакетов и выводит их в консоль.
"""

import sys

from capture.sniffer import start_sniffing


def main():
    print("=" * 70)
    print("  DDoS Traffic Analyzer — прототип (захват трафика)")
    print("=" * 70)

    # count=20 — захватим 20 пакетов и остановимся.
    # Для бесконечного захвата передайте count=0.
    start_sniffing(count=500, save_to="data/normal_traffic.pcap")

    print("\nЗахват завершён.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nОстановлено пользователем.")
        sys.exit(0)
