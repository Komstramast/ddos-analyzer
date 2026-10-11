"""
Генератор HTTP-нагрузки для тестирования HTTP-flood.

Запускает N параллельных потоков, каждый из которых шлёт GET-запросы
к указанному URL на протяжении заданного времени.

Использование:
    python tools/http_load.py <url> [duration] [concurrency]

Пример:
    python tools/http_load.py http://192.168.56.101:5000/ 30 50
"""

import concurrent.futures
import sys
import time

import requests


def worker(url: str, end_time: float) -> int:
    """Поток-работник: шлёт запросы до истечения end_time."""
    count = 0
    session = requests.Session()
    session.headers.update(
        {"Connection": "close"}
    )  # без keep-alive → больше TCP-пакетов

    while time.time() < end_time:
        try:
            session.get(url, timeout=2)
            count += 1
        except Exception:
            pass

    return count


def main():
    if len(sys.argv) < 2:
        print("Использование: python tools/http_load.py <url> [duration] [concurrency]")
        print("Пример: python tools/http_load.py http://192.168.56.101:5000/ 30 50")
        sys.exit(1)

    url = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    concurrency = int(sys.argv[3]) if len(sys.argv) > 3 else 50

    print(f"HTTP-load: url={url}, duration={duration}s, concurrency={concurrency}")
    print("Запуск...")

    end_time = time.time() + duration
    total = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker, url, end_time) for _ in range(concurrency)]
        for f in concurrent.futures.as_completed(futures):
            total += f.result()

    elapsed = duration
    print(f"\nВсего запросов: {total}")
    print(f"Средний RPS: {total / elapsed:.1f}")


if __name__ == "__main__":
    main()
