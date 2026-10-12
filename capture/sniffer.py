"""
Модуль захвата сетевого трафика.
Использует Scapy для перехвата пакетов с указанного интерфейса.

Поддерживает:
  - вывод пакетов в консоль в реальном времени (verbose=True);
  - передачу каждого IP-пакета внешнему обработчику через on_packet;
  - сохранение захваченных пакетов в .pcap-файл.
"""

import threading
import time

from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer, wrpcap

from config import CAPTURE_FILTER, CAPTURE_INTERFACE

_captured_packets = []


def _print_packet(packet):
    """Краткий вывод информации о пакете в консоль."""
    ip_layer = packet[IP]
    proto = "OTHER"
    info = ""

    if TCP in packet:
        proto = "TCP"
        info = (
            f"sport={packet[TCP].sport} dport={packet[TCP].dport} "
            f"flags={packet[TCP].flags}"
        )
    elif UDP in packet:
        proto = "UDP"
        info = f"sport={packet[UDP].sport} dport={packet[UDP].dport}"
    elif ICMP in packet:
        proto = "ICMP"
        info = f"type={packet[ICMP].type}"

    print(
        f"[{proto:5}] {ip_layer.src:>15} -> {ip_layer.dst:<15} | "
        f"len={len(packet):>5} | {info}"
    )


def save_pcap(path: str):
    """Сохраняет накопленные пакеты в .pcap-файл."""
    if not _captured_packets:
        print("Нет пакетов для сохранения — файл не создан.")
        return
    wrpcap(path, _captured_packets)
    print(f"\nСохранено {len(_captured_packets)} пакетов в {path}")


def start_sniffing(
    count: int = 0,
    duration: int = 0,
    save_to=None,
    on_packet=None,
    verbose: bool = False,
):
    """
    Запускает захват трафика через AsyncSniffer.

    Args:
        count:    остановиться после N пакетов (0 = без ограничения).
        duration: остановиться через N секунд (0 = без ограничения).
        save_to:  путь к .pcap-файлу.
        on_packet: callback(packet) для каждого IP-пакета.
        verbose:  печатать ли каждый пакет.
    """
    print(f"Захват на интерфейсе: {CAPTURE_INTERFACE or 'default'}")
    print(f"Фильтр: {CAPTURE_FILTER}")
    if duration:
        print(f"Длительность: {duration} сек")
    if count:
        print(f"Лимит пакетов: {count}")
    if save_to:
        print(f"Сохранение в: {save_to}")
    print("Нажмите Ctrl+C для остановки.\n")

    _captured_packets.clear()

    def _callback(packet):
        if IP not in packet:
            return
        _captured_packets.append(packet)
        if verbose:
            _print_packet(packet)
        if on_packet is not None:
            on_packet(packet)

    sniffer = AsyncSniffer(
        iface=CAPTURE_INTERFACE,
        filter=CAPTURE_FILTER,
        prn=_callback,
        store=False,
        count=count,
    )
    sniffer.start()

    # Таймер остановки по времени
    timer = None
    if duration > 0:
        timer = threading.Timer(duration, sniffer.stop)
        timer.daemon = True
        timer.start()

    try:
        while sniffer.running:
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\nОстанавливаю захват (Ctrl+C)...")
    finally:
        if timer is not None:
            timer.cancel()
        if sniffer.running:
            sniffer.stop()
        if save_to:
            save_pcap(save_to)
