"""
Модуль захвата сетевого трафика.
Использует Scapy для перехвата пакетов с указанного интерфейса.

Поддерживает два режима:
  - вывод пакетов в консоль в реальном времени;
  - сохранение захваченных пакетов в .pcap-файл для дальнейшего анализа.
"""

from scapy.all import ICMP, IP, TCP, UDP, sniff, wrpcap

from config import CAPTURE_FILTER, CAPTURE_INTERFACE

# Буфер для пакетов, которые нужно сохранить в pcap.
# Хранит только те пакеты, что прошли фильтр и были захвачены в текущей сессии.
_captured_packets = []


def packet_callback(packet):
    """
    Функция-обработчик, вызываемая для каждого захваченного пакета.
    Выводит краткую информацию в консоль и складывает пакет в буфер.
    """
    if IP not in packet:
        return

    # Складываем в буфер для последующего сохранения в pcap.
    _captured_packets.append(packet)

    ip_layer = packet[IP]
    proto = "OTHER"
    info = ""

    if TCP in packet:
        proto = "TCP"
        flags = packet[TCP].flags
        info = f"sport={packet[TCP].sport} dport={packet[TCP].dport} flags={flags}"
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
    """
    Сохраняет накопленные пакеты в .pcap-файл.

    Args:
        path: путь к файлу (например, "data/normal_traffic.pcap").
              Родительская папка должна существовать.
    """
    if not _captured_packets:
        print("Нет пакетов для сохранения — файл не создан.")
        return

    wrpcap(path, _captured_packets)
    print(f"\nСохранено {len(_captured_packets)} пакетов в {path}")


def start_sniffing(count: int = 0, save_to: str | None = None):
    """
    Запускает захват трафика.

    Args:
        count: количество пакетов для захвата (0 = бесконечно).
        save_to: путь к .pcap-файлу. Если None — пакеты не сохраняются.
                 Файл записывается по завершении захвата (в т.ч. по Ctrl+C).
    """
    print(f"Захват на интерфейсе: {CAPTURE_INTERFACE or 'default'}")
    print(f"Фильтр: {CAPTURE_FILTER}")
    if save_to:
        print(f"Сохранение в: {save_to}")
    print("Нажмите Ctrl+C для остановки.\n")

    _captured_packets.clear()

    try:
        sniff(
            iface=CAPTURE_INTERFACE,
            filter=CAPTURE_FILTER,
            prn=packet_callback,
            store=False,  # не храним пакеты в памяти Scapy — только в своём буфере
            count=count,
        )
    finally:
        # finally сработает и при нормальном завершении, и при Ctrl+C.
        # Так мы не потеряем захваченные пакеты, если остановимся вручную.
        if save_to:
            save_pcap(save_to)
