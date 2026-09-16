"""
Конфигурация приложения.
Все настройки в одном месте — легко менять и объяснять в ВКР.
"""

# --- Сетевые настройки ---
# Интерфейс для захвата. None = Scapy выберет интерфейс по умолчанию.
# Если захотите указать явно — на Windows это имя из ipconfig (например, "Ethernet"),
# на Linux — из ifconfig (например, "eth0" или "wlan0").
CAPTURE_INTERFACE = r"\Device\NPF_{635E3D4A-FA0F-4C3B-AC07-4F8B3EA13674}"

# BPF-фильтр: захватываем только IP-трафик (TCP, UDP, ICMP).
# Это снижает нагрузку и отсекает служебные протоколы.
CAPTURE_FILTER = "(tcp or udp port 53 or icmp) and not port 8886"

# --- Настройки анализа (пока не используются, но пригодятся позже) ---
AGGREGATION_INTERVAL = 1.0

THRESHOLDS = {
    "pps_per_ip": 100,  # Пакетов в секунду от одного IP
    "syn_ratio": 0.8,  # Доля SYN-пакетов среди TCP
    "udp_flood_pps": 200,  # PPS для UDP-флуда на один порт
}

# --- Хранение ---
DATABASE_PATH = "data/traffic.db"
LOG_PATH = "data/alerts.log"

# --- Веб-интерфейс ---
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
