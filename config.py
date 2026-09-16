"""
Конфигурация приложения.
Все настройки в одном месте — легко менять и объяснять в ВКР.
"""

# --- Сетевые настройки ---
CAPTURE_INTERFACE = r"\Device\NPF_{635E3D4A-FA0F-4C3B-AC07-4F8B3EA13674}"

CAPTURE_FILTER = "(tcp or udp port 53 or icmp) and not port 8886"

# --- Настройки агрегации ---
# Раз в сколько секунд агрегатор сбрасывает счётчики и печатает сводку.
AGGREGATION_INTERVAL = 1.0

# --- Пороги для правил детекции ---
# Эти значения — отправная точка. Их нужно калибровать под свою сеть.
THRESHOLDS = {
    "pps_per_ip": 300,  # PPS от одного IP (больше — подозрительно)
    "syn_ratio": 0.70,  # Доля SYN среди TCP (0.7 = 70%)
    "udp_flood_pps": 400,  # PPS UDP на один порт
}

# --- Хранение ---
DATABASE_PATH = "data/traffic.db"
LOG_PATH = "data/alerts.log"

# --- Веб-интерфейс ---
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
