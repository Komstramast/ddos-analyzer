"""
Модуль выявления аномалий в сетевом трафике.

Реализует:
  - агрегацию метрик в реальном времени (PPS, BPS, доля SYN, топ-источники);
  - периодический сброс счётчиков (раз в AGGREGATION_INTERVAL секунд);
  - простые правила детекции DDoS-подобной активности;
  - запись сводок и алертов в SQLite.

Агрегация работает в фоновом потоке, чтобы не блокировать захват пакетов.
"""

import math
import threading
from collections import Counter
from datetime import datetime

from config import AGGREGATION_INTERVAL, THRESHOLDS
from storage.database import save_alert, save_metrics

_THREAT_SYMBOLS = {
    "green": "🟢",
    "yellow": "🟡",
    "red": "🔴",
}


class TrafficAggregator:
    """Потокобезопасный агрегатор метрик с периодическим сбросом."""

    def __init__(self, output_fields=None):
        from config import OUTPUT_FIELDS

        self.output_fields = output_fields or OUTPUT_FIELDS
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._reset()

    # ---------- Счётчики ----------

    def _reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.src_packets = Counter()
        self.src_bytes = Counter()
        self.protocols = Counter()
        self.tcp_total = 0
        self.tcp_syn = 0
        self.udp_dst_ports = Counter()
        # Новые счётчики — для SYN-ratio по источнику
        self.src_tcp = Counter()
        self.src_syn = Counter()

    def add_packet(self, features: dict):
        """Принимает признаки одного пакета и обновляет счётчики."""
        with self._lock:
            self.total_packets += 1
            self.total_bytes += features["packet_size"]
            self.src_packets[features["src_ip"]] += 1
            self.src_bytes[features["src_ip"]] += features["packet_size"]
            self.protocols[features["protocol"]] += 1

            if features["protocol"] == "TCP":
                self.tcp_total += 1
                flags = features.get("tcp_flags") or ""
                is_syn = "S" in flags
                if is_syn:
                    self.tcp_syn += 1

                src = features["src_ip"]
                self.src_tcp[src] += 1
                if is_syn:
                    self.src_syn[src] += 1

            elif features["protocol"] == "UDP":
                dport = features.get("dst_port")
                if dport is not None:
                    self.udp_dst_ports[dport] += 1

    # ---------- Метрики ----------

    def _collect_metrics(self) -> dict:
        """Собирает метрики из текущих счётчиков. Не сбрасывает."""
        total_pps = self.total_packets / AGGREGATION_INTERVAL
        total_bps = self.total_bytes / AGGREGATION_INTERVAL
        syn_ratio = self.tcp_syn / self.tcp_total if self.tcp_total else 0.0

        if self.src_packets:
            top_ip, top_count = self.src_packets.most_common(1)[0]
            top_pps = top_count / AGGREGATION_INTERVAL
        else:
            top_ip, top_pps = None, 0.0

        if self.udp_dst_ports:
            top_udp_port, top_udp_count = self.udp_dst_ports.most_common(1)[0]
            top_udp_pps = top_udp_count / AGGREGATION_INTERVAL
        else:
            top_udp_port, top_udp_pps = None, 0.0

        if self.src_syn:
            top_syn_ip, top_syn_count = self.src_syn.most_common(1)[0]
            top_syn_total = self.src_tcp.get(top_syn_ip, 0)
            top_syn_ratio = top_syn_count / top_syn_total if top_syn_total else 0.0
        else:
            top_syn_ip, top_syn_count, top_syn_ratio = None, 0, 0.0

        # Расчёт энтропии Шеннона по IP-источникам
        entropy = 0.0
        if self.total_packets > 0:
            for count in self.src_packets.values():
                p = count / self.total_packets
                entropy -= p * math.log2(p)

        return {
            "timestamp": datetime.now(),
            "total_pps": total_pps,
            "total_bps": total_bps,
            "syn_ratio": syn_ratio,
            "tcp_total": self.tcp_total,
            "unique_src_ips": len(self.src_packets),
            "top_src_ip": top_ip,
            "top_src_pps": top_pps,
            "top_udp_port": top_udp_port,
            "top_udp_pps": top_udp_pps,
            "top_syn_ip": top_syn_ip,
            "top_syn_count": top_syn_count,
            "top_syn_ratio": top_syn_ratio,
            "entropy": entropy,
        }

    # ---------- Правила ----------

    def _check_rules(self, metrics: dict) -> list:
        """Применяет эвристики и возвращает список алертов."""
        alerts = []

        # Правило 1: высокий PPS от одного источника
        if metrics["top_src_ip"] and metrics["top_src_pps"] > THRESHOLDS["pps_per_ip"]:
            alerts.append(
                {
                    "type": "HIGH_PPS",
                    "src_ip": metrics["top_src_ip"],
                    "details": (
                        f"PPS={metrics['top_src_pps']:.1f} "
                        f"(порог {THRESHOLDS['pps_per_ip']})"
                    ),
                }
            )

        # Правило 2: SYN Flood от одного источника
        if (
            metrics["top_syn_ip"]
            and metrics["top_syn_count"] >= 10
            and metrics["top_syn_ratio"] > THRESHOLDS["syn_ratio"]
        ):
            alerts.append(
                {
                    "type": "SYN_FLOOD",
                    "src_ip": metrics["top_syn_ip"],
                    "details": (
                        f"SYN ratio={metrics['top_syn_ratio']:.1%} "
                        f"(порог {THRESHOLDS['syn_ratio']:.0%}), "
                        f"SYN={metrics['top_syn_count']} от одного источника"
                    ),
                }
            )

        # Правило 3: UDP-флуд на один порт
        if (
            metrics["top_udp_port"] is not None
            and metrics["top_udp_pps"] > THRESHOLDS["udp_flood_pps"]
        ):
            alerts.append(
                {
                    "type": "UDP_FLOOD",
                    "src_ip": metrics["top_src_ip"],
                    "details": (
                        f"UDP порт {metrics['top_udp_port']}: "
                        f"PPS={metrics['top_udp_pps']:.1f} "
                        f"(порог {THRESHOLDS['udp_flood_pps']})"
                    ),
                }
            )

        # Правило 4: Распределённая атака (ботнет)
        if (
            metrics["unique_src_ips"] >= THRESHOLDS["unique_ips_min"]
            and metrics["entropy"] >= THRESHOLDS["entropy_min"]
            and metrics["total_pps"] > THRESHOLDS["pps_per_ip"]
        ):
            alerts.append(
                {
                    "type": "DISTRIBUTED_FLOOD",
                    "src_ip": "MULTIPLE",
                    "details": (
                        f"Энтропия={metrics['entropy']:.2f} (порог {THRESHOLDS['entropy_min']}), "
                        f"уникальных IP={metrics['unique_src_ips']}, "
                        f"PPS={metrics['total_pps']:.1f}"
                    ),
                }
            )

        return alerts

    def _threat_level(self, metrics: dict, alerts: list) -> str:
        """
        Определяет уровень угрозы по метрикам и алертам:
        🟢 green  — норма
        🟡 yellow — внимание (есть алерты или метрики близки к порогу)
        🔴 red    — атака (много алертов или превышение порогов)
        """
        from config import THREAT_LEVEL, THRESHOLDS

        # Красный: любая распределённая атака или много алертов
        if any(a["type"] == "DISTRIBUTED_FLOOD" for a in alerts):
            return "red"
        if len(alerts) >= THREAT_LEVEL["red_alerts"]:
            return "red"

        # Красный: много алертов
        if len(alerts) >= THREAT_LEVEL["red_alerts"]:
            return "red"

        # Жёлтый: есть алерты
        if len(alerts) >= THREAT_LEVEL["yellow_alerts"]:
            return "yellow"

        # Проверяем, насколько метрики близки к порогам
        ratios = []
        if THRESHOLDS["pps_per_ip"] > 0:
            ratios.append(metrics["top_src_pps"] / THRESHOLDS["pps_per_ip"])
        if THRESHOLDS["syn_ratio"] > 0 and metrics["tcp_total"] >= 10:
            ratios.append(metrics["syn_ratio"] / THRESHOLDS["syn_ratio"])
        if THRESHOLDS["udp_flood_pps"] > 0 and metrics["top_udp_pps"] > 0:
            ratios.append(metrics["top_udp_pps"] / THRESHOLDS["udp_flood_pps"])

        if ratios and max(ratios) >= THREAT_LEVEL["yellow_ratio"]:
            return "yellow"

        return "green"

    def _format_metrics(self, metrics: dict, level: str) -> str:
        """Формирует строку сводки по выбранным пользователем полям."""
        from config import SHOW_THREAT_LEVEL

        parts = []
        for field in self.output_fields:
            if field == "time":
                parts.append(metrics["timestamp"].strftime("%H:%M:%S"))
            elif field == "pps":
                parts.append(f"PPS={metrics['total_pps']:>7.1f}")
            elif field == "bps":
                parts.append(f"BPS={metrics['total_bps'] / 1024:>8.1f}KB/s")
            elif field == "syn":
                parts.append(f"SYN={metrics['syn_ratio']:>5.1%}")
            elif field == "syn_top":
                parts.append(f"SYNtop={metrics['top_syn_ratio']:>5.1%}")
            elif field == "uniq":
                parts.append(f"uniq={metrics['unique_src_ips']:>3}")
            elif field == "top":
                top = metrics["top_src_ip"] or "-"
                parts.append(f"top={top:<15} ({metrics['top_src_pps']:.1f}pps)")
            elif field == "udp":
                port = metrics["top_udp_port"] or "-"
                parts.append(f"udp={port} ({metrics['top_udp_pps']:.1f}pps)")
            elif field == "entropy":
                parts.append(f"ent={metrics['entropy']:>5.2f}")

        prefix = ""
        if SHOW_THREAT_LEVEL:
            prefix = f"[{_THREAT_SYMBOLS[level]}] "

        return f"{prefix}[{' | '.join(parts)}]"

    # ---------- Вывод и запись ----------

    def _report(self, metrics: dict, alerts: list):
        """Печатает сводку и алерты, сохраняет в БД."""
        level = self._threat_level(metrics, alerts)
        line = self._format_metrics(metrics, level)
        print(line)

        # Алерты печатаем всегда, если они есть — они важны
        for a in alerts:
            print(f"    [!] {a['type']:10} {a['src_ip'] or '-':<15} {a['details']}")

        try:
            save_metrics(metrics)
            for a in alerts:
                save_alert(a["type"], a["src_ip"] or "", a["details"])
        except Exception as e:
            print(f"    ! Ошибка записи в БД: {e}")

    # ---------- Жизненный цикл ----------

    def _flush(self):
        """Собрать метрики, проверить правила, сбросить счётчики."""
        with self._lock:
            metrics = self._collect_metrics()
            alerts = self._check_rules(metrics)
            self._reset()
        return metrics, alerts

    def _run(self):
        """Фоновый цикл агрегации."""
        while not self._stop_event.wait(AGGREGATION_INTERVAL):
            metrics, alerts = self._flush()
            self._report(metrics, alerts)

    def start(self):
        """Запускает фоновую агрегацию."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Останавливает агрегацию и делает финальный flush."""
        if not self._thread:
            return
        self._stop_event.set()
        self._thread.join(timeout=AGGREGATION_INTERVAL + 1)
        # Финальный flush — не теряем последнюю неполную секунду
        metrics, alerts = self._flush()
        if metrics["total_pps"] > 0:
            self._report(metrics, alerts)
