"""
Модуль выявления аномалий в сетевом трафике.

Реализует:
  - агрегацию метрик в реальном времени (PPS, BPS, доля SYN, топ-источники);
  - периодический сброс счётчиков (раз в AGGREGATION_INTERVAL секунд);
  - простые правила детекции DDoS-подобной активности;
  - запись сводок и алертов в SQLite.

Агрегация работает в фоновом потоке, чтобы не блокировать захват пакетов.
"""

import threading
from collections import Counter
from datetime import datetime

from config import AGGREGATION_INTERVAL, THRESHOLDS
from storage.database import save_alert, save_metrics


class TrafficAggregator:
    """Потокобезопасный агрегатор метрик с периодическим сбросом."""

    def __init__(self):
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
                if "S" in flags:
                    self.tcp_syn += 1
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

        # Правило 2: высокая доля SYN среди TCP (признак SYN Flood)
        if (
            metrics["tcp_total"] >= 10
            and metrics["syn_ratio"] > THRESHOLDS["syn_ratio"]
        ):
            alerts.append(
                {
                    "type": "SYN_FLOOD",
                    "src_ip": metrics["top_src_ip"],
                    "details": (
                        f"SYN ratio={metrics['syn_ratio']:.1%} "
                        f"(порог {THRESHOLDS['syn_ratio']:.0%}), "
                        f"TCP={metrics['tcp_total']}"
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

        return alerts

    # ---------- Вывод и запись ----------

    def _report(self, metrics: dict, alerts: list):
        """Печатает сводку и алерты, сохраняет в БД."""
        ts = metrics["timestamp"].strftime("%H:%M:%S")
        print(
            f"[{ts}] "
            f"PPS={metrics['total_pps']:>7.1f} | "
            f"BPS={metrics['total_bps'] / 1024:>8.1f} KB/s | "
            f"SYN={metrics['syn_ratio']:>5.1%} | "
            f"uniq={metrics['unique_src_ips']:>3} | "
            f"top={metrics['top_src_ip'] or '-':<15} "
            f"({metrics['top_src_pps']:.1f} pps)"
        )

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
