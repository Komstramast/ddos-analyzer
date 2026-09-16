"""
Модуль работы с базой данных SQLite.
Хранит агрегированные метрики и события безопасности.
"""

import sqlite3

from config import DATABASE_PATH


def init_db():
    """Создаёт таблицы, если они ещё не существуют."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            total_pps REAL,
            total_bps REAL,
            syn_ratio REAL,
            unique_src_ips INTEGER,
            top_src_ip TEXT,
            top_src_pps REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            alert_type TEXT,
            src_ip TEXT,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()
    print(f"База данных инициализирована: {DATABASE_PATH}")


def save_metrics(metrics: dict):
    """Сохраняет агрегированные метрики за интервал."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO metrics
            (total_pps, total_bps, syn_ratio, unique_src_ips, top_src_ip, top_src_pps)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            metrics.get("total_pps"),
            metrics.get("total_bps"),
            metrics.get("syn_ratio"),
            metrics.get("unique_src_ips"),
            metrics.get("top_src_ip"),
            metrics.get("top_src_pps"),
        ),
    )
    conn.commit()
    conn.close()


def save_alert(alert_type: str, src_ip: str, details: str):
    """Сохраняет событие (алерт) в базу."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO alerts (alert_type, src_ip, details)
        VALUES (?, ?, ?)
    """,
        (alert_type, src_ip, details),
    )
    conn.commit()
    conn.close()
