"""
Веб-интерфейс для визуализации метрик DDoS-детектора.
Читает данные из SQLite базы.
"""

import sys
from pathlib import Path

# Добавляем корень проекта в sys.path, чтобы работал импорт config
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import sqlite3

from flask import Flask, jsonify, render_template

import config

app = Flask(__name__, template_folder="templates", static_folder="static")


def get_db_connection():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/metrics")
def api_metrics():
    """Возвращает последние 60 секунд метрик для графиков."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT timestamp, total_pps, total_bps, syn_ratio, unique_src_ips, entropy
        FROM metrics ORDER BY id DESC LIMIT 60
    """).fetchall()
    conn.close()

    # Разворачиваем, чтобы график шёл слева направо (от старых к новым)
    data = [dict(row) for row in reversed(rows)]
    return jsonify(data)


@app.route("/api/alerts")
def api_alerts():
    """Возвращает последние 10 алертов."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT timestamp, alert_type, src_ip, details
        FROM alerts ORDER BY id DESC LIMIT 10
    """).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/status")
def api_status():
    """Возвращает текущий уровень угрозы и последние метрики."""
    conn = get_db_connection()

    # Последний алерт (если был за последние 3 секунды)
    recent_alert = conn.execute("""
        SELECT alert_type, timestamp FROM alerts 
        WHERE timestamp >= datetime('now', 'localtime', '-3 seconds')
        ORDER BY id DESC LIMIT 1
    """).fetchone()

    # Последняя метрика
    latest = conn.execute("""
        SELECT total_pps, unique_src_ips FROM metrics ORDER BY id DESC LIMIT 1
    """).fetchone()
    conn.close()

    level = "green"
    if recent_alert:
        level = (
            "red"
            if recent_alert["alert_type"] in ["DISTRIBUTED_FLOOD", "SYN_FLOOD"]
            else "yellow"
        )

    return jsonify(
        {
            "level": level,
            "pps": latest["total_pps"] if latest else 0,
            "unique_ips": latest["unique_src_ips"] if latest else 0,
        }
    )


if __name__ == "__main__":
    print(f"Запуск веб-сервера на http://{config.WEB_HOST}:{config.WEB_PORT}")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False)
