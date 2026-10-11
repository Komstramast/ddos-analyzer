"""
HTTP-сервер на Waitress для тестирования HTTP-flood.
Waitress — многопоточный WSGI-сервер, устойчив к нагрузке.
"""

from flask import Flask
from waitress import serve

app = Flask(__name__)


@app.route("/")
def index():
    return "OK"


if __name__ == "__main__":
    print("Waitress слушает 0.0.0.0:5000 (threads=100)")
    serve(app, host="0.0.0.0", port=5000, threads=100)
