from pathlib import Path

from flask import Flask, jsonify, send_from_directory

from capture import clear_records, snapshot, start_capture, statistics

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT_ROOT / "frontend"

app = Flask(__name__)


@app.get("/")
def home():
    return send_from_directory(FRONTEND, "index.html")


@app.get("/api/packets")
def packets():
    return jsonify(snapshot())


@app.get("/api/summary")
def summary():
    return jsonify(statistics())


@app.post("/api/packets/clear")
def clear():
    clear_records()
    return jsonify({"ok": True})


if __name__ == "__main__":
    start_capture()
    print("Network Pulse is available at http://127.0.0.1:5001")
    print("Packet capture may require administrator privileges.")
    app.run(host="127.0.0.1", port=5001, debug=False)
