# Network Pulse — packet monitor

A locally hosted Flask dashboard that visualises live IP packet metadata using
Scapy. It is an original implementation inspired by the internship task's
requirements, with a different design and a metadata-only privacy approach.

## Run it

1. Open a terminal in this folder.
2. Create and activate a virtual environment (recommended):
   `python3 -m venv .venv && source .venv/bin/activate`
3. Install packages: `pip install -r requirements.txt`
4. Start the app: `sudo python3 backend/app.py`
5. Visit `http://127.0.0.1:5001`.

Packet capture may require administrator access and should be used only on
networks where you have permission. The application does not retain payload
contents—only timestamp, endpoints, protocol, ports, and packet size.

## Project structure

```
backend/app.py       Flask routes and local web server
backend/capture.py   Capture thread, data normalisation, statistics
frontend/index.html  Responsive dashboard UI
```
