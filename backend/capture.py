"""Packet capture helpers for the Network Pulse dashboard.

This monitor is intended for traffic on networks you own or are authorised to
observe. It records packet metadata only; packet contents are never retained.
"""

from collections import Counter, deque
from datetime import datetime, timezone
from threading import Lock, Thread

from scapy.all import ICMP, IP, TCP, UDP, sniff

MAX_RECORDS = 150
records = deque(maxlen=MAX_RECORDS)
records_lock = Lock()
capture_state = {"running": False, "error": None}


def _protocol_name(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    return f"IP-{packet[IP].proto}"


def _packet_summary(packet):
    """Return a display-safe, JSON-ready metadata record."""
    if IP not in packet:
        return None

    source_port = destination_port = None
    if TCP in packet:
        source_port, destination_port = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        source_port, destination_port = packet[UDP].sport, packet[UDP].dport

    return {
        "captured_at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "source": packet[IP].src,
        "destination": packet[IP].dst,
        "protocol": _protocol_name(packet),
        "source_port": source_port,
        "destination_port": destination_port,
        "bytes": len(packet),
    }


def store_packet(packet):
    summary = _packet_summary(packet)
    if summary is not None:
        with records_lock:
            records.append(summary)


def _capture_loop():
    capture_state["running"] = True
    capture_state["error"] = None
    try:
        sniff(filter="ip", prn=store_packet, store=False)
    except Exception as exc:  # e.g. insufficient capture permissions
        capture_state["error"] = str(exc)
    finally:
        capture_state["running"] = False


def start_capture():
    """Start capture once in a daemon thread and return whether it was started."""
    if capture_state["running"]:
        return False
    Thread(target=_capture_loop, name="packet-capture", daemon=True).start()
    return True


def snapshot():
    with records_lock:
        return list(reversed(records))


def statistics():
    with records_lock:
        protocol_counts = Counter(item["protocol"] for item in records)
        total_bytes = sum(item["bytes"] for item in records)
        total = len(records)

    known = sum(protocol_counts[name] for name in ("TCP", "UDP", "ICMP"))
    return {
        "total": total,
        "tcp": protocol_counts["TCP"],
        "udp": protocol_counts["UDP"],
        "icmp": protocol_counts["ICMP"],
        "other": total - known,
        "total_bytes": total_bytes,
        "status": "capturing" if capture_state["running"] else "waiting",
        "error": capture_state["error"],
    }


def clear_records():
    with records_lock:
        records.clear()
