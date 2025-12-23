# heuristics.py
from collections import Counter

def suspicious_domain(domain):
    return len(domain) > 20 or "suspicious" in domain.lower()

def large_outbound_streams(streams, threshold=1000):
    suspicious = []
    for key, data in streams.items():
        if len(data) > threshold:
            suspicious.append({"session": key, "size": len(data)})
    return suspicious

def frequent_destinations(streams, threshold=5):
    counter = Counter(dst for (_, _, dst, _) in streams.keys())
    return [ip for ip, count in counter.items() if count >= threshold]

def generate_alerts(summary, tcp_streams):
    alerts = []

    if summary["total_packets"] > 10000:
        alerts.append({"type":"High Traffic","message":"Total packets exceed threshold (10k)."})

    large_streams = large_outbound_streams(tcp_streams)
    for s in large_streams:
        alerts.append({"type":"Large Stream","message":f"Session {s['session']} has {s['size']} bytes."})

    frequent = frequent_destinations(tcp_streams)
    for ip in frequent:
        alerts.append({"type":"Frequent Destination","message":f"IP {ip} contacted multiple times."})

    return alerts
