# analysis_engine.py
import os, csv, json
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, DNSQR
from heuristics import generate_alerts
from collections import defaultdict, Counter

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    tcp_sessions = defaultdict(list)
    dns_domains = []
    http_requests = []
    http_responses = []

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                key = (src_ip, pkt[TCP].sport, dst_ip, pkt[TCP].dport)
                seq = pkt[TCP].seq
                payload = pkt[Raw].load if pkt.haslayer(Raw) else b""
                tcp_sessions[key].append((seq, payload))

            if UDP in pkt and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                if pkt.haslayer(DNSQR):
                    dns_domains.append(pkt[DNSQR].qname.decode() if pkt[DNSQR].qname else "")

    tcp_streams = {}
    for key, segments in tcp_sessions.items():
        segments.sort(key=lambda x: x[0])
        stream_data = b"".join(seg[1] for seg in segments)
        tcp_streams[key] = stream_data

        try:
            text = stream_data.decode(errors="ignore")
            if text.startswith(("GET", "POST")):
                lines = text.split("\r\n")
                host_line = next((l for l in lines if l.startswith("Host:")), "")
                host = host_line.split(":", 1)[1].strip() if host_line else ""
                full_url = f"http://{host}{lines[0].split()[1]}" if host else lines[0]
                http_requests.append(full_url)
        except: pass

        try:
            text = stream_data.decode(errors="ignore")
            if text.startswith("HTTP/1."):
                lines = text.split("\r\n")
                status_line = lines[0] if len(lines) > 0 else ""
                content_length = 0
                for line in lines:
                    if line.lower().startswith("content-length:"):
                        try: content_length = int(line.split(":",1)[1].strip())
                        except: pass
                http_responses.append({"session": key, "status_line": status_line, "content_length": content_length})
        except: pass

    total_packets = len(packets)
    tcp_count = sum(1 for pkt in packets if TCP in pkt)
    udp_count = sum(1 for pkt in packets if UDP in pkt)
    unique_src = set(src for (src,_,_,_) in tcp_streams.keys())
    unique_dst = set(dst for (_,_,dst,_) in tcp_streams.keys())

    summary = {
        "total_packets": total_packets,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "unique_src": len(unique_src),
        "unique_dst": len(unique_dst),
        "dns_count": len(dns_domains),
        "http_count": len(http_requests),
        "top_talkers": Counter({ip: sum(len(data) for k,data in tcp_streams.items() if ip in k[:2] or ip in k[2:]) for ip in unique_src|unique_dst}).most_common(5)
    }

    alerts = generate_alerts(summary, tcp_streams)

    return summary, tcp_streams, dns_domains, http_requests, http_responses, alerts

def export_report(data, file_path, format="csv"):
    if format=="csv":
        with open(file_path,"w",newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Type","Data"])
            for key,val in data.items():
                writer.writerow([key,val])
    elif format=="json":
        with open(file_path,"w") as f:
            json.dump(data,f, indent=2)
