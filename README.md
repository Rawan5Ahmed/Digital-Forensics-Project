# Digital-Forensics-Project
# WireFish – PCAP Network Investigation Tool

![WireFish Logo](./static/W-removebg-preview.png)

---

## Overview

**WireFish** is a **web-based network investigation tool** designed for digital forensics and incident response.  
It allows cybersecurity investigators and SOC analysts to upload **PCAP/PCAPNG** files and get a **detailed analysis of network traffic**.  

**Key Features:**

- Parse network traffic: TCP, UDP, HTTP, DNS, and other protocols.
- Rank top talkers by bandwidth usage.
- Detect suspicious activity automatically using heuristics:
  - High traffic from specific IPs
  - Suspicious domains
  - Sensitive URL patterns
- Search and filter traffic by IP or protocol.
- Export results in JSON/CSV.
- Modern, Nemo-inspired UI design that is both **visually engaging** and **investigation-focused**.

## Project Structure
WireFish/

├── app.py -->Flask server & routing

├── analysis_engine.py -->Processes PCAP files, extracts stats

├── heuristics.py -->Suspicious activity detection logic

├── uploads/ -->Temporary storage for uploaded PCAP files

├── static/ -->Frontend assets (CSS, JS, images)

│ ├── index.html -->Main HTML file

│ ├── W-removebg-preview.png -->Logo / watermark

│ ├── exclamation.png -->Alert watermark

│ └── malicious.png -->Critical alert icon

├── screenshots/ -->Store screenshots for README

└── README.md


**Explanation:**

- `app.py` – Runs the web server, handles uploads, and serves the frontend.  
- `analysis_engine.py` – Reads PCAP files, calculates packet statistics, top talkers, DNS queries, HTTP requests, etc.  
- `heuristics.py` – Implements alert rules for suspicious traffic.  
- `uploads/` – Stores uploaded PCAP files temporarily.  
- `static/` – Contains frontend assets (images, styles, scripts).  

---

## Deployment

### Requirements

- Python 3.9+
- Flask
- Scapy

### Steps

1. Clone the repository:

```bash
git clone https://github.com/Rawan5Ahmed/Digital-Forensics-Project.git
cd Digital-Forensics-Project/WireFish
