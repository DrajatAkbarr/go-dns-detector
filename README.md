# 🛡️ DNS Exfiltration Detector (Go)

![Go Version](https://img.shields.io/badge/go-1.21%2B-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue)
![Security](https://img.shields.io/badge/focus-Network%20Security-red)

> **A real-time Network Intrusion Detection System (NIDS) specifically designed to detect DNS Tunneling and data exfiltration attempts using Deep Packet Inspection (DPI).**

## 📖 Overview

Traditional firewalls often overlook DNS traffic (Port 53), making it a prime vector for attackers to smuggle data out of compromised networks. This tool monitors network interfaces in promiscuous mode, captures DNS packets, and analyzes payload entropy to identify anomalous queries indicative of **DNS Tunneling**.

**Why Go?**
Built with Golang for high-concurrency packet processing and low-latency analysis, ensuring minimal impact on network performance.

## 🚀 Key Features

- **Deep Packet Inspection (DPI):** Analyzes raw packet headers and payloads using `gopacket`.
- **Entropy Analysis:** Calculates Shannon entropy of DNS queries to detect encrypted/encoded data chunks typical of tunneling attacks (e.g., Cobalt Strike beacons, Iodine).
- **Query Length Heuristics:** Flags unusually long subdomains that deviate from standard RFC norms.
- **Red Team Simulation:** Includes a built-in attack simulator (`simulasi/`) to validate detection logic.

## 🛠️ Architecture

```mermaid
graph LR
    A[Network Interface] -->|Raw Packets| B(Packet Capturer)
    B -->|Filter: UDP 53| C{Analyzer Engine}
    C -->|Normal Query| D[Allow Log]
    C -->|High Entropy / Long String| E[🚨 ALERT TRIGGER]
    E -->|Log Details| F[Console/File Output]
