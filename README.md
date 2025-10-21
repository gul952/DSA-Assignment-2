# Network Monitor — README

**Course:** CS250 — Data Structures & Algorithms (BSDS-2)
**Assignment:** 2 — Network Monitor
**Author:** *Gulwarina Muska Saleem* 
**Date:** 22 Oct 2025

---

## Project summary

This repository contains a single-file C++ implementation of a Linux Network Packet Analyzer that:

* captures Ethernet frames from a single Linux interface using raw sockets,
* uses **custom** Stack and Queue data structures (no STL for core DS) to manage packets,
* dissects packet layers with a stack-driven parser (Ethernet, IPv4, IPv6, TCP, UDP),
* filters and replays selected packets, retrying failed replays up to **2** times and moving failed ones to a backup queue,
* prints human-readable logs and supports a configurable demo run (default 60 seconds).

The implementation was developed and tested on Ubuntu (VM) and requires root privileges for raw socket access.

---

## Repo contents

* `network_monitor.cpp` — main source (single-file implementation)
* `README.md` — this file
* `capture_log.txt` —  sample output from a demo run

GitHub repo: `https://github.com/gul952/DSA-Assignment-2.git`

---

## System requirements

* Linux (Ubuntu recommended; VirtualBox VM with bridged adapter recommended)
* `g++` (part of `build-essential`)
* `sudo` (root) or capability `CAP_NET_RAW` for raw sockets
* Recommended VM disk: 25–30 GB; RAM: 2 GB minimum (4 GB recommended)

---

## Assumptions (state these in your report)

* Program requires root (or `CAP_NET_RAW`) to open raw sockets. Run with `sudo` unless capabilities set.
* Single interface capture only — user supplies `--iface`.
* IPv6 extension headers are **not** fully parsed (basic IPv6 header handled). Documented limitation.
* Replay re-sends raw frames to the same interface; replay success depends on network/switch policies.

---

## Build (compile)

Open a terminal in the directory containing `network_monitor.cpp`:

```bash
sudo apt update
sudo apt install -y build-essential

# compile
g++ -std=c++17 -O2 -pthread network_monitor.cpp -o network_monitor
```

Optional (instead of sudo every run):

```bash
# Grant CAP_NET_RAW and CAP_NET_ADMIN so you can run without sudo (may still need sudo in some environments)
sudo setcap cap_net_raw,cap_net_admin=eip ./network_monitor
```

---

## Usage / Run examples

1. Identify your interface:

```bash
ip link        # find interface name, e.g., enp0s3
```

2. Basic demo (60s capture):

```bash
sudo ./network_monitor --iface enp0s3 --duration 60 --filter-src 0.0.0.0 --filter-dst 0.0.0.0
```

3. Save output to a log (recommended for report):

```bash
sudo ./network_monitor --iface enp0s3 --duration 60 --filter-src 0.0.0.0 --filter-dst 0.0.0.0 |& tee ~/Desktop/capture_log.txt
```

4. Run with specific filters:

```bash
sudo ./network_monitor --iface enp0s3 --duration 30 --filter-src 192.168.1.10 --filter-dst 8.8.8.8
```

5. Simulate replay failures (demonstrates retry + backup):

```bash
sudo ./network_monitor --iface enp0s3 --duration 30 --simulate-failure |& tee ~/Desktop/capture_log_simfail.txt
```

---

## Command-line flags

* `--iface IFACE` (required) — interface to bind (e.g., `enp0s3`)
* `--duration N` (optional) — demo duration in seconds (default: 60)
* `--filter-src IP` (optional) — source IP filter (use `0.0.0.0` to match any)
* `--filter-dst IP` (optional) — destination IP filter (use `0.0.0.0` to match any)
* `--simulate-failure` (optional) — simulate send failures to show retry/backup behavior

---

## What the program prints (examples)

* `[CAP] id=1 size=93 ts=2025-10-22 00:02:54.179` — captured packet
* `[DSC] id=1 layers=3 src=10.0.2.15 dst=142.250.102.84` — dissected packet
* `[FLT] moved id=xx to replay (delay_ms=yy)` — packet matched filters and queued for replay
* `[RPLY] sent id=xx size=.. attempts=..` — successful replay
* `[RPLY] moved id=xx to backup after 3 attempts` — moved to backup after retries

### Example capture excerpt

```
Starting Network Monitor on iface=enp0s3 duration=60s
Filters: src=0.0.0.0 dst=0.0.0.0
[CAP] id=1 size=93 ts=2025-10-22 00:02:54.179
[CAP] id=2 size=93 ts=2025-10-22 00:02:54.179
[CAP] id=3 size=60 ts=2025-10-22 00:02:54.179
[DSC] id=1 layers=3 src=10.0.2.15 dst=142.250.102.84
[DSC] id=2 layers=3 src=10.0.2.15 dst=142.250.200.170
...
```

---

## How this maps to assignment functional requirements

* **Packet Management:** `Packet` struct stores `id`, `timestamp`, dynamic `raw` buffer, `src_ip`, `dst_ip`. Queues manage lifecycle (enqueue/dequeue, drop-oldest when full).
* **Capture Management:** `AF_PACKET` raw socket bound to `--iface` captures frames continuously in a capture thread.
* **Packet Dissection:** Custom `Stack<ParseFrame>` used to parse Ethernet, IPv4, IPv6 (basic), TCP, UDP. All parsing done manually using header structs and `ntohs/ntohl`.
* **Filtering & Replay:** Filter thread moves matching packets to replay queue. Oversized (>1500 bytes) skipping policy implemented. Delay estimate = `size/1000` ms.
* **Replay & Error Handling:** Replay attempts `sendto()` via AF_PACKET; on failure retries up to 2 times and moves to backup queue. `--simulate-failure` available for demo.
* **Display:** Console outputs provide packet lists, per-packet layers, replay/backup queues and delays.
* **Demonstration:** `--duration 60` provides >= 1 minute continuous capture; sample logs included.

---

## Troubleshooting & tips

* Permission errors: run with `sudo` or use `setcap`.
* No captures: ensure the interface is `UP` and has traffic; test with `sudo tcpdump -i enp0s3 -c 5`.
* Replay failures: network switches may block replayed frames; use `--simulate-failure` to demonstrate retry & backup logic.
* IPv6 packets present but limited parsing: IPv6 extension headers are intentionally not fully parsed (documented limitation).




