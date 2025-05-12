# DNS Sniffer 🌐🕵️‍♂️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Libpcap](https://img.shields.io/badge/dependency-libpcap-yellow.svg)

> A lightweight, zero‐configuration DNS sniffer for Linux that captures and displays
> A, AAAA and CNAME records in real time via a BPF‐powered libpcap filter.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- ✅ **IPv4 & IPv6** support (A & AAAA records)
- ✅ **CNAME** chain resolution
- ✅ **UDP & TCP** DNS capture (including DNS-over-TCP length prefix)
- ✅ **Kernel‐side BPF filter** for minimal user‐space overhead
- ✅ **Single-file C implementation** with no deps beyond [libpcap](https://www.tcpdump.org/)

---

## Installation

```bash
# Install libpcap development headers
sudo apt update
sudo apt install -y libpcap-dev

# Clone & build
git clone https://github.com/danrapa/DnsSniffer.git 
cd DnsSniffer
make
```

## Usage

# Run on default "any" interface
sudo ./dnsSniffer

# Or specify one interface (e.g. eth0, wlan0, enp0s3)
sudo ./dnsSniffer <Interface>

# then, on another terminal run:
ping google.com

# you'll see:
Domain: google.com

  IPv4:
    142.250.75.206

Domain: google.com

  IPv6:
    2a00:1450:4028:80b::200e


