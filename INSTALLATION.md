# 🛠️ Installation Guide

Follow these steps to set up **SniffGu@rd V2** on your Linux system.

> [!IMPORTANT]
> SniffGu@rd V2 requires **Linux** and **Root Privileges** to function properly as it interacts directly with network hardware.

## 📋 Prerequisites

Before installing, ensure you have the following installed:

| Component | Requirement |
| :--- | :--- |
| **OS** | Linux (Ubuntu/Debian/Kali recommended) |
| **Python** | 3.8 or higher |
| **Tools** | `iwconfig`, `iw`, `iproute2`, `wireless-tools` |

## 🚀 Step-by-Step Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Rudii-25/Sniffguard.git
cd "sniffguard v2"
```

### 2. Install System Dependencies
```bash
sudo apt update
sudo apt install wireless-tools iw iproute2 python3-pip
```

### 3. Install Python Requirements
It is recommended to use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🛡️ Running the Application

Since SniffGu@rd performs low-level network operations, you must run it with `sudo`:

```bash
sudo ./venv/bin/python sniffguard.py
```

---

<div align="center">

[⬅️ Back to README](README.md) &nbsp;|&nbsp; [🌍 Project Website](https://rudii-25.github.io/Sniffguard/) &nbsp;|&nbsp; [⭐ GitHub](https://github.com/Rudii-25/Sniffguard)

Made with ❤️ by **[Rudra Sharma](https://www.linkedin.com/in/rudra-sharma-714a7b259/)** &nbsp;|&nbsp; © 2026 Rudra Sharma

</div>
