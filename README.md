<div align="center">

<!-- Animated SVG Banner -->
<p align="center">
  <img src="https://sniffguardsvgforreadme.netlify.app/sniffguard.svg" alt="SniffGuard Banner"/>
</p>

<br/>

<!-- Badges -->
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-00b894?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00cec9?style=for-the-badge)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-41CD52?style=for-the-badge&logo=qt&logoColor=white)

<br/>

> **SniffGu@rd V2** is a professional-grade wireless security auditing tool. Scan nearby networks, detect rogue access points, analyze signal strengths, and produce detailed security reports — all from an elegant GUI.

</div>

---

## 🧭 Navigation

<div align="center">

| 📄 Document | Description |
| :---: | :--- |
| [🛠️ Installation Guide](INSTALLATION.md) | Set up SniffGu@rd on your Linux system step-by-step |
| [✨ Features](FEATURES.md) | Explore all the powerful capabilities of the tool |
| [📖 Usage Manual](USAGE.md) | Learn how to operate and get the most out of SniffGu@rd |
| [🤝 Contributing](CONTRIBUTING.md) | How to contribute and report bugs |
| [⚖️ License](LICENSE) | MIT License — open source and free |
| [🌐 Live Website](https://rudii-25.github.io/Sniffguard/) | Official SniffGu@rd project website |

</div>

---

## 🔭 What is SniffGu@rd?

**SniffGu@rd V2** is an advanced wireless network security scanner and auditing suite designed for ethical hackers, penetration testers, and network administrators. Built on top of Python's battle-tested `Scapy` library and wrapped in a clean **PyQt6** graphical interface, it gives you a real-time window into the wireless landscape around you.

Whether you're securing your own infrastructure or conducting authorized security audits, SniffGu@rd equips you with the tools and intelligence you need.

---

## ⚡ Key Features at a Glance

<div align="center">

| Feature | Description |
| :--- | :--- |
| 📡 **Real-Time Scanning** | Discover all nearby Wi-Fi networks live, with no refresh needed |
| 🔐 **Security Classification** | Automatically tags Open, WEP, WPA, WPA2, and WPA3 networks |
| 📶 **Dual-Band Support** | Full support for 2.4 GHz and 5 GHz networks with accurate channel resolution |
| 🏠 **BSSID / OUI Lookup** | Identify manufacturer of access points from their MAC address |
| 📊 **Signal Strength Mapping** | Visualize RSSI levels to physically locate access points |
| 📁 **Log Management** | Structured logging stored in the `logs/` directory for later review |
| 🖥️ **Professional GUI** | Clean, responsive PyQt6 interface with real-time data tables |

</div>

---

## 🏗️ Project Architecture

```
sniffguard v2/
│
├── 📄 sniffguard.py        # Main entry point — startup, checks & launch
│
├── 📁 core/                # Core logic (scanner, analyzer, packet engine)
├── 📁 gui/                 # PyQt6 graphical interface
│   └── main_window.py      # Main dashboard & UI controller
├── 📁 threads/             # Background worker threads for scanning
├── 📁 utils/               # Logger, helpers, and utilities
├── 📁 logs/                # Auto-generated log files
│
├── 📄 requirements.txt     # Python dependencies
├── 📄 INSTALLATION.md      # Setup guide
├── 📄 FEATURES.md          # Feature documentation
├── 📄 USAGE.md             # How to use
├── 📄 CONTRIBUTING.md      # Contribution guide
└── 📄 LICENSE              # MIT License
```

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Rudii-25/Sniffguard.git
cd "sniffguard v2"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run (requires sudo for monitor mode)
sudo python3 sniffguard.py
```

> 📖 For detailed setup, see the [Installation Guide](INSTALLATION.md).

---

## 🛡️ Disclaimer

> [!CAUTION]
> **SniffGu@rd is designed strictly for authorized security auditing and educational purposes.** Scanning networks you do not own or do not have explicit written permission to test is **illegal** in most jurisdictions. The developers assume no liability for misuse of this tool.

---

## ⚖️ License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for full details.

---

<div align="center">

Made with ❤️ by **[Rudra Sharma](https://www.linkedin.com/in/rudra-sharma-714a7b259/)** &nbsp;|&nbsp; [🌐 rudrasharma.tech](https://rudrasharma.tech) &nbsp;|&nbsp; [🌍 Project Website](https://rudii-25.github.io/Sniffguard/) &nbsp;|&nbsp; [⭐ Star on GitHub](https://github.com/Rudii-25/Sniffguard)

© 2025 Rudra Sharma. Released under the MIT License.

</div>
