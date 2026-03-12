<div align="center">

<!-- Animated SVG Banner -->
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 180" width="900" height="180">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0f0c29;stop-opacity:1" />
      <stop offset="50%" style="stop-color:#302b63;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#24243e;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="textGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#00f2fe"/>
      <stop offset="100%" style="stop-color:#4facfe"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3.5" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <style>
      .pulse { animation: pulse 2s infinite; }
      @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }
      .slide-in { animation: slideIn 1s ease forwards; }
      @keyframes slideIn { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
    </style>
  </defs>
  <rect width="900" height="180" rx="18" fill="url(#bgGrad)"/>
  <!-- Animated scan line -->
  <line x1="0" y1="90" x2="900" y2="90" stroke="#4facfe" stroke-width="0.5" opacity="0.3"/>
  <!-- Icon: shield -->
  <g transform="translate(60,40)" filter="url(#glow)">
    <path d="M45,0 L90,20 L90,55 C90,80 70,95 45,105 C20,95 0,80 0,55 L0,20 Z" fill="none" stroke="#4facfe" stroke-width="2.5" class="pulse"/>
    <text x="45" y="60" text-anchor="middle" font-size="30" fill="#00f2fe" font-family="monospace">👁</text>
  </g>
  <!-- Title -->
  <text x="175" y="75" font-family="Segoe UI, sans-serif" font-size="46" font-weight="bold" fill="url(#textGrad)" filter="url(#glow)">SniffGu@rd</text>
  <text x="177" y="105" font-family="Segoe UI, sans-serif" font-size="18" fill="#a0c4ff" letter-spacing="4">V 2 . 0  ·  A D V A N C E D  W I R E L E S S  S E C U R I T Y</text>
  <!-- Bottom accent line -->
  <rect x="175" y="120" width="500" height="2" rx="1" fill="url(#textGrad)" opacity="0.7"/>
  <!-- Animated dot -->
  <circle cx="880" cy="30" r="6" fill="#00f2fe" class="pulse" filter="url(#glow)"/>
  <text x="866" y="55" font-family="monospace" font-size="10" fill="#4facfe">LIVE</text>
</svg>

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
