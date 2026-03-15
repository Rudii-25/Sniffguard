<p align="center">
  <img src="https://img.shields.io/badge/SniffGu@rd--blueviolet?style=for-the-badge&logo=python&logoColor=yellow" alt="SniffGu@rd Badge">
</p>

<h1 align="center">🛡️ SniffGu@rd – Wi-Fi Security Tool 🚀</h1>

<p align="center">
  <img src="https://img.shields.io/github/license/Rudii-25/SniffGuard?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/github/stars/Rudii-25/SniffGuard?style=for-the-badge" alt="stars">
  <img src="https://img.shields.io/github/forks/Rudii-25/SniffGuard?style=for-the-badge" alt="forks">
  <img src="https://img.shields.io/github/issues/Rudii-25/SniffGuard?style=for-the-badge" alt="issues">
</p>
<p align="center">
  <b>Detect ⚡ | Defend 🛡 | Secure 🔐</b>
</p>


<p align="center">
  🔍 A <b>real-time Wi-Fi security & defense tool</b> built in Python.  
  SniffGu@rd lets you <b>scan, detect, and defend</b> against rogue access points –  
  designed for cybersecurity students, red/blue teamers, and Wi-Fi researchers.
</p>

---

## 📸 Preview
<p align="center">
  <img width="400" alt="dashboard-preview" src="https://github.com/user-attachments/assets/xxxxxxx" />
  <img width="400" alt="scan-result" src="https://github.com/user-attachments/assets/yyyyyyy" />
</p>

---

## ✨ Features
- 📡 **Real-time Wi-Fi Scanning**
- 🔎 **Suspicious Access Point Detection**
- 🖥️ **Interactive Dashboard (GUI)**
- 🛡 **Active Defense (optional, user-confirmed)**
- 📝 **Logging & Report Generation**

---
## 📂 Installation & Usage

### 1. Clone this repository

```bash
git clone https://github.com/Rudii-25/SniffGuard.git
cd SniffGuard
```

### 2. Install requirements

Make sure you have **Python 3.8+** installed.
Install required Python packages:

```bash
pip install -r requirements.txt
```
### **3. Run SniffGu@rd**

* **GUI Mode**
```bash
sudo python3 sniffguard.py
```

* **Passive Monitoring**
```bash
sudo python3 sniffgu@rd.py --interface wlan0mon --mode passive
```
* **Active Mode (with confirmation)**
```bash
sudo python3 sniffgu@rd.py --interface wlan0mon --mode active --confirm
```
### **4. Other Method**
* <b> By Downloading linux release of this app</b>

## 🛠 Built With
* **Python 3**
* **Scapy** – Packet sniffing
* **PyQt5** – GUI dashboard
* **Colorama & Termcolor** – CLI styling

---

### **Notes**
 
---

* Always run the tool only on networks / devices you have explicit permission to test.
* If your system uses NetworkManager, you may need to stop it before switching interfaces to monitor mode:

```bash
sudo systemctl stop NetworkManager
```

* To re-enable managed mode after testing:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
sudo systemctl start NetworkManager
```

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
</br>
⚠️ **Attribution is required** – If you use this project, please credit **Rudra** in your work.

---

## 💖 Credits

Designed & Developed by **[Rudra](https://github.com/Rudii-25)**
<h2 >❤️ Show Some Love</h2>
<p >If you like this project:</p>

<p >
  ⭐ Star this repo <br>
  🔄 Share with your friends <br>
  💬 Suggest improvements
</p>

---

<p align="center">
  Made with ❤️ by <b>Rudra Sharma</b>
</p>