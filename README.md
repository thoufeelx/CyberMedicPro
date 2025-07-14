# 🧠 CyberMedic Pro v1.0

> System Healing & Malware Scanning Tool for Linux & Windows  
> Built with Python + PyQt5 — featuring a full GUI, animations, sound, and real diagnostics.

## 🧪 Features

- 🧹 **Quick Scan** – Lightweight system scan with no deep checks
- 🛠️ **Full Heal** – Runs OS updates, auto repairs, malware removal
- 🎯 **Custom Scan** – Choose between Malware, Hardware, Performance, or Disk scan
- 🎧 **Hacker UI** with animation, terminal output, and audio FX
- 🐧 Linux-specific commands for full diagnostic flow
- 🔐 Sudo access prompt for secure tasks

- ## 📸 Screenshots




## ⚙️ Installation

### ✅ 1. Clone the Repository

git clone https://github.com/yourusername/CyberMedicPro.git
cd CyberMedicPro

# (Optional) Create a Virtual Environment

python3 -m venv myenv
source myenv/bin/activate

# Install Python Requirements

pip install pyqt5
pip install psutil
pip install pygame

# Install System Packages (Linux Only)

sudo apt update
sudo apt install -y \
  sysbench \
  rkhunter \
  chkrootkit \
  clamav \
  smartmontools \
  lm-sensors

# Run the Application

python3 main.py


💡 Usage Tips

🔐 Linux will ask for sudo password (in GUI)

💾 Custom scans allow you to run focused diagnostics

🎧 Sound FX play on start, and completion

✅ Output shown in hacker-style terminal inside the app

Known Issues

Requires active internet to install missing Linux tools during first scan

Windows version is UI-only (no system command execution)

If sounds don’t play, ensure pygame is installed and volume is up

🧠 Made With

Python 3

PyQt5

QSoundEffect / Pygame mixer

System Tools (rkhunter, chkrootkit, clamav, sysbench, smartctl)

📜 License
MIT License © [R Muhammed Thoufeel]





