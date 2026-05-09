# 🛡️ DG-SEC SCANNER - Advanced Security Framework

![DG-HACKER](https://img.shields.io/badge/DG-HACKER-RED?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-green?style=for-the-badge)
![Kali Linux](https://img.shields.io/badge/Kali-Linux-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge)

## 🔥 DG-HACKER SECURITY SCANNER

**Author:** Durgesh Gaikwad  
**Version:** 1.0.0  
**Platform:** Kali Linux / Ubuntu / Any Linux Distribution

---

## 📖 Description

DG-SEC Scanner is an advanced cybersecurity framework designed for security professionals, penetration testers, and ethical hackers. This tool provides comprehensive scanning capabilities for malicious files, suspicious URLs, IP addresses, APK files, and document files. Built with an attractive hacker-themed GUI, it makes security analysis both powerful and visually engaging.

### 🎯 Key Features

- **🔍 Malicious File Scanner** - Detect malware, viruses, and suspicious patterns
- **🌐 URL Scanner** - Check URLs against blacklists and detect phishing sites
- **📍 IP Scanner** - Analyze IP addresses for threats and reputation
- **📱 APK Scanner** - Analyze Android APK files for malware and permissions
- **📄 Document Scanner** - Scan DOC, PDF, and Office files for macro viruses
- **🎨 Hacker-Themed GUI** - Dynamic and attractive matrix-style interface
- **⚡ Real-time Scanning** - Fast multi-threaded scanning engine
- **📊 Detailed Reports** - Generate comprehensive HTML/JSON reports

---

## 🚀 Installation

### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# Install required system packages
sudo apt install tkinter tk-dev -y

# Make setup executable
chmod +x setup.sh

# Run setup
./setup.sh

# Activate environment
source venv/bin/activate

# Run the tool
python3 dg_scanner.py
python3 dg_scanner.py --scan-file /path/to/suspicious/file
python3 dg_scanner.py --scan-url https://suspicious-site.com
python3 dg_scanner.py --scan-ip 192.168.1.100
python3 dg_scanner.py --scan-apk /path/to/app.apk
python3 dg_scanner.py --scan-doc /path/to/document.doc

💻 Usage
GUI Mode (Recommended)
bash
source venv/bin/activate
python3 dg_scanner.py

git clone https://github.com/H-A-C-K-design/DG-SCANNER.git

cd DG-SCANNER

python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run setup
chmod +x setup.sh
./setup.sh


