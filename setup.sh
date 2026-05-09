#!/bin/bash

# DG-SEC Scanner Setup Script
# Author: Durgesh Gaikwad

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║    ██████╗  ██████╗       ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
║    ██╔══██╗██╔════╝       ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
║    ██║  ██║██║  ███╗█████╗███████║███████║██║     █████╔╝ █████╗  ██████╔╝
║    ██║  ██║██║   ██║╚════╝██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
║    ██████╔╝╚██████╔╝      ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
║    ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
║                                                                              
║         SECURITY SCANNER FRAMEWORK - by Durgesh Gaikwad                     
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${CYAN}[*] Starting DG-SEC Scanner Setup...${NC}\n"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Please do not run this script as root!${NC}"
   exit 1
fi

# Check Python version
echo -e "${YELLOW}[*] Checking Python version...${NC}"
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Python3 is not installed. Installing...${NC}"
    sudo apt install python3 python3-pip -y
fi

# Create virtual environment
echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
python3 -m venv venv

# Activate virtual environment
echo -e "${YELLOW}[*] Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}[*] Upgrading pip...${NC}"
pip install --upgrade pip

# Install system dependencies
echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
sudo apt update
sudo apt install -y python3-tk tk-dev libtk-img python3-pil python3-pil.imagetk
sudo apt install -y libyara3 yara python3-yara
sudo apt install -y apktool dex2jar
sudo apt install -y whois dnsutils

# Install Python dependencies
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Create necessary directories
echo -e "${YELLOW}[*] Creating directories...${NC}"
mkdir -p reports
mkdir -p logs
mkdir -p quarantine
mkdir -p assets
mkdir -p modules

# Download YARA rules
echo -e "${YELLOW}[*] Downloading YARA rules...${NC}"
if [ ! -f "rules/index.yar" ]; then
    mkdir -p rules
    git clone https://github.com/Yara-Rules/rules.git temp_rules
    mv temp_rules/* rules/
    rm -rf temp_rules
fi

# Set permissions
echo -e "${YELLOW}[*] Setting permissions...${NC}"
chmod +x dg_scanner.py
chmod +x setup.sh

# Create desktop shortcut
echo -e "${YELLOW}[*] Creating desktop shortcut...${NC}"
cat > ~/Desktop/DG-Scanner.desktop << EOL
[Desktop Entry]
Name=DG-SEC Scanner
Comment=Advanced Security Scanner by Durgesh Gaikwad
Exec=$(pwd)/venv/bin/python3 $(pwd)/dg_scanner.py
Icon=$(pwd)/assets/icon.png
Terminal=false
Type=Application
Categories=Security;
EOL
chmod +x ~/Desktop/DG-Scanner.desktop

# Final message
echo -e "\n${GREEN}[✓] Setup completed successfully!${NC}"
echo -e "${GREEN}[✓] Author: Durgesh Gaikwad${NC}"
echo -e "${GREEN}[✓] Tool: DG-HACKER Security Scanner${NC}"
echo -e "\n${CYAN}[*] To start the scanner:${NC}"
echo -e "${PURPLE}    source venv/bin/activate${NC}"
echo -e "${PURPLE}    python3 dg_scanner.py${NC}"
echo -e "\n${CYAN}[*] Or use the desktop shortcut${NC}"
echo -e "${GREEN}[✓] Happy Hunting! 🎯${NC}\n"