#!/bin/bash

# Define colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Custom banner
echo -e "${CYAN}${BOLD}"
echo " __      __    _        _____                __   __   "
echo " \ \    / /   | |      / ____|               \ \ / /    "
echo "  \ \  / /   _| |_ __ | (___   ___ __ _ _ __  \ V /     "
echo "   \ \/ / | | | |  _ \ \___ \ / __/ _  | '_ \  > <      "
echo "    \  /| |_| | | | | |____) | (_| (_| | | | |/ . \     "
echo "     \/  \__,_|_|_| |_|_____/ \___\__,_|_| |_/_/ \_\    "
echo "                                                        "
echo -e "${NC}"
echo -e "===================================================\n"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a tool if it doesn't exist
install_tool() {
    local tool_name=$1
    local install_command=$2

    if ! command_exists "$tool_name"; then
        echo -e "${YELLOW}[+] Installing $tool_name...${NC}"
        eval "$install_command"
    else
        echo -e "${GREEN}[+] $tool_name is already installed.${NC}"
    fi
}

# Update package list
echo -e "${YELLOW}[+] Updating package list...${NC}"
sudo apt-get update

# Install Git if not installed
install_tool "git" "sudo apt-get install -y git"

# Install Python3 and pip if not installed
install_tool "python3" "sudo apt-get install -y python3"
install_tool "pip3" "sudo apt-get install -y python3-pip"

# Install Flask and other Python dependencies
echo -e "${YELLOW}[+] Installing Python dependencies (Flask, etc.)...${NC}"
pip3 install flask gevent urllib3 --break-system-packages

# Install required tools
echo -e "${YELLOW}[+] Installing required tools...${NC}"

# Install Amass
install_tool "amass" "sudo apt-get install -y amass"

# Install Subfinder
install_tool "subfinder" "sudo apt-get install -y subfinder"

# Install Sublist3r
install_tool "sublist3r" "sudo apt-get install -y sublist3r"

# Install httpx
install_tool "httpx" "sudo apt-get install -y httpx"

# Install ffuf
install_tool "ffuf" "sudo apt-get install -y ffuf"

# Install waybackurls
install_tool "waybackurls" "go install github.com/tomnomnom/waybackurls@latest"

# Install katana
install_tool "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest"

# Install waymore
install_tool "waymore" "go install github.com/xnl-h4ck3r/waymore@latest"

# Install Commix
install_tool "commix" "sudo apt-get install -y commix"

# Install Dalfox
install_tool "dalfox" "go install github.com/hahwul/dalfox/v2@latest"

# Install SQLMap
install_tool "sqlmap" "sudo apt-get install -y sqlmap"

# Add VulnScanX directory to PATH for both Bash and Zsh
echo -e "${YELLOW}[+] Adding VulnScanX directory to PATH for Bash and Zsh...${NC}"
echo 'export PATH=$PATH:~/VulnScanX' >> ~/.bashrc
echo 'export PATH=$PATH:~/VulnScanX' >> ~/.zshrc
source ~/.bashrc
source ~/.zshrc

# Create a shortcut command to run VulnScanX
echo -e "${YELLOW}[+] Creating shortcut command 'vulnscanx'...${NC}"
echo 'alias vulnscanx="python3 ~/VulnScanX/VulnScanX.py"' >> ~/.bashrc
echo 'alias vulnscanx="python3 ~/VulnScanX/VulnScanX.py"' >> ~/.zshrc
source ~/.bashrc
source ~/.zshrc

echo -e "${GREEN}[+] Installation completed successfully!${NC}"
echo -e "${MAGENTA}${BOLD}[+] You can now run VulnScanX by typing 'vulnscanx' in your terminal.${NC}"