#!/bin/bash

echo -e "\e[1;31m[+] Starting Tayyab-Sec CLI Setup...\e[0m"

if [[ $EUID -ne 0 ]]; then
   echo -e "\e[1;33m[!] Please run as root or with sudo\e[0m"
   exit 1
fi

echo -e "\e[1;34m[*] Updating system packages...\e[0m"
apt-get update -y

echo -e "\e[1;34m[*] Installing system dependencies (Nmap, Python3)...\e[0m"
apt-get install -y python3 python3-pip nmap

echo -e "\e[1;34m[*] Installing Python requirements...\e[0m"
pip3 install rich requests scapy beautifulsoup4 python-nmap phonenumbers whois --break-system-packages

chmod +x main.py

echo -e "\e[1;32m[+] Setup Complete! Run the tool using: python3 main.py\e[0m"
