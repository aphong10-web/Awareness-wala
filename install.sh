#!/bin/bash

echo "[+] Installing Awareness-wala..."

sudo apt update

sudo apt install -y \
    aircrack-ng \
    dnsmasq \
    hostapd \
    hcxdumptool \
    hashcat \
    python3 \
    python3-pip

pip3 install -r requirements.txt

chmod +x main.py

sudo ln -sf "$(pwd)/main.py" /usr/local/bin/awareness-wala

echo
echo "[+] Installation complete."
echo "[+] Run using:"
echo "    awareness-wala"
