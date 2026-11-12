#!/bin/bash
# ERSIN Project Setup Script
# Eğitim Amaçlı C2 Framework

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  ERSIN - Eğitim Amaçlı C2 Framework"
echo "  E: Endpoint | R: Reconnaissance"
echo "  S: Stage | I: Injector | N: Node"
echo "============================================"
echo ""

# Python3 kontrolü
if ! command -v python3 &> /dev/null; then
    echo "[HATA] python3 bulunamadı! Lütfen Python 3.8+ kurun."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[*] Python sürümü: $PYTHON_VERSION"

# venv oluştur
if [ ! -d "venv" ]; then
    echo "[*] Sanal ortam (venv) oluşturuluyor..."
    python3 -m venv venv
    echo "[+] venv oluşturuldu."
else
    echo "[*] venv zaten mevcut."
fi

# venv aktif et
echo "[*] venv aktif ediliyor..."
source venv/bin/activate

# Bağımlılıkları yükle
echo "[*] Bağımlılıklar yükleniyor..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

echo ""
echo "[+] Kurulum tamamlandı!"
echo ""
echo "Kullanım:"
echo "  source venv/bin/activate"
echo "  python3 ersin.py --help"
echo ""
echo "============================================"
