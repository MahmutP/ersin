# ERSIN

**E: Endpoint | R: Reconnaissance | S: Stage | I: Injector | N: Node**

Çalışan, güçlü ve eğitim amaçlı yazılmış özel bir Python C2 (Command & Control) framework'ü.

> ⚠️ **UYARI**: Bu proje tamamen eğitim amaçlıdır. Sadece kendi lab ortamınızda ve izinli sistemlerde kullanın. Kötüye kullanım yasalara aykırıdır.

---

## 🎯 Özellikler

### 🔴 Red Team (Saldırı)
- **C2 Sunucu**: Reverse TCP bağlantıları kabul eden komuta & kontrol sunucusu
- **Stager Sistemi**: İki aşamalı payload dağıtımı
  - **Stager** (küçük): Sunucuya bağlanıp asıl payload'ı indirir
  - **Stage** (asıl): Tam özellikli reverse shell client
- **Şifreli İletişim**: AES-256-CBC ile tüm trafik şifrelenir
- **Özel Protokol**: ERSN magic byte, SHA-256 hash doğrulama, paket bütünlük kontrolü
- **Çoklu Oturum**: Birden fazla hedef yönetimi
- **Heartbeat**: Otomatik bağlantı canlılık kontrolü

### 🔵 Blue Team (Savunma)
- **Payload Tespiti**: Şüpheli process ve bağlantı taraması
- **C2 Sunucu Tespiti**: Banner grabbing, protokol imza analizi, anahtar değişimi kontrolü
- **Ağ Dinleme (Sniffer)**: Wireshark benzeri basit trafik izleme
- **Port Yönetimi**: Açık portları listeleme, şüpheli portları kapatma
- **Process Sonlandırma**: PID veya port bazlı zararlı process öldürme
- **Otomatik Savunma**: Sürekli tarama + otomatik tehdit müdahalesi
- **Hata Koruma**: Hata durumunda otomatik port kapatma

---

## 📦 Kurulum

```bash
# Projeyi klonla
git clone <repo-url>
cd ersin

# Otomatik kurulum (venv + bağımlılıklar)
chmod +x setup.sh
./setup.sh

# veya manuel kurulum
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Kullanım

### İnteraktif Konsol
```bash
source venv/bin/activate
python3 ersin.py
```

### Hızlı Modlar
```bash
# Hızlı C2 başlat
python3 ersin.py --quick-listen 4444

# Hızlı tarama
python3 ersin.py --quick-scan

# Hızlı savunma
python3 ersin.py --quick-defend --auto-kill
```

---

## 📋 Komut Referansı

### 🔴 Red Team Komutları
| Komut | Açıklama |
|-------|----------|
| `listen [host] [port]` | C2 sunucusu başlat (varsayılan: 127.0.0.1:4444) |
| `stop` | C2 sunucusunu durdur ve portları kapat |
| `sessions` | Aktif oturumları listele |
| `interact <id>` | Oturumla etkileşim (reverse shell) |
| `kill <id>` | Oturumu sonlandır |
| `generate [host] [c2port] [stagerport]` | Stager + Stage payload oluştur (varsayılan: 127.0.0.1 4444 8080) |
| `stager [host] [stagerport]` | Stage dağıtım sunucusu başlat (varsayılan: generate'deki stager portu) |

### 🔵 Blue Team Komutları
| Komut | Açıklama |
|-------|----------|
| `scan` | Tam sistem taraması (ağ + process) |
| `detect` | Şüpheli process tespiti |
| `sniff [port] [süre]` | Ağ trafiği dinle (Wireshark-lite) |
| `c2scan [host] [port..]` | C2 sunucu tespiti |
| `ports` | Dinleme yapan portları listele |
| `closeport <port>` | Belirli portu kapat |
| `killpid <pid>` | Process'i PID ile sonlandır |
| `killport <port>` | Port üzerindeki tüm process'leri öldür |
| `defend [-k] [-i N]` | Otomatik savunma sistemi (-k: auto-kill) |

---

## 🏗️ Proje Yapısı

```
ersin/
├── ersin.py                 # Ana giriş noktası (konsol arayüzü)
├── setup.sh                 # Otomatik kurulum scripti
├── requirements.txt         # Python bağımlılıkları
├── README.md
│
├── shared/                  # Ortak modüller
│   ├── config.py            # Yapılandırma, sabitler, renk kodları
│   ├── crypto.py            # AES-256-CBC şifreleme
│   └── protocol.py          # ERSIN iletişim protokolü
│
├── server/                  # C2 Sunucu
│   └── c2_server.py         # Komuta & kontrol sunucusu
│
├── stager/                  # Payload Üretici
│   └── generator.py         # Stager + Stage oluşturucu
│
├── defender/                # Savunma Modülü
│   └── defender.py          # Tespit, sonlandırma, dinleme, koruma
│
├── stages/                  # Oluşturulan payload dosyaları
├── logs/                    # Log dosyaları (JSON)
└── loot/                    # Toplanan veriler
```

---

## 🔄 Çalışma Akışı

### Saldırı Senaryosu (Lab)
```
1. ERSIN konsolu başlat
2. listen                  → C2 sunucusu başlat
3. generate                → Stager + Stage oluştur (host, C2 portu, stager portu)
4. stager                  → Stage dağıtım sunucusu başlat (generate'deki stager portu)
5. [Hedefte] python3 stager_xxx.py   → Stager çalıştır
6. sessions                → Bağlanan oturumları gör
7. interact 1              → Reverse shell
```

### Savunma Senaryosu
```
1. ERSIN konsolu başlat
2. scan                    → Sistem taraması
3. c2scan 127.0.0.1        → C2 sunucu tespiti
4. sniff 4444              → Port 4444 trafiğini dinle
5. detect                  → Zararlı process tespiti
6. killpid <pid>           → Zararlı process'i öldür
7. closeport 4444          → Portu kapat
8. defend -k               → Otomatik savunma (auto-kill)
```

---

## 🔐 Protokol Detayları

ERSIN özel bir ikili protokol kullanır:

```
┌──────────┬──────────┬──────────┬──────────────┬─────────┐
│ MAGIC(4) │ LEN(4)   │ HASH(32) │ PAYLOAD(N)   │ END(4)  │
│ "ERSN"   │ uint32   │ SHA-256  │ AES-256-CBC  │ "NRSE"  │
└──────────┴──────────┴──────────┴──────────────┴─────────┘
```

- **MAGIC**: `ERSN` (4 byte) - Paket başlangıç imzası
- **LEN**: Payload uzunluğu (4 byte, big-endian)
- **HASH**: Şifreli payload'ın SHA-256 hash'i (32 byte)
- **PAYLOAD**: AES-256-CBC ile şifrelenmiş JSON veri
- **END**: `NRSE` (4 byte) - Paket bitiş imzası

### Anahtar Değişimi
Bağlantı kurulduğunda sunucu 32 byte AES anahtarını doğrudan gönderir (eğitim amaçlı basit yöntem).

---

## ⚙️ Bağımlılıklar

| Paket | Açıklama |
|-------|----------|
| `colorama` | Terminal renk desteği |
| `cryptography` | AES-256-CBC şifreleme |
| `scapy` | Ağ paketi analizi |
| `psutil` | Process ve sistem bilgisi |
| `tabulate` | Tablo formatı |
| `prompt_toolkit` | Gelişmiş terminal girişi |

---

## 📝 Lisans

Bu proje eğitim amaçlıdır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## ⚠️ Sorumluluk Reddi

Bu araç **tamamen eğitim ve araştırma amaçlıdır**. Yazarlar, bu aracın kötüye kullanımından kaynaklanan hiçbir zarardan sorumlu değildir. Sadece kendi kontrol ettiğiniz sistemlerde ve yasal çerçevede kullanın.
