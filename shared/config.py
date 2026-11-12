"""
ERSIN - Shared Configuration & Constants
Ortak yapılandırma ve sabitler
"""

import os
import json
from datetime import datetime

# =====================================================
# Proje Bilgileri
# =====================================================
PROJECT_NAME = "ERSIN"
VERSION = "1.0.0"
DESCRIPTION = (
    "E: Endpoint | R: Reconnaissance | S: Stage | I: Injector | N: Node\n"
    "Eğitim Amaçlı C2 Framework - Red Team & Blue Team"
)

# =====================================================
# Ağ Yapılandırması
# =====================================================
DEFAULT_C2_HOST = "127.0.0.1"
DEFAULT_C2_PORT = 4444
DEFAULT_STAGER_PORT = 8080
DEFAULT_BUFFER_SIZE = 4096
MAX_CONNECTIONS = 10
CONNECTION_TIMEOUT = 30  # saniye

# =====================================================
# Şifreleme
# =====================================================
KEY_SIZE = 32  # AES-256
IV_SIZE = 16
ENCODING = "utf-8"

# =====================================================
# Protokol Komutları
# =====================================================
CMD_STAGE_REQUEST = "ERSIN_STAGE_REQ"
CMD_STAGE_RESPONSE = "ERSIN_STAGE_RES"
CMD_HEARTBEAT = "ERSIN_HB"
CMD_HEARTBEAT_ACK = "ERSIN_HB_ACK"
CMD_SHELL = "ERSIN_SHELL"
CMD_SHELL_RESULT = "ERSIN_SHELL_RES"
CMD_EXIT = "ERSIN_EXIT"
CMD_UPLOAD = "ERSIN_UPLOAD"
CMD_DOWNLOAD = "ERSIN_DOWNLOAD"
CMD_SYSINFO = "ERSIN_SYSINFO"
CMD_SCREENSHOT = "ERSIN_SCREENSHOT"
CMD_PERSIST = "ERSIN_PERSIST"
CMD_KILL = "ERSIN_KILL"

# =====================================================
# Dosya Yolları
# =====================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOOT_DIR = os.path.join(BASE_DIR, "loot")
STAGE_DIR = os.path.join(BASE_DIR, "stages")

for d in [LOG_DIR, LOOT_DIR, STAGE_DIR]:
    os.makedirs(d, exist_ok=True)

# =====================================================
# Renk Kodları (Terminal)
# =====================================================
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    @staticmethod
    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}"

    @staticmethod
    def success(text: str) -> str:
        return Colors.colorize(f"[+] {text}", Colors.GREEN)

    @staticmethod
    def error(text: str) -> str:
        return Colors.colorize(f"[-] {text}", Colors.RED)

    @staticmethod
    def warning(text: str) -> str:
        return Colors.colorize(f"[!] {text}", Colors.YELLOW)

    @staticmethod
    def info(text: str) -> str:
        return Colors.colorize(f"[*] {text}", Colors.CYAN)

    @staticmethod
    def debug(text: str) -> str:
        return Colors.colorize(f"[~] {text}", Colors.DIM)


# =====================================================
# Banner
# =====================================================
BANNER = f"""{Colors.RED}{Colors.BOLD}
    ███████╗██████╗ ███████╗██╗███╗   ██╗
    ██╔════╝██╔══██╗██╔════╝██║████╗  ██║
    █████╗  ██████╔╝███████╗██║██╔██╗ ██║
    ██╔══╝  ██╔══██╗╚════██║██║██║╚██╗██║
    ███████╗██║  ██║███████║██║██║ ╚████║
    ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝
{Colors.RESET}
{Colors.CYAN}    E: Endpoint | R: Reconnaissance | S: Stage | I: Injector | N: Node{Colors.RESET}
{Colors.YELLOW}    v{VERSION} - Eğitim Amaçlı C2 Framework{Colors.RESET}
{Colors.DIM}    Red Team & Blue Team | Offensive & Defensive{Colors.RESET}
"""


def log_event(event_type: str, message: str, extra: dict = None):
    """Olayları JSON formatında log dosyasına yaz."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "message": message,
    }
    if extra:
        log_entry["details"] = extra

    log_file = os.path.join(LOG_DIR, f"ersin_{datetime.now().strftime('%Y%m%d')}.log")
    with open(log_file, "a", encoding=ENCODING) as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
