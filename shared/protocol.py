"""
ERSIN - Protocol Module
C2 iletişim protokolü: mesaj paketleme, çözme, doğrulama
"""

import json
import struct
import hashlib
import time
from typing import Optional
from shared.crypto import ErsinCrypto
from shared.config import ENCODING


class ErsinProtocol:
    """
    ERSIN Protokol Formatı:
    ┌──────────┬──────────┬──────────┬──────────────┬─────────┐
    │ MAGIC(4) │ LEN(4)   │ HASH(32) │ PAYLOAD(N)   │ END(4)  │
    │ ERSN     │ uint32   │ sha256   │ encrypted    │ NRSE    │
    └──────────┴──────────┴──────────┴──────────────┴─────────┘
    """

    MAGIC = b"ERSN"
    END_MARKER = b"NRSE"
    HEADER_SIZE = 4 + 4 + 32  # magic + length + hash
    FOOTER_SIZE = 4

    def __init__(self, crypto: ErsinCrypto):
        self.crypto = crypto

    def pack_message(self, command: str, data: dict = None) -> bytes:
        """Komutu protokol paketine dönüştür."""
        message = {
            "cmd": command,
            "ts": time.time(),
            "data": data or {},
        }
        json_bytes = json.dumps(message, ensure_ascii=False).encode(ENCODING)
        encrypted = self.crypto.encrypt(json_bytes)

        # SHA-256 hash (bütünlük kontrolü)
        payload_hash = hashlib.sha256(encrypted).digest()

        # Paket oluştur
        length = len(encrypted)
        packet = (
            self.MAGIC
            + struct.pack("!I", length)
            + payload_hash
            + encrypted
            + self.END_MARKER
        )
        return packet

    def unpack_message(self, packet: bytes) -> Optional[dict]:
        """Protokol paketini çöz ve doğrula."""
        # Magic kontrolü
        if not packet.startswith(self.MAGIC):
            return None

        # Uzunluk çöz
        offset = 4
        length = struct.unpack("!I", packet[offset:offset + 4])[0]
        offset += 4

        # Hash al
        expected_hash = packet[offset:offset + 32]
        offset += 32

        # Payload al
        encrypted = packet[offset:offset + length]
        offset += length

        # End marker kontrolü
        if packet[offset:offset + 4] != self.END_MARKER:
            return None

        # Hash doğrula
        actual_hash = hashlib.sha256(encrypted).digest()
        if actual_hash != expected_hash:
            return None

        # Çöz
        try:
            decrypted = self.crypto.decrypt(encrypted)
            message = json.loads(decrypted.decode(ENCODING))
            return message
        except Exception:
            return None

    @staticmethod
    def calculate_packet_size(payload_length: int) -> int:
        """Toplam paket boyutunu hesapla."""
        return ErsinProtocol.HEADER_SIZE + payload_length + ErsinProtocol.FOOTER_SIZE


def send_message(sock, protocol: ErsinProtocol, command: str, data: dict = None):
    """Socket üzerinden şifreli mesaj gönder."""
    packet = protocol.pack_message(command, data)
    # Önce paket boyutunu gönder (4 byte)
    sock.sendall(struct.pack("!I", len(packet)))
    sock.sendall(packet)


class SocketTimeout(Exception):
    """Socket zaman aşımı - bağlantı hala geçerli, sadece veri yok."""
    pass


class ConnectionLost(Exception):
    """Bağlantı koptu - karşı taraf kapattı."""
    pass


def recv_message(sock, protocol: ErsinProtocol, buffer_size: int = 65536) -> Optional[dict]:
    """
    Socket üzerinden şifreli mesaj al ve çöz.
    Raises:
        SocketTimeout: Timeout oldu ama bağlantı hala geçerli
        ConnectionLost: Bağlantı koptu
    """
    try:
        # Paket boyutunu oku
        size_data = _recv_exact(sock, 4)
        if size_data is None:
            raise ConnectionLost("Karşı taraf bağlantıyı kapattı")
        packet_size = struct.unpack("!I", size_data)[0]

        # Paketi oku
        packet = _recv_exact(sock, packet_size)
        if packet is None:
            raise ConnectionLost("Paket verisi alınamadı")

        return protocol.unpack_message(packet)
    except socket.timeout:
        raise SocketTimeout("Veri bekleme zaman aşımı")
    except (ConnectionLost, SocketTimeout):
        raise
    except (ConnectionResetError, BrokenPipeError, OSError):
        raise ConnectionLost("Bağlantı hatası")
    except Exception:
        return None


def _recv_exact(sock, n: int) -> Optional[bytes]:
    """Tam olarak n byte oku. Bağlantı koparsa None döner."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
