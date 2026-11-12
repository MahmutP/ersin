"""
ERSIN - Crypto Module
AES-256-CBC şifreleme/çözme + anahtar değişimi
"""

import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class ErsinCrypto:
    """C2 iletişimi için AES-256-CBC şifreleme sınıfı."""

    def __init__(self, key: bytes = None):
        if key:
            self.key = hashlib.sha256(key).digest()
        else:
            self.key = secrets.token_bytes(32)

    @staticmethod
    def generate_key() -> bytes:
        """Rastgele 32 byte anahtar üret."""
        return secrets.token_bytes(32)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Veriyi AES-256-CBC ile şifrele.
        Format: IV (16 byte) + şifreli veri
        """
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        AES-256-CBC ile şifrelenmiş veriyi çöz.
        İlk 16 byte IV olarak kullanılır.
        """
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # PKCS7 unpadding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def encrypt_b64(self, plaintext: str) -> str:
        """String şifrele, base64 olarak döndür."""
        encrypted = self.encrypt(plaintext.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt_b64(self, b64_ciphertext: str) -> str:
        """Base64 şifreli veriyi çöz, string olarak döndür."""
        ciphertext = base64.b64decode(b64_ciphertext)
        decrypted = self.decrypt(ciphertext)
        return decrypted.decode("utf-8")

    def get_key_hex(self) -> str:
        """Anahtarı hex olarak döndür."""
        return self.key.hex()

    @classmethod
    def from_hex_key(cls, hex_key: str) -> "ErsinCrypto":
        """Hex anahtardan crypto nesnesi oluştur."""
        key = bytes.fromhex(hex_key)
        obj = cls.__new__(cls)
        obj.key = key
        return obj
