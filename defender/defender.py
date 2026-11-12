"""
ERSIN - Defender Module (Blue Team)
Zararlı yazılım tespiti, payload bağlantısı dinleme, port kapatma
"""

import socket
import threading
import time
import os
import signal
import json
import struct
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set

import psutil

from shared.config import Colors, log_event, LOG_DIR


class PayloadDetector:
    """
    Zararlı payload tespiti:
    - Şüpheli ağ bağlantılarını tespit et
    - Bilinen C2 imzalarını ara
    - Şüpheli process'leri tespit et
    """

    # Bilinen C2 imzaları (eğitim amaçlı)
    KNOWN_SIGNATURES = {
        b"ERSN": "ERSIN C2 Protokolü",
        b"NRSE": "ERSIN End Marker",
        b"meterpreter": "Metasploit Meterpreter",
        b"reverse_tcp": "Reverse TCP Shell",
        b"cmd.exe /c": "Windows Command Shell",
        b"/bin/sh -i": "Unix Reverse Shell",
        b"/bin/bash -i": "Bash Reverse Shell",
        b"socket.connect": "Python Socket Connect",
        b"subprocess.": "Python Subprocess",
    }

    # Şüpheli portlar
    SUSPICIOUS_PORTS = {
        4444, 4445, 5555, 6666, 7777, 8888, 9999,
        1234, 31337, 12345, 54321,
        4443, 8443, 8080, 9090,
    }

    def __init__(self):
        self.detected_threats: List[dict] = []
        self.monitored_pids: Set[int] = set()
        self._running = False

    def scan_connections(self) -> List[dict]:
        """Tüm ağ bağlantılarını tara ve şüphelileri tespit et."""
        threats = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                threat = self._analyze_connection(conn)
                if threat:
                    threats.append(threat)
                    self.detected_threats.append(threat)
        except (psutil.AccessDenied, PermissionError):
            print(Colors.warning("Bağlantı taraması için yetki gerekli (sudo)"))
        return threats

    def _analyze_connection(self, conn) -> Optional[dict]:
        """Tek bir bağlantıyı analiz et."""
        risk_score = 0
        reasons = []

        # Şüpheli port kontrolü
        local_port = conn.laddr.port if conn.laddr else 0
        remote_port = conn.raddr.port if conn.raddr else 0

        if local_port in self.SUSPICIOUS_PORTS:
            risk_score += 30
            reasons.append(f"Şüpheli yerel port: {local_port}")
        if remote_port in self.SUSPICIOUS_PORTS:
            risk_score += 40
            reasons.append(f"Şüpheli uzak port: {remote_port}")

        # ESTABLISHED bağlantılarını kontrol et
        if conn.status == "ESTABLISHED" and conn.raddr:
            remote_ip = conn.raddr.ip
            # Localhost dışına bağlantılar
            if remote_ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                risk_score += 10

            # Process analizi
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    cmdline = " ".join(proc.cmdline())

                    # Python reverse shell kontrolü
                    if "python" in proc_name.lower():
                        if any(kw in cmdline.lower() for kw in [
                            "socket", "connect", "reverse", "shell",
                            "subprocess", "stage", "payload"
                        ]):
                            risk_score += 50
                            reasons.append(f"Python şüpheli process: {cmdline[:80]}")

                    # Genel şüpheli process
                    if any(kw in cmdline.lower() for kw in [
                        "nc -e", "ncat", "socat", "msfconsole",
                        "msfvenom", "reverse", "backdoor"
                    ]):
                        risk_score += 60
                        reasons.append(f"Bilinen zararlı araç: {proc_name}")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        if risk_score >= 30:
            return {
                "timestamp": datetime.now().isoformat(),
                "type": "suspicious_connection",
                "risk_score": min(risk_score, 100),
                "pid": conn.pid,
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?",
                "status": conn.status,
                "reasons": reasons,
            }
        return None

    def scan_processes(self) -> List[dict]:
        """Şüpheli process'leri tara."""
        threats = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                info = proc.info
                cmdline = " ".join(info.get('cmdline') or [])

                # Şüpheli komut satırı kalıpları
                suspicious_patterns = [
                    ("reverse_tcp", "Reverse TCP payload"),
                    ("reverse_shell", "Reverse shell"),
                    ("ERSIN_STAGE", "ERSIN stage payload"),
                    ("stager_", "Stager dosyası"),
                    ("stage_", "Stage dosyası"),
                    ("meterpreter", "Meterpreter"),
                    ("/bin/sh -i", "Interactive shell redirect"),
                    ("bash -i >& /dev/tcp", "Bash reverse shell"),
                ]

                for pattern, desc in suspicious_patterns:
                    if pattern.lower() in cmdline.lower():
                        threat = {
                            "timestamp": datetime.now().isoformat(),
                            "type": "suspicious_process",
                            "pid": info['pid'],
                            "name": info['name'],
                            "cmdline": cmdline[:120],
                            "pattern": desc,
                            "risk_score": 80,
                        }
                        threats.append(threat)
                        self.detected_threats.append(threat)
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return threats

    def detect_c2_traffic(self, data: bytes) -> Optional[dict]:
        """Veri içinde C2 imzaları ara."""
        for signature, description in self.KNOWN_SIGNATURES.items():
            if signature in data:
                threat = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "c2_signature",
                    "signature": signature.decode("utf-8", errors="replace"),
                    "description": description,
                    "data_preview": data[:100].hex(),
                    "risk_score": 90,
                }
                self.detected_threats.append(threat)
                return threat
        return None

    def full_scan(self) -> dict:
        """Tam sistem taraması yap."""
        print(Colors.info("Tam sistem taraması başlatılıyor..."))
        print()

        # Bağlantı taraması
        print(Colors.info("Ağ bağlantıları taranıyor..."))
        conn_threats = self.scan_connections()

        # Process taraması
        print(Colors.info("Process'ler taranıyor..."))
        proc_threats = self.scan_processes()

        all_threats = conn_threats + proc_threats

        if all_threats:
            print(Colors.error(f"{len(all_threats)} tehdit tespit edildi!"))
            for t in all_threats:
                risk = t["risk_score"]
                color = Colors.RED if risk >= 70 else Colors.YELLOW
                print(f"  {Colors.colorize(f'[Risk: {risk}]', color)} "
                      f"{t['type']}: {t.get('reasons', t.get('pattern', ''))}")
                if t.get('pid'):
                    print(f"    PID: {t['pid']} | "
                          f"{t.get('local', '')} → {t.get('remote', '')}")
        else:
            print(Colors.success("Tehdit tespit edilmedi ✓"))

        return {
            "scan_time": datetime.now().isoformat(),
            "total_threats": len(all_threats),
            "connection_threats": len(conn_threats),
            "process_threats": len(proc_threats),
            "threats": all_threats,
        }


class ProcessKiller:
    """Tespit edilen zararlı process'leri sonlandır."""

    @staticmethod
    def kill_process(pid: int) -> bool:
        """PID'ye göre process'i sonlandır."""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()

            # 3 saniye bekle, hala çalışıyorsa KILL gönder
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()

            print(Colors.success(f"Process sonlandırıldı: PID={pid} ({proc_name})"))
            log_event("DEFENDER", f"Process sonlandırıldı: PID={pid}", {"name": proc_name})
            return True

        except psutil.NoSuchProcess:
            print(Colors.warning(f"Process bulunamadı: PID={pid}"))
            return False
        except psutil.AccessDenied:
            print(Colors.error(f"Yetki hatası: PID={pid} (sudo gerekli)"))
            return False
        except Exception as e:
            print(Colors.error(f"Process sonlandırma hatası: {e}"))
            return False

    @staticmethod
    def kill_by_port(port: int) -> bool:
        """Belirli bir portu kullanan tüm process'leri sonlandır."""
        killed = False
        try:
            connections = psutil.net_connections(kind='inet')
            pids = set()
            for conn in connections:
                if conn.laddr and conn.laddr.port == port and conn.pid:
                    pids.add(conn.pid)
                if conn.raddr and conn.raddr.port == port and conn.pid:
                    pids.add(conn.pid)

            for pid in pids:
                if ProcessKiller.kill_process(pid):
                    killed = True

            if not pids:
                print(Colors.warning(f"Port {port} üzerinde aktif process bulunamadı"))

        except (psutil.AccessDenied, PermissionError):
            print(Colors.error("Bağlantı taraması için yetki gerekli"))

        return killed


class PortManager:
    """Port yönetimi: açma, kapatma, durum kontrolü."""

    @staticmethod
    def close_port(port: int) -> bool:
        """Belirli bir portu kullanan process'leri bulup kapatarak portu serbest bırak."""
        print(Colors.info(f"Port {port} kapatılıyor..."))
        try:
            connections = psutil.net_connections(kind='inet')
            pids = set()
            for conn in connections:
                if conn.laddr and conn.laddr.port == port and conn.pid:
                    pids.add(conn.pid)

            if not pids:
                print(Colors.info(f"Port {port} zaten boş"))
                return True

            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    print(Colors.info(f"  Port {port} → PID={pid} ({proc.name()}) kapatılıyor"))
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    print(Colors.success(f"  PID={pid} sonlandırıldı"))
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(Colors.error(f"  PID={pid} kapatılamadı: {e}"))

            log_event("DEFENDER", f"Port {port} kapatıldı", {"pids": list(pids)})
            return True

        except Exception as e:
            print(Colors.error(f"Port kapatma hatası: {e}"))
            return False

    @staticmethod
    def list_listening_ports() -> List[dict]:
        """Dinleme yapan tüm portları listele."""
        ports = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == "LISTEN" and conn.laddr:
                    proc_name = "?"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except Exception:
                            pass

                    suspicious = conn.laddr.port in PayloadDetector.SUSPICIOUS_PORTS
                    ports.append({
                        "port": conn.laddr.port,
                        "ip": conn.laddr.ip,
                        "pid": conn.pid,
                        "process": proc_name,
                        "suspicious": suspicious,
                    })

        except (psutil.AccessDenied, PermissionError):
            print(Colors.warning("Port listesi için yetki gerekli"))

        return sorted(ports, key=lambda x: x["port"])

    @staticmethod
    def check_port(port: int) -> dict:
        """Belirli bir portun durumunu kontrol et."""
        result = {
            "port": port,
            "status": "closed",
            "pid": None,
            "process": None,
            "connections": [],
        }

        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.laddr and conn.laddr.port == port:
                    result["status"] = conn.status.lower()
                    result["pid"] = conn.pid
                    if conn.pid:
                        try:
                            result["process"] = psutil.Process(conn.pid).name()
                        except Exception:
                            pass
                    result["connections"].append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                        "status": conn.status,
                    })
        except Exception:
            pass

        return result


class NetworkSniffer:
    """
    Basit ağ trafiği dinleyici (Wireshark benzeri).
    Belirli bir porttaki trafiği yakalar ve analiz eder.
    """

    def __init__(self, port: int = None, interface: str = "lo0"):
        self.port = port
        self.interface = interface
        self.captured_packets: List[dict] = []
        self._running = False
        self._lock = threading.Lock()
        self.detector = PayloadDetector()

    def start_capture(self, duration: int = 60, callback=None):
        """
        Socket tabanlı basit paket yakalama.
        Not: Scapy gerektirmeden temel TCP yakalama.
        """
        self._running = True
        print(Colors.info(f"Ağ dinleme başlatıldı (Port: {self.port or 'tümü'})"))
        print(Colors.info(f"Süre: {duration} saniye | Durdurmak için Ctrl+C"))
        print(f"\n{'='*80}")
        print(f"{'Zaman':<12} {'Kaynak':<22} {'Hedef':<22} {'Boyut':<8} {'Durum':<10}")
        print(f"{'='*80}")

        start_time = time.time()
        try:
            # Periyodik bağlantı taraması ile dinleme
            while self._running and (time.time() - start_time) < duration:
                try:
                    connections = psutil.net_connections(kind='inet')
                    for conn in connections:
                        if conn.status != "NONE":
                            local_port = conn.laddr.port if conn.laddr else 0
                            remote_port = conn.raddr.port if conn.raddr else 0

                            if self.port and local_port != self.port and remote_port != self.port:
                                continue

                            packet_info = {
                                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:12],
                                "src": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?",
                                "dst": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?",
                                "status": conn.status,
                                "pid": conn.pid,
                            }

                            with self._lock:
                                # Duplike kontrolü
                                key = f"{packet_info['src']}-{packet_info['dst']}-{packet_info['status']}"
                                existing_keys = {
                                    f"{p['src']}-{p['dst']}-{p['status']}"
                                    for p in self.captured_packets[-50:]
                                }
                                if key not in existing_keys:
                                    self.captured_packets.append(packet_info)

                                    # Terminal çıktısı
                                    status_color = Colors.GREEN if conn.status == "ESTABLISHED" else Colors.YELLOW
                                    is_suspicious = (
                                        local_port in PayloadDetector.SUSPICIOUS_PORTS
                                        or remote_port in PayloadDetector.SUSPICIOUS_PORTS
                                    )
                                    marker = Colors.colorize(" ⚠ C2?", Colors.RED) if is_suspicious else ""

                                    print(
                                        f"{packet_info['timestamp']:<12} "
                                        f"{packet_info['src']:<22} "
                                        f"{packet_info['dst']:<22} "
                                        f"{'---':<8} "
                                        f"{Colors.colorize(conn.status, status_color):<10}"
                                        f"{marker}"
                                    )

                                    if callback:
                                        callback(packet_info)

                    time.sleep(0.5)

                except (psutil.AccessDenied, PermissionError):
                    print(Colors.warning("Dinleme için yetki gerekli"))
                    break

        except KeyboardInterrupt:
            pass

        self._running = False
        print(f"\n{'='*80}")
        print(Colors.info(f"Dinleme durduruldu. Toplam yakalanan: {len(self.captured_packets)}"))

        return self.captured_packets

    def stop_capture(self):
        """Dinlemeyi durdur."""
        self._running = False


class C2ServerDetector:
    """
    Bir bağlantının C2 sunucusuna ait olup olmadığını tespit eder.
    - Port tarama
    - Banner grabbing
    - Protokol imza kontrolü
    """

    KNOWN_C2_PORTS = {4444, 4445, 5555, 8080, 8443, 1234, 31337}

    @staticmethod
    def detect_c2_server(host: str, port: int, timeout: float = 3.0) -> dict:
        """Belirtilen host:port'un C2 sunucusu olup olmadığını kontrol et."""
        result = {
            "host": host,
            "port": port,
            "is_c2": False,
            "confidence": 0,
            "indicators": [],
            "banner": None,
        }

        # 1. Port açık mı kontrol
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        except (socket.timeout, ConnectionRefusedError, OSError):
            result["indicators"].append("Port kapalı veya erişilemez")
            return result

        # 2. Banner grabbing
        try:
            sock.settimeout(2)
            banner_data = sock.recv(1024)
            if banner_data:
                result["banner"] = banner_data[:200].hex()

                # ERSIN protokol kontrolü
                if banner_data[:4] == b"ERSN" or b"ERSN" in banner_data:
                    result["is_c2"] = True
                    result["confidence"] = 95
                    result["indicators"].append("ERSIN C2 protokol imzası tespit edildi")

                # Diğer C2 imzaları
                for sig, desc in PayloadDetector.KNOWN_SIGNATURES.items():
                    if sig in banner_data:
                        result["is_c2"] = True
                        result["confidence"] = max(result["confidence"], 80)
                        result["indicators"].append(f"C2 imzası: {desc}")

        except socket.timeout:
            # Timeout olması da C2 göstergesi olabilir (sunucu komut bekliyor)
            result["indicators"].append("Banner timeout - olası C2 dinleme modu")
            result["confidence"] += 20

        except Exception:
            pass

        # 3. Bilinen C2 port kontrolü
        if port in C2ServerDetector.KNOWN_C2_PORTS:
            result["confidence"] += 30
            result["indicators"].append(f"Bilinen C2 portu: {port}")

        # 4. 32 byte anahtar gönderimi kontrolü (ERSIN spesifik)
        try:
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            data = sock.recv(32)
            if data and len(data) == 32:
                result["confidence"] += 30
                result["indicators"].append("32 byte anahtar değişimi tespit edildi (AES-256)")
                result["is_c2"] = True
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        # Sonuç değerlendirmesi
        if result["confidence"] >= 50:
            result["is_c2"] = True

        result["confidence"] = min(result["confidence"], 100)
        return result

    @staticmethod
    def scan_for_c2_servers(host: str = "127.0.0.1",
                             ports: List[int] = None) -> List[dict]:
        """Birden fazla portu C2 sunucusu için tara."""
        if ports is None:
            ports = sorted(C2ServerDetector.KNOWN_C2_PORTS)

        results = []
        print(Colors.info(f"C2 sunucu taraması: {host}"))
        print(Colors.info(f"Taranacak portlar: {ports}"))
        print()

        for port in ports:
            result = C2ServerDetector.detect_c2_server(host, port)
            results.append(result)

            if result["is_c2"]:
                print(Colors.error(
                    f"  ⚠ {host}:{port} - C2 SUNUCU TESPİT EDİLDİ "
                    f"(Güven: %{result['confidence']})"
                ))
                for indicator in result["indicators"]:
                    print(f"    → {indicator}")
            else:
                status = "Açık" if result["indicators"] else "Kapalı"
                print(Colors.info(f"  ✓ {host}:{port} - {status}"))

        return results


class AutoDefender:
    """
    Otomatik savunma sistemi:
    - Sürekli ağ taraması
    - Tehdit tespitinde otomatik aksiyon
    - Hata durumunda port kapatma
    """

    def __init__(self, auto_kill: bool = False, watch_ports: List[int] = None):
        self.auto_kill = auto_kill
        self.watch_ports = watch_ports or list(PayloadDetector.SUSPICIOUS_PORTS)
        self.detector = PayloadDetector()
        self.killer = ProcessKiller()
        self.port_manager = PortManager()
        self._running = False
        self.alerts: List[dict] = []

    def start(self, interval: int = 5):
        """Otomatik savunma döngüsünü başlat."""
        self._running = True
        print(Colors.info("Otomatik savunma sistemi başlatıldı"))
        print(Colors.info(f"Tarama aralığı: {interval} saniye"))
        print(Colors.info(f"İzlenen portlar: {self.watch_ports}"))
        print(Colors.info(f"Otomatik sonlandırma: {'AÇIK' if self.auto_kill else 'KAPALI'}"))
        print(Colors.info("Durdurmak için Ctrl+C"))
        print()

        try:
            while self._running:
                # Bağlantı taraması
                conn_threats = self.detector.scan_connections()
                proc_threats = self.detector.scan_processes()

                all_threats = conn_threats + proc_threats

                for threat in all_threats:
                    self._handle_threat(threat)

                time.sleep(interval)

        except KeyboardInterrupt:
            pass

        self._running = False
        print(Colors.info("Otomatik savunma durduruldu"))

    def _handle_threat(self, threat: dict):
        """Tespit edilen tehdide karşı aksiyon al."""
        risk = threat.get("risk_score", 0)
        pid = threat.get("pid")

        alert = {
            "timestamp": datetime.now().isoformat(),
            "threat": threat,
            "action_taken": None,
        }

        if risk >= 70:
            print(Colors.error(
                f"[ALERT] Yüksek riskli tehdit! Risk: {risk}/100"
            ))

            if self.auto_kill and pid:
                if self.killer.kill_process(pid):
                    alert["action_taken"] = f"Process sonlandırıldı (PID: {pid})"
                    print(Colors.success(f"  → Process otomatik sonlandırıldı: PID={pid}"))

                    # İlgili portu da kapat
                    for reason in threat.get("reasons", []):
                        if "port:" in reason.lower():
                            try:
                                port = int(reason.split(":")[-1].strip())
                                self.port_manager.close_port(port)
                                alert["action_taken"] += f", Port {port} kapatıldı"
                            except (ValueError, IndexError):
                                pass
            else:
                print(Colors.warning(
                    f"  → Tehdit tespit edildi ama otomatik sonlandırma kapalı"
                ))
                if pid:
                    print(Colors.warning(f"  → Manuel sonlandırma: kill {pid}"))

        elif risk >= 30:
            print(Colors.warning(
                f"[WARN] Orta riskli aktivite: {threat.get('type')} (Risk: {risk})"
            ))

        self.alerts.append(alert)
        log_event("DEFENDER_ALERT", json.dumps(threat, default=str))

    def stop(self):
        """Savunma sistemini durdur."""
        self._running = False
