#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious servis tanımlayıcı modülü - açık portlardaki servisleri tanımlar

teknikler:
    1. banner grabbing - servisin gönderdiği karşılama mesajını okur
    2. http header analizi - server/x-powered-by header'larını parse eder
    3. ssl/tls bilgi toplama - sertifika bilgisi çeker
    4. protokol parmak izi - servis yanıtlarını bilinen imzalarla karşılaştırır
"""

import socket
import ssl
import re
from typing import List, Optional, Dict, Tuple

from cekirdek.gunluk import Gunluk
from cekirdek.ag_yardimcilar import ip_gecerli_mi
from zafiyet_veritabani import zafiyet_ara, port_servis_adi, risk_renk_kodu


# bilinen servis imzaları — banner'dan servis tespiti için
_SERVIS_IMZALARI = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)", re.IGNORECASE), "openssh"),
    (re.compile(r"SSH-[\d.]+-dropbear[_\s]*([\d.]+)", re.IGNORECASE), "dropbear"),
    (re.compile(r"SSH-", re.IGNORECASE), "ssh"),
    (re.compile(r"220.*vsftpd\s+([\d.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"220.*ProFTPD\s+([\d.]+)", re.IGNORECASE), "proftpd"),
    (re.compile(r"220.*FileZilla Server\s+([\d.]+)", re.IGNORECASE), "filezilla"),
    (re.compile(r"220.*FTP", re.IGNORECASE), "ftp"),
    (re.compile(r"Welcome to Vulnerable Server", re.IGNORECASE), "vulnserver"),
    (re.compile(r"VulnServer", re.IGNORECASE), "vulnserver"),
    (re.compile(r"\+OK.*Dovecot", re.IGNORECASE), "dovecot"),
    (re.compile(r"\+OK.*POP3", re.IGNORECASE), "pop3"),
    (re.compile(r"220.*SMTP", re.IGNORECASE), "smtp"),
    (re.compile(r"220.*Postfix", re.IGNORECASE), "postfix"),
    (re.compile(r"220.*Microsoft ESMTP", re.IGNORECASE), "exchange"),
    (re.compile(r"\* OK.*IMAP", re.IGNORECASE), "imap"),
    (re.compile(r"MySQL", re.IGNORECASE), "mysql"),
    (re.compile(r"MariaDB", re.IGNORECASE), "mariadb"),
    (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql"),
    (re.compile(r"Redis", re.IGNORECASE), "redis"),
    (re.compile(r"MongoDB", re.IGNORECASE), "mongodb"),
]


def servis_tespiti_baslat(hedef_ip, acik_portlar=None, zaman_asimi=3.0, gunluk=None):
    """
    açık portlardaki servisleri tanımlar ve versiyon tespiti yapar

    parametreler:
        hedef_ip: hedef ip adresi
        acik_portlar: açık port listesi (none ise yaygın portlar denenir)
        zaman_asimi: bağlantı zaman aşımı (saniye)
        gunluk: loglama nesnesi

    döndürür:
        servis bilgilerini içeren sözlük listesi
    """
    if gunluk is None:
        gunluk = Gunluk()

    if not ip_gecerli_mi(hedef_ip):
        gunluk.hata(f"geçersiz hedef ip: {hedef_ip}")
        return []

    # açık port listesi yoksa yaygın portları kullan
    if acik_portlar is None:
        acik_portlar = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 9999]

    # port numaralarını çıkar (dict listesi veya int listesi olabilir)
    port_numaralari = []
    for p in acik_portlar:
        if isinstance(p, dict):
            port_numaralari.append(p["port"])
        else:
            port_numaralari.append(p)

    gunluk.baslik(f"servis tespiti — {hedef_ip}")
    gunluk.bilgi(f"hedef       : {hedef_ip}")
    gunluk.bilgi(f"port sayısı : {len(port_numaralari)}")
    gunluk.bilgi(f"zaman aşımı : {zaman_asimi}s")
    gunluk.bos_satir()

    sonuclar = []

    for port in port_numaralari:
        servis_bilgi = _port_servis_tespit(hedef_ip, port, zaman_asimi, gunluk)
        sonuclar.append(servis_bilgi)

    # sonuçları göster
    if sonuclar:
        gunluk.bilgi(f"{'PORT':<10}{'SERVİS':<16}{'VERSİYON':<25}{'BANNER'}")
        gunluk.ayirici(karakter="-", uzunluk=70)

        for s in sonuclar:
            banner_kisalt = (s.get("banner") or "")[:40]
            gunluk.basari(
                f"{s['port']}/tcp   "
                f"{s['servis']:<16}"
                f"{s.get('versiyon', ''):<25}"
                f"{banner_kisalt}"
            )

    # zafiyet kontrolü
    gunluk.bos_satir()
    zafiyet_sayisi = 0
    for s in sonuclar:
        if s.get("zafiyetler"):
            zafiyet_sayisi += len(s["zafiyetler"])
            for z in s["zafiyetler"]:
                gunluk.uyari(f"[{s['port']}/tcp {s['servis']}] {z}")

    gunluk.bos_satir()
    gunluk.basari(f"{len(sonuclar)} servis tanımlandı")
    if zafiyet_sayisi > 0:
        gunluk.uyari(f"{zafiyet_sayisi} potansiyel zafiyet tespit edildi")

    return sonuclar


def _port_servis_tespit(hedef_ip, port, zaman_asimi, gunluk):
    """tek bir porttaki servisi tespit eder"""
    sonuc = {
        "port": port,
        "servis": port_servis_adi(port),
        "versiyon": "",
        "banner": None,
        "ssl": False,
        "zafiyetler": [],
    }

    # banner grabbing
    banner = _banner_al(hedef_ip, port, zaman_asimi)
    if banner:
        sonuc["banner"] = banner
        # servis ve versiyon eşleştirme
        servis, versiyon = _servis_eslesitir(banner, port)
        if servis:
            sonuc["servis"] = servis
        if versiyon:
            sonuc["versiyon"] = versiyon

    # http portları için header analizi
    if port in (80, 8080, 8000, 8443, 8888, 443):
        http_bilgi = _http_baslik_analiz(hedef_ip, port, zaman_asimi)
        if http_bilgi:
            if http_bilgi.get("server"):
                sonuc["versiyon"] = http_bilgi["server"]
                # server header'dan servis adı çıkar
                server_kucuk = http_bilgi["server"].lower()
                if "apache" in server_kucuk:
                    sonuc["servis"] = "apache"
                elif "nginx" in server_kucuk:
                    sonuc["servis"] = "nginx"
                elif "iis" in server_kucuk:
                    sonuc["servis"] = "iis"
                elif "tomcat" in server_kucuk:
                    sonuc["servis"] = "tomcat"

    # ssl portları için ssl bilgisi
    if port in (443, 8443, 465, 636, 993, 995, 990):
        ssl_bilgi = _ssl_bilgi_al(hedef_ip, port, zaman_asimi)
        if ssl_bilgi:
            sonuc["ssl"] = True
            if ssl_bilgi.get("konu"):
                sonuc["versiyon"] += f" [TLS: {ssl_bilgi['konu']}]"

    # zafiyet kontrolü
    if sonuc["servis"] and sonuc["versiyon"]:
        # versiyon string'inden sayısal kısmı çıkar
        versiyon_temiz = _versiyon_ayikla(sonuc["versiyon"])
        if versiyon_temiz:
            zafiyet = zafiyet_ara(sonuc["servis"], versiyon_temiz)
            if zafiyet:
                sonuc["zafiyetler"] = zafiyet.get("zafiyetler", [])
                sonuc["risk"] = zafiyet.get("risk", "bilinmiyor")

    # vulnserver özel kontrolü
    if sonuc["servis"] == "vulnserver":
        zafiyet = zafiyet_ara("vulnserver", "1.0")
        if zafiyet:
            sonuc["zafiyetler"] = zafiyet.get("zafiyetler", [])
            sonuc["risk"] = zafiyet.get("risk", "kritik")
            sonuc["versiyon"] = sonuc["versiyon"] or "1.0"

    return sonuc


def _banner_al(hedef_ip, port, zaman_asimi):
    """port'tan banner okur"""
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        soket.connect((hedef_ip, port))

        # bazı servisler bağlantıda hemen banner gönderir
        try:
            banner = soket.recv(4096)
            soket.close()
            if banner:
                return banner.decode("utf-8", errors="replace").strip()
        except (socket.timeout, UnicodeDecodeError):
            pass

        soket.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return None


def _http_baslik_analiz(hedef_ip, port, zaman_asimi):
    """http response header analizi"""
    sonuc = {}
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        soket.connect((hedef_ip, port))

        istek = f"HEAD / HTTP/1.1\r\nHost: {hedef_ip}\r\nConnection: close\r\n\r\n"
        soket.sendall(istek.encode())

        yanit = b""
        while True:
            try:
                parca = soket.recv(4096)
                if not parca:
                    break
                yanit += parca
                if b"\r\n\r\n" in yanit:
                    break
            except socket.timeout:
                break

        soket.close()

        yanit_str = yanit.decode("utf-8", errors="replace")

        # server header
        server_eslesme = re.search(r"Server:\s*(.+?)(?:\r\n|\n)", yanit_str, re.IGNORECASE)
        if server_eslesme:
            sonuc["server"] = server_eslesme.group(1).strip()

        # x-powered-by
        powered_eslesme = re.search(r"X-Powered-By:\s*(.+?)(?:\r\n|\n)", yanit_str, re.IGNORECASE)
        if powered_eslesme:
            sonuc["powered_by"] = powered_eslesme.group(1).strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return sonuc


def _ssl_bilgi_al(hedef_ip, port, zaman_asimi):
    """ssl sertifika bilgisi çeker"""
    sonuc = {}
    try:
        baglam = ssl.create_default_context()
        baglam.check_hostname = False
        baglam.verify_mode = ssl.CERT_NONE

        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        ssl_soket = baglam.wrap_socket(soket, server_hostname=hedef_ip)
        ssl_soket.connect((hedef_ip, port))

        sertifika = ssl_soket.getpeercert(binary_form=False)
        ssl_soket.close()

        if sertifika:
            konu = sertifika.get("subject", ())
            for alan in konu:
                for anahtar, deger in alan:
                    if anahtar == "commonName":
                        sonuc["konu"] = deger
                        break

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        pass

    return sonuc


def _servis_eslesitir(banner, port):
    """banner'ı bilinen servis imzalarıyla eşleştirir"""
    servis = None
    versiyon = ""

    for desen, servis_adi in _SERVIS_IMZALARI:
        eslesme = desen.search(banner)
        if eslesme:
            servis = servis_adi
            if eslesme.groups():
                versiyon = eslesme.group(1)
            break

    return servis, versiyon


def _versiyon_ayikla(versiyon_str):
    """versiyon string'inden sayısal versiyon kısmını çıkarır"""
    eslesme = re.search(r"(\d+(?:\.\d+)*(?:p\d+)?)", versiyon_str)
    if eslesme:
        return eslesme.group(1)
    return None
