#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious ağ tarayıcı modülü - aynı subnet'teki aktif cihazları keşfeder

keşif yöntemleri:
    1. arp tarama (root gerektirir) - en hızlı ve güvenilir
    2. icmp ping sweep (root gerektirir) - yaygın yöntem
    3. tcp connect sweep (root gerektirmez) - fallback yöntem
"""

import socket
import struct
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Tuple

from cekirdek.gunluk import Gunluk
from cekirdek.ag_yardimcilar import (
    yerel_ip_bul,
    subnet_hesapla,
    mac_adresi_al,
    arp_paketi_olustur,
    ag_arayuzleri_listele,
    cidr_ayikla,
    cidr_gecerli_mi,
    ip_gecerli_mi,
    varsayilan_subnet_bul,
)


# yaygın portlar — tcp connect sweep için
_TCP_TARAMA_PORTLARI = [22, 80, 443, 445, 139, 3389, 8080, 21, 23, 25, 53, 110, 3306, 5432, 8443, 9999]


def ag_taramasi_baslat(
    subnet: Optional[str] = None,
    yontem: str = "otomatik",
    zaman_asimi: float = 1.0,
    is_parcacigi_sayisi: int = 50,
    gunluk: Optional[Gunluk] = None,
) -> List[Dict[str, Optional[str]]]:
    """
    ağ keşif taraması başlatır — aynı subnet'teki aktif cihazları tespit eder

    parametreler:
        subnet: taranacak subnet cidr notasyonu (ör: "192.168.1.0/24")
                none ise otomatik tespit edilir
        yontem: tarama yöntemi ("arp", "icmp", "tcp", "otomatik")
                otomatik: root ise arp, değilse tcp
        zaman_asimi: her host için zaman aşımı (saniye)
        is_parcacigi_sayisi: paralel thread sayısı
        gunluk: loglama nesnesi

    döndürür:
        bulunan host bilgilerini içeren sözlük listesi
        her sözlük: {"ip": str, "mac": str veya none}
    """
    if gunluk is None:
        gunluk = Gunluk()

    # subnet otomatik tespiti
    if subnet is None:
        try:
            subnet = varsayilan_subnet_bul()
            gunluk.bilgi(f"subnet otomatik tespit edildi: {subnet}")
        except OSError as hata:
            gunluk.hata(f"subnet tespit edilemedi: {hata}")
            return []

    # subnet doğrulama
    if not cidr_gecerli_mi(subnet):
        gunluk.hata(f"geçersiz subnet: {subnet}")
        return []

    # yerel ip
    try:
        yerel_ip = yerel_ip_bul()
    except OSError:
        yerel_ip = "bilinmiyor"

    # host listesi
    ip_str, cidr = cidr_ayikla(subnet)
    host_listesi = subnet_hesapla(ip_str, cidr)

    # yöntem belirleme
    root_mu = os.geteuid() == 0 if hasattr(os, "geteuid") else False

    if yontem == "otomatik":
        if root_mu:
            yontem = "arp"
        else:
            yontem = "tcp"

    # başlık göster
    gunluk.baslik("ağ keşfi başlatılıyor")
    gunluk.bilgi(f"yerel ip        : {yerel_ip}")
    gunluk.bilgi(f"subnet          : {subnet}")
    gunluk.bilgi(f"tarama yöntemi  : {yontem}")
    gunluk.bilgi(f"thread sayısı   : {is_parcacigi_sayisi}")
    gunluk.bilgi(f"host sayısı     : {len(host_listesi)}")
    gunluk.bos_satir()

    # tarama başlat
    basla = time.time()

    if yontem == "arp":
        if not root_mu:
            gunluk.uyari("arp tarama root yetkisi gerektirir, tcp yöntemine düşülüyor")
            yontem = "tcp"
            sonuclar = _tcp_tarama(host_listesi, _TCP_TARAMA_PORTLARI, zaman_asimi, is_parcacigi_sayisi, gunluk)
        else:
            sonuclar = _arp_tarama(host_listesi, zaman_asimi, gunluk)
    elif yontem == "icmp":
        if not root_mu:
            gunluk.uyari("icmp tarama root yetkisi gerektirir, tcp yöntemine düşülüyor")
            yontem = "tcp"
            sonuclar = _tcp_tarama(host_listesi, _TCP_TARAMA_PORTLARI, zaman_asimi, is_parcacigi_sayisi, gunluk)
        else:
            sonuclar = _icmp_tarama(host_listesi, zaman_asimi, is_parcacigi_sayisi, gunluk)
    elif yontem == "tcp":
        sonuclar = _tcp_tarama(host_listesi, _TCP_TARAMA_PORTLARI, zaman_asimi, is_parcacigi_sayisi, gunluk)
    else:
        gunluk.hata(f"bilinmeyen tarama yöntemi: {yontem}")
        return []

    bitis = time.time()
    sure = bitis - basla

    # sonuçları sıralı göster
    sonuclar.sort(key=lambda x: socket.inet_aton(x["ip"]))

    gunluk.bos_satir()
    for host in sonuclar:
        ek_bilgi = ""
        if host["ip"] == yerel_ip:
            ek_bilgi = "   (bu cihaz)"
        # basit gateway tespiti — .1 ile biten ip genelde gateway'dir
        elif host["ip"].endswith(".1"):
            ek_bilgi = "   (muhtemel gateway)"

        mac_str = host.get("mac") or "bilinmiyor"
        gunluk.basari(f"{host['ip']:<16} {mac_str:<20}{ek_bilgi}")

    gunluk.bos_satir()
    gunluk.basari(f"toplam aktif host: {len(sonuclar)} ({sure:.1f} saniye)")

    return sonuclar


def _arp_tarama(
    host_listesi: List[str],
    zaman_asimi: float,
    gunluk: Gunluk,
) -> List[Dict[str, Optional[str]]]:
    """
    arp tabanlı host keşfi — raw socket ile arp request gönderir

    root yetkisi gerektirir.
    """
    sonuclar = []

    # aktif arayüzü bul
    arayuzler = ag_arayuzleri_listele()
    if not arayuzler:
        gunluk.hata("aktif ağ arayüzü bulunamadı")
        return sonuclar

    arayuz = arayuzler[0]
    arayuz_adi = arayuz["arayuz"]
    kaynak_ip = arayuz["ip"]
    kaynak_mac = arayuz.get("mac")

    if not kaynak_mac:
        gunluk.hata(f"mac adresi alınamadı: {arayuz_adi}")
        return sonuclar

    gunluk.ayiklama(f"arayüz: {arayuz_adi}, ip: {kaynak_ip}, mac: {kaynak_mac}")

    try:
        # raw socket aç (af_packet — ethernet seviyesi)
        soket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)
        )
        soket.settimeout(zaman_asimi)
        soket.bind((arayuz_adi, 0))

        for hedef_ip in host_listesi:
            paket = arp_paketi_olustur(hedef_ip, kaynak_ip, kaynak_mac)
            soket.send(paket)

        # yanıtları topla
        bekleme_bitis = time.time() + zaman_asimi + 1.0
        goruldu = set()

        while time.time() < bekleme_bitis:
            try:
                yanit = soket.recv(65535)
                # arp yanıtı mı kontrol et (opcode == 2, reply)
                if len(yanit) >= 42:
                    # ethernet başlığını atla (14 byte)
                    arp_opcode = struct.unpack("!H", yanit[20:22])[0]
                    if arp_opcode == 2:  # arp reply
                        gonderici_mac = ":".join(f"{b:02x}" for b in yanit[22:28])
                        gonderici_ip = socket.inet_ntoa(yanit[28:32])

                        if gonderici_ip not in goruldu and gonderici_ip in host_listesi:
                            goruldu.add(gonderici_ip)
                            sonuclar.append({"ip": gonderici_ip, "mac": gonderici_mac})
            except socket.timeout:
                break

        soket.close()

    except PermissionError:
        gunluk.hata("arp tarama için root yetkisi gerekli (sudo ile çalıştırın)")
    except OSError as hata:
        gunluk.hata(f"arp tarama hatası: {hata}")

    return sonuclar


def _icmp_tarama(
    host_listesi: List[str],
    zaman_asimi: float,
    is_parcacigi_sayisi: int,
    gunluk: Gunluk,
) -> List[Dict[str, Optional[str]]]:
    """
    icmp ping sweep — raw socket ile icmp echo request gönderir

    root yetkisi gerektirir.
    """
    sonuclar = []

    def _tek_ping(hedef_ip: str) -> Optional[Dict[str, Optional[str]]]:
        """tek bir host'a icmp ping gönderir"""
        try:
            soket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            soket.settimeout(zaman_asimi)

            # icmp echo request paketi oluştur
            icmp_tip = 8     # echo request
            icmp_kod = 0
            icmp_checksum = 0
            icmp_id = os.getpid() & 0xFFFF
            icmp_sira = 1

            baslik = struct.pack("!BBHHH", icmp_tip, icmp_kod, icmp_checksum, icmp_id, icmp_sira)
            veri = b"noxious-ping" + struct.pack("!d", time.time())

            # checksum hesapla
            icmp_checksum = _checksum_hesapla(baslik + veri)
            baslik = struct.pack("!BBHHH", icmp_tip, icmp_kod, icmp_checksum, icmp_id, icmp_sira)

            soket.sendto(baslik + veri, (hedef_ip, 0))

            # yanıt bekle
            yanit, adres = soket.recvfrom(1024)
            soket.close()

            return {"ip": hedef_ip, "mac": None}

        except (socket.timeout, OSError):
            try:
                soket.close()
            except Exception:
                pass
            return None

    with ThreadPoolExecutor(max_workers=is_parcacigi_sayisi) as havuz:
        gelecekler = {havuz.submit(_tek_ping, ip): ip for ip in host_listesi}
        for gelecek in as_completed(gelecekler):
            sonuc = gelecek.result()
            if sonuc:
                sonuclar.append(sonuc)

    return sonuclar


def _tcp_tarama(
    host_listesi: List[str],
    portlar: List[int],
    zaman_asimi: float,
    is_parcacigi_sayisi: int,
    gunluk: Gunluk,
) -> List[Dict[str, Optional[str]]]:
    """
    tcp connect sweep — yaygın portlara tcp bağlantısı deneyerek canlı host tespiti

    root yetkisi gerektirmez.
    """
    sonuclar = []
    bulunan = set()

    def _host_kontrol(hedef_ip: str) -> Optional[Dict[str, Optional[str]]]:
        """tek bir host'un canlı olup olmadığını kontrol eder"""
        for port in portlar:
            try:
                soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                soket.settimeout(zaman_asimi)
                sonuc = soket.connect_ex((hedef_ip, port))
                soket.close()

                if sonuc == 0:
                    return {"ip": hedef_ip, "mac": None}
            except (socket.timeout, OSError):
                try:
                    soket.close()
                except Exception:
                    pass
        return None

    with ThreadPoolExecutor(max_workers=is_parcacigi_sayisi) as havuz:
        gelecekler = {havuz.submit(_host_kontrol, ip): ip for ip in host_listesi}
        for gelecek in as_completed(gelecekler):
            sonuc = gelecek.result()
            if sonuc and sonuc["ip"] not in bulunan:
                bulunan.add(sonuc["ip"])
                sonuclar.append(sonuc)

    return sonuclar


def _checksum_hesapla(veri: bytes) -> int:
    """icmp checksum hesaplar (rfc 1071)"""
    if len(veri) % 2:
        veri += b"\x00"

    toplam = 0
    for i in range(0, len(veri), 2):
        kelime = (veri[i] << 8) + veri[i + 1]
        toplam += kelime

    toplam = (toplam >> 16) + (toplam & 0xFFFF)
    toplam += toplam >> 16

    return ~toplam & 0xFFFF
