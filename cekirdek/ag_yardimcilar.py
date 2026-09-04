#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious ağ yardımcıları - ip hesaplama, subnet yardımcıları, arp paket oluşturucu
"""

import socket
import struct
import ipaddress
import fcntl
import os
from typing import List, Optional, Tuple, Dict


def yerel_ip_bul() -> str:
    """
    sistemin yerel ağ ip adresini otomatik tespit eder

    udp soketi ile 8.8.8.8'e bağlanmayı deneyerek yerel ip'yi bulur.
    gerçekte paket göndermez, sadece route tablosunu sorgular.

    döndürür:
        yerel ip adresi stringi (ör: "192.168.1.105")

    istisnalar:
        OSError: ağ arayüzü bulunamazsa
    """
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        soket.settimeout(0.1)
        # gerçekte bağlanmaz, sadece route tablosunu kontrol eder
        soket.connect(("8.8.8.8", 80))
        ip = soket.getsockname()[0]
        soket.close()
        return ip
    except OSError:
        # fallback: hostname üzerinden
        try:
            return socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            raise OSError("yerel ip adresi tespit edilemedi")


def subnet_hesapla(ip: str, cidr: int = 24) -> List[str]:
    """
    cidr notasyonundan taranacak host ip listesi üretir

    parametreler:
        ip: ağ adresi veya herhangi bir host ip'si (ör: "192.168.1.0" veya "192.168.1.105")
        cidr: alt ağ maskesi bit uzunluğu (ör: 24)

    döndürür:
        taranabilir host ip adresleri listesi (ağ ve broadcast adresleri hariç)

    örnek:
        >>> subnet_hesapla("192.168.1.0", 24)
        ['192.168.1.1', '192.168.1.2', ..., '192.168.1.254']
    """
    ag = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
    # ağ adresi ve broadcast adresi hariç
    return [str(host) for host in ag.hosts()]


def ip_gecerli_mi(ip_str: str) -> bool:
    """
    ip adresinin geçerli bir ipv4 adresi olup olmadığını kontrol eder

    parametreler:
        ip_str: kontrol edilecek ip adresi stringi

    döndürür:
        geçerli ise true, değilse false

    örnek:
        >>> ip_gecerli_mi("192.168.1.1")
        True
        >>> ip_gecerli_mi("999.999.999.999")
        False
    """
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def cidr_gecerli_mi(cidr_str: str) -> bool:
    """
    cidr notasyonunun geçerli olup olmadığını kontrol eder

    parametreler:
        cidr_str: kontrol edilecek cidr notasyonu (ör: "192.168.1.0/24")

    döndürür:
        geçerli ise true, değilse false

    örnek:
        >>> cidr_gecerli_mi("192.168.1.0/24")
        True
        >>> cidr_gecerli_mi("192.168.1.0/33")
        False
    """
    try:
        ipaddress.IPv4Network(cidr_str, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def cidr_ayikla(cidr_str: str) -> Tuple[str, int]:
    """
    cidr notasyonunu ip ve prefix length olarak ayırır

    parametreler:
        cidr_str: cidr notasyonu (ör: "192.168.1.0/24")

    döndürür:
        (ip, prefix_length) tuple'ı

    istisnalar:
        ValueError: geçersiz cidr notasyonu
    """
    try:
        ag = ipaddress.IPv4Network(cidr_str, strict=False)
        return str(ag.network_address), ag.prefixlen
    except (ipaddress.AddressValueError, ValueError) as hata:
        raise ValueError(f"geçersiz cidr notasyonu: {cidr_str}") from hata


def mac_adresi_al(arayuz: str = "eth0") -> Optional[str]:
    """
    belirtilen ağ arayüzünün mac adresini döndürür (sadece linux)

    parametreler:
        arayuz: ağ arayüzü adı (ör: "eth0", "wlan0")

    döndürür:
        mac adresi stringi (ör: "aa:bb:cc:dd:ee:ff") veya none
    """
    try:
        yol = f"/sys/class/net/{arayuz}/address"
        if os.path.exists(yol):
            with open(yol, "r") as f:
                return f.read().strip()
    except (OSError, IOError):
        pass

    # fallback: ioctl ile
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bilgi = fcntl.ioctl(
            soket.fileno(),
            0x8927,  # siocgifhwaddr
            struct.pack("256s", arayuz[:15].encode("utf-8")),
        )
        mac = ":".join(f"{b:02x}" for b in bilgi[18:24])
        soket.close()
        return mac
    except (OSError, IOError):
        return None


def arp_paketi_olustur(
    hedef_ip: str, kaynak_ip: str, kaynak_mac: str
) -> bytes:
    """
    raw arp request paketi oluşturur (ethernet çerçevesi dahil)

    parametreler:
        hedef_ip: hedef ip adresi
        kaynak_ip: kaynak (bizim) ip adresi
        kaynak_mac: kaynak mac adresi (ör: "aa:bb:cc:dd:ee:ff")

    döndürür:
        ethernet + arp çerçevesi olarak ham byte verisi
    """
    # mac adreslerini byte'a çevir
    kaynak_mac_bayt = bytes.fromhex(kaynak_mac.replace(":", ""))
    hedef_mac_bayt = b"\xff\xff\xff\xff\xff\xff"  # broadcast

    # ethernet başlığı (14 byte)
    eth_baslik = struct.pack(
        "!6s6sH",
        hedef_mac_bayt,    # hedef mac (broadcast)
        kaynak_mac_bayt,   # kaynak mac
        0x0806,            # ethertype: arp
    )

    # arp başlığı (28 byte)
    arp_baslik = struct.pack(
        "!HHBBH6s4s6s4s",
        0x0001,                                    # hardware type: ethernet
        0x0800,                                    # protocol type: ipv4
        6,                                         # hardware size: 6
        4,                                         # protocol size: 4
        0x0001,                                    # opcode: request
        kaynak_mac_bayt,                           # sender mac
        socket.inet_aton(kaynak_ip),               # sender ip
        b"\x00\x00\x00\x00\x00\x00",              # target mac (bilinmiyor)
        socket.inet_aton(hedef_ip),                # target ip
    )

    return eth_baslik + arp_baslik


def ag_arayuzleri_listele() -> List[Dict[str, str]]:
    """
    sistemdeki aktif ağ arayüzlerini listeler (sadece linux)

    döndürür:
        arayüz bilgilerini içeren sözlük listesi
        her sözlük: {"arayuz": "eth0", "ip": "192.168.1.105", "mac": "aa:bb:cc:dd:ee:ff"}
    """
    arayuzler = []

    # /sys/class/net/ dizininden arayüzleri oku
    net_dizin = "/sys/class/net"
    if not os.path.exists(net_dizin):
        return arayuzler

    for arayuz_adi in sorted(os.listdir(net_dizin)):
        # loopback ve sanal arayüzleri atla (docker, veth, virbr, tun, tap vb.)
        if arayuz_adi == "lo" or any(arayuz_adi.startswith(on) for on in ("docker", "veth", "virbr", "br-", "tun", "tap")):
            continue

        bilgi = {"arayuz": arayuz_adi, "ip": None, "mac": None}

        # mac adresi
        mac = mac_adresi_al(arayuz_adi)
        if mac and mac != "00:00:00:00:00:00":
            bilgi["mac"] = mac

        # ip adresi
        try:
            soket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_bilgi = fcntl.ioctl(
                soket.fileno(),
                0x8915,  # siocgifaddr
                struct.pack("256s", arayuz_adi[:15].encode("utf-8")),
            )
            ip = socket.inet_ntoa(ip_bilgi[20:24])
            bilgi["ip"] = ip
            soket.close()
        except (OSError, IOError):
            pass

        # sadece ip'si olan arayüzleri ekle
        if bilgi["ip"]:
            arayuzler.append(bilgi)

    # fiziksel arayüzleri öne al (eth*, wlan*, en*, wl*)
    arayuzler.sort(key=lambda a: 0 if any(a["arayuz"].startswith(p) for p in ("eth", "wlan", "en", "wl")) else 1)

    return arayuzler


def varsayilan_subnet_bul() -> str:
    """
    sistemin bağlı olduğu varsayılan subnet'i cidr notasyonunda döndürür

    döndürür:
        cidr notasyonlu subnet (ör: "192.168.1.0/24")

    istisnalar:
        OSError: ağ bilgisi alınamazsa
    """
    ip = yerel_ip_bul()
    # varsayılan olarak /24 subnet kullan
    ag = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return str(ag)
