#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious port tarayıcı modülü - hedef üzerinde açık portları tespit eder
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict

from cekirdek.gunluk import Gunluk
from cekirdek.ag_yardimcilar import ip_gecerli_mi
from zafiyet_veritabani import port_servis_adi

# en yaygın 100 port
PROFIL_HIZLI = [
    7, 20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 464, 465,
    500, 514, 515, 520, 521, 554, 587, 593, 631, 636, 646, 873, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1214, 1241, 1311, 1337,
    1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2049, 2121, 2717, 3000,
    3128, 3268, 3306, 3389, 3986, 4000, 4899, 5000, 5009, 5050, 5060, 5100,
    5190, 5222, 5432, 5631, 5666, 5800, 5900, 5901, 6000, 6001, 6379, 6667,
    8000, 8008, 8080, 8443, 8888, 9100, 9999, 10000,
]

# genişletilmiş profil
PROFIL_TAM = sorted(set(PROFIL_HIZLI + list(range(1, 1025)) + [
    4443, 4444, 5001, 5003, 5555, 5985, 5986, 6588, 6668, 6697, 7000,
    7001, 7002, 7070, 7443, 7777, 7778, 8081, 8082, 8088, 8500, 8889,
    9000, 9001, 9090, 9200, 9300, 9418, 9443, 10443, 11211, 15672,
    27017, 27018, 28017, 32768, 49152, 49153, 49154, 49155,
]))


def port_taramasi_baslat(hedef_ip, port_listesi=None, profil="hizli",
                         tarama_tipi="tcp", is_parcacigi_sayisi=100,
                         zaman_asimi=1.0, gunluk=None):
    """hedef üzerinde port taraması başlatır"""
    if gunluk is None:
        gunluk = Gunluk()
    if not ip_gecerli_mi(hedef_ip):
        gunluk.hata(f"geçersiz hedef ip: {hedef_ip}")
        return []

    portlar = _port_listesi_olustur(profil, port_listesi)
    if not portlar:
        gunluk.hata("taranacak port bulunamadı")
        return []

    profil_bilgi = f"özel ({len(portlar)} port)" if port_listesi else f"{profil} ({len(portlar)} port)"

    gunluk.baslik(f"port taraması — {hedef_ip}")
    gunluk.bilgi(f"hedef     : {hedef_ip}")
    gunluk.bilgi(f"profil    : {profil_bilgi}")
    gunluk.bilgi(f"tarama    : {tarama_tipi} connect")
    gunluk.bilgi(f"thread    : {is_parcacigi_sayisi}")
    gunluk.bos_satir()

    basla = time.time()
    acik_portlar = _tcp_connect_tarama(hedef_ip, portlar, zaman_asimi, is_parcacigi_sayisi, gunluk)
    sure = time.time() - basla

    acik_portlar.sort(key=lambda x: x["port"])

    if acik_portlar:
        gunluk.bilgi(f"{'PORT':<10}{'DURUM':<9}{'SERVİS'}")
        gunluk.ayirici(karakter="-", uzunluk=35)
        for p in acik_portlar:
            gunluk.basari(f"{p['port']}/tcp   {'açık':<9}{p['servis']}")

    gunluk.bos_satir()
    gunluk.basari(f"{len(acik_portlar)} açık port bulundu ({len(portlar)} port tarandı, {sure:.1f}s)")
    return acik_portlar


def _port_listesi_olustur(profil, ozel_portlar=None):
    """profil veya özel listeden port seti oluşturur"""
    if ozel_portlar:
        return sorted(set(ozel_portlar))
    if profil == "hizli":
        return PROFIL_HIZLI[:]
    elif profil == "tam":
        return PROFIL_TAM[:]
    elif profil == "tumu":
        return list(range(1, 65536))
    return PROFIL_HIZLI[:]


def _tcp_connect_tara(hedef_ip, port, zaman_asimi):
    """tek bir porta tcp connect taraması yapar"""
    try:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(zaman_asimi)
        sonuc = soket.connect_ex((hedef_ip, port))
        soket.close()
        if sonuc == 0:
            return {"port": port, "durum": "açık", "servis": port_servis_adi(port)}
    except (socket.timeout, OSError):
        try:
            soket.close()
        except Exception:
            pass
    return None


def _tcp_connect_tarama(hedef_ip, portlar, zaman_asimi, is_parcacigi_sayisi, gunluk):
    """paralel tcp connect port taraması"""
    sonuclar = []
    with ThreadPoolExecutor(max_workers=is_parcacigi_sayisi) as havuz:
        gelecekler = {havuz.submit(_tcp_connect_tara, hedef_ip, p, zaman_asimi): p for p in portlar}
        for gelecek in as_completed(gelecekler):
            try:
                sonuc = gelecek.result()
                if sonuc:
                    sonuclar.append(sonuc)
                    gunluk.ayiklama(f"açık port bulundu: {sonuc['port']}/tcp")
            except Exception:
                pass
    return sonuclar


def port_araligi_ayikla(port_str):
    """
    port string ifadesini port listesine çevirir

    desteklenen formatlar:
        "22,80,443" → [22, 80, 443]
        "1-1024" → [1, 2, ..., 1024]
        "22,80,8000-8100" → karışık
    """
    portlar = set()
    for parca in port_str.split(","):
        parca = parca.strip()
        if "-" in parca:
            baslangic, bitis = parca.split("-", 1)
            try:
                b = int(baslangic.strip())
                s = int(bitis.strip())
                if b < 1 or s > 65535 or b > s:
                    raise ValueError(f"geçersiz port aralığı: {parca}")
                portlar.update(range(b, s + 1))
            except ValueError:
                raise ValueError(f"geçersiz port aralığı: {parca}")
        else:
            try:
                port = int(parca)
                if port < 1 or port > 65535:
                    raise ValueError(f"geçersiz port numarası: {port}")
                portlar.add(port)
            except ValueError:
                raise ValueError(f"geçersiz port ifadesi: {parca}")
    return sorted(portlar)
