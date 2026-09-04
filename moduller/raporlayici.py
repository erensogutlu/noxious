#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious raporlayıcı modülü - tarama sonuçlarını yapılandırılmış formatta sunar

çıktı formatları:
    - terminal (varsayılan): renkli tablo formatı
    - json: makine okunabilir çıktı
    - metin dosyası: dosyaya kayıt
"""

import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from datetime import datetime

from cekirdek.gunluk import Gunluk


@dataclass
class PortBilgisi:
    """tek bir portun tarama sonucu"""
    port: int
    protokol: str = "tcp"
    durum: str = "açık"
    servis: Optional[str] = None
    versiyon: Optional[str] = None
    banner: Optional[str] = None
    zafiyetler: List[str] = field(default_factory=list)


@dataclass
class HostBilgisi:
    """tek bir host'un tarama sonucu"""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    acik_portlar: List[PortBilgisi] = field(default_factory=list)
    isletim_sistemi: Optional[str] = None


@dataclass
class TaramaSonucu:
    """tam tarama raporu"""
    subnet: str = ""
    baslangic_zamani: str = ""
    bitis_zamani: str = ""
    tarama_suresi: float = 0.0
    toplam_host: int = 0
    aktif_host: int = 0
    hostlar: List[HostBilgisi] = field(default_factory=list)


def rapor_olustur(tarama_sonucu, format_tipi="terminal", cikti_dosyasi=None, gunluk=None):
    """
    tarama sonuçlarını belirtilen formatta raporlar

    parametreler:
        tarama_sonucu: TaramaSonucu dataclass nesnesi
        format_tipi: çıktı formatı ("terminal", "json", "metin")
        cikti_dosyasi: dosyaya kayıt yolu (none ise sadece terminal)
        gunluk: loglama nesnesi

    döndürür:
        rapor stringi
    """
    if gunluk is None:
        gunluk = Gunluk()

    if format_tipi == "json":
        rapor = _json_rapor(tarama_sonucu)
    elif format_tipi == "metin":
        rapor = _metin_rapor(tarama_sonucu)
    else:
        rapor = _terminal_rapor(tarama_sonucu, gunluk)

    # dosyaya kayıt
    if cikti_dosyasi:
        try:
            with open(cikti_dosyasi, "w", encoding="utf-8") as f:
                if format_tipi == "json":
                    f.write(rapor)
                else:
                    f.write(rapor)
            gunluk.basari(f"rapor kaydedildi: {cikti_dosyasi}")
        except OSError as hata:
            gunluk.hata(f"rapor dosyası yazılamadı: {hata}")

    return rapor


def _terminal_rapor(sonuc, gunluk):
    """terminal formatında renkli rapor"""
    satirlar = []

    gunluk.baslik("ağ sızma testi raporu")
    gunluk.bilgi(f"subnet          : {sonuc.subnet}")
    gunluk.bilgi(f"tarama süresi   : {sonuc.tarama_suresi:.1f} saniye")
    gunluk.bilgi(f"toplam host     : {sonuc.toplam_host}")
    gunluk.bilgi(f"aktif host      : {sonuc.aktif_host}")
    gunluk.bos_satir()

    toplam_zafiyet = 0

    for host in sonuc.hostlar:
        gunluk.ayirici(karakter="═", uzunluk=60)
        mac_str = host.mac or "bilinmiyor"
        gunluk.basari(f"HOST: {host.ip}  ({mac_str})")

        if host.acik_portlar:
            gunluk.bilgi(f"  {'PORT':<10}{'SERVİS':<16}{'VERSİYON':<25}")
            gunluk.ayirici(karakter="-", uzunluk=55)

            for port in host.acik_portlar:
                servis = port.servis or "bilinmiyor"
                versiyon = port.versiyon or ""
                gunluk.bilgi(f"  {port.port}/{port.protokol:<7}{servis:<16}{versiyon}")

                if port.zafiyetler:
                    for z in port.zafiyetler:
                        toplam_zafiyet += 1
                        gunluk.uyari(f"    ⚠ {z}")
        else:
            gunluk.bilgi("  açık port bulunamadı")

        gunluk.bos_satir()

    # özet
    gunluk.ayirici(karakter="═", uzunluk=60)
    gunluk.baslik("özet")
    gunluk.basari(f"aktif host      : {sonuc.aktif_host}")
    toplam_port = sum(len(h.acik_portlar) for h in sonuc.hostlar)
    gunluk.basari(f"toplam açık port: {toplam_port}")
    if toplam_zafiyet > 0:
        gunluk.uyari(f"tespit edilen zafiyet: {toplam_zafiyet}")
    else:
        gunluk.basari("tespit edilen zafiyet: 0")

    return ""


def _json_rapor(sonuc):
    """json formatında rapor"""
    veri = {
        "rapor": {
            "subnet": sonuc.subnet,
            "baslangic_zamani": sonuc.baslangic_zamani,
            "bitis_zamani": sonuc.bitis_zamani,
            "tarama_suresi": sonuc.tarama_suresi,
            "toplam_host": sonuc.toplam_host,
            "aktif_host": sonuc.aktif_host,
            "hostlar": [],
        }
    }

    for host in sonuc.hostlar:
        host_veri = {
            "ip": host.ip,
            "mac": host.mac,
            "hostname": host.hostname,
            "acik_portlar": [],
        }
        for port in host.acik_portlar:
            host_veri["acik_portlar"].append({
                "port": port.port,
                "protokol": port.protokol,
                "durum": port.durum,
                "servis": port.servis,
                "versiyon": port.versiyon,
                "banner": port.banner,
                "zafiyetler": port.zafiyetler,
            })
        veri["rapor"]["hostlar"].append(host_veri)

    return json.dumps(veri, ensure_ascii=False, indent=2)


def _metin_rapor(sonuc):
    """düz metin formatında rapor"""
    satirlar = [
        "=" * 60,
        "  NOXIOUS — AĞ SIZMA TESTİ RAPORU",
        "=" * 60,
        f"  Subnet          : {sonuc.subnet}",
        f"  Başlangıç       : {sonuc.baslangic_zamani}",
        f"  Bitiş           : {sonuc.bitis_zamani}",
        f"  Tarama Süresi   : {sonuc.tarama_suresi:.1f} saniye",
        f"  Toplam Host     : {sonuc.toplam_host}",
        f"  Aktif Host      : {sonuc.aktif_host}",
        "",
    ]

    for host in sonuc.hostlar:
        satirlar.append("-" * 60)
        mac_str = host.mac or "bilinmiyor"
        satirlar.append(f"  HOST: {host.ip}  (MAC: {mac_str})")
        satirlar.append("")

        if host.acik_portlar:
            satirlar.append(f"  {'PORT':<10}{'SERVİS':<16}{'VERSİYON'}")
            satirlar.append("  " + "-" * 50)

            for port in host.acik_portlar:
                servis = port.servis or "bilinmiyor"
                versiyon = port.versiyon or ""
                satirlar.append(f"  {port.port}/{port.protokol:<7}{servis:<16}{versiyon}")

                for z in port.zafiyetler:
                    satirlar.append(f"    [!] {z}")
        else:
            satirlar.append("  Açık port bulunamadı")

        satirlar.append("")

    # özet
    satirlar.append("=" * 60)
    satirlar.append("  ÖZET")
    satirlar.append("=" * 60)
    toplam_port = sum(len(h.acik_portlar) for h in sonuc.hostlar)
    toplam_zafiyet = sum(len(z) for h in sonuc.hostlar for p in h.acik_portlar for z in [p.zafiyetler])
    satirlar.append(f"  Aktif Host       : {sonuc.aktif_host}")
    satirlar.append(f"  Toplam Açık Port : {toplam_port}")
    satirlar.append(f"  Tespit Edilen Zafiyet: {toplam_zafiyet}")
    satirlar.append("=" * 60)

    return "\n".join(satirlar)
