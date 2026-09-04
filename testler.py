#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious kapsamli test scripti - tum modulleri detayli test eder
"""

import sys
import os

# test sayaclari
toplam_test = 0
basarili_test = 0
basarisiz_test = 0
hatalar = []


def test_baslat(test_adi):
    """test baslatma mesaji"""
    global toplam_test
    toplam_test += 1
    print(f"  [{toplam_test:03d}] {test_adi}...", end=" ")


def test_basarili():
    """test basari mesaji"""
    global basarili_test
    basarili_test += 1
    print("GECTI")


def test_basarisiz(hata_mesaji):
    """test basarisizlik mesaji"""
    global basarisiz_test
    basarisiz_test += 1
    hatalar.append(f"[{toplam_test:03d}] {hata_mesaji}")
    print(f"BASARISIZ - {hata_mesaji}")


def bolum_baslik(baslik):
    """test bolumu basligi"""
    print(f"\n{'='*60}")
    print(f"  {baslik}")
    print(f"{'='*60}")


# ========================================
# bolum 1: import testleri
# ========================================
bolum_baslik("BOLUM 1: IMPORT TESTLERI")

test_baslat("cekirdek paketi import")
try:
    import cekirdek
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cekirdek.gunluk import")
try:
    from cekirdek.gunluk import Gunluk
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cekirdek.baglanti import")
try:
    from cekirdek.baglanti import BaglantiYoneticisi, BaglantiHatasi
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cekirdek.yardimcilar import")
try:
    from cekirdek.yardimcilar import (
        desen_olustur, desen_bul, kotu_karakter_olustur,
        hex_goster, adres_pakitle, msfvenom_onerisi, payload_dosyadan_oku
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("moduller paketi import")
try:
    import moduller
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("moduller.fuzzer import")
try:
    from moduller.fuzzer import fuzzing_baslat, DESTEKLENEN_KOMUTLAR
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("moduller.offset_bulucu import")
try:
    from moduller.offset_bulucu import offset_tespiti_baslat, offset_hesapla
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("moduller.karakter_analiz import")
try:
    from moduller.karakter_analiz import karakter_analizi_baslat
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("moduller.istismarci import")
try:
    from moduller.istismarci import istismar_baslat
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 2: desen ureteci testleri
# ========================================
bolum_baslik("BOLUM 2: DESEN URETECI TESTLERI")

test_baslat("desen_olustur(0) bos desen")
try:
    d = desen_olustur(0)
    assert d == "", f"beklenen: '', alinan: '{d}'"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_olustur(1) tek karakter")
try:
    d = desen_olustur(1)
    assert d == "A", f"beklenen: 'A', alinan: '{d}'"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_olustur(3) ilk uclu")
try:
    d = desen_olustur(3)
    assert d == "Aa0", f"beklenen: 'Aa0', alinan: '{d}'"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_olustur(20) kisa desen")
try:
    d = desen_olustur(20)
    assert len(d) == 20, f"beklenen uzunluk: 20, alinan: {len(d)}"
    assert d == "Aa0Aa1Aa2Aa3Aa4Aa5Aa", f"yanlis desen: {d}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_olustur(3000) uzun desen uzunlugu")
try:
    d = desen_olustur(3000)
    assert len(d) == 3000, f"beklenen: 3000, alinan: {len(d)}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_olustur(3000) benzersizlik kontrolu")
try:
    d = desen_olustur(3000)
    # her 4 byte'lik alt dizi benzersiz olmali
    alt_diziler = set()
    tekrar_var = False
    for i in range(len(d) - 3):
        alt = d[i:i+4]
        if alt in alt_diziler:
            tekrar_var = True
            break
        alt_diziler.add(alt)
    assert not tekrar_var, "4 byte'lik tekrar bulundu"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_olustur metasploit uyumlulugu")
try:
    d = desen_olustur(100)
    # metasploit ile ayni baslangic
    assert d.startswith("Aa0Aa1Aa2Aa3"), f"metasploit uyumsuz: {d[:20]}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 3: desen bulma (offset) testleri
# ========================================
bolum_baslik("BOLUM 3: DESEN BULMA (OFFSET) TESTLERI")

test_baslat("desen_bul(386F4337) offset=2003")
try:
    sonuc = desen_bul("386F4337")
    assert sonuc == 2003, f"beklenen: 2003, alinan: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_bul ilk offset (Aa0A -> 0)")
try:
    d = desen_olustur(100)
    # ilk 4 karakter "aa0a" -> hex: 41613041 -> little endian: 41306141
    sonuc = desen_bul("41306141", d)
    assert sonuc == 0, f"beklenen: 0, alinan: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("desen_bul gecersiz hex hatasi")
try:
    desen_bul("ZZZZ")
    test_basarisiz("ValueError bekleniyor ama alinmadi")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(f"yanlis hata tipi: {type(e).__name__}: {e}")

test_baslat("desen_bul bulunamayan deger hatasi")
try:
    desen_bul("DEADBEEF")
    test_basarisiz("ValueError bekleniyor ama alinmadi")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(f"yanlis hata tipi: {type(e).__name__}: {e}")

test_baslat("desen_bul ozel desen ile")
try:
    d = desen_olustur(500)
    # offset 100'deki 4 byte'i al
    dort_bayt = d[100:104]
    hex_deger = dort_bayt[::-1].encode("ascii").hex()
    sonuc = desen_bul(hex_deger, d)
    assert sonuc == 100, f"beklenen: 100, alinan: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 4: kotu karakter testleri
# ========================================
bolum_baslik("BOLUM 4: KOTU KARAKTER TESTLERI")

test_baslat("kotu_karakter_olustur() varsayilan (null haric)")
try:
    k = kotu_karakter_olustur()
    assert len(k) == 255, f"beklenen: 255, alinan: {len(k)}"
    assert 0x00 not in k, "null byte bulundu"
    assert k[0] == 0x01, f"ilk byte 0x01 olmali, alinan: 0x{k[0]:02x}"
    assert k[-1] == 0xFF, f"son byte 0xff olmali, alinan: 0x{k[-1]:02x}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("kotu_karakter_olustur([0x0a, 0x0d]) spesifik haric")
try:
    k = kotu_karakter_olustur([0x0a, 0x0d])
    assert len(k) == 253, f"beklenen: 253, alinan: {len(k)}"
    assert 0x00 not in k, "null byte bulundu"
    assert 0x0a not in k, "0x0a bulundu"
    assert 0x0d not in k, "0x0d bulundu"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("kotu_karakter_olustur bos liste")
try:
    k = kotu_karakter_olustur([])
    assert len(k) == 255, f"beklenen: 255, alinan: {len(k)}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("kotu_karakter_olustur cok haric")
try:
    haric = list(range(0x00, 0x20))  # ilk 32 byte haric
    k = kotu_karakter_olustur(haric)
    assert len(k) == 256 - 32, f"beklenen: 224, alinan: {len(k)}"
    for b in range(0x00, 0x20):
        assert b not in k, f"0x{b:02x} bulundu"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("kotu_karakter_olustur siralama kontrolu")
try:
    k = kotu_karakter_olustur([0x05])
    # 0x01, 0x02, 0x03, 0x04, 0x06, 0x07... sirasiyla
    assert k[0] == 0x01
    assert k[1] == 0x02
    assert k[2] == 0x03
    assert k[3] == 0x04
    assert k[4] == 0x06  # 0x05 atlanmali
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 5: hex dump testleri
# ========================================
bolum_baslik("BOLUM 5: HEX DUMP TESTLERI")

test_baslat("hex_goster bos veri")
try:
    sonuc = hex_goster(b"")
    assert sonuc == "", f"bos veri icin bos string bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("hex_goster kisa veri")
try:
    sonuc = hex_goster(b"\x41\x42\x43")
    assert "41 42 43" in sonuc, f"hex degerleri bulunamadi: {sonuc}"
    assert "|ABC|" in sonuc, f"ascii kismi bulunamadi: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("hex_goster yazdirilmayan karakter")
try:
    sonuc = hex_goster(b"\x00\x01\x7f\xff")
    assert "|....|" in sonuc, f"noktalar bekleniyor: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("hex_goster adres baslangici")
try:
    sonuc = hex_goster(b"A" * 20)
    assert sonuc.startswith("00000000"), f"adres baslangici yanlis: {sonuc[:10]}"
    satirlar = sonuc.strip().split("\n")
    assert len(satirlar) == 2, f"2 satir bekleniyor, alinan: {len(satirlar)}"
    assert satirlar[1].startswith("00000010"), f"ikinci satir adresi yanlis"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 6: adres pakitleme testleri
# ========================================
bolum_baslik("BOLUM 6: ADRES PAKITLEME TESTLERI")

test_baslat("adres_pakitle('625011af') little-endian")
try:
    sonuc = adres_pakitle("625011af")
    assert sonuc == b"\xaf\x11\x50\x62", f"yanlis: {sonuc.hex()}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("adres_pakitle('0x625011af') 0x onekli")
try:
    sonuc = adres_pakitle("0x625011af")
    assert sonuc == b"\xaf\x11\x50\x62", f"yanlis: {sonuc.hex()}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("adres_pakitle('DEADBEEF') buyuk harf")
try:
    sonuc = adres_pakitle("DEADBEEF")
    assert sonuc == b"\xef\xbe\xad\xde", f"yanlis: {sonuc.hex()}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("adres_pakitle('00000000') sifir adres")
try:
    sonuc = adres_pakitle("00000000")
    assert sonuc == b"\x00\x00\x00\x00", f"yanlis: {sonuc.hex()}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("adres_pakitle('FFFFFFFF') max adres")
try:
    sonuc = adres_pakitle("FFFFFFFF")
    assert sonuc == b"\xff\xff\xff\xff", f"yanlis: {sonuc.hex()}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("adres_pakitle gecersiz hex hatasi")
try:
    adres_pakitle("XYZZ1234")
    test_basarisiz("ValueError bekleniyor")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(f"yanlis hata: {e}")

test_baslat("adres_pakitle 32-bit sinir asimi hatasi")
try:
    adres_pakitle("1FFFFFFFF")
    test_basarisiz("ValueError bekleniyor")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(f"yanlis hata: {e}")


# ========================================
# bolum 7: msfvenom onerisi testleri
# ========================================
bolum_baslik("BOLUM 7: MSFVENOM ONERISI TESTLERI")

test_baslat("msfvenom_onerisi windows varsayilan")
try:
    sonuc = msfvenom_onerisi("10.0.2.5")
    assert "windows/shell_reverse_tcp" in sonuc
    assert "LHOST=10.0.2.5" in sonuc
    assert "LPORT=4444" in sonuc
    assert "-f python" in sonuc
    assert "EXITFUNC=thread" in sonuc
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("msfvenom_onerisi linux platform")
try:
    sonuc = msfvenom_onerisi("10.0.2.5", platform="linux")
    assert "linux/x86/shell_reverse_tcp" in sonuc
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("msfvenom_onerisi ozel port")
try:
    sonuc = msfvenom_onerisi("10.0.2.5", yerel_port=5555)
    assert "LPORT=5555" in sonuc
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 8: baglanti yoneticisi testleri
# ========================================
bolum_baslik("BOLUM 8: BAGLANTI YONETICISI TESTLERI")

test_baslat("BaglantiYoneticisi olusturma")
try:
    g = Gunluk(renkli=False)
    by = BaglantiYoneticisi("127.0.0.1", 9999, gunluk=g)
    assert by.hedef_bilgisi == "127.0.0.1:9999"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi repr")
try:
    by = BaglantiYoneticisi("10.0.2.4", 9999)
    r = repr(by)
    assert "10.0.2.4:9999" in r
    assert "bagli degil" in r
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi erisilemeyen hedefe baglanma")
try:
    g = Gunluk(renkli=False)
    by = BaglantiYoneticisi("192.0.2.1", 1, zaman_asimi=1.0, gunluk=g)
    sonuc = by.baglan()
    assert sonuc == False, "erisilemeyen hedefe baglanma basarili olmamali"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi gonder soket yok")
try:
    g = Gunluk(renkli=False)
    by = BaglantiYoneticisi("127.0.0.1", 9999, gunluk=g)
    sonuc = by.gonder(b"test")
    assert sonuc == False, "soketsiz gonderim basarisiz olmali"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi al soket yok")
try:
    by = BaglantiYoneticisi("127.0.0.1", 9999)
    sonuc = by.al()
    assert sonuc is None, "soketsiz alma none donmeli"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi hedef_eriselebilir_mi (kapali port)")
try:
    by = BaglantiYoneticisi("127.0.0.1", 1)
    sonuc = by.hedef_eriselebilir_mi()
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi kapat guvenli (soket yok)")
try:
    by = BaglantiYoneticisi("127.0.0.1", 9999)
    by.kapat()  # hata vermemeli
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiHatasi istisna sinifi")
try:
    raise BaglantiHatasi("test hatasi")
except BaglantiHatasi as e:
    assert str(e) == "test hatasi"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("BaglantiYoneticisi context manager (basarisiz baglanti)")
try:
    g = Gunluk(renkli=False)
    by = BaglantiYoneticisi("192.0.2.1", 1, zaman_asimi=1.0, gunluk=g)
    try:
        with by:
            pass
        test_basarisiz("BaglantiHatasi bekleniyor")
    except BaglantiHatasi:
        test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 9: gunluk (loglama) testleri
# ========================================
bolum_baslik("BOLUM 9: GUNLUK (LOGLAMA) TESTLERI")

test_baslat("Gunluk olusturma varsayilan")
try:
    g = Gunluk(renkli=False)
    assert g._seviye == Gunluk.BILGI
    assert g._renkli == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("Gunluk seviye filtreleme")
try:
    g = Gunluk(seviye=Gunluk.HATA, renkli=False)
    # bilgi ve uyari mesajlari goruntulenmemeli ama hata atilmamali
    g.bilgi("bu gorunmemeli")
    g.uyari("bu da gorunmemeli")
    g.hata("bu gorunmeli")
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("Gunluk dosyaya yazma")
try:
    log_dosya = os.path.join(os.path.dirname(__file__), "__test_log.tmp")
    g = Gunluk(renkli=False, dosya_yolu=log_dosya)
    g.bilgi("test mesaji")
    del g  # dosya kapatilir
    with open(log_dosya, "r", encoding="utf-8") as f:
        icerik = f.read()
    assert "test mesaji" in icerik, f"log dosyasinda mesaj bulunamadi: {icerik}"
    os.remove(log_dosya)
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))
    try:
        os.remove(log_dosya)
    except:
        pass

test_baslat("Gunluk tum log metodlari hatasiz calisir")
try:
    g = Gunluk(seviye=Gunluk.AYIKLAMA, renkli=False)
    g.bilgi("bilgi")
    g.basari("basari")
    g.uyari("uyari")
    g.hata("hata")
    g.kritik("kritik")
    g.ayiklama("ayiklama")
    g.bos_satir()
    g.ayirici()
    g.baslik("test basligi")
    g.banner()
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 10: desteklenen komutlar testleri
# ========================================
bolum_baslik("BOLUM 10: DESTEKLENEN KOMUTLAR TESTLERI")

test_baslat("DESTEKLENEN_KOMUTLAR listesi bos degil")
try:
    assert len(DESTEKLENEN_KOMUTLAR) > 0
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("TRUN desteklenen komutlarda")
try:
    assert "TRUN" in DESTEKLENEN_KOMUTLAR
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("GMON desteklenen komutlarda")
try:
    assert "GMON" in DESTEKLENEN_KOMUTLAR
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 11: payload dosya okuma testleri
# ========================================
bolum_baslik("BOLUM 11: PAYLOAD DOSYA OKUMA TESTLERI")

test_baslat("payload_dosyadan_oku raw binary")
try:
    test_dosya = os.path.join(os.path.dirname(__file__), "__test_payload.bin")
    with open(test_dosya, "wb") as f:
        f.write(b"\x90\x90\x90\xcc")
    sonuc = payload_dosyadan_oku(test_dosya)
    assert sonuc == b"\x90\x90\x90\xcc", f"yanlis: {sonuc.hex()}"
    os.remove(test_dosya)
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))
    try:
        os.remove(test_dosya)
    except:
        pass

test_baslat("payload_dosyadan_oku python format")
try:
    test_dosya = os.path.join(os.path.dirname(__file__), "__test_payload.py")
    with open(test_dosya, "w") as f:
        f.write('buf =  ""\n')
        f.write('buf += "\\x90\\x90\\x90\\xcc"\n')
    sonuc = payload_dosyadan_oku(test_dosya)
    assert sonuc == b"\x90\x90\x90\xcc", f"yanlis: {sonuc.hex()}"
    os.remove(test_dosya)
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))
    try:
        os.remove(test_dosya)
    except:
        pass

test_baslat("payload_dosyadan_oku dosya bulunamadi hatasi")
try:
    payload_dosyadan_oku("olmayan_dosya.bin")
    test_basarisiz("FileNotFoundError bekleniyor")
except FileNotFoundError:
    test_basarili()
except Exception as e:
    test_basarisiz(f"yanlis hata: {type(e).__name__}: {e}")


# ========================================
# bolum 12: entegrasyon testleri
# ========================================
bolum_baslik("BOLUM 12: ENTEGRASYON TESTLERI")

test_baslat("tam exploit payload olusturma")
try:
    offset = 2003
    jmp_adresi = adres_pakitle("625011af")
    kotu_kar = kotu_karakter_olustur([0x00])
    desen = desen_olustur(3000)

    dolgu = b"A" * offset
    nop_sled = b"\x90" * 32
    shellcode = b"\xcc" * 4

    payload = b"TRUN /.:/:" + dolgu + jmp_adresi + nop_sled + shellcode
    assert len(payload) > 2000
    assert jmp_adresi == b"\xaf\x11\x50\x62"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("offset -> kotu karakter -> exploit pipeline")
try:
    # 1. desen uret ve offset bul
    desen = desen_olustur(3000)
    offset = desen_bul("386F4337", desen)
    assert offset == 2003

    # 2. kotu karakter olustur
    kotu = kotu_karakter_olustur([0x00])
    assert len(kotu) == 255

    # 3. adres pakitle
    adres = adres_pakitle("625011af")
    assert len(adres) == 4

    # 4. msfvenom onerisi
    oneri = msfvenom_onerisi("10.0.2.5")
    assert "msfvenom" in oneri

    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 13: ag yardimcilar testleri
# ========================================
bolum_baslik("BOLUM 13: AG YARDIMCILAR TESTLERI")

test_baslat("ag_yardimcilar import")
try:
    from cekirdek.ag_yardimcilar import (
        yerel_ip_bul, subnet_hesapla, ip_gecerli_mi,
        cidr_gecerli_mi, cidr_ayikla, arp_paketi_olustur,
        varsayilan_subnet_bul, ag_arayuzleri_listele,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("ip_gecerli_mi gecerli adresler")
try:
    assert ip_gecerli_mi("192.168.1.1") == True
    assert ip_gecerli_mi("10.0.0.1") == True
    assert ip_gecerli_mi("255.255.255.255") == True
    assert ip_gecerli_mi("0.0.0.0") == True
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("ip_gecerli_mi gecersiz adresler")
try:
    assert ip_gecerli_mi("999.999.999.999") == False
    assert ip_gecerli_mi("abc.def.ghi.jkl") == False
    assert ip_gecerli_mi("") == False
    assert ip_gecerli_mi("192.168.1") == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cidr_gecerli_mi gecerli notasyonlar")
try:
    assert cidr_gecerli_mi("192.168.1.0/24") == True
    assert cidr_gecerli_mi("10.0.0.0/8") == True
    assert cidr_gecerli_mi("172.16.0.0/16") == True
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cidr_gecerli_mi gecersiz notasyonlar")
try:
    assert cidr_gecerli_mi("192.168.1.0/33") == False
    assert cidr_gecerli_mi("abc/24") == False
    assert cidr_gecerli_mi("") == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("subnet_hesapla /24 subnet")
try:
    hostlar = subnet_hesapla("192.168.1.0", 24)
    assert len(hostlar) == 254, f"beklenen: 254, alinan: {len(hostlar)}"
    assert hostlar[0] == "192.168.1.1"
    assert hostlar[-1] == "192.168.1.254"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("subnet_hesapla /30 subnet")
try:
    hostlar = subnet_hesapla("192.168.1.0", 30)
    assert len(hostlar) == 2, f"beklenen: 2, alinan: {len(hostlar)}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cidr_ayikla gecerli")
try:
    ip, prefix = cidr_ayikla("192.168.1.0/24")
    assert ip == "192.168.1.0"
    assert prefix == 24
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("cidr_ayikla gecersiz hata")
try:
    cidr_ayikla("invalid/99")
    test_basarisiz("ValueError bekleniyor")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("arp_paketi_olustur boyut kontrolu")
try:
    paket = arp_paketi_olustur("192.168.1.1", "192.168.1.100", "aa:bb:cc:dd:ee:ff")
    assert len(paket) == 42, f"beklenen: 42 byte, alinan: {len(paket)}"
    # ethernet header 14 + arp header 28 = 42
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("yerel_ip_bul fonksiyonu")
try:
    ip = yerel_ip_bul()
    assert ip_gecerli_mi(ip), f"gecersiz ip dondu: {ip}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 14: port tarayici testleri
# ========================================
bolum_baslik("BOLUM 14: PORT TARAYICI TESTLERI")

test_baslat("port_tarayici import")
try:
    from moduller.port_tarayici import (
        port_taramasi_baslat, port_araligi_ayikla,
        _port_listesi_olustur, _tcp_connect_tara,
        PROFIL_HIZLI, PROFIL_TAM,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("PROFIL_HIZLI 100 port icermeli")
try:
    assert len(PROFIL_HIZLI) == 100, f"beklenen: 100, alinan: {len(PROFIL_HIZLI)}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("PROFIL_TAM PROFIL_HIZLI icermeli")
try:
    for p in PROFIL_HIZLI:
        assert p in PROFIL_TAM, f"port {p} tam profilde yok"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_araligi_ayikla virgullu")
try:
    sonuc = port_araligi_ayikla("22,80,443")
    assert sonuc == [22, 80, 443], f"yanlis: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_araligi_ayikla aralikli")
try:
    sonuc = port_araligi_ayikla("1-5")
    assert sonuc == [1, 2, 3, 4, 5], f"yanlis: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_araligi_ayikla karisik")
try:
    sonuc = port_araligi_ayikla("22,80,100-102")
    assert sonuc == [22, 80, 100, 101, 102], f"yanlis: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_araligi_ayikla gecersiz hata")
try:
    port_araligi_ayikla("abc")
    test_basarisiz("ValueError bekleniyor")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_araligi_ayikla sinir asimi hatasi")
try:
    port_araligi_ayikla("0")
    test_basarisiz("ValueError bekleniyor")
except ValueError:
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_port_listesi_olustur hizli profil")
try:
    sonuc = _port_listesi_olustur("hizli")
    assert len(sonuc) == 100
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_port_listesi_olustur ozel portlar")
try:
    sonuc = _port_listesi_olustur("hizli", [22, 80])
    assert sonuc == [22, 80]
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_tcp_connect_tara kapali port")
try:
    sonuc = _tcp_connect_tara("127.0.0.1", 1, 0.5)
    assert sonuc is None, "kapali port icin None bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_taramasi_baslat gecersiz ip")
try:
    g = Gunluk(renkli=False)
    sonuc = port_taramasi_baslat("999.999.999.999", gunluk=g)
    assert sonuc == [], "gecersiz ip icin bos liste bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 15: servis tanimlayici testleri
# ========================================
bolum_baslik("BOLUM 15: SERVIS TANIMLAYICI TESTLERI")

test_baslat("servis_tanımlayici import")
try:
    from moduller.servis_tanımlayici import (
        servis_tespiti_baslat, _servis_eslesitir,
        _versiyon_ayikla,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("servis_eslesitir OpenSSH banner")
try:
    s, v = _servis_eslesitir("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22)
    assert s == "openssh", f"beklenen: openssh, alinan: {s}"
    assert v == "8.9p1", f"beklenen: 8.9p1, alinan: {v}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("servis_eslesitir vsftpd banner")
try:
    s, v = _servis_eslesitir("220 (vsFTPd 2.3.4)", 21)
    assert s == "vsftpd", f"beklenen: vsftpd, alinan: {s}"
    assert v == "2.3.4", f"beklenen: 2.3.4, alinan: {v}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("servis_eslesitir VulnServer banner")
try:
    s, v = _servis_eslesitir("Welcome to Vulnerable Server! Enter HELP for help.", 9999)
    assert s == "vulnserver", f"beklenen: vulnserver, alinan: {s}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("servis_eslesitir bilinmeyen banner")
try:
    s, v = _servis_eslesitir("totally unknown service xyz", 12345)
    assert s is None, f"bilinmeyen banner icin None bekleniyor, alinan: {s}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("versiyon_ayikla standart versiyon")
try:
    assert _versiyon_ayikla("Apache/2.4.49 (Ubuntu)") == "2.4.49"
    assert _versiyon_ayikla("nginx/1.22.0") == "1.22.0"
    assert _versiyon_ayikla("OpenSSH_8.9p1") == "8.9p1"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("versiyon_ayikla versiyon yok")
try:
    sonuc = _versiyon_ayikla("no version here")
    assert sonuc is None, f"None bekleniyor, alinan: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("servis_tespiti_baslat gecersiz ip")
try:
    g = Gunluk(renkli=False)
    sonuc = servis_tespiti_baslat("999.999.999.999", gunluk=g)
    assert sonuc == [], "gecersiz ip icin bos liste bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 16: raporlayici testleri
# ========================================
bolum_baslik("BOLUM 16: RAPORLAYICI TESTLERI")

test_baslat("raporlayici import")
try:
    from moduller.raporlayici import (
        rapor_olustur, TaramaSonucu, HostBilgisi, PortBilgisi,
        _json_rapor, _metin_rapor,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("TaramaSonucu dataclass olusturma")
try:
    ts = TaramaSonucu(subnet="192.168.1.0/24", aktif_host=3)
    assert ts.subnet == "192.168.1.0/24"
    assert ts.aktif_host == 3
    assert ts.hostlar == []
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("json rapor ciktisi")
try:
    import json
    pb = PortBilgisi(port=22, servis="ssh", versiyon="OpenSSH 8.9")
    hb = HostBilgisi(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", acik_portlar=[pb])
    ts = TaramaSonucu(subnet="192.168.1.0/24", aktif_host=1, hostlar=[hb])
    rapor = _json_rapor(ts)
    veri = json.loads(rapor)
    assert "rapor" in veri
    assert veri["rapor"]["aktif_host"] == 1
    assert len(veri["rapor"]["hostlar"]) == 1
    assert veri["rapor"]["hostlar"][0]["ip"] == "192.168.1.10"
    assert veri["rapor"]["hostlar"][0]["acik_portlar"][0]["port"] == 22
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("metin rapor ciktisi")
try:
    pb = PortBilgisi(port=80, servis="http")
    hb = HostBilgisi(ip="10.0.0.1", acik_portlar=[pb])
    ts = TaramaSonucu(subnet="10.0.0.0/24", aktif_host=1, hostlar=[hb])
    rapor = _metin_rapor(ts)
    assert "10.0.0.1" in rapor
    assert "http" in rapor
    assert "ÖZET" in rapor
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 17: zafiyet veritabani testleri
# ========================================
bolum_baslik("BOLUM 17: ZAFIYET VERITABANI TESTLERI")

test_baslat("zafiyet_veritabani import")
try:
    from zafiyet_veritabani import (
        zafiyet_ara, port_servis_adi, tum_zafiyetleri_listele,
        ZAFIYET_VERITABANI, PORT_SERVIS_ESLESTIRME,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_servis_adi bilinen portlar")
try:
    assert port_servis_adi(22) == "ssh"
    assert port_servis_adi(80) == "http"
    assert port_servis_adi(443) == "https"
    assert port_servis_adi(9999) == "vulnserver"
    assert port_servis_adi(3306) == "mysql"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("port_servis_adi bilinmeyen port")
try:
    assert port_servis_adi(99999) == "bilinmiyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("zafiyet_ara vsftpd 2.3.4 kritik")
try:
    sonuc = zafiyet_ara("vsftpd", "2.3.4")
    assert sonuc is not None, "vsftpd 2.3.4 zafiyeti bulunamadi"
    assert sonuc["risk"] == "kritik"
    assert any("CVE-2011-2523" in z for z in sonuc["zafiyetler"])
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("zafiyet_ara apache 2.4.49 kritik")
try:
    sonuc = zafiyet_ara("apache", "2.4.49")
    assert sonuc is not None
    assert sonuc["risk"] == "kritik"
    assert any("CVE-2021-41773" in z for z in sonuc["zafiyetler"])
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("zafiyet_ara bilinmeyen servis None donmeli")
try:
    sonuc = zafiyet_ara("bilinmeyen_servis", "1.0")
    assert sonuc is None, f"None bekleniyor, alinan: {sonuc}"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("tum_zafiyetleri_listele bos degil")
try:
    tumu = tum_zafiyetleri_listele()
    assert len(tumu) > 0, "zafiyet listesi bos"
    # her eleman (servis, versiyon, bilgi) tuple olmali
    for servis, versiyon, bilgi in tumu:
        assert isinstance(servis, str)
        assert isinstance(versiyon, str)
        assert "zafiyetler" in bilgi
        assert "risk" in bilgi
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("ZAFIYET_VERITABANI vulnserver icermeli")
try:
    assert "vulnserver" in ZAFIYET_VERITABANI
    assert "1.0" in ZAFIYET_VERITABANI["vulnserver"]
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 18: saldiri verileri testleri
# ========================================
bolum_baslik("BOLUM 18: SALDIRI VERILERI TESTLERI")

test_baslat("saldiri_verileri import")
try:
    from saldiri_verileri import (
        YAYGIN_KULLANICILAR, YAYGIN_PAROLALAR,
        YAYGIN_DIZINLER, PATH_TRAVERSAL_PAYLOADLARI,
        HTTP_USER_AGENTS,
        kullanici_listesi_yukle, parola_listesi_yukle,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("YAYGIN_KULLANICILAR en az 50 kayit")
try:
    assert len(YAYGIN_KULLANICILAR) >= 50, f"beklenen: >=50, alinan: {len(YAYGIN_KULLANICILAR)}"
    assert "root" in YAYGIN_KULLANICILAR
    assert "admin" in YAYGIN_KULLANICILAR
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("YAYGIN_PAROLALAR en az 100 kayit")
try:
    assert len(YAYGIN_PAROLALAR) >= 100, f"beklenen: >=100, alinan: {len(YAYGIN_PAROLALAR)}"
    assert "123456" in YAYGIN_PAROLALAR
    assert "admin" in YAYGIN_PAROLALAR
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("YAYGIN_DIZINLER /admin icermeli")
try:
    assert "/admin" in YAYGIN_DIZINLER
    assert "/login" in YAYGIN_DIZINLER
    assert "/.env" in YAYGIN_DIZINLER
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("PATH_TRAVERSAL_PAYLOADLARI bos degil")
try:
    assert len(PATH_TRAVERSAL_PAYLOADLARI) > 0
    assert any("etc/passwd" in p for p in PATH_TRAVERSAL_PAYLOADLARI)
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("kullanici_listesi_yukle gomulu liste")
try:
    liste = kullanici_listesi_yukle(None)
    assert len(liste) >= 50
    assert "root" in liste
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("parola_listesi_yukle gomulu liste")
try:
    liste = parola_listesi_yukle(None)
    assert len(liste) >= 100
    assert "password" in liste
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("kullanici_listesi_yukle dosya bulunamadi hatasi")
try:
    kullanici_listesi_yukle("/olmayan/dosya.txt")
    test_basarisiz("FileNotFoundError bekleniyor")
except FileNotFoundError:
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("HTTP_USER_AGENTS bos degil")
try:
    assert len(HTTP_USER_AGENTS) > 0
    assert any("Noxious" in ua for ua in HTTP_USER_AGENTS)
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 19: brute force testleri
# ========================================
bolum_baslik("BOLUM 19: BRUTE FORCE TESTLERI")

test_baslat("brute_force import")
try:
    from moduller.brute_force import (
        bruteforce_baslat, _ftp_dene, _ssh_dene,
        _telnet_dene, _http_basic_dene, _port_acik_mi,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("bruteforce_baslat gecersiz ip")
try:
    g = Gunluk(renkli=False)
    sonuc = bruteforce_baslat("999.999.999.999", gunluk=g)
    assert sonuc == [], "gecersiz ip icin bos liste bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("bruteforce_baslat desteklenmeyen servis")
try:
    g = Gunluk(renkli=False)
    sonuc = bruteforce_baslat("192.168.1.1", servis="bilinmeyen", gunluk=g)
    assert sonuc == []
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_ftp_dene erisilemeyen hedef")
try:
    sonuc = _ftp_dene("192.0.2.1", 21, "test", "test", 1.0)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_ssh_dene erisilemeyen hedef")
try:
    sonuc = _ssh_dene("192.0.2.1", 22, "test", "test", 1.0)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_telnet_dene erisilemeyen hedef")
try:
    sonuc = _telnet_dene("192.0.2.1", 23, "test", "test", 1.0)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_http_basic_dene erisilemeyen hedef")
try:
    sonuc = _http_basic_dene("192.0.2.1", 80, "/", "test", "test", 1.0)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_port_acik_mi kapali port")
try:
    sonuc = _port_acik_mi("127.0.0.1", 1, 0.5)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 20: ag saldiri testleri
# ========================================
bolum_baslik("BOLUM 20: AG SALDIRI TESTLERI")

test_baslat("ag_saldiri import")
try:
    from moduller.ag_saldiri import (
        saldiri_baslat, _vsftpd_backdoor, _ftp_anonim_giris,
        _apache_path_traversal, _http_dizin_tarama,
        _vulnserver_tespiti,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("saldiri_baslat gecersiz ip")
try:
    g = Gunluk(renkli=False)
    sonuc = saldiri_baslat("999.999.999.999", gunluk=g)
    assert sonuc == [], "gecersiz ip icin bos liste bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_vsftpd_backdoor erisilemeyen hedef")
try:
    g = Gunluk(renkli=False)
    sonuc = _vsftpd_backdoor("192.0.2.1", 1.0, g)
    assert sonuc["basarili"] == False
    assert sonuc["exploit"] == "vsftpd-2.3.4-backdoor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_ftp_anonim_giris erisilemeyen hedef")
try:
    g = Gunluk(renkli=False)
    sonuc = _ftp_anonim_giris("192.0.2.1", 21, 1.0, g)
    assert sonuc["basarili"] == False
    assert sonuc["exploit"] == "ftp-anonymous"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_apache_path_traversal erisilemeyen hedef")
try:
    g = Gunluk(renkli=False)
    sonuc = _apache_path_traversal("192.0.2.1", 80, 1.0, g)
    assert sonuc["basarili"] == False
    assert sonuc["exploit"] == "apache-path-traversal"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_vulnserver_tespiti erisilemeyen hedef")
try:
    g = Gunluk(renkli=False)
    sonuc = _vulnserver_tespiti("192.0.2.1", 9999, 1.0, g)
    assert sonuc["basarili"] == False
    assert sonuc["exploit"] == "vulnserver-detect"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("saldiri sonuc yapisi dogru")
try:
    g = Gunluk(renkli=False)
    sonuc = _ftp_anonim_giris("192.0.2.1", 21, 0.5, g)
    assert "exploit" in sonuc
    assert "hedef" in sonuc
    assert "basarili" in sonuc
    assert "detay" in sonuc
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# bolum 21: arp spoof testleri
# ========================================
bolum_baslik("BOLUM 21: ARP SPOOF TESTLERI")

test_baslat("arp_spoof import")
try:
    from moduller.arp_spoof import (
        arp_spoof_baslat, _root_mu, _arp_tablosundan_bul,
        _ip_forwarding_ayarla, _sahte_arp_gonder,
    )
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("arp_spoof_baslat gecersiz hedef ip")
try:
    g = Gunluk(renkli=False)
    sonuc = arp_spoof_baslat("999.999.999.999", "192.168.1.1", gunluk=g)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("arp_spoof_baslat gecersiz gateway ip")
try:
    g = Gunluk(renkli=False)
    sonuc = arp_spoof_baslat("192.168.1.10", "abc.def.ghi.jkl", gunluk=g)
    assert sonuc == False
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_root_mu fonksiyonu bool donmeli")
try:
    sonuc = _root_mu()
    assert isinstance(sonuc, bool)
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("arp_spoof_baslat root olmadan hata")
try:
    if not _root_mu():
        g = Gunluk(renkli=False)
        sonuc = arp_spoof_baslat("192.168.1.10", "192.168.1.1", gunluk=g)
        assert sonuc == False, "root olmadan False donmeli"
        test_basarili()
    else:
        # root ise bu testi atla
        test_basarili()
except Exception as e:
    test_basarisiz(str(e))

test_baslat("_arp_tablosundan_bul olmayan ip")
try:
    sonuc = _arp_tablosundan_bul("192.0.2.254")
    assert sonuc is None, "olmayan ip icin None bekleniyor"
    test_basarili()
except Exception as e:
    test_basarisiz(str(e))


# ========================================
# sonuc raporu
# ========================================
print(f"\n{'='*60}")
print(f"  TEST SONUCLARI")
print(f"{'='*60}")
print(f"  Toplam  : {toplam_test}")
print(f"  Basarili: {basarili_test}")
print(f"  Basarisiz: {basarisiz_test}")
print(f"{'='*60}")

if hatalar:
    print(f"\n  BASARISIZ TESTLER:")
    for h in hatalar:
        print(f"    {h}")

if basarisiz_test == 0:
    print(f"\n  TUM TESTLER BASARIYLA GECTI!")
    sys.exit(0)
else:
    print(f"\n  {basarisiz_test} TEST BASARISIZ!")
    sys.exit(1)
