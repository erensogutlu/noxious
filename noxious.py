#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious - buffer overflow exploit toolkit & ağ sızma testi aracı
ana giriş noktası ve cli arayüzü
"""

import sys
import argparse
import time
from typing import List, Optional
from datetime import datetime

from cekirdek.gunluk import Gunluk
from moduller.fuzzer import fuzzing_baslat, DESTEKLENEN_KOMUTLAR
from moduller.offset_bulucu import offset_tespiti_baslat, offset_hesapla
from moduller.karakter_analiz import karakter_analizi_baslat
from moduller.istismarci import istismar_baslat
from moduller.ag_tarayici import ag_taramasi_baslat
from moduller.port_tarayici import port_taramasi_baslat, port_araligi_ayikla
from moduller.servis_tanımlayici import servis_tespiti_baslat
from moduller.raporlayici import (
    rapor_olustur, TaramaSonucu, HostBilgisi, PortBilgisi,
)
from moduller.brute_force import bruteforce_baslat
from moduller.ag_saldiri import saldiri_baslat
from moduller.arp_spoof import arp_spoof_baslat


def _ana_ayristirici_olustur() -> argparse.ArgumentParser:
    """ana argparse ayrıştırıcısını oluşturur"""
    ayristirici = argparse.ArgumentParser(
        prog="noxious",
        description=(
            "noxious - buffer overflow exploit toolkit & ağ sızma testi aracı\n"
            "vulnserver ve benzeri hedeflere yönelik adım adım exploit geliştirme\n"
            "ve ağ keşfi / port tarama / servis tespiti / zafiyet analizi aracı"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "kullanım örnekleri:\n"
            "  python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999\n"
            "  python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 3000\n"
            "  python3 noxious.py offset --hedef 10.0.2.4 --eip 386F4337\n"
            "  python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003\n"
            "  python3 noxious.py exploit --hedef 10.0.2.4 --jmp-adresi 625011af\n"
            "\n"
            "  python3 noxious.py kesfet\n"
            "  python3 noxious.py kesfet --subnet 192.168.1.0/24\n"
            "  python3 noxious.py portscan --hedef 192.168.1.10\n"
            "  python3 noxious.py servis --hedef 192.168.1.10\n"
            "  python3 noxious.py rapor --subnet 192.168.1.0/24\n"
            "\n"
            "  python3 noxious.py bruteforce --hedef 192.168.1.10 --servis ftp\n"
            "  python3 noxious.py saldiri --hedef 192.168.1.10\n"
            "  python3 noxious.py arpspoof --hedef 192.168.1.10 --gateway 192.168.1.1\n"
        ),
    )

    ayristirici.add_argument(
        "--sessiz",
        action="store_true",
        help="sadece hata ve başarı mesajlarını göster",
    )
    ayristirici.add_argument(
        "--ayiklama",
        action="store_true",
        help="ayıklama (debug) mesajlarını da göster",
    )
    ayristirici.add_argument(
        "--log-dosyasi",
        type=str,
        default=None,
        metavar="DOSYA",
        help="log çıktısını dosyaya kaydet",
    )

    alt_komutlar = ayristirici.add_subparsers(
        dest="modul",
        title="modüller",
        description="kullanılabilir exploit ve ağ tarama aşamaları",
    )

    # --- fuzzing alt komutu ---
    fuzzer_ayristirici = alt_komutlar.add_parser(
        "fuzzing",
        help="hedef servisi artımlı buffer ile fuzzing yaparak çökme noktasını bul",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fuzzer_ayristirici.add_argument(
        "--hedef", required=True, help="hedef ip adresi"
    )
    fuzzer_ayristirici.add_argument(
        "--port", type=int, default=9999, help="hedef port numarası (varsayılan: 9999)"
    )
    fuzzer_ayristirici.add_argument(
        "--komut",
        type=str,
        default="TRUN",
        choices=DESTEKLENEN_KOMUTLAR,
        help="test edilecek vulnserver komutu (varsayılan: TRUN)",
    )
    fuzzer_ayristirici.add_argument(
        "--baslangic",
        type=int,
        default=100,
        metavar="BYTE",
        help="başlangıç tampon boyutu (varsayılan: 100)",
    )
    fuzzer_ayristirici.add_argument(
        "--adim",
        type=int,
        default=100,
        metavar="BYTE",
        help="her adımdaki artış miktarı (varsayılan: 100)",
    )
    fuzzer_ayristirici.add_argument(
        "--maksimum",
        type=int,
        default=10000,
        metavar="BYTE",
        help="maksimum tampon boyutu (varsayılan: 10000)",
    )
    fuzzer_ayristirici.add_argument(
        "--bekleme",
        type=float,
        default=1.0,
        metavar="SANIYE",
        help="gönderimler arası bekleme süresi (varsayılan: 1.0)",
    )
    fuzzer_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=5.0,
        metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 5.0)",
    )

    # --- offset alt komutu ---
    offset_ayristirici = alt_komutlar.add_parser(
        "offset",
        help="eip offset tespiti için döngüsel desen gönder veya offset hesapla",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    offset_ayristirici.add_argument(
        "--hedef", required=True, help="hedef ip adresi"
    )
    offset_ayristirici.add_argument(
        "--port", type=int, default=9999, help="hedef port numarası (varsayılan: 9999)"
    )
    offset_ayristirici.add_argument(
        "--uzunluk",
        type=int,
        default=3000,
        metavar="BYTE",
        help="desen uzunluğu (varsayılan: 3000)",
    )
    offset_ayristirici.add_argument(
        "--komut",
        type=str,
        default="TRUN",
        choices=DESTEKLENEN_KOMUTLAR,
        help="vulnserver komutu (varsayılan: TRUN)",
    )
    offset_ayristirici.add_argument(
        "--eip",
        type=str,
        default=None,
        metavar="HEX",
        help="debugger'dan alınan eip değeri (ör: 386F4337)",
    )
    offset_ayristirici.add_argument(
        "--sadece-hesapla",
        action="store_true",
        help="desen göndermeden sadece offset hesapla",
    )
    offset_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=5.0,
        metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 5.0)",
    )

    # --- karakter alt komutu ---
    karakter_ayristirici = alt_komutlar.add_parser(
        "karakter",
        help="kötü karakter analizi - tüm byte değerlerini test et",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    karakter_ayristirici.add_argument(
        "--hedef", required=True, help="hedef ip adresi"
    )
    karakter_ayristirici.add_argument(
        "--port", type=int, default=9999, help="hedef port numarası (varsayılan: 9999)"
    )
    karakter_ayristirici.add_argument(
        "--offset",
        type=int,
        default=2003,
        help="eip offset değeri (varsayılan: 2003)",
    )
    karakter_ayristirici.add_argument(
        "--komut",
        type=str,
        default="TRUN",
        choices=DESTEKLENEN_KOMUTLAR,
        help="vulnserver komutu (varsayılan: TRUN)",
    )
    karakter_ayristirici.add_argument(
        "--haric",
        type=str,
        default=None,
        metavar="HEX_LISTESI",
        help="hariç tutulacak byte'lar, virgülle ayrılmış (ör: 00,0a,0d)",
    )
    karakter_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=5.0,
        metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 5.0)",
    )

    # --- exploit alt komutu ---
    exploit_ayristirici = alt_komutlar.add_parser(
        "exploit",
        help="final exploit - shellcode ile buffer overflow saldırısı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    exploit_ayristirici.add_argument(
        "--hedef", required=True, help="hedef ip adresi"
    )
    exploit_ayristirici.add_argument(
        "--port", type=int, default=9999, help="hedef port numarası (varsayılan: 9999)"
    )
    exploit_ayristirici.add_argument(
        "--offset",
        type=int,
        default=2003,
        help="eip offset değeri (varsayılan: 2003)",
    )
    exploit_ayristirici.add_argument(
        "--jmp-adresi",
        type=str,
        default="625011af",
        metavar="HEX",
        help="jmp esp gadget adresi (varsayılan: 625011af)",
    )
    exploit_ayristirici.add_argument(
        "--shellcode-dosyasi",
        type=str,
        default=None,
        metavar="DOSYA",
        help="shellcode dosya yolu (msfvenom -f python veya raw binary)",
    )
    exploit_ayristirici.add_argument(
        "--nop",
        type=int,
        default=32,
        metavar="BYTE",
        help="nop sled boyutu (varsayılan: 32)",
    )
    exploit_ayristirici.add_argument(
        "--komut",
        type=str,
        default="TRUN",
        choices=DESTEKLENEN_KOMUTLAR,
        help="vulnserver komutu (varsayılan: TRUN)",
    )
    exploit_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=5.0,
        metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 5.0)",
    )

    # --- kesfet alt komutu ---
    kesfet_ayristirici = alt_komutlar.add_parser(
        "kesfet",
        help="aynı ağdaki aktif cihazları keşfet (ARP/ICMP/TCP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    kesfet_ayristirici.add_argument(
        "--subnet",
        type=str,
        default=None,
        metavar="CIDR",
        help="taranacak subnet (ör: 192.168.1.0/24). belirtilmezse otomatik tespit",
    )
    kesfet_ayristirici.add_argument(
        "--yontem",
        type=str,
        default="otomatik",
        choices=["arp", "icmp", "tcp", "otomatik"],
        help="tarama yöntemi (varsayılan: otomatik)",
    )
    kesfet_ayristirici.add_argument(
        "--thread",
        type=int,
        default=50,
        metavar="SAYI",
        help="paralel thread sayısı (varsayılan: 50)",
    )
    kesfet_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=1.0,
        metavar="SANIYE",
        help="host başına zaman aşımı (varsayılan: 1.0)",
    )

    # --- portscan alt komutu ---
    portscan_ayristirici = alt_komutlar.add_parser(
        "portscan",
        help="hedef üzerinde port taraması yap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    portscan_ayristirici.add_argument(
        "--hedef",
        type=str,
        required=True,
        help="hedef ip adresi",
    )
    portscan_ayristirici.add_argument(
        "--portlar",
        type=str,
        default=None,
        metavar="PORT_LISTESI",
        help="özel port listesi (ör: 22,80,443 veya 1-1024)",
    )
    portscan_ayristirici.add_argument(
        "--profil",
        type=str,
        default="hizli",
        choices=["hizli", "tam", "tumu"],
        help="port profili (varsayılan: hizli)",
    )
    portscan_ayristirici.add_argument(
        "--thread",
        type=int,
        default=100,
        metavar="SAYI",
        help="paralel thread sayısı (varsayılan: 100)",
    )
    portscan_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=1.0,
        metavar="SANIYE",
        help="port başına zaman aşımı (varsayılan: 1.0)",
    )

    # --- servis alt komutu ---
    servis_ayristirici = alt_komutlar.add_parser(
        "servis",
        help="açık portlardaki servisleri tanımla ve versiyon tespit et",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    servis_ayristirici.add_argument(
        "--hedef",
        type=str,
        required=True,
        help="hedef ip adresi",
    )
    servis_ayristirici.add_argument(
        "--portlar",
        type=str,
        default=None,
        metavar="PORT_LISTESI",
        help="servis tespiti yapılacak portlar (ör: 22,80,9999)",
    )
    servis_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=3.0,
        metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 3.0)",
    )

    # --- rapor alt komutu ---
    rapor_ayristirici = alt_komutlar.add_parser(
        "rapor",
        help="tam ağ sızma testi raporu (keşfet + portscan + servis birleşik)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    rapor_ayristirici.add_argument(
        "--subnet",
        type=str,
        default=None,
        metavar="CIDR",
        help="taranacak subnet (ör: 192.168.1.0/24)",
    )
    rapor_ayristirici.add_argument(
        "--format",
        type=str,
        default="terminal",
        choices=["terminal", "json", "metin"],
        dest="rapor_format",
        help="rapor formatı (varsayılan: terminal)",
    )
    rapor_ayristirici.add_argument(
        "--cikti",
        type=str,
        default=None,
        metavar="DOSYA",
        help="raporu dosyaya kaydet",
    )
    rapor_ayristirici.add_argument(
        "--thread",
        type=int,
        default=50,
        metavar="SAYI",
        help="paralel thread sayısı (varsayılan: 50)",
    )
    rapor_ayristirici.add_argument(
        "--zaman-asimi",
        type=float,
        default=1.0,
        metavar="SANIYE",
        help="zaman aşımı (varsayılan: 1.0)",
    )

    # --- bruteforce alt komutu ---
    bruteforce_ayristirici = alt_komutlar.add_parser(
        "bruteforce",
        help="kaba kuvvet parola saldırısı (FTP/SSH/Telnet/HTTP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bruteforce_ayristirici.add_argument(
        "--hedef", type=str, required=True, help="hedef ip adresi",
    )
    bruteforce_ayristirici.add_argument(
        "--servis", type=str, default="ftp",
        choices=["ftp", "ssh", "telnet", "http"],
        help="hedef servis (varsayılan: ftp)",
    )
    bruteforce_ayristirici.add_argument(
        "--port", type=int, default=None,
        help="hedef port (belirtilmezse servis varsayılanı)",
    )
    bruteforce_ayristirici.add_argument(
        "--kullanicilar", type=str, default=None, metavar="DOSYA",
        help="özel kullanıcı adı listesi dosyası",
    )
    bruteforce_ayristirici.add_argument(
        "--parolalar", type=str, default=None, metavar="DOSYA",
        help="özel parola listesi dosyası",
    )
    bruteforce_ayristirici.add_argument(
        "--yol", type=str, default="/",
        help="HTTP Basic Auth yolu (varsayılan: /)",
    )
    bruteforce_ayristirici.add_argument(
        "--thread", type=int, default=5, metavar="SAYI",
        help="paralel thread sayısı (varsayılan: 5)",
    )
    bruteforce_ayristirici.add_argument(
        "--bekleme", type=float, default=0.0, metavar="SANIYE",
        help="denemeler arası bekleme (varsayılan: 0)",
    )
    bruteforce_ayristirici.add_argument(
        "--zaman-asimi", type=float, default=5.0, metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 5.0)",
    )

    # --- saldiri alt komutu ---
    saldiri_ayristirici = alt_komutlar.add_parser(
        "saldiri",
        help="keşfedilen servislere otomatik exploit çalıştır",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    saldiri_ayristirici.add_argument(
        "--hedef", type=str, required=True, help="hedef ip adresi",
    )
    saldiri_ayristirici.add_argument(
        "--port", type=int, default=None,
        help="hedef port (belirtilmezse yaygın portlar taranır)",
    )
    saldiri_ayristirici.add_argument(
        "--zaman-asimi", type=float, default=5.0, metavar="SANIYE",
        help="bağlantı zaman aşımı (varsayılan: 5.0)",
    )

    # --- arpspoof alt komutu ---
    arpspoof_ayristirici = alt_komutlar.add_parser(
        "arpspoof",
        help="ARP spoofing / MITM saldırısı (root gerektirir)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    arpspoof_ayristirici.add_argument(
        "--hedef", type=str, required=True, help="hedef cihazın ip adresi",
    )
    arpspoof_ayristirici.add_argument(
        "--gateway", type=str, required=True, help="ağ geçidinin (gateway) ip adresi",
    )
    arpspoof_ayristirici.add_argument(
        "--arayuz", type=str, default=None,
        help="ağ arayüzü (belirtilmezse otomatik tespit)",
    )
    arpspoof_ayristirici.add_argument(
        "--yakala", action="store_true",
        help="yakalanan paketleri göster",
    )

    return ayristirici


def _haric_listesi_ayikla(haric_str: Optional[str]) -> List[int]:
    """
    virgülle ayrılmış hex string'i int listesine çevirir

    parametreler:
        haric_str: "00,0a,0d" formatında string

    döndürür:
        [0x00, 0x0a, 0x0d] formatında liste
    """
    if not haric_str:
        return []

    sonuc = []
    for parca in haric_str.split(","):
        parca = parca.strip().lower()
        if parca.startswith("0x"):
            parca = parca[2:]
        try:
            sonuc.append(int(parca, 16))
        except ValueError:
            pass

    return sonuc


def ana() -> None:
    """ana giriş fonksiyonu"""
    ayristirici = _ana_ayristirici_olustur()
    arglar = ayristirici.parse_args()

    # modül seçilmemişse yardım göster
    if not arglar.modul:
        gunluk = Gunluk()
        gunluk.banner()
        ayristirici.print_help()
        sys.exit(0)

    # loglama seviyesini belirle
    if arglar.ayiklama:
        seviye = Gunluk.AYIKLAMA
    elif arglar.sessiz:
        seviye = Gunluk.UYARI
    else:
        seviye = Gunluk.BILGI

    gunluk = Gunluk(
        seviye=seviye,
        dosya_yolu=arglar.log_dosyasi,
    )

    gunluk.banner()

    # modüle göre yönlendir
    try:
        if arglar.modul == "fuzzing":
            fuzzing_baslat(
                hedef_ip=arglar.hedef,
                hedef_port=arglar.port,
                komut=arglar.komut,
                baslangic_boyutu=arglar.baslangic,
                adim_boyutu=arglar.adim,
                maksimum_boyut=arglar.maksimum,
                bekleme_suresi=arglar.bekleme,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "offset":
            if arglar.sadece_hesapla:
                if not arglar.eip:
                    gunluk.hata("--sadece-hesapla modu için --eip parametresi gerekli")
                    sys.exit(1)
                offset_hesapla(
                    eip_degeri=arglar.eip,
                    desen_uzunlugu=arglar.uzunluk,
                    gunluk=gunluk,
                )
            else:
                offset_tespiti_baslat(
                    hedef_ip=arglar.hedef,
                    hedef_port=arglar.port,
                    desen_uzunlugu=arglar.uzunluk,
                    komut=arglar.komut,
                    eip_degeri=arglar.eip,
                    zaman_asimi=arglar.zaman_asimi,
                    gunluk=gunluk,
                )

        elif arglar.modul == "karakter":
            haric_liste = _haric_listesi_ayikla(arglar.haric)
            karakter_analizi_baslat(
                hedef_ip=arglar.hedef,
                hedef_port=arglar.port,
                offset=arglar.offset,
                komut=arglar.komut,
                haric_karakterler=haric_liste,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "exploit":
            istismar_baslat(
                hedef_ip=arglar.hedef,
                hedef_port=arglar.port,
                offset=arglar.offset,
                jmp_adresi=arglar.jmp_adresi,
                shellcode_dosyasi=arglar.shellcode_dosyasi,
                nop_boyutu=arglar.nop,
                komut=arglar.komut,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "kesfet":
            ag_taramasi_baslat(
                subnet=arglar.subnet,
                yontem=arglar.yontem,
                zaman_asimi=arglar.zaman_asimi,
                is_parcacigi_sayisi=arglar.thread,
                gunluk=gunluk,
            )

        elif arglar.modul == "portscan":
            port_listesi = None
            if arglar.portlar:
                port_listesi = port_araligi_ayikla(arglar.portlar)

            port_taramasi_baslat(
                hedef_ip=arglar.hedef,
                port_listesi=port_listesi,
                profil=arglar.profil,
                is_parcacigi_sayisi=arglar.thread,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "servis":
            port_listesi = None
            if arglar.portlar:
                port_listesi = port_araligi_ayikla(arglar.portlar)

            servis_tespiti_baslat(
                hedef_ip=arglar.hedef,
                acik_portlar=port_listesi,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "rapor":
            _tam_rapor_calistir(arglar, gunluk)

        elif arglar.modul == "bruteforce":
            bruteforce_baslat(
                hedef_ip=arglar.hedef,
                servis=arglar.servis,
                port=arglar.port,
                kullanici_dosyasi=arglar.kullanicilar,
                parola_dosyasi=arglar.parolalar,
                http_yol=arglar.yol,
                is_parcacigi_sayisi=arglar.thread,
                bekleme=arglar.bekleme,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "saldiri":
            saldiri_baslat(
                hedef_ip=arglar.hedef,
                port=arglar.port,
                zaman_asimi=arglar.zaman_asimi,
                gunluk=gunluk,
            )

        elif arglar.modul == "arpspoof":
            arp_spoof_baslat(
                hedef_ip=arglar.hedef,
                gateway_ip=arglar.gateway,
                arayuz=arglar.arayuz,
                paket_yakalama=arglar.yakala,
                gunluk=gunluk,
            )

    except KeyboardInterrupt:
        gunluk.bos_satir()
        gunluk.uyari("kullanıcı tarafından iptal edildi (ctrl+c)")
        sys.exit(130)
    except Exception as hata:
        gunluk.bos_satir()
        gunluk.kritik(f"beklenmeyen hata: {hata}")
        if arglar.ayiklama:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _tam_rapor_calistir(arglar, gunluk):
    """tam ağ sızma testi raporu — keşfet + portscan + servis birleşik"""
    baslangic = datetime.now()
    basla = time.time()

    # 1. ağ keşfi
    gunluk.bilgi("aşama 1/3: ağ keşfi başlatılıyor...")
    aktif_hostlar = ag_taramasi_baslat(
        subnet=arglar.subnet,
        zaman_asimi=arglar.zaman_asimi,
        is_parcacigi_sayisi=arglar.thread,
        gunluk=gunluk,
    )

    if not aktif_hostlar:
        gunluk.uyari("aktif host bulunamadı, rapor oluşturulamıyor")
        return

    # 2. her host için port tarama ve servis tespiti
    host_bilgileri = []

    for i, host in enumerate(aktif_hostlar, 1):
        hedef_ip = host["ip"]
        gunluk.bos_satir()
        gunluk.bilgi(f"aşama 2/3: port taraması [{i}/{len(aktif_hostlar)}] — {hedef_ip}")

        acik_portlar = port_taramasi_baslat(
            hedef_ip=hedef_ip,
            profil="hizli",
            is_parcacigi_sayisi=arglar.thread,
            zaman_asimi=arglar.zaman_asimi,
            gunluk=gunluk,
        )

        # 3. servis tespiti
        servis_sonuclari = []
        if acik_portlar:
            gunluk.bilgi(f"aşama 3/3: servis tespiti [{i}/{len(aktif_hostlar)}] — {hedef_ip}")
            servis_sonuclari = servis_tespiti_baslat(
                hedef_ip=hedef_ip,
                acik_portlar=acik_portlar,
                zaman_asimi=3.0,
                gunluk=gunluk,
            )

        # host bilgisini oluştur
        port_bilgileri = []
        for s in servis_sonuclari:
            port_bilgileri.append(PortBilgisi(
                port=s["port"],
                servis=s.get("servis"),
                versiyon=s.get("versiyon"),
                banner=s.get("banner"),
                zafiyetler=s.get("zafiyetler", []),
            ))

        host_bilgileri.append(HostBilgisi(
            ip=hedef_ip,
            mac=host.get("mac"),
            acik_portlar=port_bilgileri,
        ))

    bitis = datetime.now()
    sure = time.time() - basla

    # rapor oluştur
    from cekirdek.ag_yardimcilar import varsayilan_subnet_bul
    subnet_str = arglar.subnet or varsayilan_subnet_bul()

    tarama_sonucu = TaramaSonucu(
        subnet=subnet_str,
        baslangic_zamani=baslangic.strftime("%Y-%m-%d %H:%M:%S"),
        bitis_zamani=bitis.strftime("%Y-%m-%d %H:%M:%S"),
        tarama_suresi=sure,
        toplam_host=254,
        aktif_host=len(aktif_hostlar),
        hostlar=host_bilgileri,
    )

    rapor_olustur(
        tarama_sonucu=tarama_sonucu,
        format_tipi=arglar.rapor_format,
        cikti_dosyasi=arglar.cikti,
        gunluk=gunluk,
    )


if __name__ == "__main__":
    ana()
