#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious bağlantı yöneticisi - soket bağlantı işlemleri
"""

import socket
import time
from typing import Optional, Tuple

from cekirdek.gunluk import Gunluk


class BaglantiHatasi(Exception):
    """bağlantı işlemlerinde oluşan hataları temsil eder"""
    pass


class BaglantiYoneticisi:
    """
    tcp soket bağlantı yöneticisi

    özellikler:
        - otomatik bağlantı kurma ve kapatma
        - zaman aşımı yönetimi
        - yeniden deneme mekanizması
        - context manager desteği (with bloğu)
        - veri gönderme ve alma
    """

    VARSAYILAN_ZAMAN_ASIMI = 5.0
    VARSAYILAN_DENEME_SAYISI = 3
    DENEME_ARASI_BEKLEME = 1.0

    def __init__(
        self,
        hedef_ip: str,
        hedef_port: int,
        zaman_asimi: float = VARSAYILAN_ZAMAN_ASIMI,
        gunluk: Optional[Gunluk] = None,
    ) -> None:
        """
        bağlantı yöneticisini başlatır

        parametreler:
            hedef_ip: hedef sunucu ip adresi
            hedef_port: hedef sunucu port numarası
            zaman_asimi: bağlantı zaman aşımı (saniye)
            gunluk: loglama nesnesi
        """
        self._hedef_ip = hedef_ip
        self._hedef_port = hedef_port
        self._zaman_asimi = zaman_asimi
        self._gunluk = gunluk or Gunluk()
        self._soket: Optional[socket.socket] = None

    @property
    def hedef_bilgisi(self) -> str:
        """hedef ip:port bilgisini string olarak döndürür"""
        return f"{self._hedef_ip}:{self._hedef_port}"

    def baglan(self) -> bool:
        """
        hedef sunucuya tcp bağlantısı kurar

        döndürür:
            başarılı ise true, değilse false
        """
        try:
            self._soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._soket.settimeout(self._zaman_asimi)
            self._soket.connect((self._hedef_ip, self._hedef_port))
            self._gunluk.ayiklama(f"bağlantı kuruldu: {self.hedef_bilgisi}")
            return True
        except socket.timeout:
            self._gunluk.hata(f"bağlantı zaman aşımına uğradı: {self.hedef_bilgisi}")
            self._temizle()
            return False
        except ConnectionRefusedError:
            self._gunluk.hata(f"bağlantı reddedildi: {self.hedef_bilgisi}")
            self._temizle()
            return False
        except OSError as hata:
            self._gunluk.hata(f"bağlantı hatası: {hata}")
            self._temizle()
            return False

    def gonder(self, veri: bytes) -> bool:
        """
        bağlı sokete ham veri gönderir

        parametreler:
            veri: gönderilecek byte verisi

        döndürür:
            başarılı ise true
        """
        if not self._soket:
            self._gunluk.hata("gönderim başarısız: soket bağlı değil")
            return False

        try:
            self._soket.sendall(veri)
            self._gunluk.ayiklama(f"{len(veri)} byte gönderildi")
            return True
        except (BrokenPipeError, ConnectionResetError):
            self._gunluk.ayiklama("bağlantı karşı tarafça kapatıldı (hedef çökmüş olabilir)")
            return False
        except OSError as hata:
            self._gunluk.hata(f"gönderim hatası: {hata}")
            return False

    def al(self, tampon_boyutu: int = 4096) -> Optional[bytes]:
        """
        soketten veri alır

        parametreler:
            tampon_boyutu: maksimum alınacak byte sayısı

        döndürür:
            alınan veri veya none
        """
        if not self._soket:
            return None

        try:
            veri = self._soket.recv(tampon_boyutu)
            return veri if veri else None
        except socket.timeout:
            return None
        except OSError:
            return None

    def gonder_ve_kapat(self, veri: bytes) -> bool:
        """
        veriyi gönderir ve bağlantıyı kapatır (tek seferlik işlemler için)

        parametreler:
            veri: gönderilecek byte verisi

        döndürür:
            gönderim başarılı ise true
        """
        sonuc = self.gonder(veri)
        self.kapat()
        return sonuc

    def baglan_ve_gonder(
        self,
        veri: bytes,
        deneme_sayisi: int = VARSAYILAN_DENEME_SAYISI,
    ) -> bool:
        """
        bağlantı kurar, veri gönderir ve kapatır - yeniden deneme destekli

        parametreler:
            veri: gönderilecek byte verisi
            deneme_sayisi: maksimum deneme sayısı

        döndürür:
            işlem başarılı ise true

        istisnalar:
            BaglantiHatasi: tüm denemeler başarısız olursa
        """
        for deneme in range(1, deneme_sayisi + 1):
            if self.baglan():
                sonuc = self.gonder_ve_kapat(veri)
                return sonuc

            if deneme < deneme_sayisi:
                self._gunluk.uyari(
                    f"yeniden deneniyor ({deneme}/{deneme_sayisi})..."
                )
                time.sleep(self.DENEME_ARASI_BEKLEME)

        raise BaglantiHatasi(
            f"{self.hedef_bilgisi} adresine {deneme_sayisi} denemede baglanilamadi"
        )

    def hedef_eriselebilir_mi(self) -> bool:
        """
        hedefin erişilebilir olup olmadığını kontrol eder

        döndürür:
            erişilebilir ise true
        """
        try:
            test_soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_soket.settimeout(2.0)
            test_soket.connect((self._hedef_ip, self._hedef_port))
            test_soket.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def kapat(self) -> None:
        """soket bağlantısını güvenli şekilde kapatır"""
        self._temizle()

    def _temizle(self) -> None:
        """soket kaynağını serbest bırakır"""
        if self._soket:
            try:
                self._soket.close()
            except OSError:
                pass
            finally:
                self._soket = None

    # context manager desteği
    def __enter__(self) -> "BaglantiYoneticisi":
        """with bloğuna girerken bağlantı kurar"""
        if not self.baglan():
            raise BaglantiHatasi(f"baglanti kurulamadi: {self.hedef_bilgisi}")
        return self

    def __exit__(self, tip, deger, iz) -> None:
        """with bloğundan çıkarken bağlantıyı kapatır"""
        self.kapat()

    def __repr__(self) -> str:
        durum = "bagli" if self._soket else "bagli degil"
        return f"BaglantiYoneticisi({self.hedef_bilgisi}, durum={durum})"
