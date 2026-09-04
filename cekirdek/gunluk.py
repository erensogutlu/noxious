#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious loglama modülü - renkli terminal çıktısı ve dosya kaydı
"""

import sys
import os
import logging
from datetime import datetime
from typing import Optional


# ansi renk kodları (kali linux terminalleri tam destek sağlar)
class _Renkler:
    """terminal renk kodlarını barındıran sabit sınıf"""

    SIFIRLA = "\033[0m"
    KALIN = "\033[1m"
    SOLUK = "\033[2m"

    # ön plan renkleri
    KIRMIZI = "\033[91m"
    YESIL = "\033[92m"
    SARI = "\033[93m"
    MAVI = "\033[94m"
    MOR = "\033[95m"
    CYAN = "\033[96m"
    BEYAZ = "\033[97m"

    # arka plan renkleri
    ARKAPLAN_KIRMIZI = "\033[41m"
    ARKAPLAN_YESIL = "\033[42m"


def _renk_destegi_var_mi() -> bool:
    """terminalin ansi renk desteğini kontrol eder"""
    # windows'ta renk desteği kontrolü
    if sys.platform == "win32":
        return os.environ.get("ANSICON") is not None or "WT_SESSION" in os.environ
    # linux/macos — tty ise renk desteklenir
    # ansi escape kodları encoding'den bağımsızdır (7-bit ascii)
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Gunluk:
    """
    noxious profesyonel loglama sınıfı

    özellikler:
        - renkli terminal çıktısı (kali linux tam destek)
        - seviye bazlı loglama (bilgi, uyarı, hata, başarı, ayıklama)
        - isteğe bağlı dosyaya kayıt
        - zaman damgalı mesajlar
    """

    # seviye sabitleri
    AYIKLAMA = logging.DEBUG
    BILGI = logging.INFO
    UYARI = logging.WARNING
    HATA = logging.ERROR
    KRITIK = logging.CRITICAL

    def __init__(
        self,
        seviye: int = logging.INFO,
        dosya_yolu: Optional[str] = None,
        renkli: Optional[bool] = None,
    ) -> None:
        """
        loglama sistemini başlatır

        parametreler:
            seviye: minimum log seviyesi
            dosya_yolu: log dosyası yolu (none ise dosyaya yazılmaz)
            renkli: renk desteği (none ise otomatik algıla)
        """
        self._seviye = seviye
        self._dosya_yolu = dosya_yolu
        self._renkli = renkli if renkli is not None else _renk_destegi_var_mi()
        self._dosya_akisi = None

        if self._dosya_yolu:
            try:
                self._dosya_akisi = open(self._dosya_yolu, "a", encoding="utf-8")
            except OSError as hata:
                self._terminal_yaz(
                    "HATA",
                    f"log dosyası açılamadı: {hata}",
                    _Renkler.KIRMIZI,
                )

    def __del__(self) -> None:
        """yıkıcı - açık dosya akışını kapatır"""
        self._dosya_kapat()

    def __enter__(self) -> "Gunluk":
        """context manager girişi - with bloğu desteği"""
        return self

    def __exit__(self, tip, deger, iz) -> None:
        """context manager çıkışı - dosya akışını kapatır"""
        self._dosya_kapat()

    def _dosya_kapat(self) -> None:
        """açık dosya akışını güvenli şekilde kapatır"""
        if self._dosya_akisi and not self._dosya_akisi.closed:
            self._dosya_akisi.close()

    def _zaman_damgasi(self) -> str:
        """şu anki zamanı formatlanmış string olarak döndürür"""
        return datetime.now().strftime("%H:%M:%S")

    def _terminal_yaz(self, etiket: str, mesaj: str, renk: str) -> None:
        """terminale renkli formatlı mesaj yazar"""
        zaman = self._zaman_damgasi()
        if self._renkli:
            satir = (
                f"{_Renkler.SOLUK}{zaman}{_Renkler.SIFIRLA} "
                f"{renk}{_Renkler.KALIN}[{etiket}]{_Renkler.SIFIRLA} "
                f"{mesaj}"
            )
        else:
            satir = f"{zaman} [{etiket}] {mesaj}"

        print(satir, flush=True)

    def _dosyaya_yaz(self, etiket: str, mesaj: str) -> None:
        """log dosyasına zaman damgalı mesaj yazar"""
        if self._dosya_akisi and not self._dosya_akisi.closed:
            zaman = self._zaman_damgasi()
            self._dosya_akisi.write(f"{zaman} [{etiket}] {mesaj}\n")
            self._dosya_akisi.flush()

    def _logla(self, seviye: int, etiket: str, mesaj: str, renk: str) -> None:
        """genel loglama metodu"""
        if seviye >= self._seviye:
            self._terminal_yaz(etiket, mesaj, renk)
            self._dosyaya_yaz(etiket, mesaj)

    def bilgi(self, mesaj: str) -> None:
        """bilgi seviyesinde log yazar"""
        self._logla(self.BILGI, "*", mesaj, _Renkler.MAVI)

    def basari(self, mesaj: str) -> None:
        """başarı mesajı yazar (bilgi seviyesinde)"""
        self._logla(self.BILGI, "+", mesaj, _Renkler.YESIL)

    def uyari(self, mesaj: str) -> None:
        """uyarı seviyesinde log yazar"""
        self._logla(self.UYARI, "!", mesaj, _Renkler.SARI)

    def hata(self, mesaj: str) -> None:
        """hata seviyesinde log yazar"""
        self._logla(self.HATA, "-", mesaj, _Renkler.KIRMIZI)

    def kritik(self, mesaj: str) -> None:
        """kritik seviyede log yazar"""
        self._logla(self.KRITIK, "X", mesaj, _Renkler.ARKAPLAN_KIRMIZI)

    def ayiklama(self, mesaj: str) -> None:
        """ayıklama (debug) seviyesinde log yazar"""
        self._logla(self.AYIKLAMA, "?", mesaj, _Renkler.MOR)

    def bos_satir(self) -> None:
        """boş satır yazdırır"""
        print()

    def ayirici(self, karakter: str = "-", uzunluk: int = 60) -> None:
        """görsel ayırıcı çizgi yazdırır"""
        if self._renkli:
            print(f"{_Renkler.SOLUK}{karakter * uzunluk}{_Renkler.SIFIRLA}")
        else:
            print(karakter * uzunluk)

    def baslik(self, mesaj: str) -> None:
        """büyük başlık yazdırır"""
        self.ayirici()
        if self._renkli:
            print(
                f"  {_Renkler.CYAN}{_Renkler.KALIN}{mesaj}{_Renkler.SIFIRLA}"
            )
        else:
            print(f"  {mesaj}")
        self.ayirici()

    def banner(self) -> None:
        """noxious ascii banner'ını gösterir"""
        banner_metni = (
            "\n"
            "   ███╗   ██╗██████╗ ██╗  ██╗██╗██████╗ ██╗   ██╗███████╗\n"
            "   ████╗  ██║██╔══██╗╚██╗██╔╝██║██╔══██╗██║   ██║██╔════╝\n"
            "   ██╔██╗ ██║██║  ██║ ╚███╔╝ ██║██║  ██║██║   ██║███████╗\n"
            "   ██║╚██╗██║██║  ██║ ██╔██╗ ██║██║  ██║██║   ██║╚════██║\n"
            "   ██║ ╚████║██████╔╝██╔╝ ██╗██║██████╔╝╚██████╔╝███████║\n"
            "   ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝\n"
            "\n"
            "             Buffer Overflow & Ağ Sızma Testi Aracı\n"
        )
        if self._renkli:
            print(f"{_Renkler.KIRMIZI}{_Renkler.KALIN}{banner_metni}{_Renkler.SIFIRLA}")
        else:
            print(banner_metni)

