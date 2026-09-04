#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious zafiyet veritabanı - bilinen servis zafiyetleri imza veritabanı

statik, gömülü zafiyet veritabanı. internet bağlantısı gerektirmez.
servis versiyon bilgilerini bilinen zafiyetlerle eşleştirir.
"""

from typing import Dict, List, Optional, Tuple


# risk seviyeleri
RISK_KRITIK = "kritik"
RISK_YUKSEK = "yüksek"
RISK_ORTA = "orta"
RISK_DUSUK = "düşük"
RISK_BILGI = "bilgi"


# ana zafiyet veritabanı
# yapı: servis_adi -> versiyon_deseni -> zafiyet bilgileri
ZAFIYET_VERITABANI: Dict[str, Dict[str, dict]] = {
    "vulnserver": {
        "1.0": {
            "zafiyetler": [
                "Buffer Overflow (TRUN komutu)",
                "Buffer Overflow (GMON komutu — SEH tabanlı)",
                "Buffer Overflow (KSTET komutu — egg hunter)",
                "Buffer Overflow (GTER komutu — kısıtlı alan)",
                "Buffer Overflow (HTER komutu — hex karakterler)",
                "Buffer Overflow (LTER komutu — alfanümerik)",
            ],
            "risk": RISK_KRITIK,
            "referans": "VulnServer — eğitim amaçlı kasıtlı zafiyetli TCP sunucu",
            "exploit_onerisi": "noxious fuzzing/offset/exploit modüllerini kullanın",
        },
    },
    "openssh": {
        "7.0": {
            "zafiyetler": [
                "CVE-2016-0777 — Roaming bilgi sızıntısı",
            ],
            "risk": RISK_ORTA,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2016-0777",
        },
        "7.6": {
            "zafiyetler": [
                "CVE-2018-15473 — Kullanıcı numaralandırma",
            ],
            "risk": RISK_ORTA,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        },
        "8.5": {
            "zafiyetler": [
                "CVE-2021-41617 — AuthorizedKeysCommand yetki yükseltme",
            ],
            "risk": RISK_ORTA,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2021-41617",
        },
        "9.1": {
            "zafiyetler": [
                "CVE-2023-38408 — PKCS#11 uzaktan kod çalıştırma (agent forwarding)",
            ],
            "risk": RISK_YUKSEK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        },
    },
    "apache": {
        "2.4.49": {
            "zafiyetler": [
                "CVE-2021-41773 — Path Traversal / RCE",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
        "2.4.50": {
            "zafiyetler": [
                "CVE-2021-42013 — Path Traversal bypass (CVE-2021-41773 düzeltme atlatma)",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        },
        "2.4.7": {
            "zafiyetler": [
                "CVE-2017-9798 — Optionsbleed bellek sızıntısı",
            ],
            "risk": RISK_ORTA,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2017-9798",
        },
    },
    "nginx": {
        "1.4.0": {
            "zafiyetler": [
                "CVE-2013-2028 — Chunked transfer encoding buffer overflow",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2013-2028",
        },
        "1.18.0": {
            "zafiyetler": [
                "CVE-2021-23017 — DNS resolver off-by-one heap yazma",
            ],
            "risk": RISK_YUKSEK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        },
    },
    "vsftpd": {
        "2.3.4": {
            "zafiyetler": [
                "CVE-2011-2523 — Backdoor komut çalıştırma (port 6200)",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
            "exploit_onerisi": "telnet <hedef> 6200 ile backdoor bağlantısı deneyin",
        },
    },
    "proftpd": {
        "1.3.3c": {
            "zafiyetler": [
                "CVE-2010-4221 — Telnet IAC buffer overflow",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2010-4221",
        },
        "1.3.5": {
            "zafiyetler": [
                "CVE-2015-3306 — mod_copy izinsiz dosya kopyalama",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
        },
    },
    "mysql": {
        "5.5.0": {
            "zafiyetler": [
                "CVE-2012-2122 — Kimlik doğrulama atlama (memcmp timing)",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2012-2122",
        },
    },
    "samba": {
        "3.5.0": {
            "zafiyetler": [
                "CVE-2017-7494 — SambaCry uzaktan kod çalıştırma",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2017-7494",
        },
    },
    "microsoft-ds": {
        "smb1": {
            "zafiyetler": [
                "CVE-2017-0144 — EternalBlue (MS17-010) uzaktan kod çalıştırma",
                "CVE-2017-0145 — EternalRomance uzaktan kod çalıştırma",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            "exploit_onerisi": "use exploit/windows/smb/ms17_010_eternalblue (Metasploit)",
        },
    },
    "iis": {
        "6.0": {
            "zafiyetler": [
                "CVE-2017-7269 — WebDAV buffer overflow (ScStoragePathFromUrl)",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
        },
    },
    "tomcat": {
        "8.5.19": {
            "zafiyetler": [
                "CVE-2017-12617 — PUT metodu ile JSP yükleme (RCE)",
            ],
            "risk": RISK_KRITIK,
            "referans": "https://nvd.nist.gov/vuln/detail/CVE-2017-12617",
        },
    },
}

# yaygın port → servis eşleştirme tablosu
PORT_SERVIS_ESLESTIRME: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2121: "ftp-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    6667: "irc",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9999: "vulnserver",
    27017: "mongodb",
}


def port_servis_adi(port: int) -> str:
    """
    port numarasına karşılık gelen bilinen servis adını döndürür

    parametreler:
        port: port numarası

    döndürür:
        servis adı stringi veya "bilinmiyor"
    """
    return PORT_SERVIS_ESLESTIRME.get(port, "bilinmiyor")


def zafiyet_ara(servis: str, versiyon: str) -> Optional[dict]:
    """
    servis ve versiyon bilgisine göre bilinen zafiyetleri arar

    parametreler:
        servis: servis adı (ör: "openssh", "apache")
        versiyon: servis versiyonu (ör: "8.5", "2.4.49")

    döndürür:
        zafiyet bilgi sözlüğü veya none (zafiyet bulunamazsa)
    """
    servis_kucuk = servis.lower().strip()

    # servis ismi normalleştirme
    # bazı banner'larda "openssh" olarak gelir, veritabanında "openssh" olarak tutulur
    normalizasyon = {
        "open ssh": "openssh",
        "apache httpd": "apache",
        "apache http server": "apache",
        "microsoft iis": "iis",
        "apache tomcat": "tomcat",
        "microsoft-ds": "microsoft-ds",
    }

    for anahtar, deger in normalizasyon.items():
        if anahtar in servis_kucuk:
            servis_kucuk = deger
            break

    # veritabanında servis ara
    if servis_kucuk not in ZAFIYET_VERITABANI:
        return None

    servis_veritabani = ZAFIYET_VERITABANI[servis_kucuk]

    # tam versiyon eşleşmesi
    if versiyon in servis_veritabani:
        return servis_veritabani[versiyon]

    # kısmi versiyon eşleşmesi (major.minor)
    versiyon_parcalari = versiyon.split(".")
    if len(versiyon_parcalari) >= 2:
        kismi = f"{versiyon_parcalari[0]}.{versiyon_parcalari[1]}"
        if kismi in servis_veritabani:
            return servis_veritabani[kismi]

    # major versiyon eşleşmesi
    if len(versiyon_parcalari) >= 1:
        for vt_versiyon, vt_bilgi in servis_veritabani.items():
            if vt_versiyon.startswith(versiyon_parcalari[0] + "."):
                return vt_bilgi

    return None


def tum_zafiyetleri_listele() -> List[Tuple[str, str, dict]]:
    """
    veritabanındaki tüm zafiyetleri listeler

    döndürür:
        (servis, versiyon, bilgi) tuple listesi
    """
    sonuc = []
    for servis, versiyonlar in ZAFIYET_VERITABANI.items():
        for versiyon, bilgi in versiyonlar.items():
            sonuc.append((servis, versiyon, bilgi))
    return sonuc


def risk_renk_kodu(risk: str) -> str:
    """
    risk seviyesine göre ansi renk kodu döndürür

    parametreler:
        risk: risk seviyesi stringi

    döndürür:
        ansi renk escape kodu
    """
    renk_haritasi = {
        RISK_KRITIK: "\033[91m",   # kırmızı
        RISK_YUKSEK: "\033[93m",   # sarı
        RISK_ORTA: "\033[33m",     # turuncu
        RISK_DUSUK: "\033[94m",    # mavi
        RISK_BILGI: "\033[37m",    # beyaz
    }
    return renk_haritasi.get(risk, "\033[0m")
