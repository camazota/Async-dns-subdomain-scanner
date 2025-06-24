# Async DNS Subdomain Scanner with Wildcard Detection  
Bu proje, Python’un `asyncio` kütüphanesi ile yazılmış yüksek performanslı, asenkron DNS alt alan adı tarayıcıdır.  
Birden fazla DNS sunucusu kullanarak hızlı ve verimli subdomain keşfi yapar ve wildcard IP tespiti ile sahte sonuçları filtreler.

This project is a high-performance asynchronous DNS subdomain scanner built with Python's `asyncio` library.  
It performs fast and efficient subdomain enumeration using multiple DNS servers and filters out false positives with wildcard IP detection.

---

## Özellikler / Features

- Asenkron sorgular ile yüksek hız / High speed with asynchronous queries  
- Çoklu DNS sunucu desteği / Multi-DNS server support  
- Joker DNS tespiti / Wildcard DNS detection  
- Rate limiting ile DNS sunucularının korunması / Rate limiting to protect DNS servers  
- JSONL formatında sonuç kaydı / Results saved in JSONL format  
- A, AAAA, NS, TXT ve MX DNS kayıt türleri desteği / Support for A, AAAA, NS, TXT and MX DNS record types

---

## Kurulum / Installation

```bash
   git clone https://github.com/camazota/Async-dns-subdomain-scanner.git
   cd async-dns-subdomain-scanner
   pip install -r requirements.txt
```

---

## Kullanım / Usage

1. `config/dns_servers.txt` dosyasına DNS sunucularını ekleyin.  
   Add your DNS servers in the `config/dns_servers.txt` file.

2. `config/domains.txt` dosyasına hedef domainleri ekleyin.  
   Add target domains in the `config/domains.txt` file.

3. `config/subdomains.txt` dosyasına alt alan adlarını ekleyin.  
   Add subdomains in the `config/subdomains.txt` file.

4. Programı çalıştırın:  
   Run the program:

<code>python main.py</code>

Program sizden domain ve subdomain dosya isimlerini isteyecektir (varsayılanlar belirtilmiştir).  
The program will ask for domain and subdomain file names (defaults are provided).

---

## Lisans / License

MIT License © 2025 camazota

---

## İletişim / Contact

Projeyle ilgili sorular için: akbasd507@gmail.com 
For questions regarding the project: akbasd507@gmail.com
