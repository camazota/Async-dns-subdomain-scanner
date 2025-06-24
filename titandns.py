import asyncio
import dns.asyncresolver
import json
import random
import string
import time
from pathlib import Path
from collections import Counter

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"

TIMEOUT = 3
MAX_CONCURRENT_QUERIES = 2000
REPEAT_PER_DNS = 5
BATCH_SIZE = 5000
RESULTS_BUFFER_SIZE = 1000

RECORD_TYPES = ['A', 'AAAA']

DNS_SERVERS = []

RATE_LIMIT_PER_SECOND = 800

def random_subdomain(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def load_lines(filename):
    path = Path("config/"+filename)
    if not path.exists():
        print(f"{RED}Dosya bulunamadı: {filename}{RESET}")
        return []
    return [line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

async def detect_wildcard(domain, resolver):
    test_subs = [random_subdomain() for _ in range(5)]
    ip_sets = []

    for sub in test_subs:
        fqdn = f"{sub}.{domain}"
        try:
            answer = await resolver.resolve(fqdn, "A")
            ips = set(r.to_text() for r in answer)
            ip_sets.append(ips)
        except Exception:
            ip_sets.append(set())

    ip_occurrences = Counter(ip for ips in ip_sets for ip in ips)

    if not ip_occurrences:
        print(f"{YELLOW}[Wildcard] {domain} -> YOK{RESET}")
        return False, None

    max_ip, max_count = ip_occurrences.most_common(1)[0]
    if max_count >= 3:
        print(f"{RED}[Wildcard] {domain} -> VAR (IP: {max_ip}, tekrar: {max_count}){RESET}")
        return True, max_ip

    print(f"{YELLOW}[Wildcard] {domain} -> YOK{RESET}")
    return False, None

class RateLimiter:
    def __init__(self, rate_per_sec):
        self._rate = rate_per_sec
        self._tokens = rate_per_sec
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens += elapsed * self._rate
            if self._tokens > self._rate:
                self._tokens = self._rate
            self._last = now
            if self._tokens >= 1:
                self._tokens -= 1
                return

            wait_time = (1 - self._tokens) / self._rate
        await asyncio.sleep(wait_time)
        await self.acquire()

dns_cache = {}

class DNSClient:
    def __init__(self, dns_ip, rate_limit):
        self.dns_ip = dns_ip
        self.rate_limiter = RateLimiter(rate_limit)
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = [dns_ip]
        self.resolver.timeout = TIMEOUT
        self.resolver.lifetime = TIMEOUT

    async def query(self, fqdn, rtype):
        cache_key = (fqdn, rtype, self.dns_ip)
        if cache_key in dns_cache:
            return dns_cache[cache_key]

        await self.rate_limiter.acquire()
        results = set()
        try:
            answer = await self.resolver.resolve(fqdn, rtype)
            for r in answer:
                if rtype == "MX":
                    results.add(str(r.exchange).rstrip('.'))
                elif rtype == "TXT":
                    if hasattr(r, "strings"):
                        txt = b"".join(r.strings).decode(errors="ignore")
                    else:
                        txt = str(r)
                    results.add(txt)
                elif rtype == "NS":
                    results.add(str(r.target).rstrip('.'))
                else:
                    results.add(r.to_text())
            dns_cache[cache_key] = results
        except Exception as e:
            with open("errors.log", "a", encoding="utf-8") as ef:
                ef.write(f"{fqdn} [{rtype}] via {self.dns_ip} - Error: {repr(e)}\n")
        return results

async def write_buffer(outfile_jsonl, buffer):
    if buffer:
        with open(outfile_jsonl, "a", encoding="utf-8") as jf:
            for entry in buffer:
                json.dump(entry, jf, ensure_ascii=False)
                jf.write("\n")
        buffer.clear()

async def limited_task(client, fqdn, rtype, wildcard, wildcard_ip, sem, results_buffer, outfile_jsonl):
    async with sem:
        res = await client.query(fqdn, rtype)
        if not res:
            return
        for val in res:
            print(f"{CYAN}{fqdn:<30}{RESET}{RED}[{rtype}]{RESET} -> {GREEN}{val:<25}{RESET} ({client.dns_ip}) Wildcard: {YELLOW}{wildcard}{RESET}")
            results_buffer.append({
                "fqdn": fqdn,
                "record_type": rtype,
                "value": val,
                "dns_server": client.dns_ip,
                "wildcard": wildcard,
                "wildcard_ip": wildcard_ip
            })
            if len(results_buffer) >= RESULTS_BUFFER_SIZE:
                await write_buffer(outfile_jsonl, results_buffer)

async def scan(domains, subdomains, outfile_jsonl="results.jsonl"):
    sem = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)

    print(f"{BLUE}[INFO] Wildcard tespiti yapılıyor...{RESET}")
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT
    domain_wildcards = {}
    domain_wildcard_ips = {}
    for domain in domains:
        has_wc, wc_ip = await detect_wildcard(domain, resolver)
        domain_wildcards[domain] = has_wc
        domain_wildcard_ips[domain] = wc_ip

    open(outfile_jsonl, "w", encoding="utf-8").close()
    open("errors.log", "w", encoding="utf-8").close()

    clients = [DNSClient(ip, RATE_LIMIT_PER_SECOND // len(DNS_SERVERS)) for ip in DNS_SERVERS]

    results_buffer = []

    tasks = []
    for domain in domains:
        wildcard = domain_wildcards[domain]
        wc_ip = domain_wildcard_ips[domain]
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            for client in clients:
                for _ in range(REPEAT_PER_DNS):
                    for rtype in RECORD_TYPES:
                        tasks.append(limited_task(client, fqdn, rtype, wildcard, wc_ip, sem, results_buffer, outfile_jsonl))

    print(f"{BLUE}[INFO] Toplam {len(tasks)} görev oluşturuldu. Batch size: {BATCH_SIZE}{RESET}")

    for i in range(0, len(tasks), BATCH_SIZE):
        print(f"{MAGENTA}[Batch {i // BATCH_SIZE + 1}] başlıyor...{RESET}")
        await asyncio.gather(*tasks[i:i + BATCH_SIZE])
        await write_buffer(outfile_jsonl, results_buffer)
        print(f"{MAGENTA}[Batch {i // BATCH_SIZE + 1}] tamamlandı.{RESET}")

    await write_buffer(outfile_jsonl, results_buffer)

    print(f"{GREEN}[TAMAMLANDI] Toplam sorgu cachelenmiş: {len(dns_cache)}{RESET}")

def main():
    with open("config/dns_servers.txt", "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                DNS_SERVERS.append(line.strip())
    domain_file = input(f"{BLUE}Domain [varsayılan: config/domains.txt]: {RESET}").strip() or "domains.txt"
    sub_file = input(f"{BLUE}Subdomain [varsayılan: config/subdomains.txt]: {RESET}").strip() or "subdomains.txt"

    domains = load_lines(domain_file)
    subdomains = load_lines(sub_file)

    if not domains:
        print(f"{RED}Domain listesi boş veya bulunamadı!{RESET}")
        return
    if not subdomains:
        print(f"{RED}Subdomain listesi boş veya bulunamadı!{RESET}")
        return

    print(f"{YELLOW}\n[INFO] Tarama başlıyor... Domain sayısı: {len(domains)}, Subdomain sayısı: {len(subdomains)}{RESET}\n")
    asyncio.run(scan(domains, subdomains))

if __name__ == "__main__":
    main()
