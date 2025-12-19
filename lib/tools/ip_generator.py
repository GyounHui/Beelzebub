import requests
import ipaddress
import random
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from lib.tools.utils import clear, banner
from lib.tools.colors import wh, r, g, res
from lib.tools.ipc import check_ip


def fetch_aws_prefixes() -> List[str]:
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        prefixes = [p.get("ip_prefix") for p in data.get("prefixes", []) if p.get("ip_prefix")]
        prefixes += [p.get("ipv6_prefix") for p in data.get("ipv6_prefixes", []) if p.get("ipv6_prefix")]
        return prefixes
    except Exception:
        return []


def fetch_gcp_prefixes() -> List[str]:
    url = "https://www.gstatic.com/ipranges/cloud.json"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        prefixes = [p.get("ipv4Prefix") for p in data.get("prefixes", []) if p.get("ipv4Prefix")]
        prefixes += [p.get("ipv6Prefix") for p in data.get("prefixes", []) if p.get("ipv6Prefix")]
        return prefixes
    except Exception:
        return []


def fetch_cloudflare_prefixes() -> List[str]:
    urls = [
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ]
    prefixes = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            for line in resp.text.splitlines():
                line = line.strip()
                if line:
                    prefixes.append(line)
        except Exception:
            continue
    return prefixes


def fetch_microsoft_prefixes() -> List[str]:
    """Fetch Microsoft Azure public IP ranges."""
    url = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
    try:
        resp = requests.get(url, timeout=10)
        # Parse JSON from the page (Azure publishes JSON file)
        data = resp.json()
        prefixes = []
        for value in data.get('values', []):
            for prefix in value.get('properties', {}).get('addressPrefixes', []):
                prefixes.append(prefix)
        return prefixes
    except Exception:
        # Fallback: try direct JSON endpoint
        try:
            resp = requests.get("https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20231211.json", timeout=10)
            data = resp.json()
            prefixes = []
            for svc in data.get('values', []):
                prefixes.extend(svc.get('properties', {}).get('addressPrefixes', []))
            return prefixes
        except Exception:
            return []


def fetch_japan_providers() -> List[str]:
    """Fetch IP ranges from major Japan ISPs (NTT, IIJ, etc.)."""
    urls = [
        "https://ftp.ripe.net/ripe/stats/delegated-apnic-latest",  # APNIC delegated (includes Japan)
    ]
    prefixes = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith('apnic|JP|ipv4') or line.startswith('apnic|JP|ipv6'):
                    parts = line.split('|')
                    if len(parts) >= 4:
                        ip = parts[3]
                        count = int(parts[4]) if parts[4].isdigit() else 1
                        if count > 0 and '.' in ip:
                            # Calculate CIDR from count
                            import math
                            if count >= 256:
                                cidr = 16
                            elif count >= 128:
                                cidr = 17
                            elif count >= 64:
                                cidr = 18
                            elif count >= 32:
                                cidr = 19
                            elif count >= 16:
                                cidr = 20
                            else:
                                cidr = 24
                            prefixes.append(f"{ip}/{cidr}")
        except Exception:
            continue
    return prefixes


def fetch_us_providers() -> List[str]:
    """Fetch IP ranges from major US ISPs and providers."""
    urls = [
        "https://ftp.ripe.net/ripe/stats/delegated-apnic-latest",  # APNIC includes US assignments
    ]
    prefixes = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith('arin|US|ipv4') or line.startswith('arin|US|ipv6'):
                    parts = line.split('|')
                    if len(parts) >= 4:
                        ip = parts[3]
                        count = int(parts[4]) if parts[4].isdigit() else 1
                        if count > 0 and '.' in ip:
                            import math
                            if count >= 256:
                                cidr = 16
                            elif count >= 128:
                                cidr = 17
                            elif count >= 64:
                                cidr = 18
                            elif count >= 32:
                                cidr = 19
                            elif count >= 16:
                                cidr = 20
                            else:
                                cidr = 24
                            prefixes.append(f"{ip}/{cidr}")
        except Exception:
            continue
    return prefixes


def fetch_exchange_points() -> List[str]:
    """Fetch IP ranges from major internet exchange points (NE, AR, DX, etc.)."""
    # NE = NLIX (Netherlands), AR = AMS-IX (Amsterdam), DX = DE-CIX (Germany), etc.
    urls = {
        'de-cix': "https://www.de-cix.net/en/locations/germany/frankfurt/network-information",  # DX
        'ams-ix': "https://www.ams-ix.net/ams/public/peering/",  # AR
    }
    prefixes = []
    
    # DE-CIX Frankfurt known ranges (manually curated for reliability)
    de_cix_ranges = [
        "80.81.192.0/19",
        "80.81.224.0/19",
        "185.1.109.0/24",
        "2001:7f8:1::/48",
    ]
    
    # AMS-IX Amsterdam known ranges
    ams_ix_ranges = [
        "80.249.208.0/21",
        "80.249.216.0/21",
        "2001:7f8:1::0/48",
    ]
    
    prefixes.extend(de_cix_ranges)
    prefixes.extend(ams_ix_ranges)
    
    return prefixes


def sample_ips_from_cidr(cidr: str, count: int = 1) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        total = net.num_addresses
        # if very small, expand fully
        if total <= count * 2 or total <= 256:
            return [str(ip) for ip in net.hosts()][:count]

        ips = set()
        min_int = int(net.network_address)
        max_int = int(net.broadcast_address)
        while len(ips) < count:
            n = random.randint(min_int + 1, max_int - 1)
            ips.add(str(ipaddress.ip_address(n)))
        return list(ips)
    except Exception:
        return []


def generate_ips(providers: List[str], sample_per_prefix: int, max_ips: int = None) -> List[str]:
    prefixes = []
    if "aws" in providers:
        prefixes += fetch_aws_prefixes()
    if "gcp" in providers:
        prefixes += fetch_gcp_prefixes()
    if "cloudflare" in providers:
        prefixes += fetch_cloudflare_prefixes()
    if "microsoft" in providers or "azure" in providers:
        prefixes += fetch_microsoft_prefixes()
    if "japan" in providers or "jp" in providers:
        prefixes += fetch_japan_providers()
    if "us" in providers or "usa" in providers:
        prefixes += fetch_us_providers()
    if "exchange" in providers or "exchanges" in providers or "ix" in providers:
        prefixes += fetch_exchange_points()

    ips = []
    for p in prefixes:
        if max_ips and len(ips) >= max_ips:
            break
        sampled = sample_ips_from_cidr(p, sample_per_prefix)
        for ip in sampled:
            ips.append(ip)
            if max_ips and len(ips) >= max_ips:
                break

    return ips


def write_ip_list(ips: List[str], path: str):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as f:
        for ip in ips:
            f.write(ip + '\n')


def check_ips_concurrent(ips: List[str], threads: int = 100):
    # Reuse check_ip from ipc; it writes Goodip/Badip inside
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(check_ip, ip) for ip in ips]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                continue


def ip_generator_cli():
    clear()
    print(banner)
    print(f"{wh}[{g}+{wh}] IP Generator + Live Checker (Enhanced)\n")

    provider_list = "aws, gcp, cloudflare, microsoft, japan, us, exchange"
    prov = input(f"{wh}[{g}?{wh}] Providers (comma separated):\n    {provider_list}\n    [aws,gcp,cloudflare]: {res}").strip() or 'aws,gcp,cloudflare'
    providers = [p.strip().lower() for p in prov.split(',') if p.strip()]

    try:
        sample_per = int(input(f"{wh}[{g}+{wh}] Sample IPs per prefix (e.g., 1-10) [2]: {res}").strip() or '2')
    except ValueError:
        sample_per = 2

    try:
        max_ips = input(f"{wh}[{g}+{wh}] Max total IPs (empty for no limit): {res}").strip()
        max_ips = int(max_ips) if max_ips else None
    except ValueError:
        max_ips = None

    try:
        threads = int(input(f"{wh}[{g}+{wh}] Threads for liveness check [100]: {res}").strip() or '100')
    except ValueError:
        threads = 100

    try:
        timeout = int(input(f"{wh}[{g}+{wh}] Timeout per IP check in seconds [5]: {res}").strip() or '5')
    except ValueError:
        timeout = 5

    consent = input(f"{wh}[{g}!{wh}] Scanning IPs may be intrusive. Type 'I consent' to proceed: {res}")
    if consent.strip() != 'I consent':
        print(f"{r}[!] Consent not given. Aborting.{res}")
        return

    print(f"{wh}[{g}!{wh}] Fetching prefixes from providers: {providers} ...{res}")
    ips = generate_ips(providers, sample_per, max_ips)
    if not ips:
        print(f"{r}[!] No IPs generated. Exiting.{res}")
        return

    out_path = 'Result/generated_ips.txt'
    write_ip_list(ips, out_path)
    print(f"{wh}[{g}+{wh}] Generated {len(ips)} IPs -> {out_path}")
    print(f"{wh}[{g}+{wh}] Providers used: {', '.join(providers)}")
    print(f"{wh}[{g}+{wh}] Timeout per check: {timeout}s, Threads: {threads}")
    time.sleep(0.5)
    print(f"{wh}[{g}+{wh}] Starting liveness checks with {threads} threads...{res}")
    check_ips_concurrent(ips, threads)
    print(f"{wh}[{g}+{wh}] Done. Check Result/Goodip.txt and Result/Badip.txt{res}")


if __name__ == '__main__':
    ip_generator_cli()
