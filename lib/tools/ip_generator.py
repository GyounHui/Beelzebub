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
    print(f"{wh}[{g}+{wh}] IP Generator + Live Checker\n")

    prov = input(f"{wh}[{g}?{wh}] Providers (comma separated from aws,gcp,cloudflare) [aws,gcp]: {res}").strip() or 'aws,gcp'
    providers = [p.strip().lower() for p in prov.split(',') if p.strip()]

    try:
        sample_per = int(input(f"{wh}[{g}+{wh}] Sample IPs per prefix (e.g., 1-10) [1]: {res}").strip() or '1')
    except ValueError:
        sample_per = 1

    try:
        max_ips = input(f"{wh}[{g}+{wh}] Max total IPs (empty for no limit): {res}").strip()
        max_ips = int(max_ips) if max_ips else None
    except ValueError:
        max_ips = None

    try:
        threads = int(input(f"{wh}[{g}+{wh}] Threads for liveness check [100]: {res}").strip() or '100')
    except ValueError:
        threads = 100

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
    time.sleep(0.5)
    print(f"{wh}[{g}+{wh}] Starting liveness checks with {threads} threads...{res}")
    check_ips_concurrent(ips, threads)
    print(f"{wh}[{g}+{wh}] Done. Check Result/Goodip.txt and Result/Badip.txt{res}")


if __name__ == '__main__':
    ip_generator_cli()
