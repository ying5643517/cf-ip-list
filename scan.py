import concurrent.futures
import ipaddress
import random
import socket
import urllib.request

MAX_LIMIT_PER_REGION = 300
PORTS = [443, 8443, 2053, 2083]

# 精准且全面覆盖 US / SG / TW / JP 的 Cloudflare 官方 IPv4 / IPv6 网段
REGION_CIDRS = {
    "US": [
        "104.16.0.0/12", "172.64.0.0/13", "162.158.0.0/15",
        "2606:4700::/32"
    ],
    "SG": [
        "104.28.0.0/16", "172.67.0.0/16", "103.21.244.0/22", "104.18.0.0/15",
        "2400:cb00::/32"
    ],
    "TW": [
        "104.28.128.0/17", "162.158.128.0/17", "103.31.4.0/22", "104.17.0.0/15", 
        "172.68.0.0/16", "104.28.0.0/15", "141.101.64.0/18"
    ],
    "JP": [
        "104.28.0.0/16", "172.69.0.0/16", "103.22.200.0/22", "104.19.0.0/15", 
        "104.28.64.0/18", "162.158.64.0/18", "141.101.128.0/18"
    ]
}

def verify_ip(ip_str, port, region):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        is_ipv6 = ip_obj.version == 6
        formatted_ip = f"[{ip_str}]" if is_ipv6 else ip_str
        
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(1.2)
        s.connect((ip_str, port))
        s.close()

        req_url = f"http://{formatted_ip}:{port}/"
        req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            urllib.request.urlopen(req, timeout=1.2)
        except urllib.error.HTTPError as e:
            server_header = e.headers.get("Server", "").lower()
            if "cloudflare" in server_header or e.code in [400, 403, 405]:
                ip_type = "v6" if is_ipv6 else "v4"
                return f"{formatted_ip}:{port}#{region}-{ip_type}-{ip_str}"
        except Exception:
            pass
    except OSError:
        # 捕捉 Linux 运行环境不支持 IPv6 时的 Network Unreachable 异常
        pass
    except Exception:
        pass
    return None

def generate_random_ipv6(cidr_str, count=200):
    """安全生成 IPv6 样例地址"""
    results = []
    try:
        network = ipaddress.ip_network(cidr_str)
        net_int = int(network.network_address)
        mask_len = network.prefixlen
        host_bits = 128 - mask_len
        
        for _ in range(count):
            rand_bits = random.getrandbits(host_bits)
            random_ip_int = net_int | rand_bits
            results.append(str(ipaddress.ip_address(random_ip_int)))
    except Exception:
        pass
    return results

def main():
    all_region_results = []

    for region, cidrs in REGION_CIDRS.items():
        print(f"=== 开始扫描 {region} 地区节点 ===")
        candidate_ips = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr)
            if net.version == 4:
                hosts = list(net.hosts())
                sample_count = min(len(hosts), 800)
                candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])
            else:
                candidate_ips.extend(generate_random_ipv6(cidr, count=200))

        valid_results = []
        random.shuffle(candidate_ips)

        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
            futures = [executor.submit(verify_ip, ip, random.choice(PORTS), region) for ip in candidate_ips]

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res and res not in valid_results:
                    valid_results.append(res)
                    if len(valid_results) >= MAX_LIMIT_PER_REGION:
                        break

        print(f"{region} 地区完成，获取 {len(valid_results)} 个有效 IP。")
        
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_results))

        all_region_results.extend(valid_results)

    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

if __name__ == "__main__":
    main()
