import concurrent.futures
import ipaddress
import random
import socket
import urllib.request

MAX_LIMIT_PER_REGION = 300
PORTS = [443, 8443, 2053, 2083]

REGION_CIDRS = {
    "US": [
        "104.16.0.0/12", "172.64.0.0/13",
        "2606:4700::/32"
    ],
    "SG": [
        "104.28.0.0/16", "172.67.0.0/16",
        "2400:cb00::/32"
    ],
    "TW": [
        "104.28.128.0/17", "162.158.128.0/17",
        "2606:4700:d0::/48"
    ],
    "JP": [
        "104.28.0.0/16", "172.69.0.0/16",
        "2606:4700:d1::/48"
    ]
}

def verify_ip(ip_str, port, region):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        is_ipv6 = ip_obj.version == 6
        formatted_ip = f"[{ip_str}]" if is_ipv6 else ip_str
        
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip_str, port))
        s.close()

        req_url = f"http://{formatted_ip}:{port}/"
        req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            urllib.request.urlopen(req, timeout=1.0)
        except urllib.error.HTTPError as e:
            server_header = e.headers.get("Server", "").lower()
            if "cloudflare" in server_header or e.code in [400, 403, 405]:
                ip_type = "v6" if is_ipv6 else "v4"
                return f"{formatted_ip}:{port}#{region}-{ip_type}-{ip_str}"
        except Exception:
            pass
    except Exception:
        pass
    return None

def main():
    all_region_results = []

    for region, cidrs in REGION_CIDRS.items():
        print(f"=== 开始扫描 {region} 地区节点 ===")
        candidate_ips = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr)
            if net.version == 4:
                hosts = list(net.hosts())
                sample_count = min(len(hosts), 600)
                candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])
            else:
                prefix = str(net.network_address)[:-1]
                for _ in range(300):
                    rand_suffix = ":".join(f"{random.randint(0, 65535):x}" for _ in range(4))
                    candidate_ips.append(f"{prefix}{rand_suffix}")

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
        
        # 写入地区文件
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_results))

        all_region_results.extend(valid_results)

    # 写入汇总文件
    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

if __name__ == "__main__":
    main()
