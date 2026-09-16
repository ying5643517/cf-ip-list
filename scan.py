import concurrent.futures
import ipaddress
import random
import socket
import urllib.request

MAX_LIMIT_PER_REGION = 300
PORTS = [443, 8443, 2053, 2083]

# 严格校验过的 Cloudflare 官方 IPv4 网段
REGION_CIDRS = {
    "US": [
        "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15"
    ],
    "SG": [
        "104.28.0.0/16", "172.67.0.0/16", "103.21.244.0/22"
    ],
    "TW": [
        "104.28.128.0/17", "162.158.128.0/17", "103.31.4.0/22", "172.68.0.0/16"
    ],
    "JP": [
        "104.28.0.0/16", "172.69.0.0/16", "103.22.200.0/22", "162.158.64.0/18"
    ]
}

def verify_ip(ip_str, port, region):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        s.connect((ip_str, port))
        s.close()

        req_url = f"http://{ip_str}:{port}/"
        req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            urllib.request.urlopen(req, timeout=1.2)
        except urllib.error.HTTPError as e:
            server_header = e.headers.get("Server", "").lower()
            if "cloudflare" in server_header or e.code in [400, 403, 405]:
                return f"{ip_str}:{port}#{region}-v4-{ip_str}"
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
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            sample_count = min(len(hosts), 1000)
            candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])

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
