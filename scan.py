import concurrent.futures
import ipaddress
import random
import socket
import urllib.request

MAX_LIMIT_PER_REGION = 300
PORTS = [443, 8443, 2053, 2083]

# 第三方云厂商（Oracle, AWS, GCP, DO, Linode 等）常用于反代 CF 的公网 CIDR 网段
REGION_PROXY_CIDRS = {
    "JP": [
        "150.95.0.0/16",    # ConoHa / Sakura Japan
        "132.145.0.0/16",   # Oracle Tokyo
        "140.238.0.0/16",   # Oracle Tokyo
        "152.69.192.0/18",  # Oracle Osaka
        "13.112.0.0/14",    # AWS Tokyo
        "35.72.0.0/13",     # AWS Tokyo
        "133.130.0.0/16",   # GMO / Z.com Japan
    ],
    "TW": [
        "103.147.20.0/22",  # Taiwan Chief Telecom / HiNet
        "34.80.0.0/14",     # GCP Changhua Taiwan
        "35.221.128.0/17",  # GCP Taiwan
        "61.216.0.0/13",    # HiNet Taiwan
        "210.61.0.0/16"     # HiNet Taiwan
    ],
    "SG": [
        "129.150.0.0/16",   # Oracle Singapore
        "140.238.192.0/18", # Oracle Singapore
        "13.228.0.0/15",    # AWS Singapore
        "18.136.0.0/15",    # AWS Singapore
        "128.199.0.0/16",   # DigitalOcean Singapore
        "139.59.0.0/16"     # DigitalOcean Singapore
    ],
    "US": [
        "129.213.0.0/16",   # Oracle US
        "130.61.0.0/16",    # Oracle US
        "52.0.0.0/11",      # AWS US
        "54.144.0.0/12",    # AWS US
        "157.230.0.0/16",   # DigitalOcean US
        "104.236.0.0/16"    # DigitalOcean US
    ]
}

def verify_proxy_ip(ip_str, port, region):
    """验证目标 IP 是否支持 Cloudflare 反代/中转功能"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        s.connect((ip_str, port))
        s.close()

        # 发送带反代特征头的请求验证
        req_url = f"http://{ip_str}:{port}/"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Host": "icook.tw"  # 广泛用于测试 CF 反代接管能力的测试 Host
        }
        req = urllib.request.Request(req_url, headers=headers)
        
        try:
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                # 能正常响应 200/301/302 或返回 CF 特征标头说明是有效反代 IP
                server_header = resp.headers.get("Server", "").lower()
                if "cloudflare" in server_header or resp.status in [200, 301, 302]:
                    return f"{ip_str}:{port}#{region}-Proxy-{ip_str}"
        except urllib.error.HTTPError as e:
            server_header = e.headers.get("Server", "").lower()
            if "cloudflare" in server_header or e.code in [400, 403, 405, 502, 503]:
                return f"{ip_str}:{port}#{region}-Proxy-{ip_str}"
        except Exception:
            pass
    except Exception:
        pass
    return None

def main():
    all_region_results = []

    for region, cidrs in REGION_PROXY_CIDRS.items():
        print(f"=== 开始扫描 {region} 地区反代中转 IP ===")
        candidate_ips = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            sample_count = min(len(hosts), 1200)
            candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])

        valid_results = []
        random.shuffle(candidate_ips)

        # 80 线程并发跑反代扫描
        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
            futures = [executor.submit(verify_proxy_ip, ip, random.choice(PORTS), region) for ip in candidate_ips]

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res and res not in valid_results:
                    valid_results.append(res)
                    if len(valid_results) >= MAX_LIMIT_PER_REGION:
                        break

        print(f"{region} 地区扫描完成，获取 {len(valid_results)} 个有效反代 IP。")
        
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_results))

        all_region_results.extend(valid_results)

    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

if __name__ == "__main__":
    main()
