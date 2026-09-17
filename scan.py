import concurrent.futures
import ipaddress
import random
import socket
import time

MAX_LIMIT_PER_REGION = 150  # 每个地区保留有效 IP 数
TIMEOUT = 1.5                # 适当放宽超时，避免误杀国内高延迟直连 IP

# 精准筛选的 Cloudflare / 第三方反代优质网段
REGION_PROXY_CIDRS = {
    "JP": [
        "103.200.112.0/23", "103.152.220.0/22", "157.7.0.0/16", 
        "150.95.0.0/16", "133.130.0.0/16", "45.76.96.0/19", "139.162.64.0/18"
    ],
    "TW": [
        "103.147.20.0/22", "103.130.208.0/22", "61.216.0.0/13", 
        "210.61.0.0/16", "35.221.128.0/17", "118.163.0.0/16"
    ],
    "SG": [
        "103.213.244.0/22", "128.199.0.0/16", "139.59.0.0/16", 
        "13.228.0.0/15", "18.136.0.0/15", "45.32.96.0/19"
    ],
    "US": [
        "154.21.0.0/16", "154.22.0.0/16", "154.3.0.0/16",
        "104.236.0.0/16", "157.230.0.0/16", "107.170.0.0/16", "143.198.0.0/16"
    ]
}

def verify_ip(ip_str, port, region):
    """验证端口联通性，并带上精准格式的节点备注"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip_str, port))
        s.close()
        # 输出标准格式：IP:Port#地区-IP
        return f"{ip_str}:{port}#{region}-{ip_str}"
    except Exception:
        return None

def main():
    all_region_results = []
    start_time = time.time()

    for region, cidrs in REGION_PROXY_CIDRS.items():
        print(f"=== 开始扫描 {region} 地区节点 ===")
        candidate_ips = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            sample_count = min(len(hosts), 800)
            candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])

        valid_results = []
        random.shuffle(candidate_ips)

        # 100 线程并发
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(verify_ip, ip, 443, region) for ip in candidate_ips]

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res and res not in valid_results:
                    valid_results.append(res)
                    if len(valid_results) >= MAX_LIMIT_PER_REGION:
                        break

        print(f"{region} 地区扫描完成，共找到 {len(valid_results)} 个可连通 IP。")
        
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_results))

        all_region_results.extend(valid_results)

    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

    print(f"全部扫描完成，耗时: {round(time.time() - start_time, 2)} 秒，共生成 {len(all_region_results)} 个节点。")

if __name__ == "__main__":
    main()
