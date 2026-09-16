import concurrent.futures
import ipaddress
import random
import socket

MAX_LIMIT_PER_REGION = 300
PORTS = [443, 8443, 2053, 2083]

# 针对中国大陆网络优化的亚洲及美洲核心 IP 网段池
REGION_PROXY_CIDRS = {
    "JP": [
        # 原有网段
        "103.200.112.0/23", "103.152.220.0/22", "157.7.0.0/16", 
        "150.95.0.0/16", "133.130.0.0/16", "45.76.96.0/19", "139.162.64.0/18",
        # 新增国内直连优化段 (IIJ, NTT, KDDI, ConoHa)
        "210.140.0.0/16", "118.238.0.0/16", "202.232.0.0/16",
        "160.16.0.0/16",  "118.27.0.0/16",  "133.242.0.0/16",
        "219.117.0.0/16", "222.158.0.0/16"
    ],
    "TW": [
        # 原有网段
        "103.147.20.0/22", "103.130.208.0/22", "61.216.0.0/13", 
        "210.61.0.0/16", "35.221.128.0/17", "118.163.0.0/16",
        # 新增 HiNet / 方曙 / 远传等台湾本地直连段
        "220.130.0.0/16", "211.20.0.0/16",  "163.28.0.0/16",
        "59.120.0.0/14",  "114.32.0.0/12",  "103.234.80.0/22"
    ],
    "SG": [
        # 原有网段
        "103.213.244.0/22", "128.199.0.0/16", "139.59.0.0/16", 
        "13.228.0.0/15", "18.136.0.0/15", "45.32.96.0/19",
        # 新增 Singtel / StarHub / 东南亚优质云网段
        "203.116.0.0/16", "116.12.0.0/14",  "103.28.108.0/22",
        "180.129.0.0/16", "103.253.24.0/22", "43.255.188.0/22"
    ],
    "US": [
        # 原有网段 & 154 系列网段
        "154.21.0.0/16", "154.22.0.0/16", "154.3.0.0/16",
        "104.236.0.0/16", "157.230.0.0/16", "107.170.0.0/16", 
        "198.51.100.0/22", "54.144.0.0/12", "143.198.0.0/16",
        # 新增美洲大带宽出口段 (Anexia, Cogent, HE, Level3)
        "154.85.0.0/16",  "154.208.0.0/16", "199.195.240.0/22",
        "38.122.0.0/16",  "64.71.128.0/18",  "12.234.0.0/16"
    ]
}

def verify_ip(ip_str, port, region):
    """检测 IP 端口连通性"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip_str, port))
        s.close()
        return f"{ip_str}:{port}"
    except Exception:
        return None

def main():
    all_region_results = []

    for region, cidrs in REGION_PROXY_CIDRS.items():
        print(f"=== 开始扫描 {region} 地区优选节点 IP ===")
        candidate_ips = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            sample_count = min(len(hosts), 2000)
            candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])

        valid_results = []
        random.shuffle(candidate_ips)

        # 120 线程并发测试
        with concurrent.futures.ThreadPoolExecutor(max_workers=120) as executor:
            futures = [executor.submit(verify_ip, ip, random.choice(PORTS), region) for ip in candidate_ips]

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res and res not in valid_results:
                    valid_results.append(res)
                    if len(valid_results) >= MAX_LIMIT_PER_REGION:
                        break

        print(f"{region} 地区扫描完成，获取到 {len(valid_results)} 个可用节点 IP。")
        
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_results))

        all_region_results.extend(valid_results)

    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

if __name__ == "__main__":
    main()
