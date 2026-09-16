import concurrent.futures
import ipaddress
import random
import socket
import urllib.request

MAX_TOTAL_PER_REGION = 300
TARGET_IPV6_LIMIT = 100
PORTS = [443, 8443, 2053, 2083]

# 地区 CIDR 配置 (分 IPv4 与 IPv6 列表)
REGION_CIDRS = {
    "US": {
        "v6": ["2606:4700::/32", "2606:4700:3030::/48"],
        "v4": ["104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15"]
    },
    "SG": {
        "v6": ["2400:cb00::/32", "2606:4700:d0::/32"],
        "v4": ["104.28.0.0/16", "172.67.0.0/16", "103.21.244.0/22"]
    },
    "TW": {
        "v6": ["2606:4700:d0::/32", "2400:cb00:2048::/32"],
        "v4": ["104.28.128.0/17", "162.158.128.0/17", "103.31.4.0/22", "172.68.0.0/16"]
    },
    "JP": {
        "v6": ["2606:4700:d1::/32", "2400:cb00:2048::/32"],
        "v4": ["104.28.0.0/16", "172.69.0.0/16", "103.22.200.0/22", "162.158.64.0/18"]
    }
}

def verify_ip(ip_str, port, region):
    """测试 TCP 握手及 HTTP 响应的合法性"""
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
        # 网络环境不支持 IPv6 或网络不可达时优雅退出
        pass
    except Exception:
        pass
    return None

def generate_random_ipv6(cidr_str, count=400):
    """安全生成指定 IPv6 网段的随机节点"""
    results = []
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
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

def scan_candidates(candidates, region, max_needed):
    """通用多线程扫描逻辑"""
    if max_needed <= 0 or not candidates:
        return []
    
    valid_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
        futures = [executor.submit(verify_ip, ip, random.choice(PORTS), region) for ip in candidates]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res and res not in valid_results:
                valid_results.append(res)
                if len(valid_results) >= max_needed:
                    break
    return valid_results

def main():
    all_region_results = []

    for region, config in REGION_CIDRS.items():
        print(f"=== 开始扫描 {region} 地区节点 ===")
        region_valid_ips = []

        # 阶段 1: 扫描 IPv6 (目标 100 个)
        v6_candidates = []
        for cidr in config.get("v6", []):
            v6_candidates.extend(generate_random_ipv6(cidr, count=400))
        random.shuffle(v6_candidates)

        v6_results = scan_candidates(v6_candidates, region, TARGET_IPV6_LIMIT)
        region_valid_ips.extend(v6_results)
        print(f"{region} 地区 IPv6 获取到 {len(v6_results)} 个节点。")

        # 阶段 2: 计算剩余配额，使用 IPv4 补充到 300 个
        remaining_needed = MAX_TOTAL_PER_REGION - len(region_valid_ips)
        if remaining_needed > 0:
            print(f"{region} 地区需要补充 {remaining_needed} 个 IPv4 节点...")
            v4_candidates = []
            for cidr in config.get("v4", []):
                net = ipaddress.ip_network(cidr, strict=False)
                hosts = list(net.hosts())
                sample_count = min(len(hosts), 800)
                v4_candidates.extend([str(ip) for ip in random.sample(hosts, sample_count)])
            random.shuffle(v4_candidates)

            v4_results = scan_candidates(v4_candidates, region, remaining_needed)
            region_valid_ips.extend(v4_results)
            print(f"{region} 地区 IPv4 获取到 {len(v4_results)} 个节点。")

        print(f"{region} 地区扫描结束，共计 {len(region_valid_ips)} 个节点。")

        # 写入地区文件
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(region_valid_ips))

        all_region_results.extend(region_valid_ips)

    # 写入汇总文件
    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

if __name__ == "__main__":
    main()
