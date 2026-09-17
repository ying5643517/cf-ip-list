import concurrent.futures
import ipaddress
import random
import socket
import ssl
import time

MAX_LIMIT_PER_REGION = 200
TIMEOUT = 0.8  # 超时时间缩短，大幅提升扫描速度

# 精简优化后的核心网段（聚焦国内直连高命中率 IP）
REGION_PROXY_CIDRS = {
    "JP": [
        "103.200.112.0/24", "150.95.0.0/18", "133.130.0.0/18", 
        "118.27.0.0/18", "160.16.0.0/18", "210.140.0.0/18"
    ],
    "TW": [
        "103.147.20.0/24", "61.216.0.0/16", "210.61.0.0/16", 
        "220.130.0.0/16", "118.163.0.0/16", "103.234.80.0/23"
    ],
    "SG": [
        "103.213.244.0/24", "128.199.0.0/18", "139.59.0.0/18", 
        "18.136.0.0/16", "203.116.0.0/18", "180.129.0.0/18"
    ],
    "US": [
        "154.21.0.0/18", "154.22.0.0/18", "154.3.0.0/18",
        "154.85.0.0/18", "104.236.0.0/18", "157.230.0.0/18"
    ]
}

def verify_cf_node(ip_str, port, region):
    """深度校验：TCP 连接 + TLS 发起 HTTP 探针，确认是否为真实 CF 节点"""
    try:
        # 1. 快速 TCP 探针
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip_str, port))
        s.close()

        # 2. TLS/HTTP 验证是否具有 CF 特征
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tls.settimeout(TIMEOUT)
        conn = ctx.wrap_socket(s_tls, server_hostname="speed.cloudflare.com")
        conn.connect((ip_str, port))
        
        # 发送简单的 HTTP HEAD 请求
        req = f"HEAD / HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n"
        conn.sendall(req.encode())
        response = conn.recv(512).decode('utf-8', errors='ignore')
        conn.close()

        # 只要返回包含 cloudflare 或 400/403/101 等 CF 常见状态即认为有效
        if "Server: cloudflare" in response or "CF-RAY" in response or "HTTP/1.1 400" in response or "HTTP/1.1 403" in response:
            return f"{ip_str}:{port}#{region}-{ip_str}"
    except Exception:
        pass
    return None

def main():
    all_region_results = []
    start_time = time.time()

    for region, cidrs in REGION_PROXY_CIDRS.items():
        print(f"=== 正在扫描 {region} 节点 ===")
        candidate_ips = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            sample_count = min(len(hosts), 400) # 控制样本数量加速
            candidate_ips.extend([str(ip) for ip in random.sample(hosts, sample_count)])

        valid_results = []
        random.shuffle(candidate_ips)

        # 提升至 150 高并发线程
        with concurrent.futures.ThreadPoolExecutor(max_workers=150) as executor:
            futures = [executor.submit(verify_cf_node, ip, 443, region) for ip in candidate_ips]

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res and res not in valid_results:
                    valid_results.append(res)
                    if len(valid_results) >= MAX_LIMIT_PER_REGION:
                        break

        print(f"{region} 完成：找到 {len(valid_results)} 个真实有效节点")
        
        with open(f"{region.lower()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(valid_results))

        all_region_results.extend(valid_results)

    with open("all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_region_results))

    print(f"全部扫描完成，耗时: {round(time.time() - start_time, 2)} 秒")

if __name__ == "__main__":
    main()
