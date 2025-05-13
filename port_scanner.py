import socket
import threading
from queue import Queue

# 端口和服务映射，根据 security_scanner_plan.md
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http-get", # Hydra 使用 http-get
    110: "pop3",
    143: "imap",
    443: "https-get", # Hydra 使用 https-get
    445: "smb",
    1433: "mssql",
    1521: "oracle-listener", # Hydra 可能需要特定模块或调整
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc"
}

# 要扫描的端口列表
DEFAULT_PORTS_TO_SCAN = list(PORT_SERVICE_MAP.keys())

# 线程数
MAX_THREADS = 20 # 可以根据实际情况调整

# 扫描单个端口
def scan_port(ip, port, open_ports_for_ip, custom_scan=False):
    """
    尝试连接到指定IP的指定端口。
    如果端口开放，则将其添加到 open_ports_for_ip 列表中。
    Args:
        ip (str): 目标IP.
        port (int): 目标端口.
        open_ports_for_ip (list): 用于收集此IP开放端口的列表.
        custom_scan (bool): 如果为True，表示是自定义端口扫描，服务名可能未知.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 连接超时时间1秒
        result = sock.connect_ex((ip, port))
        if result == 0:
            if custom_scan:
                # 对于自定义端口，如果不在已知映射中，尝试通用获取或标记为unknown_custom
                service_name = PORT_SERVICE_MAP.get(port)
                if not service_name:
                    try:
                        service_name = socket.getservbyport(port)
                    except OSError: # OSError if port/protocol not found
                        service_name = f"unknown_custom_port_{port}" # Mark distinctly
                # For Hydra, we still need a protocol string.
                # If it's a custom port not in PORT_SERVICE_MAP, Hydra might not work unless it's a common service on a non-standard port.
                # We will rely on PORT_SERVICE_MAP for Hydra compatibility.
                # If a custom port is scanned and open, but not in PORT_SERVICE_MAP, it won't be Hydra'd unless user knows the protocol.
                # For now, let's stick to PORT_SERVICE_MAP for service_name used by Hydra.
                # The display can show the getservbyport result.
                display_service_name = PORT_SERVICE_MAP.get(port, f"unknown_port_{port}") # Default for display
                try:
                    display_service_name = socket.getservbyport(port)
                except OSError:
                    pass # keep the default if getservbyport fails
                
                # For Hydra, the service_name must be one it understands.
                # We will use the one from PORT_SERVICE_MAP if available, otherwise it's effectively un-Hydra-able by default.
                hydra_service_name = PORT_SERVICE_MAP.get(port, "unknown") # Use this for the tuple passed to Hydra
                open_ports_for_ip.append((port, hydra_service_name)) # hydra_service_name for consistency
                # print(f"[SCAN] IP: {ip}, Port: {port} ({display_service_name}) is open.")

            else: # Not a custom scan, or custom port is in PORT_SERVICE_MAP
                service_name = PORT_SERVICE_MAP.get(port, "unknown")
                open_ports_for_ip.append((port, service_name))
                # print(f"[SCAN] IP: {ip}, Port: {port} ({service_name}) is open.")
        sock.close()
    except socket.error as e:
        # print(f"[SCAN_ERROR] IP: {ip}, Port: {port}, Error: {e}")
        pass # 静默处理连接错误

# 扫描单个IP的所有指定端口
def scan_ip(ip, ports_to_scan, is_custom_scan=False):
    """
    扫描单个IP地址的指定端口列表。
    Args:
        ip (str): 目标IP.
        ports_to_scan (list): 要扫描的端口号列表.
        is_custom_scan (bool): 是否为自定义端口列表扫描.
    """
    # print(f"[INFO] Scanning IP: {ip} for ports: {ports_to_scan}")
    open_ports_for_ip = []
    threads = []
    for port in ports_to_scan:
        thread = threading.Thread(target=scan_port, args=(ip, port, open_ports_for_ip, is_custom_scan))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    
    return ip, open_ports_for_ip

# 主扫描函数，使用线程池处理多个IP
def scan_multiple_ips(ip_list, custom_ports_str=None):
    """
    扫描IP地址列表中的所有指定端口。
    Args:
        ip_list (list): IP地址字符串列表.
        custom_ports_str (str, optional): 逗号分隔的自定义端口号字符串.
    """
    ports_to_scan_final = []
    is_custom_port_scan = False

    if custom_ports_str:
        try:
            ports_to_scan_final = [int(p.strip()) for p in custom_ports_str.split(',') if p.strip().isdigit()]
            if not ports_to_scan_final:
                print("[WARNING] 自定义端口列表为空或格式不正确，将使用默认端口列表。")
                ports_to_scan_final = DEFAULT_PORTS_TO_SCAN
            else:
                print(f"[INFO] 将扫描自定义端口列表: {ports_to_scan_final}")
                is_custom_port_scan = True
        except ValueError:
            print("[WARNING] 自定义端口列表包含无效数字，将使用默认端口列表。")
            ports_to_scan_final = DEFAULT_PORTS_TO_SCAN
    else:
        ports_to_scan_final = DEFAULT_PORTS_TO_SCAN
        print(f"[INFO] 将扫描默认端口列表: {ports_to_scan_final}")


    results = {}
    task_queue = Queue()
    
    for ip in ip_list:
        task_queue.put(ip)

    def worker():
        while not task_queue.empty():
            try:
                current_ip = task_queue.get_nowait()
            except Queue.Empty:
                break
            
            # print(f"[THREAD_WORKER] Scanning IP: {current_ip}")
            ip_addr, open_ports = scan_ip(current_ip, ports_to_scan_final, is_custom_port_scan)
            if open_ports:
                results[ip_addr] = open_ports
            task_queue.task_done()

    threads = []
    for _ in range(min(MAX_THREADS, len(ip_list))):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    task_queue.join() # 等待队列中的所有任务完成

    for thread in threads:
        thread.join() # 确保所有工作线程都已结束

    return results

if __name__ == '__main__':
    # 测试代码
    # 假设我们有一个本地的FTP服务器在 127.0.0.1:21 和 HTTP 服务器在 127.0.0.1:80
    # 你可能需要根据你的环境修改这里的测试IP和预期结果
    test_ips = ["127.0.0.1"] 
    
    print(f"开始扫描IP: {test_ips} 针对端口: {DEFAULT_PORTS_TO_SCAN}")
    scan_results = scan_multiple_ips(test_ips)

    if scan_results:
        print("\n扫描结果:")
        for ip, open_ports in scan_results.items():
            print(f"  IP: {ip}")
            for port, service in open_ports:
                print(f"    - Port {port} ({service}) is open")
    else:
        print("\n没有发现开放端口。")

    # 测试一个不存在的IP或没有开放端口的IP
    test_ips_no_open = ["192.0.2.1"] # RFC 5737 TEST-NET-1, 应该不可达
    print(f"\n开始扫描IP: {test_ips_no_open} (预期无开放端口)")
    scan_results_no_open = scan_multiple_ips(test_ips_no_open)
    if not scan_results_no_open:
        print("扫描完成，没有发现开放端口，符合预期。")
    else:
        print(f"意外发现开放端口: {scan_results_no_open}")