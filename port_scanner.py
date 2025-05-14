import subprocess
import xml.etree.ElementTree as ET

# 端口和服务映射，主要用于Hydra兼容性
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http-get",
    110: "pop3",
    143: "imap",
    443: "https-get",
    445: "smb",
    1433: "mssql",
    1521: "oracle-listener",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc"
}

DEFAULT_PORTS_TO_SCAN = list(PORT_SERVICE_MAP.keys())

def parse_nmap_xml_output(xml_output):
    """
    解析 Nmap XML 输出并提取开放的端口和服务。
    """
    open_services_by_ip = {}
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            ports_element = host.find('ports')
            if ports_element is None:
                continue

            open_ports_for_ip = []
            for port_element in ports_element.findall('port'):
                if port_element.find('state').get('state') == 'open':
                    port_id = int(port_element.get('portid'))
                    service_element = port_element.find('service')
                    nmap_service_name = "unknown"
                    if service_element is not None and service_element.get('name'):
                        nmap_service_name = service_element.get('name')
                    
                    # 优先使用 PORT_SERVICE_MAP 中的服务名以兼容 Hydra
                    # 如果端口不在 PORT_SERVICE_MAP 中，则尝试使用 nmap 提供的服务名
                    # 如果 nmap 也没有提供，则为 "unknown"
                    hydra_service_name = PORT_SERVICE_MAP.get(port_id, nmap_service_name)
                    
                    open_ports_for_ip.append((port_id, hydra_service_name))
            
            if open_ports_for_ip:
                open_services_by_ip[ip_address] = open_ports_for_ip
    except ET.ParseError as e:
        print(f"[ERROR] 解析 Nmap XML 输出失败: {e}")
        print(f"[DEBUG] XML Output was: {xml_output}")
    return open_services_by_ip

def scan_multiple_ips(ip_list, custom_ports_str=None):
    """
    使用 Nmap 扫描IP地址列表中的指定端口。
    Args:
        ip_list (list): IP地址字符串列表.
        custom_ports_str (str, optional): 逗号分隔的自定义端口号字符串.
    """
    ports_to_scan_str = ""
    if custom_ports_str:
        try:
            parsed_ports = [p.strip() for p in custom_ports_str.split(',') if p.strip().isdigit()]
            if parsed_ports:
                ports_to_scan_str = ",".join(parsed_ports)
                print(f"[INFO] 将使用 Nmap 扫描自定义端口列表: {ports_to_scan_str}")
            else:
                print("[WARNING] 自定义端口列表为空或格式不正确，将使用默认端口列表进行 Nmap 扫描。")
        except Exception: # 更广泛地捕获解析错误
            print("[WARNING] 解析自定义端口列表时出错，将使用默认端口列表进行 Nmap 扫描。")

    if not ports_to_scan_str: # 如果自定义端口处理失败或未提供
        ports_to_scan_str = ",".join(map(str, DEFAULT_PORTS_TO_SCAN))
        print(f"[INFO] 将使用 Nmap 扫描默认端口列表: {ports_to_scan_str}")

    if not ip_list:
        print("[ERROR] IP列表为空，无法执行Nmap扫描。")
        return {}

    # 构建 Nmap 命令
    # -Pn: 无ping扫描 (假设主机在线)
    # -sT: TCP connect() 扫描 (更可靠，但可能较慢且易被检测)
    # -p: 指定端口
    # -oX -: XML输出到标准输出
    # --open: 只显示开放的端口
    nmap_command = ["nmap", "-Pn", "-sT", "-p", ports_to_scan_str, "--open", "-oX", "-"] + ip_list
    
    print(f"[INFO] 执行 Nmap 命令: {' '.join(nmap_command)}")

    try:
        process = subprocess.run(nmap_command, capture_output=True, text=True, check=True, timeout=300) # 5分钟超时
        if process.stdout:
            return parse_nmap_xml_output(process.stdout)
        else:
            print("[ERROR] Nmap 未返回任何输出。")
            if process.stderr:
                print(f"[NMAP_STDERR] {process.stderr.strip()}")
            return {}
    except FileNotFoundError:
        print("[ERROR] Nmap 命令未找到。请确保 Nmap 已安装并在系统 PATH 中。")
        return {}
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nmap 执行失败，返回码: {e.returncode}")
        if e.stdout:
            print(f"[NMAP_STDOUT] {e.stdout.strip()}")
        if e.stderr:
            print(f"[NMAP_STDERR] {e.stderr.strip()}")
        return {}
    except subprocess.TimeoutExpired:
        print("[ERROR] Nmap 执行超时。")
        return {}
    except Exception as e:
        print(f"[ERROR] 执行 Nmap 时发生未知错误: {e}")
        return {}

if __name__ == '__main__':
    # 测试代码
    # 确保你的机器上安装了 Nmap 并且在 PATH 中
    # 你可能需要根据你的环境修改这里的测试IP和预期结果
    # 例如，在本地启动一个简单的HTTP服务器: python -m http.server 8080
    # 然后用自定义端口测试: test_ips_custom = ["127.0.0.1"], custom_ports = "8080,22"
    
    test_ips_default = ["127.0.0.1"] 
    # 确保你的机器上至少有一个默认列表中的端口是开放的，例如 SSH (22) 或本地HTTP (80)
    print(f"开始使用 Nmap 扫描IP: {test_ips_default} 针对默认端口")
    scan_results_default = scan_multiple_ips(test_ips_default)

    if scan_results_default:
        print("\nNmap 默认端口扫描结果:")
        for ip, open_ports in scan_results_default.items():
            print(f"  IP: {ip}")
            for port, service in open_ports:
                print(f"    - Port {port} ({service}) is open")
    else:
        print("\nNmap 默认端口扫描未发现开放端口。")

    print("-" * 30)

    # 测试自定义端口
    test_ips_custom = ["127.0.0.1"]
    # 假设你在 127.0.0.1 的 8080 端口运行了一个服务
    custom_ports_test = "8080,22,9999" # 9999 应该是不开放的
    print(f"\n开始使用 Nmap 扫描IP: {test_ips_custom} 针对自定义端口: {custom_ports_test}")
    scan_results_custom = scan_multiple_ips(test_ips_custom, custom_ports_str=custom_ports_test)
    
    if scan_results_custom:
        print("\nNmap 自定义端口扫描结果:")
        for ip, open_ports in scan_results_custom.items():
            print(f"  IP: {ip}")
            for port, service in open_ports:
                print(f"    - Port {port} ({service}) is open")
    else:
        print("\nNmap 自定义端口扫描未发现开放端口。")

    print("-" * 30)
    
    # 测试一个通常不可达的IP
    test_ips_unreachable = ["192.0.2.1"] # RFC 5737 TEST-NET-1
    print(f"\n开始使用 Nmap 扫描不可达IP: {test_ips_unreachable} (预期无开放端口)")
    scan_results_unreachable = scan_multiple_ips(test_ips_unreachable)
    if not scan_results_unreachable:
        print("Nmap 扫描完成，没有发现开放端口，符合预期。")
    else:
        print(f"Nmap 意外发现开放端口: {scan_results_unreachable}")
