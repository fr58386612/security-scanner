import ipaddress

def read_ips_from_file(filepath="ip.txt"):
    """
    从指定文件中读取IP地址列表。

    Args:
        filepath (str): 包含IP地址的文件路径。

    Returns:
        list: IP地址字符串列表。如果文件不存在或为空，则返回空列表。
    """
    ips = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'): # 忽略空行和注释行
                    try:
                        # 验证是否为有效的IP地址 (可选，但推荐)
                        ipaddress.ip_address(line)
                        ips.append(line)
                    except ValueError:
                        print(f"[WARNING] 文件 '{filepath}' 中的无效IP地址: {line}")
    except FileNotFoundError:
        print(f"[ERROR] IP地址文件 '{filepath}' 未找到。")
    return ips

if __name__ == '__main__':
    # 测试代码
    ip_list = read_ips_from_file()
    if ip_list:
        print(f"从 ip.txt 读取到的IP地址: {ip_list}")
    
    # 测试不存在的文件
    non_existent_ips = read_ips_from_file("non_existent_ips.txt")
    print(f"尝试读取不存在的文件: {non_existent_ips}")

    # 测试包含无效IP的文件
    with open("test_ips_invalid.txt", "w") as f:
        f.write("192.168.1.1\n")
        f.write("not_an_ip\n")
        f.write("10.0.0.1\n")
    invalid_ips_test = read_ips_from_file("test_ips_invalid.txt")
    print(f"从 test_ips_invalid.txt 读取到的IP地址: {invalid_ips_test}")