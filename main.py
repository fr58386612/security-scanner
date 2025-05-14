import time
import os
# import json # No longer using json for open ports output
import shutil # For removing directory
import argparse # For command-line arguments
import csv # For CSV output

from ip_reader import read_ips_from_file
from port_scanner import scan_multiple_ips, PORT_SERVICE_MAP
from hydra_attacker import attack_multiple_services, HYDRA_PATH, TEMP_DIR # Import TEMP_DIR

def main():
    parser = argparse.ArgumentParser(description="Python Security Scanner with Port Scanning and Hydra Brute-forcing.")
    parser.add_argument("-UL", "--user-list", help="Path to a custom username list file for Hydra.")
    parser.add_argument("-PL", "--pass-list", help="Path to a custom password list file for Hydra.")
    parser.add_argument("-IP", "--ip-file", default="ip.txt", help="Path to the file containing target IP addresses (default: ip.txt).")
    parser.add_argument("-P", "--ports", help="Comma-separated list of custom ports to scan (e.g., 80,443,8080). Overrides default port list.")
    args = parser.parse_args()

    start_time = time.time()
    print("[INFO] 安全扫描程序启动...")

    # 1. 读取IP地址
    print(f"[INFO] 正在从 {args.ip_file} 读取目标IP地址...")
    target_ips = read_ips_from_file(args.ip_file)

    if not target_ips:
        print(f"[ERROR] 未能从 {args.ip_file} 读取到任何IP地址，程序退出。")
        return

    print(f"[INFO] 读取到 {len(target_ips)} 个IP地址: {target_ips}")

    # 2. 端口扫描
    print("\n[INFO] 开始端口扫描...")
    open_services_by_ip = scan_multiple_ips(target_ips, custom_ports_str=args.ports)

    if not open_services_by_ip:
        print("[INFO] 端口扫描完成，没有在任何目标IP上发现指定的开放端口。程序退出。")
        end_time = time.time()
        print(f"\n[INFO] 总耗时: {end_time - start_time:.2f} 秒。")
        return

    print("\n[INFO] 端口扫描完成。发现以下开放服务:")
    for ip, services in open_services_by_ip.items():
        print(f"  IP: {ip}")
        for port, service_name in services:
            print(f"    - Port {port} ({service_name}) is open")

    # 保存开放端口结果到 CSV 文件
    open_ports_csv_file = "open_ports_results.csv"
    try:
        with open(open_ports_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # 写入表头
            csv_writer.writerow(["IP Address", "Open Ports & Services"])
            
            for ip, services in open_services_by_ip.items():
                if services: # If there are open ports for this IP
                    ports_services_str_list = []
                    for port, service_name in services:
                        ports_services_str_list.append(f"{port}({service_name})")
                    csv_writer.writerow([ip, ", ".join(ports_services_str_list)])
                else: # If an IP had no open ports
                    csv_writer.writerow([ip, "No open ports found"])
        print(f"\n[INFO] 开放端口信息已保存到 {open_ports_csv_file}")
    except IOError as e:
        print(f"\n[WARNING] 保存开放端口信息到 CSV 文件 '{open_ports_csv_file}' 失败: {e}")

    # 3. Hydra爆破
    print("\n[INFO] 开始对发现的开放服务进行Hydra爆破...")
    
    # 检查Hydra是否存在
    try:
        # 在Windows上，如果hydra在PATH中，可以直接调用'hydra'。如果不在，需要完整路径。
        # subprocess.run的shell=True参数在安全上有风险，应尽量避免。
        # check=False允许我们处理命令未找到或执行失败的情况。
        # 为了更好的跨平台兼容性和错误处理，这里不使用shell=True。
        # 注意：HYDRA_PATH 应该被配置为指向 Hydra 可执行文件的正确路径。
        # 例如 '/usr/bin/hydra' 或 'C:\\Hydra\\hydra.exe'
        # 如果 HYDRA_PATH 只是 'hydra'，则它必须在系统的 PATH 环境变量中。
        process_result = subprocess.run([HYDRA_PATH, "-h"], capture_output=True, text=True, check=False, timeout=10)
        if process_result.returncode != 0 and "not found" in process_result.stderr.lower(): # 更通用的检查方式
             raise FileNotFoundError # 模拟未找到文件错误
    except FileNotFoundError:
        print(f"[ERROR] Hydra 命令 '{HYDRA_PATH}' 未找到。请确保Hydra已安装并在系统PATH中，或者 HYDRA_PATH 指向正确的路径。程序退出。")
        return
    except subprocess.TimeoutExpired:
        print(f"[ERROR] 检查 Hydra 命令 '{HYDRA_PATH}' 超时。程序退出。")
        return
    except Exception as e: # 捕获其他可能的subprocess错误
        print(f"[ERROR] 执行 Hydra 命令 '{HYDRA_PATH}' 时发生未知错误: {e}。程序退出。")
        return


    # 传递用户和密码列表参数
    successful_logins = attack_multiple_services(open_services_by_ip,
                                               user_list_file=args.user_list,
                                               pass_list_file=args.pass_list)

    if not successful_logins:
        print("[INFO] Hydra爆破完成，没有发现任何成功登录。")
    else:
        print("\n[SUCCESS] Hydra爆破发现以下成功登录凭证:")
        hydra_error_reported_main = False
        logins_to_save = []
        for login_info in successful_logins:
            if isinstance(login_info, dict) and "error" in login_info:
                if not hydra_error_reported_main:
                    print(f"  [HYDRA_ERROR] {login_info['error']}")
                    hydra_error_reported_main = True
            elif isinstance(login_info, dict):
                logins_to_save.append(login_info)

        if logins_to_save:
            successful_logins_csv_file = "successful_logins.csv"
            try:
                with open(successful_logins_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
                    csv_writer = csv.writer(csvfile)
                    # 写入表头
                    csv_writer.writerow(["IP", "Port", "Service", "Login", "Password"])
                    for cred in logins_to_save:
                        csv_writer.writerow([cred['ip'], cred['port'], cred['service'], cred['login'], cred['password']])
                print(f"\n[INFO] 成功登录的凭证已保存到 {successful_logins_csv_file}")
            except IOError as e:
                print(f"\n[WARNING] 保存成功登录凭证到 CSV 文件 '{successful_logins_csv_file}' 失败: {e}")
        elif not hydra_error_reported_main:
             print("[INFO] Hydra爆破完成，但未通过任何凭证成功登录。")

    print(f"\n[INFO] 尝试清理Hydra生成的临时文件目录: {TEMP_DIR}...")
    if os.path.exists(TEMP_DIR):
        try:
            shutil.rmtree(TEMP_DIR)
            print(f"[INFO] 临时文件目录 '{TEMP_DIR}' 已成功删除。")
        except OSError as e:
            print(f"[WARNING] 清理临时文件目录 '{TEMP_DIR}' 失败: {e}")
    else:
        print(f"[INFO] 临时文件目录 '{TEMP_DIR}' 未找到，无需清理。")

    end_time = time.time()
    print(f"\n[INFO] 所有扫描和爆破任务完成。总耗时: {end_time - start_time:.2f} 秒。")
    print("[IMPORTANT] 请记住，此工具仅用于授权的渗透测试和安全评估。")

if __name__ == '__main__':
    import subprocess # 需要导入subprocess以供检查Hydra是否存在时使用
    main()
