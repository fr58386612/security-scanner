import time
import os
# import json # No longer using json for open ports output
import shutil # For removing directory
import argparse # For command-line arguments
try:
    import openpyxl
except ImportError:
    print("[ERROR] 'openpyxl' library is not installed. Please install it using 'pip install openpyxl' to save results to Excel.")
    print("[INFO] Proceeding without Excel export for open ports.")
    openpyxl = None # Sentinel to indicate library is not available

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
    # 使用 port_scanner 中定义的端口列表
    # DEFAULT_PORTS_TO_SCAN = list(PORT_SERVICE_MAP.keys())
    # scan_multiple_ips 函数现在会处理自定义端口参数
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

    # 保存开放端口结果到 Excel 文件
    if openpyxl: # Proceed only if library is available
        open_ports_excel_file = "open_ports_results.xlsx"
        try:
            workbook = openpyxl.Workbook()
            sheet = workbook.active
            sheet.title = "Open Ports"
            
            # Write headers
            sheet['A1'] = "IP Address"
            sheet['B1'] = "Open Ports & Services"
            
            row_num = 2 # Start data from row 2
            for ip, services in open_services_by_ip.items():
                sheet[f'A{row_num}'] = ip
                if services: # If there are open ports for this IP
                    ports_services_str_list = []
                    for port, service_name in services:
                        ports_services_str_list.append(f"{port}({service_name})")
                    sheet[f'B{row_num}'] = ", ".join(ports_services_str_list)
                else: # If an IP had no open ports
                    # This case might not be hit if scan_multiple_ips only returns IPs with open ports.
                    # However, if it can return an IP with an empty list of services, this handles it.
                    sheet[f'B{row_num}'] = "No open ports found"
                row_num +=1
            
            # Auto-adjust column widths for better readability
            for col in sheet.columns:
                max_length = 0
                column = col[0].column_letter # Get the column name
                for cell in col:
                    try: # Necessary to avoid error on empty cells
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = (max_length + 2)
                sheet.column_dimensions[column].width = adjusted_width

            workbook.save(open_ports_excel_file)
            print(f"\n[INFO] 开放端口信息已保存到 {open_ports_excel_file}")
        except Exception as e: # Catch any exception from openpyxl
            print(f"\n[WARNING] 保存开放端口信息到 Excel 文件 '{open_ports_excel_file}' 失败: {e}")
    else:
        print("\n[INFO] 'openpyxl' 未安装，跳过将开放端口信息保存到 Excel 文件。")


    # 3. Hydra爆破
    print("\n[INFO] 开始对发现的开放服务进行Hydra爆破...")
    
    # 检查Hydra是否存在
    try:
        subprocess.run([HYDRA_PATH, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5)
    except FileNotFoundError:
        print(f"[ERROR] Hydra 命令 '{HYDRA_PATH}' 未找到。请确保Hydra已安装并在系统PATH中。程序退出。")
        return
    except subprocess.TimeoutExpired:
        print(f"[ERROR] 检查 Hydra 命令 '{HYDRA_PATH}' 超时。程序退出。")
        return

    # 传递用户和密码列表参数
    successful_logins = attack_multiple_services(open_services_by_ip,
                                               user_list_file=args.user_list,
                                               pass_list_file=args.pass_list)

    if not successful_logins:
        print("[INFO] Hydra爆破完成，没有发现任何成功登录。")
    else:
        print("\n[SUCCESS] Hydra爆破发现以下成功登录凭证:") # This will print after all immediate successes
        hydra_error_reported_main = False
        logins_to_save = []
        for login_info in successful_logins:
            if isinstance(login_info, dict) and "error" in login_info:
                if not hydra_error_reported_main: # 避免重复打印Hydra未找到
                    print(f"  [HYDRA_ERROR] {login_info['error']}") # Printed if Hydra itself fails
                    hydra_error_reported_main = True
            elif isinstance(login_info, dict): # 确保是字典格式的凭证
                # 即时成功信息已由 hydra_attacker.py 打印
                # 这里只收集用于最终文件保存和可选的汇总打印
                logins_to_save.append(login_info)
                # Optionally, re-print here if a final summary is desired in console,
                # but it might be redundant with immediate green prints.
                # For now, let's assume immediate prints are sufficient for console.
                # print(f"  - IP: {login_info['ip']}, Port: {login_info['port']}, Service: {login_info['service']}, Login: {login_info['login']}, Password: {login_info['password']}")

        if logins_to_save:
            successful_logins_file = "successful_logins.txt"
            try:
                with open(successful_logins_file, 'a') as f: # Append mode
                    # Add a timestamp for each run's entries if the file already exists and has content
                    if f.tell() == 0: # File is new or empty
                        f.write(f"--- Scan run at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                    else: # File exists and has content, add a separator and new timestamp
                        f.write(f"\n--- Scan run at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                        
                    for cred in logins_to_save:
                        f.write(f"IP: {cred['ip']}, Port: {cred['port']}, Service: {cred['service']}, Login: {cred['login']}, Password: {cred['password']}\n")
                print(f"\n[INFO] 成功登录的凭证已追加到 {successful_logins_file}")
            except IOError as e:
                print(f"\n[WARNING] 保存成功登录凭证到文件 '{successful_logins_file}' 失败: {e}")
        elif not hydra_error_reported_main: # No actual logins and no hydra error
             print("[INFO] Hydra爆破完成，但未通过任何凭证成功登录。")


    # 清理Hydra生成的临时用户/密码文件和输出文件
    # 这些文件是在 hydra_attacker.py 中创建的
    # 为了保持模块独立性，清理逻辑最好也在那里，或者主程序统一处理已知模式的文件
    # hydra_attacker.py 中的 run_hydra_attack 示例已包含清理逻辑（被注释掉了）
    # 这里我们假设 hydra_attacker.py 会自行清理或用户手动清理
    # 如果要在这里清理，需要知道文件名模式
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
    # 为了能从main.py中直接调用hydra_attacker，需要确保hydra_attacker.py中的subprocess.run能找到hydra
    # 这通常意味着hydra在系统PATH中
    import subprocess # 需要导入subprocess以供检查Hydra是否存在时使用
    main()