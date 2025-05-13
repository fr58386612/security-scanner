import subprocess
import threading
from queue import Queue
import re # For parsing Hydra output
import os # For directory creation and file path joining

# 假设Hydra在系统PATH中
HYDRA_PATH = "hydra"
TEMP_DIR = "temp_hydra_files" # Directory for temporary files

# Hydra默认用户名和密码列表 (这些是示例，Hydra有其内置列表，也可以指定文件)
# 如果不指定 -L 和 -P, Hydra可能会使用其编译时定义的默认列表或需要用户交互。
# 为了自动化，最好指定一些小的常用列表或者让用户配置。
# 计划中提到“Hydra默认字典”，这里我们先尝试不显式指定 -L -P，依赖Hydra的默认行为。
# 或者，我们可以创建小的默认列表文件。为简单起见，先尝试让Hydra自己处理。
# 如果Hydra在没有-L/-P的情况下不工作或效果不佳，则需要提供默认列表文件。
# 常见的Hydra成功登录输出格式: "[<service>] host: <ip> login: <user> password: <pass>"
# 或 "[SUCCESS] <attempts> valid password(s) found for <service>://<ip>:<port> - <user> <password>"
# 我们需要一个灵活的正则来匹配

# 线程数
MAX_HYDRA_THREADS = 10 # Hydra本身可能很耗资源

def run_hydra_attack(ip, port, service_protocol, user_list_file=None, pass_list_file=None):
    """
    对指定的IP、端口和服务协议运行Hydra攻击。
    Args:
        ip (str): 目标IP.
        port (int): 目标端口.
        service_protocol (str): Hydra服务协议 (e.g., "ssh", "ftp").
        user_list_file (str, optional): 用户名字典文件路径.
        pass_list_file (str, optional): 密码字典文件路径.
    """
    # print(f"[HYDRA_ATTACK] Attacking {service_protocol} on {ip}:{port}")
    # 构建Hydra命令。注意：不同的服务可能需要不同的Hydra参数。
    # 例如，RDP可能需要 `-t 1` (单线程) 或特定模块。
    # 这里使用一个通用模板，可能需要根据服务类型调整。
    # -V: Verbose output (有助于调试和解析)
    # -f: Exit after finding first valid credentials for a host
    # -q: Quiet mode (suppresses status, but we need output for parsing)
    # 我们需要找到一个平衡点，或者解析详细输出。
    # 尝试一个基础命令，如果Hydra有默认列表，它可能会使用。
    # 如果没有，我们需要提供 -L <userlist> -P <passlist>
    # 常见的用户/密码列表可以很小，例如 top 10。
    
    # 简单的用户和密码列表作为示例，如果Hydra不自带或效果不好
    common_users = ["root", "admin", "user", "test"]
    common_passwords = ["password", "123456", "admin", "root", "test"]

    # 确保临时目录存在
    os.makedirs(TEMP_DIR, exist_ok=True)
    hydra_output_file = os.path.join(TEMP_DIR, f"hydra_output_{ip}_{port}.txt")

    # 确定用户和密码列表文件
    final_user_file = None
    final_pass_file = None
    created_temp_user_file = False # Tracks if we created a temp file from hardcoded list
    created_temp_pass_file = False

    # Determine user list file
    if user_list_file and os.path.exists(user_list_file):
        final_user_file = user_list_file
        # print(f"[INFO] Hydra将使用命令行指定的用户列表: {final_user_file}") # Removed as per request
    elif os.path.exists("default_users.txt"):
        final_user_file = "default_users.txt"
        # print(f"[INFO] Hydra将使用默认用户列表: {final_user_file}") # Removed
    else:
        if user_list_file: # Provided via CLI but not found
            print(f"[WARNING] 指定的用户列表文件 '{user_list_file}' 未找到。")
        # print(f"[INFO] 未找到命令行指定或默认用户列表，将使用内置的简单用户列表并创建临时文件。") # Removed
        final_user_file = os.path.join(TEMP_DIR, "temp_users.txt")
        with open(final_user_file, "w") as f:
            for u in common_users:
                f.write(u + "\n")
        created_temp_user_file = True
        
    # Determine password list file
    if pass_list_file and os.path.exists(pass_list_file):
        final_pass_file = pass_list_file
        # print(f"[INFO] Hydra将使用命令行指定的密码列表: {final_pass_file}") # Removed
    elif os.path.exists("default_passwords.txt"):
        final_pass_file = "default_passwords.txt"
        # print(f"[INFO] Hydra将使用默认密码列表: {final_pass_file}") # Removed
    else:
        if pass_list_file: # Provided via CLI but not found
            print(f"[WARNING] 指定的密码列表文件 '{pass_list_file}' 未找到。")
        # print(f"[INFO] 未找到命令行指定或默认密码列表，将使用内置的简单密码列表并创建临时文件。") # Removed
        final_pass_file = os.path.join(TEMP_DIR, "temp_pass.txt")
        with open(final_pass_file, "w") as f:
            for p in common_passwords:
                f.write(p + "\n")
        created_temp_pass_file = True
        
    # 针对不同服务的Hydra命令调整
    # RDP (-s <port> if not default)
    # SMB (-s <port> if not default)
    # HTTP/HTTPS (http-get, http-post-form, etc.)
    # Oracle (oracle-listener, oracle-sid)
    
    # 基础命令，使用我们创建的临时列表
    # -f: 找到第一个就停止对该主机的该服务爆破
    # -t 4: Hydra内部的并发任务数 (不是我们脚本的线程数)
    cmd = [
        HYDRA_PATH,
        "-L", final_user_file,
        "-P", final_pass_file,
        "-f",
        "-t", "4",
        "-o", hydra_output_file, # 将输出保存到文件，方便调试
        f"{service_protocol}://{ip}:{port}"
    ]
    
    # 对于某些服务，端口可能不需要在协议串中，而是作为独立参数
    # 例如 rdp://ip (hydra会自动用3389) 或 hydra -s <port> ip rdp
    # 我们这里的 PORT_SERVICE_MAP 里的 service_protocol 已经是Hydra能识别的格式
    # 如 "ssh", "ftp", "rdp", "mysql"

    hydra_command_str = ' '.join(cmd)
    # The command string will be printed by the worker thread.

    try:
        # print(f"[INFO] 执行Hydra命令: {' '.join(cmd)}") # Restored: This should be printed here.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=300) # 5分钟超时

        # print(f"[HYDRA_STDOUT for {ip}:{port}]\n{stdout}")
        # if stderr:
        #     print(f"[HYDRA_STDERR for {ip}:{port}]\n{stderr}")

        # 解析 stdout 寻找成功登录信息
        # Hydra的成功输出通常包含 "host:", "login:", "password:"
        # 或者 "[SUCCESS]"
        # 示例: 1 target completed, 1 valid password found
        # [ftp] host: 127.0.0.1 login: user password: password123
        
        # 更通用的匹配方式
        # 匹配 "host: <ip_or_host> login: <login> password: <password>"
        # 或者 "login: <login>   password: <password>" 在包含IP和端口的行附近
        success_pattern = re.compile(r"host:\s*(\S+)\s*login:\s*(\S+)\s*password:\s*(\S+)", re.IGNORECASE)
        # Hydra 9.0+ format: [SUCCESS] ... - <login> <password>
        success_pattern_v9 = re.compile(r"\[SUCCESS\].*?-\s*(\S+)\s+(\S+)", re.IGNORECASE)

        found_credentials = []
        for line in stdout.splitlines():
            match = success_pattern.search(line)
            if match:
                # _, found_login, found_pass = match.groups() # 第一个group是host
                # 确保匹配到的host是我们正在攻击的IP
                matched_host, found_login, found_pass = match.groups()
                if matched_host == ip: # 确保是当前目标
                    credential = {"ip": ip, "port": port, "service": service_protocol, "login": found_login, "password": found_pass}
                    found_credentials.append(credential)
                    # 立即以绿色打印成功信息
                    GREEN = '\033[92m'
                    RESET = '\033[0m'
                    print(f"{GREEN}[SUCCESS_IMMEDIATE] 登录成功! IP: {ip}, Port: {port}, Service: {service_protocol}, Login: {found_login}, Password: {found_pass}{RESET}")
            else:
                match_v9 = success_pattern_v9.search(line)
                if match_v9:
                    found_login, found_pass = match_v9.groups()
                    credential = {"ip": ip, "port": port, "service": service_protocol, "login": found_login, "password": found_pass}
                    found_credentials.append(credential)
                    # 立即以绿色打印成功信息
                    GREEN = '\033[92m'
                    RESET = '\033[0m'
                    print(f"{GREEN}[SUCCESS_IMMEDIATE] 登录成功! IP: {ip}, Port: {port}, Service: {service_protocol}, Login: {found_login}, Password: {found_pass}{RESET}")
        
        # 清理临时文件 (单个攻击的输出文件，用户/密码列表在主函数或调用者处清理)
        # if os.path.exists(hydra_output_file):
        #     os.remove(hydra_output_file) # Output file is cleaned by main.py via TEMP_DIR removal
        if created_temp_user_file and os.path.exists(final_user_file):
            os.remove(final_user_file)
        if created_temp_pass_file and os.path.exists(final_pass_file):
            os.remove(final_pass_file)
        return found_credentials

    except subprocess.TimeoutExpired:
        # print(f"[HYDRA_TIMEOUT] Hydra timed out for {ip}:{port} ({service_protocol})")
        if created_temp_user_file and os.path.exists(final_user_file): os.remove(final_user_file)
        if created_temp_pass_file and os.path.exists(final_pass_file): os.remove(final_pass_file)
        return []
    except FileNotFoundError:
        print(f"[HYDRA_ERROR] Hydra command '{HYDRA_PATH}' not found. Please ensure Hydra is installed and in your PATH.")
        if created_temp_user_file and os.path.exists(final_user_file): os.remove(final_user_file)
        if created_temp_pass_file and os.path.exists(final_pass_file): os.remove(final_pass_file)
        return {"error": "Hydra not found"} # 特殊标记错误
    except Exception as e:
        # print(f"[HYDRA_EXCEPTION] Error running Hydra for {ip}:{port} ({service_protocol}): {e}")
        if created_temp_user_file and os.path.exists(final_user_file): os.remove(final_user_file)
        if created_temp_pass_file and os.path.exists(final_pass_file): os.remove(final_pass_file)
        return []


def attack_multiple_services(scan_results, user_list_file=None, pass_list_file=None):
    """
    对扫描结果中发现的开放服务进行Hydra爆破。
    scan_results: {'ip_address': [('port', 'service_name'), ...]}
    user_list_file (str, optional): 用户名字典文件路径.
    pass_list_file (str, optional): 密码字典文件路径.
    """
    successful_logins = []
    task_queue = Queue()

    for ip, services in scan_results.items():
        for port, service_protocol in services:
            # 一些服务可能不适合用Hydra爆破，或者需要非常特定的参数
            # 例如 oracle-listener 通常是发现SID，而不是直接爆破监听器密码
            # 跳过 HTTP/HTTPS (80, 443) 的爆破
            if service_protocol in ["http-get", "https-get"]:
                print(f"[INFO] 跳过对 {ip}:{port} ({service_protocol}) 的Hydra爆破。")
                continue
            if service_protocol not in ["unknown", "oracle-listener"]: # 示例：跳过其他特定服务
                 task_queue.put((ip, port, service_protocol))

    hydra_results_collector = [] # 收集所有线程的结果
    total_tasks = task_queue.qsize()
    completed_tasks = 0
    progress_lock = threading.Lock()

    if total_tasks == 0:
        print("[INFO] 没有需要进行Hydra爆破的服务。")
        return []

    print(f"[INFO] Hydra爆破任务总数: {total_tasks}")

    def worker():
        nonlocal completed_tasks
        while not task_queue.empty():
            try:
                current_ip, current_port, current_service = task_queue.get_nowait()
            except Queue.Empty:
                break
            
            # print(f"[HYDRA_WORKER] Attacking {current_service} on {current_ip}:{current_port}")
            # Construct the command string here to print it with progress
            # This requires some refactoring or passing more info if we want the exact command string
            # For now, let's just indicate which service is being processed.
            # The actual command string is built inside run_hydra_attack.
            # To get the command string here, run_hydra_attack would need to return it or we duplicate logic.
            # Simpler: print target, then call run_hydra_attack which prints its own command.
            
            # The run_hydra_attack function now prints its own command.
            # We will print progress before calling it.
            
            with progress_lock:
                # This print might appear before the [INFO] 执行Hydra命令 from run_hydra_attack
                # due to GIL and thread scheduling.
                # For a more synchronized log, the command print should ideally be here.
                # Let's try to make run_hydra_attack return the command string as well for cleaner logging.
                # For now, the command print is inside run_hydra_attack.
                pass # Progress will be printed after task_done

            creds = run_hydra_attack(current_ip, current_port, current_service, user_list_file, pass_list_file)
            
            if creds:
                if isinstance(creds, dict) and "error" in creds: # Hydra未找到的错误
                    hydra_results_collector.append(creds) # 传递错误信息
                else:
                    hydra_results_collector.extend(creds)
            task_queue.task_done()

            with progress_lock:
                completed_tasks += 1
                # The [INFO] 执行Hydra命令: ... will be printed by run_hydra_attack just before Popen.
                # This progress message will appear after that command log for that specific task.
                print(f"[HYDRA_PROGRESS] ({completed_tasks}/{total_tasks}) 任务完成: {current_service} on {current_ip}:{current_port}")


    threads = []
    # 限制Hydra并发数，因为它很消耗资源
    num_threads = min(MAX_HYDRA_THREADS, task_queue.qsize()) 
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    task_queue.join()

    for thread in threads:
        thread.join()
    
    # 处理收集到的结果，特别是错误
    final_logins = []
    hydra_not_found_error = False
    for res in hydra_results_collector:
        if isinstance(res, dict) and res.get("error") == "Hydra not found":
            hydra_not_found_error = True
            # 如果Hydra未找到，通常只报告一次
            if not any(r == res for r in final_logins if isinstance(r, dict)):
                 final_logins.append(res)
        else:
            final_logins.append(res)
    
    if hydra_not_found_error and not any(isinstance(item, dict) and item.get("error") == "Hydra not found" for item in successful_logins):
        # 确保只添加一次Hydra未找到的错误信息
        # 这部分逻辑有点复杂，主要是为了不重复打印 "Hydra not found"
        # 简化：如果hydra_results_collector包含错误，主程序会处理
        pass


    return hydra_results_collector # 返回包含成功登录和潜在错误信息的列表


if __name__ == '__main__':
    # 测试代码
    # 假设我们有一个本地FTP服务器在 127.0.0.1:21，用户user,密码password123
    # 你需要确保Hydra已安装，并且你的测试服务是可爆破的
    
    # 模拟 port_scanner 的输出
    mock_scan_results = {
        "127.0.0.1": [(21, "ftp"), (22, "ssh")] 
        # "192.168.1.101": [(3306, "mysql")]
    }
    
    print(f"开始Hydra爆破，目标: {mock_scan_results}")
    
    # 创建临时文件给Hydra (在主测试中也需要，因为run_hydra_attack会创建它们)
    # 或者在run_hydra_attack中处理文件创建/删除的原子性
    # 为了测试，我们可以在这里创建，并在之后删除
    user_file_main = "temp_users.txt" # This will be created in TEMP_DIR if default_users.txt is not found
    pass_file_main = "temp_pass.txt" # This will be created in TEMP_DIR if default_passwords.txt is not found
    
    # For testing, ensure default_users.txt and default_passwords.txt exist or are handled
    # The run_hydra_attack logic now handles this.
    # If default_users.txt/default_passwords.txt are not present, it will create temp_users.txt/temp_pass.txt in TEMP_DIR.

    successes = attack_multiple_services(mock_scan_results)

    if successes:
        hydra_error_reported = False
        print("\nHydra爆破成功登录信息:")
        for cred in successes:
            if isinstance(cred, dict) and "error" in cred:
                if not hydra_error_reported: # 只打印一次Hydra未找到的错误
                    print(f"  错误: {cred['error']}")
                    hydra_error_reported = True
            elif isinstance(cred, dict):
                print(f"  IP: {cred['ip']}, Port: {cred['port']}, Service: {cred['service']}, Login: {cred['login']}, Password: {cred['password']}")
    else:
        print("\nHydra爆破未发现成功登录。")

    # 清理主测试中创建的临时文件 (现在它们应该在 TEMP_DIR 中)
    # import os # Already imported
    # import shutil # For removing directory
    try:
        # The temp_users.txt and temp_pass.txt are now created inside TEMP_DIR by run_hydra_attack if needed,
        # and cleaned up by it if it created them.
        # The main.py will clean up the entire TEMP_DIR.
        
        # Hydra输出文件也可能需要清理，如果测试时生成了
        for ip_key in mock_scan_results:
            for port_val, service_proto_val in mock_scan_results[ip_key]:
                 if service_proto_val not in ["http-get", "https-get"]: # 只清理实际尝试爆破的服务的输出
                    output_file_path = os.path.join(TEMP_DIR, f"hydra_output_{ip_key}_{port_val}.txt")
                    if os.path.exists(output_file_path): os.remove(output_file_path)
        
        # 清理临时目录，如果它是空的
        if os.path.exists(TEMP_DIR) and not os.listdir(TEMP_DIR):
             os.rmdir(TEMP_DIR)
        # For testing, if TEMP_DIR was created, try to remove it if empty or all files.
        # This cleanup is more robustly handled in main.py after all operations.

    except OSError as e:
        print(f"清理临时文件时出错: {e}")