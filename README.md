# Python 安全扫描器

一个使用 Python 编写的多线程安全扫描器，能够执行端口扫描和针对已发现服务的 Hydra 暴力破解攻击。

## 功能特性

*   **IP 地址输入**: 从指定文件（默认为 `ip.txt`）读取目标 IP 地址。
*   **端口扫描**:
    *   扫描预定义的常见端口列表或通过命令行参数提供的自定义端口列表。
    *   识别开放端口并尝试确定其上运行的服务。
    *   多线程并发扫描多个 IP。
    *   将扫描结果保存到 Excel 文件 (`open_ports_results.xlsx`)，每个 IP 地址占一行，其开放端口/服务信息汇总显示。
*   **Hydra 暴力破解**:
    *   使用 THC-Hydra 对发现的服务（默认排除 HTTP/HTTPS）执行暴力破解攻击。
    *   支持通过命令行参数指定自定义的用户名和密码列表文件。
    *   如果未指定自定义列表，则优先使用当前目录下的 `default_users.txt` 和 `default_passwords.txt`。如果这些默认文件也不存在，则使用内置的少量简单列表。
    *   多线程并发攻击多个服务（Hydra 实例数量可配置）。
    *   实时显示暴力破解任务的进度。
    *   立即以绿色高亮在控制台打印成功破解的凭证。
    *   将所有成功破解的凭证追加到 `successful_logins.txt` 文件，并为每次运行添加时间戳。
*   **输出与日志**:
    *   详细的控制台输出，显示各个阶段、进度和结果。
    *   端口扫描结果保存到 `open_ports_results.xlsx`。
    *   Hydra 成功登录的凭证保存到 `successful_logins.txt`。
    *   Hydra 生成的临时文件存储在 `temp_hydra_files/` 目录中，并在程序完成时自动清理。
*   **自定义配置**:
    *   指定目标 IP 文件。
    *   指定用于扫描的自定义端口列表。
    *   为 Hydra 指定自定义的用户名和密码列表。

## 环境要求

1.  **Python 3.x**: 确保您的系统已安装 Python 3。
2.  **THC-Hydra**: Hydra 必须已安装，并且可以通过系统 PATH 访问（即，在终端输入 `hydra` 应能运行它）。
    *   在 Debian/Ubuntu 系统上: `sudo apt-get update && sudo apt-get install hydra`
3.  **Python 库**:
    *   `openpyxl`: 用于将端口扫描结果保存到 Excel 文件。使用 pip 安装:
        ```bash
        pip install openpyxl
        ```

## 使用方法

1.  **准备 IP 列表**: 创建一个文件（例如 `ip.txt`），每行包含一个 IP 地址。
    ```
    192.168.1.1
    192.168.1.2
    # 注释行会被忽略
    192.168.1.5
    ```

2.  **准备字典文件 (可选)**:
    *   如果您想为 Hydra 使用自己的字典，请准备 `users.txt` 和 `passwords.txt`。
    *   否则，脚本将查找同目录下的 `default_users.txt` 和 `default_passwords.txt`。
    *   如果这些文件都未找到，将使用内置的极简列表。

3.  **运行扫描器**:
    在脚本所在目录打开终端，并使用所需选项运行 `main.py`：

    ```bash
    python main.py [选项]
    ```

    **命令行选项**:
    ```
    usage: main.py [-h] [-UL USER_LIST] [-PL PASS_LIST] [-IP IP_FILE] [-P PORTS]

    Python 安全扫描器，具备端口扫描和 Hydra 暴力破解功能。

    选项:
      -h, --help            显示此帮助信息并退出
      -UL USER_LIST, --user-list USER_LIST
                            用于 Hydra 的自定义用户名字典文件路径。
      -PL PASS_LIST, --pass-list PASS_LIST
                            用于 Hydra 的自定义密码字典文件路径。
      -IP IP_FILE, --ip-file IP_FILE
                            包含目标 IP 地址的文件路径 (默认为: ip.txt)。
      -P PORTS, --ports PORTS
                            逗号分隔的自定义端口列表，用于扫描 (例如: 80,443,8080)。将覆盖默认端口列表。
    ```

    **示例**:
    *   使用默认端口和默认/内置字典扫描 `ip.txt` 中的 IP：
        ```bash
        python main.py
        ```
    *   扫描 `targets.txt` 中的 IP，扫描自定义端口，并使用自定义的 Hydra 字典：
        ```bash
        python main.py --ip-file targets.txt --ports 80,443,2222 --user-list myusers.txt --pass-list mypasses.txt
        ```

## 输出文件

*   `open_ports_results.xlsx`: 包含 IP 列表及其发现的开放端口和服务。
*   `successful_logins.txt`: 追加记录 Hydra 攻击成功破解的凭证。
*   `temp_hydra_files/`: Hydra 中间文件的临时目录（自动创建和删除）。

## 重要提示

本工具仅用于授权的渗透测试和安全评估目的。未经授权对您没有权限测试的系统使用本工具是违法的。用户需对自己的行为负责。