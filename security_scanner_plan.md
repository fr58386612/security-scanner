# Python 安全扫描程序开发计划

## 项目目标
开发一个 Python 命令行工具，该工具能够：
1.  从 `ip.txt` 文件读取目标 IP 地址。
2.  对每个 IP 地址扫描指定的常见服务端口。
3.  对扫描到的开放服务，使用 Hydra 和其默认字典尝试登录。
4.  所有操作使用多线程以提高效率，线程数将进行基本优化。
5.  在命令行界面清晰地显示成功登录的信息。

## 端口列表和服务映射
*   **21: ftp** (FTP)
*   **22: ssh** (SSH)
*   **23: telnet** (Telnet)
*   **80: http-get** (HTTP)
*   **110: pop3** (POP3)
*   **143: imap** (IMAP)
*   **443: https-get** (HTTPS)
*   **445: smb** (SMB/CIFS)
*   **1433: mssql** (Microsoft SQL Server)
*   **1521: oracle-listener** (Oracle Database)
*   **3306: mysql** (MySQL)
*   **3389: rdp** (Remote Desktop Protocol)
*   **5432: postgres** (PostgreSQL)
*   **5900: vnc** (VNC 远程桌面)

## 开发步骤与模块

### 1. 环境准备与依赖
*   确保目标系统已安装 Python。
*   确保目标系统已安装 Hydra。程序将通过调用系统命令来使用 Hydra。
*   Python 库：
    *   `socket` (用于端口扫描)
    *   `threading` (用于多线程)
    *   `subprocess` (用于调用 Hydra)
    *   `queue` (用于线程间任务分发和结果收集，可选但推荐)

### 2. IP 地址读取模块 (`ip_reader.py`)
*   功能：读取 `ip.txt` 文件，返回 IP 地址列表。
*   错误处理：处理文件不存在或格式错误的情况。

### 3. 端口扫描模块 (`port_scanner.py`)
*   输入：IP 地址列表，待扫描端口列表 (见上方更新列表)。
*   功能：
    *   对每个 IP 并行扫描指定的端口。
    *   使用 `socket` 尝试连接。
    *   记录每个 IP 开放的端口及其对应的服务（根据更新后的映射）。
*   输出：一个数据结构，例如字典，存储 `{'ip_address': [('port', 'service_name'), ...]}`。
*   多线程：为每个 IP 的端口扫描任务或每个独立的端口扫描（IP+端口组合）分配一个线程。线程池大小可以根据 CPU 核心数设定一个合理值。

### 4. Hydra 爆破模块 (`hydra_attacker.py`)
*   输入：端口扫描模块的输出（包含 IP、开放端口和服务名称）。
*   功能：
    *   为每个开放的服务（IP + 端口 + 服务名）构建并执行 Hydra 命令。
    *   示例命令：`hydra -L <default_user_list> -P <default_pass_list> <ip_address> <service_protocol>`
    *   需要确定 Hydra 默认字典的路径，或者让 Hydra 自动使用其内置列表。
    *   解析 Hydra 的输出，判断是否登录成功。
*   输出：成功登录的凭证列表，例如 `[('ip_address', 'service_name', 'username', 'password'), ...]`。
*   多线程：为每个 Hydra 攻击任务分配一个线程。

### 5. 主控制模块 (`main.py`)
*   协调以上模块的执行流程。
*   初始化线程池。
*   调用 IP 读取模块。
*   将 IP 列表分发给端口扫描任务。
*   收集端口扫描结果，分发给 Hydra 爆破任务。
*   收集 Hydra 爆破结果。
*   在命令行打印扫描进度（例如，"正在扫描 IP: x.x.x.x..."）和最终的成功登录信息。
*   错误处理和日志记录（基本）。

## Mermaid 流程图

```mermaid
graph TD
    A[开始] --> B(读取 ip.txt);
    B -- IP列表 --> C{创建IP任务队列};
    C --> D(启动端口扫描线程池);
    D -- 为每个IP启动扫描任务 --> E[扫描指定端口 (更新后列表)];
    E -- 发现开放端口 --> F{记录开放服务 (IP, 端口, 服务名)};
    F --> G{创建Hydra任务队列};
    G --> H(启动Hydra爆破线程池);
    H -- 为每个开放服务启动爆破任务 --> I[调用Hydra命令 (使用默认字典)];
    I -- 解析Hydra输出 --> J{判断是否成功};
    J -- 成功 --> K(命令行打印成功登录信息);
    J -- 失败 --> L(静默或记录);
    K --> M[任务结束];
    L --> M;
    E -- 无开放端口 --> M;
    A --> Z[结束];
    M --> Z;
```

## 命令行输出示例
```
[INFO] 开始扫描...
[INFO] 从 ip.txt 读取到 X 个 IP 地址。
[SCAN] 正在扫描 IP: 192.168.2.1...
[SCAN] 192.168.2.1: 端口 22 (ssh) 开放。
[SCAN] 正在扫描 IP: 192.168.2.2...
[HYDRA] 尝试爆破 192.168.2.1:22 (ssh)...
[SUCCESS] 登录成功! IP: 192.168.2.1, 服务: ssh, 用户名: root, 密码: password123
...
[INFO] 所有扫描任务完成。