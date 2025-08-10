在 Windows 11 中管理防火墙（即“Windows Defender 防火墙”）有多种方式，包括图形界面和命令行操作。下面分别介绍常见的管理方法：

✅一、使用图形界面管理防火墙
1. 打开防火墙设置
步骤如下：

点击开始菜单 → 设置（Settings）

进入 “隐私和安全性” → “Windows 安全中心”

点击 “打开 Windows 安全中心”

选择 “防火墙和网络保护”

2. 选择网络配置
你会看到三种网络类型：

域网络（公司域使用）

专用网络（家庭、信任网络）

公用网络（咖啡厅、机场等不安全网络）

点击其中一个可以开启或关闭防火墙。

3. 允许应用通过防火墙
如果你想让某些应用访问网络：

点击 “允许应用通过防火墙”

点击右上角的 “更改设置”

勾选你想要允许的程序及其网络类型（专用、公用）

✅ 二、使用高级防火墙设置（适合细粒度控制）
按 Win + S 搜索 “高级安全 Windows Defender 防火墙”

进入后，你可以：

创建入站规则（允许/阻止进入你电脑的连接）

创建出站规则（允许/阻止你电脑出去的连接）

设置程序路径、端口、IP 地址范围、协议类型等

支持导入导出配置，适合企业或高级用户部署策略。

✅ 三、使用命令行（适合批量或脚本操作）
1. 使用 PowerShell
```powershell
# 查看所有防火墙配置文件状态
Get-NetFirewallProfile

# 开启所有防火墙
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# 关闭所有防火墙
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

# 允许某程序通过防火墙（以 Chrome 举例）
New-NetFirewallRule -DisplayName "Allow Chrome" -Direction Inbound -Program "C:\Program Files\Google\Chrome\Application\chrome.exe" -Action Allow

# 阻止端口（以 80 端口为例）
New-NetFirewallRule -DisplayName "Block Port 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block

```
2. 使用 CMD 命令（旧版防火墙接口）

```powershell
# 开启防火墙
netsh advfirewall set allprofiles state on

# 关闭防火墙
netsh advfirewall set allprofiles state off

# 查看规则
netsh advfirewall firewall show rule name=all

```
✅ 四、恢复默认设置
如果你改乱了设置，想恢复初始状态：

打开 “防火墙和网络保护”

点击最下方 “还原默认值”

确认即可恢复为系统默认规则

✅ 五、建议与安全提示
不要完全关闭防火墙，除非是排查问题。

对于不信任的应用或网络，保持防火墙开启。

使用第三方防火墙软件（如 Bitdefender、Kaspersky）时，Windows 防火墙可能会自动关闭。







```powershell
```