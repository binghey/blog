在 Kali Linux 中安装 VMware Tools 可以显著提升虚拟机的性能和用户体验，例如支持屏幕分辨率自适应、剪贴板共享和文件拖放等功能。以下是详细的安装步骤。

方法一：通过命令行安装

步骤 1：更新系统

确保系统软件包是最新的：

sudo apt update && sudo apt full-upgrade -y
sudo apt autoremove -y
复制
步骤 2：安装 VMware Tools

使用以下命令安装所需的软件包：

sudo apt install open-vm-tools open-vm-tools-desktop fuse -y
复制
如果软件包已安装但无法正常工作，可以尝试重新安装：

sudo apt install --reinstall open-vm-tools open-vm-tools-desktop fuse -y
复制
步骤 3：重启虚拟机

完成安装后，重启虚拟机以使 VMware Tools 生效：

sudo reboot
复制
方法二：通过 VMware 图形界面安装

步骤 1：挂载 VMware Tools

在 VMware 菜单中选择 “虚拟机” > “安装 VMware Tools”。

如果该选项是灰色的，请重启虚拟机后重试。

步骤 2：解压并运行安装程序

打开终端，创建一个目录并挂载 VMware Tools：

mkdir /mnt/cdrom
sudo mount /dev/cdrom /mnt/cdrom
复制
解压安装包：

tar -zxvf /mnt/cdrom/VMwareTools-*.tar.gz -C /tmp/
复制
切换到解压后的目录并运行安装程序：

cd /tmp/vmware-tools-distrib/
sudo ./vmware-install.pl
复制
按提示一路回车完成安装。

步骤 3：重启虚拟机

完成后，重启虚拟机以激活功能：

sudo reboot
复制
注意事项与最佳实践

定期更新：建议定期更新 open-vm-tools 以确保兼容性和性能。

检查功能：确保剪贴板共享、文件拖放等功能已在 VMware 设置中启用。

问题排查：若屏幕分辨率无法自动调整，检查是否正确安装了 open-vm-tools-desktop 包。

通过以上方法，您可以轻松在 Kali Linux 中安装并使用 VMware Tools，从而提升虚拟机的使用体验。