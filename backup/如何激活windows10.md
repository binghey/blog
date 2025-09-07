在使用Win10系统的时候，要是没有windows密钥，那么在使用的功能上就会有很多限制，甚至没有个性化来设置Win10系统。如果想要激活Win10就需要有win10密钥激活码，也就是windows密钥啦。
    1、 找到电脑左下角控制区或者按win键，然后右键引出菜单，找到并选择Windows PowerShell（管理员））。

<img width="496" height="516" alt="Image" src="https://github.com/user-attachments/assets/777f4803-033f-43f6-8d9f-02dfab4917c7" />

    2、点击Windows PowerShell（管理员）进入，输入“wmic os get caption”，查看自己电脑现在的windows系统版本。

<img width="500" height="91" alt="Image" src="https://github.com/user-attachments/assets/972cb038-b607-495a-bf89-ebb4ba25f58e" />


<img width="500" height="110" alt="Image" src="https://github.com/user-attachments/assets/f69bdf03-5951-4fc8-9773-41e239db6ae1" />


    3、 打开https://technet.microsoft.com/en-us/library/jj612867.aspx查看自己系统版本对应的激活密钥，比如我是win10专业版，密钥是W269N-WFGWX-YVC9B-4J6C9-T83GX。
    4、激活指令 (1)打开控制台（左下角右键选择Windows PowerShell（管理员）），输入以下指令（x代表密匙）
slmgr /ipk xxxxx-xxxxx-xxxxx-xxxxx
xxxxx-xxxxx-xxxxx-xxxxx填入上一步得到的密钥，如我是win10专业版，则我该输入的指令就是
slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
    5、然后输入
       slmgr /skms kms.03k.org
这一步是把kms服务器设定为kms.03k.org，如果这个服务器挂掉了，可以自行搜索kms服务器，网上应该会有很多可替代的
   6、最后输入
slmgr /auto
   7、激活完成，可以使用win10未激活时被限制的功能了.