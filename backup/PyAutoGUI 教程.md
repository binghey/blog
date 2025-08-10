## 1. 什么是 PyAutoGUI

**PyAutoGUI** 是 Python 的一个自动化操作库，可以控制 **鼠标、键盘、屏幕截图** 等，用于桌面自动化脚本，比如自动点击按钮、输入文字、截屏识别等。

安装：

```bash
pip install pyautogui
```

---

## 2. 导入模块

```python
import pyautogui  # 导入 PyAutoGUI 模块，用于控制鼠标、键盘和屏幕
import time       # 导入 time 模块，用于延迟执行
```

---

## 3. 基础鼠标操作

```python
# 获取当前鼠标坐标（返回一个 Point 对象，包含 x 和 y 坐标）
position = pyautogui.position()
print("当前鼠标位置：", position)

# 将鼠标移动到指定位置 (x=500, y=300)，用 1 秒时间完成
pyautogui.moveTo(500, 300, duration=1)

# 鼠标相对当前位置移动 (右 100 像素，下 50 像素)
pyautogui.moveRel(100, 50, duration=0.5)

# 鼠标左键单击
pyautogui.click()

# 鼠标右键单击
pyautogui.rightClick()

# 鼠标双击
pyautogui.doubleClick()

# 鼠标拖动到指定位置（模拟拖拽操作）
pyautogui.dragTo(800, 500, duration=1)

# 鼠标相对当前位置拖动
pyautogui.dragRel(-200, -100, duration=1)
```

---

## 4. 键盘输入

```python
# 输入一段文字（自动键入）
pyautogui.typewrite("Hello, PyAutoGUI!", interval=0.1)  # 每个字符间隔 0.1 秒

# 按下单个键
pyautogui.press("enter")  # 模拟按下 Enter

# 按住某个键不放（如 Ctrl+C）
pyautogui.keyDown("ctrl")  # 按下 Ctrl
pyautogui.press("c")       # 按下 C
pyautogui.keyUp("ctrl")    # 松开 Ctrl

# 组合快捷键（等效于 Ctrl+V）
pyautogui.hotkey("ctrl", "v")
```

---

## 5. 屏幕操作

```python
# 获取屏幕分辨率（返回宽度和高度）
screen_width, screen_height = pyautogui.size()
print("屏幕分辨率：", screen_width, "x", screen_height)

# 判断鼠标是否在屏幕范围内
x, y = pyautogui.position()
if 0 <= x < screen_width and 0 <= y < screen_height:
    print("鼠标在屏幕范围内")

# 屏幕截图（保存为文件）
screenshot = pyautogui.screenshot("screen.png")

# 截取屏幕某个区域（x, y, width, height）
region_screenshot = pyautogui.screenshot("region.png", region=(0, 0, 500, 400))
```

---

## 6. 图像识别点击（基于截图）

```python
# 在屏幕上查找图片（需要提前准备好一个小图片，如 button.png）
button_location = pyautogui.locateOnScreen("button.png", confidence=0.8)  
# confidence 参数是匹配精度（0~1 之间，需要安装 opencv-python）

if button_location:
    print("找到按钮位置：", button_location)
    # 获取按钮中心位置
    center_x, center_y = pyautogui.center(button_location)
    # 点击按钮
    pyautogui.click(center_x, center_y)
else:
    print("未找到按钮")
```

---

## 7. 安全退出（防止脚本失控）

```python
# 启用鼠标移动到屏幕左上角 (0,0) 自动终止脚本
pyautogui.FAILSAFE = True

# 如果你不想使用这个安全功能，可以关闭
# pyautogui.FAILSAFE = False
```

---

## 8. 延迟与防抖

```python
# 全局延迟（每次 PyAutoGUI 执行动作后延迟 0.5 秒）
pyautogui.PAUSE = 0.5
```

---

## 9. 示例：自动打开记事本并输入文字

```python
import pyautogui
import time

pyautogui.PAUSE = 0.5
pyautogui.FAILSAFE = True

# 打开 Windows 搜索
pyautogui.press("win")
pyautogui.typewrite("notepad", interval=0.1)
pyautogui.press("enter")

time.sleep(1)  # 等待记事本打开

# 输入文字
pyautogui.typewrite("Hello! This text is typed by PyAutoGUI.", interval=0.05)

# 保存文件
pyautogui.hotkey("ctrl", "s")
time.sleep(0.5)
pyautogui.typewrite("test.txt", interval=0.1)
pyautogui.press("enter")
```

---

✅ 这样你不仅学了 PyAutoGUI 的常用功能，还能用它做自动化脚本。
如果你愿意，我还可以帮你写一个 **PyAutoGUI 可视化坐标助手**，可以实时显示鼠标位置，方便你写自动化脚本时定位点击位置。
这样配合上面的教程，就能直接做自动化点击了。

你要我帮你做这个可视化坐标助手吗？我可以直接给你代码。
