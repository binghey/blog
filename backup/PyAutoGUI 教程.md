##openpyxl 在 Python 中的应用教程，内容覆盖从创建 Excel、写入数据、读取数据、修改数据、样式设置、合并单元格、公式到保存文件等常用功能。
1. 安装 openpyxl
```bash
  pip install openpyxl
```
openpyxl 是一个专门处理 .xlsx 格式 Excel 文件的 Python 库。
2. 创建 Excel 并写入数据
```python
from openpyxl import Workbook  # 从 openpyxl 导入 Workbook 类（用于创建新 Excel）

# 创建一个新的 Excel 工作簿对象
wb = Workbook()

# 获取当前活跃的工作表（默认是第一个工作表）
ws = wb.active

# 给工作表命名
ws.title = "学生成绩表"

# 在指定单元格写入数据
ws["A1"] = "姓名"   # 第一列第一行
ws["B1"] = "语文"
ws["C1"] = "数学"

# 用循环写入多行数据
data = [
    ["张三", 85, 90],
    ["李四", 78, 88],
    ["王五", 92, 95]
]
for row in data:
    ws.append(row)  # append 会自动按行追加数据

# 保存 Excel 文件
wb.save("学生成绩.xlsx")

```
3. 读取 Excel 数据
```python
from openpyxl import load_workbook  # 用于加载已存在的 Excel 文件

# 打开 Excel 文件
wb = load_workbook("学生成绩.xlsx")

# 选择工作表（方式一：按名称）
ws = wb["学生成绩表"]

# 方式二：按索引获取（第一个工作表）
# ws = wb.worksheets[0]

# 读取单元格内容
print(ws["A1"].value)  # 输出：姓名

# 读取某一行
for cell in ws[1]:  # 第一行
    print(cell.value)

# 读取所有行（跳过表头）
for row in ws.iter_rows(min_row=2, values_only=True):  
    # min_row=2 表示从第二行开始，values_only=True 表示只返回值而不是 cell 对象
    print(row)

wb.close()  # 用完关闭（释放内存）

```
4. 修改 Excel 数据
```python
# 修改某个单元格
ws["B2"] = 88  # 把张三的语文成绩改成 88

# 保存修改
wb.save("学生成绩.xlsx")

```
5. 设置单元格样式（字体、颜色、对齐方式等）

```python
from openpyxl.styles import Font, PatternFill, Alignment

# 设置字体
ws["A1"].font = Font(name="微软雅黑", size=14, bold=True, color="FFFFFF")  # 白色字体

# 设置背景颜色
ws["A1"].fill = PatternFill("solid", fgColor="4F81BD")  # 蓝色背景

# 设置对齐方式
ws["A1"].alignment = Alignment(horizontal="center", vertical="center")

wb.save("学生成绩.xlsx")

```
6. 合并与拆分单元格

```python
# 合并 A1 到 C1
ws.merge_cells("A1:C1")
ws["A1"] = "成绩表"

# 拆分（取消合并）
ws.unmerge_cells("A1:C1")

wb.save("学生成绩.xlsx")

```

7. 插入公式
```python
# 在 D 列计算平均分
ws["D1"] = "平均分"
for row in range(2, 5):  # 第 2 到第 4 行有数据
    ws[f"D{row}"] = f"=AVERAGE(B{row}:C{row})"  # Excel 平均公式

wb.save("学生成绩.xlsx")

```
8. 读取 Excel 的行列范围
```python
# 读取第一列所有数据
for cell in ws["A"]:
    print(cell.value)

# 读取第二列到第三列
for col in ws.iter_cols(min_col=2, max_col=3, values_only=True):
    print(col)

```
9. 删除和插入行列
```python

# 插入一行（在第 2 行的位置插入）
ws.insert_rows(2)

# 删除第 3 行
ws.delete_rows(3)

# 插入一列（在第 2 列位置插入）
ws.insert_cols(2)

# 删除第 3 列
ws.delete_cols(3)

wb.save("学生成绩.xlsx")

```
10. 设置列宽和行高

```python
# 设置列宽
ws.column_dimensions["A"].width = 15
ws.column_dimensions["B"].width = 10

# 设置行高
ws.row_dimensions[1].height = 25

wb.save("学生成绩.xlsx")

```
11. 冻结窗口（方便滚动时表头不动）
```python
# 冻结首行
ws.freeze_panes = "A2"

wb.save("学生成绩.xlsx")

```
Excel 工具类实现
```python
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Font, PatternFill, Alignment


class ExcelHelper:
    """
    Excel 操作工具类
    使用 openpyxl 封装常用 Excel 操作，适用于生产环境
    """

    def __init__(self, filename=None):
        """
        初始化 Excel 文件
        :param filename: Excel 文件路径（如果为 None，则新建一个）
        """
        if filename:
            # 如果传入了文件名，尝试加载
            self.wb = load_workbook(filename)
            self.filename = filename
        else:
            # 新建 Excel 文件
            self.wb = Workbook()
            self.filename = None

        # 默认选中第一个工作表
        self.ws = self.wb.active

    def set_sheet(self, sheet_name):
        """
        设置当前操作的工作表
        :param sheet_name: 工作表名称
        """
        if sheet_name in self.wb.sheetnames:
            self.ws = self.wb[sheet_name]
        else:
            self.ws = self.wb.create_sheet(sheet_name)

    def write_cell(self, row, col, value):
        """
        写入单元格
        :param row: 行号（1开始）
        :param col: 列号（1开始）
        :param value: 写入的值
        """
        self.ws.cell(row=row, column=col, value=value)

    def read_cell(self, row, col):
        """
        读取单元格
        :param row: 行号
        :param col: 列号
        :return: 单元格的值
        """
        return self.ws.cell(row=row, column=col).value

    def append_row(self, data_list):
        """
        追加一行数据
        :param data_list: 列表形式的一行数据
        """
        self.ws.append(data_list)

    def read_all(self):
        """
        读取所有数据（返回二维列表）
        """
        return [[cell.value for cell in row] for row in self.ws.iter_rows()]

    def set_style(self, cell_range, font=None, fill=None, alignment=None):
        """
        批量设置单元格样式
        :param cell_range: 例如 "A1:C1"
        :param font: 字体对象
        :param fill: 填充对象
        :param alignment: 对齐对象
        """
        for row in self.ws[cell_range]:
            for cell in row:
                if font:
                    cell.font = font
                if fill:
                    cell.fill = fill
                if alignment:
                    cell.alignment = alignment

    def merge_cells(self, cell_range):
        """合并单元格"""
        self.ws.merge_cells(cell_range)

    def unmerge_cells(self, cell_range):
        """取消合并单元格"""
        self.ws.unmerge_cells(cell_range)

    def insert_formula(self, cell, formula):
        """
        插入 Excel 公式
        :param cell: 单元格位置，如 "D2"
        :param formula: 公式字符串，例如 "=SUM(A1:A3)"
        """
        self.ws[cell] = formula

    def insert_rows(self, idx, amount=1):
        """插入行"""
        self.ws.insert_rows(idx, amount)

    def delete_rows(self, idx, amount=1):
        """删除行"""
        self.ws.delete_rows(idx, amount)

    def insert_cols(self, idx, amount=1):
        """插入列"""
        self.ws.insert_cols(idx, amount)

    def delete_cols(self, idx, amount=1):
        """删除列"""
        self.ws.delete_cols(idx, amount)

    def set_column_width(self, col_letter, width):
        """设置列宽"""
        self.ws.column_dimensions[col_letter].width = width

    def set_row_height(self, row, height):
        """设置行高"""
        self.ws.row_dimensions[row].height = height

    def freeze_panes(self, cell):
        """
        冻结窗格
        :param cell: 冻结到的单元格，例如 "A2"
        """
        self.ws.freeze_panes = cell

    def save(self, filename=None):
        """
        保存 Excel 文件
        :param filename: 文件名（如果为 None，则覆盖原文件）
        """
        if filename:
            self.wb.save(filename)
            self.filename = filename
        else:
            if self.filename:
                self.wb.save(self.filename)
            else:
                raise ValueError("必须提供文件名才能保存。")

    def close(self):
        """关闭工作簿"""
        self.wb.close()

```

使用示例
```python
if __name__ == "__main__":
    excel = ExcelHelper()  # 创建新文件
    excel.set_sheet("学生成绩表")

    # 写表头
    excel.append_row(["姓名", "语文", "数学", "平均分"])

    # 写数据
    excel.append_row(["张三", 85, 90, None])
    excel.append_row(["李四", 78, 88, None])
    excel.append_row(["王五", 92, 95, None])

    # 插入公式
    for row in range(2, 5):
        excel.insert_formula(f"D{row}", f"=AVERAGE(B{row}:C{row})")

    # 设置样式
    header_font = Font(name="微软雅黑", size=12, bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="4F81BD")
    center_align = Alignment(horizontal="center", vertical="center")
    excel.set_style("A1:D1", font=header_font, fill=header_fill, alignment=center_align)

    # 设置列宽
    excel.set_column_width("A", 12)
    excel.set_column_width("B", 10)
    excel.set_column_width("C", 10)
    excel.set_column_width("D", 10)

    # 冻结首行
    excel.freeze_panes("A2")

    # 保存
    excel.save("学生成绩.xlsx")

    excel.close()

```
这样封装的好处是：

统一接口，写法更简洁

每个功能单独封装，方便维护

直接可用于生产环境

可扩展，例如加批量读取写入、数据校验等

```python
```