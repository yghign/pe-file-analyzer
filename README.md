### **《PE文件分析器项目接口约定》**

**项目成员与分工：**
*   **刘**：研究PE文件格式，实现文件头解析模块 (`pe_headers.py`)
*   **冯**：实现节表分析和解析模块 (`pe_sections.py`)
*   **贾**：实现字符串提取和哈希计算模块 (`pe_utils.py`)
*   **钟**：整合并开发GUI界面 (`gui.py`, `main.py`)

**通用规则：**
1.  **输入统一**：分析模块的函数统一接收一个参数 `pe`，它是由 `pefile.PE(file_path)` 创建的对象。
2.  **输出统一**：所有函数都返回一个 **“字典的列表”** (`List[Dict]`)，以便GUI统一显示。即使只有一条数据（如文件头），也返回一个只包含一个字典的列表。
3.  **命名统一**：函数名统一使用 `analyze_`开头。

---

#### **各模块接口详细定义**

**1. 文件头解析模块 (刘 负责)**
*   **文件：** `pe_headers.py`
*   **函数定义：**
    ```python
    def analyze_headers(pe):
        """
        解析PE文件头信息
        :param pe: pefile.PE对象
        :return: 一个列表，包含一个存储了文件头信息的字典。
        """
        # 代码实现部分...
        return [header_info_dict] # 注意：返回的是列表！
    ```
*   **返回数据格式示例：**
    ```python
    [{
        "Machine": "AMD64",
        "NumberOfSections": 5,
        "TimeDateStamp": "2022-01-01 12:00:00",
        "PointerToSymbolTable": "0x0",
        "NumberOfSymbols": 0,
        "SizeOfOptionalHeader": 240,
        "Characteristics": "Executable, 64-bit"
    }]
    ```

**2. 节表分析模块 (冯 负责)**
*   **文件：** `pe_sections.py`
*   **函数定义：**
    ```python
    def analyze_sections(pe):
        """
        解析PE文件节表信息
        :param pe: pefile.PE对象
        :return: 一个列表，每个元素是一个存储了节信息的字典。
        """
        # 代码实现部分...
        return [section_dict_1, section_dict_2, ...] # 返回包含多个字典的列表
    ```
*   **返回数据格式示例：**
    ```python
    [
        {
            "Name": ".text",
            "VirtualAddress": "0x1000",
            "Misc_VirtualSize": 2048,
            "SizeOfRawData": 2048,
            "PointerToRawData": "0x400",
            "Characteristics": "0x60000020",
            "Meaning": "可执行, 可读, 包含代码"
        },
        {
            "Name": ".data",
            "VirtualAddress": "0x2000",
            "Misc_VirtualSize": 1024,
            "SizeOfRawData": 1024,
            "PointerToRawData": "0xC00",
            "Characteristics": "0xC0000040",
            "Meaning": "可读, 可写, 包含已初始化数据"
        }
    ]
    ```

**3. 工具模块 (贾 负责)**
*   **文件：** `pe_utils.py`
*   **函数定义：**
    ```python
    def calculate_hashes(file_path):
        """
        计算文件的哈希值
        :param file_path: 文件路径（字符串）
        :return: 一个列表，包含一个存储了哈希值的字典。
        """
        # 代码实现部分...
        return [hashes_dict] # 注意：返回的是列表！

    def extract_strings(file_path, min_length=4):
        """
        从文件中提取可打印字符串
        :param file_path: 文件路径（字符串）
        :param min_length: 字符串最小长度，默认为4
        :return: 一个列表，每个元素是一个字符串字典。
        """
        # 代码实现部分...
        return [string_dict_1, string_dict_2, ...] # 返回包含多个字典的列表
    ```
*   **返回数据格式示例：**
    ```python
    # calculate_hashes 返回格式
    [{
        "MD5": "a1b2c3d4e5f6...",
        "SHA1": "1029384756...",
        "SHA256": "abcdef123456..."
    }]

    # extract_strings 返回格式
    [
        {"Offset": "0x500", "String": "Hello World"},
        {"Offset": "0x50C", "String": "This is a test"},
        {"Offset": "0x520", "String": "KERNEL32.DLL"}
    ]
    ```

**4. GUI与主程序模块 (钟 负责)**
*   **文件：** `main.py`, `gui.py`
*   **职责：**
    1.  在 `main.py` 中编写主流程，调用以上所有模块的函数。
    2.  在 `gui.py` 中设计界面，接收 `main.py` 整合后的数据并展示。
*   **调用示例 (`main.py`)：**
    ```python
    # 主程序示例
    import pefile
    from pe_headers import analyze_headers
    from pe_sections import analyze_sections
    from pe_utils import calculate_hashes, extract_strings

    def main(file_path):
        # 加载文件
        pe = pefile.PE(file_path)

        # 调用各模块函数（严格按照接口约定！）
        headers_info = analyze_headers(pe)    # 调用冯的函数
        sections_info = analyze_sections(pe)  # 调用刘的函数
        hashes_info = calculate_hashes(file_path) # 调用贾的函数
        strings_info = extract_strings(file_path) # 调用贾的函数

        # 现在得到了所有数据，可以传递给GUI显示
        # headers_info, sections_info 等都是“字典的列表”
        all_data = {
            'headers': headers_info,
            'sections': sections_info,
            'hashes': hashes_info,
            'strings': strings_info
        }
        return all_data
