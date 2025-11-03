import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import sys

# 添加src目录到Python路径
sys.path.append(os.path.dirname(__file__))

# 导入各组员的模块
try:
    from pe_headers import analyze_headers
    from pe_sections import analyze_sections
    from pe_imports import analyze_imports
    from pe_utils import calculate_hashes, extract_strings
    import pefile
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保所有依赖库已安装: pip install pefile")
    sys.exit(1)


class PEAnalyzerGUI:
    def __init__(self, root):
        # 初始化主窗口
        self.root = root
        self.root.title("简易PE文件分析器 - 团队项目")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)

        # 存储PE文件对象和路径
        self.pe = None
        self.pe_path = ""

        # 1. 顶部选择区域
        self.top_frame = tk.Frame(root, padx=10, pady=10)
        self.top_frame.pack(fill=tk.X)

        self.select_btn = tk.Button(
            self.top_frame, text="选择PE文件", command=self.select_pe_file,
            width=15, height=2, bg="#4CAF50", fg="white"
        )
        self.select_btn.pack(side=tk.LEFT, padx=5)

        self.analyze_btn = tk.Button(
            self.top_frame, text="开始分析", command=self.analyze_pe,
            width=15, height=2, bg="#2196F3", fg="white", state=tk.DISABLED
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = tk.Button(
            self.top_frame, text="清空结果", command=self.clear_result,
            width=15, height=2, bg="#f44336", fg="white"
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        self.file_label = tk.Label(self.top_frame, text="未选择文件", font=("Arial", 10))
        self.file_label.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=10)

        # 2. 中间标签页区域
        self.tab_control = ttk.Notebook(root)
        self.tab_control.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 创建各个标签页
        self.create_tabs()

    def create_tabs(self):
        """创建所有标签页"""
        # 基础信息标签页（冯亮媚）
        self.basic_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.basic_tab, text="基础信息")
        self.basic_text = self.create_text_widget(self.basic_tab)

        # 节表分析标签页（你）
        self.section_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.section_tab, text="节表分析")
        self.section_text = self.create_text_widget(self.section_tab)

        # 导入表分析标签页（Eee）
        self.import_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.import_tab, text="导入表分析")
        self.import_text = self.create_text_widget(self.import_tab)

        # 字符串提取标签页（Eee）
        self.strings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.strings_tab, text="字符串提取")
        self.strings_text = self.create_text_widget(self.strings_tab)

        # 文件哈希标签页（Eee）
        self.hashes_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.hashes_tab, text="文件哈希")
        self.hashes_text = self.create_text_widget(self.hashes_tab)

    def create_text_widget(self, parent):
        """创建带滚动条的文本框"""
        text_widget = tk.Text(parent, wrap=tk.WORD, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        return text_widget

    def select_pe_file(self):
        """选择PE文件"""
        self.pe_path = filedialog.askopenfilename(
            title="选择PE文件",
            filetypes=[("PE文件", "*.exe;*.dll;*.sys"), ("所有文件", "*.*")]
        )
        if self.pe_path:
            self.file_label.config(text=f"当前文件：{os.path.basename(self.pe_path)}")
            self.analyze_btn.config(state=tk.NORMAL)
            self.clear_result()

    def analyze_pe(self):
        """分析PE文件 - 集成各个模块"""
        try:
            # 加载PE文件
            self.pe = pefile.PE(self.pe_path)

            # 使用各个模块进行分析
            self.display_basic_info()  # 冯亮媚的模块
            self.display_section_info()  # 你的模块
            self.display_import_info()  # Eee的模块
            self.display_strings_info()  # Eee的模块
            self.display_hashes_info()  # Eee的模块

            messagebox.showinfo("分析完成", "PE文件分析成功！所有模块集成完成。")

        except Exception as e:
            messagebox.showerror("分析失败", f"错误信息：{str(e)}")
            self.clear_result()

    def display_basic_info(self):
        """显示基础信息 - 使用冯亮媚的模块"""
        self.clear_text_widget(self.basic_text)

        try:
            headers_info = analyze_headers(self.pe)

            info = ["=" * 60, "PE文件基础信息", "=" * 60, ""]

            for header in headers_info:
                for key, value in header.items():
                    info.append(f"{key}: {value}")
                info.append("")

            self.insert_text(self.basic_text, "\n".join(info))

        except Exception as e:
            self.insert_text(self.basic_text, f"基础信息解析失败: {str(e)}")

    def display_section_info(self):
        """显示节表信息 - 使用你的模块"""
        self.clear_text_widget(self.section_text)

        try:
            sections_result = analyze_sections(self.pe)

            if sections_result["status"] == "success":
                info = ["=" * 80, "PE文件节表分析", "=" * 80, ""]

                for i, section in enumerate(sections_result["sections"], 1):
                    info.append(f"节 #{i}: {section['name']}")
                    info.append(f"  用途: {section['purpose']}")
                    info.append(f"  内存地址: {section['memory_layout']['virtual_address_hex']}")
                    info.append(f"  内存大小: {section['memory_layout']['virtual_size_hex']}")
                    info.append(f"  文件大小: {section['file_layout']['raw_size_hex']}")
                    info.append(f"  权限: {section['security']['permissions']}")

                    # 显示安全分析
                    security_notes = section['security']['security_analysis']
                    if security_notes:
                        info.append("  安全分析:")
                        for note in security_notes:
                            info.append(f"    - {note}")

                    info.append("")

                self.insert_text(self.section_text, "\n".join(info))
            else:
                self.insert_text(self.section_text, "节表分析失败")

        except Exception as e:
            self.insert_text(self.section_text, f"节表分析失败: {str(e)}")

    def display_import_info(self):
        """显示导入表信息 - 使用Eee的模块"""
        self.clear_text_widget(self.import_text)

        try:
            imports_info = analyze_imports(self.pe)

            info = ["=" * 60, "PE文件导入表分析", "=" * 60, ""]

            for import_item in imports_info:
                info.append(f"DLL: {import_item['dll_name']}")
                info.append(f"函数数量: {import_item['function_count']}")
                info.append("导入函数:")

                for func in import_item['functions']:
                    info.append(f"  - {func['name']}")

                info.append("")

            self.insert_text(self.import_text, "\n".join(info))

        except Exception as e:
            self.insert_text(self.import_text, f"导入表分析失败: {str(e)}")

    def display_strings_info(self):
        """显示字符串信息 - 使用Eee的模块"""
        self.clear_text_widget(self.strings_text)

        try:
            strings_info = extract_strings(self.pe_path)

            info = ["=" * 60, "PE文件字符串提取", "=" * 60, ""]
            info.append(f"共找到 {len(strings_info)} 个字符串\n")

            for string_item in strings_info[:50]:  # 只显示前50个，避免太多
                info.append(f"偏移: {string_item['offset']}")
                info.append(f"字符串: {string_item['string'][:100]}...")  # 限制长度
                info.append("-" * 40)

            if len(strings_info) > 50:
                info.append(f"\n... 还有 {len(strings_info) - 50} 个字符串未显示")

            self.insert_text(self.strings_text, "\n".join(info))

        except Exception as e:
            self.insert_text(self.strings_text, f"字符串提取失败: {str(e)}")

    def display_hashes_info(self):
        """显示哈希值信息 - 使用Eee的模块"""
        self.clear_text_widget(self.hashes_text)

        try:
            hashes_info = calculate_hashes(self.pe_path)

            info = ["=" * 60, "PE文件哈希值", "=" * 60, ""]

            for hash_item in hashes_info:
                for hash_type, hash_value in hash_item.items():
                    info.append(f"{hash_type}: {hash_value}")

            self.insert_text(self.hashes_text, "\n".join(info))

        except Exception as e:
            self.insert_text(self.hashes_text, f"哈希计算失败: {str(e)}")

    def clear_text_widget(self, text_widget):
        """清空文本框"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)

    def insert_text(self, text_widget, text):
        """向文本框插入文本"""
        text_widget.config(state=tk.NORMAL)
        text_widget.insert(tk.END, text + "\n")
        text_widget.config(state=tk.DISABLED)

    def clear_result(self):
        """清空所有结果"""
        self.clear_text_widget(self.basic_text)
        self.clear_text_widget(self.section_text)
        self.clear_text_widget(self.import_text)
        self.clear_text_widget(self.strings_text)
        self.clear_text_widget(self.hashes_text)


def main():
    """主程序入口"""
    root = tk.Tk()
    app = PEAnalyzerGUI(root)
    root.mainloop()



if __name__ == "__main__":
    main()