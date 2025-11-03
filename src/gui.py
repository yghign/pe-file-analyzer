import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pefile
import os

class PEAnalyzerGUI:
    def __init__(self, root):
        # 初始化主窗口
        self.root = root
        self.root.title("简易PE文件分析器")
        self.root.geometry("900x600")
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

        # 标签页1：基础信息
        self.basic_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.basic_tab, text="基础信息")
        self.basic_text = tk.Text(self.basic_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.basic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页2：节表信息
        self.section_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.section_tab, text="节表信息")
        self.section_text = tk.Text(self.section_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.section_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页3：导入表信息
        self.import_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.import_tab, text="导入表信息")
        self.import_text = tk.Text(self.import_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.import_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def select_pe_file(self):
        """选择PE文件"""
        self.pe_path = filedialog.askopenfilename(
            title="选择PE文件",
            filetypes=[("PE文件", "*.exe;*.dll;*.sys"), ("所有文件", "*.*")]
        )
        if self.pe_path:
            self.file_label.config(text=f"当前文件：{os.path.basename(self.pe_path)}")
            self.analyze_btn.config(state=tk.NORMAL)  # 启用分析按钮
            self.clear_result()  # 清空历史结果

    def analyze_pe(self):
        """分析PE文件核心逻辑"""
        try:
            # 加载PE文件
            self.pe = pefile.PE(self.pe_path)
            # 解析并显示各部分信息
            self.parse_basic_info()
            self.parse_section_info()
            self.parse_import_info()
            messagebox.showinfo("分析完成", "PE文件分析成功，结果已显示在各标签页中！")
        except Exception as e:
            messagebox.showerror("分析失败", f"错误信息：{str(e)}")
            self.clear_result()

    def parse_basic_info(self):
        """解析基础信息（DOS头、NT头、文件头）"""
        info = []
        info.append("=" * 50)
        info.append("                PE文件基础信息")
        info.append("=" * 50)
        # DOS头信息
        info.append(f"1. DOS头信息:")
        info.append(
            f"   - 魔数(Magic): 0x{self.pe.DOS_HEADER.e_magic:04X} (验证为PE文件: {hex(self.pe.DOS_HEADER.e_magic) == '0x5a4d'})")
        info.append(f"   - PE头偏移: 0x{self.pe.DOS_HEADER.e_lfanew:08X}")

        # NT头信息
        info.append(f"\n2. NT头信息:")
        info.append(f"   - 签名(Signature): 0x{self.pe.NT_HEADERS.Signature:08X}")

        # 文件头信息
        info.append(f"\n3. 文件头(FileHeader)信息:")
        info.append(
            f"   - 机器类型: 0x{self.pe.FILE_HEADER.Machine:04X} ({self.get_machine_type(self.pe.FILE_HEADER.Machine)})")
        info.append(f"   - 节表数量: {self.pe.FILE_HEADER.NumberOfSections}")
        info.append(f"   - 创建时间戳: {self.pe.FILE_HEADER.TimeDateStamp}")
        info.append(f"   - 特征值: 0x{self.pe.FILE_HEADER.Characteristics:04X}")

        # 可选头信息
        info.append(f"\n4. 可选头(OptionalHeader)信息:")
        info.append(
            f"   - 魔术字: 0x{self.pe.OPTIONAL_HEADER.Magic:04X} ({'32位' if self.pe.OPTIONAL_HEADER.Magic == 0x10B else '64位'})")
        info.append(f"   - 入口点地址: 0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        info.append(f"   - 代码段起始RVA: 0x{self.pe.OPTIONAL_HEADER.BaseOfCode:08X}")
        info.append(f"   - 数据段起始RVA: 0x{self.pe.OPTIONAL_HEADER.BaseOfData:08X}")
        info.append(f"   - 镜像基址: 0x{self.pe.OPTIONAL_HEADER.ImageBase:08X}")
        info.append(f"   - 节对齐: 0x{self.pe.OPTIONAL_HEADER.SectionAlignment:08X}")
        info.append(f"   - 文件对齐: 0x{self.pe.OPTIONAL_HEADER.FileAlignment:08X}")
        info.append(f"   - 镜像大小: {self.pe.OPTIONAL_HEADER.SizeOfImage} 字节")
        info.append(f"   - 头部大小: {self.pe.OPTIONAL_HEADER.SizeOfHeaders} 字节")

        # 写入文本框
        self.basic_text.config(state=tk.NORMAL)
        self.basic_text.insert(tk.END, "\n".join(info) + "\n")
        self.basic_text.config(state=tk.DISABLED)

    def parse_section_info(self):
        """解析节表信息"""
        info = []
        info.append("=" * 80)
        info.append("                          PE文件节表信息")
        info.append("=" * 80)
        info.append(
            f"{'节名':<10} {'虚拟地址(RVA)':<15} {'虚拟大小':<12} {'文件偏移':<12} {'文件大小':<12} {'特征值':<15}")
        info.append("-" * 80)

        for section in self.pe.sections:
            section_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            info.append(
                f"{section_name:<10} "
                f"0x{section.VirtualAddress:08X:<13} "
                f"{section.Misc_VirtualSize:<12} "
                f"0x{section.PointerToRawData:08X:<10} "
                f"{section.SizeOfRawData:<12} "
                f"0x{section.Characteristics:08X}"
            )

        self.section_text.config(state=tk.NORMAL)
        self.section_text.insert(tk.END, "\n".join(info) + "\n")
        self.section_text.config(state=tk.DISABLED)

    def parse_import_info(self):
        """解析导入表信息"""
        info = []
        info.append("=" * 60)
        info.append("                          PE文件导入表信息")
        info.append("=" * 60)

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = imp.dll.decode("utf-8")
                info.append(f"\n[+] 导入DLL: {dll_name}")
                info.append(f"    函数列表:")
                for func in imp.imports:
                    func_name = func.name.decode("utf-8") if func.name else f"序数_{func.ordinal}"
                    info.append(f"      - {func_name:<30} 地址: 0x{func.address:08X}")
        else:
            info.append("[-] 该PE文件无导入表信息")

        self.import_text.config(state=tk.NORMAL)
        self.import_text.insert(tk.END, "\n".join(info) + "\n")
        self.import_text.config(state=tk.DISABLED)

    def get_machine_type(self, machine_code):
        """获取机器类型描述"""
        machine_map = {
            0x0: "未知",
            0x14C: "x86 (32位)",
            0x8664: "x64 (64位)",
            0x162: "MIPS",
            0x184: "ARM"
        }
        return machine_map.get(machine_code, "其他架构")

    def clear_result(self):
        """清空所有结果"""
        self.basic_text.config(state=tk.NORMAL)
        self.section_text.config(state=tk.NORMAL)
        self.import_text.config(state=tk.NORMAL)

        self.basic_text.delete(1.0, tk.END)
        self.section_text.delete(1.0, tk.END)
        self.import_text.delete(1.0, tk.END)

        self.basic_text.config(state=tk.DISABLED)
        self.section_text.config(state=tk.DISABLED)
        self.import_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    # 安装依赖提示（首次运行需执行）
    try:
        import pefile
    except ImportError:
        import sys
        print("请先安装依赖库：pip install pefile")
        sys.exit(1)

    root = tk.Tk()
    app = PEAnalyzerGUI(root)  # 修正这里
    root.mainloop()
