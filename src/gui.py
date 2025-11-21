import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pefile
import os
import string


class PEAnalyzerGUI:
    def __init__(self, root):
        # 初始化主窗口（原有代码不变）
        self.root = root
        self.root.title("简易PE文件分析器")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.pe = None
        self.pe_path = ""

        # 顶部选择区域（原有代码不变）
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

        # 中间标签页区域：新增【DOS头信息】标签页
        self.tab_control = ttk.Notebook(root)
        self.tab_control.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 新增标签页1：DOS头信息（专门展示DOS头解析结果）
        self.dos_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.dos_tab, text="DOS头信息")
        self.dos_text = tk.Text(self.dos_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.dos_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页2：基础信息（原有代码不变，移除原DOS头相关解析）
        self.basic_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.basic_tab, text="基础信息")
        self.basic_text = tk.Text(self.basic_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.basic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页3：节表信息（原有代码不变）
        self.section_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.section_tab, text="节表信息")
        self.section_text = tk.Text(self.section_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.section_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页4：导入表信息（原有代码不变）
        self.import_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.import_tab, text="导入表信息")
        self.import_text = tk.Text(self.import_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.import_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页5：字符串提取（原有代码不变）
        self.string_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.string_tab, text="字符串提取")
        self.string_text = tk.Text(self.string_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.string_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # 原有函数：select_pe_file（不变）
    def select_pe_file(self):
        self.pe_path = filedialog.askopenfilename(
            title="选择PE文件",
            filetypes=[("PE文件", "*.exe;*.dll;*.sys"), ("所有文件", "*.*")]
        )
        if self.pe_path:
            self.file_label.config(text=f"当前文件：{os.path.basename(self.pe_path)}")
            self.analyze_btn.config(state=tk.NORMAL)
            self.clear_result()

    # 核心分析函数：新增 parse_dos_header() 调用
    def analyze_pe(self):
        try:
            self.pe = pefile.PE(self.pe_path)
            # 1. 先调用DOS头解析函数（新增）
            self.parse_dos_header()
            # 2. 原有分析流程（基础属性→结构信息→字符串提取）
            self.simple_pe_analysis()
            self.parse_basic_info()
            self.parse_section_info()
            self.parse_import_info()
            self.simple_string_extract()
            messagebox.showinfo("分析完成", "PE文件全量分析（含DOS头）成功！")
        except Exception as e:
            messagebox.showerror("分析失败", f"错误信息：{str(e)}")
            self.clear_result()

    # 新增函数：parse_dos_header（专门解析DOS头详细信息）
    def parse_dos_header(self):
        """独立解析PE文件DOS头信息，展示关键字段"""
        info = []
        info.append("=" * 60)
        info.append("                  PE文件DOS头（IMAGE_DOS_HEADER）详细信息")
        info.append("=" * 60)
        # DOS头核心字段解析
        dos_header = self.pe.DOS_HEADER
        info.append(f"1. 魔数（e_magic）: 0x{dos_header.e_magic:04X}")
        info.append(f"   - 含义: {'有效DOS头' if dos_header.e_magic == 0x5A4D else '无效DOS头'}（0x5A4D对应ASCII 'MZ'）")
        info.append(f"2. 最后一页字节数（e_cblp）: {dos_header.e_cblp}")
        info.append(f"3. 文件总页数（e_cp）: {dos_header.e_cp}")
        info.append(f"4. 重定位项数（e_crlc）: {dos_header.e_crlc}")
        info.append(f"5. 头部大小（e_cparhdr）: {dos_header.e_cparhdr} 个段落（1段落=16字节）")
        info.append(f"6. 最小附加段（e_minalloc）: {dos_header.e_minalloc}")
        info.append(f"7. 最大附加段（e_maxalloc）: {dos_header.e_maxalloc}")
        info.append(f"8. 初始SS值（e_ss）: 0x{dos_header.e_ss:04X}（DOS时代栈段寄存器）")
        info.append(f"9. 初始SP值（e_sp）: 0x{dos_header.e_sp:04X}（DOS时代栈指针）")
        info.append(f"10. 校验和（e_csum）: 0x{dos_header.e_csum:04X}")
        info.append(f"11. 初始IP值（e_ip）: 0x{dos_header.e_ip:04X}（DOS时代指令指针）")
        info.append(f"12. 初始CS值（e_cs）: 0x{dos_header.e_cs:04X}（DOS时代代码段寄存器）")
        info.append(f"13. 重定位表偏移（e_lfarlc）: 0x{dos_header.e_lfarlc:04X}")
        info.append(f"14. overlay编号（e_ovno）: {dos_header.e_ovno}")
        info.append(f"15. PE头偏移（e_lfanew）: 0x{dos_header.e_lfanew:08X}")
        info.append(f"    - 作用: 指向NT头起始位置，是PE文件结构的关键跳转点")

        # 写入DOS头标签页
        self.dos_text.config(state=tk.NORMAL)
        self.dos_text.insert(tk.END, "\n".join(info) + "\n")
        self.dos_text.config(state=tk.DISABLED)

    # 原有函数：parse_basic_info（移除原DOS头解析部分，避免重复）
    def parse_basic_info(self):
        info = []
        info.append("=" * 50)
        info.append("                PE文件基础信息（NT头+文件头+可选头）")
        info.append("=" * 50)
        # NT头信息
        info.append(f"1. NT头信息:")
        info.append(f"   - 签名(Signature): 0x{self.pe.NT_HEADERS.Signature:08X}（0x4550对应ASCII 'PE'）")
        # 文件头信息
        info.append(f"\n2. 文件头(FileHeader)信息:")
        info.append(
            f"   - 机器类型: 0x{self.pe.FILE_HEADER.Machine:04X} ({self.get_machine_type(self.pe.FILE_HEADER.Machine)})")
        info.append(f"   - 节表数量: {self.pe.FILE_HEADER.NumberOfSections}")
        info.append(f"   - 创建时间戳: {self.pe.FILE_HEADER.TimeDateStamp}")
        info.append(f"   - 特征值: 0x{self.pe.FILE_HEADER.Characteristics:04X}")
        # 可选头信息
        info.append(f"\n3. 可选头(OptionalHeader)信息:")
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
        self.basic_text.config(state=tk.NORMAL)
        self.basic_text.insert(tk.END, "\n".join(info) + "\n")
        self.basic_text.config(state=tk.DISABLED)

    # 原有函数：parse_section_info（不变）
    def parse_section_info(self):
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
                f"{section_name:<10} 0x{section.VirtualAddress:08X:<13} {section.Misc_VirtualSize:<12} 0x{section.PointerToRawData:08X:<10} {section.SizeOfRawData:<12} 0x{section.Characteristics:08X}")
        self.section_text.config(state=tk.NORMAL)
        self.section_text.insert(tk.END, "\n".join(info) + "\n")
        self.section_text.config(state=tk.DISABLED)

    # 原有函数：parse_import_info（不变）
    def parse_import_info(self):
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

    # 原有函数：get_machine_type（不变）
    def get_machine_type(self, machine_code):
        machine_map = {0x0: "未知", 0x14C: "x86 (32位)", 0x8664: "x64 (64位)", 0x162: "MIPS", 0x184: "ARM"}
        return machine_map.get(machine_code, "其他架构")

    # 原有函数：clear_result（新增DOS头文本框清空）
    def clear_result(self):
        for text_box in [self.dos_text, self.basic_text, self.section_text, self.import_text, self.string_text]:
            text_box.config(state=tk.NORMAL)
            text_box.delete(1.0, tk.END)
            text_box.config(state=tk.DISABLED)

    # 原有函数：simple_pe_analysis（不变）
    def simple_pe_analysis(self):
        info = []
        info.append("=" * 50)
        info.append("                PE文件基础信息（属性分析）")
        info.append("=" * 50)
        file_size = os.path.getsize(self.pe_path)
        info.append(f"1. 文件属性:")
        info.append(f"   - 文件路径: {self.pe_path}")
        info.append(f"   - 文件大小: {file_size} 字节 ({file_size / 1024:.2f} KB)")
        is_executable = (self.pe.FILE_HEADER.Characteristics & 0x0002) != 0
        info.append(f"   - 是否可执行: {'是' if is_executable else '否'}")
        is_dll = (self.pe.FILE_HEADER.Characteristics & 0x2000) != 0
        info.append(f"   - 是否为DLL: {'是' if is_dll else '否'}")
        self.basic_text.config(state=tk.NORMAL)
        self.basic_text.insert(tk.END, "\n".join(info) + "\n\n")
        self.basic_text.config(state=tk.DISABLED)

    # 原有函数：simple_string_extract（不变）
    def simple_string_extract(self):
        info = []
        info.append("=" * 60)
        info.append("                PE文件可打印字符串提取（ASCII）")
        info.append("=" * 60)
        info.append(f"说明：仅显示长度≥4的可打印字符串\n")
        with open(self.pe_path, "rb") as f:
            raw_data = f.read()
        current_string = b""
        for byte in raw_data:
            if 0x20 <= byte <= 0x7E:
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:
                    info.append(current_string.decode("ascii", errors="replace"))
                current_string = b""
        if len(current_string) >= 4:
            info.append(current_string.decode("ascii", errors="replace"))
        self.string_text.config(state=tk.NORMAL)
        if len(info) > 3:
            self.string_text.insert(tk.END, "\n".join(info) + "\n")
        else:
            self.string_text.insert(tk.END,
                                    "=" * 60 + "\n" + "                未提取到可打印字符串\n" + "=" * 60 + "\n")
        self.string_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    try:
        import pefile
    except ImportError:
        import sys

        print("请先安装依赖库：pip install pefile")
        sys.exit(1)
    root = tk.Tk()
    app = PEAnalyzerGUI(root)
    root.mainloop()
