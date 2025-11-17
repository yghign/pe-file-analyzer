import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pefile
import os
import string


class PEAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("简易PE文件分析器")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.pe = None
        self.pe_path = ""
        self.setup_ui()

    def setup_ui(self):
        # 顶部选择区域
        self.top_frame = tk.Frame(self.root, padx=10, pady=10)
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

        # 中间标签页区域
        self.tab_control = ttk.Notebook(self.root)
        self.tab_control.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 标签页1：DOS头信息
        self.dos_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.dos_tab, text="DOS头信息")
        self.dos_text = tk.Text(self.dos_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.dos_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页2：基础信息
        self.basic_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.basic_tab, text="基础信息")
        self.basic_text = tk.Text(self.basic_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.basic_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页3：节表信息
        self.section_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.section_tab, text="节表信息")
        self.section_text = tk.Text(self.section_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.section_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页4：导入表信息
        self.import_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.import_tab, text="导入表信息")
        self.import_text = tk.Text(self.import_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.import_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 标签页5：字符串提取
        self.string_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.string_tab, text="字符串提取")
        self.string_text = tk.Text(self.string_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.string_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def clear_result(self):
        for text_box in [self.dos_text, self.basic_text, self.section_text, self.import_text, self.string_text]:
            text_box.config(state=tk.NORMAL)
            text_box.delete(1.0, tk.END)
            text_box.config(state=tk.DISABLED)

    def select_pe_file(self):
        self.pe_path = filedialog.askopenfilename(
            title="选择PE文件",
            filetypes=[("PE文件", "*.exe;*.dll;*.sys"), ("所有文件", "*.*")]
        )
        if self.pe_path:
            self.file_label.config(text=f"当前文件：{os.path.basename(self.pe_path)}")
            self.analyze_btn.config(state=tk.NORMAL)
            self.clear_result()

    def analyze_pe(self):
        try:
            self.pe = pefile.PE(self.pe_path)
            self.parse_dos_header()
            self.parse_basic_info()
            self.parse_section_info()
            self.parse_import_info()
            self.extract_strings()
            messagebox.showinfo("分析完成", "PE文件分析成功！")
        except Exception as e:
            messagebox.showerror("分析失败", f"错误信息：{str(e)}")
            self.clear_result()

    def parse_dos_header(self):
        info = []
        info.append("=" * 60)
        info.append("                  PE文件DOS头（IMAGE_DOS_HEADER）详细信息")
        info.append("=" * 60)
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

        self.dos_text.config(state=tk.NORMAL)
        self.dos_text.delete(1.0, tk.END)
        self.dos_text.insert(tk.END, "\n".join(info) + "\n")
        self.dos_text.config(state=tk.DISABLED)

    def parse_basic_info(self):
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

        info.append(f"\n2. NT头信息:")
        info.append(f"   - 签名(Signature): 0x{self.pe.NT_HEADERS.Signature:08X}（0x4550对应ASCII 'PE'）")

        info.append(f"\n3. 文件头(FileHeader)信息:")
        info.append(
            f"   - 机器类型: 0x{self.pe.FILE_HEADER.Machine:04X} ({self.get_machine_type(self.pe.FILE_HEADER.Machine)})")
        info.append(f"   - 节表数量: {self.pe.FILE_HEADER.NumberOfSections}")
        info.append(f"   - 创建时间戳: {self.pe.FILE_HEADER.TimeDateStamp}")
        info.append(f"   - 特征值: 0x{self.pe.FILE_HEADER.Characteristics:04X}")

        info.append(f"\n4. 可选头(OptionalHeader)信息:")
        info.append(
            f"   - 魔术字: 0x{self.pe.OPTIONAL_HEADER.Magic:04X} ({'32位' if self.pe.OPTIONAL_HEADER.Magic == 0x10B else '64位'})")
        info.append(f"   - 入口点地址: 0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        info.append(f"   - 代码段起始RVA: 0x{self.pe.OPTIONAL_HEADER.BaseOfCode:08X}")
        if hasattr(self.pe.OPTIONAL_HEADER, 'BaseOfData'):
            info.append(f"   - 数据段起始RVA: 0x{self.pe.OPTIONAL_HEADER.BaseOfData:08X}")
        info.append(f"   - 镜像基址: 0x{self.pe.OPTIONAL_HEADER.ImageBase:08X}")
        info.append(f"   - 节对齐: 0x{self.pe.OPTIONAL_HEADER.SectionAlignment:08X}")
        info.append(f"   - 文件对齐: 0x{self.pe.OPTIONAL_HEADER.FileAlignment:08X}")
        info.append(f"   - 镜像大小: {self.pe.OPTIONAL_HEADER.SizeOfImage} 字节")
        info.append(f"   - 头部大小: {self.pe.OPTIONAL_HEADER.SizeOfHeaders} 字节")

        self.basic_text.config(state=tk.NORMAL)
        self.basic_text.delete(1.0, tk.END)
        self.basic_text.insert(tk.END, "\n".join(info) + "\n")
        self.basic_text.config(state=tk.DISABLED)

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
                f"{section_name:<10} 0x{section.VirtualAddress:08X}     {section.Misc_VirtualSize:<12} 0x{section.PointerToRawData:08X}     {section.SizeOfRawData:<12} 0x{section.Characteristics:08X}")

        self.section_text.config(state=tk.NORMAL)
        self.section_text.delete(1.0, tk.END)
        self.section_text.insert(tk.END, "\n".join(info) + "\n")
        self.section_text.config(state=tk.DISABLED)

    def extract_strings(self):
        info = []
        info.append("=" * 60)
        info.append("                PE文件可打印字符串提取（ASCII）")
        info.append("=" * 60)
        info.append(f"说明：仅显示长度≥4的可打印字符串\n")

        try:
            with open(self.pe_path, "rb") as f:
                raw_data = f.read()

            current_string = b""
            strings_found = []

            for byte in raw_data:
                if 0x20 <= byte <= 0x7E:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= 4:
                        strings_found.append(current_string.decode("ascii", errors="replace"))
                    current_string = b""

            if len(current_string) >= 4:
                strings_found.append(current_string.decode("ascii", errors="replace"))

            max_display = 1000
            if len(strings_found) > max_display:
                info.append(f"注：发现 {len(strings_found)} 个字符串，仅显示前 {max_display} 个\n")
                strings_found = strings_found[:max_display]

            if strings_found:
                info.extend(strings_found)
            else:
                info.append("未提取到可打印字符串")

        except Exception as e:
            info.append(f"字符串提取失败: {str(e)}")

        self.string_text.config(state=tk.NORMAL)
        self.string_text.delete(1.0, tk.END)
        self.string_text.insert(tk.END, "\n".join(info) + "\n")
        self.string_text.config(state=tk.DISABLED)

    def parse_import_info(self):
        info = []
        info.append("=" * 60)
        info.append("                          PE文件导入表信息")
        info.append("=" * 60)

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = imp.dll.decode("utf-8", errors="replace")
                info.append(f"\n[+] 导入DLL: {dll_name}")
                info.append(f"    函数列表:")
                for func in imp.imports:
                    if func.name:
                        func_name = func.name.decode("utf-8", errors="replace")
                    else:
                        func_name = f"序数_{func.ordinal}"
                    info.append(f"      - {func_name:<30} 地址: 0x{func.address:08X}")
        else:
            info.append("[-] 该PE文件无导入表信息")

        self.import_text.config(state=tk.NORMAL)
        self.import_text.delete(1.0, tk.END)
        self.import_text.insert(tk.END, "\n".join(info) + "\n")
        self.import_text.config(state=tk.DISABLED)

    def get_machine_type(self, machine_code):
        machine_map = {
            0x0: "未知",
            0x14C: "x86 (32位)",
            0x8664: "x64 (64位)",
            0x162: "MIPS",
            0x184: "ARM",
            0x1C0: "ARM64",
            0x1F0: "PowerPC"
        }
        return machine_map.get(machine_code, f"其他架构 (0x{machine_code:04X})")


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
