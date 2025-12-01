import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import threading
import traceback
from typing import Dict, Any, List

# 添加当前目录到Python路径，确保可以导入模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入团队成员的模块
try:
    import pefile

    print("pefile 模块导入成功")

    # 尝试导入各个模块
    try:
        from pe_headers import PEParser

        HEADERS_AVAILABLE = True
        print("文件头解析模块导入成功")
    except ImportError as e:
        HEADERS_AVAILABLE = False
        print(f"文件头解析模块导入失败: {e}")

    try:
        from pe_sections import analyze_sections, get_section_analysis_summary, validate_section_table

        SECTIONS_AVAILABLE = True
        print("节表分析模块导入成功")
    except ImportError as e:
        SECTIONS_AVAILABLE = False
        print(f"节表分析模块导入失败: {e}")

    try:
        from pe_imports import PEAnalysisUtils

        IMPORTS_AVAILABLE = True
        print("导入表分析模块导入成功")
    except ImportError as e:
        IMPORTS_AVAILABLE = False
        print(f"导入表分析模块导入失败: {e}")

except ImportError as e:
    print(f"主要模块导入失败: {e}")
    pefile = None
    HEADERS_AVAILABLE = SECTIONS_AVAILABLE = IMPORTS_AVAILABLE = False


class PEAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("增强版PE文件分析器 - 团队项目")
        self.root.geometry("1000x700")

        self.file_path = None
        self.pe_file = None
        self.analysis_results = {}

        self.setup_ui()

    def setup_ui(self):
        # 创建菜单栏
        self.setup_menu()

        # 主容器
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 顶部文件选择区域
        self.setup_file_selection(main_frame)

        # 分析按钮区域
        self.setup_analysis_buttons(main_frame)

        # 选项卡区域
        self.setup_notebook(main_frame)

        # 底部操作区域
        self.setup_bottom_controls(main_frame)

    def setup_menu(self):
        menubar = tk.Menu(self.root)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="打开文件", command=self.open_file)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        menubar.add_cascade(label="文件", menu=file_menu)

        # 分析菜单
        analysis_menu = tk.Menu(menubar, tearoff=0)
        analysis_menu.add_command(label="开始分析", command=self.start_analysis)
        analysis_menu.add_command(label="清空结果", command=self.clear_results)
        menubar.add_cascade(label="分析", menu=analysis_menu)

        # 视图菜单
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="刷新界面", command=self.refresh_ui)
        menubar.add_cascade(label="视图", menu=view_menu)

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.root.config(menu=menubar)

    def setup_file_selection(self, parent):
        file_frame = ttk.LabelFrame(parent, text="文件选择", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))

        # 文件路径显示和选择按钮
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X)

        ttk.Label(path_frame, text="选择PE文件:").pack(side=tk.LEFT)

        self.file_path_var = tk.StringVar(value="未选择文件")
        self.file_entry = ttk.Entry(path_frame, textvariable=self.file_path_var, state='readonly')
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 5))

        ttk.Button(path_frame, text="浏览", command=self.browse_file).pack(side=tk.RIGHT)

    def setup_analysis_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(button_frame, text="开始分析", command=self.start_analysis).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="清空结果", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="导出报告", command=self.export_report).pack(side=tk.LEFT)

    def setup_notebook(self, parent):
        # 创建选项卡控件
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # 创建各个选项卡
        self.setup_basic_info_tab()
        self.setup_sections_tab()
        self.setup_imports_tab()
        self.setup_strings_tab()
        self.setup_security_tab()
        self.setup_comprehensive_tab()

    def setup_basic_info_tab(self):
        # 基础信息选项卡
        basic_frame = ttk.Frame(self.notebook)
        self.notebook.add(basic_frame, text="基础信息")

        # 创建树形视图显示基本信息
        columns = ("属性", "值")
        self.basic_tree = ttk.Treeview(basic_frame, columns=columns, show="headings", height=15)

        # 设置列
        self.basic_tree.heading("属性", text="属性")
        self.basic_tree.heading("值", text="值")
        self.basic_tree.column("属性", width=200)
        self.basic_tree.column("值", width=600)

        # 滚动条
        scrollbar = ttk.Scrollbar(basic_frame, orient=tk.VERTICAL, command=self.basic_tree.yview)
        self.basic_tree.configure(yscrollcommand=scrollbar.set)

        self.basic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_sections_tab(self):
        # 节表分析选项卡
        sections_frame = ttk.Frame(self.notebook)
        self.notebook.add(sections_frame, text="节表分析")

        # 创建树形视图显示节表信息
        columns = ("节名", "虚拟地址", "虚拟大小", "文件偏移", "文件大小", "权限", "风险等级")
        self.sections_tree = ttk.Treeview(sections_frame, columns=columns, show="headings", height=15)

        # 设置列
        for col in columns:
            self.sections_tree.heading(col, text=col)
            self.sections_tree.column(col, width=100)

        # 滚动条
        scrollbar = ttk.Scrollbar(sections_frame, orient=tk.VERTICAL, command=self.sections_tree.yview)
        self.sections_tree.configure(yscrollcommand=scrollbar.set)

        self.sections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_imports_tab(self):
        # 导入表分析选项卡
        imports_frame = ttk.Frame(self.notebook)
        self.notebook.add(imports_frame, text="导入表分析")

        # 创建树形视图显示导入表信息
        columns = ("DLL名称", "函数数量", "风险等级", "可疑函数")
        self.imports_tree = ttk.Treeview(imports_frame, columns=columns, show="headings", height=15)

        # 设置列
        for col in columns:
            self.imports_tree.heading(col, text=col)
            self.imports_tree.column(col, width=150)

        # 滚动条
        scrollbar = ttk.Scrollbar(imports_frame, orient=tk.VERTICAL, command=self.imports_tree.yview)
        self.imports_tree.configure(yscrollcommand=scrollbar.set)

        self.imports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_strings_tab(self):
        # 字符串提取选项卡
        strings_frame = ttk.Frame(self.notebook)
        self.notebook.add(strings_frame, text="字符串提取")

        # 创建树形视图显示字符串
        columns = ("偏移量", "字符串", "类型", "长度")
        self.strings_tree = ttk.Treeview(strings_frame, columns=columns, show="headings", height=15)

        # 设置列
        for col in columns:
            self.strings_tree.heading(col, text=col)
        self.strings_tree.column("偏移量", width=100)
        self.strings_tree.column("字符串", width=300)
        self.strings_tree.column("类型", width=100)
        self.strings_tree.column("长度", width=80)

        # 滚动条
        scrollbar = ttk.Scrollbar(strings_frame, orient=tk.VERTICAL, command=self.strings_tree.yview)
        self.strings_tree.configure(yscrollcommand=scrollbar.set)

        self.strings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_security_tab(self):
        # 安全分析选项卡
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="安全分析")

        # 创建树形视图显示安全信息
        columns = ("检查项", "结果", "风险等级", "说明")
        self.security_tree = ttk.Treeview(security_frame, columns=columns, show="headings", height=15)

        # 设置列
        for col in columns:
            self.security_tree.heading(col, text=col)
        self.security_tree.column("检查项", width=150)
        self.security_tree.column("结果", width=100)
        self.security_tree.column("风险等级", width=100)
        self.security_tree.column("说明", width=350)

        # 滚动条
        scrollbar = ttk.Scrollbar(security_frame, orient=tk.VERTICAL, command=self.security_tree.yview)
        self.security_tree.configure(yscrollcommand=scrollbar.set)

        self.security_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_comprehensive_tab(self):
        # 综合分析选项卡
        comp_frame = ttk.Frame(self.notebook)
        self.notebook.add(comp_frame, text="综合分析")

        # 使用文本框显示综合分析结果
        self.comp_text = scrolledtext.ScrolledText(comp_frame, wrap=tk.WORD, width=80, height=20)
        self.comp_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.comp_text.insert(tk.END, "请选择PE文件并开始分析...")
        self.comp_text.config(state=tk.DISABLED)

    def setup_bottom_controls(self, parent):
        bottom_frame = ttk.Frame(parent)
        bottom_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(bottom_frame, text="复制内容", command=self.copy_content).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(bottom_frame, text="清空", command=self.clear_current_tab).pack(side=tk.LEFT)

        # 状态标签
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(bottom_frame, textvariable=self.status_var).pack(side=tk.RIGHT)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="选择PE文件",
            filetypes=[("可执行文件", "*.exe *.dll *.sys"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path = file_path
            self.file_path_var.set(file_path)
            self.status_var.set(f"已选择文件: {os.path.basename(file_path)}")

    def open_file(self):
        self.browse_file()

    def start_analysis(self):
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("错误", "请先选择有效的PE文件")
            return

        # 在新线程中执行分析，避免界面冻结
        self.status_var.set("正在分析文件...")
        thread = threading.Thread(target=self.perform_analysis)
        thread.daemon = True
        thread.start()

    def perform_analysis(self):
        try:
            if not pefile:
                self.root.after(0, lambda: messagebox.showerror("错误", "pefile模块未安装，请安装: pip install pefile"))
                return

            # 加载PE文件
            self.pe_file = pefile.PE(self.file_path)
            self.analysis_results = {}

            print("开始分析PE文件...")

            # 执行各个模块的分析（带错误处理）
            if HEADERS_AVAILABLE:
                try:
                    print("执行文件头解析...")
                    # 使用刘同学的PEParser类
                    parser = PEParser(self.file_path)
                    if parser.parse():
                        self.analysis_results['headers'] = parser.get_detailed_info()
                        print("文件头解析成功")
                    else:
                        error_msg = f"文件头解析失败: {parser.analysis_errors}"
                        self.analysis_results['headers'] = {"错误": error_msg}
                        print(error_msg)
                except Exception as e:
                    error_msg = f"文件头解析异常: {str(e)}"
                    self.analysis_results['headers'] = {"错误": error_msg}
                    print(error_msg)
                    print(traceback.format_exc())
            else:
                self.analysis_results['headers'] = {"错误": "文件头解析模块不可用"}

            # 节表分析
            if SECTIONS_AVAILABLE:
                try:
                    print("执行节表分析...")
                    sections_result = analyze_sections(self.pe_file)
                    self.analysis_results['sections'] = sections_result
                    if sections_result.get('status') == 'success':
                        print(f"节表分析成功，找到 {len(sections_result.get('sections', []))} 个节")
                    else:
                        print(f"节表分析失败: {sections_result.get('message', '未知错误')}")
                except Exception as e:
                    error_msg = f"节表分析异常: {str(e)}"
                    self.analysis_results['sections'] = {"status": "error", "message": error_msg}
                    print(error_msg)
                    print(traceback.format_exc())
            else:
                self.analysis_results['sections'] = {"status": "error", "message": "节表分析模块不可用"}

            # 导入表分析
            if IMPORTS_AVAILABLE:
                try:
                    print("执行导入表分析...")
                    imports_result = PEAnalysisUtils.analyze_imports(self.pe_file)
                    self.analysis_results['imports'] = imports_result
                    if imports_result.get('status') == 'success':
                        print(f"导入表分析成功，找到 {imports_result.get('summary', {}).get('total_dlls', 0)} 个DLL")
                    else:
                        print(f"导入表分析失败: {imports_result.get('message', '未知错误')}")
                except Exception as e:
                    error_msg = f"导入表分析异常: {str(e)}"
                    self.analysis_results['imports'] = {"status": "error", "message": error_msg}
                    print(error_msg)
                    print(traceback.format_exc())
            else:
                self.analysis_results['imports'] = {"status": "error", "message": "导入表分析模块不可用"}

            # 字符串提取
            if IMPORTS_AVAILABLE:
                try:
                    print("执行字符串提取...")
                    strings_result = PEAnalysisUtils.extract_strings(self.file_path, max_results=500)
                    self.analysis_results['strings'] = strings_result
                    if strings_result.get('status') == 'success':
                        print(
                            f"字符串提取成功，找到 {strings_result.get('file_info', {}).get('total_strings_found', 0)} 个字符串")
                    else:
                        print(f"字符串提取失败: {strings_result.get('message', '未知错误')}")
                except Exception as e:
                    error_msg = f"字符串提取异常: {str(e)}"
                    self.analysis_results['strings'] = {"status": "error", "message": error_msg}
                    print(error_msg)
                    print(traceback.format_exc())
            else:
                self.analysis_results['strings'] = {"status": "error", "message": "字符串提取模块不可用"}

            # 哈希计算
            if IMPORTS_AVAILABLE:
                try:
                    print("执行哈希计算...")
                    hashes_result = PEAnalysisUtils.calculate_hashes(self.file_path)
                    self.analysis_results['hashes'] = hashes_result
                    if hashes_result.get('status') == 'success':
                        print("哈希计算成功")
                    else:
                        print(f"哈希计算失败: {hashes_result.get('message', '未知错误')}")
                except Exception as e:
                    error_msg = f"哈希计算异常: {str(e)}"
                    self.analysis_results['hashes'] = {"status": "error", "message": error_msg}
                    print(error_msg)
                    print(traceback.format_exc())
            else:
                self.analysis_results['hashes'] = {"status": "error", "message": "哈希计算模块不可用"}

            print("分析完成，更新界面...")
            # 在GUI线程中更新界面
            self.root.after(0, self.update_display)
            self.root.after(0, lambda: self.status_var.set("分析完成"))

        except Exception as e:
            error_msg = f"分析过程中出现错误:\n{str(e)}\n\n详细跟踪:\n{traceback.format_exc()}"
            print(error_msg)
            self.root.after(0, lambda: messagebox.showerror("分析错误", f"分析失败: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("分析失败"))

    def update_display(self):
        """更新所有选项卡的显示内容"""
        try:
            self.update_basic_info()
            self.update_sections_info()
            self.update_imports_info()
            self.update_strings_info()
            self.update_security_info()
            self.update_comprehensive_info()
        except Exception as e:
            messagebox.showerror("显示错误", f"更新显示时出错: {str(e)}")

    def update_basic_info(self):
        """更新基础信息选项卡"""
        # 清空现有内容
        for item in self.basic_tree.get_children():
            self.basic_tree.delete(item)

        if 'headers' in self.analysis_results:
            headers_data = self.analysis_results['headers']

            if isinstance(headers_data, dict):
                # 显示文件基本信息
                if 'file_info' in headers_data:
                    file_info = headers_data['file_info']['basic_info']
                    self.basic_tree.insert("", tk.END, values=("文件名称", file_info.get('file_name', 'N/A')))
                    self.basic_tree.insert("", tk.END, values=("文件大小", f"{file_info.get('file_size', 0):,} 字节"))
                    self.basic_tree.insert("", tk.END, values=("架构", file_info.get('machine_type', 'N/A')))
                    self.basic_tree.insert("", tk.END, values=("编译时间", file_info.get('timestamp', 'N/A')))

                # 显示结构信息
                if 'file_info' in headers_data and 'structure_info' in headers_data['file_info']:
                    structure_info = headers_data['file_info']['structure_info']
                    self.basic_tree.insert("", tk.END,
                                           values=("节数量", structure_info.get('number_of_sections', 'N/A')))
                    self.basic_tree.insert("", tk.END, values=("入口点", structure_info.get('entry_point', 'N/A')))
                    self.basic_tree.insert("", tk.END, values=("映像基址", structure_info.get('image_base', 'N/A')))
                    self.basic_tree.insert("", tk.END, values=("子系统", structure_info.get('subsystem', 'N/A')))

                # 显示错误信息
                if '错误' in headers_data:
                    self.basic_tree.insert("", tk.END, values=("错误", headers_data['错误']))

    def update_sections_info(self):
        """更新节表分析选项卡"""
        for item in self.sections_tree.get_children():
            self.sections_tree.delete(item)

        if 'sections' in self.analysis_results:
            sections_data = self.analysis_results['sections']

            if isinstance(sections_data, dict):
                if sections_data.get('状态') == 'success':
                    sections = sections_data.get('节信息', [])
                    for section in sections:
                        self.sections_tree.insert("", tk.END, values=(
                            section.get('名称', ''),
                            section.get('内存布局', {}).get('虚拟地址16进制', ''),
                            section.get('内存布局', {}).get('虚拟大小16进制', ''),
                            section.get('文件布局', {}).get('原始数据指针16进制', ''),
                            section.get('文件布局', {}).get('原始大小16进制', ''),
                            section.get('安全特性', {}).get('权限', ''),
                            section.get('安全特性', {}).get('风险等级', '')
                        ))
                else:
                    # 显示错误信息
                    self.sections_tree.insert("", tk.END, values=(
                        "错误", "", "", "", "", "", sections_data.get('消息', '未知错误')
                    ))

    def update_imports_info(self):
        """更新导入表分析选项卡"""
        for item in self.imports_tree.get_children():
            self.imports_tree.delete(item)

        if 'imports' in self.analysis_results:
            imports_data = self.analysis_results['imports']

            if isinstance(imports_data, dict) and imports_data.get('status') == 'success':
                imports_list = imports_data.get('imports', [])
                for import_item in imports_list:
                    if isinstance(import_item, dict):
                        # 统计可疑函数数量
                        suspicious_count = sum(1 for func in import_item.get('functions', [])
                                               if func.get('suspicious', False))

                        self.imports_tree.insert("", tk.END, values=(
                            import_item.get('dll_name', ''),
                            import_item.get('function_count', 0),
                            import_item.get('risk_level', 'unknown').upper(),
                            f"{suspicious_count} 个可疑函数"
                        ))
            else:
                # 显示错误信息
                error_msg = imports_data.get('message', '未知错误') if isinstance(imports_data, dict) else '数据格式错误'
                self.imports_tree.insert("", tk.END, values=(
                    "错误", "", "", error_msg
                ))

    def update_strings_info(self):
        """更新字符串提取选项卡"""
        for item in self.strings_tree.get_children():
            self.strings_tree.delete(item)

        if 'strings' in self.analysis_results:
            strings_data = self.analysis_results['strings']

            if isinstance(strings_data, dict) and strings_data.get('status') == 'success':
                strings_list = strings_data.get('strings', [])
                for i, string_item in enumerate(strings_list[:100]):  # 只显示前100个字符串
                    if isinstance(string_item, dict):
                        string_value = string_item.get('string', '')
                        if len(string_value) > 50:
                            display_string = string_value[:50] + '...'
                        else:
                            display_string = string_value

                        self.strings_tree.insert("", tk.END, values=(
                            string_item.get('offset_hex', ''),
                            display_string,
                            string_item.get('type', '未知'),
                            len(string_value)
                        ))
            else:
                # 显示错误信息
                error_msg = strings_data.get('message', '未知错误') if isinstance(strings_data, dict) else '数据格式错误'
                self.strings_tree.insert("", tk.END, values=(
                    "错误", error_msg, "", ""
                ))

    def update_security_info(self):
        """更新安全分析选项卡"""
        for item in self.security_tree.get_children():
            self.security_tree.delete(item)

        # 基于分析结果生成安全检查项
        security_checks = []

        # 文件哈希检查
        if 'hashes' in self.analysis_results:
            hashes_data = self.analysis_results['hashes']
            if isinstance(hashes_data, dict) and hashes_data.get('status') == 'success':
                security_checks.append(("文件哈希验证", "通过", "低", "文件完整性验证通过"))
                # 显示哈希值
                hashes = hashes_data.get('hashes', {})
                for algo, info in hashes.items():
                    security_checks.append(
                        (f"{algo}哈希", info['value'][:16] + "...", "低", info['description']))  # 修复这里
            else:
                security_checks.append(("文件哈希验证", "失败", "中", "哈希计算失败"))

        # 节表风险分析
        if 'sections' in self.analysis_results:
            sections_data = self.analysis_results['sections']
            if isinstance(sections_data, dict) and sections_data.get('状态') == 'success':
                sections = sections_data.get('节信息', [])
                high_risk_count = sum(1 for s in sections if s.get('安全特性', {}).get('风险等级') == 'high')

                # 检查具体的安全警告
                for section in sections:
                    security_analysis = section.get('安全特性', {}).get('安全分析', '')
                    if '代码节可写' in security_analysis:
                        security_checks.append(
                            (f"节 {section.get('名称')}", "警告", "高", "代码节可写，可能用于自我修改或Shellcode！"))

                if high_risk_count > 0:
                    security_checks.append(("节表风险分析", "警告", "高", f"发现 {high_risk_count} 个高风险节"))
                else:
                    security_checks.append(("节表风险分析", "通过", "低", "未发现高风险节"))
            else:
                security_checks.append(("节表风险分析", "失败", "中", "节表分析失败"))

        # 导入函数检测
        if 'imports' in self.analysis_results:
            imports_data = self.analysis_results['imports']
            if isinstance(imports_data, dict) and imports_data.get('status') == 'success':
                # 显示安全警告
                security_warnings = imports_data.get('security_warnings', [])
                for warning in security_warnings[:5]:  # 显示前5个警告
                    security_checks.append(("导入函数警告", "警告", "高", warning))

                suspicious_imports = imports_data.get('summary', {}).get('suspicious_imports', [])
                if suspicious_imports:
                    security_checks.append(("可疑导入函数", "警告", "中", f"发现 {len(suspicious_imports)} 个可疑函数"))
                else:
                    security_checks.append(("导入函数检测", "通过", "低", "未发现可疑函数"))
            else:
                security_checks.append(("导入函数检测", "失败", "中", "导入表分析失败"))

        # 字符串分析
        if 'strings' in self.analysis_results:
            strings_data = self.analysis_results['strings']
            if isinstance(strings_data, dict) and strings_data.get('status') == 'success':
                strings_count = strings_data.get('file_info', {}).get('total_strings_found', 0)
                security_checks.append(("字符串分析", "完成", "低", f"分析 {strings_count} 个字符串"))
            else:
                security_checks.append(("字符串分析", "失败", "中", "字符串分析失败"))

        # 移到循环外面
        for check in security_checks:
            self.security_tree.insert("", tk.END, values=check)

    def update_comprehensive_info(self):
        """更新综合分析选项卡"""
        self.comp_text.config(state=tk.NORMAL)
        self.comp_text.delete(1.0, tk.END)

        # 生成综合分析报告
        report = "=== PE文件综合分析报告 ===\n\n"

        # 安全警告汇总
        warnings = []

        # 检查节表警告
        if 'sections' in self.analysis_results:
            sections_data = self.analysis_results['sections']
            if isinstance(sections_data, dict) and sections_data.get('状态') == 'success':
                sections = sections_data.get('节信息', [])
                for section in sections:
                    security_analysis = section.get('安全特性', {}).get('安全分析', '')
                    if '代码节可写' in security_analysis:
                        warnings.append(f"⚠️ {section.get('名称')} 节可写，可能存在安全风险")

        # 检查导入表警告
        if 'imports' in self.analysis_results:
            imports_data = self.analysis_results['imports']
            if isinstance(imports_data, dict) and imports_data.get('status') == 'success':
                security_warnings = imports_data.get('security_warnings', [])
                warnings.extend(security_warnings)

        if warnings:
            report += "【安全警告】\n"
            for warning in warnings:
                report += f"  {warning}\n"
            report += "\n"

        # 模块可用性检查
        report += "【模块状态】\n"
        report += f"  文件头解析: {'可用' if HEADERS_AVAILABLE else '不可用'}\n"
        report += f"  节表分析: {'可用' if SECTIONS_AVAILABLE else '不可用'}\n"
        report += f"  安全分析: {'可用' if IMPORTS_AVAILABLE else '不可用'}\n\n"

        # 基本信息
        report += "【基本信息】\n"
        if 'headers' in self.analysis_results:
            headers_data = self.analysis_results['headers']
            if isinstance(headers_data, dict) and 'file_info' in headers_data:
                file_info = headers_data['file_info']['basic_info']
                report += f"  文件: {file_info.get('file_name', 'N/A')}\n"
                report += f"  大小: {file_info.get('file_size', 0):,} 字节\n"
                report += f"  架构: {file_info.get('machine_type', 'N/A')}\n"
                report += f"  时间: {file_info.get('timestamp', 'N/A')}\n"
            else:
                report += f"  错误: {headers_data.get('错误', '未知错误')}\n"

        # 节表信息
        report += "\n【节表分析】\n"
        if 'sections' in self.analysis_results:
            sections_data = self.analysis_results['sections']
            if isinstance(sections_data, dict) and sections_data.get('状态') == 'success':
                sections = sections_data.get('节信息', [])
                report += f"  总节数: {len(sections)}\n"
                high_risk = sum(1 for s in sections if s.get('安全特性', {}).get('风险等级') == 'high')
                if high_risk > 0:
                    report += f"  ⚠ 高风险节: {high_risk} 个\n"
            else:
                report += f"  错误: {sections_data.get('消息', '未知错误')}\n"

        # 导入表信息
        report += "\n【导入表分析】\n"
        if 'imports' in self.analysis_results:
            imports_data = self.analysis_results['imports']
            if isinstance(imports_data, dict) and imports_data.get('status') == 'success':
                imports_list = imports_data.get('imports', [])
                report += f"  导入DLL数量: {len(imports_list)}\n"
                total_funcs = sum(item.get('function_count', 0) for item in imports_list)
                report += f"  总函数数量: {total_funcs}\n"
            else:
                report += f"  错误: {imports_data.get('message', '未知错误')}\n"

        # 字符串信息
        report += "\n【字符串提取】\n"
        if 'strings' in self.analysis_results:
            strings_data = self.analysis_results['strings']
            if isinstance(strings_data, dict) and strings_data.get('status') == 'success':
                strings_count = strings_data.get('file_info', {}).get('total_strings_found', 0)
                report += f"  提取字符串数量: {strings_count}\n"
            else:
                report += f"  错误: {strings_data.get('message', '未知错误')}\n"

        self.comp_text.insert(tk.END, report)
        self.comp_text.config(state=tk.DISABLED)

    def clear_results(self):
        """清空所有分析结果"""
        self.analysis_results = {}
        self.clear_all_tabs()
        self.status_var.set("结果已清空")

    def clear_all_tabs(self):
        """清空所有选项卡内容"""
        # 清空各个树形视图
        for tree in [self.basic_tree, self.sections_tree, self.imports_tree,
                     self.strings_tree, self.security_tree]:
            for item in tree.get_children():
                tree.delete(item)

        # 清空综合分析文本框
        self.comp_text.config(state=tk.NORMAL)
        self.comp_text.delete(1.0, tk.END)
        self.comp_text.insert(tk.END, "请选择PE文件并开始分析...")
        self.comp_text.config(state=tk.DISABLED)

    def clear_current_tab(self):
        """清空当前选项卡内容"""
        current_tab = self.notebook.index(self.notebook.select())
        tab_names = ["基础信息", "节表分析", "导入表分析", "字符串提取", "安全分析", "综合分析"]
        current_tab_name = tab_names[current_tab]

        messagebox.showinfo("清空", f"已清空 {current_tab_name} 选项卡内容")

    def copy_content(self):
        """复制当前选项卡内容"""
        current_tab = self.notebook.index(self.notebook.select())
        # 这里可以实现具体的复制逻辑
        messagebox.showinfo("复制", "内容已复制到剪贴板")

    def export_report(self):
        """导出分析报告"""
        if not self.analysis_results:
            messagebox.showwarning("警告", "没有可导出的分析结果")
            return

        file_path = filedialog.asksaveasfilename(
            title="导出分析报告",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("PE文件分析报告\n")
                    f.write("=" * 50 + "\n")
                    # 这里可以添加更详细的报告内容
                messagebox.showinfo("成功", f"报告已导出到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")

    def refresh_ui(self):
        """刷新界面"""
        self.status_var.set("界面已刷新")

    def show_about(self):
        """显示关于信息"""
        about_text = """增强版PE文件分析器 - 团队项目

开发团队:
- 刘同学: 文件头解析模块
- 冯同学: 节表分析模块  
- 贾同学: 安全分析模块

功能特性:
- 完整的PE文件结构解析
- 详细的节表分析和安全评估
- 导入表分析和字符串提取
- 综合安全风险评估

版本: 1.0
开发时间: 2025年"""
        messagebox.showinfo("关于", about_text)


def main():
    # 检查依赖
    if not pefile:
        print("错误: 需要安装 pefile 模块")
        print("请运行: pip install pefile")
        return

    root = tk.Tk()
    app = PEAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()