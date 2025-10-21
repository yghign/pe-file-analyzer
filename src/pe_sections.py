import pefile
import os


def analyze_sections(pe):
    """
    分析PE文件的节表（Section Table）
    """
    sections_info = []

    if not hasattr(pe, 'sections'):
        return [{"Error": "此PE文件没有节表或无法解析节表"}]

    for section in pe.sections:
        try:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')

            section_info = {
                "基本信息": {
                    "名称": section_name,
                    "用途分析": analyze_section_purpose(section_name, section.Characteristics),
                    "描述": get_section_description(section_name)
                },
                "内存布局": {
                    "虚拟地址": {
                        "值": f"0x{section.VirtualAddress:08X}",
                        "解释": "该节在内存中的起始位置（相对地址）",
                        "详细说明": f"程序加载时，这个节会被映射到内存地址 ImageBase + 0x{section.VirtualAddress:08X} 处"
                    },
                    "虚拟大小": {
                        "值": f"0x{section.Misc_VirtualSize:08X}",
                        "解释": "该节在内存中实际需要的大小",
                        "详细说明": f"在内存中占用 0x{section.Misc_VirtualSize:08X} 字节 ({section.Misc_VirtualSize} 字节)，可能包含未初始化的数据区域"
                    }
                },
                "文件布局": {
                    "原始数据大小": {
                        "值": f"0x{section.SizeOfRawData:08X}",
                        "解释": "该节在磁盘文件中的实际数据大小",
                        "详细说明": f"在文件中占用 0x{section.SizeOfRawData:08X} 字节 ({section.SizeOfRawData} 字节)"
                    },
                    "原始数据指针": {
                        "值": f"0x{section.PointerToRawData:08X}",
                        "解释": "该节数据在文件中的起始位置",
                        "详细说明": f"从文件开头偏移 0x{section.PointerToRawData:08X} 字节处开始就是这个节的数据"
                    }
                },
                "安全属性": {
                    "特性值": f"0x{section.Characteristics:08X}",
                    "特性含义": get_section_characteristics(section.Characteristics),
                    "安全分析": analyze_section_security(section.Characteristics, section_name)
                }
            }

            # 计算内存对齐信息
            if section.SizeOfRawData > 0:
                alignment_info = calculate_alignment_info(section, pe.OPTIONAL_HEADER)
                section_info["技术细节"] = alignment_info

            sections_info.append(section_info)

        except Exception as e:
            error_section = {
                "基本信息": {
                    "名称": "解析失败",
                    "错误信息": str(e)
                }
            }
            sections_info.append(error_section)

    return sections_info


def get_section_description(section_name):
    """获取节的描述信息"""
    descriptions = {
        ".text": "代码节，包含程序的可执行指令。这是程序的'大脑'，CPU实际执行的代码都在这里。",
        ".data": "数据节，包含初始化的全局变量和静态变量。程序运行时需要修改的数据通常在这里。",
        ".rdata": "只读数据节，包含常量、字符串字面量和调试信息。这些数据在运行时不会被修改。",
        ".reloc": "重定位节，包含地址修正信息。当程序无法在首选内存地址加载时，系统用这些信息调整地址。",
        ".rsrc": "资源节，包含程序的资源数据，如图标、位图、对话框模板、字符串表等。",
        ".idata": "导入表节，包含程序依赖的外部DLL函数信息。记录着程序调用了哪些外部函数。",
        ".edata": "导出表节，包含这个DLL导出的函数信息。其他程序可以通过这些信息调用这个DLL的函数。",
        ".tls": "线程局部存储节，用于线程特定的数据存储。每个线程都有这个数据的独立副本。",
        ".pdata": "异常处理数据节，包含结构化异常处理信息，用于调试和异常处理。",
        ".crt": "C运行时数据节，包含C运行时库的初始化数据。",
        ".bss": "未初始化数据节，包含未初始化的全局变量。在文件不占空间，但运行时需要内存。"
    }

    # 尝试精确匹配
    if section_name in descriptions:
        return descriptions[section_name]

    # 尝试前缀匹配
    for key, desc in descriptions.items():
        if section_name.startswith(key):
            return desc

    return "这是一个自定义节或特殊用途节。"


def analyze_section_purpose(section_name, characteristics):
    """分析节的用途"""
    purpose = ""

    # 根据特性判断主要用途
    if characteristics & 0x00000020:  # IMAGE_SCN_CNT_CODE
        purpose = "代码节"
    elif characteristics & 0x00000040:  # IMAGE_SCN_CNT_INITIALIZED_DATA
        purpose = "数据节"
    elif characteristics & 0x00000080:  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
        purpose = "未初始化数据节"
    else:
        purpose = "特殊数据节"

    # 根据节名进一步细化
    if section_name == ".text":
        purpose += " - 主程序代码"
    elif section_name == ".data":
        purpose += " - 可读写数据"
    elif section_name == ".rdata":
        purpose += " - 只读数据"
    elif section_name == ".reloc":
        purpose += " - 地址重定位信息"
    elif section_name == ".rsrc":
        purpose += " - 程序资源"

    return purpose


def analyze_section_security(characteristics, section_name):
    """分析节的安全特征"""
    security_notes = []

    # 检查可疑的组合
    executable = characteristics & 0x20000000  # 可执行
    writable = characteristics & 0x80000000  # 可写
    readable = characteristics & 0x40000000  # 可读

    if executable and writable:
        security_notes.append("⚠️ 警告：节同时具有可执行和可写权限，这可能存在安全风险（可能包含shellcode）")

    if not executable and writable and section_name == ".text":
        security_notes.append("⚠️ 异常：代码节不可执行但可写，这可能被恶意利用")

    if executable and not readable:
        security_notes.append("⚠️ 异常：节可执行但不可读，这不太常见")

    # 检查常见的恶意软件特征
    if section_name in [".packed", ".themida", ".vmp", ".upx"]:
        security_notes.append("🔍 注意：这个节名表明程序可能被加壳或保护")

    if characteristics & 0x02000000:  # IMAGE_SCN_MEM_DISCARDABLE
        security_notes.append("✅ 这个节在加载后可以被丢弃，有助于节省内存")

    if not security_notes:
        security_notes.append("✅ 权限设置正常")

    return security_notes


def calculate_alignment_info(section, optional_header):
    """计算对齐相关的技术信息"""
    virtual_size = section.Misc_VirtualSize
    raw_size = section.SizeOfRawData
    file_alignment = optional_header.FileAlignment
    section_alignment = optional_header.SectionAlignment

    alignment_info = {
        "文件对齐": {
            "值": f"0x{file_alignment:08X}",
            "解释": "节在文件中的对齐粒度",
            "说明": f"每个节在文件中的大小必须是 0x{file_alignment:08X} 的倍数"
        },
        "内存对齐": {
            "值": f"0x{section_alignment:08X}",
            "解释": "节在内存中的对齐粒度",
            "说明": f"每个节在内存中的起始地址必须是 0x{section_alignment:08X} 的倍数"
        },
        "大小差异分析": {
            "虚拟大小": f"0x{virtual_size:08X}",
            "文件大小": f"0x{raw_size:08X}",
            "差异": f"0x{abs(raw_size - virtual_size):08X}",
            "解释": "文件大小和内存大小的差异通常是由于对齐要求或未初始化数据造成的"
        }
    }

    return alignment_info


def get_section_characteristics(characteristics):
    """解析节特性值"""
    flags = {
        0x00000020: '包含代码',
        0x00000040: '包含初始化数据',
        0x00000080: '包含未初始化数据',
        0x00000001: '共享节',
        0x00000002: '可执行',
        0x00000004: '可读',
        0x00000008: '可写',
        0x00000010: '可丢弃',
        0x10000000: '共享数据',
        0x20000000: '扩展重定位',
        0x40000000: '可丢弃',
        0x80000000: '不缓存'
    }

    meanings = []
    for flag, meaning in flags.items():
        if characteristics & flag:
            meanings.append(meaning)

    return ", ".join(meanings) if meanings else "无特殊特性"


def analyze_pe_file(file_path):
    """
    分析指定的PE文件
    参数: file_path - PE文件的路径
    返回值: 分析结果字典
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return {"status": "error", "error": f"文件不存在: {file_path}"}

        # 检查文件大小
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {"status": "error", "error": "文件为空"}

        # 加载PE文件
        pe = pefile.PE(file_path)

        # 获取基础文件信息
        basic_info = {
            "文件名": os.path.basename(file_path),
            "文件大小": f"{file_size} 字节 ({file_size / 1024:.2f} KB)",
            "文件路径": file_path,
            "PE类型": "64位程序" if pe.PE_TYPE == 0x20b else "32位程序",
            "编译时间": format_timestamp(pe.FILE_HEADER.TimeDateStamp),
            "入口点": f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}",
            "映像基址": f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}",
            "节数量": len(pe.sections),
            "子系统": get_subsystem_name(pe.OPTIONAL_HEADER.Subsystem)
        }

        # 分析节表
        sections_info = analyze_sections(pe)

        # 总体安全评估
        overall_security = assess_overall_security(sections_info)

        # 返回完整结果
        return {
            "status": "success",
            "basic_info": basic_info,
            "sections_info": sections_info,
            "overall_security": overall_security,
            "summary": generate_summary(basic_info, sections_info)
        }

    except pefile.PEFormatError:
        return {"status": "error", "error": "这不是一个有效的PE文件"}
    except Exception as e:
        return {"status": "error", "error": f"分析过程中出错: {str(e)}"}


def format_timestamp(timestamp):
    """格式化时间戳"""
    from datetime import datetime
    try:
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return "无效时间戳"


def get_subsystem_name(subsystem):
    """获取子系统名称"""
    subsystems = {
        1: "原生系统 (设备驱动程序)",
        2: "Windows GUI (图形界面程序)",
        3: "Windows CUI (控制台程序)",
        5: "OS/2 CUI",
        7: "POSIX CUI",
        9: "Windows CE GUI",
        10: "EFI应用程序",
        11: "EFI引导服务驱动",
        12: "EFI运行时驱动",
        13: "EFI ROM",
        14: "XBOX"
    }
    return subsystems.get(subsystem, f"未知子系统 ({subsystem})")


def assess_overall_security(sections_info):
    """总体安全评估"""
    security_issues = []
    warnings = []

    for section in sections_info:
        security_analysis = section.get("安全属性", {}).get("安全分析", [])
        for note in security_analysis:
            if "警告" in note or "异常" in note:
                security_issues.append(f"{section['基本信息']['名称']}: {note}")
            elif "注意" in note:
                warnings.append(f"{section['基本信息']['名称']}: {note}")

    return {
        "安全问题": security_issues,
        "注意事项": warnings,
        "总体评级": "高风险" if security_issues else "中等风险" if warnings else "低风险"
    }


def generate_summary(basic_info, sections_info):
    """生成分析摘要"""
    total_sections = len(sections_info)
    code_sections = sum(1 for s in sections_info if "代码" in s["基本信息"]["用途分析"])
    data_sections = sum(1 for s in sections_info if "数据" in s["基本信息"]["用途分析"])

    # 查找主要的代码节和数据节
    main_code_section = next((s for s in sections_info if s["基本信息"]["名称"] == ".text"), None)
    main_data_section = next((s for s in sections_info if s["基本信息"]["名称"] == ".data"), None)

    summary = {
        "节统计": f"共 {total_sections} 个节 ({code_sections} 个代码节, {data_sections} 个数据节)",
        "程序类型": basic_info["PE类型"],
        "主要代码节": main_code_section["基本信息"]["名称"] if main_code_section else "未找到",
        "主要数据节": main_data_section["基本信息"]["名称"] if main_data_section else "未找到",
        "分析结论": "这是一个结构正常的PE文件" if total_sections >= 3 else "节数量较少，可能经过特殊处理"
    }

    return summary


def print_analysis_result(result):
    """以友好的格式打印分析结果"""
    if result.get("status") != "success":
        print(f"❌ 分析失败: {result.get('error', '未知错误')}")
        return

    # 打印基本信息
    basic_info = result["basic_info"]
    print("\n" + "=" * 80)
    print("📊 PE文件分析报告")
    print("=" * 80)
    print("\n📁 文件基本信息:")
    print("-" * 40)
    for key, value in basic_info.items():
        print(f"  {key}: {value}")

    # 打印摘要
    summary = result["summary"]
    print(f"\n📋 分析摘要:")
    print("-" * 40)
    for key, value in summary.items():
        print(f"  {key}: {value}")

    # 打印总体安全评估
    security = result["overall_security"]
    print(f"\n🔒 总体安全评估: {security['总体评级']}")
    print("-" * 40)
    if security["安全问题"]:
        print("  🚨 发现的安全问题:")
        for issue in security["安全问题"]:
            print(f"    • {issue}")
    if security["注意事项"]:
        print("  ⚠️  注意事项:")
        for warning in security["注意事项"]:
            print(f"    • {warning}")
    if not security["安全问题"] and not security["注意事项"]:
        print("  ✅ 未发现明显安全问题")

    # 打印节表信息
    sections_info = result["sections_info"]
    print(f"\n🔍 详细节表分析 (共 {len(sections_info)} 个节):")
    print("=" * 80)

    for i, section in enumerate(sections_info):
        print(f"\n📖 节 #{i + 1}:")
        print("-" * 60)

        # 基本信息
        basic = section.get("基本信息", {})
        print(f"  🏷️  名称: {basic.get('名称', 'N/A')}")
        print(f"  🎯 用途: {basic.get('用途分析', 'N/A')}")
        print(f"  📝 描述: {basic.get('描述', 'N/A')}")

        # 内存布局
        print(f"\n  💾 内存布局:")
        memory = section.get("内存布局", {})
        for key, info in memory.items():
            print(f"     {key}: {info.get('值', 'N/A')}")
            print(f"        💡 {info.get('解释', '')}")

        # 文件布局
        print(f"\n  📄 文件布局:")
        file_layout = section.get("文件布局", {})
        for key, info in file_layout.items():
            print(f"     {key}: {info.get('值', 'N/A')}")
            print(f"        💡 {info.get('解释', '')}")

        # 安全属性
        security_attr = section.get("安全属性", {})
        print(f"\n  🔒 安全属性:")
        print(f"     权限: {security_attr.get('特性含义', 'N/A')}")
        security_notes = security_attr.get('安全分析', [])
        for note in security_notes:
            print(f"     {note}")

        # 技术细节
        tech = section.get("技术细节", {})
        if tech:
            print(f"\n  ⚙️  技术细节:")
            for category, details in tech.items():
                if isinstance(details, dict):
                    print(f"     {category}: {details.get('值', 'N/A')}")
                    print(f"        💡 {details.get('解释', '')}")
                else:
                    print(f"     {category}: {details}")


def main():
    """主函数"""
    print("🔍 PE文件节表分析器")
    print("=" * 50)
    print("本工具可以分析Windows可执行文件(.exe/.dll)的内部结构")
    print("提供详细的内存布局、文件结构和安全分析信息\n")

    while True:
        print("\n请选择操作:")
        print("1. 分析指定文件")
        print("2. 分析默认测试文件")
        print("3. 退出程序")

        choice = input("\n请输入选择 (1/2/3): ").strip()

        if choice == "1":
            # 用户输入文件路径
            file_path = input("请输入PE文件路径: ").strip()

            # 去除路径两端的引号
            file_path = file_path.strip('"\'')

            if not file_path:
                print("❌ 文件路径不能为空！")
                continue

            print(f"\n🔄 正在分析文件: {file_path}")
            result = analyze_pe_file(file_path)
            print_analysis_result(result)

        elif choice == "2":
            # 尝试找到默认测试文件
            test_files = [
                "notepad.exe",
                "test.exe",
                "C:\\Windows\\System32\\notepad.exe",
                "C:\\Windows\\System32\\calc.exe",
                "C:\\Windows\\System32\\winver.exe"
            ]

            test_file = None
            for file in test_files:
                if os.path.exists(file):
                    test_file = file
                    break

            if test_file:
                print(f"\n🔄 使用测试文件: {test_file}")
                result = analyze_pe_file(test_file)
                print_analysis_result(result)
            else:
                print("❌ 未找到可用的测试文件")
                print("💡 请确保系统目录中存在notepad.exe或calc.exe")

        elif choice == "3":
            print("\n👋 感谢使用PE文件分析器，再见！")
            break

        else:
            print("❌ 无效选择，请重新输入！")


if __name__ == "__main__":
    main()