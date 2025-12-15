import pefile
import os
import math
from typing import Dict, List, Any, Optional


def get_section_characteristics(characteristics: int) -> List[str]:
    """获取节特性标志的描述"""
    flags = {
        0x00000020: "代码节",
        0x00000040: "已初始化数据节",
        0x00000080: "未初始化数据节",
        0x00000200: "链接信息",
        0x00000800: "链接移除",
        0x00001000: "链接COMDAT",
        0x00004000: "GP相对寻址",
        0x00008000: "内存可清除",
        0x00010000: "16位内存",
        0x00020000: "内存锁定",
        0x00040000: "内存预加载",
        0x00100000: "1字节对齐",
        0x00200000: "2字节对齐",
        0x00300000: "4字节对齐",
        0x00400000: "8字节对齐",
        0x00500000: "16字节对齐",
        0x00600000: "32字节对齐",
        0x00700000: "64字节对齐",
        0x00800000: "128字节对齐",
        0x00900000: "256字节对齐",
        0x00A00000: "512字节对齐",
        0x00B00000: "1024字节对齐",
        0x00C00000: "2048字节对齐",
        0x00D00000: "4096字节对齐",
        0x00E00000: "8192字节对齐",
        0x01000000: "重定位溢出",
        0x02000000: "内存可丢弃",
        0x04000000: "内存不缓存",
        0x08000000: "内存不换页",
        0x10000000: "内存共享",
        0x20000000: "内存可执行",
        0x40000000: "内存可读",
        0x80000000: "内存可写"
    }

    desc = []
    for flag, name in flags.items():
        if characteristics & flag:
            desc.append(name)
    return desc


def get_section_description(section_name: str) -> str:
    """获取节的描述信息"""
    section_descriptions = {
        '.text': '代码节，包含程序的可执行代码',
        '.data': '数据节，包含初始化的全局和静态变量',
        '.rdata': '只读数据节，包含常量数据和字符串',
        '.bss': '未初始化数据节，包含未初始化的全局和静态变量',
        '.idata': '导入表节，包含导入函数信息',
        '.edata': '导出表节，包含导出函数信息',
        '.rsrc': '资源节，包含程序资源（图标、对话框等）',
        '.reloc': '重定位节，包含地址重定位信息',
        '.tls': '线程局部存储节',
        '.crt': 'C运行时初始化数据',
        '.debug': '调试信息节',
        '.pdata': '异常处理数据',
        '.xdata': '异常处理信息',
        '.sdata': '共享数据节',
        '.srdata': '共享只读数据节',
    }

    clean_name = section_name.lower().rstrip('\x00').strip('.')
    for key, desc in section_descriptions.items():
        if key in section_name.lower():
            return desc

    # 根据常见模式推断
    if 'code' in section_name.lower():
        return '代码节，可能包含程序的可执行代码'
    elif 'data' in section_name.lower():
        return '数据节，可能包含程序数据'
    elif 'import' in section_name.lower():
        return '导入表相关节'
    elif 'export' in section_name.lower():
        return '导出表相关节'
    elif 'resource' in section_name.lower() or 'rsrc' in section_name.lower():
        return '资源节，可能包含程序资源'

    return '未知节，需要进一步分析'


def analyze_section_purpose(section_name: str, characteristics: int) -> str:
    """分析节的用途"""
    # 基于节名判断
    name_lower = section_name.lower()

    if '.text' in name_lower or 'code' in name_lower:
        return "代码执行"
    elif '.data' in name_lower and '.rdata' not in name_lower:
        return "数据存储"
    elif '.rdata' in name_lower:
        return "只读数据"
    elif '.bss' in name_lower:
        return "未初始化数据"
    elif '.idata' in name_lower or '.edata' in name_lower:
        return "导入导出表"
    elif '.rsrc' in name_lower or 'resource' in name_lower:
        return "资源数据"
    elif '.reloc' in name_lower:
        return "重定位数据"
    elif '.tls' in name_lower:
        return "线程局部存储"
    elif '.debug' in name_lower:
        return "调试信息"
    elif '.pdata' in name_lower or '.xdata' in name_lower:
        return "异常处理"

    # 基于特性标志判断
    if characteristics & 0x20000000:  # 可执行
        return "可执行代码"
    elif characteristics & 0x40000000:  # 可读
        if characteristics & 0x80000000:  # 可写
            return "读写数据"
        else:
            return "只读数据"
    elif characteristics & 0x00000020:  # 代码节
        return "代码数据"
    elif characteristics & 0x00000040:  # 初始化数据
        return "初始化数据"
    elif characteristics & 0x00000080:  # 未初始化数据
        return "未初始化数据"

    return "未知用途"


def analyze_section_security(characteristics: int, section_name: str) -> str:
    """分析节的安全特性"""
    security_notes = []

    # 检查可执行且可写的节（高风险）
    if (characteristics & 0x20000000 and  # 可执行
            characteristics & 0x80000000):  # 可写
        security_notes.append("可执行且可写 - 高风险")

    # 检查可写代码节
    if (characteristics & 0x20000000 and  # 可执行
            characteristics & 0x80000000 and  # 可写
            (characteristics & 0x00000020 or '.text' in section_name.lower())):  # 代码节
        security_notes.append("可写代码节，可能用于自我修改或Shellcode！")

    # 检查可疑节名
    suspicious_names = ['.crypt', '.encrypted', '.packed', '.upx', '.vmp', '.themida']
    if any(name in section_name.lower() for name in suspicious_names):
        security_notes.append("可疑节名 - 可能被加壳")

    # 检查无权限节
    if not (characteristics & 0xE0000000):  # 没有读、写、执行权限
        security_notes.append("无内存权限 - 异常")

    if not security_notes:
        return "安全特性正常"

    return "; ".join(security_notes)


def assess_section_risk(characteristics: int, section_name: str) -> str:
    """评估节的风险等级"""
    # 可执行且可写的节 - 高风险
    if (characteristics & 0x20000000 and  # 可执行
            characteristics & 0x80000000):  # 可写
        return "high"

    # 可疑节名
    suspicious_names = ['.crypt', '.encrypted', '.packed', '.upx', '.vmp', '.themida', '.aspack']
    if any(name in section_name.lower() for name in suspicious_names):
        return "high"

    # 异常权限组合
    if (characteristics & 0x20000000 and  # 可执行
            not characteristics & 0x40000000):  # 不可读
        return "medium"

    # 数据节可执行
    if (characteristics & 0x20000000 and  # 可执行
            (characteristics & 0x00000040 or  # 初始化数据
             characteristics & 0x00000080)):  # 未初始化数据
        return "medium"

    return "low"


def calculate_alignment_info(section, optional_header) -> Dict[str, Any]:
    """计算节的对齐信息"""
    try:
        section_alignment = optional_header.SectionAlignment
        file_alignment = optional_header.FileAlignment

        virtual_size = section.Misc_VirtualSize
        raw_size = section.SizeOfRawData

        # 计算对齐后的尺寸
        aligned_virtual_size = (virtual_size + section_alignment - 1) // section_alignment * section_alignment
        aligned_raw_size = (raw_size + file_alignment - 1) // file_alignment * file_alignment

        return {
            "节对齐": section_alignment,
            "文件对齐": file_alignment,
            "对齐后虚拟大小": aligned_virtual_size,
            "对齐后原始大小": aligned_raw_size,
            "虚拟空间浪费": aligned_virtual_size - virtual_size,
            "原始空间浪费": aligned_raw_size - raw_size
        }
    except Exception:
        return {}


def calculate_section_entropy(section) -> Optional[float]:
    """计算节的熵值（用于检测加壳）"""
    try:
        data = section.get_data()
        if not data or len(data) == 0:
            return 0.0

        # 计算字节频率
        byte_count = [0] * 256
        for byte in data:
            byte_count[byte] += 1

        # 计算熵值
        entropy = 0.0
        data_len = len(data)

        for count in byte_count:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)

        return entropy
    except Exception:
        return None


def extract_section_permissions(characteristics: int) -> str:
    """提取节的权限信息"""
    permissions = []

    if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        permissions.append("可执行")
    if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
        permissions.append("可读")
    if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
        permissions.append("可写")

    return ", ".join(permissions) if permissions else "无权限"


def analyze_sections(pe) -> Dict[str, Any]:
    """
    分析PE文件的节表 - 纯数据处理函数
    返回结构化的数据，不包含任何显示逻辑

    Args:
        pe: pefile.PE对象

    Returns:
        包含节表分析结果的字典
    """
    sections_info = []

    if not hasattr(pe, 'sections') or not pe.sections:
        return {"状态": "error", "消息": "此PE文件没有节表或无法解析节表"}

    for section in pe.sections:
        try:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')

            # 获取节的特性和描述
            characteristics_desc = get_section_characteristics(section.Characteristics)
            purpose = analyze_section_purpose(section_name, section.Characteristics)
            description = get_section_description(section_name)

            section_info = {
                "名称": section_name,
                "用途": purpose,
                "描述": description,
                "内存布局": {
                    "虚拟地址": section.VirtualAddress,
                    "虚拟地址16进制": f"0x{section.VirtualAddress:08X}",
                    "虚拟大小": section.Misc_VirtualSize,
                    "虚拟大小16进制": f"0x{section.Misc_VirtualSize:08X}",
                    "虚拟结束地址": section.VirtualAddress + section.Misc_VirtualSize,
                    "虚拟结束地址16进制": f"0x{section.VirtualAddress + section.Misc_VirtualSize:08X}",
                    "虚拟地址说明": "该节在内存中的起始位置（相对地址）"
                },
                "文件布局": {
                    "原始大小": section.SizeOfRawData,
                    "原始大小16进制": f"0x{section.SizeOfRawData:08X}",
                    "原始数据指针": section.PointerToRawData,
                    "原始数据指针16进制": f"0x{section.PointerToRawData:08X}",
                    "原始结束位置": section.PointerToRawData + section.SizeOfRawData,
                    "原始结束位置16进制": f"0x{section.PointerToRawData + section.SizeOfRawData:08X}",
                    "原始数据说明": "该节数据在文件中的起始位置"
                },
                "安全特性": {
                    "特性标志": section.Characteristics,
                    "特性标志16进制": f"0x{section.Characteristics:08X}",
                    "特性描述": characteristics_desc,
                    "权限": extract_section_permissions(section.Characteristics),
                    "安全分析": analyze_section_security(section.Characteristics, section_name),
                    "风险等级": assess_section_risk(section.Characteristics, section_name),
                    "熵值": calculate_section_entropy(section)
                },
                "标志位": {
                    "可执行": bool(section.Characteristics & 0x20000000),
                    "可写": bool(section.Characteristics & 0x80000000),
                    "可读": bool(section.Characteristics & 0x40000000),
                    "代码节": bool(section.Characteristics & 0x00000020),
                    "已初始化数据": bool(section.Characteristics & 0x00000040),
                    "未初始化数据": bool(section.Characteristics & 0x00000080)
                }
            }

            # 添加对齐信息（如果可用）
            if hasattr(pe, 'OPTIONAL_HEADER'):
                alignment_info = calculate_alignment_info(section, pe.OPTIONAL_HEADER)
                if alignment_info:
                    section_info["对齐信息"] = alignment_info

            sections_info.append(section_info)

        except Exception as e:
            error_section = {
                "名称": "解析失败",
                "错误": str(e),
                "用途": "错误节",
                "描述": "解析此节时出现错误",
                "内存布局": {},
                "文件布局": {},
                "安全特性": {},
                "标志位": {}
            }
            sections_info.append(error_section)

    return {
        "状态": "success",
        "节信息": sections_info,
        "元数据": {
            "总节数": len(sections_info),
            "分析时间戳": os.times().elapsed if hasattr(os, 'times') else 0
        }
    }


def get_section_analysis_summary(sections_data: Dict[str, Any]) -> Dict[str, Any]:
    """生成节表分析的摘要信息"""
    if sections_data.get("状态") != "success":
        return {"错误": "无法生成摘要"}

    sections = sections_data.get("节信息", [])
    total_sections = len(sections)

    if total_sections == 0:
        return {"错误": "没有可分析的节"}

    # 统计各类节的数量 - 使用中文键名
    code_sections = sum(1 for s in sections if s.get("标志位", {}).get("代码节", False))
    data_sections = sum(1 for s in sections if s.get("标志位", {}).get("已初始化数据", False))
    uninit_data_sections = sum(1 for s in sections if s.get("标志位", {}).get("未初始化数据", False))

    # 安全风险统计 - 使用中文键名
    high_risk = sum(1 for s in sections if s.get("安全特性", {}).get("风险等级") == "high")
    medium_risk = sum(1 for s in sections if s.get("安全特性", {}).get("风险等级") == "medium")
    low_risk = sum(1 for s in sections if s.get("安全特性", {}).get("风险等级") == "low")

    # 权限统计 - 使用中文键名
    executable_sections = sum(1 for s in sections if s.get("标志位", {}).get("可执行", False))
    writable_sections = sum(1 for s in sections if s.get("标志位", {}).get("可写", False))
    readable_sections = sum(1 for s in sections if s.get("标志位", {}).get("可读", False))

    # 计算平均熵（用于检测加壳）
    entropies = [s.get("安全特性", {}).get("熵值", 0) for s in sections if
                 s.get("安全特性", {}).get("熵值") is not None]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0

    # 安全评估
    security_assessment = "安全状况良好"
    if high_risk > 0:
        security_assessment = "存在高风险节，建议详细分析"
    elif medium_risk > 0:
        security_assessment = "存在中等风险节，需要注意"
    elif avg_entropy > 7.0:
        security_assessment = "熵值较高，可能被加壳或压缩"

    return {
        "总节数": total_sections,
        "代码节数": code_sections,
        "数据节数": data_sections,
        "未初始化数据节数": uninit_data_sections,
        "可执行节数": executable_sections,
        "可写节数": writable_sections,
        "可读节数": readable_sections,
        "高风险节数": high_risk,
        "中风险节数": medium_risk,
        "低风险节数": low_risk,
        "平均熵值": round(avg_entropy, 3),
        "安全评估": security_assessment,
        "风险百分比": round((high_risk + medium_risk * 0.5) / total_sections * 100, 2) if total_sections > 0 else 0
    }


def validate_section_table(pe, sections_data: Dict[str, Any]) -> List[str]:
    """验证节表完整性"""
    issues = []

    if not hasattr(pe, 'sections') or not pe.sections:
        issues.append("❌ 文件没有节表或节表为空")
        return issues

    sections = pe.sections
    total_sections = len(sections)

    # 检查节重叠（内存）
    sections_sorted_by_va = sorted(sections, key=lambda s: s.VirtualAddress)
    for i in range(len(sections_sorted_by_va) - 1):
        current = sections_sorted_by_va[i]
        next_sec = sections_sorted_by_va[i + 1]
        current_end = current.VirtualAddress + current.Misc_VirtualSize
        next_start = next_sec.VirtualAddress

        if current_end > next_start:
            current_name = current.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            next_name = next_sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            issues.append(f"⚠️ 节 '{current_name}' 与 '{next_name}' 存在内存重叠")

    # 检查节重叠（文件）
    sections_sorted_by_raw = sorted([s for s in sections if s.SizeOfRawData > 0],
                                    key=lambda s: s.PointerToRawData)
    for i in range(len(sections_sorted_by_raw) - 1):
        current = sections_sorted_by_raw[i]
        next_sec = sections_sorted_by_raw[i + 1]
        current_end = current.PointerToRawData + current.SizeOfRawData
        next_start = next_sec.PointerToRawData

        if current_end > next_start:
            current_name = current.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            next_name = next_sec.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            issues.append(f"⚠️ 节 '{current_name}' 与 '{next_name}' 存在文件重叠")

    # 检查可疑的节数量
    if total_sections > 20:
        issues.append("⚠️ 节数量过多，可能是加壳或混淆的迹象")
    elif total_sections < 3:
        issues.append("⚠️ 节数量过少，可能不完整或被修改")

    # 检查节名长度异常和可疑节名
    suspicious_names = []
    for section in sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')

        if len(name) > 8:
            issues.append(f"⚠️ 节名 '{name}' 长度异常")

        # 检查可疑节名
        clean_name = name.lower()
        suspicious_patterns = ['.crypt', '.encrypted', '.hidden', '.secret',
                               '.unknown', '.malicious', '.inject']
        if any(pattern in clean_name for pattern in suspicious_patterns):
            suspicious_names.append(name)

    if suspicious_names:
        issues.append(f"🚩 发现可疑节名: {', '.join(suspicious_names)}")

    # 检查可执行且可写的节
    wx_sections = []
    for section in sections:
        if (section.Characteristics & 0x20000000 and  # 可执行
                section.Characteristics & 0x80000000):  # 可写
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            wx_sections.append(name)

    if wx_sections:
        issues.append(f"🔴 发现可执行且可写的节: {', '.join(wx_sections)}")

    return issues if issues else ["✅ 节表结构正常"]


def _test_module():
    """模块测试函数"""
    try:
        # 测试文件路径 - 请根据实际情况修改
        test_file = "C:\\Windows\\System32\\notepad.exe"
        if not os.path.exists(test_file):
            print(f"测试文件不存在: {test_file}")
            return None

        pe = pefile.PE(test_file)
        result = analyze_sections(pe)
        print("模块测试成功！")
        print(f"找到 {len(result['节信息'])} 个节")

        # 显示前3个节的信息 - 使用中文键名
        for i, section in enumerate(result['节信息'][:3]):
            print(f"\n--- 节 {i + 1}: {section['名称']} ---")
            print(f"用途: {section['用途']}")
            print(f"权限: {section['安全特性']['权限']}")
            print(f"风险等级: {section['安全特性']['风险等级']}")

        # 测试新功能
        summary = get_section_analysis_summary(result)
        print(f"\n摘要信息:")
        for key, value in summary.items():
            print(f"  {key}: {value}")

        validation = validate_section_table(pe, result)
        print(f"\n节表验证:")
        for issue in validation:
            print(f"  {issue}")

        return result
    except Exception as e:
        print(f"模块测试失败: {e}")
        return None


if __name__ == "__main__":
    _test_module()