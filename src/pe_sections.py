import pefile


def analyze_sections(pe):
    """
    分析PE文件的节表（Section Table）
    参数: pe - 一个由 pefile.PE() 创建的对象
    返回值: 一个列表，包含所有节的信息，每个节是一个字典
    """
    sections_info = []  # 创建一个空列表来存储所有节的信息

    # 检查PE对象是否有节表
    if not hasattr(pe, 'sections'):
        return [{"Error": "此PE文件没有节表或无法解析节表"}]

    # 遍历PE文件中的所有节
    for section in pe.sections:
        try:
            # 提取节的信息并转换为字典
            section_info = {
                "名称": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),  # 节名称，去除空字符
                "虚拟地址": f"0x{section.VirtualAddress:08X}",  # 内存中的虚拟地址(RVA)
                "虚拟大小": f"0x{section.Misc_VirtualSize:08X}",  # 节在内存中的大小
                "原始数据大小": f"0x{section.SizeOfRawData:08X}",  # 节在文件中的大小
                "原始数据指针": f"0x{section.PointerToRawData:08X}",  # 节在文件中的偏移量
                "特性值": f"0x{section.Characteristics:08X}",  # 节的属性标志
                "特性含义": get_section_characteristics(section.Characteristics)  # 解析特性值的含义
            }
            sections_info.append(section_info)  # 将节信息添加到列表中
        except Exception as e:
            # 如果处理某个节时出错，记录错误信息但继续处理其他节
            error_section = {
                "名称": "解析失败",
                "错误信息": str(e)
            }
            sections_info.append(error_section)

    return sections_info


def get_section_characteristics(characteristics):
    """
    解析节特性值，返回可读的权限描述
    参数: characteristics - 节的特性值
    返回值: 包含权限描述的字符串
    """
    # 定义PE文件节特性标志
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

    # 解析特性值
    meanings = []
    for flag, meaning in flags.items():
        if characteristics & flag:
            meanings.append(meaning)

    return ", ".join(meanings) if meanings else "无特殊特性"


# 测试代码
if __name__ == "__main__":
    # 使用示例 - 这部分代码不会在模块被导入时执行
    import sys
    import os

    # 获取当前脚本所在目录的路径
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # 尝试找到一个测试文件
    test_files = [
        os.path.join(current_dir, "notepad.exe"),
        os.path.join(current_dir, "test.exe"),
        "C:\\Windows\\System32\\notepad.exe",  # Windows系统自带的记事本
        "C:\\Windows\\System32\\calc.exe"  # Windows系统自带的计算器
    ]

    test_file = None
    for file in test_files:
        if os.path.exists(file):
            test_file = file
            break

    if test_file:
        print(f"使用测试文件: {test_file}")
        try:
            # 加载PE文件
            pe = pefile.PE(test_file)

            # 调用我们的函数分析节表
            result = analyze_sections(pe)

            # 打印结果
            print(f"\n找到 {len(result)} 个节:")
            print("=" * 80)
            for i, section in enumerate(result):
                print(f"节 #{i + 1}:")
                for key, value in section.items():
                    print(f"  {key}: {value}")
                print("-" * 40)

        except Exception as e:
            print(f"处理文件时出错: {e}")
    else:
        print("未找到可用的测试文件。请将PE文件放在脚本同目录下，或修改测试代码中的路径。")
        print("您也可以手动指定一个PE文件路径:")
        print("1. 将PE文件复制到项目目录中")
        print("2. 修改测试代码中的 test_file 变量")