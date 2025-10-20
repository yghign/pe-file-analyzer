import pefile
import hashlib

def calculate_pe_file_hash(pe_file_path, hash_algorithm="sha256"):
    """
    计算Windows PE文件的有效数据哈希值（仅计算节区实际代码/数据）
    :param pe_file_path: PE文件路径（如.exe、.dll）
    :param hash_algorithm: 哈希算法，支持"md5"、"sha1"、"sha256"（默认sha256）
    :return: 十六进制格式的哈希值字符串，失败返回None
    """
    # 1. 初始化哈希对象
    try:
        hash_obj = hashlib.new(hash_algorithm)
    except ValueError:
        print(f"不支持的哈希算法：{hash_algorithm}")
        return None

    # 2. 解析PE文件结构
    try:
        pe = pefile.PE(pe_file_path, fast_load=True)  # fast_load=True加速，仅加载核心结构
        pe.parse_data_directories()  # 解析节表等关键数据目录
    except pefile.PEFormatError as e:
        print(f"PE文件格式错误：{e}")
        return None
    except FileNotFoundError:
        print(f"文件未找到：{pe_file_path}")
        return None

    # 3. 遍历所有节区，读取并更新有效数据到哈希对象
    try:
        with open(pe_file_path, "rb") as f:
            for section in pe.sections:
                # 关键：仅处理节区中包含实际数据的部分（排除对齐填充、空节）
                # 节区在文件中的偏移：section.PointerToRawData
                # 节区实际数据大小：section.SizeOfRawData（非虚拟大小）
                if section.SizeOfRawData == 0 or section.PointerToRawData == 0:
                    continue  # 跳过无实际数据的节区

                # 移动文件指针到当前节区的起始位置
                f.seek(section.PointerToRawData, 0)
                # 读取当前节区的有效数据
                section_data = f.read(section.SizeOfRawData)
                # 将节区数据更新到哈希对象
                hash_obj.update(section_data)
    except Exception as e:
        print(f"读取文件数据失败：{e}")
        return None
    finally:
        pe.close()  # 关闭PE解析对象，释放资源

    # 4. 返回十六进制格式的哈希值（全大写，符合常见工具输出习惯）
    return hash_obj.hexdigest().upper()