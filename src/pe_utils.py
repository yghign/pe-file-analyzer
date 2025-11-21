import hashlib
import os


def calculate_hashes(file_path):
    """
    计算文件的哈希值
    参数: file_path - 文件路径
    返回: 哈希值列表
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        hashes_info = [{
            "MD5": hashlib.md5(data).hexdigest(),
            "SHA1": hashlib.sha1(data).hexdigest(),
            "SHA256": hashlib.sha256(data).hexdigest()
        }]

        return hashes_info

    except Exception as e:
        return [{"error": f"哈希计算失败: {str(e)}"}]


def extract_strings(file_path, min_length=4):
    """
    从文件中提取可打印字符串
    参数:
        file_path - 文件路径
        min_length - 最小字符串长度
    返回: 字符串信息列表
    """
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        strings_info = []
        current_string = ""

        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII范围
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings_info.append({
                        "offset": f"0x{data.find(current_string.encode()):08X}",
                        "string": current_string
                    })
                current_string = ""

        # 处理最后一个字符串
        if len(current_string) >= min_length:
            strings_info.append({
                "offset": f"0x{data.find(current_string.encode()):08X}",
                "string": current_string
            })

        return strings_info

    except Exception as e:
        return [{"error": f"字符串提取失败: {str(e)}"}]