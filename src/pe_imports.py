import hashlib
import pe_imports
import os


def simple_pe_analysis():
    """最简单的PE文件分析函数 - 用户交互版"""

    # 获取文件路径
    file_path = input("请输入PE文件路径: ").strip().strip('"')

    # 检查文件是否存在
    if not os.path.exists(file_path):
        print(f"错误：文件 '{file_path}' 不存在！")
        return

    try:
        # 加载PE文件
        pe = pe_imports.PE(file_path)

        # 读取文件数据
        with open(file_path, 'rb') as f:
            data = f.read()

        print("\n=== PE文件分析结果 ===")
        print(f"文件: {file_path}")
        print(f"大小: {len(data)} 字节")

        # 计算哈希
        print("\n文件哈希:")
        print(f"MD5:    {hashlib.md5(data).hexdigest()}")
        print(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
        print(f"SHA256: {hashlib.sha256(data).hexdigest()}")

        # 节信息
        print("\n节信息:")
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            section_data = section.get_data()
            print(f"  {name}: MD5={hashlib.md5(section_data).hexdigest()[:8]}..., 大小={len(section_data)}字节")

    except Exception as e:
        print(f"分析失败: {e}")


# 使用
if __name__ == "__main__":
    simple_pe_analysis()