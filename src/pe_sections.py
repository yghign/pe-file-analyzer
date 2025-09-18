import pefile

# 这是你要实现的函数
def analyze_sections(pe):
    """
    分析PE文件的节表
    参数: pe - 一个由pefile.PE()创建的对象
    返回值: 一个包含节表信息的列表，每个节的信息是一个字典
    """
    # 1. 创建一个空列表，准备存放结果
    result = []
    
    # 2. 在这里写你的分析代码... (这是你需要努力完成的部分)
    #    例如：遍历 pe.sections，提取信息，然后组装成字典，append到result里。
    
    # 3. 最后返回这个结果列表
    return result

# 这是你的“私人测试区”，别人不会调用这里
if __name__ == '__main__':
    # 下面是你自己测试用的代码，用于验证你的函数是否正确
    file_path = "notepad.exe" # 自己找一个测试文件
    pe = pefile.PE(file_path)
    
    # 调用你自己写的函数
    sections_data = analyze_sections(pe)
    
    # 打印出来看看结果
    for section in sections_data:
        print(section)
