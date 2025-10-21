def simple_string_extract():

    file_path = input("请输入文件路径: ").strip()

    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        print(f"\n文件: {file_path}")
        print(f"大小: {len(data)} 字节")
        print("-" * 30)

        # 提取可打印字符串（长度>=4）
        current = ""
        strings = []

        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII范围
                current += chr(byte)
            else:
                if len(current) >= 4:
                    strings.append(current)
                current = ""

        # 显示找到的字符串
        print(f"找到 {len(strings)} 个字符串:\n")
        for i, s in enumerate(strings[:20], 1):  # 只显示前20个
            print(f"{i}. {s}")

        if len(strings) > 20:
            print(f"... 还有 {len(strings) - 20} 个字符串")

    except FileNotFoundError:
        print("文件不存在！")
    except Exception as e:
        print(f"错误: {e}")


