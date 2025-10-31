import struct
import os
from datetime import datetime
from typing import Dict, List, Any


class PEParser:
    """PE文件解析器 - 文件头解析模块"""

    def __init__(self, file_path: str):
        """
        初始化PE解析器

        Args:
            file_path: PE文件路径
        """
        self.file_path = file_path
        self.file_data = None
        self.dos_header = {}
        self.file_header = {}
        self.optional_header = {}
        self.sections = []
        self.is_pe_file = False
        self.is_64_bit = False

    def load_file(self) -> bool:
        """
        加载文件数据

        Returns:
            bool: 是否成功加载
        """
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            return True
        except Exception as e:
            print(f"文件加载失败: {e}")
            return False

    def parse_dos_header(self) -> bool:
        """
        解析DOS头 (IMAGE_DOS_HEADER)

        Returns:
            bool: 解析是否成功
        """
        try:
            if len(self.file_data) < 64:
                return False

            # 解析DOS头关键字段
            e_magic = self.file_data[0:2]  # MZ签名
            e_lfanew = struct.unpack_from('<L', self.file_data, 0x3C)[0]  # NT头偏移

            self.dos_header = {
                'e_magic': e_magic,
                'e_lfanew': e_lfanew
            }

            # 检查MZ签名
            if e_magic != b'MZ':
                return False

            return True
        except Exception as e:
            print(f"DOS头解析失败: {e}")
            return False

    def parse_nt_headers(self) -> bool:
        """
        解析NT头 (IMAGE_NT_HEADERS)
        包括PE签名、文件头(COFF头)、可选头

        Returns:
            bool: 解析是否成功
        """
        try:
            e_lfanew = self.dos_header['e_lfanew']

            # 检查PE签名
            if e_lfanew + 4 > len(self.file_data):
                return False

            signature = struct.unpack_from('<L', self.file_data, e_lfanew)[0]
            if signature != 0x4550:  # 'PE\0\0'
                return False

            # 文件头位置 (IMAGE_FILE_HEADER)
            file_header_offset = e_lfanew + 4

            if file_header_offset + 20 > len(self.file_data):
                return False

            # 解析COFF文件头
            machine = struct.unpack_from('<H', self.file_data, file_header_offset)[0]
            number_of_sections = struct.unpack_from('<H', self.file_data, file_header_offset + 2)[0]
            time_date_stamp = struct.unpack_from('<I', self.file_data, file_header_offset + 4)[0]
            pointer_to_symbol_table = struct.unpack_from('<I', self.file_data, file_header_offset + 8)[0]
            number_of_symbols = struct.unpack_from('<I', self.file_data, file_header_offset + 12)[0]
            size_of_optional_header = struct.unpack_from('<H', self.file_data, file_header_offset + 16)[0]
            characteristics = struct.unpack_from('<H', self.file_data, file_header_offset + 18)[0]

            self.file_header = {
                'machine': machine,
                'number_of_sections': number_of_sections,
                'time_date_stamp': time_date_stamp,
                'pointer_to_symbol_table': pointer_to_symbol_table,
                'number_of_symbols': number_of_symbols,
                'size_of_optional_header': size_of_optional_header,
                'characteristics': characteristics
            }

            # 解析可选头 (IMAGE_OPTIONAL_HEADER)
            optional_header_offset = file_header_offset + 20
            return self.parse_optional_header(optional_header_offset, size_of_optional_header)

        except Exception as e:
            print(f"NT头解析失败: {e}")
            return False

    def parse_optional_header(self, offset: int, size: int) -> bool:
        """
        解析可选头

        Args:
            offset: 可选头起始偏移
            size: 可选头大小

        Returns:
            bool: 解析是否成功
        """
        try:
            if offset + 2 > len(self.file_data):
                return False

            # 读取Magic字段判断架构
            magic = struct.unpack_from('<H', self.file_data, offset)[0]
            self.is_64_bit = (magic == 0x20b)  # PE32+为0x20b, PE32为0x10b

            # 初始化可选头字典
            self.optional_header = {
                'magic': magic,
                'address_of_entry_point': 0,
                'image_base': 0,
                'subsystem': 2,  # 默认Windows GUI
                'size_of_image': 0,
                'size_of_headers': 0
            }

            # 解析基本字段
            if offset + 24 <= len(self.file_data):
                try:
                    # 读取关键字段
                    major_linker_version = self.file_data[offset + 2]
                    minor_linker_version = self.file_data[offset + 3]
                    size_of_code = struct.unpack_from('<I', self.file_data, offset + 4)[0]
                    size_of_initialized_data = struct.unpack_from('<I', self.file_data, offset + 8)[0]
                    size_of_uninitialized_data = struct.unpack_from('<I', self.file_data, offset + 12)[0]
                    address_of_entry_point = struct.unpack_from('<I', self.file_data, offset + 16)[0]
                    base_of_code = struct.unpack_from('<I', self.file_data, offset + 20)[0]

                    self.optional_header.update({
                        'major_linker_version': major_linker_version,
                        'minor_linker_version': minor_linker_version,
                        'size_of_code': size_of_code,
                        'size_of_initialized_data': size_of_initialized_data,
                        'size_of_uninitialized_data': size_of_uninitialized_data,
                        'address_of_entry_point': address_of_entry_point,
                        'base_of_code': base_of_code
                    })

                    # 解析映像基址
                    if self.is_64_bit and offset + 32 <= len(self.file_data):
                        image_base = struct.unpack_from('<Q', self.file_data, offset + 24)[0]
                        self.optional_header['image_base'] = image_base
                    elif not self.is_64_bit and offset + 28 <= len(self.file_data):
                        image_base = struct.unpack_from('<I', self.file_data, offset + 24)[0]
                        self.optional_header['image_base'] = image_base

                    # 解析子系统信息
                    if self.is_64_bit and offset + 88 <= len(self.file_data):
                        subsystem = struct.unpack_from('<H', self.file_data, offset + 68)[0]
                        self.optional_header['subsystem'] = subsystem
                    elif not self.is_64_bit and offset + 68 <= len(self.file_data):
                        subsystem = struct.unpack_from('<H', self.file_data, offset + 68)[0]
                        self.optional_header['subsystem'] = subsystem

                    # 解析映像大小信息
                    if self.is_64_bit and offset + 56 <= len(self.file_data):
                        size_of_image = struct.unpack_from('<I', self.file_data, offset + 56)[0]
                        size_of_headers = struct.unpack_from('<I', self.file_data, offset + 60)[0]
                        self.optional_header.update({
                            'size_of_image': size_of_image,
                            'size_of_headers': size_of_headers
                        })
                    elif not self.is_64_bit and offset + 56 <= len(self.file_data):
                        size_of_image = struct.unpack_from('<I', self.file_data, offset + 56)[0]
                        size_of_headers = struct.unpack_from('<I', self.file_data, offset + 60)[0]
                        self.optional_header.update({
                            'size_of_image': size_of_image,
                            'size_of_headers': size_of_headers
                        })

                except Exception as e:
                    print(f"可选头部分字段解析失败: {e}")

            return True

        except Exception as e:
            print(f"可选头解析失败: {e}")
            return False

    def parse_sections(self) -> bool:
        """
        解析节表 (IMAGE_SECTION_HEADER)

        Returns:
            bool: 解析是否成功
        """
        try:
            number_of_sections = self.file_header['number_of_sections']
            optional_header_size = self.file_header['size_of_optional_header']

            # 计算节表起始位置
            sections_offset = self.dos_header['e_lfanew'] + 4 + 20 + optional_header_size

            self.sections = []

            for i in range(number_of_sections):
                section_offset = sections_offset + i * 40  # 每个节表项40字节

                if section_offset + 40 > len(self.file_data):
                    break

                # 解析节表字段
                name = self.file_data[section_offset:section_offset + 8]
                virtual_size = struct.unpack_from('<I', self.file_data, section_offset + 8)[0]
                virtual_address = struct.unpack_from('<I', self.file_data, section_offset + 12)[0]
                size_of_raw_data = struct.unpack_from('<I', self.file_data, section_offset + 16)[0]
                pointer_to_raw_data = struct.unpack_from('<I', self.file_data, section_offset + 20)[0]
                characteristics = struct.unpack_from('<I', self.file_data, section_offset + 36)[0]

                # 清理节名中的空字符
                section_name = name.split(b'\x00')[0].decode('ascii', errors='ignore')

                section_info = {
                    'name': section_name,
                    'virtual_size': virtual_size,
                    'virtual_address': virtual_address,
                    'size_of_raw_data': size_of_raw_data,
                    'pointer_to_raw_data': pointer_to_raw_data,
                    'characteristics': characteristics
                }

                self.sections.append(section_info)

            return True

        except Exception as e:
            print(f"节表解析失败: {e}")
            return False

    def parse(self) -> bool:
        """
        执行完整的PE文件解析

        Returns:
            bool: 解析是否成功
        """
        if not self.load_file():
            return False

        if not self.parse_dos_header():
            return False

        if not self.parse_nt_headers():
            return False

        if not self.parse_sections():
            return False

        self.is_pe_file = True
        return True

    def get_machine_type(self) -> str:
        """
        获取机器类型

        Returns:
            str: 机器类型描述
        """
        machine_types = {
            0x14c: 'I386 (32-bit x86)',
            0x8664: 'x64 (64-bit x86)',
            0x1c0: 'ARM (little endian)',
            0xaa64: 'ARM64',
            0x1c4: 'ARMNT',
            0x200: 'IA64 (Itanium)',
        }

        machine = self.file_header.get('machine', 0)
        return machine_types.get(machine, f'UNKNOWN (0x{machine:04x})')

    def get_subsystem_type(self) -> str:
        """
        获取子系统类型

        Returns:
            str: 子系统类型描述
        """
        subsystems = {
            1: 'NATIVE',
            2: 'WINDOWS_GUI',
            3: 'WINDOWS_CUI',
            5: 'OS2_CUI',
            7: 'POSIX_CUI',
        }

        subsystem = self.optional_header.get('subsystem', 2)
        return subsystems.get(subsystem, f'UNKNOWN ({subsystem})')

    def get_timestamp(self) -> str:
        """
        获取时间戳

        Returns:
            str: 格式化的时间字符串
        """
        timestamp = self.file_header.get('time_date_stamp', 0)
        if timestamp == 0:
            return "Not available"

        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return f"Invalid timestamp: {timestamp}"

    def get_file_info(self) -> Dict[str, Any]:
        """
        获取文件基本信息

        Returns:
            Dict: 文件信息字典
        """
        if not self.is_pe_file:
            return {}

        file_stats = os.stat(self.file_path)

        return {
            'file_path': self.file_path,
            'file_name': os.path.basename(self.file_path),
            'file_size': file_stats.st_size,
            'is_64_bit': self.is_64_bit,
            'machine_type': self.get_machine_type(),
            'timestamp': self.get_timestamp(),
            'number_of_sections': self.file_header.get('number_of_sections', 0),
            'characteristics': hex(self.file_header.get('characteristics', 0)),
            'entry_point': hex(self.optional_header.get('address_of_entry_point', 0)),
            'image_base': hex(self.optional_header.get('image_base', 0)),
            'subsystem': self.get_subsystem_type(),
            'size_of_image': self.optional_header.get('size_of_image', 0),
            'size_of_headers': self.optional_header.get('size_of_headers', 0)
        }

    def get_detailed_info(self) -> Dict[str, Any]:
        """
        获取详细的PE头信息

        Returns:
            Dict: 详细头信息字典
        """
        if not self.is_pe_file:
            return {}

        return {
            'dos_header': self.dos_header,
            'file_header': self.file_header,
            'optional_header': self.optional_header,
            'sections': self.sections,
            'file_info': self.get_file_info()
        }

    def print_summary(self):
        """
        打印PE文件摘要信息
        """
        if not self.is_pe_file:
            print("不是有效的PE文件")
            return

        info = self.get_file_info()

        print("\n" + "=" * 60)
        print("PE文件分析摘要 - 文件头解析模块")
        print("=" * 60)
        print(f"文件名称: {info['file_name']}")
        print(f"文件路径: {info['file_path']}")
        print(f"文件大小: {info['file_size']:,} bytes")
        print(f"架构: {'64位' if info['is_64_bit'] else '32位'} ({info['machine_type']})")
        print(f"编译时间: {info['timestamp']}")
        print(f"节数量: {info['number_of_sections']}")
        print(f"入口点: {info['entry_point']}")
        print(f"映像基址: {info['image_base']}")
        print(f"子系统: {info['subsystem']}")
        print(f"映像大小: {info['size_of_image']:,} bytes")
        print(f"头大小: {info['size_of_headers']:,} bytes")
        print(f"文件特性: {info['characteristics']}")

        if self.sections:
            print("\n节表信息:")
            print("-" * 70)
            for i, section in enumerate(self.sections):
                print(f"{i + 1:2d}. {section['name']:12s} "
                      f"VA: 0x{section['virtual_address']:08x} "
                      f"Size: 0x{section['virtual_size']:08x} "
                      f"Raw: 0x{section['pointer_to_raw_data']:08x} "
                      f"Chars: 0x{section['characteristics']:08x}")


# 使用示例
def analyze_pe_file(file_path: str):
    """
    分析PE文件的示例函数

    Args:
        file_path: PE文件路径
    """
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return

    print(f"正在分析PE文件: {file_path}")

    # 创建解析器
    parser = PEParser(file_path)

    # 执行解析
    if parser.parse():
        print("✅ PE文件解析成功！")

        # 打印摘要信息
        parser.print_summary()

        # 返回解析结果供其他模块使用
        return parser.get_detailed_info()
    else:
        print("❌ PE文件解析失败！")
        return None


if __name__ == "__main__":
    # 测试代码
    test_file = input("请输入PE文件路径: ").strip()
    analyze_pe_file(test_file)