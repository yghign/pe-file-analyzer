import struct
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


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
        self.data_directories = {}
        self.sections = []
        self.is_pe_file = False
        self.is_64_bit = False
        self.analysis_errors = []

    def load_file(self) -> bool:
        """
        加载文件数据

        Returns:
            bool: 是否成功加载
        """
        try:
            if not os.path.exists(self.file_path):
                self.analysis_errors.append(f"文件不存在: {self.file_path}")
                return False

            file_size = os.path.getsize(self.file_path)
            if file_size < 64:
                self.analysis_errors.append(f"文件过小 ({file_size} bytes)，可能不是有效的PE文件")
                return False

            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()

            return True
        except Exception as e:
            error_msg = f"文件加载失败: {e}"
            self.analysis_errors.append(error_msg)
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

            # 检查MZ签名
            if e_magic != b'MZ':
                self.analysis_errors.append("无效的DOS签名 (不是MZ)")
                return False

            # 检查NT头偏移是否合理
            if e_lfanew >= len(self.file_data) or e_lfanew < 64:
                self.analysis_errors.append(f"NT头偏移无效: 0x{e_lfanew:X}")
                return False

            self.dos_header = {
                'e_magic': e_magic.hex().upper(),
                'e_magic_ascii': e_magic.decode('ascii', errors='ignore'),
                'e_lfanew': e_lfanew,
                'e_lfanew_hex': f"0x{e_lfanew:08X}"
            }

            return True
        except Exception as e:
            error_msg = f"DOS头解析失败: {e}"
            self.analysis_errors.append(error_msg)
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
                self.analysis_errors.append("PE签名位置超出文件范围")
                return False

            signature = struct.unpack_from('<L', self.file_data, e_lfanew)[0]
            if signature != 0x4550:  # 'PE\0\0'
                self.analysis_errors.append(f"无效的PE签名: 0x{signature:08X}")
                return False

            # 文件头位置 (IMAGE_FILE_HEADER)
            file_header_offset = e_lfanew + 4

            if file_header_offset + 20 > len(self.file_data):
                self.analysis_errors.append("文件头位置超出文件范围")
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
                'machine_hex': f"0x{machine:04X}",
                'number_of_sections': number_of_sections,
                'time_date_stamp': time_date_stamp,
                'pointer_to_symbol_table': pointer_to_symbol_table,
                'pointer_to_symbol_table_hex': f"0x{pointer_to_symbol_table:08X}",
                'number_of_symbols': number_of_symbols,
                'size_of_optional_header': size_of_optional_header,
                'characteristics': characteristics,
                'characteristics_hex': f"0x{characteristics:04X}",
                'characteristics_desc': self._parse_file_characteristics(characteristics)
            }

            # 解析可选头 (IMAGE_OPTIONAL_HEADER)
            optional_header_offset = file_header_offset + 20
            return self.parse_optional_header(optional_header_offset, size_of_optional_header)

        except Exception as e:
            error_msg = f"NT头解析失败: {e}"
            self.analysis_errors.append(error_msg)
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
                self.analysis_errors.append("可选头位置超出文件范围")
                return False

            # 读取Magic字段判断架构
            magic = struct.unpack_from('<H', self.file_data, offset)[0]
            self.is_64_bit = (magic == 0x20b)  # PE32+为0x20b, PE32为0x10b

            if magic not in [0x10b, 0x20b]:
                self.analysis_errors.append(f"不支持的Optional Header Magic: 0x{magic:04X}")
                return False

            # 初始化可选头字典
            self.optional_header = {
                'magic': magic,
                'magic_hex': f"0x{magic:04X}",
                'magic_desc': 'PE32' if magic == 0x10b else 'PE32+ (64-bit)',
                'address_of_entry_point': 0,
                'image_base': 0,
                'subsystem': 2,  # 默认Windows GUI
                'size_of_image': 0,
                'size_of_headers': 0,
                'section_alignment': 0,
                'file_alignment': 0
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
                        'size_of_code_hex': f"0x{size_of_code:08X}",
                        'size_of_initialized_data': size_of_initialized_data,
                        'size_of_initialized_data_hex': f"0x{size_of_initialized_data:08X}",
                        'size_of_uninitialized_data': size_of_uninitialized_data,
                        'size_of_uninitialized_data_hex': f"0x{size_of_uninitialized_data:08X}",
                        'address_of_entry_point': address_of_entry_point,
                        'address_of_entry_point_hex': f"0x{address_of_entry_point:08X}",
                        'base_of_code': base_of_code,
                        'base_of_code_hex': f"0x{base_of_code:08X}"
                    })

                    # 解析映像基址
                    if self.is_64_bit and offset + 32 <= len(self.file_data):
                        image_base = struct.unpack_from('<Q', self.file_data, offset + 24)[0]
                        self.optional_header['image_base'] = image_base
                        self.optional_header['image_base_hex'] = f"0x{image_base:016X}"
                    elif not self.is_64_bit and offset + 28 <= len(self.file_data):
                        image_base = struct.unpack_from('<I', self.file_data, offset + 24)[0]
                        self.optional_header['image_base'] = image_base
                        self.optional_header['image_base_hex'] = f"0x{image_base:08X}"

                    # 解析对齐信息
                    if self.is_64_bit and offset + 40 <= len(self.file_data):
                        section_alignment = struct.unpack_from('<I', self.file_data, offset + 32)[0]
                        file_alignment = struct.unpack_from('<I', self.file_data, offset + 36)[0]
                        self.optional_header.update({
                            'section_alignment': section_alignment,
                            'file_alignment': file_alignment
                        })
                    elif not self.is_64_bit and offset + 36 <= len(self.file_data):
                        section_alignment = struct.unpack_from('<I', self.file_data, offset + 32)[0]
                        file_alignment = struct.unpack_from('<I', self.file_data, offset + 36)[0]
                        self.optional_header.update({
                            'section_alignment': section_alignment,
                            'file_alignment': file_alignment
                        })

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
                            'size_of_image_hex': f"0x{size_of_image:08X}",
                            'size_of_headers': size_of_headers,
                            'size_of_headers_hex': f"0x{size_of_headers:08X}"
                        })
                    elif not self.is_64_bit and offset + 56 <= len(self.file_data):
                        size_of_image = struct.unpack_from('<I', self.file_data, offset + 56)[0]
                        size_of_headers = struct.unpack_from('<I', self.file_data, offset + 60)[0]
                        self.optional_header.update({
                            'size_of_image': size_of_image,
                            'size_of_image_hex': f"0x{size_of_image:08X}",
                            'size_of_headers': size_of_headers,
                            'size_of_headers_hex': f"0x{size_of_headers:08X}"
                        })

                    # 解析数据目录
                    self._parse_data_directories(offset)

                except Exception as e:
                    self.analysis_errors.append(f"可选头部分字段解析失败: {e}")

            return True

        except Exception as e:
            error_msg = f"可选头解析失败: {e}"
            self.analysis_errors.append(error_msg)
            return False

    def _parse_data_directories(self, optional_header_offset: int):
        """解析数据目录表"""
        try:
            # 数据目录表在可选头中的偏移量
            if self.is_64_bit:
                dd_offset = optional_header_offset + 112
            else:
                dd_offset = optional_header_offset + 96

            if dd_offset + 128 > len(self.file_data):
                return

            data_directory_names = [
                "Export Table", "Import Table", "Resource Table", "Exception Table",
                "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
                "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
                "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
            ]

            self.data_directories = {}
            for i in range(16):
                rva = struct.unpack_from('<I', self.file_data, dd_offset + i * 8)[0]
                size = struct.unpack_from('<I', self.file_data, dd_offset + i * 8 + 4)[0]

                if rva != 0 or size != 0:
                    self.data_directories[data_directory_names[i]] = {
                        'rva': rva,
                        'rva_hex': f"0x{rva:08X}",
                        'size': size,
                        'size_hex': f"0x{size:08X}"
                    }

        except Exception as e:
            self.analysis_errors.append(f"数据目录解析失败: {e}")

    def _parse_file_characteristics(self, characteristics: int) -> List[str]:
        """解析文件特性标志"""
        flags = {
            0x0001: "RELOCS_STRIPPED",
            0x0002: "EXECUTABLE_IMAGE",
            0x0004: "LINE_NUMS_STRIPPED",
            0x0008: "LOCAL_SYMS_STRIPPED",
            0x0010: "AGGRESSIVE_WS_TRIM",
            0x0020: "LARGE_ADDRESS_AWARE",
            0x0080: "BYTES_REVERSED_LO",
            0x0100: "32BIT_MACHINE",
            0x0200: "DEBUG_STRIPPED",
            0x0400: "REMOVABLE_RUN_FROM_SWAP",
            0x0800: "NET_RUN_FROM_SWAP",
            0x1000: "SYSTEM",
            0x2000: "DLL",
            0x4000: "UP_SYSTEM_ONLY",
            0x8000: "BYTES_REVERSED_HI"
        }

        desc = []
        for flag, name in flags.items():
            if characteristics & flag:
                desc.append(name)
        return desc

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
                    self.analysis_errors.append(f"节表 {i} 超出文件范围")
                    break

                # 解析节表字段
                name_bytes = self.file_data[section_offset:section_offset + 8]
                virtual_size = struct.unpack_from('<I', self.file_data, section_offset + 8)[0]
                virtual_address = struct.unpack_from('<I', self.file_data, section_offset + 12)[0]
                size_of_raw_data = struct.unpack_from('<I', self.file_data, section_offset + 16)[0]
                pointer_to_raw_data = struct.unpack_from('<I', self.file_data, section_offset + 20)[0]
                characteristics = struct.unpack_from('<I', self.file_data, section_offset + 36)[0]

                # 清理节名中的空字符
                try:
                    section_name = name_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')
                except:
                    section_name = name_bytes.hex()

                section_info = {
                    'index': i + 1,
                    'name': section_name,
                    'virtual_size': virtual_size,
                    'virtual_size_hex': f"0x{virtual_size:08X}",
                    'virtual_address': virtual_address,
                    'virtual_address_hex': f"0x{virtual_address:08X}",
                    'size_of_raw_data': size_of_raw_data,
                    'size_of_raw_data_hex': f"0x{size_of_raw_data:08X}",
                    'pointer_to_raw_data': pointer_to_raw_data,
                    'pointer_to_raw_data_hex': f"0x{pointer_to_raw_data:08X}",
                    'characteristics': characteristics,
                    'characteristics_hex': f"0x{characteristics:08X}",
                    'characteristics_desc': self._parse_section_characteristics(characteristics)
                }

                self.sections.append(section_info)

            return True

        except Exception as e:
            error_msg = f"节表解析失败: {e}"
            self.analysis_errors.append(error_msg)
            return False

    def _parse_section_characteristics(self, characteristics: int) -> List[str]:
        """解析节特性标志"""
        flags = {
            0x00000020: "CODE",
            0x00000040: "INITIALIZED_DATA",
            0x00000080: "UNINITIALIZED_DATA",
            0x00000008: "EXECUTE",
            0x00000004: "READ",
            0x00000002: "WRITE",
            0x00000010: "DISCARDABLE",
            0x02000000: "MEM_NOT_CACHED",
            0x04000000: "MEM_NOT_PAGED",
            0x08000000: "MEM_SHARED",
            0x10000000: "MEM_EXECUTE",
            0x20000000: "MEM_READ",
            0x40000000: "MEM_WRITE"
        }

        desc = []
        for flag, name in flags.items():
            if characteristics & flag:
                desc.append(name)
        return desc

    def parse(self) -> bool:
        """
        执行完整的PE文件解析

        Returns:
            bool: 解析是否成功
        """
        self.analysis_errors.clear()

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
            0xebc: 'EFI Byte Code',
            0x9041: 'M32R',
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
            0: 'UNKNOWN',
            1: 'NATIVE',
            2: 'WINDOWS_GUI',
            3: 'WINDOWS_CUI',
            5: 'OS2_CUI',
            7: 'POSIX_CUI',
            9: 'WINDOWS_CE_GUI',
            10: 'EFI_APPLICATION',
            11: 'EFI_BOOT_SERVICE_DRIVER',
            12: 'EFI_RUNTIME_DRIVER',
            13: 'EFI_ROM',
            14: 'XBOX'
        }

        subsystem = self.optional_header.get('subsystem', 0)
        return subsystems.get(subsystem, f'UNKNOWN ({subsystem})')

    def get_timestamp(self) -> Dict[str, Any]:
        """
        获取时间戳信息

        Returns:
            Dict: 包含原始时间戳和格式化时间的字典
        """
        timestamp = self.file_header.get('time_date_stamp', 0)

        result = {
            'raw': timestamp,
            'hex': f"0x{timestamp:08X}"
        }

        if timestamp == 0:
            result['formatted'] = "Not available"
            result['is_valid'] = False
        else:
            try:
                dt = datetime.fromtimestamp(timestamp)
                result['formatted'] = dt.strftime("%Y-%m-%d %H:%M:%S")
                result['is_valid'] = True
            except:
                result['formatted'] = f"Invalid timestamp: {timestamp}"
                result['is_valid'] = False

        return result

    def validate_pe_structure(self) -> Dict[str, Any]:
        """
        验证PE结构完整性

        Returns:
            Dict: 验证结果
        """
        validation_results = {
            'is_valid': True,
            'warnings': [],
            'errors': self.analysis_errors.copy()
        }

        if not self.is_pe_file:
            validation_results['is_valid'] = False
            return validation_results

        # 检查节表完整性
        if len(self.sections) != self.file_header.get('number_of_sections', 0):
            validation_results['warnings'].append("节表数量与文件头声明不符")

        # 检查入口点有效性
        entry_point = self.optional_header.get('address_of_entry_point', 0)
        if entry_point == 0:
            validation_results['warnings'].append("入口点为0，可能是DLL文件")

        # 检查映像大小合理性
        file_size = os.path.getsize(self.file_path)
        image_size = self.optional_header.get('size_of_image', 0)
        if image_size < file_size:
            validation_results['warnings'].append("映像大小小于文件大小")

        return validation_results

    def get_file_info(self) -> Dict[str, Any]:
        """
        获取文件基本信息

        Returns:
            Dict: 文件信息字典
        """
        if not self.is_pe_file:
            return {}

        file_stats = os.stat(self.file_path)
        timestamp_info = self.get_timestamp()

        return {
            'basic_info': {
                'file_path': self.file_path,
                'file_name': os.path.basename(self.file_path),
                'file_size': file_stats.st_size,
                'file_size_mb': round(file_stats.st_size / (1024 * 1024), 2),
                'is_64_bit': self.is_64_bit,
                'machine_type': self.get_machine_type(),
                'timestamp': timestamp_info['formatted'],
                'timestamp_raw': timestamp_info['raw']
            },
            'structure_info': {
                'number_of_sections': self.file_header.get('number_of_sections', 0),
                'characteristics': self.file_header.get('characteristics_desc', []),
                'entry_point': self.optional_header.get('address_of_entry_point_hex', '0x0'),
                'image_base': self.optional_header.get('image_base_hex', '0x0'),
                'subsystem': self.get_subsystem_type(),
                'size_of_image': self.optional_header.get('size_of_image', 0),
                'size_of_headers': self.optional_header.get('size_of_headers', 0),
                'section_alignment': self.optional_header.get('section_alignment', 0),
                'file_alignment': self.optional_header.get('file_alignment', 0)
            },
            'validation': self.validate_pe_structure()
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
            'data_directories': self.data_directories,
            'sections': self.sections,
            'file_info': self.get_file_info(),
            'analysis_errors': self.analysis_errors
        }

    def print_summary(self):
        """
        打印PE文件摘要信息
        """
        if not self.is_pe_file:
            print("不是有效的PE文件")
            if self.analysis_errors:
                print("错误信息:")
                for error in self.analysis_errors:
                    print(f"  - {error}")
            return

        info = self.get_file_info()

        print("\n" + "=" * 70)
        print("PE文件分析摘要 - 文件头解析模块")
        print("=" * 70)

        basic = info['basic_info']
        structure = info['structure_info']

        print(f"文件名称: {basic['file_name']}")
        print(f"文件大小: {basic['file_size']:,} bytes ({basic['file_size_mb']} MB)")
        print(f"架构: {'64位' if basic['is_64_bit'] else '32位'} ({basic['machine_type']})")
        print(f"编译时间: {basic['timestamp']}")
        print(f"节数量: {structure['number_of_sections']}")
        print(f"入口点: {structure['entry_point']}")
        print(f"映像基址: {structure['image_base']}")
        print(f"子系统: {structure['subsystem']}")
        print(f"映像大小: {structure['size_of_image']:,} bytes")
        print(f"头大小: {structure['size_of_headers']:,} bytes")
        print(f"节对齐: {structure['section_alignment']:,} bytes")
        print(f"文件对齐: {structure['file_alignment']:,} bytes")

        print(f"文件特性: {', '.join(structure['characteristics'])}")

        # 数据目录信息
        if self.data_directories:
            print(f"\n数据目录表 ({len(self.data_directories)} 个有效项):")
            for name, dir_info in list(self.data_directories.items())[:5]:  # 显示前5个
                print(f"  {name}: RVA={dir_info['rva_hex']}, Size={dir_info['size_hex']}")

        if self.sections:
            print(f"\n节表信息 ({len(self.sections)} 个节):")
            print("-" * 90)
            print(
                f"{'序号':<4} {'节名':<12} {'虚拟地址':<12} {'虚拟大小':<12} {'文件偏移':<12} {'文件大小':<12} {'特性'}")
            print("-" * 90)
            for section in self.sections:
                flags = section['characteristics_desc']
                main_flag = flags[0] if flags else "DATA"
                print(f"{section['index']:<4} {section['name']:<12} {section['virtual_address_hex']:<12} "
                      f"{section['virtual_size_hex']:<12} {section['pointer_to_raw_data_hex']:<12} "
                      f"{section['size_of_raw_data_hex']:<12} {main_flag}")

        # 显示验证结果
        validation = info['validation']
        if validation['warnings']:
            print(f"\n警告信息 ({len(validation['warnings'])} 个):")
            for warning in validation['warnings']:
                print(f"  ⚠ {warning}")

        if validation['errors']:
            print(f"\n错误信息 ({len(validation['errors'])} 个):")
            for error in validation['errors']:
                print(f"  ❌ {error}")


# 适配器函数 - 保持与团队接口一致
def analyze_headers(pe) -> List[Dict[str, Any]]:
    """
    适配器函数 - 保持与团队接口一致
    参数: pe - pefile.PE对象
    返回: 列表，包含字典格式的头信息
    """
    try:
        # 从pefile对象获取文件路径
        if hasattr(pe, 'filename'):
            file_path = pe.filename
        else:
            return [{"错误": "无法获取文件路径"}]

        # 使用PEParser解析器
        parser = PEParser(file_path)
        if parser.parse():
            file_info = parser.get_file_info()
            detailed_info = parser.get_detailed_info()

            # 转换为约定的列表格式
            headers_list = []

            # 基本信息
            basic = file_info['basic_info']
            structure = file_info['structure_info']

            headers_list.append({
                "类型": "基本信息",
                "文件名称": basic['file_name'],
                "文件大小": f"{basic['file_size']:,} 字节",
                "架构": f"{'64位' if basic['is_64_bit'] else '32位'}",
                "机器类型": basic['machine_type'],
                "编译时间": basic['timestamp'],
                "节数量": structure['number_of_sections'],
                "入口点": structure['entry_point'],
                "映像基址": structure['image_base'],
                "子系统": structure['subsystem'],
                "映像大小": f"{structure['size_of_image']:,} 字节",
                "头大小": f"{structure['size_of_headers']:,} 字节",
                "文件特性": ", ".join(structure['characteristics'])
            })

            # DOS头信息
            headers_list.append({
                "类型": "DOS头",
                **parser.dos_header
            })

            # 文件头信息
            headers_list.append({
                "类型": "文件头",
                **parser.file_header
            })

            # 可选头信息
            headers_list.append({
                "类型": "可选头",
                **parser.optional_header
            })

            return headers_list
        else:
            return [{"错误": "PE文件解析失败", "详细错误": parser.analysis_errors}]

    except Exception as e:
        return [{"错误": f"头信息解析失败: {str(e)}"}]


# 使用示例
def analyze_pe_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    分析PE文件的示例函数

    Args:
        file_path: PE文件路径

    Returns:
        Dict: 解析结果
    """
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return None

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
        if parser.analysis_errors:
            print("错误详情:")
            for error in parser.analysis_errors:
                print(f"  - {error}")
        return None


if __name__ == "__main__":
    # 测试代码
    test_file = input("请输入PE文件路径: ").strip()
    if not test_file:
        # 默认测试文件
        test_file = "C:\\Windows\\System32\\notepad.exe"

    result = analyze_pe_file(test_file)