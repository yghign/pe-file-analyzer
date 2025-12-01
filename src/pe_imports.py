import hashlib
import os
import pefile
from typing import Dict, List, Any, Optional


class PEAnalysisUtils:
    """
    PE文件分析工具类
    包含哈希计算、字符串提取、导入表分析等辅助功能
    """

    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, Any]:
        """
        计算文件的多种哈希值

        Args:
            file_path: 文件路径

        Returns:
            包含各种哈希值的字典
        """
        try:
            if not os.path.exists(file_path):
                return {"status": "error", "message": f"文件不存在: {file_path}"}

            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return {"status": "error", "message": "文件为空"}

            with open(file_path, 'rb') as f:
                data = f.read()

            # 计算各种哈希值
            md5_hash = hashlib.md5(data).hexdigest()
            sha1_hash = hashlib.sha1(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
            sha512_hash = hashlib.sha512(data).hexdigest()

            return {
                "status": "success",
                "file_info": {
                    "file_path": file_path,
                    "file_size": file_size,
                    "file_size_mb": round(file_size / (1024 * 1024), 2)
                },
                "hashes": {
                    "MD5": {
                        "value": md5_hash,
                        "description": "128位哈希，常用于文件完整性验证"
                    },
                    "SHA1": {
                        "value": sha1_hash,
                        "description": "160位哈希，安全性高于MD5"
                    },
                    "SHA256": {
                        "value": sha256_hash,
                        "description": "256位哈希，目前广泛使用的安全哈希"
                    },
                    "SHA512": {
                        "value": sha512_hash,
                        "description": "512位哈希，最高安全级别的哈希算法"
                    }
                },
                "hash_analysis": PEAnalysisUtils._analyze_hashes(md5_hash, sha1_hash, sha256_hash)
            }

        except Exception as e:
            return {"status": "error", "message": f"哈希计算失败: {str(e)}"}

    @staticmethod
    def _analyze_hashes(md5: str, sha1: str, sha256: str) -> Dict[str, Any]:
        """分析哈希值的特征"""
        analysis = {
            "hash_lengths_valid": True,
            "warnings": []
        }

        # 检查哈希长度
        if len(md5) != 32:
            analysis["hash_lengths_valid"] = False
            analysis["warnings"].append("MD5哈希长度异常")

        if len(sha1) != 40:
            analysis["hash_lengths_valid"] = False
            analysis["warnings"].append("SHA1哈希长度异常")

        if len(sha256) != 64:
            analysis["hash_lengths_valid"] = False
            analysis["warnings"].append("SHA256哈希长度异常")

        # 检查哈希特征（简单的模式检查）
        if md5.startswith("000000"):
            analysis["warnings"].append("MD5哈希前缀异常")

        if sha256.startswith("000000"):
            analysis["warnings"].append("SHA256哈希前缀异常")

        if not analysis["warnings"]:
            analysis["warnings"].append("哈希值格式正常")

        return analysis

    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4, max_results: int = 1000) -> Dict[str, Any]:
        """
        从文件中提取可打印字符串

        Args:
            file_path: 文件路径
            min_length: 最小字符串长度
            max_results: 最大返回结果数量

        Returns:
            字符串提取结果字典
        """
        try:
            if not os.path.exists(file_path):
                return {"status": "error", "message": f"文件不存在: {file_path}"}

            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return {"status": "error", "message": "文件为空"}

            with open(file_path, 'rb') as file:
                data = file.read()

            strings_info = []
            current_string = ""
            string_count = 0

            for i, byte in enumerate(data):
                if 32 <= byte <= 126:  # 可打印ASCII范围
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        # 计算字符串的偏移量
                        offset = i - len(current_string)

                        # 字符串分类
                        string_type = PEAnalysisUtils._classify_string(current_string)

                        strings_info.append({
                            "offset": offset,
                            "offset_hex": f"0x{offset:08X}",
                            "string": current_string,
                            "length": len(current_string),
                            "type": string_type
                        })
                        string_count += 1

                        if string_count >= max_results:
                            break

                    current_string = ""

            # 处理最后一个字符串
            if len(current_string) >= min_length and string_count < max_results:
                offset = len(data) - len(current_string)
                string_type = PEAnalysisUtils._classify_string(current_string)

                strings_info.append({
                    "offset": offset,
                    "offset_hex": f"0x{offset:08X}",
                    "string": current_string,
                    "length": len(current_string),
                    "type": string_type
                })

            return {
                "status": "success",
                "file_info": {
                    "file_path": file_path,
                    "file_size": file_size,
                    "total_strings_found": len(strings_info),
                    "min_length": min_length,
                    "max_results": max_results
                },
                "strings": strings_info,
                "statistics": PEAnalysisUtils._analyze_strings(strings_info)
            }

        except Exception as e:
            return {"status": "error", "message": f"字符串提取失败: {str(e)}"}

    @staticmethod
    def _classify_string(string: str) -> str:
        """对字符串进行分类"""
        string_lower = string.lower()

        # URL检测
        if any(proto in string_lower for proto in ['http://', 'https://', 'ftp://', 'www.']):
            return "URL"

        # 文件路径检测
        if any(sep in string for sep in ['\\', '/', ':', '.exe', '.dll', '.sys']):
            return "文件路径"

        # 注册表路径检测
        if 'hkey_' in string_lower or '\\software\\' in string_lower:
            return "注册表路径"

        # API函数检测
        if string.startswith(('Get', 'Set', 'Create', 'Open', 'Close', 'Read', 'Write')):
            return "API函数"

        # DLL名称检测
        if string.endswith(('.dll', '.exe', '.sys', '.drv')) and len(string) <= 260:
            return "模块名称"

        # 可执行代码检测（常见汇编指令）
        common_instructions = ['mov ', 'push ', 'pop ', 'call ', 'jmp ', 'cmp ', 'test ']
        if any(instr in string_lower for instr in common_instructions):
            return "代码片段"

        # 数字字符串
        if all(c in '0123456789.-+ ' for c in string):
            return "数字"

        # 长文本
        if len(string) > 50 and ' ' in string:
            return "文本内容"

        return "普通字符串"

    @staticmethod
    def _analyze_strings(strings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析字符串统计信息"""
        if not strings:
            return {"total_strings": 0, "type_breakdown": {}}

        total_length = sum(s["length"] for s in strings)
        type_count = {}

        for string_info in strings:
            str_type = string_info["type"]
            type_count[str_type] = type_count.get(str_type, 0) + 1

        return {
            "total_strings": len(strings),
            "average_length": round(total_length / len(strings), 2),
            "max_length": max(s["length"] for s in strings),
            "min_length": min(s["length"] for s in strings),
            "type_breakdown": type_count,
            "suspicious_patterns": PEAnalysisUtils._detect_suspicious_patterns(strings)
        }

    @staticmethod
    def _detect_suspicious_patterns(strings: List[Dict[str, Any]]) -> List[str]:
        """检测可疑字符串模式"""
        suspicious = []
        suspicious_keywords = [
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit', 'keylogger',
            'exploit', 'payload', 'inject', 'bypass', 'elevate', 'privilege',
            'admin', 'password', 'credential', 'token', 'hash', 'dump',
            'crypt', 'encrypt', 'decrypt', 'ransom', 'locker'
        ]

        for string_info in strings:
            string_lower = string_info["string"].lower()

            # 检查可疑关键词
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    suspicious.append(f"发现可疑关键词 '{keyword}': {string_info['string'][:50]}...")
                    break

            # 检查长Base64-like字符串
            if len(string_info["string"]) > 50 and all(c.isalnum() or c in '+/=' for c in string_info["string"]):
                suspicious.append(f"疑似Base64编码数据: {string_info['string'][:30]}...")

        return suspicious[:10]  # 返回前10个可疑项

    @staticmethod
    def _is_suspicious_function(dll_name: str, func_name: str) -> Dict[str, Any]:
        """检查函数是否可疑并返回详细信息"""
        suspicious_functions = {
            'kernel32.dll': {
                'VirtualAlloc': '动态内存分配，可能用于代码注入',
                'VirtualProtect': '修改内存权限，可能用于绕过DEP',
                'WriteProcessMemory': '写入其他进程内存，可能用于进程注入',
                'CreateRemoteThread': '在其他进程创建线程，可能用于远程代码执行',
                'LoadLibrary': '动态加载DLL',
                'GetProcAddress': '动态获取函数地址'
            },
            'advapi32.dll': {
                'RegSetValue': '修改注册表',
                'RegDeleteValue': '删除注册表项',
                'AdjustTokenPrivileges': '调整令牌权限，可能用于提权'
            },
            'ws2_32.dll': {
                'socket': '创建网络套接字',
                'bind': '绑定网络端口',
                'listen': '监听网络连接',
                'accept': '接受网络连接',
                'connect': '发起网络连接'
            },
            'wininet.dll': {
                'InternetOpen': '初始化网络连接',
                'InternetConnect': '连接到网络服务器',
                'HttpOpenRequest': '创建HTTP请求'
            },
            'urlmon.dll': {
                'URLDownloadToFile': '从URL下载文件'
            },
            'shell32.dll': {
                'ShellExecute': '执行外部程序'
            }
        }

        dll_lower = dll_name.lower()
        for suspicious_dll, functions in suspicious_functions.items():
            if suspicious_dll in dll_lower and func_name in functions:
                return {
                    "suspicious": True,
                    "risk_level": "high",
                    "description": functions[func_name]
                }

        # 网络DLL的一般检测
        network_dlls = ['ws2_32.dll', 'wininet.dll', 'urlmon.dll']
        if any(dll in dll_lower for dll in network_dlls):
            return {
                "suspicious": True,
                "risk_level": "medium",
                "description": "程序可能具有网络功能"
            }

        return {"suspicious": False, "risk_level": "low", "description": ""}

    @staticmethod
    def _assess_dll_risk(dll_name: str) -> str:
        """评估DLL的风险等级"""
        high_risk_dlls = ['kernel32.dll', 'ntdll.dll', 'advapi32.dll', 'ws2_32.dll']
        medium_risk_dlls = ['user32.dll', 'gdi32.dll', 'shell32.dll', 'wininet.dll']

        dll_lower = dll_name.lower()
        if any(hr_dll in dll_lower for hr_dll in high_risk_dlls):
            return "high"
        elif any(mr_dll in dll_lower for mr_dll in medium_risk_dlls):
            return "medium"
        else:
            return "low"

    @staticmethod
    def analyze_imports(pe: pefile.PE) -> Dict[str, Any]:
        """
        分析PE文件的导入表

        Args:
            pe: pefile.PE对象

        Returns:
            导入表分析结果字典
        """
        try:
            imports_info = []
            total_functions = 0
            suspicious_imports = []
            security_warnings = []

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').rstrip('\x00')
                    dll_functions = []

                    for func in entry.imports:
                        if func.name:
                            func_name = func.name.decode('utf-8', errors='ignore')
                        else:
                            func_name = f"Ordinal_{func.ordinal}"

                        # 检查可疑函数
                        suspicious_info = PEAnalysisUtils._is_suspicious_function(dll_name, func_name)

                        function_info = {
                            "name": func_name,
                            "ordinal": func.ordinal,
                            "address": f"0x{func.address:08X}" if func.address else "N/A",
                            "suspicious": suspicious_info["suspicious"],
                            "risk_level": suspicious_info["risk_level"],
                            "description": suspicious_info["description"]
                        }

                        if suspicious_info["suspicious"]:
                            suspicious_imports.append({
                                "dll": dll_name,
                                "function": func_name,
                                "description": suspicious_info["description"],
                                "risk_level": suspicious_info["risk_level"]
                            })

                            # 添加到安全警告
                            if suspicious_info["risk_level"] == "high":
                                security_warnings.append(
                                    f"高危函数: {dll_name}.{func_name} - {suspicious_info['description']}")

                        dll_functions.append(function_info)

                    dll_info = {
                        "dll_name": dll_name,
                        "function_count": len(dll_functions),
                        "functions": dll_functions,
                        "risk_level": PEAnalysisUtils._assess_dll_risk(dll_name)
                    }

                    imports_info.append(dll_info)
                    total_functions += len(dll_functions)

            return {
                "status": "success",
                "imports": imports_info,
                "summary": {
                    "total_dlls": len(imports_info),
                    "total_functions": total_functions,
                    "suspicious_imports_count": len(suspicious_imports),
                    "suspicious_imports": suspicious_imports
                },
                "security_warnings": security_warnings,  # 添加安全警告字段
                "analysis": PEAnalysisUtils._analyze_import_patterns(imports_info)
            }

        except Exception as e:
            return {"status": "error", "message": f"导入表解析失败: {str(e)}"}

    @staticmethod
    def _analyze_import_patterns(imports_info: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析导入表模式"""
        analysis = {
            "risk_assessment": "低风险",
            "warnings": [],
            "observations": []
        }

        total_dlls = len(imports_info)
        high_risk_dlls = sum(1 for dll in imports_info if dll["risk_level"] == "high")

        if high_risk_dlls > 3:
            analysis["risk_assessment"] = "高风险"
            analysis["warnings"].append("发现多个高风险DLL导入")
        elif high_risk_dlls > 0:
            analysis["risk_assessment"] = "中等风险"
            analysis["warnings"].append("发现高风险DLL导入")

        # 检查网络相关DLL
        network_dlls = [dll for dll in imports_info if any(net_dll in dll["dll_name"].lower()
                                                           for net_dll in ['ws2_32', 'wininet', 'urlmon'])]
        if network_dlls:
            analysis["observations"].append("包含网络功能相关DLL")

        # 检查加壳迹象（导入函数很少）
        total_functions = sum(dll["function_count"] for dll in imports_info)
        if total_functions < 10:
            analysis["warnings"].append("导入函数数量过少，可能是加壳程序")

        return analysis

    @staticmethod
    def get_comprehensive_analysis(file_path: str) -> Dict[str, Any]:
        """
        获取PE文件的综合分析

        Args:
            file_path: 文件路径

        Returns:
            综合分析结果字典
        """
        try:
            if not os.path.exists(file_path):
                return {"status": "error", "message": "文件不存在"}

            # 计算哈希值
            hash_analysis = PEAnalysisUtils.calculate_hashes(file_path)

            # 提取字符串
            string_analysis = PEAnalysisUtils.extract_strings(file_path, min_length=4, max_results=500)

            # 使用pefile解析导入表
            pe = pefile.PE(file_path)
            import_analysis = PEAnalysisUtils.analyze_imports(pe)

            return {
                "status": "success",
                "file_info": {
                    "path": file_path,
                    "size": os.path.getsize(file_path),
                    "name": os.path.basename(file_path)
                },
                "hash_analysis": hash_analysis,
                "string_analysis": string_analysis,
                "import_analysis": import_analysis,
                "summary": PEAnalysisUtils._generate_summary(hash_analysis, string_analysis, import_analysis)
            }

        except Exception as e:
            return {"status": "error", "message": f"综合分析失败: {str(e)}"}

    @staticmethod
    def _generate_summary(hash_analysis: Dict, string_analysis: Dict, import_analysis: Dict) -> Dict[str, Any]:
        """生成综合分析摘要"""
        return {
            "file_integrity": "正常" if hash_analysis.get("status") == "success" else "异常",
            "string_analysis": f"找到 {string_analysis.get('file_info', {}).get('total_strings_found', 0)} 个字符串",
            "import_analysis": f"导入 {import_analysis.get('summary', {}).get('total_dlls', 0)} 个DLL, {import_analysis.get('summary', {}).get('total_functions', 0)} 个函数",
            "risk_level": import_analysis.get('analysis', {}).get('risk_assessment', '未知')
        }


# 保持原有函数接口的适配器函数
def calculate_hashes(file_path: str) -> List[Dict[str, str]]:
    """适配器函数 - 保持原有接口"""
    result = PEAnalysisUtils.calculate_hashes(file_path)
    if result["status"] == "success":
        return [{"MD5": result["hashes"]["MD5"]["value"],
                 "SHA1": result["hashes"]["SHA1"]["value"],
                 "SHA256": result["hashes"]["SHA256"]["value"]}]
    else:
        return [{"error": result["message"]}]


def extract_strings(file_path: str, min_length: int = 4) -> List[Dict[str, str]]:
    """适配器函数 - 保持原有接口"""
    result = PEAnalysisUtils.extract_strings(file_path, min_length)
    if result["status"] == "success":
        # 转换为原有格式
        return [{"offset": s["offset_hex"], "string": s["string"]} for s in result["strings"]]
    else:
        return [{"error": result["message"]}]


def analyze_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    """适配器函数 - 保持原有接口"""
    result = PEAnalysisUtils.analyze_imports(pe)
    if result["status"] == "success":
        return result["imports"]
    else:
        return [{"error": result["message"]}]


# 测试代码
if __name__ == "__main__":
    # 测试功能
    test_file = "C:\\Windows\\System32\\notepad.exe"

    if os.path.exists(test_file):
        print("测试PE分析工具...")

        # 测试哈希计算
        hashes = PEAnalysisUtils.calculate_hashes(test_file)
        print("哈希计算:", hashes["status"])

        # 测试字符串提取
        strings = PEAnalysisUtils.extract_strings(test_file, max_results=10)
        print("字符串提取:", strings["status"])

        # 测试导入表分析
        pe = pefile.PE(test_file)
        imports = PEAnalysisUtils.analyze_imports(pe)
        print("导入表分析:", imports["status"])

        if imports["status"] == "success":
            print("安全警告:", imports.get("security_warnings", []))

        # 测试综合分析
        analysis = PEAnalysisUtils.get_comprehensive_analysis(test_file)
        print("综合分析:", analysis["status"])

        if analysis["status"] == "success":
            print("文件:", analysis["file_info"]["name"])
            print("大小:", analysis["file_info"]["size"], "bytes")
            print("风险等级:", analysis["summary"]["risk_level"])
    else:
        print("测试文件不存在，请修改测试文件路径")