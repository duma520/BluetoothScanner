import os
import sys
import time
import logging
import threading
import traceback
import json
import csv
import platform
import subprocess
import asyncio
from datetime import datetime
from tkinter import (
    Tk, Frame, Label, Button, Text, Scrollbar, Listbox, 
    StringVar, Entry, messagebox, filedialog, ttk, DISABLED, NORMAL, PhotoImage
)
from typing import Optional, Dict, List, Tuple, Any, Union
from tkinter import *

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bluetooth_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 尝试导入所有可能的蓝牙库
try:
    import bluetooth
    from bluetooth.ble import DiscoveryService
    PYBLUEZ_AVAILABLE = True
except ImportError:
    PYBLUEZ_AVAILABLE = False
    logger.warning("PyBluez不可用")

try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    logger.warning("Bleak不可用")

class BluetoothScannerBase:
    """蓝牙扫描器基类"""
    
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.timeout = 10
        self.lock = threading.Lock()
        self.cached_devices = []
        self.last_scan_time = 0
        self.cache_expiry = 300
        
    def is_bluetooth_available(self) -> bool:
        """检查系统蓝牙是否可用"""
        raise NotImplementedError
        
    def scan_devices(self, timeout: int = 10) -> List[Dict[str, Any]]:
        """扫描附近的蓝牙设备"""
        raise NotImplementedError
        
    def _get_device_details(self, addr: str, name: Optional[str], device_class: Optional[int] = None, 
                          rssi: Optional[int] = None, adv_data: Optional[Dict] = None) -> Dict[str, Any]:
        """获取设备详细信息"""
        raise NotImplementedError
        
    def _decode_device_class(self, device_class: int) -> str:
        """解码设备类"""
        major_class = (device_class >> 8) & 0x1F
        minor_class = (device_class >> 2) & 0x3F
        
        major_classes = {
            0x00: "杂项",
            0x01: "计算机",
            0x02: "手机",
            0x03: "网络设备",
            0x04: "音频/视频设备",
            0x05: "外设",
            0x06: "成像设备",
            0x07: "可穿戴设备",
            0x08: "玩具",
            0x09: "健康设备",
            0x1F: "未指定"
        }
        
        minor_classes = {
            (0x01, 0x00): "台式工作站",
            (0x01, 0x01): "服务器",
            (0x01, 0x02): "笔记本电脑",
            (0x01, 0x03): "手持PC/PDA",
            (0x01, 0x04): "掌上电脑",
            (0x01, 0x05): "可穿戴设备",
            (0x02, 0x00): "手机",
            (0x02, 0x01): "调制解调器",
            (0x02, 0x02): "网关",
            (0x04, 0x00): "耳机",
            (0x04, 0x01): "扬声器",
            (0x04, 0x02): "便携式音频",
            (0x04, 0x03): "车载音频",
            (0x04, 0x04): "视频显示器",
            (0x04, 0x05): "视频摄像机",
            (0x04, 0x06): "视频录像机",
            (0x04, 0x07): "视频会议设备",
            (0x05, 0x01): "键盘",
            (0x05, 0x02): "鼠标",
            (0x05, 0x03): "操纵杆",
            (0x05, 0x04): "游戏控制器",
            (0x05, 0x05): "触控板",
            (0x05, 0x06): "远程控制",
            (0x05, 0x07): "传感设备"
        }
        
        major = major_classes.get(major_class, "未知")
        minor = minor_classes.get((major_class, minor_class), "未知")
        
        return f"{major} ({minor})"

class PyBluezScanner(BluetoothScannerBase):
    """使用PyBluez的蓝牙扫描器实现（经典蓝牙）"""
    
    def is_bluetooth_available(self) -> bool:
        try:
            bluetooth._bluetooth.hci_send_req(
                bluetooth._bluetooth.HCI_DEV_NONE,
                bluetooth._bluetooth.OGF_HOST_CTL,
                0x0014
            )
            return True
        except Exception as e:
            logger.error(f"蓝牙不可用: {str(e)}")
            return False
    
    def scan_devices(self, timeout: int = 10) -> List[Dict[str, Any]]:
        if not self.is_bluetooth_available():
            raise RuntimeError("系统蓝牙不可用或未启用")
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logger.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        devices = []
        
        try:
            logger.info(f"开始经典蓝牙扫描, 超时时间: {timeout}秒")
            
            # 扫描经典蓝牙设备
            classic_devices = bluetooth.discover_devices(
                duration=timeout, 
                flush_cache=True, 
                lookup_names=True, 
                lookup_class=True
            )
            
            for addr, name, device_class in classic_devices:
                try:
                    device_info = self._get_device_details(addr, name, device_class)
                    devices.append(device_info)
                except Exception as e:
                    logger.error(f"获取设备 {addr} 详细信息失败: {str(e)}")
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logger.error(f"扫描过程中发生错误: {str(e)}")
            raise
        finally:
            self.scanning = False
            
        return devices
    
    def _get_device_details(self, addr: str, name: Optional[str], device_class: int, 
                          rssi: Optional[int] = None, adv_data: Optional[Dict] = None) -> Dict[str, Any]:
        device_info = {
            'address': addr,
            'name': name or '未知',
            'type': '经典蓝牙',
            'class': self._decode_device_class(device_class),
            'class_code': device_class,
            'rssi': rssi or '未知',
            'paired': self._check_paired_status(addr),
            'services': self._get_device_services(addr),
            'manufacturer': self._get_manufacturer_info(addr),
            'discovery_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'bluetooth_version': '未知',
            'adv_data': adv_data or {}
        }
        
        try:
            device_info['rssi'] = bluetooth.read_rssi(addr)
        except:
            pass
            
        return device_info
    
    def _check_paired_status(self, addr: str) -> bool:
        try:
            return addr in [d[0] for d in bluetooth.discover_devices(lookup_names=False)]
        except:
            return False
    
    def _get_device_services(self, addr: str) -> List[str]:
        try:
            services = bluetooth.find_service(address=addr)
            return [s['name'] for s in services if 'name' in s]
        except:
            return []
    
    def _get_manufacturer_info(self, addr: str) -> str:
        try:
            return '未知'
        except:
            return '未知'

class BleakScannerWrapper(BluetoothScannerBase):
    """使用Bleak的蓝牙扫描器实现（BLE蓝牙4.0-5.4）"""
    
    def __init__(self):
        super().__init__()
        self.loop = None
        self.loop_thread = None
        self._setup_event_loop()
    
    def _setup_event_loop(self):
        """为Bleak设置事件循环"""
        if not self.loop:
            self.loop = asyncio.new_event_loop()
            self.loop_thread = threading.Thread(
                target=self._run_event_loop,
                args=(self.loop,),
                daemon=True
            )
            self.loop_thread.start()
    
    def _run_event_loop(self, loop):
        """运行事件循环"""
        asyncio.set_event_loop(loop)
        loop.run_forever()
    
    def is_bluetooth_available(self) -> bool:
        return BLEAK_AVAILABLE
    
    def scan_devices(self, timeout: int = 10) -> List[Dict[str, Any]]:
        if not self.is_bluetooth_available():
            raise RuntimeError("Bleak不可用，无法扫描BLE设备")
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logger.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        devices = []
        
        try:
            logger.info(f"开始BLE蓝牙扫描, 超时时间: {timeout}秒")
            
            # 在事件循环中运行扫描
            future = asyncio.run_coroutine_threadsafe(
                self._async_scan_devices(timeout),
                self.loop
            )
            
            try:
                devices = future.result(timeout + 5)
            except asyncio.TimeoutError:
                logger.warning("BLE扫描超时")
                future.cancel()
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logger.error(f"BLE扫描过程中发生错误: {str(e)}")
            raise
        finally:
            self.scanning = False
            
        return devices
    
    async def _async_scan_devices(self, timeout: int) -> List[Dict[str, Any]]:
        """异步扫描BLE设备"""
        devices = []
        
        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            """发现设备的回调函数"""
            try:
                device_info = self._get_device_details(
                    device.address,
                    device.name,
                    None,  # BLE设备没有设备类
                    advertisement_data.rssi,
                    {
                        'local_name': advertisement_data.local_name,
                        'manufacturer_data': dict(advertisement_data.manufacturer_data),
                        'service_data': dict(advertisement_data.service_data),
                        'service_uuids': advertisement_data.service_uuids,
                        'tx_power': advertisement_data.tx_power,
                        'platform_data': advertisement_data.platform_data
                    }
                )
                
                # 估计蓝牙版本
                if device_info['adv_data'].get('manufacturer_data'):
                    device_info['bluetooth_version'] = self._estimate_bluetooth_version(device_info)
                else:
                    device_info['bluetooth_version'] = '4.x'
                
                devices.append(device_info)
            except Exception as e:
                logger.error(f"处理设备 {device.address} 失败: {str(e)}")
        
        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        
        return devices
    
    def _estimate_bluetooth_version(self, device_info: Dict[str, Any]) -> str:
        """根据广告数据估计蓝牙版本"""
        try:
            manufacturer_data = device_info['adv_data'].get('manufacturer_data', {})
            if not manufacturer_data:
                return '4.x'
            
            # 检查蓝牙5.x特征
            for data in manufacturer_data.values():
                if len(data) >= 3 and data[0] == 0x02 and data[1] == 0x0A:
                    # 检查蓝牙5.1+特征
                    if len(data) >= 4 and (data[3] & 0x02):
                        return '5.1+'
                    return '5.0'
            
            # 检查蓝牙4.2特征
            service_uuids = device_info['adv_data'].get('service_uuids', [])
            if any('fe2c' in uuid.lower() for uuid in service_uuids):
                return '4.2'
            
            return '4.x'
        except:
            return '未知'
    
    def _get_device_details(self, addr: str, name: Optional[str], device_class: Optional[int], 
                          rssi: Optional[int], adv_data: Optional[Dict]) -> Dict[str, Any]:
        return {
            'address': addr,
            'name': name or '未知',
            'type': 'BLE',
            'class': '未知',
            'class_code': 0,
            'rssi': rssi or '未知',
            'paired': False,
            'services': adv_data.get('service_uuids', []) if adv_data else [],
            'manufacturer': self._get_ble_manufacturer(adv_data),
            'discovery_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'bluetooth_version': '未知',
            'adv_data': adv_data or {}
        }
    
    def _get_ble_manufacturer(self, adv_data: Optional[Dict]) -> str:
        """从广告数据获取BLE设备制造商"""
        if not adv_data or not adv_data.get('manufacturer_data'):
            return '未知'
        
        try:
            # 第一个制造商ID
            manufacturer_id = next(iter(adv_data['manufacturer_data'].keys()))
            
            # 常见制造商ID
            manufacturers = {
                0x004C: "Apple",
                0x0006: "Microsoft",
                0x000F: "Texas Instruments",
                0x001D: "Qualcomm",
                0x0030: "Sony",
                0x0059: "Nordic Semiconductor",
                0x0075: "Samsung",
                0x00E0: "Google",
                0x015D: "Realtek"
            }
            
            return manufacturers.get(manufacturer_id, f"未知 (ID: {manufacturer_id})")
        except:
            return '未知'

class SystemCommandScanner(BluetoothScannerBase):
    """使用系统命令的蓝牙扫描器替代实现"""
    
    def is_bluetooth_available(self) -> bool:
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-PnpDevice -Class Bluetooth'],
                    capture_output=True, text=True, timeout=5
                )
                return 'Bluetooth' in result.stdout
            elif platform.system() == 'Linux':
                result = subprocess.run(
                    ['hciconfig'],
                    capture_output=True, text=True, timeout=5
                )
                return result.returncode == 0
            elif platform.system() == 'Darwin':
                result = subprocess.run(
                    ['system_profiler', 'SPBluetoothDataType'],
                    capture_output=True, text=True, timeout=5
                )
                return 'Bluetooth:' in result.stdout
            else:
                return False
        except Exception as e:
            logger.error(f"检查蓝牙可用性失败: {str(e)}")
            return False
    
    def scan_devices(self, timeout: int = 10) -> List[Dict[str, Any]]:
        if not self.is_bluetooth_available():
            raise RuntimeError("系统蓝牙不可用或未启用")
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logger.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        devices = []
        
        try:
            logger.info(f"开始蓝牙扫描, 超时时间: {timeout}秒")
            
            if platform.system() == 'Windows':
                devices = self._scan_windows(timeout)
            elif platform.system() == 'Linux':
                devices = self._scan_linux(timeout)
            elif platform.system() == 'Darwin':
                devices = self._scan_macos(timeout)
            else:
                raise RuntimeError("不支持的操作系统")
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logger.error(f"扫描过程中发生错误: {str(e)}")
            raise
        finally:
            self.scanning = False
            
        return devices
    
    def _scan_windows(self, timeout: int) -> List[Dict[str, Any]]:
        """Windows系统下的蓝牙扫描"""
        devices = []
        
        try:
            result = subprocess.run(
                ['powershell', '-Command', f'$timeout={timeout}; $start=Get-Date; do {{ Get-PnpDevice -Class Bluetooth | Where-Object {{$_.Status -eq "OK"}} | Select-Object Name,DeviceID; Start-Sleep -Seconds 1; }} while ((Get-Date) -lt $start.AddSeconds($timeout))'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"扫描失败: {result.stderr}")
            
            current_device = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Name'):
                    current_device['name'] = line.split(':', 1)[1].strip()
                elif line.startswith('DeviceID'):
                    current_device['address'] = line.split(':', 1)[1].strip()
                    if current_device.get('name') and current_device.get('address'):
                        devices.append(self._get_device_details(
                            current_device['address'],
                            current_device['name']
                        ))
                        current_device = {}
            
        except subprocess.TimeoutExpired:
            logger.warning("蓝牙扫描超时")
        except Exception as e:
            logger.error(f"Windows扫描错误: {str(e)}")
        
        return devices
    
    def _scan_linux(self, timeout: int) -> List[Dict[str, Any]]:
        """Linux系统下的蓝牙扫描"""
        devices = []
        
        try:
            subprocess.run(
                ['bluetoothctl', 'scan', 'on'],
                capture_output=True, text=True, timeout=5
            )
            
            time.sleep(timeout)
            
            result = subprocess.run(
                ['bluetoothctl', 'devices'],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"扫描失败: {result.stderr}")
            
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    name = ' '.join(parts[2:]) if len(parts) > 2 else '未知'
                    devices.append(self._get_device_details(addr, name))
            
            subprocess.run(
                ['bluetoothctl', 'scan', 'off'],
                capture_output=True, text=True, timeout=5
            )
            
        except subprocess.TimeoutExpired:
            logger.warning("蓝牙扫描超时")
        except Exception as e:
            logger.error(f"Linux扫描错误: {str(e)}")
        
        return devices
    
    def _scan_macos(self, timeout: int) -> List[Dict[str, Any]]:
        """macOS系统下的蓝牙扫描"""
        devices = []
        
        try:
            result = subprocess.run(
                ['system_profiler', 'SPBluetoothDataType'],
                capture_output=True, text=True, timeout=timeout + 5
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"扫描失败: {result.stderr}")
            
            current_section = None
            current_device = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Devices:' in line:
                    current_section = 'devices'
                elif current_section == 'devices' and line.startswith('Name:'):
                    current_device['name'] = line.split(':', 1)[1].strip()
                elif current_section == 'devices' and line.startswith('Address:'):
                    current_device['address'] = line.split(':', 1)[1].strip()
                    if current_device.get('name') and current_device.get('address'):
                        devices.append(self._get_device_details(
                            current_device['address'],
                            current_device['name']
                        ))
                        current_device = {}
            
        except subprocess.TimeoutExpired:
            logger.warning("蓝牙扫描超时")
        except Exception as e:
            logger.error(f"macOS扫描错误: {str(e)}")
        
        return devices
    
    def _get_device_details(self, addr: str, name: Optional[str], device_class: Optional[int] = None, 
                          rssi: Optional[int] = None, adv_data: Optional[Dict] = None) -> Dict[str, Any]:
        return {
            'address': addr,
            'name': name or '未知',
            'type': '蓝牙设备',
            'class': '未知',
            'class_code': 0,
            'rssi': '未知',
            'paired': False,
            'services': [],
            'manufacturer': '未知',
            'discovery_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'bluetooth_version': '未知',
            'adv_data': {}
        }

class BluetoothScannerApp:
    """蓝牙扫描器GUI应用"""
    
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("蓝牙设备扫描工具 (支持蓝牙5.4)")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)
        
        # 创建扫描器实例
        self.scanners = []
        
        if PYBLUEZ_AVAILABLE:
            self.scanners.append(PyBluezScanner())
            logger.info("PyBluez扫描器已启用")
        
        if BLEAK_AVAILABLE:
            self.scanners.append(BleakScannerWrapper())
            logger.info("Bleak扫描器已启用")
        
        if not self.scanners:
            self.scanners.append(SystemCommandScanner())
            logger.info("使用系统命令扫描器")
        
        # 创建UI
        self._setup_ui()
        
        # 状态变量
        self.scan_in_progress = False
        self.current_devices = []
        
        # 检查蓝牙可用性
        self._check_initial_bluetooth_status()
    
    def _setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # 顶部控制面板
        control_frame = Frame(main_frame)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # 扫描按钮
        self.scan_button = Button(
            control_frame, 
            text="开始扫描", 
            command=self._toggle_scan,
            width=15
        )
        self.scan_button.pack(side='left', padx=(0, 10))
        
        # 超时设置
        Label(control_frame, text="扫描超时(秒):").pack(side='left', padx=(10, 5))
        self.timeout_var = StringVar(value="10")
        timeout_entry = Entry(
            control_frame, 
            textvariable=self.timeout_var, 
            width=5
        )
        timeout_entry.pack(side='left')
        
        # 扫描类型选择
        self.scan_type_var = StringVar(value="all")
        scan_type_frame = Frame(control_frame)
        scan_type_frame.pack(side='left', padx=(10, 0))
        Label(scan_type_frame, text="扫描类型:").pack(side='left')
        Radiobutton(
            scan_type_frame, 
            text="全部", 
            variable=self.scan_type_var, 
            value="all"
        ).pack(side='left')
        if PYBLUEZ_AVAILABLE:
            Radiobutton(
                scan_type_frame, 
                text="经典蓝牙", 
                variable=self.scan_type_var, 
                value="classic"
            ).pack(side='left', padx=(5, 0))
        if BLEAK_AVAILABLE:
            Radiobutton(
                scan_type_frame, 
                text="BLE", 
                variable=self.scan_type_var, 
                value="ble"
            ).pack(side='left', padx=(5, 0))
        
        # 导出按钮
        Button(
            control_frame, 
            text="导出报告", 
            command=self._export_report,
            width=15
        ).pack(side='right')
        
        # 设备列表
        list_frame = Frame(main_frame)
        list_frame.pack(fill='both', expand=True)
        
        # 列表标题
        columns = ["名称", "地址", "类型", "蓝牙版本", "设备类", "信号强度", "配对状态"]
        self.device_list = ttk.Treeview(
            list_frame, 
            columns=columns, 
            show='headings',
            selectmode='browse'
        )
        
        for col in columns:
            self.device_list.heading(col, text=col)
            self.device_list.column(col, width=80, anchor='center')
        
        self.device_list.column("名称", width=150, anchor='w')
        self.device_list.column("地址", width=120)
        self.device_list.column("设备类", width=150)
        self.device_list.column("蓝牙版本", width=80)
        
        # 滚动条
        scrollbar = Scrollbar(list_frame, orient="vertical", command=self.device_list.yview)
        self.device_list.configure(yscrollcommand=scrollbar.set)
        
        self.device_list.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # 设备详情
        detail_frame = Frame(main_frame)
        detail_frame.pack(fill='both', expand=True, pady=(10, 0))
        
        Label(detail_frame, text="设备详细信息:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        self.detail_text = Text(
            detail_frame, 
            wrap='word', 
            height=12,
            state=DISABLED
        )
        scrollbar = Scrollbar(detail_frame, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=scrollbar.set)
        
        self.detail_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # 状态栏
        self.status_var = StringVar()
        self.status_var.set("就绪")
        status_bar = Label(
            self.root, 
            textvariable=self.status_var,
            relief='sunken', 
            anchor='w'
        )
        status_bar.pack(side='bottom', fill='x')
        
        # 绑定事件
        self.device_list.bind('<<TreeviewSelect>>', self._show_device_details)
        
    def _check_initial_bluetooth_status(self):
        """检查初始蓝牙状态"""
        available = any(scanner.is_bluetooth_available() for scanner in self.scanners)
        if not available:
            messagebox.showerror(
                "错误", 
                "系统蓝牙不可用或未启用。请确保蓝牙已打开并重试。"
            )
            self.scan_button.config(state=DISABLED)
    
    def _toggle_scan(self):
        """切换扫描状态"""
        if self.scan_in_progress:
            self._stop_scan()
        else:
            self._start_scan()
    
    def _start_scan(self):
        """开始扫描"""
        try:
            timeout = int(self.timeout_var.get())
            if timeout <= 0 or timeout > 60:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "错误", 
                "请输入1-60之间的有效超时时间(秒)"
            )
            return
        
        self.current_devices = []
        for item in self.device_list.get_children():
            self.device_list.delete(item)
        
        self.detail_text.config(state=NORMAL)
        self.detail_text.delete(1.0, 'end')
        self.detail_text.config(state=DISABLED)
        
        self.scan_in_progress = True
        self.scan_button.config(text="停止扫描")
        self.status_var.set("扫描中...")
        
        self.scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(timeout,),
            daemon=True
        )
        self.scan_thread.start()
        
        self._monitor_scan_progress()
    
    def _stop_scan(self):
        """停止扫描"""
        self.scan_in_progress = False
        self.scan_button.config(text="开始扫描")
        self.status_var.set("扫描已停止")
    
    def _perform_scan(self, timeout: int):
        """执行实际的扫描操作"""
        try:
            scan_type = self.scan_type_var.get()
            devices = []
            
            if scan_type == "all":
                for scanner in self.scanners:
                    try:
                        devices.extend(scanner.scan_devices(timeout))
                    except Exception as e:
                        logger.error(f"{type(scanner).__name__} 扫描失败: {str(e)}")
            elif scan_type == "classic" and PYBLUEZ_AVAILABLE:
                devices.extend(self.scanners[0].scan_devices(timeout))
            elif scan_type == "ble" and BLEAK_AVAILABLE:
                devices.extend(self.scanners[-1].scan_devices(timeout))
            
            # 去重
            unique_devices = {}
            for device in devices:
                if device['address'] not in unique_devices:
                    unique_devices[device['address']] = device
                else:
                    # 合并信息
                    existing = unique_devices[device['address']]
                    for key in ['name', 'type', 'class', 'rssi', 'services', 'manufacturer', 'bluetooth_version']:
                        if existing[key] == '未知' and device[key] != '未知':
                            existing[key] = device[key]
                    
                    if isinstance(device['adv_data'], dict) and device['adv_data']:
                        existing['adv_data'].update(device['adv_data'])
            
            self.current_devices = list(unique_devices.values())
            self.root.after(0, self._update_device_list, self.current_devices)
            self.status_var.set(f"扫描完成, 找到 {len(self.current_devices)} 个设备")
            
        except Exception as e:
            logger.error(f"扫描错误: {str(e)}")
            self.root.after(0, messagebox.showerror, 
                          "扫描错误", 
                          f"扫描过程中发生错误: {str(e)}")
            self.root.after(0, lambda: self.status_var.set(f"扫描错误: {str(e)}"))
        
        finally:
            self.root.after(0, lambda: setattr(self, 'scan_in_progress', False))
            self.root.after(0, lambda: self.scan_button.config(text="开始扫描"))
    
    def _monitor_scan_progress(self):
        """监控扫描进度"""
        if self.scan_in_progress:
            current_status = self.status_var.get()
            if "..." in current_status:
                dots = current_status.count(".")
                new_status = current_status.split("...")[0] + "." * ((dots % 3) + 1)
                self.status_var.set(new_status)
            else:
                self.status_var.set(current_status + ".")
            
            self.root.after(500, self._monitor_scan_progress)
    
    def _update_device_list(self, devices: List[Dict[str, Any]]):
        """更新设备列表"""
        for item in self.device_list.get_children():
            self.device_list.delete(item)
        
        for device in devices:
            self.device_list.insert('', 'end', values=(
                device['name'],
                device['address'],
                device['type'],
                device['bluetooth_version'],
                device['class'],
                str(device['rssi']) if device['rssi'] != '未知' else '未知',
                "已配对" if device['paired'] else "未配对"
            ))
    
    def _show_device_details(self, event):
        """显示选定设备的详细信息"""
        selected = self.device_list.selection()
        if not selected:
            return
            
        item = self.device_list.item(selected[0])
        addr = item['values'][1]
        
        device = next((d for d in self.current_devices if d['address'] == addr), None)
        if not device:
            return
            
        self.detail_text.config(state=NORMAL)
        self.detail_text.delete(1.0, 'end')
        
        details = [
            f"名称: {device['name']}",
            f"地址: {device['address']}",
            f"类型: {device['type']}",
            f"蓝牙版本: {device['bluetooth_version']}",
            f"设备类: {device['class']} (代码: {device['class_code']})",
            f"信号强度(RSSI): {device['rssi']}",
            f"配对状态: {'已配对' if device['paired'] else '未配对'}",
            f"制造商: {device['manufacturer']}",
            f"发现时间: {device['discovery_time']}",
            "",
            "服务:"
        ]
        
        if device['services']:
            details.extend([f"  - {s}" for s in device['services']])
        else:
            details.append("  无已知服务")
        
        # 添加广告数据详情
        if device.get('adv_data'):
            details.append("\n广告数据:")
            for key, value in device['adv_data'].items():
                if value:
                    details.append(f"  {key}: {value}")
        
        self.detail_text.insert('end', '\n'.join(details))
        self.detail_text.config(state=DISABLED)
    
    def _export_report(self):
        """导出扫描报告"""
        if not self.current_devices:
            messagebox.showwarning("警告", "没有可导出的设备数据")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON 文件", "*.json"),
                ("CSV 文件", "*.csv"),
                ("文本文件", "*.txt"),
                ("所有文件", "*.*")
            ],
            title="保存扫描报告"
        )
        
        if not file_path:
            return
            
        try:
            ext = os.path.splitext(file_path)[1].lower()
            
            if ext == '.json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.current_devices, f, indent=2, ensure_ascii=False)
            elif ext == '.csv':
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        '名称', '地址', '类型', '蓝牙版本', '设备类', '设备类代码',
                        '信号强度', '配对状态', '制造商', '发现时间', '服务'
                    ])
                    for device in self.current_devices:
                        writer.writerow([
                            device['name'],
                            device['address'],
                            device['type'],
                            device['bluetooth_version'],
                            device['class'],
                            device['class_code'],
                            device['rssi'],
                            '已配对' if device['paired'] else '未配对',
                            device['manufacturer'],
                            device['discovery_time'],
                            '; '.join(device['services'])
                        ])
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for device in self.current_devices:
                        f.write(f"名称: {device['name']}\n")
                        f.write(f"地址: {device['address']}\n")
                        f.write(f"类型: {device['type']}\n")
                        f.write(f"蓝牙版本: {device['bluetooth_version']}\n")
                        f.write(f"设备类: {device['class']} (代码: {device['class_code']})\n")
                        f.write(f"信号强度(RSSI): {device['rssi']}\n")
                        f.write(f"配对状态: {'已配对' if device['paired'] else '未配对'}\n")
                        f.write(f"制造商: {device['manufacturer']}\n")
                        f.write(f"发现时间: {device['discovery_time']}\n")
                        f.write("服务:\n")
                        for service in device['services']:
                            f.write(f"  - {service}\n")
                        
                        if device.get('adv_data'):
                            f.write("\n广告数据:\n")
                            for key, value in device['adv_data'].items():
                                if value:
                                    f.write(f"  {key}: {value}\n")
                        
                        f.write("\n" + "="*50 + "\n\n")
            
            messagebox.showinfo("成功", f"报告已成功导出到:\n{file_path}")
            self.status_var.set(f"报告已导出: {os.path.basename(file_path)}")
            
        except Exception as e:
            logger.error(f"导出报告失败: {str(e)}")
            messagebox.showerror("错误", f"导出报告失败: {str(e)}")
            self.status_var.set("导出报告失败")

def main():
    """主函数"""
    try:
        root = Tk()
        app = BluetoothScannerApp(root)
        
        # 设置窗口图标
        try:
            if sys.platform == 'win32':
                root.iconbitmap(default='bluetooth.ico')
            else:
                img = PhotoImage(file='bluetooth.png')
                root.tk.call('wm', 'iconphoto', root._w, img)
        except:
            pass
            
        root.mainloop()
        
    except Exception as e:
        logger.critical(f"应用程序崩溃: {str(e)}")
        logger.critical(traceback.format_exc())
        messagebox.showerror(
            "致命错误", 
            f"应用程序遇到致命错误:\n{str(e)}\n\n详细信息请查看日志文件。"
        )

if __name__ == "__main__":
    main()