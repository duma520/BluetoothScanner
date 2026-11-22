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
import queue
import socket
import struct
import uuid
import zlib
from datetime import datetime
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple, Any, Union, Callable
from tkinter import (
    Tk, Frame, Label, Button, Text, Scrollbar, Listbox, 
    StringVar, Entry, messagebox, filedialog, ttk, DISABLED, NORMAL, 
    PhotoImage, Menu, BooleanVar, IntVar, DoubleVar, Radiobutton, 
    Scale, Spinbox, LabelFrame, PanedWindow, Toplevel, simpledialog
)
from tkinter.ttk import Progressbar, Notebook, Separator

# 尝试导入PIL，如果失败则使用替代方案
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logging.warning("PIL模块未安装，图标功能将不可用")

# ==================== 配置和常量 ====================
APP_NAME = "终极蓝牙扫描分析工具"
APP_VERSION = "2.0.0"
DEFAULT_TIMEOUT = 10
MAX_SCAN_TIME = 300  # 5分钟
CACHE_EXPIRY = 300  # 5分钟
LOG_FILE = "bluetooth_scanner.log"
CONFIG_FILE = "config.json"
ICON_FILE = "bluetooth_icon.png"
DB_FILE = "bluetooth_devices.db"

# 蓝牙版本特征
BT_VERSION_FEATURES = {
    '4.0': {'le_adv': True, 'le_scan': True},
    '4.1': {'le_adv': True, 'le_scan': True, 'le_conn': True},
    '4.2': {'le_adv': True, 'le_scan': True, 'le_conn': True, 'le_sec_conn': True},
    '5.0': {'le_2m_phy': True, 'le_coded_phy': True, 'le_ext_adv': True},
    '5.1': {'le_angle_of_arrival': True, 'le_angle_of_departure': True},
    '5.2': {'le_iso': True, 'le_power_control': True},
    '5.3': {'le_audio': True, 'le_qos': True},
    '5.4': {'le_periodic_adv_sync_transfer': True, 'le_cis': True}
}

# ==================== 日志配置 ====================
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',    # 青色
        'INFO': '\033[32m',     # 绿色
        'WARNING': '\033[33m',  # 黄色
        'ERROR': '\033[31m',    # 红色
        'CRITICAL': '\033[31m'  # 红色
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        message = super().format(record)
        return f"{color}{message}{self.RESET}" if color else message

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # 文件处理器
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

# ==================== 数据模型 ====================
class DeviceType(Enum):
    CLASSIC = auto()
    BLE = auto()
    DUAL = auto()

@dataclass
class BluetoothDevice:
    address: str
    name: str
    device_type: DeviceType
    device_class: Optional[int] = None
    rssi: Optional[int] = None
    paired: bool = False
    services: List[str] = None
    manufacturer: str = "未知"
    first_seen: datetime = None
    last_seen: datetime = None
    bluetooth_version: str = "未知"
    adv_data: Dict = None
    tx_power: Optional[int] = None
    connection_status: bool = False
    security_level: str = "未知"
    supported_features: List[str] = None
    battery_level: Optional[int] = None
    vendor_id: Optional[int] = None
    product_id: Optional[int] = None
    
    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()
        if self.adv_data is None:
            self.adv_data = {}
        if self.supported_features is None:
            self.supported_features = []

    def update_last_seen(self):
        self.last_seen = datetime.now()

    def get_device_class_str(self) -> str:
        if self.device_class is None:
            return "未知"
        return decode_device_class(self.device_class)

    def get_bluetooth_version_details(self) -> Dict:
        return BT_VERSION_FEATURES.get(self.bluetooth_version, {})

# ==================== 工具函数 ====================
def decode_device_class(device_class: int) -> str:
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

def get_manufacturer_name(manufacturer_id: int) -> str:
    """根据制造商ID获取制造商名称"""
    manufacturers = {
        0x0001: "Ericsson Technology Licensing",
        0x0002: "Nokia Mobile Phones",
        0x0003: "Intel Corp.",
        0x004C: "Apple",
        0x0059: "Nordic Semiconductor",
        0x0075: "Samsung",
        0x00E0: "Google",
        0x015D: "Realtek"
    }
    return manufacturers.get(manufacturer_id, f"未知 (ID: {manufacturer_id:04X})")

# ==================== 蓝牙扫描器基类 ====================
class BluetoothScannerBase:
    """蓝牙扫描器基类"""
    
    def __init__(self):
        self.scanning = False
        self.scan_thread = None
        self.timeout = DEFAULT_TIMEOUT
        self.lock = threading.Lock()
        self.cached_devices = []
        self.last_scan_time = 0
        self.cache_expiry = CACHE_EXPIRY
        self.callbacks = {
            'device_found': [],
            'scan_started': [],
            'scan_completed': [],
            'error_occurred': []
        }
        self.scan_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
    
    def register_callback(self, event: str, callback: Callable):
        """注册事件回调"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def notify_callbacks(self, event: str, *args, **kwargs):
        """通知所有注册的回调"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logging.error(f"回调执行失败: {str(e)}")
    
    def is_bluetooth_available(self) -> bool:
        """检查系统蓝牙是否可用"""
        raise NotImplementedError
        
    def scan_devices(self, timeout: int = DEFAULT_TIMEOUT) -> List[BluetoothDevice]:
        """扫描附近的蓝牙设备"""
        raise NotImplementedError
        
    def stop_scan(self):
        """停止扫描"""
        self.stop_event.set()
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)
        self.scanning = False
    
    def get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        """获取设备详细信息"""
        raise NotImplementedError
    
    def connect_device(self, address: str) -> bool:
        """连接到设备"""
        raise NotImplementedError
    
    def disconnect_device(self, address: str) -> bool:
        """断开设备连接"""
        raise NotImplementedError
    
    def get_services(self, address: str) -> List[Dict]:
        """获取设备服务"""
        raise NotImplementedError
    
    def get_characteristics(self, address: str, service_uuid: str) -> List[Dict]:
        """获取服务特征"""
        raise NotImplementedError
    
    def read_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str) -> bytes:
        """读取特征值"""
        raise NotImplementedError
    
    def write_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str, value: bytes) -> bool:
        """写入特征值"""
        raise NotImplementedError
    
    def start_notifications(self, address: str, service_uuid: str, characteristic_uuid: str, callback: Callable) -> bool:
        """启动通知"""
        raise NotImplementedError
    
    def stop_notifications(self, address: str, service_uuid: str, characteristic_uuid: str) -> bool:
        """停止通知"""
        raise NotImplementedError

# ==================== PyBluez扫描器实现 ====================
class PyBluezScanner(BluetoothScannerBase):
    """使用PyBluez的蓝牙扫描器实现（经典蓝牙）"""
    
    def __init__(self):
        super().__init__()
        try:
            import bluetooth
            self.bluetooth = bluetooth
            self.available = True
        except ImportError:
            self.available = False
            logging.warning("PyBluez模块未安装")
        self.connected_devices = {}
    
    def is_bluetooth_available(self) -> bool:
        if not self.available:
            return False
        try:
            # 尝试发现设备来检查蓝牙是否可用
            devices = self.bluetooth.discover_devices(duration=2, lookup_names=False, flush_cache=True)
            return True
        except Exception as e:
            logging.error(f"PyBluez蓝牙检查失败: {str(e)}")
            return False
    
    def scan_devices(self, timeout: int = DEFAULT_TIMEOUT) -> List[BluetoothDevice]:
        if not self.available:
            raise RuntimeError("PyBluez不可用")
        
        if not self.is_bluetooth_available():
            logging.warning("PyBluez蓝牙不可用，跳过")
            return []
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logging.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        self.stop_event.clear()
        devices = []
        
        try:
            self.notify_callbacks('scan_started')
            logging.info(f"开始经典蓝牙扫描, 超时时间: {timeout}秒")
            
            # 扫描经典蓝牙设备
            classic_devices = self.bluetooth.discover_devices(
                duration=timeout, 
                flush_cache=True, 
                lookup_names=True, 
                lookup_class=True
            )
            
            for addr, name, device_class in classic_devices:
                if self.stop_event.is_set():
                    break
                
                try:
                    device = BluetoothDevice(
                        address=addr,
                        name=name or '未知',
                        device_type=DeviceType.CLASSIC,
                        device_class=device_class,
                        first_seen=datetime.now(),
                        last_seen=datetime.now()
                    )
                    device = self.get_device_details(device)
                    devices.append(device)
                    self.notify_callbacks('device_found', device)
                except Exception as e:
                    logging.error(f"获取设备 {addr} 详细信息失败: {str(e)}")
                    self.notify_callbacks('error_occurred', str(e))
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logging.error(f"扫描过程中发生错误: {str(e)}")
            self.notify_callbacks('error_occurred', str(e))
        finally:
            self.scanning = False
            self.notify_callbacks('scan_completed', devices)
            
        return devices
    
    def get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        try:
            # 获取RSSI
            try:
                device.rssi = self.bluetooth.read_rssi(device.address)
            except:
                device.rssi = None
            
            # 检查配对状态
            device.paired = self._check_paired_status(device.address)
            
            # 获取服务
            device.services = self._get_device_services(device.address)
            
            # 获取制造商信息
            device.manufacturer = self._get_manufacturer_info(device.address)
            
            # 估计蓝牙版本
            device.bluetooth_version = self._estimate_bluetooth_version(device)
            
            return device
        except Exception as e:
            logging.error(f"获取设备详情失败: {str(e)}")
            return device
    
    def _check_paired_status(self, addr: str) -> bool:
        try:
            return addr in [d[0] for d in self.bluetooth.discover_devices(lookup_names=False)]
        except:
            return False
    
    def _get_device_services(self, addr: str) -> List[str]:
        try:
            services = self.bluetooth.find_service(address=addr)
            return [s.get('name', '未知服务') for s in services]
        except:
            return []
    
    def _get_manufacturer_info(self, addr: str) -> str:
        try:
            return "未知"
        except:
            return "未知"
    
    def _estimate_bluetooth_version(self, device: BluetoothDevice) -> str:
        return "2.1+EDR"
    
    def connect_device(self, address: str) -> bool:
        try:
            return True
        except:
            return False
    
    def disconnect_device(self, address: str) -> bool:
        try:
            return True
        except:
            return False
    
    def get_services(self, address: str) -> List[Dict]:
        return []
    
    def get_characteristics(self, address: str, service_uuid: str) -> List[Dict]:
        return []
    
    def read_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str) -> bytes:
        return b''
    
    def write_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str, value: bytes) -> bool:
        return False
    
    def start_notifications(self, address: str, service_uuid: str, characteristic_uuid: str, callback: Callable) -> bool:
        return False
    
    def stop_notifications(self, address: str, service_uuid: str, characteristic_uuid: str) -> bool:
        return False

# ==================== Bleak扫描器实现 ====================
class BleakScannerWrapper(BluetoothScannerBase):
    """使用Bleak的蓝牙扫描器实现（BLE蓝牙4.0-5.4）"""
    
    def __init__(self):
        super().__init__()
        try:
            from bleak import BleakScanner, BleakClient
            self.BleakScanner = BleakScanner
            self.BleakClient = BleakClient
            self.available = True
        except ImportError:
            self.available = False
            logging.warning("Bleak模块未安装")
        self.loop = None
        self.loop_thread = None
        if self.available:
            self._setup_event_loop()
        self.connected_devices = {}
    
    def _setup_event_loop(self):
        """为Bleak设置事件循环"""
        if not self.loop and self.available:
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
        if not self.available:
            return False
        try:
            from bleak import __version__
            return True
        except ImportError:
            return False
    
    def scan_devices(self, timeout: int = DEFAULT_TIMEOUT) -> List[BluetoothDevice]:
        if not self.available:
            raise RuntimeError("Bleak不可用，无法扫描BLE设备")
        
        if not self.is_bluetooth_available():
            logging.warning("Bleak不可用，跳过")
            return []
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logging.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        self.stop_event.clear()
        devices = []
        
        try:
            self.notify_callbacks('scan_started')
            logging.info(f"开始BLE蓝牙扫描, 超时时间: {timeout}秒")
            
            # 在事件循环中运行扫描
            future = asyncio.run_coroutine_threadsafe(
                self._async_scan_devices(timeout),
                self.loop
            )
            
            try:
                devices = future.result(timeout + 5)
            except asyncio.TimeoutError:
                logging.warning("BLE扫描超时")
                future.cancel()
            except Exception as e:
                logging.error(f"BLE扫描失败: {str(e)}")
                self.notify_callbacks('error_occurred', str(e))
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logging.error(f"BLE扫描过程中发生错误: {str(e)}")
            self.notify_callbacks('error_occurred', str(e))
        finally:
            self.scanning = False
            self.notify_callbacks('scan_completed', devices)
            
        return devices
    
    async def _async_scan_devices(self, timeout: int) -> List[BluetoothDevice]:
        """异步扫描BLE设备"""
        devices = []
        seen_devices = set()
        
        def detection_callback(device, advertisement_data):
            """发现设备的回调函数"""
            if self.stop_event.is_set():
                return
                
            if device.address in seen_devices:
                return
                
            seen_devices.add(device.address)
            
            try:
                ble_device = BluetoothDevice(
                    address=device.address,
                    name=device.name or '未知',
                    device_type=DeviceType.BLE,
                    rssi=advertisement_data.rssi,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    adv_data={
                        'local_name': advertisement_data.local_name,
                        'manufacturer_data': dict(advertisement_data.manufacturer_data) if advertisement_data.manufacturer_data else {},
                        'service_data': dict(advertisement_data.service_data) if advertisement_data.service_data else {},
                        'service_uuids': advertisement_data.service_uuids,
                        'tx_power': advertisement_data.tx_power,
                        'platform_data': advertisement_data.platform_data
                    },
                    services=advertisement_data.service_uuids,
                    tx_power=advertisement_data.tx_power
                )
                
                # 估计蓝牙版本
                ble_device.bluetooth_version = self._estimate_bluetooth_version(ble_device)
                
                # 获取制造商信息
                ble_device.manufacturer = self._get_ble_manufacturer(ble_device.adv_data)
                
                devices.append(ble_device)
                self.notify_callbacks('device_found', ble_device)
            except Exception as e:
                logging.error(f"处理设备 {device.address} 失败: {str(e)}")
                self.notify_callbacks('error_occurred', str(e))
        
        scanner = self.BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        
        start_time = time.time()
        while time.time() - start_time < timeout and not self.stop_event.is_set():
            await asyncio.sleep(0.1)
        
        await scanner.stop()
        return devices
    
    def get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        """获取BLE设备详细信息"""
        if device.device_type != DeviceType.BLE:
            return device
            
        try:
            # 在事件循环中运行
            future = asyncio.run_coroutine_threadsafe(
                self._async_get_device_details(device),
                self.loop
            )
            return future.result(10)  # 10秒超时
        except Exception as e:
            logging.error(f"获取设备详情失败: {str(e)}")
            return device
    
    async def _async_get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        """异步获取设备详情"""
        try:
            async with self.BleakClient(device.address, timeout=5) as client:
                # 获取所有服务
                services = await client.get_services()
                device.services = [str(s.uuid) for s in services]
                
                # 检查连接状态
                device.connection_status = client.is_connected
                
                # 尝试获取电池电量（如果支持）
                try:
                    battery_service = next((s for s in services if s.uuid == '0000180f-0000-1000-8000-00805f9b34fb'), None)
                    if battery_service:
                        battery_char = next((c for c in battery_service.characteristics if c.uuid == '00002a19-0000-1000-8000-00805f9b34fb'), None)
                        if battery_char:
                            battery_level = await client.read_gatt_char(battery_char.uuid)
                            device.battery_level = int.from_bytes(battery_level, byteorder='little')
                except Exception:
                    pass
                
                return device
        except Exception as e:
            logging.error(f"连接设备 {device.address} 失败: {str(e)}")
            return device
    
    def _estimate_bluetooth_version(self, device: BluetoothDevice) -> str:
        """根据广告数据估计蓝牙版本"""
        try:
            manufacturer_data = device.adv_data.get('manufacturer_data', {})
            if not manufacturer_data:
                return '4.x'
            
            # 检查蓝牙5.x特征
            for data in manufacturer_data.values():
                if isinstance(data, bytes) and len(data) >= 3:
                    if data[0] == 0x02 and data[1] == 0x0A:
                        # 检查蓝牙5.1+特征
                        if len(data) >= 4 and (data[3] & 0x02):
                            return '5.1+'
                        return '5.0'
            
            # 检查蓝牙4.2特征
            service_uuids = device.adv_data.get('service_uuids', [])
            if any('fe2c' in str(uuid).lower() for uuid in service_uuids):
                return '4.2'
            
            return '4.x'
        except:
            return '未知'
    
    def _get_ble_manufacturer(self, adv_data: Dict) -> str:
        """从广告数据获取BLE设备制造商"""
        if not adv_data or not adv_data.get('manufacturer_data'):
            return '未知'
        
        try:
            # 第一个制造商ID
            manufacturer_id = next(iter(adv_data['manufacturer_data'].keys()))
            if isinstance(manufacturer_id, int):
                return get_manufacturer_name(manufacturer_id)
            return '未知'
        except:
            return '未知'
    
    def connect_device(self, address: str) -> bool:
        try:
            return True
        except:
            return False
    
    def disconnect_device(self, address: str) -> bool:
        try:
            return True
        except:
            return False
    
    def get_services(self, address: str) -> List[Dict]:
        return []
    
    def get_characteristics(self, address: str, service_uuid: str) -> List[Dict]:
        return []
    
    def read_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str) -> bytes:
        return b''
    
    def write_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str, value: bytes) -> bool:
        return False
    
    def start_notifications(self, address: str, service_uuid: str, characteristic_uuid: str, callback: Callable) -> bool:
        return False
    
    def stop_notifications(self, address: str, service_uuid: str, characteristic_uuid: str) -> bool:
        return False

# ==================== Windows蓝牙扫描器实现（使用socket和Windows API） ====================
class WindowsBluetoothScanner(BluetoothScannerBase):
    """Windows系统下的蓝牙扫描器 - 使用Windows Socket API"""
    
    def __init__(self):
        super().__init__()
        self.sock = None
        self._init_socket()
    
    def _init_socket(self):
        """初始化蓝牙socket"""
        try:
            # AF_BTH是Windows蓝牙地址族
            if hasattr(socket, 'AF_BTH'):
                self.sock = socket.socket(socket.AF_BTH, socket.SOCK_STREAM, socket.BTHPROTO_RFCOMM)
            else:
                self.sock = None
        except Exception as e:
            logging.error(f"初始化蓝牙socket失败: {str(e)}")
            self.sock = None
    
    def is_bluetooth_available(self) -> bool:
        """检查Windows蓝牙是否可用"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # 使用Windows API检查蓝牙适配器
            setupapi = ctypes.windll.setupapi
            setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
            setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
            
            # 蓝牙设备类GUID: {e0cbf06c-cd8b-4647-bb8a-263b43f0f974}
            bluetooth_guid = ctypes.create_unicode_buffer("{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}")
            
            # 获取设备信息集
            device_info_set = setupapi.SetupDiGetClassDevsW(
                ctypes.cast(bluetooth_guid, ctypes.c_void_p),
                None,
                None,
                0x00000012  # DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
            )
            
            if device_info_set == -1:
                return False
            
            # 检查是否有蓝牙设备
            return device_info_set is not None and device_info_set != -1
            
        except Exception as e:
            logging.error(f"Windows蓝牙检查失败: {str(e)}")
            return self._check_via_powershell()
    
    def _check_via_powershell(self) -> bool:
        """通过PowerShell检查蓝牙可用性"""
        try:
            # 使用更短的超时时间
            result = subprocess.run(
                ['powershell', '-Command', 'Get-PnpDevice -Class Bluetooth -Status OK'],
                capture_output=True, text=True, timeout=3,
                encoding='utf-8', errors='ignore'
            )
            return 'Bluetooth' in result.stdout and result.returncode == 0
        except:
            return False
    
    def scan_devices(self, timeout: int = DEFAULT_TIMEOUT) -> List[BluetoothDevice]:
        """扫描蓝牙设备"""
        if not self.is_bluetooth_available():
            logging.warning("Windows蓝牙不可用")
            return []
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logging.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        self.stop_event.clear()
        devices = []
        
        try:
            self.notify_callbacks('scan_started')
            logging.info(f"开始Windows蓝牙扫描, 超时时间: {timeout}秒")
            
            # 使用PowerShell获取蓝牙设备
            ps_script = '''
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            Function Await($WinRtTask, $ResultType) {
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType).Invoke($null, @($WinRtTask))
                $asTask.Wait(-1) | Out-Null
                return $asTask.Result
            }
            [Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType = WindowsRuntime] | Out-Null
            $devices = Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync([Windows.Devices.Enumeration.DeviceClass]::Bluetooth)) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Enumeration.DeviceInformation]])
            foreach ($device in $devices) {
                Write-Output "$($device.Name)|$($device.Id)"
            }
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True, text=True, timeout=timeout + 3,
                encoding='utf-8', errors='ignore'
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if self.stop_event.is_set():
                        break
                    
                    if '|' in line:
                        parts = line.split('|', 1)
                        name = parts[0].strip()
                        device_id = parts[1].strip() if len(parts) > 1 else ''
                        
                        # 提取地址
                        address = self._extract_address(device_id)
                        if address:
                            device = BluetoothDevice(
                                address=address,
                                name=name if name else '未知设备',
                                device_type=DeviceType.CLASSIC,
                                first_seen=datetime.now(),
                                last_seen=datetime.now()
                            )
                            devices.append(device)
                            self.notify_callbacks('device_found', device)
            
            # 如果没有找到设备，尝试使用netsh命令
            if not devices:
                devices = self._scan_with_netsh()
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logging.error(f"Windows扫描过程中发生错误: {str(e)}")
            self.notify_callbacks('error_occurred', str(e))
        finally:
            self.scanning = False
            self.notify_callbacks('scan_completed', devices)
            
        return devices
    
    def _scan_with_netsh(self) -> List[BluetoothDevice]:
        """使用netsh命令扫描蓝牙设备"""
        devices = []
        try:
            # 使用netsh命令列出蓝牙设备
            result = subprocess.run(
                ['netsh', 'bth', 'show', 'devices'],
                capture_output=True, text=True, timeout=10,
                encoding='gbk', errors='ignore'
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if self.stop_event.is_set():
                    break
                
                # 解析netsh输出，格式类似: "设备名称   地址"
                line = line.strip()
                if line and not line.startswith('---'):
                    parts = line.split()
                    if len(parts) >= 2:
                        # 尝试识别MAC地址格式
                        addr_part = None
                        name_parts = []
                        for part in parts:
                            if self._is_mac_address(part):
                                addr_part = part
                            else:
                                name_parts.append(part)
                        
                        if addr_part:
                            name = ' '.join(name_parts) if name_parts else '未知设备'
                            device = BluetoothDevice(
                                address=addr_part,
                                name=name,
                                device_type=DeviceType.CLASSIC,
                                first_seen=datetime.now(),
                                last_seen=datetime.now()
                            )
                            devices.append(device)
                            self.notify_callbacks('device_found', device)
        except Exception as e:
            logging.error(f"netsh扫描错误: {str(e)}")
        
        return devices
    
    def _extract_address(self, device_id: str) -> str:
        """从设备ID中提取蓝牙地址"""
        import re
        # 查找MAC地址模式
        mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        match = re.search(mac_pattern, device_id)
        if match:
            return match.group(0).upper()
        return ''
    
    def _is_mac_address(self, text: str) -> bool:
        """检查字符串是否为MAC地址"""
        import re
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, text))
    
    def get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        return device
    
    def connect_device(self, address: str) -> bool:
        return False
    
    def disconnect_device(self, address: str) -> bool:
        return False
    
    def get_services(self, address: str) -> List[Dict]:
        return []
    
    def get_characteristics(self, address: str, service_uuid: str) -> List[Dict]:
        return []
    
    def read_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str) -> bytes:
        return b''
    
    def write_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str, value: bytes) -> bool:
        return False
    
    def start_notifications(self, address: str, service_uuid: str, characteristic_uuid: str, callback: Callable) -> bool:
        return False
    
    def stop_notifications(self, address: str, service_uuid: str, characteristic_uuid: str) -> bool:
        return False

# ==================== 系统命令扫描器实现 ====================
class SystemCommandScanner(BluetoothScannerBase):
    """使用系统命令的蓝牙扫描器替代实现"""
    
    def is_bluetooth_available(self) -> bool:
        try:
            if platform.system() == 'Windows':
                # 使用netsh命令检查蓝牙状态（更快）
                result = subprocess.run(
                    ['netsh', 'bth', 'show', 'radio'],
                    capture_output=True, text=True, timeout=3,
                    encoding='gbk', errors='ignore'
                )
                return '无线电状态: 已启用' in result.stdout or 'Radio status: Enabled' in result.stdout
            elif platform.system() == 'Linux':
                result = subprocess.run(
                    ['hciconfig'],
                    capture_output=True, text=True, timeout=5,
                    encoding='utf-8', errors='ignore'
                )
                return result.returncode == 0 and 'UP' in result.stdout
            elif platform.system() == 'Darwin':
                result = subprocess.run(
                    ['system_profiler', 'SPBluetoothDataType'],
                    capture_output=True, text=True, timeout=5,
                    encoding='utf-8', errors='ignore'
                )
                return 'Bluetooth:' in result.stdout
            else:
                return False
        except Exception as e:
            logging.error(f"检查蓝牙可用性失败: {str(e)}")
            return False
    
    def scan_devices(self, timeout: int = DEFAULT_TIMEOUT) -> List[BluetoothDevice]:
        if not self.is_bluetooth_available():
            logging.warning("系统命令扫描器：蓝牙不可用")
            return []
        
        current_time = time.time()
        if current_time - self.last_scan_time < self.cache_expiry and self.cached_devices:
            logging.info("使用缓存中的扫描结果")
            return self.cached_devices.copy()
        
        self.scanning = True
        self.stop_event.clear()
        devices = []
        
        try:
            self.notify_callbacks('scan_started')
            logging.info(f"开始系统命令蓝牙扫描, 超时时间: {timeout}秒")
            
            if platform.system() == 'Windows':
                devices = self._scan_windows_netsh()
            elif platform.system() == 'Linux':
                devices = self._scan_linux(timeout)
            elif platform.system() == 'Darwin':
                devices = self._scan_macos(timeout)
            else:
                logging.warning(f"不支持的操作系统: {platform.system()}")
            
            with self.lock:
                self.cached_devices = devices
                self.last_scan_time = current_time
                
        except Exception as e:
            logging.error(f"扫描过程中发生错误: {str(e)}")
            self.notify_callbacks('error_occurred', str(e))
        finally:
            self.scanning = False
            self.notify_callbacks('scan_completed', devices)
            
        return devices
    
    def _scan_windows_netsh(self) -> List[BluetoothDevice]:
        """使用netsh命令扫描Windows蓝牙设备"""
        devices = []
        
        try:
            # 使用netsh命令列出蓝牙设备
            result = subprocess.run(
                ['netsh', 'bth', 'show', 'devices'],
                capture_output=True, text=True, timeout=10,
                encoding='gbk', errors='ignore'
            )
            
            if result.returncode != 0:
                logging.warning(f"netsh扫描失败: {result.stderr}")
                return devices
            
            lines = result.stdout.split('\n')
            for line in lines:
                if self.stop_event.is_set():
                    break
                
                line = line.strip()
                if not line or line.startswith('---') or '蓝牙' not in line:
                    continue
                
                # 解析netsh输出
                # 格式示例: "设备名称   XX:XX:XX:XX:XX:XX"
                parts = line.split()
                if len(parts) >= 2:
                    # 查找MAC地址
                    addr = None
                    name_parts = []
                    for part in parts:
                        if self._is_mac_address(part):
                            addr = part
                        else:
                            name_parts.append(part)
                    
                    if addr:
                        name = ' '.join(name_parts) if name_parts else '未知设备'
                        device = BluetoothDevice(
                            address=addr,
                            name=name,
                            device_type=DeviceType.CLASSIC,
                            first_seen=datetime.now(),
                            last_seen=datetime.now()
                        )
                        devices.append(device)
                        self.notify_callbacks('device_found', device)
            
        except subprocess.TimeoutExpired:
            logging.warning("netsh扫描超时")
        except Exception as e:
            logging.error(f"Windows netsh扫描错误: {str(e)}")
        
        return devices
    
    def _is_mac_address(self, text: str) -> bool:
        """检查字符串是否为MAC地址"""
        import re
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, text))
    
    def _scan_linux(self, timeout: int) -> List[BluetoothDevice]:
        """Linux系统下的蓝牙扫描"""
        devices = []
        
        try:
            # 尝试启动扫描
            subprocess.run(
                ['bluetoothctl', 'scan', 'on'],
                capture_output=True, text=True, timeout=5
            )
            
            start_time = time.time()
            while time.time() - start_time < timeout and not self.stop_event.is_set():
                time.sleep(0.1)
            
            # 获取设备列表
            result = subprocess.run(
                ['bluetoothctl', 'devices'],
                capture_output=True, text=True, timeout=5,
                encoding='utf-8', errors='ignore'
            )
            
            if result.returncode != 0:
                logging.warning(f"扫描失败: {result.stderr}")
                return devices
            
            for line in result.stdout.split('\n'):
                if self.stop_event.is_set():
                    break
                    
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    name = ' '.join(parts[2:]) if len(parts) > 2 else '未知'
                    device = BluetoothDevice(
                        address=addr,
                        name=name,
                        device_type=DeviceType.CLASSIC,
                        first_seen=datetime.now(),
                        last_seen=datetime.now()
                    )
                    devices.append(device)
                    self.notify_callbacks('device_found', device)
            
            # 关闭扫描
            subprocess.run(
                ['bluetoothctl', 'scan', 'off'],
                capture_output=True, text=True, timeout=5
            )
            
        except subprocess.TimeoutExpired:
            logging.warning("蓝牙扫描超时")
            self.notify_callbacks('error_occurred', "扫描超时")
        except Exception as e:
            logging.error(f"Linux扫描错误: {str(e)}")
            self.notify_callbacks('error_occurred', str(e))
        
        return devices
    
    def _scan_macos(self, timeout: int) -> List[BluetoothDevice]:
        """macOS系统下的蓝牙扫描"""
        devices = []
        
        try:
            result = subprocess.run(
                ['system_profiler', 'SPBluetoothDataType'],
                capture_output=True, text=True, timeout=timeout + 5,
                encoding='utf-8', errors='ignore'
            )
            
            if result.returncode != 0:
                logging.warning(f"扫描失败: {result.stderr}")
                return devices
            
            current_section = None
            current_device = {}
            
            for line in result.stdout.split('\n'):
                if self.stop_event.is_set():
                    break
                    
                line = line.strip()
                
                if 'Devices:' in line:
                    current_section = 'devices'
                elif current_section == 'devices' and line.startswith('Name:'):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_device['name'] = parts[1].strip()
                elif current_section == 'devices' and line.startswith('Address:'):
                    parts = line.split(':', 1)
                    if len(parts) > 1 and 'name' in current_device:
                        current_device['address'] = parts[1].strip()
                        device = BluetoothDevice(
                            address=current_device['address'],
                            name=current_device['name'],
                            device_type=DeviceType.CLASSIC,
                            first_seen=datetime.now(),
                            last_seen=datetime.now()
                        )
                        devices.append(device)
                        self.notify_callbacks('device_found', device)
                        current_device = {}
            
        except subprocess.TimeoutExpired:
            logging.warning("蓝牙扫描超时")
            self.notify_callbacks('error_occurred', "扫描超时")
        except Exception as e:
            logging.error(f"macOS扫描错误: {str(e)}")
            self.notify_callbacks('error_occurred', str(e))
        
        return devices
    
    def get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        return device
    
    def connect_device(self, address: str) -> bool:
        return False
    
    def disconnect_device(self, address: str) -> bool:
        return False
    
    def get_services(self, address: str) -> List[Dict]:
        return []
    
    def get_characteristics(self, address: str, service_uuid: str) -> List[Dict]:
        return []
    
    def read_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str) -> bytes:
        return b''
    
    def write_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str, value: bytes) -> bool:
        return False
    
    def start_notifications(self, address: str, service_uuid: str, characteristic_uuid: str, callback: Callable) -> bool:
        return False
    
    def stop_notifications(self, address: str, service_uuid: str, characteristic_uuid: str) -> bool:
        return False

# ==================== 蓝牙管理器 ====================
class BluetoothManager:
    """管理多个蓝牙扫描器并提供统一接口"""
    
    def __init__(self):
        self.scanners = []
        self.devices = []
        self.device_map = {}
        self.lock = threading.Lock()
        self.scan_in_progress = False
        self.scan_thread = None
        self.stop_event = threading.Event()
        
        # 添加回调功能
        self.callbacks = {
            'device_found': [],
            'scan_started': [],
            'scan_completed': [],
            'error_occurred': []
        }
        
        # 初始化所有可用的扫描器
        if self._check_pybluez_available():
            self.scanners.append(PyBluezScanner())
            logging.info("PyBluez扫描器已启用")
        
        if self._check_bleak_available():
            self.scanners.append(BleakScannerWrapper())
            logging.info("Bleak扫描器已启用")
        
        # 添加Windows专用扫描器
        if platform.system() == 'Windows':
            self.scanners.append(WindowsBluetoothScanner())
            logging.info("Windows蓝牙扫描器已启用")
        
        # 总是添加系统命令扫描器作为备选
        self.scanners.append(SystemCommandScanner())
        logging.info("系统命令扫描器已启用")
    
    def register_callback(self, event: str, callback: Callable):
        """注册事件回调"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def notify_callbacks(self, event: str, *args, **kwargs):
        """通知所有注册的回调"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logging.error(f"回调执行失败: {str(e)}")
    
    def _check_pybluez_available(self) -> bool:
        try:
            import bluetooth
            return True
        except ImportError:
            return False
    
    def _check_bleak_available(self) -> bool:
        try:
            from bleak import __version__
            return True
        except ImportError:
            return False
    
    def _handle_device_found(self, device: BluetoothDevice):
        """处理新发现的设备"""
        with self.lock:
            existing_device = self.device_map.get(device.address)
            if existing_device:
                # 更新现有设备信息
                existing_device.last_seen = datetime.now()
                if device.name != '未知' and existing_device.name == '未知':
                    existing_device.name = device.name
                if device.rssi is not None:
                    existing_device.rssi = device.rssi
                # 合并服务
                if device.services:
                    for service in device.services:
                        if service not in existing_device.services:
                            existing_device.services.append(service)
            else:
                # 添加新设备
                self.devices.append(device)
                self.device_map[device.address] = device

        # 通知设备发现
        self.notify_callbacks('device_found', device)
    
    def _handle_scan_completed(self, devices: List[BluetoothDevice]):
        """处理扫描完成事件"""
        pass
    
    def _handle_error(self, error: str):
        """处理错误事件"""
        logging.error(f"扫描器错误: {error}")
        self.notify_callbacks('error_occurred', error)
    
    def scan_devices(self, timeout: int = DEFAULT_TIMEOUT) -> List[BluetoothDevice]:
        """扫描所有类型的蓝牙设备"""
        if self.scan_in_progress:
            logging.warning("扫描已在进行中")
            return self.devices.copy()
        
        self.scan_in_progress = True
        self.stop_event.clear()
        self.devices = []
        self.device_map = {}
        
        # 通知扫描开始
        self.notify_callbacks('scan_started')
        
        # 为每个扫描器注册回调
        for scanner in self.scanners:
            scanner.register_callback('device_found', self._handle_device_found)
            scanner.register_callback('scan_completed', self._handle_scan_completed)
            scanner.register_callback('error_occurred', self._handle_error)

        def _scan():
            """在后台线程中执行扫描"""
            try:
                # 并行启动所有扫描器
                threads = []
                for scanner in self.scanners:
                    thread = threading.Thread(
                        target=scanner.scan_devices,
                        args=(timeout,),
                        daemon=True
                    )
                    thread.start()
                    threads.append(thread)
                
                # 等待所有扫描器完成或超时
                start_time = time.time()
                while time.time() - start_time < timeout + 5 and not self.stop_event.is_set():
                    # 检查是否所有线程都完成了
                    all_done = True
                    for thread in threads:
                        if thread.is_alive():
                            all_done = False
                            break
                    if all_done:
                        break
                    time.sleep(0.5)
                
                # 如果超时或停止事件被触发，停止所有扫描器
                if self.stop_event.is_set() or time.time() - start_time >= timeout + 5:
                    for scanner in self.scanners:
                        scanner.stop_scan()
                    
                    for thread in threads:
                        thread.join(timeout=1)
                
            except Exception as e:
                logging.error(f"扫描过程中发生错误: {str(e)}")
                self.notify_callbacks('error_occurred', str(e))
            finally:
                self.scan_in_progress = False
                # 通知扫描完成
                self.notify_callbacks('scan_completed', self.devices.copy())
        
        self.scan_thread = threading.Thread(target=_scan, daemon=True)
        self.scan_thread.start()
        
        return self.devices.copy()
    
    def stop_scan(self):
        """停止所有扫描"""
        self.stop_event.set()
        for scanner in self.scanners:
            scanner.stop_scan()
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)
        
        self.scan_in_progress = False
    
    def get_devices(self) -> List[BluetoothDevice]:
        """获取当前发现的设备列表"""
        with self.lock:
            return self.devices.copy()
    
    def get_device(self, address: str) -> Optional[BluetoothDevice]:
        """根据地址获取特定设备"""
        with self.lock:
            return self.device_map.get(address)
    
    def connect_device(self, address: str) -> bool:
        """连接到指定设备"""
        device = self.get_device(address)
        if not device:
            return False
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.CLASSIC and isinstance(scanner, PyBluezScanner)) or \
               (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.connect_device(address)
        
        return False
    
    def disconnect_device(self, address: str) -> bool:
        """断开指定设备"""
        device = self.get_device(address)
        if not device:
            return False
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.CLASSIC and isinstance(scanner, PyBluezScanner)) or \
               (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.disconnect_device(address)
        
        return False
    
    def get_device_details(self, device: BluetoothDevice) -> BluetoothDevice:
        """获取设备详细信息"""
        for scanner in self.scanners:
            if (device.device_type == DeviceType.CLASSIC and isinstance(scanner, PyBluezScanner)) or \
               (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.get_device_details(device)
        return device
    
    def get_services(self, address: str) -> List[Dict]:
        """获取设备服务"""
        device = self.get_device(address)
        if not device:
            return []
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.CLASSIC and isinstance(scanner, PyBluezScanner)) or \
               (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.get_services(address)
        
        return []
    
    def get_characteristics(self, address: str, service_uuid: str) -> List[Dict]:
        """获取服务特征"""
        device = self.get_device(address)
        if not device:
            return []
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.get_characteristics(address, service_uuid)
        
        return []
    
    def read_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str) -> bytes:
        """读取特征值"""
        device = self.get_device(address)
        if not device:
            return b''
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.read_characteristic(address, service_uuid, characteristic_uuid)
        
        return b''
    
    def write_characteristic(self, address: str, service_uuid: str, characteristic_uuid: str, value: bytes) -> bool:
        """写入特征值"""
        device = self.get_device(address)
        if not device:
            return False
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.write_characteristic(address, service_uuid, characteristic_uuid, value)
        
        return False
    
    def start_notifications(self, address: str, service_uuid: str, characteristic_uuid: str, callback: Callable) -> bool:
        """启动通知"""
        device = self.get_device(address)
        if not device:
            return False
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.start_notifications(address, service_uuid, characteristic_uuid, callback)
        
        return False
    
    def stop_notifications(self, address: str, service_uuid: str, characteristic_uuid: str) -> bool:
        """停止通知"""
        device = self.get_device(address)
        if not device:
            return False
            
        for scanner in self.scanners:
            if (device.device_type == DeviceType.BLE and isinstance(scanner, BleakScannerWrapper)):
                return scanner.stop_notifications(address, service_uuid, characteristic_uuid)
        
        return False

# ==================== GUI界面 ====================
class BluetoothScannerApp:
    """蓝牙扫描器GUI应用"""
    
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # 初始化蓝牙管理器
        self.manager = BluetoothManager()
        
        # 设备数据
        self.devices = []
        self.selected_device = None
        self.connected_devices = []
        self.notification_callbacks = {}
        
        # 扫描状态
        self.scan_in_progress = False
        self.scan_start_time = 0
        
        # 创建UI
        self._setup_ui()
        
        # 加载配置
        self.config = self._load_config()
        
        # 设置窗口图标
        self._set_window_icon()
        
        # 初始化设备数据库
        self._init_device_db()
        
        # 注册蓝牙管理器回调
        self.manager.register_callback('device_found', self._on_device_found)
        self.manager.register_callback('scan_completed', self._on_scan_completed)
        self.manager.register_callback('error_occurred', self._on_error)
    
    def _setup_ui(self):
        """设置用户界面"""
        # 主框架
        self.main_frame = Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 顶部控制面板
        self._setup_control_panel()
        
        # 主内容区域
        self.content_paned = PanedWindow(self.main_frame, orient='horizontal', sashwidth=5)
        self.content_paned.pack(fill='both', expand=True)
        
        # 设备列表区域
        self._setup_device_list()
        
        # 设备详情区域
        self._setup_device_details()
        
        # 状态栏
        self._setup_status_bar()
        
        # 菜单
        self._setup_menus()
    
    def _setup_control_panel(self):
        """设置控制面板"""
        control_frame = LabelFrame(self.main_frame, text="控制面板", padx=5, pady=5)
        control_frame.pack(fill='x', padx=5, pady=(0, 5))
        
        # 扫描按钮
        self.scan_button = Button(
            control_frame, 
            text="开始扫描", 
            command=self._toggle_scan,
            width=12
        )
        self.scan_button.grid(row=0, column=0, padx=(0, 10))
        
        # 停止扫描按钮
        self.stop_button = Button(
            control_frame,
            text="停止扫描",
            command=self._stop_scan,
            width=12,
            state=DISABLED
        )
        self.stop_button.grid(row=0, column=1, padx=(0, 10))
        
        # 超时设置
        Label(control_frame, text="扫描超时(秒):").grid(row=0, column=2, padx=(10, 5))
        self.timeout_var = IntVar(value=DEFAULT_TIMEOUT)
        self.timeout_spin = Spinbox(
            control_frame, 
            from_=1, 
            to=MAX_SCAN_TIME,
            textvariable=self.timeout_var,
            width=5
        )
        self.timeout_spin.grid(row=0, column=3, padx=(0, 10))
        
        # 扫描类型选择
        self.scan_type_var = StringVar(value="all")
        scan_type_frame = Frame(control_frame)
        scan_type_frame.grid(row=0, column=4, padx=(10, 0))
        Label(scan_type_frame, text="扫描类型:").pack(side='left')
        
        Radiobutton(
            scan_type_frame, 
            text="全部", 
            variable=self.scan_type_var, 
            value="all"
        ).pack(side='left')
        
        if any(isinstance(s, PyBluezScanner) for s in self.manager.scanners):
            Radiobutton(
                scan_type_frame, 
                text="经典蓝牙", 
                variable=self.scan_type_var, 
                value="classic"
            ).pack(side='left', padx=(5, 0))
        
        if any(isinstance(s, BleakScannerWrapper) for s in self.manager.scanners):
            Radiobutton(
                scan_type_frame, 
                text="BLE", 
                variable=self.scan_type_var, 
                value="ble"
            ).pack(side='left', padx=(5, 0))
        
        # 导出按钮
        self.export_button = Button(
            control_frame, 
            text="导出报告", 
            command=self._export_report,
            width=12
        )
        self.export_button.grid(row=0, column=5, padx=(10, 0))
        
        # 连接/断开按钮
        self.connect_button = Button(
            control_frame,
            text="连接设备",
            command=self._toggle_connection,
            width=12,
            state=DISABLED
        )
        self.connect_button.grid(row=0, column=6, padx=(10, 0))
        
        # 进度条
        self.progress_var = DoubleVar(value=0.0)
        self.progress_bar = Progressbar(
            control_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.grid(row=1, column=0, columnspan=7, sticky='ew', pady=(5, 0))
    
    def _setup_device_list(self):
        """设置设备列表区域"""
        device_list_frame = Frame(self.content_paned)
        self.content_paned.add(device_list_frame, width=400)
        
        # 搜索框
        search_frame = Frame(device_list_frame)
        search_frame.pack(fill='x', pady=(0, 5))
        
        Label(search_frame, text="搜索:").pack(side='left')
        self.search_var = StringVar()
        self.search_entry = Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(5, 0))
        self.search_var.trace_add('write', self._filter_devices)
        
        # 设备列表
        columns = ["名称", "地址", "类型", "蓝牙版本", "信号", "状态"]
        self.device_tree = ttk.Treeview(
            device_list_frame,
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        # 设置列
        self.device_tree.column("名称", width=150, anchor='w')
        self.device_tree.column("地址", width=120, anchor='center')
        self.device_tree.column("类型", width=80, anchor='center')
        self.device_tree.column("蓝牙版本", width=80, anchor='center')
        self.device_tree.column("信号", width=60, anchor='center')
        self.device_tree.column("状态", width=80, anchor='center')
        
        # 设置标题
        for col in columns:
            self.device_tree.heading(col, text=col)
        
        # 滚动条
        scrollbar = Scrollbar(device_list_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        self.device_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # 绑定选择事件
        self.device_tree.bind('<<TreeviewSelect>>', self._on_device_selected)
    
    def _setup_device_details(self):
        """设置设备详情区域"""
        details_frame = Frame(self.content_paned)
        self.content_paned.add(details_frame)
        
        # 详情选项卡
        self.details_notebook = Notebook(details_frame)
        self.details_notebook.pack(fill='both', expand=True)
        
        # 基本信息标签页
        self._setup_basic_info_tab()
        
        # 服务标签页
        self._setup_services_tab()
        
        # 特征标签页
        self._setup_characteristics_tab()
        
        # 广告数据标签页
        self._setup_advertisement_tab()
        
        # 高级功能标签页
        self._setup_advanced_tab()
    
    def _setup_basic_info_tab(self):
        """设置基本信息标签页"""
        basic_frame = Frame(self.details_notebook)
        self.details_notebook.add(basic_frame, text="基本信息")
        
        # 基本信息表格
        self.basic_info_tree = ttk.Treeview(
            basic_frame,
            columns=("属性", "值"),
            show='tree',
            height=10
        )
        
        self.basic_info_tree.column("#0", width=0, stretch=False)
        self.basic_info_tree.column("属性", width=150, anchor='e')
        self.basic_info_tree.column("值", width=250, anchor='w')
        
        self.basic_info_tree.heading("属性", text="属性")
        self.basic_info_tree.heading("值", text="值")
        
        # 滚动条
        scrollbar = Scrollbar(basic_frame, orient="vertical", command=self.basic_info_tree.yview)
        self.basic_info_tree.configure(yscrollcommand=scrollbar.set)
        
        self.basic_info_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def _setup_services_tab(self):
        """设置服务标签页"""
        services_frame = Frame(self.details_notebook)
        self.details_notebook.add(services_frame, text="服务")
        
        # 服务列表
        self.services_tree = ttk.Treeview(
            services_frame,
            columns=("UUID", "名称", "类型"),
            show='headings',
            height=10
        )
        
        self.services_tree.column("UUID", width=300, anchor='w')
        self.services_tree.column("名称", width=150, anchor='w')
        self.services_tree.column("类型", width=100, anchor='center')
        
        self.services_tree.heading("UUID", text="UUID")
        self.services_tree.heading("名称", text="名称")
        self.services_tree.heading("类型", text="类型")
        
        # 滚动条
        scrollbar = Scrollbar(services_frame, orient="vertical", command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=scrollbar.set)
        
        self.services_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # 绑定选择事件
        self.services_tree.bind('<<TreeviewSelect>>', self._on_service_selected)
    
    def _setup_characteristics_tab(self):
        """设置特征标签页"""
        chars_frame = Frame(self.details_notebook)
        self.details_notebook.add(chars_frame, text="特征")
        
        # 特征列表
        self.chars_tree = ttk.Treeview(
            chars_frame,
            columns=("UUID", "名称", "属性", "值"),
            show='headings',
            height=10
        )
        
        self.chars_tree.column("UUID", width=250, anchor='w')
        self.chars_tree.column("名称", width=150, anchor='w')
        self.chars_tree.column("属性", width=100, anchor='center')
        self.chars_tree.column("值", width=200, anchor='w')
        
        self.chars_tree.heading("UUID", text="UUID")
        self.chars_tree.heading("名称", text="名称")
        self.chars_tree.heading("属性", text="属性")
        self.chars_tree.heading("值", text="值")
        
        # 滚动条
        scrollbar = Scrollbar(chars_frame, orient="vertical", command=self.chars_tree.yview)
        self.chars_tree.configure(yscrollcommand=scrollbar.set)
        
        self.chars_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # 特征操作按钮
        button_frame = Frame(chars_frame)
        button_frame.pack(fill='x', pady=(5, 0))
        
        self.read_char_button = Button(
            button_frame,
            text="读取",
            command=self._read_characteristic,
            state=DISABLED
        )
        self.read_char_button.pack(side='left', padx=(0, 5))
        
        self.write_char_button = Button(
            button_frame,
            text="写入",
            command=self._write_characteristic,
            state=DISABLED
        )
        self.write_char_button.pack(side='left', padx=(0, 5))
        
        self.notify_char_button = Button(
            button_frame,
            text="通知",
            command=self._toggle_notifications,
            state=DISABLED
        )
        self.notify_char_button.pack(side='left')
    
    def _setup_advertisement_tab(self):
        """设置广告数据标签页"""
        adv_frame = Frame(self.details_notebook)
        self.details_notebook.add(adv_frame, text="广告数据")
        
        # 广告数据文本
        self.adv_text = Text(
            adv_frame,
            wrap='word',
            state=DISABLED
        )
        
        scrollbar = Scrollbar(adv_frame, command=self.adv_text.yview)
        self.adv_text.configure(yscrollcommand=scrollbar.set)
        
        self.adv_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def _setup_advanced_tab(self):
        """设置高级功能标签页"""
        advanced_frame = Frame(self.details_notebook)
        self.details_notebook.add(advanced_frame, text="高级")
        
        # 添加高级功能组件...
        Label(advanced_frame, text="高级功能正在开发中...").pack(pady=50)
    
    def _setup_status_bar(self):
        """设置状态栏"""
        self.status_var = StringVar()
        self.status_var.set("就绪")
        
        self.status_bar = Label(
            self.main_frame,
            textvariable=self.status_var,
            relief='sunken',
            anchor='w',
            padx=10
        )
        self.status_bar.pack(side='bottom', fill='x')
    
    def _setup_menus(self):
        """设置菜单"""
        menubar = Menu(self.root)
        
        # 文件菜单
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="导出报告...", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        menubar.add_cascade(label="文件", menu=file_menu)
        
        # 扫描菜单
        scan_menu = Menu(menubar, tearoff=0)
        scan_menu.add_command(label="开始扫描", command=self._start_scan)
        scan_menu.add_command(label="停止扫描", command=self._stop_scan)
        menubar.add_cascade(label="扫描", menu=scan_menu)
        
        # 设备菜单
        device_menu = Menu(menubar, tearoff=0)
        device_menu.add_command(label="连接设备", command=self._connect_device)
        device_menu.add_command(label="断开设备", command=self._disconnect_device)
        device_menu.add_separator()
        device_menu.add_command(label="刷新设备信息", command=self._refresh_device)
        menubar.add_cascade(label="设备", menu=device_menu)
        
        # 工具菜单
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="选项...", command=self._show_options)
        menubar.add_cascade(label="工具", menu=tools_menu)
        
        # 帮助菜单
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于...", command=self._show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _set_window_icon(self):
        """设置窗口图标"""
        if not PIL_AVAILABLE:
            return
        try:
            if os.path.exists(ICON_FILE):
                img = Image.open(ICON_FILE)
                photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, photo)
        except Exception as e:
            logging.warning(f"无法设置窗口图标: {str(e)}")
    
    def _load_config(self) -> Dict:
        """加载配置文件"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"加载配置失败: {str(e)}")
        return {}
    
    def _save_config(self):
        """保存配置文件"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logging.error(f"保存配置失败: {str(e)}")
    
    def _init_device_db(self):
        """初始化设备数据库"""
        pass
    
    def _update_device_db(self, device: BluetoothDevice):
        """更新设备数据库"""
        pass
    
    def _start_scan(self):
        """开始扫描"""
        if self.scan_in_progress:
            return
            
        timeout = self.timeout_var.get()
        if timeout < 1 or timeout > MAX_SCAN_TIME:
            messagebox.showerror("错误", f"超时时间必须在1-{MAX_SCAN_TIME}秒之间")
            return
        
        # 清空设备列表
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # 重置设备列表
        self.devices = []
        
        # 重置进度条
        self.progress_var.set(0)
        
        # 开始扫描
        self.scan_in_progress = True
        self.scan_start_time = time.time()
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.status_var.set("扫描中...")
        
        # 在后台线程中执行扫描
        threading.Thread(
            target=self._perform_scan,
            args=(timeout,),
            daemon=True
        ).start()
        
        # 启动进度更新
        self._update_scan_progress()
    
    def _perform_scan(self, timeout: int):
        """执行扫描操作"""
        try:
            self.manager.scan_devices(timeout)
        except Exception as e:
            logging.error(f"扫描失败: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("扫描错误", str(e)))
        finally:
            self.root.after(0, self._scan_completed)
    
    def _update_scan_progress(self):
        """更新扫描进度"""
        if not self.scan_in_progress:
            return
            
        elapsed = time.time() - self.scan_start_time
        timeout = self.timeout_var.get()
        progress = min(100, (elapsed / timeout) * 100)
        self.progress_var.set(progress)
        
        if progress >= 100:
            self._scan_completed()
        else:
            self.root.after(200, self._update_scan_progress)
    
    def _stop_scan(self):
        """停止扫描"""
        self.manager.stop_scan()
        self._scan_completed()
    
    def _scan_completed(self):
        """扫描完成处理"""
        self.scan_in_progress = False
        self.scan_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        self.progress_var.set(100)
        self.status_var.set(f"扫描完成，找到 {len(self.devices)} 个设备")
    
    def _toggle_scan(self):
        """切换扫描状态"""
        if self.scan_in_progress:
            self._stop_scan()
        else:
            self._start_scan()
    
    def _on_device_found(self, device: BluetoothDevice):
        """处理新发现的设备"""
        self.root.after(0, self._add_device_to_tree, device)
    
    def _add_device_to_tree(self, device: BluetoothDevice):
        """添加设备到树视图"""
        # 检查设备是否已存在
        existing_item = None
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item, 'values')
            if len(values) > 1 and values[1] == device.address:
                existing_item = item
                break
        
        # 准备显示值
        values = (
            device.name,
            device.address,
            "经典" if device.device_type == DeviceType.CLASSIC else "BLE",
            device.bluetooth_version,
            str(device.rssi) if device.rssi is not None else "未知",
            "已连接" if device.connection_status else "未连接"
        )
        
        if existing_item:
            # 更新现有项目
            self.device_tree.item(existing_item, values=values)
        else:
            # 添加新项目
            self.device_tree.insert('', 'end', values=values)
            self.devices.append(device)
    
    def _on_scan_completed(self, devices: List[BluetoothDevice]):
        """处理扫描完成事件"""
        self.devices = devices
        self.root.after(0, lambda: self.status_var.set(f"扫描完成，找到 {len(devices)} 个设备"))
    
    def _on_error(self, error: str):
        """处理错误事件"""
        self.root.after(0, lambda: self.status_var.set(f"错误: {error}"))
        logging.error(error)
    
    def _on_device_selected(self, event):
        """处理设备选择事件"""
        selected = self.device_tree.selection()
        if not selected:
            self.selected_device = None
            self.connect_button.config(state=DISABLED)
            return
            
        item = self.device_tree.item(selected[0])
        values = item['values']
        if len(values) > 1:
            addr = values[1]
            
            # 在设备列表中查找设备
            self.selected_device = next((d for d in self.devices if d.address == addr), None)
            
            if self.selected_device:
                self._show_device_details(self.selected_device)
                self.connect_button.config(state=NORMAL)
                self.connect_button.config(
                    text="断开连接" if self.selected_device.connection_status else "连接设备"
                )
    
    def _show_device_details(self, device: BluetoothDevice):
        """显示设备详细信息"""
        # 更新基本信息标签页
        self._update_basic_info(device)
        
        # 更新服务标签页
        self._update_services_info(device)
        
        # 更新广告数据标签页
        self._update_advertisement_info(device)
    
    def _update_basic_info(self, device: BluetoothDevice):
        """更新基本信息标签页"""
        for item in self.basic_info_tree.get_children():
            self.basic_info_tree.delete(item)
        
        info = [
            ("名称", device.name),
            ("地址", device.address),
            ("类型", "经典蓝牙" if device.device_type == DeviceType.CLASSIC else "BLE"),
            ("蓝牙版本", device.bluetooth_version),
            ("设备类", device.get_device_class_str()),
            ("信号强度", f"{device.rssi} dBm" if device.rssi is not None else "未知"),
            ("制造商", device.manufacturer),
            ("配对状态", "已配对" if device.paired else "未配对"),
            ("连接状态", "已连接" if device.connection_status else "未连接"),
            ("首次发现", device.first_seen.strftime('%Y-%m-%d %H:%M:%S')),
            ("最后发现", device.last_seen.strftime('%Y-%m-%d %H:%M:%S')),
            ("TX功率", f"{device.tx_power} dBm" if device.tx_power is not None else "未知"),
            ("电池电量", f"{device.battery_level}%" if device.battery_level is not None else "未知")
        ]
        
        for i, (key, value) in enumerate(info):
            self.basic_info_tree.insert('', 'end', iid=f"item_{i}", values=(key, value))
    
    def _update_services_info(self, device: BluetoothDevice):
        """更新服务标签页"""
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)
        
        if not device.services:
            return
            
        for i, service_uuid in enumerate(device.services):
            service_name = self._get_service_name(service_uuid)
            self.services_tree.insert('', 'end', values=(service_uuid, service_name, "主服务"))
    
    def _update_advertisement_info(self, device: BluetoothDevice):
        """更新广告数据标签页"""
        self.adv_text.config(state=NORMAL)
        self.adv_text.delete(1.0, 'end')
        
        if not device.adv_data:
            self.adv_text.insert('end', "无广告数据")
            self.adv_text.config(state=DISABLED)
            return
            
        self.adv_text.insert('end', "广告数据:\n\n")
        
        for key, value in device.adv_data.items():
            if not value:
                continue
                
            self.adv_text.insert('end', f"{key}:\n")
            
            if isinstance(value, dict):
                for k, v in value.items():
                    self.adv_text.insert('end', f"  {k}: {v}\n")
            elif isinstance(value, list):
                for item in value:
                    self.adv_text.insert('end', f"  {item}\n")
            else:
                self.adv_text.insert('end', f"  {value}\n")
            
            self.adv_text.insert('end', "\n")
        
        self.adv_text.config(state=DISABLED)
    
    def _get_service_name(self, uuid_str: str) -> str:
        """获取服务名称"""
        try:
            uuid_obj = uuid.UUID(uuid_str)
            common_services = {
                '00001800-0000-1000-8000-00805f9b34fb': "通用访问",
                '00001801-0000-1000-8000-00805f9b34fb': "通用属性",
                '0000180a-0000-1000-8000-00805f9b34fb': "设备信息",
                '0000180f-0000-1000-8000-00805f9b34fb': "电池服务",
            }
            return common_services.get(str(uuid_obj).lower(), "未知服务")
        except:
            return "无效UUID"
    
    def _on_service_selected(self, event):
        """处理服务选择事件"""
        selected = self.services_tree.selection()
        if not selected or not self.selected_device:
            return
            
        item = self.services_tree.item(selected[0])
        values = item['values']
        if len(values) > 0:
            service_uuid = values[0]
            
            # 获取服务特征
            characteristics = self.manager.get_characteristics(self.selected_device.address, service_uuid)
            self._update_characteristics_info(characteristics)
            
            # 启用特征操作按钮
            self.read_char_button.config(state=NORMAL if characteristics else DISABLED)
            self.write_char_button.config(state=NORMAL if characteristics else DISABLED)
            self.notify_char_button.config(state=NORMAL if characteristics else DISABLED)
    
    def _update_characteristics_info(self, characteristics: List[Dict]):
        """更新特征标签页"""
        for item in self.chars_tree.get_children():
            self.chars_tree.delete(item)
        
        if not characteristics:
            return
            
        for char in characteristics:
            char_name = self._get_characteristic_name(char.get('uuid', ''))
            properties = self._decode_properties(char.get('properties', 0))
            self.chars_tree.insert('', 'end', values=(
                char.get('uuid', ''),
                char_name,
                properties,
                char.get('value', '')
            ))
    
    def _get_characteristic_name(self, uuid_str: str) -> str:
        """获取特征名称"""
        try:
            uuid_obj = uuid.UUID(uuid_str)
            common_chars = {
                '00002a00-0000-1000-8000-00805f9b34fb': "设备名称",
                '00002a01-0000-1000-8000-00805f9b34fb': "外观",
                '00002a19-0000-1000-8000-00805f9b34fb': "电池电量",
                '00002a24-0000-1000-8000-00805f9b34fb': "型号字符串",
            }
            return common_chars.get(str(uuid_obj).lower(), "未知特征")
        except:
            return "无效UUID"
    
    def _decode_properties(self, properties: int) -> str:
        """解码特征属性"""
        props = []
        if properties & 0x01:
            props.append("广播")
        if properties & 0x02:
            props.append("读")
        if properties & 0x04:
            props.append("无认证读")
        if properties & 0x08:
            props.append("写")
        if properties & 0x10:
            props.append("无认证写")
        if properties & 0x20:
            props.append("通知")
        if properties & 0x40:
            props.append("指示")
        if properties & 0x80:
            props.append("认证写")
        return ", ".join(props) if props else "未知"
    
    def _read_characteristic(self):
        """读取特征值"""
        if not self.selected_device:
            return
            
        selected = self.chars_tree.selection()
        if not selected:
            return
            
        item = self.chars_tree.item(selected[0])
        values = item['values']
        if len(values) < 1:
            return
            
        char_uuid = values[0]
        service_selected = self.services_tree.selection()
        if not service_selected:
            return
            
        service_item = self.services_tree.item(service_selected[0])
        service_values = service_item['values']
        if len(service_values) < 1:
            return
            
        service_uuid = service_values[0]
        
        try:
            value = self.manager.read_characteristic(
                self.selected_device.address,
                service_uuid,
                char_uuid
            )
            
            # 更新特征值显示
            new_values = list(values)
            if len(new_values) > 3:
                new_values[3] = value.hex()
            self.chars_tree.item(selected[0], values=tuple(new_values))
            
            self.status_var.set(f"成功读取特征 {char_uuid}")
        except Exception as e:
            messagebox.showerror("错误", f"读取特征失败: {str(e)}")
            self.status_var.set(f"读取特征失败: {str(e)}")
    
    def _write_characteristic(self):
        """写入特征值"""
        if not self.selected_device:
            return
            
        selected = self.chars_tree.selection()
        if not selected:
            return
            
        item = self.chars_tree.item(selected[0])
        values = item['values']
        if len(values) < 1:
            return
            
        char_uuid = values[0]
        service_selected = self.services_tree.selection()
        if not service_selected:
            return
            
        service_item = self.services_tree.item(service_selected[0])
        service_values = service_item['values']
        if len(service_values) < 1:
            return
            
        service_uuid = service_values[0]
        
        # 弹出输入对话框
        value = simpledialog.askstring("写入特征值", "请输入要写入的值(十六进制):")
        if not value:
            return
            
        try:
            # 转换十六进制字符串为字节
            data = bytes.fromhex(value)
            
            success = self.manager.write_characteristic(
                self.selected_device.address,
                service_uuid,
                char_uuid,
                data
            )
            
            if success:
                self.status_var.set(f"成功写入特征 {char_uuid}")
                messagebox.showinfo("成功", "特征值写入成功")
            else:
                messagebox.showerror("错误", "特征值写入失败")
                self.status_var.set(f"写入特征 {char_uuid} 失败")
        except Exception as e:
            messagebox.showerror("错误", f"写入特征失败: {str(e)}")
            self.status_var.set(f"写入特征失败: {str(e)}")
    
    def _toggle_notifications(self):
        """切换通知状态"""
        if not self.selected_device:
            return
            
        selected = self.chars_tree.selection()
        if not selected:
            return
            
        item = self.chars_tree.item(selected[0])
        values = item['values']
        if len(values) < 1:
            return
            
        char_uuid = values[0]
        service_selected = self.services_tree.selection()
        if not service_selected:
            return
            
        service_item = self.services_tree.item(service_selected[0])
        service_values = service_item['values']
        if len(service_values) < 1:
            return
            
        service_uuid = service_values[0]
        
        if char_uuid in self.notification_callbacks:
            # 停止通知
            success = self.manager.stop_notifications(
                self.selected_device.address,
                service_uuid,
                char_uuid
            )
            
            if success:
                del self.notification_callbacks[char_uuid]
                self.notify_char_button.config(text="通知")
                self.status_var.set(f"已停止 {char_uuid} 的通知")
            else:
                messagebox.showerror("错误", "停止通知失败")
                self.status_var.set(f"停止 {char_uuid} 通知失败")
        else:
            # 启动通知
            def notification_callback(sender: str, data: bytearray):
                """通知回调函数"""
                self.root.after(0, lambda: self._handle_notification(char_uuid, data))
            
            success = self.manager.start_notifications(
                self.selected_device.address,
                service_uuid,
                char_uuid,
                notification_callback
            )
            
            if success:
                self.notification_callbacks[char_uuid] = notification_callback
                self.notify_char_button.config(text="停止通知")
                self.status_var.set(f"已启动 {char_uuid} 的通知")
            else:
                messagebox.showerror("错误", "启动通知失败")
                self.status_var.set(f"启动 {char_uuid} 通知失败")
    
    def _handle_notification(self, char_uuid: str, data: bytearray):
        """处理特征通知"""
        # 更新特征值显示
        for item in self.chars_tree.get_children():
            values = self.chars_tree.item(item, 'values')
            if len(values) > 0 and values[0] == char_uuid:
                new_values = list(values)
                if len(new_values) > 3:
                    new_values[3] = data.hex()
                self.chars_tree.item(item, values=tuple(new_values))
                break
        
        # 在状态栏显示通知
        self.status_var.set(f"收到 {char_uuid} 的通知: {data.hex()}")
    
    def _toggle_connection(self):
        """切换设备连接状态"""
        if not self.selected_device:
            return
            
        if self.selected_device.connection_status:
            self._disconnect_device()
        else:
            self._connect_device()
    
    def _connect_device(self):
        """连接设备"""
        if not self.selected_device:
            return
            
        try:
            success = self.manager.connect_device(self.selected_device.address)
            if success:
                self.selected_device.connection_status = True
                self.connect_button.config(text="断开连接")
                self.status_var.set(f"已连接到 {self.selected_device.name}")
                
                # 刷新设备信息
                self._refresh_device()
            else:
                messagebox.showerror("错误", "连接设备失败")
                self.status_var.set(f"连接 {self.selected_device.name} 失败")
        except Exception as e:
            messagebox.showerror("错误", f"连接设备失败: {str(e)}")
            self.status_var.set(f"连接失败: {str(e)}")
    
    def _disconnect_device(self):
        """断开设备连接"""
        if not self.selected_device:
            return
            
        try:
            success = self.manager.disconnect_device(self.selected_device.address)
            if success:
                self.selected_device.connection_status = False
                self.connect_button.config(text="连接设备")
                self.status_var.set(f"已断开 {self.selected_device.name}")
            else:
                messagebox.showerror("错误", "断开设备失败")
                self.status_var.set(f"断开 {self.selected_device.name} 失败")
        except Exception as e:
            messagebox.showerror("错误", f"断开设备失败: {str(e)}")
            self.status_var.set(f"断开失败: {str(e)}")
    
    def _refresh_device(self):
        """刷新设备信息"""
        if not self.selected_device:
            return
            
        try:
            # 获取最新设备信息
            updated_device = self.manager.get_device_details(self.selected_device)
            if updated_device:
                self.selected_device = updated_device
                self._show_device_details(self.selected_device)
                self.status_var.set(f"已刷新 {self.selected_device.name} 的信息")
            else:
                self.status_var.set(f"刷新 {self.selected_device.name} 信息失败")
        except Exception as e:
            messagebox.showerror("错误", f"刷新设备信息失败: {str(e)}")
            self.status_var.set(f"刷新失败: {str(e)}")
    
    def _filter_devices(self, *args):
        """过滤设备列表"""
        search_term = self.search_var.get().lower()
        
        for item in self.device_tree.get_children():
            values = [str(v).lower() for v in self.device_tree.item(item, 'values')]
            if any(search_term in v for v in values):
                self.device_tree.item(item, tags=('match',))
            else:
                self.device_tree.item(item, tags=('no_match',))
        
        # 可选：隐藏不匹配的项目
        self.device_tree.tag_configure('no_match', foreground='gray')
    
    def _export_report(self):
        """导出扫描报告"""
        if not self.devices:
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
                    devices_data = [self._device_to_dict(d) for d in self.devices]
                    json.dump(devices_data, f, indent=2, ensure_ascii=False, default=str)
            elif ext == '.csv':
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # 写入标题行
                    writer.writerow([
                        '名称', '地址', '类型', '蓝牙版本', '设备类', '设备类代码',
                        '信号强度', '配对状态', '制造商', '首次发现', '最后发现', '服务'
                    ])
                    # 写入数据行
                    for device in self.devices:
                        writer.writerow([
                            device.name,
                            device.address,
                            "经典" if device.device_type == DeviceType.CLASSIC else "BLE",
                            device.bluetooth_version,
                            device.get_device_class_str(),
                            device.device_class or '',
                            device.rssi or '',
                            '已配对' if device.paired else '未配对',
                            device.manufacturer,
                            device.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                            device.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                            '; '.join(device.services)
                        ])
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for device in self.devices:
                        f.write(f"名称: {device.name}\n")
                        f.write(f"地址: {device.address}\n")
                        f.write(f"类型: {'经典蓝牙' if device.device_type == DeviceType.CLASSIC else 'BLE'}\n")
                        f.write(f"蓝牙版本: {device.bluetooth_version}\n")
                        f.write(f"设备类: {device.get_device_class_str()}\n")
                        f.write(f"信号强度(RSSI): {device.rssi if device.rssi is not None else '未知'}\n")
                        f.write(f"配对状态: {'已配对' if device.paired else '未配对'}\n")
                        f.write(f"制造商: {device.manufacturer}\n")
                        f.write(f"首次发现: {device.first_seen.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"最后发现: {device.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("服务:\n")
                        for service in device.services:
                            f.write(f"  - {service}\n")
                        
                        if device.adv_data:
                            f.write("\n广告数据:\n")
                            for key, value in device.adv_data.items():
                                if value:
                                    f.write(f"  {key}: {value}\n")
                        
                        f.write("\n" + "="*50 + "\n\n")
            
            messagebox.showinfo("成功", f"报告已成功导出到:\n{file_path}")
            self.status_var.set(f"报告已导出: {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("错误", f"导出报告失败: {str(e)}")
            self.status_var.set("导出报告失败")
    
    def _device_to_dict(self, device: BluetoothDevice) -> Dict:
        """将设备对象转换为字典"""
        return {
            'address': device.address,
            'name': device.name,
            'device_type': str(device.device_type),
            'device_class': device.device_class,
            'rssi': device.rssi,
            'paired': device.paired,
            'services': device.services,
            'manufacturer': device.manufacturer,
            'first_seen': device.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'bluetooth_version': device.bluetooth_version,
            'adv_data': device.adv_data,
            'tx_power': device.tx_power,
            'connection_status': device.connection_status,
            'battery_level': device.battery_level
        }
    
    def _show_options(self):
        """显示选项对话框"""
        options_dialog = Toplevel(self.root)
        options_dialog.title("选项")
        options_dialog.geometry("400x300")
        options_dialog.resizable(False, False)
        
        # 添加选项控件...
        Label(options_dialog, text="选项设置正在开发中...").pack(pady=50)
        
        # 确定按钮
        Button(
            options_dialog,
            text="确定",
            command=options_dialog.destroy
        ).pack(side='bottom', pady=10)
    
    def _show_about(self):
        """显示关于对话框"""
        about_dialog = Toplevel(self.root)
        about_dialog.title(f"关于 {APP_NAME}")
        about_dialog.geometry("400x200")
        about_dialog.resizable(False, False)
        
        # 关于信息
        Label(
            about_dialog,
            text=f"{APP_NAME}\n版本 {APP_VERSION}\n\n蓝牙设备扫描与分析工具",
            font=('Arial', 12),
            pady=20
        ).pack()
        
        Label(
            about_dialog,
            text="© 2023 蓝牙工具开发者",
            font=('Arial', 10)
        ).pack()
        
        # 确定按钮
        Button(
            about_dialog,
            text="确定",
            command=about_dialog.destroy
        ).pack(side='bottom', pady=10)

def main():
    """主函数"""
    # 设置日志
    setup_logging()
    
    try:
        root = Tk()
        app = BluetoothScannerApp(root)
        
        # 检查蓝牙可用性
        bluetooth_available = False
        for scanner in app.manager.scanners:
            try:
                if scanner.is_bluetooth_available():
                    bluetooth_available = True
                    break
            except:
                pass
        
        if not bluetooth_available:
            messagebox.showwarning(
                "警告", 
                "系统蓝牙可能不可用或未启用。请确保蓝牙已打开并重试。\n"
                "注意：某些功能可能需要安装额外的Python模块(PyBluez或bleak)。"
            )
        
        root.mainloop()
        
    except Exception as e:
        logging.critical(f"应用程序崩溃: {str(e)}")
        logging.critical(traceback.format_exc())
        messagebox.showerror(
            "致命错误", 
            f"应用程序遇到致命错误:\n{str(e)}\n\n详细信息请查看日志文件。"
        )

if __name__ == "__main__":
    main()