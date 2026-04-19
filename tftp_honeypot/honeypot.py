#!/usr/bin/env python3
"""
HoneyJar v2 — TFTP Honeypot (UDP/69)
Handles RRQ (read) and WRQ (write) requests.
Common targets: router configs, firmware images, startup-config, boot files.
"""
import base64, json, logging, os, signal, socket, struct, sys, threading, time
from datetime import datetime, timezone

LOG_DIR    = "/tftp-logs"
EVENTS_F   = os.path.join(LOG_DIR, "tftp_events.jsonl")
LOG_F      = os.path.join(LOG_DIR, "tftp_honeypot.log")
UPLOADS_F  = "/uploads-log/uploads.jsonl"
CONFIG_F   = "/config/ports_config.json"
_wlock     = threading.Lock()

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs("/uploads-log", exist_ok=True)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOG_F), logging.StreamHandler()])
log = logging.getLogger("tftp-hp")

# TFTP opcodes
OP_RRQ  = 1
OP_WRQ  = 2
OP_DATA = 3
OP_ACK  = 4
OP_ERR  = 5

# ── Fake files served on RRQ ─────────────────────────────────────────────────

FAKE_TFTP_FILES = {
    "startup-config": (
        b"! Cisco IOS Software, Version 15.7(3)M3\n"
        b"! Last configuration change at 14:23:11 UTC Mon Dec  2 2024\n"
        b"!\nhostname core-rtr-01\n!\n"
        b"enable secret 5 $1$mERr$FakeEnableSecretHashHere\n!\n"
        b"username admin privilege 15 secret 5 $1$Abc1$FakeAdminSecretHash\n"
        b"username monitor privilege 5 password 0 M0nit0r@2024\n!\n"
        b"ip domain-name corp.local\nip ssh version 2\n!\n"
        b"interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n!\n"
        b"interface GigabitEthernet0/1\n ip address 192.168.1.1 255.255.255.0\n no shutdown\n!\n"
        b"ip route 0.0.0.0 0.0.0.0 203.0.113.1\n!\n"
        b"snmp-server community public RO\nsnmp-server community Pr1vate! RW\n!\n"
        b"line vty 0 4\n password VtyP@ss2024!\n login local\n transport input ssh\n!\nend\n"
    ),
    "running-config": (
        b"! Running configuration -- fw-edge-01\n! Generated: 2024-12-01T02:00:00Z\n!\n"
        b"hostname fw-edge-01\nenable secret 5 $1$xYz9$FakeEdgeEnableHash\n!\n"
        b"username admin privilege 15 secret 9 $9$FakeType9Hash\n!\n"
        b"ip route 0.0.0.0 0.0.0.0 203.0.113.1\nip route 10.0.0.0 255.0.0.0 10.1.1.1\n!\n"
        b"access-list 100 deny   ip 0.0.0.0 255.255.255.255 host 192.168.1.254\n"
        b"access-list 100 permit ip any any\n!\n"
        b"crypto isakmp key C1sc0@VPN2024! address 0.0.0.0\n!\nend\n"
    ),
    "boot.cfg": (
        b"# Network boot configuration\nBOOT_IMAGE=/images/firmware-v3.2.1.bin\n"
        b"DEFAULT_GATEWAY=192.168.1.1\nIP_ADDRESS=192.168.1.254\nNETMASK=255.255.255.0\n"
        b"ADMIN_USER=admin\nADMIN_PASS=Admin@Boot2024!\nTFTP_SERVER=192.168.1.100\n"
    ),
    "fortigate.conf": (
        b"config system admin\n    edit admin\n"
        b"        set password ENC SH2FakeFortigateHashHere==\n"
        b"        set accprofile super_admin\n    next\nend\n"
        b"config system interface\n    edit wan1\n"
        b"        set ip 203.0.113.2 255.255.255.0\n"
        b"        set allowaccess https ssh\n    next\nend\n"
    ),
    "firmware.bin":  os.urandom(512),
    "firmware.img":  os.urandom(1024),
    "config.txt": (
        b"[network]\nip=192.168.1.254\nmask=255.255.255.0\ngateway=192.168.1.1\ndns=8.8.8.8\n"
        b"[admin]\nuser=admin\npass=Admin@1234!\nenable=true\n"
    ),
    "backup.cfg": (
        b"# Backup configuration -- do not distribute\n"
        b"! credentials: admin / Backup@2024!\n"
        b"! db: dbadmin / DBBackup#99\n"
        b"! api_key: sk-backup-xxxxx\n"
    ),
    "network.cfg": (
        b"HOSTNAME=prod-switch-01\nMGMT_IP=10.0.0.10\nMGMT_MASK=255.255.255.0\n"
        b"MGMT_GW=10.0.0.1\nSNMP_COMMUNITY=Pr1vCommunity!\nADMIN_PASS=Sw1tch@Admin2024\n"
    ),
}

def write_upload(ip, port, filename, payload: bytes):
    """Append a captured file to the shared uploads log (base64-encoded, never executed)."""
    entry = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "protocol":    "TFTP",
        "ip":          ip,
        "port":        port,
        "filename":    filename,
        "size":        len(payload),
        "direction":   "upload",
        "content_b64": base64.b64encode(payload).decode(),
    }
    with _wlock:
        with open(UPLOADS_F, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

def write_event(ip, port, etype, data: dict):
    entry = {
        "ts":       datetime.now(timezone.utc).isoformat(),
        "protocol": "TFTP",
        "ip":       ip,
        "port":     port,
        "type":     etype,
        **data,
    }
    with _wlock:
        with open(EVENTS_F, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

def parse_request(data: bytes):
    """Parse RRQ/WRQ: opcode (2B) + filename\0 + mode\0"""
    try:
        opcode = struct.unpack("!H", data[:2])[0]
        rest   = data[2:]
        parts  = rest.split(b"\x00")
        filename = parts[0].decode("utf-8", "replace") if parts else ""
        mode     = parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""
        return opcode, filename, mode
    except Exception:
        return 0, "", ""

def make_error(code: int, msg: str) -> bytes:
    return struct.pack("!HH", OP_ERR, code) + msg.encode() + b"\x00"

def make_data(block: int, payload: bytes) -> bytes:
    return struct.pack("!HH", OP_DATA, block) + payload

def make_ack(block: int) -> bytes:
    return struct.pack("!HH", OP_ACK, block)

def handle_rrq(sock: socket.socket, addr, filename: str, mode: str):
    """Send fake file data in 512-byte blocks."""
    data = FAKE_TFTP_FILES.get(filename)
    if data is None:
        data = FAKE_TFTP_FILES.get(filename.lower())
    if data is None:
        # Unknown file — send a generic "not found" error
        sock.sendto(make_error(1, "File not found"), addr)
        return 0

    block    = 1
    offset   = 0
    sent     = 0
    attempts = 0
    sock.settimeout(5)
    while offset <= len(data):
        chunk  = data[offset: offset + 512]
        packet = make_data(block, chunk)
        try:
            sock.sendto(packet, addr)
        except Exception:
            break
        # Wait for ACK
        try:
            resp, _ = sock.recvfrom(4)
            op, ack_block = struct.unpack("!HH", resp[:4])
            if op == OP_ACK and ack_block == block:
                sent   += len(chunk)
                offset += 512
                block  += 1
                attempts = 0
            else:
                attempts += 1
                if attempts > 5:
                    break
        except socket.timeout:
            attempts += 1
            if attempts > 5:
                break
        if len(chunk) < 512:
            break
    return sent

def handle_wrq(sock: socket.socket, addr, filename: str, mode: str):
    """Accept incoming file data, log payload."""
    sock.settimeout(5)
    block    = 0
    chunks   = []
    attempts = 0
    # ACK block 0 to start transfer
    sock.sendto(make_ack(0), addr)
    while True:
        try:
            pkt, src = sock.recvfrom(516)
        except socket.timeout:
            attempts += 1
            if attempts > 5:
                break
            continue
        if len(pkt) < 4:
            break
        op, blk = struct.unpack("!HH", pkt[:4])
        if op != OP_DATA:
            break
        payload = pkt[4:]
        chunks.append(payload)
        block = blk
        sock.sendto(make_ack(block), addr)
        if len(payload) < 512:
            break
    data = b"".join(chunks)
    return data

class TFTPHandler(threading.Thread):
    def __init__(self, data, addr, server_addr):
        super().__init__(daemon=True)
        self.pkt         = data
        self.client_addr = addr
        self.server_addr = server_addr

    def run(self):
        ip   = self.client_addr[0]
        port = self.client_addr[1]
        opcode, filename, mode = parse_request(self.pkt)

        # Each transfer gets its own ephemeral UDP socket on a random port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.server_addr, 0))

        # SAFETY: filename and data are only logged and served from the in-memory
        # FAKE_TFTP_FILES dict — never written to disk or executed.
        try:
            if opcode == OP_RRQ:
                log.info(f"  RRQ {ip} -> {filename!r} ({mode})")
                write_event(ip, port, "RRQ", {"filename": filename, "mode": mode})
                sent = handle_rrq(sock, self.client_addr, filename, mode)
                write_event(ip, port, "TRANSFER_COMPLETE", {
                    "filename": filename, "direction": "sent", "bytes": sent
                })

            elif opcode == OP_WRQ:
                log.info(f"  WRQ {ip} -> {filename!r} ({mode})")
                write_event(ip, port, "WRQ", {"filename": filename, "mode": mode})
                data = handle_wrq(sock, self.client_addr, filename, mode)
                write_event(ip, port, "UPLOAD", {
                    "filename":     filename,
                    "mode":         mode,
                    "size":         len(data),
                    "payload_hex":  data[:2048].hex(),
                    "payload_text": data[:2048].decode("utf-8", "replace"),
                })
                # SAFETY: stored as bytes only — never written to disk or executed
                write_upload(ip, port, filename, data)
                log.info(f"  [UPLOAD] {ip} -> {filename!r} ({len(data)} bytes)")

            else:
                sock.sendto(make_error(4, "Illegal TFTP operation"), self.client_addr)

        except Exception as e:
            log.warning(f"  handler error {ip}: {e}")
        finally:
            sock.close()

def load_ports():
    try:
        with open(CONFIG_F) as f:
            cfg = json.load(f)
        p = cfg.get("tftp", [69])
        return [int(x) for x in (p if isinstance(p, list) else [p])]
    except Exception as e:
        log.warning(f"load_ports: {e}")
        return [69]

# ── Dynamic multi-port engine ─────────────────────────────────────────────────

_servers = {}
_pending = set()
_plock   = threading.Lock()

def _recv_loop(srv, port):
    while True:
        try:
            data, addr = srv.recvfrom(516)
            ip = addr[0]
            write_event(ip, addr[1], "CONNECT", {})
            TFTPHandler(data, addr, "0.0.0.0").start()
        except socket.timeout:
            continue
        except OSError:
            break
        except Exception as e:
            log.warning(f"recv :{port}: {e}")
    log.info(f"[-] TFTP :{port} stopped")

def _bind_worker(port):
    for attempt in range(5):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.settimeout(1.0)
            threading.Thread(target=_recv_loop, args=(srv, port), daemon=True).start()
            with _plock:
                _servers[port] = srv
                _pending.discard(port)
            log.info(f"[+] TFTP UDP :{port}")
            write_event("0.0.0.0", port, "START", {})
            return
        except PermissionError:
            log.warning(f"TFTP :{port} permission denied — need root/CAP_NET_BIND_SERVICE")
            break
        except OSError as e:
            log.warning(f"TFTP :{port} attempt {attempt+1}: {e}")
            if attempt < 4:
                time.sleep(2)
    with _plock:
        _pending.discard(port)
    log.error(f"giving up on TFTP :{port}")

def start_server(port):
    with _plock:
        if port in _servers or port in _pending:
            return
        _pending.add(port)
    threading.Thread(target=_bind_worker, args=(port,), daemon=True).start()

def stop_server(port):
    with _plock:
        srv = _servers.pop(port, None)
    if srv:
        try: srv.close()
        except Exception: pass

def sync_ports(ports):
    wanted = set(ports)
    with _plock:
        to_stop  = list(set(_servers) - wanted)
        to_start = [p for p in wanted if p not in _servers and p not in _pending]
    for p in to_stop:
        stop_server(p)
        log.info(f"[~] TFTP :{p} removed")
    for p in to_start:
        start_server(p)

def watcher():
    last, first = [], True
    while True:
        ports = load_ports()
        if ports != last or first:
            sync_ports(ports)
            last, first = ports, False
        time.sleep(5)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    watcher()
