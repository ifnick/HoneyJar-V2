#!/usr/bin/env python3
"""
HoneyJar v2 — FTP Honeypot
Fake FTP server that accepts all logins, presents a tempting filesystem,
logs every credential, command, and file transfer to JSONL.
"""
import base64, json, logging, os, signal, socket, sys, threading, time
from datetime import datetime, timezone

LOG_DIR    = "/ftp-logs"
EVENTS_F   = os.path.join(LOG_DIR, "ftp_events.jsonl")
LOG_F      = os.path.join(LOG_DIR, "ftp_honeypot.log")
UPLOADS_F  = "/uploads-log/uploads.jsonl"
CONFIG_F   = "/config/ports_config.json"
# vsftpd 2.3.4 banner — heavily probed for CVE-2011-2523 backdoor
BANNER     = "220 (vsFTPd 2.3.4)"
_wlock     = threading.Lock()

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs("/uploads-log", exist_ok=True)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOG_F), logging.StreamHandler()])
log = logging.getLogger("ftp-hp")

# ── Fake filesystem ──────────────────────────────────────────────────────────

FAKE_FS = {
    "/":                       ["backup", "www", "home", "etc", "opt", "var", "tmp"],
    "/backup":                 ["db_backup_2024-12-01.sql.gz", "db_backup_2024-11-01.sql.gz",
                                "config_backup.tar.gz", "users_export.csv", "ssl_certs.tar"],
    "/www":                    ["html", "cgi-bin"],
    "/www/html":               ["index.php", "wp-config.php", "wp-config.php.bak",
                                "admin.php", ".htpasswd", ".env", "config.php"],
    "/www/cgi-bin":            ["test.cgi", "printenv.pl", "upload.cgi"],
    "/home":                   ["admin", "deploy", "ftpuser"],
    "/home/admin":             [".ssh", "notes.txt", "credentials.txt", "todo.txt"],
    "/home/admin/.ssh":        ["id_rsa", "id_rsa.pub", "authorized_keys", "known_hosts"],
    "/home/deploy":            ["deploy_key", ".env", "release_notes.txt"],
    "/home/ftpuser":           ["uploads", "public_html"],
    "/home/ftpuser/uploads":   ["report_Q4.xlsx", "client_data.zip"],
    "/etc":                    ["passwd", "shadow", "hosts", "crontab", "vsftpd.conf"],
    "/opt":                    ["app", "scripts"],
    "/opt/app":                ["config.yaml", "secrets.json", ".env.production"],
    "/opt/scripts":            ["backup.sh", "deploy.sh", "rotate_keys.sh"],
    "/var":                    ["log", "backups"],
    "/var/log":                ["auth.log", "vsftpd.log", "syslog", "fail2ban.log"],
    "/var/backups":            ["passwd.bak", "shadow.bak"],
    "/tmp":                    [],
}

FAKE_FILES = {
    "/www/html/wp-config.php": (
        b"<?php\n"
        b"define('DB_NAME',     'wordpress_prod');\n"
        b"define('DB_USER',     'wp_dbuser');\n"
        b"define('DB_PASSWORD', 'Wp@Pr0d#2024!');\n"
        b"define('DB_HOST',     '127.0.0.1');\n"
        b"define('AUTH_KEY',    'k1L#mP9@xQw2rN7tS5vE');\n"
        b"define('WP_DEBUG',    false);\n"
        b"$table_prefix = 'wp_';\n"
    ),
    "/www/html/wp-config.php.bak": (
        b"<?php\n"
        b"define('DB_NAME',     'wordpress');\n"
        b"define('DB_USER',     'root');\n"
        b"define('DB_PASSWORD', 'toor');\n"
        b"define('DB_HOST',     'localhost');\n"
    ),
    "/www/html/.htpasswd": (
        b"admin:$apr1$8R3xY1z2$K7aWpQmNvUjBsHgFdLeIo0\n"
        b"deploy:$apr1$nP4xY7z9$vT2aQpRmKuJcHfGdLsEiB1\n"
        b"backup:$apr1$mK2xZ8a1$wS9bRqNnLtIcGfFdEsHjC0\n"
    ),
    "/www/html/.env": (
        b"APP_ENV=production\n"
        b"APP_KEY=base64:kXz1+8bFhj9yS3mP2Qw7rNdEt4oA5cU0VnYeJiGlBsK=\n"
        b"DB_HOST=127.0.0.1\n"
        b"DB_USER=appuser\n"
        b"DB_PASS=Pr0dAppP@ss!\n"
        b"STRIPE_SECRET=sk_live_51AbcDefGhIjKlMnOpQrSt\n"
        b"SENDGRID_API_KEY=SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGh\n"
    ),
    "/www/html/config.php": (
        b"<?php\n"
        b"$db_host   = '127.0.0.1';\n"
        b"$db_user   = 'dbadmin';\n"
        b"$db_pass   = 'DBAdm1n@Prod';\n"
        b"$db_name   = 'production';\n"
        b"$smtp_pass = 'Sm7p@2024!';\n"
        b"$api_key   = 'sk-prod-abcdef1234567890abcdef';\n"
    ),
    "/home/admin/credentials.txt": (
        b"# !! DO NOT SHARE - Internal credentials\n"
        b"SSH (root):    root / R00t@Pr0d2024!\n"
        b"DB (mysql):    dbadmin / DBAdm1n@Prod\n"
        b"FTP:           ftpuser / Ftp@2024\n"
        b"cPanel:        admin / cP@nel2024!\n"
        b"AWS root:      (see Bitwarden vault 'prod-aws')\n"
        b"Cloudflare:    nick@corp.local / CF@2024!\n"
    ),
    "/home/admin/notes.txt": (
        b"TODO:\n"
        b"  - rotate DB creds before Q1 audit (deadline: Jan 15)\n"
        b"  - check why backup script failed on Nov 30\n"
        b"  - renew SSL cert (expires Feb 2025)\n"
        b"\n"
        b"DB backup runs nightly at 02:00 via cron\n"
        b"Monitoring: Grafana at :3000 (admin/admin123)\n"
        b"CI/CD Jenkins token: 11ab7c3d4e5f6a7b8c9d0e1f2a3b4c5d6e\n"
    ),
    "/home/admin/.ssh/id_rsa": (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"b3BlbnNzaC1rZXktdjEAAAAA\n"
        b"BG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        b"QyNTUxOQAAACBfakeKeyDataHereForHoneypotPurposes\n"
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        b"-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "/home/admin/.ssh/authorized_keys": (
        b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3fakekey... admin@prod-server\n"
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey2... deploy@ci-server\n"
    ),
    "/home/deploy/.env": (
        b"APP_ENV=production\n"
        b"DB_HOST=10.0.0.2\n"
        b"DB_PASS=Pr0dPass!\n"
        b"SECRET_KEY=a8f3b2c1d4e5f6a7b8c9d0e1f2\n"
        b"STRIPE_KEY=sk_live_xxxxxxxxxxxx\n"
        b"GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345\n"
    ),
    "/opt/app/secrets.json": (
        b'{\n'
        b'  "database": {\n'
        b'    "host": "db-prod.internal",\n'
        b'    "user": "appuser",\n'
        b'    "password": "Sup3rS3cr3tDBP@ss"\n'
        b'  },\n'
        b'  "jwt_secret": "ey_super_secret_jwt_signing_key_32chars",\n'
        b'  "aws": {\n'
        b'    "access_key": "AKIAIOSFODNN7EXAMPLE",\n'
        b'    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        b'  }\n'
        b'}\n'
    ),
    "/opt/scripts/backup.sh": (
        b"#!/bin/bash\n"
        b"# Nightly backup script\n"
        b"DB_USER=dbadmin\n"
        b"DB_PASS=DBAdm1n@Prod\n"
        b"DB_NAME=production\n"
        b"mysqldump -u$DB_USER -p$DB_PASS $DB_NAME | gzip > /backup/db_backup_$(date +%F).sql.gz\n"
        b"scp /backup/db_backup_$(date +%F).sql.gz backup@10.0.0.5:/backups/\n"
    ),
    "/etc/passwd": (
        b"root:x:0:0:root:/root:/bin/bash\n"
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        b"admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
        b"deploy:x:1001:1001:Deploy Bot:/home/deploy:/bin/sh\n"
        b"ftpuser:x:1002:1002:FTP User:/home/ftpuser:/sbin/nologin\n"
    ),
    "/etc/shadow": (
        b"root:$6$rounds=5000$Ue4bZhK9$FakeHashForHoneypot:19720:0:99999:7:::\n"
        b"admin:$6$rounds=5000$Kp7mQxN3$FakeHashForHoneypot2:19720:0:99999:7:::\n"
        b"deploy:$6$rounds=5000$Lq8nRyO4$FakeHashForHoneypot3:19720:0:99999:7:::\n"
    ),
    "/etc/vsftpd.conf": (
        b"# vsftpd configuration\n"
        b"anonymous_enable=NO\n"
        b"local_enable=YES\n"
        b"write_enable=YES\n"
        b"local_umask=022\n"
        b"dirmessage_enable=YES\n"
        b"xferlog_enable=YES\n"
        b"connect_from_port_20=YES\n"
        b"xferlog_std_format=YES\n"
        b"listen=YES\n"
        b"pam_service_name=vsftpd\n"
        b"userlist_enable=YES\n"
        b"tcp_wrappers=YES\n"
    ),
    "/var/log/auth.log": (
        b"Dec  1 02:00:01 server sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2\n"
        b"Dec  1 02:00:03 server sshd[1235]: Failed password for admin from 198.51.100.1 port 44312 ssh2\n"
        b"Dec  1 02:00:05 server sshd[1236]: Accepted password for admin from 192.168.1.10 port 22 ssh2\n"
        b"Dec  1 03:12:44 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n"
    ),
    "/var/log/vsftpd.log": (
        b"Tue Dec  1 01:00:01 2024 [pid 2345] CONNECT: Client '45.33.32.156'\n"
        b"Tue Dec  1 01:00:02 2024 [pid 2345] [admin] FAIL LOGIN: Client '45.33.32.156'\n"
        b"Tue Dec  1 01:00:05 2024 [pid 2346] [ftpuser] OK LOGIN: Client '192.168.1.50'\n"
    ),
    "/backup/users_export.csv": (
        b"id,username,password_hash,email,role\n"
        b"1,admin,$2b$12$ABCxyzFakeHashHere1,admin@corp.local,superadmin\n"
        b"2,deploy,$2b$12$DEFxyzFakeHashHere2,deploy@corp.local,deploy\n"
        b"3,john.smith,$2b$12$GHIxyzFakeHashHere3,john@corp.local,user\n"
        b"4,jane.doe,$2b$12$JKLxyzFakeHashHere4,jane@corp.local,user\n"
    ),
}

# ── Event writer ─────────────────────────────────────────────────────────────

def write_upload(ip, port, filename, payload: bytes, direction="upload"):
    """Append a captured file to the shared uploads log (base64-encoded, never executed)."""
    entry = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "protocol":    "FTP",
        "ip":          ip,
        "port":        port,
        "filename":    filename,
        "size":        len(payload),
        "direction":   direction,
        "content_b64": base64.b64encode(payload).decode(),
    }
    with _wlock:
        with open(UPLOADS_F, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

def write_event(ip, port, etype, data: dict):
    entry = {
        "ts":       datetime.now(timezone.utc).isoformat(),
        "protocol": "FTP",
        "ip":       ip,
        "port":     port,
        "type":     etype,
        **data,
    }
    with _wlock:
        with open(EVENTS_F, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

# ── FTP session handler ───────────────────────────────────────────────────────

class FTPSession(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn    = conn
        self.ip      = addr[0]
        self.port    = addr[1]
        self.cwd     = "/"
        self.user    = None
        self.authed  = False
        self.pasv_sock   = None
        self.pasv_port   = None
        self.transfer_type = "A"

    def send(self, msg):
        try:
            self.conn.sendall((msg + "\r\n").encode())
        except Exception:
            pass

    def recv_line(self):
        buf = b""
        while True:
            c = self.conn.recv(1)
            if not c or c == b"\n":
                return buf.decode("utf-8", "replace").strip()
            if c != b"\r":
                buf += c

    def open_pasv(self):
        """Open a passive data socket and return (ip_str, port)."""
        if self.pasv_sock:
            try: self.pasv_sock.close()
            except Exception: pass
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 0))
        s.listen(1)
        s.settimeout(10)
        self.pasv_sock = s
        self.pasv_port = s.getsockname()[1]
        # Report our container IP — clients connect back to us
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip, self.pasv_port

    def data_conn(self):
        """Accept one data connection from the passive socket."""
        if not self.pasv_sock:
            return None
        try:
            c, _ = self.pasv_sock.accept()
            return c
        except Exception:
            return None

    def send_listing(self, dc, path):
        lines = []
        entries = FAKE_FS.get(path, [])
        for e in entries:
            full = path.rstrip("/") + "/" + e
            if full in FAKE_FS:           # directory
                lines.append(f"drwxr-xr-x  2 root root  4096 Jan  1 00:00 {e}")
            else:                         # file
                size = len(FAKE_FILES.get(full, b""))
                lines.append(f"-rw-r--r--  1 root root {size:6d} Jan  1 00:00 {e}")
        data = ("\r\n".join(lines) + "\r\n").encode()
        try:
            dc.sendall(data)
        finally:
            dc.close()

    def resolve(self, arg):
        """Resolve a path argument relative to cwd."""
        if not arg:
            return self.cwd
        if arg.startswith("/"):
            return arg.rstrip("/") or "/"
        parts = (self.cwd.rstrip("/") + "/" + arg).split("/")
        resolved = []
        for p in parts:
            if p in ("", "."):
                continue
            elif p == "..":
                if resolved:
                    resolved.pop()
            else:
                resolved.append(p)
        return "/" + "/".join(resolved)

    def run(self):
        log.info(f"[+] FTP connect {self.ip}:{self.port}")
        write_event(self.ip, self.port, "CONNECT", {})
        self.send(BANNER.strip())
        try:
            while True:
                line = self.recv_line()
                if not line:
                    break
                parts = line.split(" ", 1)
                cmd   = parts[0].upper()
                arg   = parts[1] if len(parts) > 1 else ""
                self._handle(cmd, arg)
        except Exception:
            pass
        finally:
            write_event(self.ip, self.port, "DISCONNECT", {})
            log.info(f"[-] FTP disconnect {self.ip}")
            try: self.conn.close()
            except Exception: pass
            if self.pasv_sock:
                try: self.pasv_sock.close()
                except Exception: pass

    def _handle(self, cmd, arg):
        # SAFETY: cmd and arg are parsed and matched against known FTP verbs only.
        # No subprocess, no eval(), no shell execution of any kind.
        log.info(f"  {self.ip} {cmd} {arg[:80] if arg else ''}")
        write_event(self.ip, self.port, "COMMAND", {"cmd": cmd, "arg": arg})

        # vsftpd 2.3.4 backdoor probe (CVE-2011-2523): USER with trailing :)
        if cmd == "USER" and arg.endswith(":)"):
            write_event(self.ip, self.port, "BACKDOOR_PROBE", {
                "cve": "CVE-2011-2523", "payload": arg
            })
            log.warning(f"  [CVE-2011-2523] vsftpd backdoor probe from {self.ip}")
            self.user = arg.rstrip(":)")
            self.send(f"331 Password required for {self.user}")

        elif cmd == "USER":
            self.user = arg
            self.send(f"331 Password required for {arg}")

        elif cmd == "PASS":
            write_event(self.ip, self.port, "CREDENTIAL", {
                "username": self.user or "", "password": arg
            })
            log.info(f"  [CRED] {self.ip} {self.user!r}:{arg!r}")
            self.authed = True
            self.send(f"230 User {self.user} logged in")

        elif cmd == "QUIT":
            self.send("221 Goodbye")
            raise ConnectionResetError

        elif cmd == "SYST":
            self.send("215 UNIX Type: L8")

        elif cmd == "FEAT":
            self.send("211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n MDTM\r\n211 End")

        elif cmd == "PWD":
            self.send(f'257 "{self.cwd}" is the current directory')

        elif cmd == "CWD":
            target = self.resolve(arg)
            if target in FAKE_FS:
                self.cwd = target
                self.send(f"250 CWD command successful")
            else:
                self.send("550 No such file or directory")

        elif cmd == "CDUP":
            self.cwd = self.resolve("..")
            self.send("200 CDUP command successful")

        elif cmd == "TYPE":
            self.transfer_type = arg.upper()
            self.send(f"200 Type set to {arg}")

        elif cmd == "PASV":
            ip, port = self.open_pasv()
            p1, p2   = port >> 8, port & 0xFF
            ip_fmt   = ip.replace(".", ",")
            self.send(f"227 Entering Passive Mode ({ip_fmt},{p1},{p2})")

        elif cmd == "LIST":
            dc = self.data_conn()
            if not dc:
                self.send("425 Can't open data connection")
                return
            self.send("150 Opening ASCII mode data connection for directory listing")
            path = self.resolve(arg) if arg else self.cwd
            self.send_listing(dc, path)
            self.send("226 Transfer complete")

        elif cmd in ("NLST", "MLSD"):
            dc = self.data_conn()
            if not dc:
                self.send("425 Can't open data connection")
                return
            self.send("150 Opening data connection")
            entries = FAKE_FS.get(self.cwd, [])
            try:
                dc.sendall(("\r\n".join(entries) + "\r\n").encode())
            finally:
                dc.close()
            self.send("226 Transfer complete")

        elif cmd == "RETR":
            path = self.resolve(arg)
            data = FAKE_FILES.get(path, b"")
            dc   = self.data_conn()
            if not dc:
                self.send("425 Can't open data connection")
                return
            self.send(f"150 Opening data connection for {arg} ({len(data)} bytes)")
            write_event(self.ip, self.port, "DOWNLOAD", {"path": path, "size": len(data)})
            try:
                dc.sendall(data)
            finally:
                dc.close()
            self.send("226 Transfer complete")

        elif cmd == "STOR":
            path = self.resolve(arg)
            dc   = self.data_conn()
            if not dc:
                self.send("425 Can't open data connection")
                return
            self.send(f"125 Data connection already open; transfer starting")
            chunks = []
            try:
                while True:
                    chunk = dc.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            finally:
                dc.close()
            payload = b"".join(chunks)
            payload_hex = payload[:2048].hex()
            write_event(self.ip, self.port, "UPLOAD", {
                "path": path,
                "size": len(payload),
                "payload_hex": payload_hex,
                "payload_text": payload[:2048].decode("utf-8","replace"),
            })
            # Store full payload in shared uploads log for dashboard download
            # SAFETY: content is stored as bytes only — never written to disk or executed
            write_upload(self.ip, self.port, path.lstrip("/") or "unknown", payload)
            log.info(f"  [UPLOAD] {self.ip} -> {path} ({len(payload)} bytes)")
            self.send("226 Transfer complete")

        elif cmd == "SIZE":
            path = self.resolve(arg)
            data = FAKE_FILES.get(path, b"")
            self.send(f"213 {len(data)}")

        elif cmd == "MDTM":
            self.send("213 20240101000000")

        elif cmd == "DELE":
            self.send("250 DELE command successful")

        elif cmd == "MKD":
            self.send(f'257 "{arg}" created')

        elif cmd == "RMD":
            self.send("250 RMD command successful")

        elif cmd == "RNFR":
            self.send("350 File exists, ready for destination name")

        elif cmd == "RNTO":
            self.send("250 RNTO command successful")

        elif cmd == "NOOP":
            self.send("200 NOOP ok")

        elif cmd == "ABOR":
            self.send("226 Abort successful")

        # ProFTPD mod_copy RCE bait (CVE-2015-3306 — SITE CPFR/CPTO)
        elif cmd == "SITE":
            sub = arg.upper()
            write_event(self.ip, self.port, "SITE_CMD", {"arg": arg})
            if sub.startswith("CPFR") or sub.startswith("CPTO"):
                log.warning(f"  [CVE-2015-3306] mod_copy probe from {self.ip}: SITE {arg}")
                self.send("350 File or directory exists, ready for destination name")
            elif sub.startswith("EXEC") or sub.startswith("CHMOD"):
                # Log the attempt — SAFETY: never executed
                log.warning(f"  [SITE EXEC] probe from {self.ip}: SITE {arg}")
                self.send("200 SITE command successful")
            else:
                self.send("200 SITE command successful")

        elif cmd in ("AUTH", "PROT", "PBSZ"):
            self.send("500 Not supported")

        else:
            self.send(f"500 Unknown command {cmd}")

def load_ports():
    try:
        with open(CONFIG_F) as f:
            cfg = json.load(f)
        p = cfg.get("ftp", [21])
        return [int(x) for x in (p if isinstance(p, list) else [p])]
    except Exception as e:
        log.warning(f"load_ports: {e}")
        return [21]

# ── Dynamic multi-port engine ─────────────────────────────────────────────────

_listeners = {}
_pending   = set()
_plock     = threading.Lock()

def _accept_loop(srv, port):
    while True:
        try:
            conn, addr = srv.accept()
            FTPSession(conn, addr).start()
        except OSError:
            break
        except Exception as e:
            log.warning(f"accept :{port}: {e}")
    log.info(f"[-] FTP :{port} stopped")

def _bind_worker(port):
    for attempt in range(5):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            srv.bind(("0.0.0.0", port))
            srv.listen(50)
            threading.Thread(target=_accept_loop, args=(srv, port), daemon=True).start()
            with _plock:
                _listeners[port] = srv
                _pending.discard(port)
            log.info(f"[+] FTP :{port}")
            return
        except PermissionError:
            log.warning(f"FTP :{port} permission denied — need root/CAP_NET_BIND_SERVICE")
            break
        except OSError as e:
            log.warning(f"FTP :{port} attempt {attempt+1}: {e}")
            if attempt < 4:
                time.sleep(2)
    with _plock:
        _pending.discard(port)
    log.error(f"giving up on FTP :{port}")

def start_server(port):
    with _plock:
        if port in _listeners or port in _pending:
            return
        _pending.add(port)
    threading.Thread(target=_bind_worker, args=(port,), daemon=True).start()

def stop_server(port):
    with _plock:
        srv = _listeners.pop(port, None)
    if srv:
        try: srv.close()
        except Exception: pass

def sync_ports(ports):
    wanted = set(ports)
    with _plock:
        to_stop  = list(set(_listeners) - wanted)
        to_start = [p for p in wanted if p not in _listeners and p not in _pending]
    for p in to_stop:
        stop_server(p)
        log.info(f"[~] FTP :{p} removed")
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
