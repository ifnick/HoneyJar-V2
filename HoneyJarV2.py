#!/usr/bin/env python3
"""
HoneyJar v2 — Honeypot Lab Orchestrator
Reads local source files, writes cowrie configs, builds & starts docker-compose.
Run as root on a Linux host:  python3 HoneyJarV2.py
"""
import json, os, shutil, stat, subprocess, sys, time
from pathlib import Path

BASE   = Path(__file__).parent.resolve()
LAB    = BASE                          # everything lives alongside this script
COWRIE = LAB / "cowrie" / "etc"

ACCESS_KEY = "HoneyJar_ChangeMe_2024!"
OWNER_KEY  = "HoneyOwner_ChangeMe_2024!"

DEFAULT_PORTS = {
    "ssh":    [2222],      # add more ports here e.g. [2222, 2223] — cowrie picks them all up
    "telnet": [23],        # add more e.g. [23, 2323]
    "http":   [8080],      # add more e.g. [8080, 8888]
    "https":  [8443],
    "ftp":    [21],        # multiple supported e.g. [21, 2121]
    "tftp":   [69],        # UDP — multiple supported e.g. [69, 6969]
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def run(cmd, cwd=None, check=True):
    print(f"  [exec] {cmd}")
    subprocess.run(cmd, shell=True, cwd=cwd, check=check)

def compose_bin():
    if subprocess.run("docker compose version", shell=True, capture_output=True).returncode == 0:
        return "docker compose"
    if shutil.which("docker-compose"):
        return "docker-compose"
    return None

def ensure_docker():
    if not shutil.which("docker"):
        print("[*] Installing Docker...")
        run("curl -fsSL https://get.docker.com | sh")
        run("systemctl enable --now docker", check=False)
    else:
        subprocess.run("docker info", shell=True, capture_output=True)

    c = compose_bin()
    if not c:
        print("[*] Installing docker compose plugin...")
        run("apt-get update -qq && apt-get install -y docker-compose-plugin", check=False)
        c = compose_bin()
    if not c:
        sys.exit("[!] Could not find docker compose. Install it manually.")
    print(f"[+] compose: {c}")
    return c

def stop_existing(COMPOSE):
    print("[*] Stopping any existing lab containers...")
    run(f"{COMPOSE} down --remove-orphans", cwd=LAB, check=False)
    for name in [
        "honeyjar-cowrie", "honeyjar-cowrie-watcher",
        "honeyjar-http", "honeyjar-ftp",
        "honeyjar-tftp", "honeyjar-dashboard", "honeyjar-postgres",
        # legacy names from older runs
        "v2_cowrie_1","v2_http_honeypot_1","v2_ftp_honeypot_1",
        "v2_tftp_honeypot_1","v2_dashboard_1","v2_postgres_1",
    ]:
        subprocess.run(f"docker rm -f {name} 2>/dev/null", shell=True, check=False)

# ─────────────────────────────────────────────────────────────────────────────
# Config writers
# ─────────────────────────────────────────────────────────────────────────────

def write_ports_config(cfg):
    COWRIE.mkdir(parents=True, exist_ok=True)
    (COWRIE / "ports_config.json").write_text(json.dumps(cfg, indent=2))

def write_cowrie_cfg(cfg):
    ssh_p    = cfg.get("ssh",    [22, 2222])
    telnet_p = cfg.get("telnet", [23, 2323])
    ssh_ep   = " ".join(f"tcp:{p}:interface=0.0.0.0" for p in ssh_p)
    tel_ep   = " ".join(f"tcp:{p}:interface=0.0.0.0" for p in telnet_p)
    cowrie_cfg = f"""[honeypot]
hostname = prod-svr01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
share_path = share/cowrie
state_path = var/lib/cowrie
etc_path = etc

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = var/log/cowrie/cowrie.log

[ssh]
enabled = true
listen_endpoints = {ssh_ep}

[telnet]
enabled = {'true' if telnet_p else 'false'}
listen_endpoints = {tel_ep}
"""
    (COWRIE / "cowrie.cfg").write_text(cowrie_cfg)
    (COWRIE / "userdb.txt").write_text(
        "root:0:*\nadmin:0:*\nubuntu:1000:*\nuser:1000:*\nguest:1000:*\n"
    )

def write_docker_compose(cfg):
    # Honeypot containers use network_mode: host so dynamic port changes (via
    # ports_config.json watcher threads) take effect immediately without
    # recreating containers or pre-declaring ports in docker-compose.
    compose = f"""version: '2.4'

services:

  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    container_name: honeyjar-postgres
    environment:
      POSTGRES_DB: honeypot
      POSTGRES_USER: honeypot
      POSTGRES_PASSWORD: honeypotpass
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL","pg_isready -U honeypot"]
      interval: 5s
      timeout: 5s
      retries: 12

  cowrie:
    image: cowrie/cowrie:latest
    restart: unless-stopped
    container_name: honeyjar-cowrie
    network_mode: host
    volumes:
      - ./cowrie/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - ./cowrie/etc/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
      - ./cowrie/var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie
      - ./cowrie/var/lib/cowrie:/cowrie/var/lib/cowrie

  cowrie_watcher:
    build: ./cowrie_watcher
    restart: unless-stopped
    container_name: honeyjar-cowrie-watcher
    network_mode: host
    cap_add:
      - NET_ADMIN
    volumes:
      - ./cowrie/etc:/config
      - /var/run/docker.sock:/var/run/docker.sock

  http_honeypot:
    build: ./http_honeypot
    restart: unless-stopped
    container_name: honeyjar-http
    network_mode: host
    cap_add:
      - NET_BIND_SERVICE
    volumes:
      - ./cowrie/etc:/config:ro
      - ./cowrie/var/log/http:/http-logs
      - ./cowrie/var/log/uploads:/uploads-log

  ftp_honeypot:
    build: ./ftp_honeypot
    restart: unless-stopped
    container_name: honeyjar-ftp
    network_mode: host
    cap_add:
      - NET_BIND_SERVICE
    volumes:
      - ./cowrie/etc:/config:ro
      - ./cowrie/var/log/ftp:/ftp-logs
      - ./cowrie/var/log/uploads:/uploads-log

  tftp_honeypot:
    build: ./tftp_honeypot
    restart: unless-stopped
    container_name: honeyjar-tftp
    network_mode: host
    cap_add:
      - NET_BIND_SERVICE
    volumes:
      - ./cowrie/etc:/config:ro
      - ./cowrie/var/log/tftp:/tftp-logs
      - ./cowrie/var/log/uploads:/uploads-log

  dashboard:
    build: ./dashboard
    restart: unless-stopped
    container_name: honeyjar-dashboard
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./cowrie/etc:/config
      - ./cowrie/var/log/cowrie:/cowrie-logs:ro
      - ./cowrie/var/log/http:/http-logs:ro
      - ./cowrie/var/log/ftp:/ftp-logs:ro
      - ./cowrie/var/log/tftp:/tftp-logs:ro
      - ./cowrie/var/log/uploads:/uploads-log:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "5000:5000"
    environment:
      DATABASE_URL: "postgresql://honeypot:honeypotpass@postgres:5432/honeypot"
      ACCESS_KEY: "{ACCESS_KEY}"
      OWNER_KEY: "{OWNER_KEY}"

volumes:
  pgdata:
"""
    (LAB / "docker-compose.yml").write_text(compose)

# ─────────────────────────────────────────────────────────────────────────────
# Cowrie port watcher (host-level — rewrites cowrie.cfg and restarts container)
# ─────────────────────────────────────────────────────────────────────────────

def install_cowrie_watcher():
    ports_path = str(COWRIE / "ports_config.json")
    cfg_path   = str(COWRIE / "cowrie.cfg")
    log_file   = "/var/log/honeyjar-cowrie-watcher.log"
    watcher_py = "/usr/local/bin/honeyjar2-cowrie-watcher.py"

    script = f"""#!/usr/bin/env python3
\"\"\"Watches ports_config.json — rewrites cowrie.cfg and restarts honeyjar-cowrie when SSH/Telnet ports change.\"\"\"
import json, subprocess, time
from pathlib import Path

PORTS_F = Path({ports_path!r})
CFG_F   = Path({cfg_path!r})

def load():
    try:
        return json.loads(PORTS_F.read_text())
    except Exception:
        return {{}}

def write_cfg(cfg):
    ssh_p    = cfg.get("ssh",    [2222])
    telnet_p = cfg.get("telnet", [23])
    ssh_ep   = " ".join(f"tcp:{{p}}:interface=0.0.0.0" for p in ssh_p)
    tel_ep   = " ".join(f"tcp:{{p}}:interface=0.0.0.0" for p in telnet_p)
    CFG_F.write_text(
        "[honeypot]\\n"
        "hostname = prod-svr01\\n"
        "log_path = var/log/cowrie\\n"
        "download_path = var/lib/cowrie/downloads\\n"
        "share_path = share/cowrie\\n"
        "state_path = var/lib/cowrie\\n"
        "etc_path = etc\\n\\n"
        "[output_jsonlog]\\n"
        "enabled = true\\n"
        "logfile = cowrie.json\\n\\n"
        "[output_textlog]\\n"
        "enabled = true\\n"
        "logfile = cowrie.log\\n\\n"
        "[ssh]\\n"
        "enabled = true\\n"
        f"listen_endpoints = {{ssh_ep}}\\n\\n"
        "[telnet]\\n"
        f"enabled = {{'true' if telnet_p else 'false'}}\\n"
        f"listen_endpoints = {{tel_ep}}\\n"
    )

def restart():
    r = subprocess.run(["docker", "restart", "honeyjar-cowrie"], capture_output=True)
    if r.returncode == 0:
        print("[+] honeyjar-cowrie restarted", flush=True)
    else:
        print(f"[!] restart failed: {{r.stderr.decode().strip()}}", flush=True)

last_ssh, last_tel, first = None, None, True
while True:
    try:
        cfg = load()
        ssh = tuple(cfg.get("ssh",    [2222]))
        tel = tuple(cfg.get("telnet", [23]))
        if ssh != last_ssh or tel != last_tel:
            write_cfg(cfg)
            if not first:
                print(f"[~] ports changed ssh={{list(ssh)}} tel={{list(tel)}}", flush=True)
                restart()
            last_ssh, last_tel, first = ssh, tel, False
    except Exception as e:
        print(f"[!] watcher error: {{e}}", flush=True)
    time.sleep(5)
"""
    try:
        Path(watcher_py).write_text(script)
        os.chmod(watcher_py, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        subprocess.run("pkill -f honeyjar2-cowrie-watcher.py", shell=True, check=False)
        subprocess.Popen(
            [sys.executable, watcher_py],
            stdout=open(log_file, "a"), stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        print(f"[+] Cowrie port watcher running (log: {log_file})")
    except PermissionError:
        print("[!] Cowrie port watcher skipped — run as root.")

# ─────────────────────────────────────────────────────────────────────────────
# Block watcher (iptables, host-level)
# ─────────────────────────────────────────────────────────────────────────────

def install_block_watcher():
    block_file = str(LAB / "cowrie" / "etc" / "blocked_ips.txt")
    log_file   = "/var/log/honeyjar-block.log"
    watcher    = "/usr/local/bin/honeyjar2-block-watcher.sh"
    script = f"""#!/bin/bash
BLOCK_FILE="{block_file}"
APPLIED=""
while true; do
  if [ -f "$BLOCK_FILE" ]; then
    CURRENT=$(sort "$BLOCK_FILE" 2>/dev/null | tr '\\n' ',')
    if [ "$CURRENT" != "$APPLIED" ]; then
      iptables -F HONEYJAR2 2>/dev/null || true
      iptables -N HONEYJAR2 2>/dev/null || true
      iptables -C INPUT -j HONEYJAR2 2>/dev/null || iptables -I INPUT 1 -j HONEYJAR2
      while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        iptables -A HONEYJAR2 -s "$ip" -j DROP 2>/dev/null
      done < "$BLOCK_FILE"
      APPLIED="$CURRENT"
      echo "[$(date -u +%FT%T)] sync: $(echo "$CURRENT" | tr ',' '\\n' | grep -c .) IPs blocked"
    fi
  fi
  sleep 3
done
"""
    try:
        Path(watcher).write_text(script)
        os.chmod(watcher, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        subprocess.run("pkill -f honeyjar2-block-watcher.sh", shell=True, check=False)
        subprocess.Popen(["/bin/bash", watcher],
                         stdout=open(log_file, "a"), stderr=subprocess.STDOUT,
                         start_new_session=True)
        print(f"[+] Block watcher running (log: {log_file})")
    except PermissionError:
        print("[!] Block watcher skipped — run as root for iptables support.")

# ─────────────────────────────────────────────────────────────────────────────
# Log dirs
# ─────────────────────────────────────────────────────────────────────────────

def create_log_dirs():
    for d in ("cowrie/var/log/cowrie", "cowrie/var/log/http",
              "cowrie/var/log/ftp",    "cowrie/var/log/tftp",
              "cowrie/var/lib/cowrie/downloads",
              "cowrie/var/log/uploads"):  # shared uploads log for all honeypots
        p = LAB / d
        p.mkdir(parents=True, exist_ok=True)
        try: os.chmod(str(p), 0o777)
        except Exception: pass

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n  HoneyJar v2")
    print("  ============\n")

    COMPOSE = ensure_docker()
    stop_existing(COMPOSE)
    create_log_dirs()

    cfg = DEFAULT_PORTS.copy()
    write_ports_config(cfg)
    write_cowrie_cfg(cfg)
    write_docker_compose(cfg)
    install_block_watcher()
    # Cowrie port watcher now runs as honeyjar-cowrie-watcher container (see cowrie_watcher/)
    # install_cowrie_watcher() kept below for Linux bare-metal deployments only

    print("\n[*] Building and starting containers...")
    run(f"{COMPOSE} up -d --build", cwd=LAB)
    time.sleep(4)

    print("\n[+] HoneyJar v2 is running!")
    print(f"    Dashboard : http://localhost:5000")
    print(f"    SSH       : {cfg['ssh']}")
    print(f"    Telnet    : {cfg['telnet']}")
    print(f"    HTTP/S    : {cfg['http']} / {cfg['https']}")
    print(f"    FTP       : {cfg['ftp']}")
    print(f"    TFTP      : {cfg['tftp']}")
    print(f"\n    Access key : {ACCESS_KEY}")
    print(f"    Owner key  : {OWNER_KEY}\n")

if __name__ == "__main__":
    main()
