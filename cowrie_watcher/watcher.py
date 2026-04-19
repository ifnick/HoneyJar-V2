#!/usr/bin/env python3
"""
HoneyJar v2 -- Cowrie Port Watcher (containerized)
Watches /config/ports_config.json, rewrites cowrie.cfg, restarts cowrie.

For privileged ports (< 1024): sets up iptables PREROUTING REDIRECT rules
pointing them at the first high port for that protocol. Cowrie only binds
to high ports; external traffic on e.g. port 22 is transparently forwarded
to port 2222 by the kernel before cowrie ever sees it.

Requires: network_mode: host, cap_add: [NET_ADMIN]
"""
import json, signal, subprocess, sys, time
from pathlib import Path

PORTS_F = Path("/config/ports_config.json")
CFG_F   = Path("/config/cowrie.cfg")
CHAIN   = "HONEYJAR2_FWD"

def load():
    try:
        return json.loads(PORTS_F.read_text())
    except Exception:
        return {}

def write_cfg(ssh_high, tel_high):
    ssh_ep = " ".join(f"tcp:{p}:interface=0.0.0.0" for p in ssh_high)
    tel_ep = " ".join(f"tcp:{p}:interface=0.0.0.0" for p in tel_high)
    CFG_F.write_text(
        "[honeypot]\n"
        "hostname = prod-svr01\n"
        "log_path = var/log/cowrie\n"
        "download_path = var/lib/cowrie/downloads\n"
        "share_path = share/cowrie\n"
        "state_path = var/lib/cowrie\n"
        "etc_path = etc\n\n"
        "[output_jsonlog]\n"
        "enabled = true\n"
        "logfile = cowrie.json\n\n"
        "[output_textlog]\n"
        "enabled = true\n"
        "logfile = cowrie.log\n\n"
        "[ssh]\n"
        "enabled = true\n"
        f"listen_endpoints = {ssh_ep}\n\n"
        "[telnet]\n"
        f"enabled = {'true' if tel_high else 'false'}\n"
        f"listen_endpoints = {tel_ep}\n"
    )

def _ipt(*args, check=False):
    r = subprocess.run(["iptables", "-t", "nat"] + list(args),
                       capture_output=True)
    return r.returncode == 0

def sync_iptables(ssh_all, tel_all):
    """
    Flush and rebuild our PREROUTING REDIRECT chain.
    Privileged ports (< 1024) are redirected to the first high port
    for their protocol. High ports need no rule -- cowrie binds directly.
    """
    # Create chain if missing, ensure PREROUTING jumps to it
    _ipt("-N", CHAIN)
    if not _ipt("-C", "PREROUTING", "-j", CHAIN):
        _ipt("-I", "PREROUTING", "1", "-j", CHAIN)

    # Rebuild rules from scratch
    _ipt("-F", CHAIN)

    ssh_priv = [p for p in ssh_all if p < 1024]
    ssh_high = [p for p in ssh_all if p >= 1024]
    tel_priv = [p for p in tel_all if p < 1024]
    tel_high = [p for p in tel_all if p >= 1024]

    if ssh_priv and ssh_high:
        target = ssh_high[0]
        for p in ssh_priv:
            _ipt("-A", CHAIN, "-p", "tcp", "--dport", str(p),
                 "-j", "REDIRECT", "--to-port", str(target))
            print(f"[+] redirect TCP :{p} -> :{target}", flush=True)
    elif ssh_priv:
        print(f"[!] SSH priv ports {ssh_priv} configured but no high port to redirect to",
              flush=True)

    if tel_priv and tel_high:
        target = tel_high[0]
        for p in tel_priv:
            _ipt("-A", CHAIN, "-p", "tcp", "--dport", str(p),
                 "-j", "REDIRECT", "--to-port", str(target))
            print(f"[+] redirect TCP :{p} -> :{target}", flush=True)
    elif tel_priv:
        print(f"[!] Telnet priv ports {tel_priv} configured but no high port to redirect to",
              flush=True)

def restart_cowrie():
    r = subprocess.run(["docker", "restart", "honeyjar-cowrie"],
                       capture_output=True, timeout=30)
    if r.returncode == 0:
        print("[+] honeyjar-cowrie restarted", flush=True)
    else:
        print(f"[!] restart failed: {r.stderr.decode().strip()}", flush=True)

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
print("[*] Cowrie port watcher started", flush=True)

last_ssh_high = None
last_tel_high = None
first = True

while True:
    try:
        cfg     = load()
        ssh_all = cfg.get("ssh",    [2222])
        tel_all = cfg.get("telnet", [23])

        # Cowrie only binds to high ports -- privileged ports are handled by iptables
        ssh_high = [p for p in ssh_all if p >= 1024] or [2222]
        tel_high = [p for p in tel_all if p >= 1024] or [2323]

        sh_t = tuple(ssh_high)
        th_t = tuple(tel_high)

        if sh_t != last_ssh_high or th_t != last_tel_high or first:
            write_cfg(ssh_high, tel_high)
            sync_iptables(ssh_all, tel_all)
            if not first:
                print(f"[~] ports changed ssh={ssh_all} tel={tel_all}", flush=True)
                restart_cowrie()
            else:
                print(f"[*] initial: ssh={ssh_all} tel={tel_all}", flush=True)
            last_ssh_high, last_tel_high, first = sh_t, th_t, False
        else:
            # Re-sync iptables every cycle in case rules got flushed externally
            sync_iptables(ssh_all, tel_all)

    except Exception as e:
        print(f"[!] watcher error: {e}", flush=True)
    time.sleep(5)
