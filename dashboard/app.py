#!/usr/bin/env python3
"""
HoneyJar v2 — Dashboard (Flask)
Ingests JSONL logs from all honeypots → PostgreSQL.
Routes: overview, events, credentials, sessions, settings, export.
"""
import http.client, json, os, socket as _unix_sock, threading, time
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

import markupsafe
from flask import (Flask, render_template, request, redirect,
                   session, jsonify, Response, url_for, abort)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql://honeypot:honeypotpass@postgres:5432/honeypot"
)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# SVG icon exposed as a Jinja2 global so every template can use {{ svgcopy }}
# without needing {% set svgcopy %} in each block (Jinja2 block-scoping issue)
_SVG_COPY = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
             '<rect x="9" y="9" width="13" height="13" rx="2"/>'
             '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>')
app.jinja_env.globals['svgcopy'] = markupsafe.Markup(_SVG_COPY)

ACCESS_HASH = generate_password_hash(os.environ.get("ACCESS_KEY", "HoneyJar_ChangeMe_2024!"))
OWNER_HASH  = generate_password_hash(os.environ.get("OWNER_KEY",  "HoneyOwner_ChangeMe_2024!"))

LOG_SOURCES = {
    "cowrie": Path("/cowrie-logs/cowrie.json"),
    "http":   Path("/http-logs/http_events.jsonl"),
    "ftp":    Path("/ftp-logs/ftp_events.jsonl"),
    "tftp":   Path("/tftp-logs/tftp_events.jsonl"),
}

CONFIG_PATH   = Path("/config/ports_config.json")
BLOCK_PATH    = Path("/config/blocked_ips.txt")
UPLOADS_LOG   = Path("/uploads-log/uploads.jsonl")  # written by honeypots, ingested here

# Container → service name mapping (used for Docker state queries)
CONTAINER_NAMES = {
    "ssh":    "honeyjar-cowrie",
    "telnet": "honeyjar-cowrie",
    "http":   "honeyjar-http",
    "https":  "honeyjar-http",
    "ftp":    "honeyjar-ftp",
    "tftp":   "honeyjar-tftp",
}

# ─────────────────────────────────────────────────────────────────────────────
# Docker socket client (stdlib only — no extra packages)
# ─────────────────────────────────────────────────────────────────────────────

class _DockerConn(http.client.HTTPConnection):
    """HTTPConnection that talks to the Docker daemon over the Unix socket."""
    def connect(self):
        self.sock = _unix_sock.socket(_unix_sock.AF_UNIX, _unix_sock.SOCK_STREAM)
        self.sock.settimeout(2)
        self.sock.connect("/var/run/docker.sock")

def _docker_inspect(name: str) -> dict:
    try:
        conn = _DockerConn("localhost")
        conn.request("GET", f"/v1.41/containers/{name}/json")
        resp = conn.getresponse()
        if resp.status == 200:
            return json.loads(resp.read())
    except Exception:
        pass
    return {}

def container_display_state(name: str) -> str:
    """
    Returns a human-readable state string for the UI:
    'running' | 'starting' | 'restarting' | 'stopping' | 'stopped' | 'unknown'
    """
    info = _docker_inspect(name)
    if not info:
        return "unknown"
    st = info.get("State", {})
    if st.get("Restarting"):
        return "restarting"
    if st.get("Running"):
        # Health check present — use it
        health = st.get("Health", {}).get("Status", "")
        if health == "starting":
            return "starting"
        return "running"
    status = st.get("Status", "unknown")
    if status in ("created", "removing"):
        return "starting"
    if status in ("exited", "dead"):
        return "stopped"
    return status   # paused, etc.

# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────

class Event(db.Model):
    __tablename__ = "events"
    id         = db.Column(db.Integer, primary_key=True)
    protocol   = db.Column(db.String(10),  nullable=False, index=True)
    ip         = db.Column(db.String(45),  nullable=False, index=True)
    port       = db.Column(db.Integer)
    ts         = db.Column(db.DateTime,    nullable=False, index=True)
    event_type = db.Column(db.String(50),  index=True)
    username   = db.Column(db.String(255), index=True)
    password   = db.Column(db.String(255))
    path       = db.Column(db.String(512))
    method     = db.Column(db.String(10))
    command    = db.Column(db.String(512))
    data       = db.Column(db.Text)          # raw JSON string for full detail

    def to_dict(self):
        return {
            "id":         self.id,
            "protocol":   self.protocol,
            "ip":         self.ip,
            "port":       self.port,
            "ts":         self.ts.isoformat() if self.ts else None,
            "event_type": self.event_type,
            "username":   self.username,
            "password":   self.password,
            "path":       self.path,
            "method":     self.method,
            "command":    self.command,
            "data":       json.loads(self.data) if self.data else {},
        }

class CapturedFile(db.Model):
    __tablename__ = "captured_files"
    id         = db.Column(db.Integer, primary_key=True)
    protocol   = db.Column(db.String(10),  nullable=False, index=True)
    ip         = db.Column(db.String(45),  nullable=False, index=True)
    port       = db.Column(db.Integer)
    ts         = db.Column(db.DateTime,    nullable=False, index=True)
    filename   = db.Column(db.String(512), nullable=False)
    size       = db.Column(db.Integer,     default=0)
    direction  = db.Column(db.String(8),   default="upload")  # upload | download
    content    = db.Column(db.LargeBinary)  # raw bytes — never executed, never written to disk

class IngestCursor(db.Model):
    __tablename__ = "ingest_cursors"
    source = db.Column(db.String(20), primary_key=True)
    offset = db.Column(db.BigInteger, default=0)

class GeoCache(db.Model):
    __tablename__ = "geo_cache"
    ip      = db.Column(db.String(45),  primary_key=True)
    lat     = db.Column(db.Float)
    lon     = db.Column(db.Float)
    country = db.Column(db.String(100))
    city    = db.Column(db.String(100))
    updated = db.Column(db.DateTime)

# ─────────────────────────────────────────────────────────────────────────────
# Log ingestion
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cowrie_line(line: str):
    """Convert a cowrie JSON log line to an Event dict."""
    try:
        d = json.loads(line)
    except Exception:
        return None
    etype = d.get("eventid", "")
    ts_str = d.get("timestamp") or d.get("ts", "")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        ts = datetime.now(timezone.utc).replace(tzinfo=None)

    dst   = d.get("dst_port")
    proto = "TELNET" if (dst and int(dst) in (23,2323,2223,5555)) or "telnet" in etype.lower() else "SSH"
    base  = dict(
        protocol   = proto,
        ip         = d.get("src_ip", ""),
        port       = d.get("src_port"),
        ts         = ts,
        data       = line.strip(),
    )
    if "login" in etype:
        base["event_type"] = "CREDENTIAL"
        base["username"]   = d.get("username")
        base["password"]   = d.get("password")
    elif "command" in etype:
        base["event_type"] = "COMMAND"
        base["command"]    = d.get("input", "")
    elif "connect" in etype:
        base["event_type"] = "CONNECT"
    elif "disconnect" in etype:
        base["event_type"] = "DISCONNECT"
    else:
        base["event_type"] = etype
    return base

def _parse_jsonl_line(line: str, source: str):
    """Parse a JSONL line from http/ftp/tftp honeypots."""
    try:
        d = json.loads(line)
    except Exception:
        return None
    ts_str = d.get("ts", "")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        ts = datetime.now(timezone.utc).replace(tzinfo=None)

    protocol   = d.get("protocol", source.upper())
    event_type = d.get("type", "EVENT")

    e = dict(
        protocol   = protocol,
        ip         = d.get("ip", ""),
        port       = d.get("port"),
        ts         = ts,
        event_type = event_type,
        data       = line.strip(),
    )
    # Credentials
    if event_type == "CREDENTIAL":
        e["username"] = d.get("username")
        e["password"] = d.get("password")
    # HTTP credential extraction
    cred = d.get("credential")
    if cred:
        e["username"] = cred.get("username")
        e["password"] = cred.get("password")
        if e["username"] or e["password"]:
            e["event_type"] = "CREDENTIAL"

    e["path"]    = d.get("path") or d.get("filename")
    e["method"]  = d.get("method")
    e["command"] = d.get("cmd") or d.get("input")
    return e

def ingest_source(source: str, log_path: Path):
    """Read new lines from a JSONL log file and insert into DB."""
    if not log_path.exists():
        return
    try:
        cursor = db.session.get(IngestCursor, source)
        offset = cursor.offset if cursor else 0

        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size <= offset:
                return
            f.seek(offset)
            new_data = f.read()
            new_offset = f.tell()

        lines = new_data.decode("utf-8", "replace").splitlines()
        batch = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if source == "cowrie":
                ed = _parse_cowrie_line(line)
            else:
                ed = _parse_jsonl_line(line, source)
            if ed:
                batch.append(Event(**{k: v for k, v in ed.items() if v is not None}))

        if batch:
            db.session.bulk_save_objects(batch)

        if cursor:
            cursor.offset = new_offset
        else:
            db.session.add(IngestCursor(source=source, offset=new_offset))

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f"ingest {source}: {e}")

def ingest_uploads():
    """Ingest captured file payloads from UPLOADS_LOG into CapturedFile table."""
    import base64
    if not UPLOADS_LOG.exists():
        return
    try:
        cursor = db.session.get(IngestCursor, "uploads")
        offset = cursor.offset if cursor else 0

        with open(UPLOADS_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size <= offset:
                return
            f.seek(offset)
            raw  = f.read()
            new_offset = f.tell()

        batch = []
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                ts_str = d.get("ts", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    ts = datetime.now(timezone.utc).replace(tzinfo=None)
                content = base64.b64decode(d.get("content_b64", "")) if d.get("content_b64") else b""
                batch.append(CapturedFile(
                    protocol  = d.get("protocol", "UNKNOWN"),
                    ip        = d.get("ip", ""),
                    port      = d.get("port"),
                    ts        = ts,
                    filename  = d.get("filename", "unknown"),
                    size      = d.get("size", len(content)),
                    direction = d.get("direction", "upload"),
                    content   = content,
                ))
            except Exception as e:
                app.logger.warning(f"ingest_uploads line: {e}")

        if batch:
            db.session.bulk_save_objects(batch)

        if cursor:
            cursor.offset = new_offset
        else:
            db.session.add(IngestCursor(source="uploads", offset=new_offset))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f"ingest_uploads: {e}")

def ingest_loop():
    """Background thread — tails all log files every 3 s."""
    with app.app_context():
        while True:
            for source, path in LOG_SOURCES.items():
                try:
                    ingest_source(source, path)
                except Exception as e:
                    app.logger.warning(f"ingest_loop {source}: {e}")
            try:
                ingest_uploads()
            except Exception as e:
                app.logger.warning(f"ingest_loop uploads: {e}")
            time.sleep(3)

def geo_lookup_loop():
    """Background thread — batch geo-lookups for new IPs every 30 s via ip-api.com."""
    import urllib.request as _ur
    with app.app_context():
        while True:
            try:
                ips = db.session.execute(text(
                    "SELECT DISTINCT ip FROM events "
                    "WHERE ip NOT IN (SELECT ip FROM geo_cache) LIMIT 100"
                )).scalars().all()
                if ips:
                    payload = json.dumps([{"query": ip} for ip in ips]).encode()
                    req = _ur.Request(
                        "http://ip-api.com/batch?fields=query,lat,lon,country,city,status",
                        data=payload, method="POST",
                        headers={"Content-Type": "application/json"}
                    )
                    with _ur.urlopen(req, timeout=10) as resp:
                        results = json.loads(resp.read())
                    for r in results:
                        if r.get("status") == "success" and r.get("lat") is not None:
                            db.session.merge(GeoCache(
                                ip=r["query"],
                                lat=r["lat"], lon=r["lon"],
                                country=r.get("country", ""),
                                city=r.get("city", ""),
                                updated=datetime.now(timezone.utc).replace(tzinfo=None)
                            ))
                    db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.warning(f"geo_lookup: {e}")
            time.sleep(30)

# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def authed():
    return session.get("auth") is True

def owner_authed():
    return session.get("owner") is True

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not authed():
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def owner_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not authed():
            return redirect(url_for("login"))
        if not owner_authed():
            return redirect(url_for("owner_verify", next=f.__name__))
        return f(*a, **kw)
    return wrapper

# ─────────────────────────────────────────────────────────────────────────────
# Stats helper
# ─────────────────────────────────────────────────────────────────────────────

def get_stats():
    total    = Event.query.count()
    by_proto = db.session.execute(
        text("SELECT protocol, COUNT(*) as n FROM events GROUP BY protocol ORDER BY n DESC")
    ).fetchall()
    creds    = Event.query.filter_by(event_type="CREDENTIAL").count()
    ips      = db.session.execute(text("SELECT COUNT(DISTINCT ip) FROM events")).scalar()
    last24h  = Event.query.filter(
        Event.ts >= datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    ).count()
    top_ips  = db.session.execute(
        text("SELECT ip, COUNT(*) as n FROM events GROUP BY ip ORDER BY n DESC LIMIT 10")
    ).fetchall()
    top_users = db.session.execute(
        text("SELECT username, COUNT(*) as n FROM events WHERE username IS NOT NULL "
             "GROUP BY username ORDER BY n DESC LIMIT 10")
    ).fetchall()
    top_passwords = db.session.execute(
        text("SELECT password, COUNT(*) as n FROM events WHERE password IS NOT NULL "
             "GROUP BY password ORDER BY n DESC LIMIT 10")
    ).fetchall()
    top_combos = db.session.execute(
        text("SELECT username, password, COUNT(*) as n FROM events "
             "WHERE event_type='CREDENTIAL' AND username IS NOT NULL AND password IS NOT NULL "
             "GROUP BY username, password ORDER BY n DESC LIMIT 15")
    ).fetchall()
    hourly_raw = db.session.execute(text(
        "SELECT date_trunc('hour', ts) as h, COUNT(*) as n "
        "FROM events WHERE ts >= NOW() - INTERVAL '24 hours' "
        "GROUP BY h ORDER BY h"
    )).fetchall()
    # Convert Row objects to plain lists so Jinja tojson can serialize them
    hourly = [[str(r[0]) if r[0] else None, r[1]] for r in hourly_raw]
    return dict(total=total, by_proto=by_proto, creds=creds, unique_ips=ips,
                last24h=last24h, top_ips=top_ips, top_users=top_users,
                top_passwords=top_passwords, top_combos=top_combos, hourly=hourly)

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        key = request.form.get("password", "")
        if check_password_hash(ACCESS_HASH, key):
            session.clear()
            session["auth"] = True
            session.permanent = True
            return redirect(url_for("overview"))
        error = "Invalid access key."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Overview ─────────────────────────────────────────────────────────────────

@app.route("/overview")
@app.route("/dashboard")
@login_required
def overview():
    stats = get_stats()
    recent = Event.query.order_by(Event.ts.desc()).limit(20).all()
    return render_template("overview.html", active="overview",
                           title="Overview", stats=stats, recent=recent)

# ── Events ───────────────────────────────────────────────────────────────────

@app.route("/events")
@login_required
def events():
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    proto    = request.args.get("proto", "")
    ip_q     = request.args.get("ip", "")
    etype_q  = request.args.get("type", "")
    date_f   = request.args.get("from", "")
    date_t   = request.args.get("to", "")

    q = Event.query.order_by(Event.ts.desc())
    if proto:  q = q.filter(Event.protocol == proto.upper())
    if ip_q:   q = q.filter(Event.ip.contains(ip_q))
    if etype_q: q = q.filter(Event.event_type == etype_q.upper())
    if date_f:
        try: q = q.filter(Event.ts >= datetime.fromisoformat(date_f))
        except Exception: pass
    if date_t:
        try: q = q.filter(Event.ts <= datetime.fromisoformat(date_t))
        except Exception: pass

    paginated = q.paginate(page=page, per_page=per_page, error_out=False)
    protocols = [r[0] for r in db.session.execute(
        text("SELECT DISTINCT protocol FROM events ORDER BY protocol")).fetchall()]
    etypes    = [r[0] for r in db.session.execute(
        text("SELECT DISTINCT event_type FROM events ORDER BY event_type")).fetchall()]
    return render_template("events.html", active="events", title="Events",
                           logs=paginated, protocols=protocols, etypes=etypes,
                           proto=proto, ip_q=ip_q, etype_q=etype_q,
                           date_f=date_f, date_t=date_t, per_page=per_page)

@app.route("/events/<int:eid>")
@login_required
def event_detail(eid):
    ev = db.get_or_404(Event, eid)
    return jsonify(ev.to_dict())

# ── Credentials ──────────────────────────────────────────────────────────────

@app.route("/credentials")
@login_required
def credentials():
    page    = int(request.args.get("page", 1))
    proto   = request.args.get("proto", "")
    user_q  = request.args.get("user", "")
    pass_q  = request.args.get("pass", "")

    q = Event.query.filter(Event.event_type == "CREDENTIAL").order_by(Event.ts.desc())
    if proto:  q = q.filter(Event.protocol == proto.upper())
    if user_q: q = q.filter(Event.username.ilike(f"%{user_q}%"))
    if pass_q: q = q.filter(Event.password.ilike(f"%{pass_q}%"))

    paginated = q.paginate(page=page, per_page=50, error_out=False)
    top_combos = db.session.execute(text(
        "SELECT username, password, COUNT(*) as n FROM events WHERE event_type='CREDENTIAL' "
        "AND username IS NOT NULL AND password IS NOT NULL "
        "GROUP BY username, password ORDER BY n DESC LIMIT 15"
    )).fetchall()
    protocols = [r[0] for r in db.session.execute(
        text("SELECT DISTINCT protocol FROM events WHERE event_type='CREDENTIAL' ORDER BY protocol")
    ).fetchall()]
    return render_template("credentials.html", active="credentials", title="Credentials",
                           logs=paginated, proto=proto, user_q=user_q, pass_q=pass_q,
                           top_combos=top_combos, protocols=protocols)

# ── Sessions ─────────────────────────────────────────────────────────────────

@app.route("/sessions")
@login_required
def sessions_view():
    proto   = request.args.get("proto", "")
    ip_q    = request.args.get("ip", "")
    page    = int(request.args.get("page", 1))
    per_page = 30

    # Group events into sessions: same IP+protocol within a 30-min inactivity window
    params: dict = {}
    where_parts = []
    if proto:
        where_parts.append("protocol = :proto")
        params["proto"] = proto.upper()
    if ip_q:
        where_parts.append("ip LIKE :ip_q")
        params["ip_q"] = f"%{ip_q}%"
    where_clause = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    offset = (page - 1) * per_page
    rows = db.session.execute(text(
        f"SELECT ip, protocol, "
        f"MIN(ts) as first_seen, MAX(ts) as last_seen, COUNT(*) as events, "
        f"COUNT(CASE WHEN event_type='CREDENTIAL' THEN 1 END) as creds, "
        f"COUNT(CASE WHEN event_type='COMMAND' THEN 1 END) as cmds "
        f"FROM events {where_clause} "
        f"GROUP BY ip, protocol ORDER BY last_seen DESC "
        f"LIMIT :lim OFFSET :off"
    ), {**params, "lim": per_page, "off": offset}).fetchall()
    total = db.session.execute(text(
        f"SELECT COUNT(*) FROM (SELECT DISTINCT ip, protocol FROM events {where_clause}) t"
    ), params).scalar()
    protocols = [r[0] for r in db.session.execute(
        text("SELECT DISTINCT protocol FROM events ORDER BY protocol")).fetchall()]

    from math import ceil
    pages = ceil(total / per_page) if total else 1
    return render_template("sessions.html", active="sessions", title="Sessions",
                           rows=rows, page=page, pages=pages, total=total,
                           protocols=protocols, proto=proto, ip_q=ip_q)

@app.route("/sessions/<path:ip>/<protocol>")
@login_required
def session_detail(ip, protocol):
    evs = Event.query.filter_by(ip=ip, protocol=protocol.upper()).order_by(Event.ts).all()
    return jsonify([e.to_dict() for e in evs])

# ── Captured Files ───────────────────────────────────────────────────────────

@app.route("/files")
@login_required
def files_view():
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    proto    = request.args.get("proto", "")
    dir_q    = request.args.get("dir", "")
    ip_q     = request.args.get("ip", "")

    q = CapturedFile.query.order_by(CapturedFile.ts.desc())
    if proto: q = q.filter(CapturedFile.protocol == proto.upper())
    if dir_q: q = q.filter(CapturedFile.direction == dir_q)
    if ip_q:  q = q.filter(CapturedFile.ip.contains(ip_q))

    paginated = q.paginate(page=page, per_page=per_page, error_out=False)
    total_size = db.session.execute(
        text("SELECT COALESCE(SUM(size),0) FROM captured_files")
    ).scalar() or 0
    protocols = [r[0] for r in db.session.execute(
        text("SELECT DISTINCT protocol FROM captured_files ORDER BY protocol")
    ).fetchall()]
    return render_template("files.html", active="files", title="Captured Files",
                           logs=paginated, proto=proto, dir_q=dir_q, ip_q=ip_q,
                           per_page=per_page, total_size=total_size,
                           protocols=protocols)

@app.route("/files/<int:fid>/download")
@login_required
def file_download(fid):
    f = db.get_or_404(CapturedFile, fid)
    import re
    safe_name = re.sub(r'[^a-zA-Z0-9._\-]', '_', f.filename) or "file"
    return Response(
        f.content or b"",
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )

@app.route("/files/<int:fid>/download.zip")
@login_required
def file_download_zip(fid):
    """Download captured file wrapped in a ZIP archive (safer transport)."""
    import io, re, zipfile
    f = db.get_or_404(CapturedFile, fid)
    safe_name = re.sub(r'[^a-zA-Z0-9._\-]', '_', f.filename) or "captured_file"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("WARNING.txt",
            "MALWARE WARNING\n"
            "===============\n"
            "This ZIP contains a file captured from a honeypot.\n"
            "It may contain malicious code. Never execute it.\n"
            "Analyze only in an isolated sandbox environment.\n\n"
            f"Filename : {f.filename}\n"
            f"Protocol : {f.protocol}\n"
            f"Source IP: {f.ip}\n"
            f"Captured : {f.ts}\n"
            f"Size     : {f.size} bytes\n"
        )
        zf.writestr(safe_name, f.content or b"")
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="captured_{safe_name}.zip"'},
    )

# ── Payloads ─────────────────────────────────────────────────────────────────

@app.route("/protocol/<proto>")
@login_required
def protocol_view(proto):
    proto_upper = proto.upper()
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    etype_q  = request.args.get("type", "")
    ip_q     = request.args.get("ip", "")

    q = Event.query.filter(Event.protocol == proto_upper).order_by(Event.ts.desc())
    if etype_q: q = q.filter(Event.event_type == etype_q.upper())
    if ip_q:    q = q.filter(Event.ip.contains(ip_q))

    paginated = q.paginate(page=page, per_page=per_page, error_out=False)

    etypes = [r[0] for r in db.session.execute(
        text("SELECT DISTINCT event_type FROM events WHERE protocol=:p ORDER BY event_type"),
        {"p": proto_upper}
    ).fetchall()]

    total      = Event.query.filter(Event.protocol == proto_upper).count()
    creds      = Event.query.filter(Event.protocol == proto_upper,
                                    Event.event_type == "CREDENTIAL").count()
    cmds       = Event.query.filter(Event.protocol == proto_upper,
                                    Event.event_type == "COMMAND").count()
    unique_ips = db.session.execute(
        text("SELECT COUNT(DISTINCT ip) FROM events WHERE protocol=:p"), {"p": proto_upper}
    ).scalar() or 0
    last24h    = Event.query.filter(
        Event.protocol == proto_upper,
        Event.ts >= datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    ).count()

    top_ips = db.session.execute(
        text("SELECT ip, COUNT(*) as n FROM events WHERE protocol=:p "
             "GROUP BY ip ORDER BY n DESC LIMIT 10"),
        {"p": proto_upper}
    ).fetchall()

    return render_template("protocol_page.html",
                           active=proto.lower(), title=f"{proto_upper} Honeypot",
                           proto=proto_upper, logs=paginated, etypes=etypes,
                           etype_q=etype_q, ip_q=ip_q, per_page=per_page,
                           stats=dict(total=total, creds=creds, cmds=cmds,
                                      unique_ips=unique_ips, last24h=last24h),
                           top_ips=top_ips)

# ── Payloads ─────────────────────────────────────────────────────────────────

@app.route("/payloads")
@login_required
def payloads():
    page  = int(request.args.get("page", 1))
    proto = request.args.get("proto", "")
    q = Event.query.filter(Event.event_type.in_(
        ["COMMAND", "UPLOAD", "DOWNLOAD", "RRQ", "WRQ"]
    )).order_by(Event.ts.desc())
    if proto: q = q.filter(Event.protocol == proto.upper())
    paginated = q.paginate(page=page, per_page=50, error_out=False)
    return render_template("payloads.html", active="payloads", title="Payloads",
                           logs=paginated, proto=proto)

# ── Settings ─────────────────────────────────────────────────────────────────

@app.route("/settings", methods=["GET", "POST"])
@owner_required
def settings():
    msg = None
    if request.method == "POST":
        action = request.form.get("action")

        if action == "block_ip":
            ip = request.form.get("ip", "").strip()
            if ip:
                blocked = set()
                if BLOCK_PATH.exists():
                    blocked = set(BLOCK_PATH.read_text().splitlines())
                blocked.add(ip)
                BLOCK_PATH.write_text("\n".join(sorted(blocked)) + "\n")
                msg = f"IP {ip} added to block list."

        elif action == "unblock_ip":
            ip = request.form.get("ip", "").strip()
            if BLOCK_PATH.exists():
                lines = [l for l in BLOCK_PATH.read_text().splitlines() if l != ip]
                BLOCK_PATH.write_text("\n".join(lines) + "\n")
            msg = f"IP {ip} removed."

        elif action == "save_ports":
            try:
                raw = request.form.get("ports_json", "{}")
                cfg = json.loads(raw)
                CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
                msg = "Port config saved. Restart containers to apply."
            except Exception as e:
                msg = f"Error: {e}"

    ports_cfg = {}
    if CONFIG_PATH.exists():
        try: ports_cfg = json.loads(CONFIG_PATH.read_text())
        except Exception: pass

    blocked_ips = []
    if BLOCK_PATH.exists():
        blocked_ips = [l for l in BLOCK_PATH.read_text().splitlines() if l.strip()]

    return render_template("settings.html", active="settings", title="Settings",
                           ports_cfg=ports_cfg, blocked_ips=blocked_ips, msg=msg)

@app.route("/owner-verify", methods=["GET", "POST"])
@login_required
def owner_verify():
    next_page = request.args.get("next", "settings")
    error = None
    if request.method == "POST":
        key = request.form.get("owner_key", "")
        if check_password_hash(OWNER_HASH, key):
            session["owner"] = True
            return redirect(url_for(next_page))
        error = "Invalid owner key."
    return render_template("owner_verify.html", error=error, next=next_page)

# ── Export API ────────────────────────────────────────────────────────────────

@app.route("/export/events.<fmt>")
@login_required
def export_events(fmt):
    proto  = request.args.get("proto", "")
    etype  = request.args.get("type", "")
    ip_q   = request.args.get("ip", "")
    limit  = min(int(request.args.get("limit", 5000)), 50000)

    q = Event.query.order_by(Event.ts.desc())
    if proto: q = q.filter(Event.protocol == proto.upper())
    if etype: q = q.filter(Event.event_type == etype.upper())
    if ip_q:  q = q.filter(Event.ip.contains(ip_q))
    rows = q.limit(limit).all()

    if fmt == "json":
        data = json.dumps([r.to_dict() for r in rows], indent=2, default=str)
        return Response(data, mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=events.json"})
    elif fmt == "csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id","protocol","ip","port","ts","event_type","username","password","path","method","command"])
        for r in rows:
            w.writerow([r.id, r.protocol, r.ip, r.port, r.ts, r.event_type,
                        r.username, r.password, r.path, r.method, r.command])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=events.csv"})
    elif fmt == "txt":
        lines = [f"{r.ts} [{r.protocol}] {r.ip} {r.event_type} "
                 f"{r.username or ''} {r.password or ''} {r.path or ''} {r.command or ''}"
                 for r in rows]
        return Response("\n".join(lines), mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=events.txt"})
    abort(400)

@app.route("/export/credentials.<fmt>")
@login_required
def export_credentials(fmt):
    limit = min(int(request.args.get("limit", 5000)), 50000)
    rows  = Event.query.filter_by(event_type="CREDENTIAL").order_by(Event.ts.desc()).limit(limit).all()
    if fmt == "json":
        data = json.dumps([{"ip":r.ip,"protocol":r.protocol,"username":r.username,
                             "password":r.password,"ts":r.ts.isoformat()} for r in rows], indent=2)
        return Response(data, mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=credentials.json"})
    elif fmt == "csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts","protocol","ip","username","password"])
        for r in rows:
            w.writerow([r.ts, r.protocol, r.ip, r.username, r.password])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=credentials.csv"})
    elif fmt == "txt":
        lines = [f"{r.username}:{r.password}" for r in rows if r.username]
        return Response("\n".join(lines), mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=credentials.txt"})
    abort(400)

# ── Sensor status API ────────────────────────────────────────────────────────

@app.route("/api/sensor-status")
@login_required
def api_sensor_status():
    import socket as _sock, struct as _struct

    # Find the Docker bridge gateway so we can probe host-bound honeypot ports
    # from inside the dashboard container (which is on the bridge network).
    gateway = "172.17.0.1"
    try:
        with open("/proc/net/route") as _f:
            for _line in _f.readlines()[1:]:
                _parts = _line.strip().split()
                if len(_parts) >= 3 and _parts[1] == "00000000":
                    _gw = int(_parts[2], 16)
                    gateway = _sock.inet_ntoa(_gw.to_bytes(4, "little"))
                    break
    except Exception:
        pass

    def check_tcp(port, timeout=0.8):
        try:
            with _sock.create_connection((gateway, port), timeout=timeout):
                return True
        except Exception:
            return False

    def check_udp_tftp(port, timeout=1.0):
        # Send a minimal TFTP RRQ — any response (even "file not found") means the port is up.
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.settimeout(timeout)
            rrq = _struct.pack("!H", 1) + b"probe\x00octet\x00"
            s.sendto(rrq, (gateway, port))
            s.recvfrom(16)
            return True
        except _sock.timeout:
            return False
        except Exception:
            return True  # got something back, port is live
        finally:
            try: s.close()
            except Exception: pass

    ports_cfg = {}
    if CONFIG_PATH.exists():
        try: ports_cfg = json.loads(CONFIG_PATH.read_text())
        except Exception: pass

    proto_type = {
        "ssh": "TCP", "telnet": "TCP", "http": "TCP",
        "https": "TCP", "ftp": "TCP", "tftp": "UDP",
    }
    label = {
        "ssh": "SSH", "telnet": "Telnet", "http": "HTTP",
        "https": "HTTPS", "ftp": "FTP", "tftp": "TFTP",
    }
    engine = {
        "ssh": "Cowrie", "telnet": "Cowrie", "http": "HTTP honeypot",
        "https": "HTTP honeypot", "ftp": "FTP honeypot", "tftp": "TFTP honeypot",
    }

    # Cache container states so we only query Docker once per protocol group
    _cstate_cache = {}
    def get_cstate(proto):
        cname = CONTAINER_NAMES.get(proto, "")
        if cname not in _cstate_cache:
            _cstate_cache[cname] = container_display_state(cname)
        return _cstate_cache[cname]

    sensors = []
    for proto in ("ssh", "telnet", "http", "https", "ftp", "tftp"):
        ports = ports_cfg.get(proto, [])
        if not isinstance(ports, list):
            ports = [ports]
        for port in ports:
            port     = int(port)
            ptype    = proto_type[proto]
            cstate   = get_cstate(proto)
            # Only probe the port when the container is actually running;
            # otherwise trust the container state for the display status.
            if cstate in ("running",):
                up = check_udp_tftp(port) if ptype == "UDP" else check_tcp(port)
            elif cstate in ("restarting", "starting"):
                up = False   # port not ready yet — show transitional state
            else:
                up = False
            sensors.append({
                "proto":    label[proto],
                "port":     port,
                "type":     ptype,
                "engine":   engine[proto],
                "up":       up,
                "cstate":   cstate,   # running | starting | restarting | stopping | stopped | unknown
            })

    return jsonify({"gateway": gateway, "sensors": sensors})

# ── Live stats API (for auto-refresh) ─────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    stats = get_stats()
    return jsonify({
        "total":      stats["total"],
        "creds":      stats["creds"],
        "unique_ips": stats["unique_ips"],
        "last24h":    stats["last24h"],
        "by_proto":   {r[0]: r[1] for r in stats["by_proto"]},
    })

@app.route("/api/geo")
@login_required
def api_geo():
    rows = db.session.execute(text(
        "SELECT g.ip, g.lat, g.lon, g.country, g.city, COUNT(e.id) as hits, "
        "(SELECT e2.protocol FROM events e2 WHERE e2.ip = g.ip "
        " GROUP BY e2.protocol ORDER BY COUNT(*) DESC LIMIT 1) as proto "
        "FROM geo_cache g JOIN events e ON g.ip = e.ip "
        "GROUP BY g.ip, g.lat, g.lon, g.country, g.city "
        "ORDER BY hits DESC"
    )).fetchall()
    return jsonify([{
        "ip": r[0], "lat": r[1], "lon": r[2],
        "country": r[3], "city": r[4], "hits": r[5], "proto": r[6]
    } for r in rows])

@app.route("/api/recent")
@login_required
def api_recent():
    since_id = int(request.args.get("since", 0))
    rows = Event.query.filter(Event.id > since_id).order_by(Event.ts.desc()).limit(30).all()
    return jsonify([r.to_dict() for r in rows])

@app.route("/api/block-ip", methods=["POST"])
@login_required
def api_block_ip():
    ip = (request.get_json() or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"ok": False}), 400
    lines   = BLOCK_PATH.read_text().splitlines() if BLOCK_PATH.exists() else []
    blocked = {l for l in lines if l.strip()}
    blocked.add(ip)
    BLOCK_PATH.write_text("\n".join(sorted(blocked)) + "\n")
    return jsonify({"ok": True})

@app.route("/api/recent-files")
@login_required
def api_recent_files():
    since = int(request.args.get("since", 0))
    rows  = CapturedFile.query.filter(CapturedFile.id > since).order_by(CapturedFile.ts.desc()).limit(10).all()
    return jsonify([{"id": f.id, "ip": f.ip, "protocol": f.protocol,
                     "filename": f.filename, "size": f.size, "direction": f.direction}
                    for f in rows])

@app.route("/favicon.ico")
def favicon():
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
           '<rect x="9" y="13" width="14" height="13" rx="3" fill="#f0b429"/>'
           '<rect x="12" y="9" width="8" height="5" rx="2" fill="#d4920a"/>'
           '<rect x="14" y="6" width="4" height="4" rx="1" fill="#b87800"/>'
           '<rect x="5" y="15" width="4" height="7" rx="2" fill="#c07800"/>'
           '</svg>')
    return Response(svg.encode(), mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})

# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    for attempt in range(20):
        try:
            with app.app_context():
                db.create_all()
                app.logger.info("[+] Database ready")
            return
        except Exception as e:
            app.logger.warning(f"DB init attempt {attempt+1}: {e}")
            time.sleep(3)
    raise RuntimeError("Could not connect to database")

if __name__ == "__main__":
    init_db()
    threading.Thread(target=ingest_loop,    daemon=True).start()
    threading.Thread(target=geo_lookup_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, threaded=True)
