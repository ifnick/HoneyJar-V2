#!/usr/bin/env python3
"""
HoneyJar v2 — HTTP/HTTPS Honeypot
Serves convincing decoy pages mimicking real CVE/RCE attack surfaces.
Captures full request detail (headers, body, path, injected payloads).
Nothing is ever executed — all data is logged only.
"""
import base64, email as _em, json, logging, os, re, signal, socket, ssl, sys, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

CONFIG_F  = "/config/ports_config.json"
EVENTS_F  = "/http-logs/http_events.jsonl"
UPLOADS_F = "/uploads-log/uploads.jsonl"
LOG_F     = "/http-logs/http_honeypot.log"
CERT_F    = "/tmp/hp_cert.pem"
KEY_F     = "/tmp/hp_key.pem"
_wlock    = threading.Lock()

os.makedirs("/http-logs",   exist_ok=True)
os.makedirs("/uploads-log", exist_ok=True)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOG_F), logging.StreamHandler()])
log = logging.getLogger("http-hp")

# ── Decoy pages ───────────────────────────────────────────────────────────────

# WordPress login
_WP = (
    "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<title>Log In &lsaquo; prod-site &mdash; WordPress</title>"
    "<style>body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}"
    "#login{width:320px;margin:80px auto}"
    ".lf{background:#fff;border:1px solid #c3c4c7;padding:26px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.04)}"
    "label{font-size:14px;font-weight:600;color:#3c434a;display:block;margin-bottom:5px}"
    "input[type=text],input[type=password]{width:100%;box-sizing:border-box;border:1px solid #8c8f94;"
    "border-radius:4px;padding:8px 10px;font-size:14px;margin-bottom:14px}"
    ".btn{width:100%;padding:9px;background:#2271b1;color:#fff;border:none;border-radius:4px;"
    "font-size:14px;cursor:pointer}.err{background:#fcf0f1;border-left:4px solid #d63638;"
    "padding:10px 14px;margin-bottom:14px;font-size:13px;color:#d63638}"
    "</style></head><body><div id='login'>"
    "<h1 style='text-align:center;font-size:22px;margin-bottom:18px'>WordPress</h1>"
    "<div class='lf'>"
    "<div class='err'>ERROR: The password you entered for the username <strong>admin</strong> is incorrect.</div>"
    "<form method='post'>"
    "<label>Username or Email Address</label><input type='text' name='log' value='admin'/>"
    "<label>Password</label><input type='password' name='pwd'/>"
    "<input class='btn' type='submit' value='Log In'/>"
    "<input type='hidden' name='redirect_to' value='/wp-admin/'/>"
    "<input type='hidden' name='testcookie' value='1'/>"
    "</form></div>"
    "<p style='color:#3c434a;font-size:13px;text-align:center;margin-top:14px'>"
    "<a href='?action=lostpassword'>Lost your password?</a> &larr; "
    "<a href='/'>prod-site</a></p></div></body></html>"
).encode()

# phpMyAdmin 4.8.x (CVE-2018-12613 LFI bait, CVE-2019-12922 CSRF bait)
_PMA = (
    "<!DOCTYPE html><html><head>"
    "<title>phpMyAdmin</title>"
    "<link rel='shortcut icon' href='favicon.ico' type='image/x-icon'/>"
    "<style>*{box-sizing:border-box}body{background:#f9f9f9;font-family:sans-serif;margin:0}"
    ".frame{max-width:380px;margin:60px auto;background:#fff;border:1px solid #ddd;"
    "border-radius:4px;padding:28px;box-shadow:0 2px 8px rgba(0,0,0,.07)}"
    ".logo{text-align:center;margin-bottom:20px;font-size:22px;font-weight:700;color:#e36209}"
    "label{font-size:13px;color:#555;display:block;margin-bottom:4px}"
    "input,select{width:100%;border:1px solid #ccc;border-radius:3px;padding:7px 9px;"
    "font-size:13px;margin-bottom:12px}.btn{width:100%;padding:8px;background:#4e73a0;"
    "color:#fff;border:none;border-radius:3px;font-size:13px;cursor:pointer}"
    ".ver{text-align:center;font-size:11px;color:#aaa;margin-top:12px}"
    "</style></head><body><div class='frame'>"
    "<div class='logo'>phpMyAdmin</div>"
    "<form method='post' action='index.php'>"
    "<label>Username</label><input type='text' name='pma_username' autocomplete='username'/>"
    "<label>Password</label><input type='password' name='pma_password' autocomplete='current-password'/>"
    "<label>Server</label>"
    "<select name='server'><option value='1'>127.0.0.1</option></select>"
    "<input type='hidden' name='target' value='index.php'/>"
    "<input type='hidden' name='token' value='3f8a2c1b'/>"
    "<button class='btn' type='submit'>Go &rarr;</button>"
    "</form>"
    "<div class='ver'>phpMyAdmin 4.8.5</div>"
    "</div></body></html>"
).encode()

# phpMyAdmin setup page (CVE-2009-1151 — setup.php RCE bait)
_PMA_SETUP = (
    "<!DOCTYPE html><html><head><title>phpMyAdmin setup</title>"
    "<style>body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px}"
    ".w{max-width:600px;margin:0 auto;background:#fff;border:1px solid #ddd;padding:20px;border-radius:4px}"
    "h2{color:#e36209}label{display:block;margin:10px 0 3px;font-size:13px}"
    "input{width:100%;padding:6px;border:1px solid #ccc;border-radius:3px;font-size:13px}"
    ".btn{background:#4e73a0;color:#fff;padding:7px 18px;border:none;border-radius:3px;cursor:pointer;margin-top:12px}"
    "</style></head><body><div class='w'>"
    "<h2>phpMyAdmin Configuration Wizard</h2>"
    "<p>This file should be deleted after setup is complete. "
    "Leaving it accessible is a security risk (see <a href='#'>CVE-2009-1151</a>).</p>"
    "<form method='post'>"
    "<label>MySQL host</label><input name='host' value='127.0.0.1'/>"
    "<label>MySQL user</label><input name='user' value='root'/>"
    "<label>MySQL password</label><input type='password' name='pass'/>"
    "<label>phpMyAdmin controluser</label><input name='controluser'/>"
    "<button class='btn'>Save configuration</button>"
    "</form></div></body></html>"
).encode()

# Adminer (often targeted alongside phpMyAdmin)
_ADMINER = (
    "<!DOCTYPE html><html><head><title>Adminer</title>"
    "<style>body{background:#eee;font-family:sans-serif;margin:0}"
    "form{background:#fff;border:1px solid #bbb;border-radius:4px;padding:24px;"
    "max-width:340px;margin:60px auto;box-shadow:0 2px 6px rgba(0,0,0,.08)}"
    "h1{font-size:18px;margin:0 0 16px;color:#a00}label{font-size:12px;color:#555;"
    "display:block;margin-bottom:3px}input,select{width:100%;padding:6px 8px;"
    "border:1px solid #bbb;border-radius:3px;font-size:13px;margin-bottom:10px}"
    ".btn{width:100%;padding:8px;background:#a00;color:#fff;border:none;"
    "border-radius:3px;font-size:13px;cursor:pointer}"
    "</style></head><body><form method='post'>"
    "<h1>Adminer 4.8.1</h1>"
    "<label>System</label>"
    "<select name='auth[driver]'><option>MySQL</option><option>PostgreSQL</option>"
    "<option>SQLite</option><option>MS SQL</option></select>"
    "<label>Server</label><input name='auth[server]' value='127.0.0.1'/>"
    "<label>Username</label><input name='auth[username]'/>"
    "<label>Password</label><input type='password' name='auth[password]'/>"
    "<label>Database</label><input name='auth[db]'/>"
    "<button class='btn'>Login</button>"
    "</form></body></html>"
).encode()

# Nginx 502 bad gateway (used as default fallback — looks like a real proxy)
_NGINX_502 = (
    "<html><head><title>502 Bad Gateway</title>"
    "<style>body{font-family:sans-serif;text-align:center;padding:80px}"
    "h1{font-size:36px;font-weight:400}hr{border:none;border-top:1px solid #eee}"
    "p{color:#666;font-size:13px}</style></head><body>"
    "<h1>502 Bad Gateway</h1><hr>"
    "<p>nginx/1.24.0 (Ubuntu)</p>"
    "</body></html>"
).encode()

# Nginx 403 forbidden
_NGINX_403 = (
    "<html><head><title>403 Forbidden</title>"
    "<style>body{font-family:sans-serif;text-align:center;padding:80px}"
    "h1{font-size:36px;font-weight:400}hr{border:none;border-top:1px solid #eee}"
    "p{color:#666;font-size:13px}</style></head><body>"
    "<h1>403 Forbidden</h1><hr><p>nginx/1.24.0 (Ubuntu)</p>"
    "</body></html>"
).encode()

# Generic admin panel (dark theme)
_ADM = (
    "<!DOCTYPE html><html><head><title>Admin Panel</title>"
    "<style>body{background:#1a1a2e;display:flex;align-items:center;justify-content:center;"
    "min-height:100vh;font-family:sans-serif}"
    ".b{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:36px;width:320px}"
    "h2{color:#e94560;margin:0 0 22px;text-align:center}"
    "label{color:#a8a8b3;font-size:13px;display:block;margin-bottom:4px}"
    "input{width:100%;box-sizing:border-box;background:#0f3460;border:1px solid #1a4a8a;"
    "color:#fff;padding:8px 10px;border-radius:4px;font-size:13px;margin-bottom:14px}"
    ".btn{width:100%;padding:9px;background:#e94560;color:#fff;border:none;"
    "border-radius:4px;font-size:14px;cursor:pointer}"
    "</style></head><body><div class='b'><h2>Admin Login</h2>"
    "<form method='post'><label>Username</label><input type='text' name='username'/>"
    "<label>Password</label><input type='password' name='password'/>"
    "<button class='btn'>Sign In</button></form></div></body></html>"
).encode()

# Fake .env / config leak
_ENV = (
    b"APP_ENV=production\n"
    b"APP_KEY=base64:kXz1+8bFhj9yS3mP2Qw7rNdEt4oA5cU0VnYeJiGlBsK=\n"
    b"APP_DEBUG=false\n"
    b"APP_URL=http://localhost\n\n"
    b"DB_CONNECTION=mysql\n"
    b"DB_HOST=127.0.0.1\n"
    b"DB_PORT=3306\n"
    b"DB_DATABASE=production_db\n"
    b"DB_USERNAME=dbadmin\n"
    b"DB_PASSWORD=Sup3rS3cr3t!\n\n"
    b"MAIL_DRIVER=smtp\n"
    b"MAIL_HOST=smtp.mailgun.org\n"
    b"MAIL_PORT=587\n"
    b"MAIL_USERNAME=postmaster@prod-site.com\n"
    b"MAIL_PASSWORD=mg_api_key_xxxxxxx\n\n"
    b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    b"AWS_DEFAULT_REGION=us-east-1\n\n"
    b"REDIS_HOST=127.0.0.1\n"
    b"REDIS_PORT=6379\n"
    b"REDIS_PASSWORD=null\n\n"
    b"JWT_SECRET=ey_super_secret_jwt_key_do_not_share\n"
    b"API_TOKEN=sk-prod-abcdef1234567890abcdef1234567890\n"
)

# Spring Boot Actuator /env (Spring4Shell / actuator exposure bait)
_ACTUATOR_ENV = json.dumps({
    "activeProfiles": ["production"],
    "propertySources": [
        {"name": "server.ports", "properties": {"local.server.port": {"value": "8080"}}},
        {"name": "applicationConfig: [classpath:/application.properties]", "properties": {
            "spring.datasource.url":      {"value": "jdbc:mysql://localhost:3306/appdb"},
            "spring.datasource.username": {"value": "appuser"},
            "spring.datasource.password": {"value": "******"},
            "server.port":                {"value": "8080"},
            "management.endpoints.web.exposure.include": {"value": "*"},
        }},
    ]
}, indent=2).encode()

# Spring Boot /actuator (index listing — exposes heapdump etc.)
_ACTUATOR_INDEX = json.dumps({
    "_links": {
        "self":      {"href": "/actuator",             "templated": False},
        "health":    {"href": "/actuator/health",      "templated": False},
        "info":      {"href": "/actuator/info",        "templated": False},
        "env":       {"href": "/actuator/env",         "templated": False},
        "env-toMatch":{"href":"/actuator/env/{toMatch}","templated": True},
        "beans":     {"href": "/actuator/beans",       "templated": False},
        "heapdump":  {"href": "/actuator/heapdump",    "templated": False},
        "threaddump":{"href": "/actuator/threaddump",  "templated": False},
        "loggers":   {"href": "/actuator/loggers",     "templated": False},
        "metrics":   {"href": "/actuator/metrics",     "templated": False},
        "mappings":  {"href": "/actuator/mappings",    "templated": False},
    }
}, indent=2).encode()

# Apache Struts showcase (CVE-2017-5638 Content-Type RCE bait)
_STRUTS = (
    "<!DOCTYPE html><html><head><title>Struts2 Showcase</title>"
    "<style>body{font-family:sans-serif;background:#f5f5f5;margin:0;padding:30px}"
    "h1{color:#333}.container{max-width:700px;margin:0 auto;background:#fff;"
    "border:1px solid #ddd;padding:24px;border-radius:4px}"
    "form input{padding:6px 10px;border:1px solid #bbb;border-radius:3px;font-size:13px}"
    ".btn{background:#4a6fa5;color:#fff;padding:7px 16px;border:none;border-radius:3px;cursor:pointer}"
    ".note{font-size:11px;color:#888;margin-top:18px}"
    "</style></head><body><div class='container'>"
    "<h1>Apache Struts 2 &mdash; Showcase</h1>"
    "<p>This is the Struts 2 showcase application.</p>"
    "<h3>Upload example</h3>"
    "<form method='post' action='/struts2/upload.action' enctype='multipart/form-data'>"
    "<input type='file' name='upload'/> "
    "<button class='btn'>Upload</button>"
    "</form>"
    "<h3>Login</h3>"
    "<form method='post' action='/struts2/Login.action'>"
    "Username: <input name='username' value=''/> "
    "Password: <input type='password' name='password'/> "
    "<button class='btn'>Login</button>"
    "</form>"
    "<p class='note'>Apache Struts 2.3.34 &bull; Powered by Tomcat/8.5.31</p>"
    "</div></body></html>"
).encode()

# Log4j / API endpoint bait (CVE-2021-44228)
_API_JSON = json.dumps({
    "status":  "ok",
    "version": "2.1.0",
    "endpoints": ["/api/v1/users", "/api/v1/orders", "/api/v1/products"],
    "server":  "Apache Tomcat/9.0.56",
}).encode()

# Webshell-not-found (plausible "already cleaned" response)
_SHELL_GONE = (
    "<html><head><title>404 Not Found</title>"
    "<style>body{font-family:sans-serif;text-align:center;padding:80px}"
    "h1{font-size:36px;font-weight:400}hr{border:none;border-top:1px solid #eee}"
    "p{color:#666;font-size:13px}</style></head><body>"
    "<h1>404 Not Found</h1><hr><p>nginx/1.24.0 (Ubuntu)</p>"
    "</body></html>"
).encode()

# Jenkins login (CVE-2024-23897 file read via CLI, CVE-2024-23898 XSS bait)
_JENKINS = (
    "<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title>"
    "<style>body{background:#fafafa;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;margin:0}"
    ".login-wrap{width:360px;margin:80px auto;background:#fff;border:1px solid #ddd;"
    "border-radius:4px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,.06)}"
    "h1{font-size:20px;color:#333;margin:0 0 20px;border-bottom:1px solid #eee;padding-bottom:12px}"
    "label{display:block;font-size:13px;color:#555;margin-bottom:4px}"
    "input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:7px 9px;"
    "border:1px solid #bbb;border-radius:3px;font-size:13px;margin-bottom:14px}"
    ".btn{width:100%;padding:9px;background:#335061;color:#fff;border:none;"
    "border-radius:3px;font-size:14px;cursor:pointer}"
    ".ver{text-align:right;font-size:10px;color:#aaa;margin-top:14px}"
    "</style></head><body><div class='login-wrap'>"
    "<h1>Sign in to Jenkins</h1>"
    "<form method='post' action='/j_spring_security_check'>"
    "<label>Username</label><input type='text' name='j_username'/>"
    "<label>Password</label><input type='password' name='j_password'/>"
    "<input type='hidden' name='from' value='/'/>"
    "<button class='btn' type='submit'>Sign in</button>"
    "</form>"
    "<div class='ver'>Jenkins 2.426.2</div>"
    "</div></body></html>"
).encode()

# Jenkins script console (Groovy RCE bait — heavily targeted)
_JENKINS_SCRIPT = (
    "<!DOCTYPE html><html><head><title>Script Console [Jenkins]</title>"
    "<style>body{font-family:'Helvetica Neue',sans-serif;background:#fafafa;margin:0;padding:24px}"
    "h1{font-size:18px;color:#333}textarea{width:100%;height:180px;font-family:monospace;"
    "font-size:13px;border:1px solid #bbb;border-radius:3px;padding:8px}"
    ".btn{margin-top:10px;padding:8px 20px;background:#335061;color:#fff;border:none;"
    "border-radius:3px;cursor:pointer;font-size:13px}"
    "pre{background:#1e1e1e;color:#d4d4d4;padding:14px;border-radius:4px;font-size:12px;margin-top:16px}"
    "</style></head><body>"
    "<h1>Script Console</h1>"
    "<form method='post'>"
    "<textarea name='script' placeholder='Groovy script'></textarea><br/>"
    "<button class='btn'>Run</button>"
    "</form>"
    "<pre>Result: hudson.security.AccessDeniedException2: anonymous is missing the Overall/Administer permission</pre>"
    "</body></html>"
).encode()

# GitLab login (CVE-2021-22205 RCE via image upload, CVE-2023-7028 account takeover)
_GITLAB = (
    "<!DOCTYPE html><html><head><title>Sign in &middot; GitLab</title>"
    "<style>*{box-sizing:border-box}body{background:#fafafa;font-family:-apple-system,sans-serif;margin:0}"
    ".wrap{max-width:380px;margin:60px auto}"
    ".card{background:#fff;border:1px solid #dbe1e8;border-radius:4px;padding:30px}"
    "h2{font-size:20px;color:#303030;margin:0 0 20px;text-align:center}"
    "label{font-size:13px;color:#303030;display:block;margin-bottom:4px;font-weight:600}"
    "input{width:100%;padding:8px 10px;border:1px solid #dbdbdb;border-radius:4px;"
    "font-size:14px;margin-bottom:14px}"
    ".btn{width:100%;padding:10px;background:#fc6d26;color:#fff;border:none;"
    "border-radius:4px;font-size:14px;cursor:pointer;font-weight:600}"
    ".divider{text-align:center;color:#999;font-size:12px;margin:14px 0}"
    ".note{font-size:11px;color:#888;text-align:center;margin-top:14px}"
    "</style></head><body><div class='wrap'>"
    "<div style='text-align:center;margin-bottom:20px;font-size:28px;font-weight:700;color:#fc6d26'>GitLab</div>"
    "<div class='card'>"
    "<h2>Sign in</h2>"
    "<form method='post' action='/users/sign_in'>"
    "<label>Username or email</label>"
    "<input type='text' name='user[login]' autocomplete='username'/>"
    "<label>Password</label>"
    "<input type='password' name='user[password]' autocomplete='current-password'/>"
    "<input type='hidden' name='authenticity_token' value='xK2mP9Qw3rN7tS1vE4oA8cU6'/>"
    "<button class='btn'>Sign in</button>"
    "</form>"
    "<div class='note'>GitLab Community Edition 16.7.0</div>"
    "</div></div></body></html>"
).encode()

# Confluence login (CVE-2023-22515 priv-esc, CVE-2022-26134 OGNL injection)
_CONFLUENCE = (
    "<!DOCTYPE html><html><head><title>Log in - Confluence</title>"
    "<style>body{background:#0052cc;display:flex;align-items:center;justify-content:center;"
    "min-height:100vh;font-family:-apple-system,sans-serif;margin:0}"
    ".card{background:#fff;border-radius:4px;padding:32px;width:340px;box-shadow:0 4px 16px rgba(0,0,0,.2)}"
    "h2{color:#172b4d;font-size:20px;margin:0 0 20px;text-align:center}"
    "label{font-size:12px;font-weight:700;color:#6b778c;display:block;margin-bottom:4px;text-transform:uppercase}"
    "input{width:100%;box-sizing:border-box;padding:8px 10px;border:2px solid #dfe1e6;"
    "border-radius:4px;font-size:14px;margin-bottom:14px}"
    "input:focus{border-color:#0052cc;outline:none}"
    ".btn{width:100%;padding:10px;background:#0052cc;color:#fff;border:none;"
    "border-radius:4px;font-size:14px;cursor:pointer;font-weight:600}"
    "</style></head><body><div class='card'>"
    "<h2>Log in to Confluence</h2>"
    "<form method='post' action='/dologin.action'>"
    "<label>Username</label>"
    "<input type='text' name='os_username'/>"
    "<label>Password</label>"
    "<input type='password' name='os_password'/>"
    "<input type='hidden' name='os_destination' value='/'/>"
    "<button class='btn'>Log in</button>"
    "</form>"
    "<p style='text-align:center;font-size:11px;color:#6b778c;margin-top:16px'>"
    "Confluence 7.19.16 &bull; Powered by Atlassian"
    "</p></div></body></html>"
).encode()

# Grafana login (CVE-2021-43798 path traversal, CVE-2023-6152)
_GRAFANA = (
    "<!DOCTYPE html><html><head><title>Grafana</title>"
    "<style>*{box-sizing:border-box}body{background:#111217;display:flex;align-items:center;"
    "justify-content:center;min-height:100vh;font-family:'Helvetica Neue',sans-serif;margin:0}"
    ".card{background:#1f1f2e;border:1px solid #2a2a3c;border-radius:6px;padding:32px;width:340px}"
    "h2{color:#d8d9da;font-size:22px;margin:0 0 24px;text-align:center}"
    "label{font-size:12px;color:#8e8ea7;display:block;margin-bottom:5px;font-weight:600}"
    "input{width:100%;background:#0b0c0e;border:1px solid #2a2a3c;color:#d8d9da;"
    "padding:9px 11px;border-radius:4px;font-size:14px;margin-bottom:14px}"
    ".btn{width:100%;padding:10px;background:#f46800;color:#fff;border:none;"
    "border-radius:4px;font-size:14px;cursor:pointer;font-weight:600}"
    "</style></head><body><div class='card'>"
    "<h2>Grafana</h2>"
    "<form method='post' action='/login'>"
    "<label>Email or username</label><input type='text' name='user' placeholder='admin'/>"
    "<label>Password</label><input type='password' name='password'/>"
    "<button class='btn'>Log in</button>"
    "</form>"
    "<p style='color:#8e8ea7;font-size:11px;text-align:center;margin-top:16px'>"
    "Grafana v9.5.3 (build 12345)</p>"
    "</div></body></html>"
).encode()

# Roundcube Webmail (CVE-2023-43770 XSS/RCE, CVE-2025-49113)
_ROUNDCUBE = (
    "<!DOCTYPE html><html><head><title>Roundcube Webmail</title>"
    "<style>body{background:#e8eaed;font-family:Arial,sans-serif;margin:0}"
    "#login{width:340px;margin:80px auto;background:#fff;border:1px solid #c8ccd0;"
    "border-radius:4px;padding:28px;box-shadow:0 1px 4px rgba(0,0,0,.08)}"
    "h2{color:#4a6785;font-size:18px;margin:0 0 20px;border-bottom:1px solid #eee;padding-bottom:10px}"
    "label{font-size:13px;color:#555;display:block;margin-bottom:4px}"
    "input{width:100%;box-sizing:border-box;padding:7px 9px;border:1px solid #bbb;"
    "border-radius:3px;font-size:13px;margin-bottom:12px}"
    ".btn{width:100%;padding:8px;background:#4a6785;color:#fff;border:none;"
    "border-radius:3px;font-size:14px;cursor:pointer}"
    ".ver{font-size:10px;color:#aaa;text-align:right;margin-top:12px}"
    "</style></head><body><div id='login'>"
    "<h2>Roundcube Webmail</h2>"
    "<form method='post' action='/?_task=login'>"
    "<label>Username</label><input type='text' name='_user'/>"
    "<label>Password</label><input type='password' name='_pass'/>"
    "<input type='hidden' name='_action' value='login'/>"
    "<input type='hidden' name='_timezone' value='_default_'/>"
    "<button class='btn'>Login</button>"
    "</form>"
    "<div class='ver'>Roundcube Webmail 1.6.4</div>"
    "</div></body></html>"
).encode()

# Ivanti Connect Secure / ICS login (CVE-2025-0282, CVE-2023-46805 + CVE-2024-21887)
_IVANTI = (
    "<!DOCTYPE html><html><head><title>Ivanti Connect Secure</title>"
    "<style>body{background:#003366;display:flex;align-items:center;justify-content:center;"
    "min-height:100vh;font-family:Arial,sans-serif;margin:0}"
    ".card{background:#fff;border-radius:4px;padding:36px;width:360px;box-shadow:0 4px 20px rgba(0,0,0,.3)}"
    "h2{color:#003366;font-size:20px;margin:0 0 22px;text-align:center}"
    "label{font-size:13px;color:#333;display:block;margin-bottom:4px}"
    "input{width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #bbb;"
    "border-radius:3px;font-size:14px;margin-bottom:14px}"
    ".btn{width:100%;padding:10px;background:#003366;color:#fff;border:none;"
    "border-radius:3px;font-size:14px;cursor:pointer;font-weight:bold}"
    ".realm{font-size:11px;color:#666;margin-top:12px;text-align:center}"
    "</style></head><body><div class='card'>"
    "<h2>Ivanti Connect Secure</h2>"
    "<form method='post' action='/dana-na/auth/url_default/login.cgi'>"
    "<label>Username</label><input type='text' name='username'/>"
    "<label>Password</label><input type='password' name='password'/>"
    "<label>Realm</label>"
    "<input type='text' name='realm' value='Users'/>"
    "<button class='btn'>Sign In</button>"
    "</form>"
    "<div class='realm'>Ivanti Connect Secure 22.7R1.1</div>"
    "</div></body></html>"
).encode()

# PHPUnit eval-stdin.php (CVE-2017-9841 — still heavily scanned in 2025)
_PHPUNIT_RESP = b"PHP Fatal error:  Class 'PHP_Token_WHITESPACE' not found in /var/www/html/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php on line 1\n"

# Fake git config leak
_GIT_CONFIG = (
    b"[core]\n"
    b"\trepositoryformatversion = 0\n"
    b"\tfilemode = true\n"
    b"\tbare = false\n"
    b"\tlogallrefupdates = true\n"
    b"[remote \"origin\"]\n"
    b"\turl = https://github.com/company-internal/prod-backend.git\n"
    b"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    b"[branch \"main\"]\n"
    b"\tremote = origin\n"
    b"\tmerge = refs/heads/main\n"
    b"[user]\n"
    b"\temail = deploy@prod-site.com\n"
    b"\tname = Deploy Bot\n"
)

# Fake wp-config.php
_WP_CONFIG = (
    b"<?php\n"
    b"/** Database settings -- do not share this file */\n"
    b"define( 'DB_NAME',     'wordpress_prod' );\n"
    b"define( 'DB_USER',     'wp_db_user' );\n"
    b"define( 'DB_PASSWORD', 'Wp@Prod#2024!' );\n"
    b"define( 'DB_HOST',     'localhost' );\n"
    b"define( 'DB_CHARSET',  'utf8mb4' );\n"
    b"define( 'AUTH_KEY',         'put your unique phrase here' );\n"
    b"define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );\n"
    b"define( 'LOGGED_IN_KEY',    'put your unique phrase here' );\n"
    b"define( 'NONCE_KEY',        'put your unique phrase here' );\n"
    b"define( 'AUTH_SALT',        'put your unique phrase here' );\n"
    b"define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );\n"
    b"define( 'LOGGED_IN_SALT',   'put your unique phrase here' );\n"
    b"define( 'NONCE_SALT',       'put your unique phrase here' );\n"
    b"$table_prefix = 'wp_';\n"
    b"define( 'WP_DEBUG', false );\n"
    b"if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }\n"
    b"require_once ABSPATH . 'wp-settings.php';\n"
)

# Fake xmlrpc.php (WordPress XMLRPC brute-force bait)
_XMLRPC = (
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    b"<methodResponse><params><param><value><string>"
    b"Jetpack by WordPress.com"
    b"</string></value></param></params></methodResponse>\n"
)

# ── Log4j JNDI payload detector ───────────────────────────────────────────────

_JNDI_RE = re.compile(r'\$\{.*?jndi.*?\}', re.IGNORECASE)

def _has_jndi(s: str) -> bool:
    return bool(_JNDI_RE.search(s))

# ── Event writer ──────────────────────────────────────────────────────────────

def _parse_multipart_files(ct: str, body: bytes):
    try:
        msg = _em.message_from_bytes(f"Content-Type: {ct}\r\n\r\n".encode() + body)
        out = []
        for part in msg.walk():
            cd = part.get("Content-Disposition", "")
            if "filename=" not in cd:
                continue
            m    = re.search(r'filename="?([^";\r\n]+)"?', cd)
            data = part.get_payload(decode=True) or b""
            if data:
                out.append((m.group(1).strip() if m else "upload", data))
        return out
    except Exception:
        return []

def write_upload(ip, port, path, body: bytes):
    filename = path.lstrip("/").replace("/", "_") or "http_body"
    entry = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "protocol":    "HTTP",
        "ip":          ip,
        "port":        port,
        "filename":    filename,
        "size":        len(body),
        "direction":   "upload",
        "content_b64": base64.b64encode(body).decode(),
    }
    with _wlock:
        with open(UPLOADS_F, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()

def write_event(method, path, ip, port, headers, body=b"", tags=None):
    try:
        hdict = {k.lower(): v for k, v in (headers.items() if hasattr(headers, "items") else {}.items())}
        entry = {
            "ts":         datetime.now(timezone.utc).isoformat(),
            "protocol":   "HTTP",
            "ip":         ip,
            "port":       port,
            "method":     method,
            "path":       path,
            "user_agent": hdict.get("user-agent", ""),
            "headers":    hdict,
            "body":       body.decode("utf-8", "replace")[:8192] if body else "",
            "body_hex":   body[:2048].hex() if body else "",
            "body_size":  len(body),
        }
        if tags:
            entry["tags"] = tags
        # Extract credentials from POST body
        if method == "POST" and body:
            body_str = body.decode("utf-8", "replace")
            from urllib.parse import parse_qs
            params = parse_qs(body_str)
            cred_fields = {
                "username": (params.get("username") or params.get("log") or
                             params.get("pma_username") or params.get("auth[username]") or [None])[0],
                "password": (params.get("password") or params.get("pwd") or
                             params.get("pma_password") or params.get("auth[password]") or [None])[0],
            }
            if cred_fields["username"] or cred_fields["password"]:
                entry["credential"] = cred_fields
        # Detect JNDI payloads in any header or path (log4j bait)
        all_text = path + " " + " ".join(str(v) for v in hdict.values())
        if _has_jndi(all_text):
            entry["tags"] = list(set((entry.get("tags") or []) + ["LOG4J_JNDI"]))
            log.warning(f"LOG4J probe from {ip}: {all_text[:200]}")
        # Detect Struts Content-Type RCE attempt (CVE-2017-5638)
        ct = hdict.get("content-type", "")
        if "${" in ct or "ognl" in ct.lower():
            entry["tags"] = list(set((entry.get("tags") or []) + ["STRUTS_RCE"]))
            log.warning(f"STRUTS probe from {ip}: content-type={ct[:200]}")
        with _wlock:
            with open(EVENTS_F, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
    except Exception as e:
        log.warning(f"write_event: {e}")

# ── Request handler ───────────────────────────────────────────────────────────

class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version    = ""

    def log_message(self, *a): pass

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(min(n, 65536)) if n > 0 else b""
        except Exception:
            return b""

    def _respond(self, body: bytes, ct="text/html; charset=utf-8", code=200, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.24.0 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.1.28")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _route(self, p: str):
        # WordPress
        if p in ("/wp-login.php", "/wp-admin", "/wp-admin/", "/wp-login",
                 "/wordpress/wp-login.php", "/blog/wp-login.php", "/wp-admin/admin-ajax.php"):
            return _WP, "text/html", 200, None
        if p == "/xmlrpc.php":
            return _XMLRPC, "text/xml", 200, None
        if p.endswith("wp-config.php") or p.endswith("wp-config.php.bak"):
            return _WP_CONFIG, "text/plain", 200, None

        # phpMyAdmin — multiple CVE bait paths
        if p in ("/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
                 "/mysql", "/db", "/dbadmin", "/phpmyadmin/index.php",
                 "/phpmyadmin/db_structure.php"):
            return _PMA, "text/html", 200, None
        # CVE-2009-1151 setup.php RCE bait
        if p in ("/phpmyadmin/scripts/setup.php", "/pma/scripts/setup.php",
                 "/phpmyadmin/setup", "/phpmyadmin/setup/"):
            return _PMA_SETUP, "text/html", 200, None
        # CVE-2018-12613 LFI bait (?target=db_sql.php%253f/../../../etc/passwd)
        if "/phpmyadmin" in p and ("target=" in p or "file=" in p or ".." in p):
            return _NGINX_403, "text/html", 403, None

        # Adminer
        if p in ("/adminer", "/adminer/", "/adminer.php", "/adminer.php/"):
            return _ADMINER, "text/html", 200, None

        # Admin panels
        if p in ("/admin", "/admin/", "/administrator", "/administrator/",
                 "/panel", "/cp", "/controlpanel", "/backend",
                 "/manage", "/manager", "/cms", "/cms/"):
            return _ADM, "text/html", 200, None

        # Spring Boot actuator (Spring4Shell / actuator exposure — CVE-2022-22965, CVE-2020-5412)
        if p in ("/actuator", "/actuator/"):
            return _ACTUATOR_INDEX, "application/vnd.spring-boot.actuator.v3+json", 200, None
        if p == "/actuator/env":
            return _ACTUATOR_ENV, "application/vnd.spring-boot.actuator.v3+json", 200, None
        if p == "/actuator/heapdump":
            # Plausible heapdump stub — just a 503 as if it temporarily failed
            return (b"503 Service Unavailable: heap dump in progress\n"), "text/plain", 503, None
        if p.startswith("/actuator/"):
            return json.dumps({"status": "UP"}).encode(), "application/json", 200, None

        # Apache Struts 2 (CVE-2017-5638, CVE-2018-11776)
        if p in ("/struts2", "/struts2/", "/struts", "/Struts2") or \
           p.endswith(".action") or p.endswith(".do"):
            return _STRUTS, "text/html", 200, None
        if "/struts2/" in p:
            return _STRUTS, "text/html", 200, None

        # Spring / Java app API (log4j JNDI bait surface — CVE-2021-44228)
        if p in ("/api", "/api/", "/api/v1", "/api/v1/", "/rest", "/rest/",
                 "/api/v2", "/api/v1/users", "/api/v1/login", "/api/v1/auth",
                 "/api/v1/products", "/api/v1/orders", "/v1", "/v2"):
            return _API_JSON, "application/json", 200, None

        # Jenkins (CVE-2024-23897, CVE-2024-23898)
        if p in ("/jenkins", "/jenkins/", "/jenkins/login", "/login"):
            return _JENKINS, "text/html", 200, None
        if p in ("/jenkins/script", "/jenkins/scriptText", "/script", "/scriptText"):
            return _JENKINS_SCRIPT, "text/html", 200, None
        # Jenkins CLI file read bait path (CVE-2024-23897)
        if p.startswith("/jenkins/cli") or p == "/cli":
            return (b"CLI endpoint -- use jenkins-cli.jar\n"), "text/plain", 400, None

        # GitLab (CVE-2021-22205, CVE-2023-7028)
        if p in ("/gitlab", "/gitlab/", "/users/sign_in", "/gitlab/users/sign_in"):
            return _GITLAB, "text/html", 200, None
        # GitLab file upload RCE bait (CVE-2021-22205 — ExifTool via image upload)
        if p.startswith("/uploads/") or (p.startswith("/api/v4") and "import" in p):
            return json.dumps({"message": "401 Unauthorized"}).encode(), "application/json", 401, None

        # Confluence (CVE-2023-22515, CVE-2022-26134 OGNL)
        if p in ("/confluence", "/confluence/", "/wiki", "/wiki/",
                 "/dologin.action", "/confluence/dologin.action"):
            return _CONFLUENCE, "text/html", 200, None
        # CVE-2022-26134 OGNL injection bait
        if p.startswith("/confluence/pages/") or "%24%7B" in p or "%{" in p:
            return _NGINX_403, "text/html", 403, None

        # Grafana (CVE-2021-43798 path traversal, CVE-2023-6152)
        if p in ("/grafana", "/grafana/", "/grafana/login"):
            return _GRAFANA, "text/html", 200, None
        # CVE-2021-43798 public/plugins path traversal bait
        if p.startswith("/public/plugins/") and ".." in p:
            return _NGINX_403, "text/html", 403, None
        if p.startswith("/grafana/public/plugins/") or p.startswith("/public/plugins/"):
            return _NGINX_403, "text/html", 403, None

        # Roundcube Webmail (CVE-2023-43770, CVE-2025-49113)
        if p in ("/roundcube", "/roundcube/", "/webmail", "/webmail/", "/mail", "/mail/"):
            return _ROUNDCUBE, "text/html", 200, None

        # Ivanti Connect Secure (CVE-2025-0282, CVE-2023-46805)
        if p in ("/dana-na/auth/url_default/welcome.cgi",
                 "/dana-na/auth/url_default/login.cgi",
                 "/remote",  "/remote/"):
            return _IVANTI, "text/html", 200, None
        # Ivanti CVE-2023-46805 auth bypass + CVE-2024-21887 RCE bait path
        if p.startswith("/dana-na/") or p.startswith("/dana/"):
            return _IVANTI, "text/html", 200, None

        # PHPUnit eval-stdin.php (CVE-2017-9841 — still scanned constantly)
        if "phpunit" in p and "eval-stdin" in p:
            return _PHPUNIT_RESP, "text/plain", 500, None
        if p.endswith("/eval-stdin.php"):
            return _PHPUNIT_RESP, "text/plain", 500, None

        # Webshells / RCE upload paths — log as shell attempt, return 404
        if any(p.endswith(x) for x in (".php?cmd=", ".php?c=", "?exec=", "?run=")) or \
           any(p.startswith(x) for x in ("/shell", "/cmd", "/exec", "/command",
                                          "/cgi-bin/", "/eval", "/system",
                                          "/webshell", "/backdoor", "/c99",
                                          "/r57", "/tool")):
            # SAFETY: path and body logged only — never passed to subprocess, exec(), or eval()
            return _SHELL_GONE, "text/html", 404, None

        # Config / credential leak paths
        if any(p.endswith(x) for x in (".env", ".env.local", ".env.production",
                                         ".env.backup", "config.php", "settings.py",
                                         "secrets.yml", "credentials.xml", "database.yml")):
            return _ENV, "text/plain", 200, None
        if p.endswith(".git/config") or p == "/.git/config":
            return _GIT_CONFIG, "text/plain", 200, None

        # Favicon
        if p in ("/favicon.ico",):
            return b"", "image/x-icon", 204, None

        # Default — nginx 502 (looks like a real backend is down behind a proxy)
        return _NGINX_502, "text/html", 502, None

    def _handle(self):
        ip   = self.client_address[0]
        port = self.server.server_address[1]
        body = self._body()
        path = self.path.split("?")[0].rstrip("/") or "/"
        log.info(f"{self.command} :{port} {ip} {self.path}")
        tags = []
        ct_req = self.headers.get("Content-Type", "")
        if self.command == "POST" and body:
            if "multipart/form-data" in ct_req:
                for fname, fdata in _parse_multipart_files(ct_req, body):
                    write_upload(ip, port, fname, fdata)
            elif "octet-stream" in ct_req or (not ct_req and len(body) > 128):
                write_upload(ip, port, path, body)
        elif self.command == "PUT" and body:
            write_upload(ip, port, path, body)
        write_event(self.command, self.path, ip, port, self.headers, body, tags or None)
        resp, ct, code, extra = self._route(path)
        self._respond(resp, ct, code, extra)

    do_GET     = _handle
    do_POST    = _handle
    do_HEAD    = _handle
    do_OPTIONS = _handle
    do_PUT     = _handle
    do_DELETE  = _handle
    do_PATCH   = _handle

# ── Multi-port server ─────────────────────────────────────────────────────────

class ReusableServer(HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        super().server_bind()

def ensure_cert():
    if os.path.exists(CERT_F) and os.path.exists(KEY_F):
        return True
    try:
        import subprocess
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", KEY_F, "-out", CERT_F, "-days", "3650",
                        "-nodes", "-subj", "/CN=localhost"],
                       capture_output=True, check=True)
        return True
    except Exception as e:
        log.warning(f"TLS cert generation failed: {e}")
        return False

_servers = {}
_pending = set()   # ports currently being started (avoid duplicate threads)
_lock    = threading.Lock()

def load_ports():
    try:
        with open(CONFIG_F) as f:
            cfg = json.load(f)
        hp = cfg.get("http",  [8080])
        sp = cfg.get("https", [443])
        return ([int(p) for p in (hp if isinstance(hp, list) else [hp])],
                [int(p) for p in (sp if isinstance(sp, list) else [sp])])
    except Exception as e:
        log.warning(f"load_ports: {e}")
        return [8080], []

def _bind_worker(port, tls):
    """Runs in its own thread — never blocks the watcher or other ports."""
    label = "HTTPS" if tls else "HTTP"
    for attempt in range(5):
        try:
            srv = ReusableServer(("0.0.0.0", port), HoneypotHandler)
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(CERT_F, KEY_F)
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            with _lock:
                _servers[port] = srv
                _pending.discard(port)
            log.info(f"[+] {label} :{port}")
            return
        except PermissionError:
            log.warning(f":{port} permission denied — container needs CAP_NET_BIND_SERVICE")
            break   # retrying won't help
        except OSError as e:
            log.warning(f"{label} :{port} attempt {attempt+1}: {e}")
            if attempt < 4:
                time.sleep(2)
    with _lock:
        _pending.discard(port)
    log.error(f"giving up on {label} :{port}")

def start_server(port, tls=False):
    """Non-blocking — each port starts in its own thread."""
    with _lock:
        if port in _servers or port in _pending:
            return
        _pending.add(port)
    threading.Thread(target=_bind_worker, args=(port, tls), daemon=True).start()

def stop_server(port):
    with _lock:
        srv = _servers.pop(port, None)
    if srv:
        try: srv.shutdown()
        except Exception: pass

def sync_ports(http_p, https_p):
    wanted = {p: False for p in http_p}
    wanted.update({p: True for p in https_p})
    with _lock:
        to_stop  = list(set(_servers) - set(wanted))
        to_start = [(p, tls) for p, tls in wanted.items()
                    if p not in _servers and p not in _pending]
    for p in to_stop:
        stop_server(p)
    for p, tls in to_start:
        start_server(p, tls)

def watcher():
    last, first = ([], []), True
    while True:
        ports = load_ports()
        if ports != last or first:
            sync_ports(*ports)
            last, first = ports, False
        time.sleep(5)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    has_tls = ensure_cert()
    http_p, https_p = load_ports()
    if not has_tls:
        https_p = []
    sync_ports(http_p, https_p)
    watcher()
