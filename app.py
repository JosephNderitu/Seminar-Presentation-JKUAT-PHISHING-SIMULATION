from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from datetime import datetime
from collections import defaultdict
import uuid, random, pyotp, qrcode, io, base64

app = Flask(__name__)
app.secret_key = "demo-secret-key-jkuat-2025"

# ── In-memory stores ──────────────────────────────────────
captured_sessions  = []   # Obj 2: phishing captures
hardened_attempts  = {}   # Obj 3: { ip: [timestamps] }  for rate limiting
locked_ips         = {}   # Obj 3: { ip: locked_until_datetime }

# ── TOTP secret (same for demo — scan once, reuse) ────────
DEMO_TOTP_SECRET = "6C7J7BSFTEKPLLIGRASBGC5FOCBDRGIW"   # base32 pad to 20+ chars
TOTP_ISSUER      = "JKUAT Portal (Secured)"

# ── Synthetic student DB ──────────────────────────────────
FAKE_STUDENT_DB = {
    "SCT211-0001/2021": {
        "name": "Alice Wanjiku Kamau",
        "first": "Alice",
        "course": "BSc. Computer Science",
        "year": 3, "gpa": "3.72",
        "fee": "6,001.00",
        "units": [
            {"name": "Business Systems Modelling",  "code": "BIT 2212"},
            {"name": "Computer Architecture",       "code": "BCT 2408"},
            {"name": "Natural Language Processing", "code": "BCT 2411"},
            {"name": "Organization and Management", "code": "BCT 2407"},
            {"name": "Professional Issues in ICT",  "code": "BIT 2313"},
            {"name": "Project Management",          "code": "BCT 2409"},
            {"name": "Seminar Presentations",       "code": "BCT 2410"},
        ]
    },
    "SCT211-0002/2021": {
        "name": "Brian Otieno Ochieng",
        "first": "Brian",
        "course": "BSc. Computer Technology",
        "year": 3, "gpa": "3.41",
        "fee": "12,500.00",
        "units": [
            {"name": "Data Structures & Algorithms", "code": "BCT 2301"},
            {"name": "Operating Systems",            "code": "BCT 2302"},
            {"name": "Database Systems",             "code": "BCT 2303"},
            {"name": "Software Engineering",         "code": "BCT 2304"},
            {"name": "Computer Networks",            "code": "BCT 2305"},
            {"name": "Seminar Presentations",        "code": "BCT 2410"},
        ]
    },
    "SCT211-0003/2022": {
        "name": "Cynthia Muthoni Njoroge",
        "first": "Cynthia",
        "course": "BSc. Information Technology",
        "year": 2, "gpa": "3.85",
        "fee": "0.00",
        "units": [
            {"name": "Web Development",            "code": "BIT 2201"},
            {"name": "Systems Analysis & Design",  "code": "BIT 2202"},
            {"name": "Information Security",       "code": "BIT 2203"},
            {"name": "Human Computer Interaction", "code": "BIT 2204"},
            {"name": "Cloud Computing",            "code": "BIT 2205"},
            {"name": "Seminar Presentations",      "code": "BCT 2410"},
        ]
    },
    "SCT211-0004/2022": {
        "name": "David Kipchoge Rotich",
        "first": "David",
        "course": "BSc. Computer Science",
        "year": 2, "gpa": "2.98",
        "fee": "34,200.00",
        "units": [
            {"name": "Discrete Mathematics",   "code": "SCS 2201"},
            {"name": "Linear Algebra",         "code": "SCS 2202"},
            {"name": "Computer Organisation",  "code": "SCS 2203"},
            {"name": "Introduction to AI",     "code": "SCS 2204"},
            {"name": "Seminar Presentations",  "code": "BCT 2410"},
        ]
    },
    "SCT211-0005/2020": {
        "name": "Esther Achieng Odhiambo",
        "first": "Esther",
        "course": "BSc. Electrical Engineering",
        "year": 4, "gpa": "3.60",
        "fee": "8,750.50",
        "units": [
            {"name": "Power Systems",             "code": "EEE 4401"},
            {"name": "Control Systems",           "code": "EEE 4402"},
            {"name": "Digital Signal Processing", "code": "EEE 4403"},
            {"name": "Telecommunications",        "code": "EEE 4404"},
            {"name": "Final Year Project",        "code": "EEE 4410"},
            {"name": "Seminar Presentations",     "code": "BCT 2410"},
        ]
    },
}

# ════════════════════════════════════════════════════════════
#  OBJECTIVE 2 — Existing phishing simulation routes
# ════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/portal", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/portal/auth", methods=["POST"])
def authenticate():
    reg_no   = request.form.get("reg_no", "").strip().upper()
    password = request.form.get("password", "")
    ip       = request.remote_addr
    ua       = request.headers.get("User-Agent", "Unknown")
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    student  = FAKE_STUDENT_DB.get(reg_no)

    entry = {
        "id":          len(captured_sessions) + 1,
        "timestamp":   ts,
        "reg_no":      reg_no,
        "password":    password,
        "ip":          ip,
        "device":      _parse_device(ua),
        "browser":     _parse_browser(ua),
        "found":       student is not None,
        "student":     student,
        "geo":         {},
        "fingerprint": {},
        "photo":       None,
        "alerts":      [],   # populated by analyse_session()
    }
    captured_sessions.append(entry)
    return redirect(url_for("loading", entry_id=entry["id"]))

@app.route("/portal/loading/<int:entry_id>")
def loading(entry_id):
    return render_template("loading.html", entry_id=entry_id)

@app.route("/api/enrich/<int:entry_id>", methods=["POST"])
def enrich(entry_id):
    entry = next((e for e in captured_sessions if e["id"] == entry_id), None)
    if not entry:
        return jsonify({"error": "not found"}), 404
    data = request.get_json()
    entry["geo"]         = data.get("geo", {})
    entry["fingerprint"] = data.get("fingerprint", {})
    entry["photo"]       = data.get("photo", None)
    # Run detection engine once enrichment data arrives
    entry["alerts"]      = analyse_session(entry)
    return jsonify({"status": "ok"})

@app.route("/portal/dashboard-view/<int:entry_id>")
def fake_dashboard(entry_id):
    entry   = next((e for e in captured_sessions if e["id"] == entry_id), None)
    student = entry["student"] if entry and entry["found"] else None

    if student:
        name  = student["name"]
        first = student["first"]
        course = student["course"]
        fee   = student["fee"]
        units = student["units"]
    else:
        name, first = "Student", "Student"
        course = "BSc. Computer Technology"
        fee    = "6,001.00"
        units  = [
            {"name": "Business Systems Modelling",  "code": "BIT 2212"},
            {"name": "Computer Architecture",       "code": "BCT 2408"},
            {"name": "Natural Language Processing", "code": "BCT 2411"},
            {"name": "Organization and Management", "code": "BCT 2407"},
            {"name": "Professional Issues in ICT",  "code": "BIT 2313"},
            {"name": "Project Management",          "code": "BCT 2409"},
            {"name": "Seminar Presentations",       "code": "BCT 2410"},
        ]

    has_photo = entry and entry.get("photo") is not None
    return render_template("fake_dashboard.html",
        entry_id      = entry_id,
        student_name  = name,
        student_first = first,
        course        = course,
        fee_balance   = fee,
        units         = units,
        has_photo     = has_photo,
    )

@app.route("/portal/awareness/<int:entry_id>")
def awareness(entry_id):
    entry = next((e for e in captured_sessions if e["id"] == entry_id), None)
    return render_template("awareness.html", entry=entry)

# ── Attacker C2 dashboard (Obj 2) ─────────────────────────
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/captures")
def api_captures():
    return jsonify(captured_sessions)

@app.route("/api/reset", methods=["POST"])
def reset():
    captured_sessions.clear()
    hardened_attempts.clear()
    locked_ips.clear()
    return jsonify({"status": "cleared"})

# ════════════════════════════════════════════════════════════
#  OBJECTIVE 3A — SOC Detection Dashboard
# ════════════════════════════════════════════════════════════

@app.route("/soc")
def soc_dashboard():
    return render_template("soc_dashboard.html")

@app.route("/api/alerts")
def api_alerts():
    """
    Returns all alerts generated across all captured sessions.
    Each alert: { id, session_id, rule, severity, title,
                  description, timestamp, ip, evidence }
    """
    all_alerts = []
    for entry in captured_sessions:
        alerts = entry.get("alerts") or analyse_session(entry)
        all_alerts.extend(alerts)
    # Also include hardened portal blocked attempts
    all_alerts.extend(_hardened_alerts)
    all_alerts.sort(key=lambda a: a["timestamp"])
    return jsonify(all_alerts)

@app.route("/api/soc-stats")
def api_soc_stats():
    """Aggregated stats for the SOC dashboard header cards."""
    all_alerts = []
    for entry in captured_sessions:
        all_alerts.extend(entry.get("alerts", []))
    all_alerts.extend(_hardened_alerts)

    return jsonify({
        "total_captures":  len(captured_sessions),
        "total_alerts":    len(all_alerts),
        "critical":        sum(1 for a in all_alerts if a["severity"] == "CRITICAL"),
        "high":            sum(1 for a in all_alerts if a["severity"] == "HIGH"),
        "medium":          sum(1 for a in all_alerts if a["severity"] == "MEDIUM"),
        "cameras_taken":   sum(1 for e in captured_sessions if e.get("photo")),
        "blocked_attempts": len(_hardened_alerts),
        "unique_ips":      len(set(e["ip"] for e in captured_sessions)),
    })

# ════════════════════════════════════════════════════════════
#  OBJECTIVE 3B — Hardened Portal
# ════════════════════════════════════════════════════════════

# In-memory store for hardened portal alerts
_hardened_alerts = []

@app.route("/hardened")
def hardened_login():
    return render_template("hardened_login.html")

@app.route("/hardened/auth", methods=["POST"])
def hardened_auth():
    """
    Step 1 of 2: validate credentials.
    If correct, issue a session token and redirect to MFA step.
    If IP is locked out or rate-limited, show blocked page.
    """
    ip       = request.remote_addr
    reg_no   = request.form.get("reg_no", "").strip().upper()
    password = request.form.get("password", "")
    ts       = datetime.now()
    ts_str   = ts.strftime("%Y-%m-%d %H:%M:%S")

    # ── Security headers helper (applied via after_request) ──

    # ── 1. Check lockout ──
    if ip in locked_ips:
        lock_until = locked_ips[ip]
        if ts < lock_until:
            _add_hardened_alert("LOCKOUT_ENFORCED", "CRITICAL",
                "Account locked — repeated failed attempts",
                f"IP {ip} attempted login while under lockout. "
                f"Locked until {lock_until.strftime('%H:%M:%S')}.",
                ip, ts_str,
                evidence={"reg_no": reg_no, "ip": ip})
            return render_template("hardened_blocked.html",
                reason="lockout",
                ip=ip,
                unlock_time=lock_until.strftime("%H:%M:%S"),
                reg_no=reg_no)
        else:
            del locked_ips[ip]   # lock expired

    # ── 2. Rate limiting: max 3 attempts per 60s ──
    now_ts = ts.timestamp()
    attempts = hardened_attempts.get(ip, [])
    # Keep only attempts in the last 60 seconds
    attempts = [t for t in attempts if now_ts - t < 60]
    attempts.append(now_ts)
    hardened_attempts[ip] = attempts

    if len(attempts) > 3:
        # Lock for 5 minutes
        from datetime import timedelta
        locked_ips[ip] = ts + timedelta(minutes=5)
        _add_hardened_alert("BRUTE_FORCE_BLOCKED", "CRITICAL",
            "Brute force detected — IP locked out",
            f"IP {ip} made {len(attempts)} login attempts in 60 seconds. "
            f"Account locked for 5 minutes.",
            ip, ts_str,
            evidence={"reg_no": reg_no, "attempts": len(attempts), "window": "60s"})
        return render_template("hardened_blocked.html",
            reason="brute_force",
            ip=ip,
            attempts=len(attempts),
            reg_no=reg_no)

    # ── 3. Validate credentials ──
    student = FAKE_STUDENT_DB.get(reg_no)
    # For demo: any password accepted for known reg numbers
    # In a real system this would be a proper hash check
    if not student:
        _add_hardened_alert("UNKNOWN_REG_NO", "MEDIUM",
            "Login attempt with unrecognised registration number",
            f"IP {ip} attempted to log in with unknown reg no: {reg_no}.",
            ip, ts_str,
            evidence={"reg_no": reg_no})
        return render_template("hardened_login.html",
            error="Invalid registration number or password.",
            reg_no=reg_no)

    # ── 4. Credentials valid — issue session, go to MFA ──
    session["pending_reg_no"] = reg_no
    session["pending_ip"]     = ip
    session["mfa_ts"]         = ts_str
    return redirect(url_for("hardened_mfa"))

@app.route("/hardened/mfa", methods=["GET"])
def hardened_mfa():
    reg_no = session.get("pending_reg_no")
    if not reg_no:
        return redirect(url_for("hardened_login"))

    # Generate QR code for TOTP (shown once on first visit)
    totp     = pyotp.TOTP(DEMO_TOTP_SECRET)
    otp_uri  = totp.provisioning_uri(name=reg_no, issuer_name=TOTP_ISSUER)
    qr_img   = qrcode.make(otp_uri)
    buf      = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64   = base64.b64encode(buf.getvalue()).decode()

    return render_template("hardened_mfa.html",
        reg_no   = reg_no,
        qr_code  = qr_b64,
        otp_uri  = otp_uri)

@app.route("/hardened/mfa", methods=["POST"])
def hardened_mfa_verify():
    reg_no = session.get("pending_reg_no")
    if not reg_no:
        return redirect(url_for("hardened_login"))

    otp_input = request.form.get("otp_code", "").strip()
    ip        = request.remote_addr
    ts_str    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    totp       = pyotp.TOTP(DEMO_TOTP_SECRET)
    valid      = totp.verify(otp_input, valid_window=1)
    # Demo bypass — allow "000000" for presentation fallback
    if otp_input == "000000":
        valid = True

    if not valid:
        _add_hardened_alert("MFA_FAILURE", "HIGH",
            "MFA verification failed",
            f"Incorrect TOTP code entered for {reg_no} from IP {ip}.",
            ip, ts_str,
            evidence={"reg_no": reg_no, "otp_entered": otp_input})
        return render_template("hardened_mfa.html",
            reg_no  = reg_no,
            qr_code = None,
            otp_uri = None,
            error   = "Incorrect code. Please try again.")

    # ── MFA passed — full authentication successful ──
    session["authenticated_reg_no"] = reg_no
    session.pop("pending_reg_no", None)

    student = FAKE_STUDENT_DB[reg_no]
    return render_template("hardened_success.html",
        student_first = student["first"],
        student_name  = student["name"],
        course        = student["course"],
        reg_no        = reg_no,
        ip            = ip,
        timestamp     = ts_str)

@app.route("/hardened/blocked")
def hardened_blocked():
    return render_template("hardened_blocked.html",
        reason="manual", ip=request.remote_addr,
        reg_no="", attempts=0)

# ════════════════════════════════════════════════════════════
#  DETECTION ENGINE — analyse_session()
# ════════════════════════════════════════════════════════════

def analyse_session(entry):
    """
    Runs all 6 detection rules against a captured session.
    Returns a list of alert dicts.
    """
    alerts  = []
    ip      = entry.get("ip", "")
    ts      = entry.get("timestamp", "")
    fp      = entry.get("fingerprint", {})
    geo     = entry.get("geo", {})
    reg_no  = entry.get("reg_no", "")
    sid     = entry.get("id", 0)

    # ── RULE 1: CRED_HARVEST — always fires on any capture ──
    alerts.append(_make_alert(
        rule        = "CRED_HARVEST",
        severity    = "CRITICAL",
        title       = "Credential harvest detected",
        description = (f"Registration number {reg_no} and plaintext password captured "
                       f"from IP {ip} via phishing portal. "
                       f"Credentials immediately usable for account takeover."),
        ip          = ip,
        ts          = ts,
        session_id  = sid,
        evidence    = {
            "reg_no":   reg_no,
            "password": entry.get("password", ""),
            "device":   entry.get("device", ""),
            "browser":  entry.get("browser", ""),
        }
    ))

    # ── RULE 2: BRUTE_FORCE — 3+ attempts from same IP ──
    same_ip_count = sum(1 for e in captured_sessions if e.get("ip") == ip)
    if same_ip_count >= 3:
        alerts.append(_make_alert(
            rule        = "BRUTE_FORCE",
            severity    = "HIGH",
            title       = "Brute force pattern detected",
            description = (f"IP {ip} has submitted {same_ip_count} credential attempts. "
                           f"Possible automated credential stuffing or repeated manual attempts."),
            ip          = ip,
            ts          = ts,
            session_id  = sid,
            evidence    = {"ip": ip, "attempt_count": same_ip_count}
        ))

    # ── RULE 3: GEO_ANOMALY — non-Kenyan ISP or unexpected region ──
    if geo and not geo.get("error"):
        country = geo.get("country", "")
        isp     = geo.get("isp", "")
        city    = geo.get("city", "")
        if country and country.lower() not in ("kenya", ""):
            alerts.append(_make_alert(
                rule        = "GEO_ANOMALY",
                severity    = "HIGH",
                title       = "Geographic anomaly — foreign origin",
                description = (f"Login attempt originated from {city}, {country} "
                               f"via ISP: {isp}. Expected origin: Kenya. "
                               f"Possible VPN, proxy, or nation-state actor."),
                ip          = ip,
                ts          = ts,
                session_id  = sid,
                evidence    = {"country": country, "city": city, "isp": isp,
                               "lat": geo.get("lat"), "lon": geo.get("lon")}
            ))

    # ── RULE 4: CAM_CAPTURE — camera photo obtained ──
    if entry.get("photo"):
        alerts.append(_make_alert(
            rule        = "CAM_CAPTURE",
            severity    = "HIGH",
            title       = "Unauthorised camera capture",
            description = (f"Front-facing camera image captured from device at IP {ip} "
                           f"via getUserMedia API disguised as a security verification step. "
                           f"Biometric data transmitted to attacker server without consent."),
            ip          = ip,
            ts          = ts,
            session_id  = sid,
            evidence    = {"photo_captured": True, "method": "getUserMedia disguised as CAPTCHA"}
        ))

    # ── RULE 5: FINGERPRINT — device uniqueness > 85% ──
    uniqueness = fp.get("uniqueness", 0)
    if uniqueness and int(uniqueness) > 85:
        alerts.append(_make_alert(
            rule        = "FINGERPRINT",
            severity    = "MEDIUM",
            title       = "High-confidence device fingerprint acquired",
            description = (f"Passive browser fingerprint collected with {uniqueness}% uniqueness score. "
                           f"Device identifiable across all sessions without cookies. "
                           f"OS: {fp.get('platform','?')}, Screen: {fp.get('screen','?')}, "
                           f"TZ: {fp.get('timezone','?')}."),
            ip          = ip,
            ts          = ts,
            session_id  = sid,
            evidence    = {
                "uniqueness":  uniqueness,
                "platform":    fp.get("platform"),
                "screen":      fp.get("screen"),
                "timezone":    fp.get("timezone"),
                "canvas_hash": fp.get("canvas_hash"),
                "cores":       fp.get("cores"),
                "memory":      fp.get("memory"),
            }
        ))

    # ── RULE 6: OFF_HOURS — login outside 06:00–22:00 ──
    try:
        hour = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").hour
        if hour < 6 or hour >= 22:
            alerts.append(_make_alert(
                rule        = "OFF_HOURS",
                severity    = "MEDIUM",
                title       = "Off-hours access attempt",
                description = (f"Login attempt recorded at {ts} (hour {hour}:00), "
                               f"outside normal operating hours (06:00–22:00). "
                               f"Could indicate automated attack or targeted intrusion."),
                ip          = ip,
                ts          = ts,
                session_id  = sid,
                evidence    = {"hour": hour, "timestamp": ts}
            ))
    except Exception:
        pass

    return alerts

def _make_alert(rule, severity, title, description, ip, ts, session_id, evidence):
    return {
        "id":          f"{rule}-{session_id}-{ts}",
        "session_id":  session_id,
        "rule":        rule,
        "severity":    severity,
        "title":       title,
        "description": description,
        "ip":          ip,
        "timestamp":   ts,
        "evidence":    evidence,
    }

def _add_hardened_alert(rule, severity, title, description, ip, ts, evidence=None):
    _hardened_alerts.append(_make_alert(
        rule        = rule,
        severity    = severity,
        title       = title,
        description = description,
        ip          = ip,
        ts          = ts,
        session_id  = f"H{len(_hardened_alerts)+1}",
        evidence    = evidence or {},
    ))

# ════════════════════════════════════════════════════════════
#  SECURITY HEADERS — applied to all responses
# ════════════════════════════════════════════════════════════

@app.after_request
def add_security_headers(response):
    """
    Applied to ALL routes.
    On the hardened portal these headers are meaningful defences.
    On the phishing portal they are intentionally absent (for demo contrast).
    """
    if request.path.startswith("/hardened"):
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com 'unsafe-inline'; "
            "img-src 'self' data: https://portal.jkuat.ac.ke; "
            "font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com;"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════

def _parse_device(ua):
    ua = ua.lower()
    if "mobile" in ua or "android" in ua: return "Mobile"
    if "tablet" in ua or "ipad" in ua:    return "Tablet"
    return "Desktop"

def _parse_browser(ua):
    u = ua.lower()
    if "edg" in u:     return "Edge"
    if "chrome" in u:  return "Chrome"
    if "firefox" in u: return "Firefox"
    if "safari" in u:  return "Safari"
    return "Unknown"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)