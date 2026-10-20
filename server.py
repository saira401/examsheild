#!/usr/bin/env python3
"""ExamShield - online exam platform. Pure Python 3.10+ stdlib. Run: python3 server.py [port]"""
import base64, hashlib, json, os, queue, re, secrets, smtplib, sqlite3, sys, threading, time, zlib
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA = DB = None
SESS, SUBS = {}, []
SEV = {"tab_hidden": 2, "window_blur": 1, "copy": 2, "paste": 3, "fullscreen_exit": 2, "context_menu": 1, "devtools": 3}
FLAG_AT = 6
EXT = {"pdf", "txt", "md", "doc", "docx", "ppt", "pptx", "png", "jpg", "jpeg"}

def hpw(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 60000).hex()

def q(sql, *a, one=False):
    c = sqlite3.connect(DB, timeout=10); c.row_factory = sqlite3.Row
    try:
        r = c.execute(sql, a); r = r.fetchone() if one else r.fetchall(); c.commit()
    finally: c.close()
    return (dict(r) if r else None) if one else [dict(x) for x in r]

def ins(sql, *a):
    c = sqlite3.connect(DB, timeout=10)
    try:
        i = c.execute(sql, a).lastrowid; c.commit(); return i
    finally: c.close()

def add_user(u, p, role, name, parent=""):
    s = secrets.token_hex(8)
    return ins("INSERT INTO users(username,pw,salt,role,name,parent_email) VALUES(?,?,?,?,?,?)", u, hpw(p, s), s, role, name, parent)

def init(data_dir):
    global DATA, DB
    DATA = data_dir
    for d in ("uploads", "outbox"): os.makedirs(os.path.join(DATA, d), exist_ok=True)
    DB = os.path.join(DATA, "examshield.db")
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,pw TEXT,salt TEXT,role TEXT,name TEXT,parent_email TEXT);
    CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY,text TEXT,options TEXT,answer INT,topic TEXT,owner INT);
    CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY,title TEXT,qids TEXT,minutes INT,pass_pct INT,owner INT);
    CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY,exam_id INT,student_id INT,started REAL,finished REAL,score INT,total INT,status TEXT,answers TEXT,UNIQUE(exam_id,student_id));
    CREATE TABLE IF NOT EXISTS signals(id INTEGER PRIMARY KEY,attempt_id INT,kind TEXT,ts REAL,detail TEXT);
    CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY,title TEXT,topic TEXT,filename TEXT,stored TEXT,owner INT,ts REAL);
    CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,attempt_id INT,to_addr TEXT,subject TEXT,status TEXT,ts REAL);
    """); c.commit(); c.close()
    if not q("SELECT 1 FROM users LIMIT 1", one=True):
        add_user("admin", "admin123", "admin", "Administrator")
        add_user("teacher", "teacher123", "teacher", "Demo Teacher")
        add_user("student", "student123", "student", "Demo Student", "parent@example.com")

# ---------- PDF (hand-written) ----------
def esc(s): return s.encode("latin-1", "replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def make_pdf(lines):
    pages, cur, y = [], [], 800
    for size, bold, text in lines:
        if y < 50: pages.append(cur); cur, y = [], 800
        cur.append(f"BT /F{2 if bold else 1} {size} Tf 50 {y} Td ({esc(text)}) Tj ET"); y -= size + 6
    pages.append(cur)
    n = len(pages); objs = {1: b"<</Type/Catalog/Pages 2 0 R>>",
        2: ("<</Type/Pages/Count %d/Kids[%s]>>" % (n, " ".join(f"{5+2*i} 0 R" for i in range(n)))).encode(),
        3: b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>", 4: b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>"}
    for i, p in enumerate(pages):
        z = zlib.compress("\n".join(p).encode("latin-1"))
        objs[5+2*i] = f"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Resources<</Font<</F1 3 0 R/F2 4 0 R>>>>/Contents {6+2*i} 0 R>>".encode()
        objs[6+2*i] = b"<</Filter/FlateDecode/Length %d>>\nstream\n" % len(z) + z + b"\nendstream"
    out, offs = bytearray(b"%PDF-1.4\n"), {}
    for k in sorted(objs): offs[k] = len(out); out += b"%d 0 obj\n" % k + objs[k] + b"\nendobj\n"
    x = len(out); m = max(objs) + 1
    out += b"xref\n0 %d\n0000000000 65535 f \n" % m + b"".join(b"%010d 00000 n \n" % offs[k] for k in range(1, m))
    return bytes(out + b"trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (m, x))

# ---------- exam logic ----------
def risk(aid):
    s = q("SELECT kind FROM signals WHERE attempt_id=?", aid)
    return sum(SEV.get(x["kind"], 1) for x in s)

def grade(att, answers):
    exam = q("SELECT * FROM exams WHERE id=?", att["exam_id"], one=True); qids = json.loads(exam["qids"])
    sc = 0
    for qid in qids:
        r = q("SELECT answer FROM questions WHERE id=?", qid, one=True)
        if r and answers.get(str(qid)) == r["answer"]: sc += 1
    return sc, len(qids), exam

def report_pdf(aid):
    a = q("SELECT * FROM attempts WHERE id=?", aid, one=True)
    st = q("SELECT * FROM users WHERE id=?", a["student_id"], one=True)
    ex = q("SELECT * FROM exams WHERE id=?", a["exam_id"], one=True)
    ans = json.loads(a["answers"] or "{}"); pct = round(100 * a["score"] / max(a["total"], 1))
    L = [(20, 1, "ExamShield - Result Report"), (11, 0, ""), (12, 1, f"Student: {st['name']} ({st['username']})"), (12, 0, f"Exam: {ex['title']}"),
         (12, 0, f"Score: {a['score']}/{a['total']} ({pct}%)  -  {'PASS' if pct >= ex['pass_pct'] else 'FAIL'} (pass mark {ex['pass_pct']}%)"),
         (12, 0, f"Status: {a['status']}   Integrity risk score: {risk(aid)} {'(FLAGGED)' if risk(aid) >= FLAG_AT else ''}"), (11, 0, ""), (14, 1, "Question breakdown")]
    for i, qid in enumerate(json.loads(ex["qids"]), 1):
        qu = q("SELECT * FROM questions WHERE id=?", qid, one=True)
        if not qu: continue
        opts = json.loads(qu["options"]); g = ans.get(str(qid))
        L.append((10, 0, f"{i}. {qu['text'][:85]}")); L.append((10, 0, f"    Answered: {opts[g] if g is not None and g < len(opts) else '-'} | Correct: {opts[qu['answer']]} | {'OK' if g == qu['answer'] else 'WRONG'}"))
    L += [(11, 0, ""), (14, 1, "Proctoring signals")]
    sg = q("SELECT kind,ts,detail FROM signals WHERE attempt_id=? ORDER BY ts", aid)
    L += [(10, 0, f"{time.strftime('%H:%M:%S', time.localtime(s['ts']))}  {s['kind']}  {s['detail'] or ''}"[:100]) for s in sg] or [(10, 0, "None recorded")]
    return make_pdf(L)

def email_parent(aid):
    a = q("SELECT * FROM attempts WHERE id=?", aid, one=True); st = q("SELECT * FROM users WHERE id=?", a["student_id"], one=True)
    ex = q("SELECT * FROM exams WHERE id=?", a["exam_id"], one=True)
    if not st["parent_email"]: return "no-parent-email"
    pct = round(100 * a["score"] / max(a["total"], 1)); subj = f"{st['name']}'s result: {ex['title']} - {pct}%"
    m = EmailMessage(); m["Subject"], m["To"], m["From"] = subj, st["parent_email"], os.environ.get("SMTP_FROM", "examshield@localhost")
    m.set_content(f"Dear Parent,\n\n{st['name']} scored {a['score']}/{a['total']} ({pct}%) in '{ex['title']}' - "
                  f"{'PASS' if pct >= ex['pass_pct'] else 'FAIL'}. The detailed report is attached.\n\nExamShield")
    m.add_attachment(report_pdf(aid), maintype="application", subtype="pdf", filename=f"result_{aid}.pdf")
    status = "saved"
    if os.environ.get("SMTP_HOST"):
        try:
            with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 25)), timeout=15) as s:
                if os.environ.get("SMTP_USER"): s.starttls(); s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
                s.send_message(m); status = "sent"
        except Exception as e: status = f"smtp-failed:{e}"[:80]
    with open(os.path.join(DATA, "outbox", f"attempt{aid}_{int(time.time()*1000)}.eml"), "wb") as f: f.write(bytes(m))
    ins("INSERT INTO outbox(attempt_id,to_addr,subject,status,ts) VALUES(?,?,?,?,?)", aid, st["parent_email"], subj, status, time.time())
    return status

def publish(ev):
    for sq in list(SUBS): sq.put(ev)

# ---------- HTTP ----------
class Err(Exception):
    def __init__(s, code, msg): s.code, s.msg = code, msg

def need(b, *keys):
    for k in keys:
        if b.get(k) in (None, ""): raise Err(400, f"missing {k}")

def own_attempt(u, aid, active=False):
    a = q("SELECT * FROM attempts WHERE id=?", aid, one=True)
    if not a or (u["role"] == "student" and a["student_id"] != u["id"]): raise Err(404, "attempt not found")
    if active and a["status"] != "active": raise Err(409, "attempt not active")
    return a

class H(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def out(s, code, body, ct="application/json", hdr=()):
        if not isinstance(body, bytes): body = json.dumps(body).encode()
        s.send_response(code); s.send_header("Content-Type", ct); s.send_header("Content-Length", str(len(body)))
        for k, v in hdr: s.send_header(k, v)
        s.end_headers(); s.wfile.write(body)
    def me(s):
        m = re.search(r"sid=(\w+)", s.headers.get("Cookie", "")); v = SESS.get(m.group(1)) if m else None
        return v["u"] if v and v["exp"] > time.time() else None
    def handle_any(s, method):
        path = s.path.split("?")[0]
        try:
            n = int(s.headers.get("Content-Length") or 0)
            if n > 8_000_000: raise Err(413, "too large")
            body = json.loads(s.rfile.read(n) or b"{}") if n else {}
            if method == "GET" and path == "/": return s.out(200, INDEX.encode(), "text/html; charset=utf-8")
            for meth, rx, roles, fn in ROUTES:
                m = re.fullmatch(rx, path)
                if meth == method and m:
                    u = s.me()
                    if roles and not u: raise Err(401, "login required")
                    if roles and u["role"] not in roles: raise Err(403, "forbidden for role " + u["role"])
                    return fn(s, m, body, u)
            raise Err(404, "not found")
        except Err as e: s.out(e.code, {"error": e.msg})
        except (json.JSONDecodeError, ValueError, KeyError, TypeError) as e: s.out(400, {"error": f"bad request: {e}"})
        except (BrokenPipeError, ConnectionResetError): pass
        except Exception as e: s.out(500, {"error": str(e)})
    do_GET = lambda s: s.handle_any("GET")
    do_POST = lambda s: s.handle_any("POST")
    do_DELETE = lambda s: s.handle_any("DELETE")

# --- handlers: (handler, match, body, user)
def login(s, m, b, u):
    r = q("SELECT * FROM users WHERE username=?", b.get("username", ""), one=True)
    if not r or hpw(b.get("password", ""), r["salt"]) != r["pw"]: raise Err(401, "invalid credentials")
    t = secrets.token_hex(16); safe = {k: r[k] for k in ("id", "username", "role", "name")}; SESS[t] = {"u": safe, "exp": time.time() + 8 * 3600}
    s.out(200, safe, hdr=[("Set-Cookie", f"sid={t}; HttpOnly; SameSite=Strict; Path=/")])
def logout(s, m, b, u):
    c = re.search(r"sid=(\w+)", s.headers.get("Cookie", "")); c and SESS.pop(c.group(1), None); s.out(200, {"ok": True})
def whoami(s, m, b, u): s.out(200, u)
def users_list(s, m, b, u): s.out(200, q("SELECT id,username,role,name,parent_email FROM users"))
def users_add(s, m, b, u):
    need(b, "username", "password", "role", "name")
    if b["role"] not in ("admin", "teacher", "student"): raise Err(400, "bad role")
    if len(b["password"]) < 6: raise Err(400, "password too short")
    if q("SELECT 1 FROM users WHERE username=?", b["username"], one=True): raise Err(409, "username taken")
    s.out(201, {"id": add_user(b["username"], b["password"], b["role"], b["name"], b.get("parent_email", ""))})
def qs_list(s, m, b, u): s.out(200, [dict(r, options=json.loads(r["options"])) for r in q("SELECT * FROM questions")])
def qs_add(s, m, b, u):
    need(b, "text", "options", "answer")
    if not isinstance(b["options"], list) or len(b["options"]) < 2 or not isinstance(b["answer"], int) or not 0 <= b["answer"] < len(b["options"]): raise Err(400, "invalid options/answer")
    s.out(201, {"id": ins("INSERT INTO questions(text,options,answer,topic,owner) VALUES(?,?,?,?,?)", b["text"], json.dumps(b["options"]), b["answer"], b.get("topic", ""), u["id"])})
def qs_del(s, m, b, u):
    if q("SELECT 1 FROM exams WHERE qids LIKE ?", f"%{m[1]}%", one=True) and any(int(m[1]) in json.loads(e["qids"]) for e in q("SELECT qids FROM exams")): raise Err(409, "question used by an exam")
    q("DELETE FROM questions WHERE id=?", m[1]); s.out(200, {"ok": True})
def ex_add(s, m, b, u):
    need(b, "title", "qids", "minutes")
    if not b["qids"] or any(not q("SELECT 1 FROM questions WHERE id=?", i, one=True) for i in b["qids"]): raise Err(400, "unknown question ids")
    s.out(201, {"id": ins("INSERT INTO exams(title,qids,minutes,pass_pct,owner) VALUES(?,?,?,?,?)", b["title"], json.dumps(b["qids"]), int(b["minutes"]), int(b.get("pass_pct", 50)), u["id"])})
def ex_list(s, m, b, u):
    rows = q("SELECT id,title,minutes,pass_pct,qids FROM exams")
    for r in rows:
        r["count"] = len(json.loads(r.pop("qids")))
        if u["role"] == "student":
            a = q("SELECT id,status FROM attempts WHERE exam_id=? AND student_id=?", r["id"], u["id"], one=True); r["attempt"] = a
    s.out(200, rows)
def start(s, m, b, u):
    ex = q("SELECT * FROM exams WHERE id=?", m[1], one=True)
    if not ex: raise Err(404, "exam not found")
    if q("SELECT 1 FROM attempts WHERE exam_id=? AND student_id=?", ex["id"], u["id"], one=True): raise Err(409, "already attempted")
    aid = ins("INSERT INTO attempts(exam_id,student_id,started,status,answers) VALUES(?,?,?,?,?)", ex["id"], u["id"], time.time(), "active", "{}")
    qsn = [q("SELECT id,text,options FROM questions WHERE id=?", i, one=True) for i in json.loads(ex["qids"])]
    for x in qsn: x["options"] = json.loads(x["options"])  # answers never sent to students
    publish({"type": "started", "attempt": aid, "student": u["name"], "exam": ex["title"]})
    s.out(201, {"attempt": aid, "minutes": ex["minutes"], "title": ex["title"], "questions": qsn})
def signal(s, m, b, u):
    a = own_attempt(u, m[1], True); need(b, "kind")
    if b["kind"] not in SEV: raise Err(400, "unknown signal")
    ins("INSERT INTO signals(attempt_id,kind,ts,detail) VALUES(?,?,?,?)", a["id"], b["kind"], time.time(), str(b.get("detail", ""))[:200])
    r = risk(a["id"]); publish({"type": "signal", "attempt": a["id"], "student": u["name"], "kind": b["kind"], "risk": r, "flagged": r >= FLAG_AT}); s.out(200, {"risk": r})
def submit(s, m, b, u):
    a = own_attempt(u, m[1], True); ans = b.get("answers") or {}
    sc, tot, ex = grade(a, {str(k): v for k, v in ans.items()})
    late = time.time() > a["started"] + ex["minutes"] * 60 + 20
    q("UPDATE attempts SET finished=?,score=?,total=?,status=?,answers=? WHERE id=?", time.time(), sc, tot, "late" if late else "submitted", json.dumps(ans), a["id"])
    mail = email_parent(a["id"]); publish({"type": "finished", "attempt": a["id"], "student": u["name"], "score": sc, "total": tot})
    s.out(200, {"score": sc, "total": tot, "pass": 100 * sc >= ex["pass_pct"] * tot, "parent_email": mail})
def results(s, m, b, u):
    rows = q("SELECT a.id,u.name student,e.title exam,a.score,a.total,a.status,a.started FROM attempts a JOIN users u ON u.id=a.student_id JOIN exams e ON e.id=a.exam_id ORDER BY a.id DESC")
    for r in rows: r["risk"] = risk(r["id"]); r["flagged"] = r["risk"] >= FLAG_AT
    s.out(200, rows)
def my_results(s, m, b, u):
    s.out(200, q("SELECT a.id,e.title exam,a.score,a.total,a.status FROM attempts a JOIN exams e ON e.id=a.exam_id WHERE a.student_id=? AND a.status!='active'", u["id"]))
def pdf(s, m, b, u):
    a = own_attempt(u, m[1])
    if a["status"] == "active": raise Err(409, "attempt still active")
    s.out(200, report_pdf(a["id"]), "application/pdf", [("Content-Disposition", f'attachment; filename="report_{a["id"]}.pdf"')])
def resend(s, m, b, u): a = own_attempt(u, m[1], False); s.out(200, {"status": email_parent(a["id"])})
def note_add(s, m, b, u):
    need(b, "title", "filename", "data")
    ext = b["filename"].rsplit(".", 1)[-1].lower()
    if ext not in EXT: raise Err(400, "file type not allowed")
    raw = base64.b64decode(b["data"], validate=True)
    if len(raw) > 5_000_000: raise Err(413, "file over 5MB")
    stored = secrets.token_hex(4) + "_" + re.sub(r"[^\w.\-]", "_", os.path.basename(b["filename"]))
    with open(os.path.join(DATA, "uploads", stored), "wb") as f: f.write(raw)
    s.out(201, {"id": ins("INSERT INTO notes(title,topic,filename,stored,owner,ts) VALUES(?,?,?,?,?,?)", b["title"], b.get("topic", ""), b["filename"], stored, u["id"], time.time())})
def note_list(s, m, b, u): s.out(200, q("SELECT id,title,topic,filename,ts FROM notes ORDER BY id DESC"))
def note_get(s, m, b, u):
    n = q("SELECT * FROM notes WHERE id=?", m[1], one=True)
    if not n: raise Err(404, "no such note")
    with open(os.path.join(DATA, "uploads", n["stored"]), "rb") as f: d = f.read()
    s.out(200, d, "application/octet-stream", [("Content-Disposition", 'attachment; filename="%s"' % re.sub(r'[^\w.\-]', '_', n["filename"]))])
def note_del(s, m, b, u):
    n = q("SELECT * FROM notes WHERE id=?", m[1], one=True)
    if n:
        try: os.remove(os.path.join(DATA, "uploads", n["stored"]))
        except OSError: pass
        q("DELETE FROM notes WHERE id=?", m[1])
    s.out(200, {"ok": True})
def outbox(s, m, b, u): s.out(200, q("SELECT * FROM outbox ORDER BY id DESC"))
def stream(s, m, b, u):
    s.send_response(200); s.send_header("Content-Type", "text/event-stream"); s.send_header("Cache-Control", "no-cache"); s.end_headers()
    sq = queue.Queue(); SUBS.append(sq)
    try:
        s.wfile.write(b": connected\n\n"); s.wfile.flush()
        while True:
            try: s.wfile.write(f"data: {json.dumps(sq.get(timeout=15))}\n\n".encode())
            except queue.Empty: s.wfile.write(b": ping\n\n")
            s.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError): pass
    finally: SUBS.remove(sq)

TA, AD, ST, ANY = ("teacher", "admin"), ("admin",), ("student",), ("teacher", "admin", "student")
ROUTES = [("POST", r"/api/login", None, login), ("POST", r"/api/logout", ANY, logout), ("GET", r"/api/me", ANY, whoami),
    ("GET", r"/api/users", AD, users_list), ("POST", r"/api/users", AD, users_add),
    ("GET", r"/api/questions", TA, qs_list), ("POST", r"/api/questions", TA, qs_add), ("DELETE", r"/api/questions/(\d+)", TA, qs_del),
    ("GET", r"/api/exams", ANY, ex_list), ("POST", r"/api/exams", TA, ex_add), ("POST", r"/api/exams/(\d+)/start", ST, start),
    ("POST", r"/api/attempts/(\d+)/signal", ST, signal), ("POST", r"/api/attempts/(\d+)/submit", ST, submit),
    ("GET", r"/api/results", TA, results), ("GET", r"/api/my/results", ST, my_results),
    ("GET", r"/api/attempts/(\d+)/report\.pdf", ANY, pdf), ("POST", r"/api/attempts/(\d+)/email", TA, resend),
    ("GET", r"/api/notes", ANY, note_list), ("POST", r"/api/notes", TA, note_add), ("GET", r"/api/notes/(\d+)/file", ANY, note_get), ("DELETE", r"/api/notes/(\d+)", TA, note_del),
    ("GET", r"/api/outbox", TA, outbox), ("GET", r"/api/stream", TA, stream)]

def make_server(port=0, data_dir=None):
    init(data_dir or os.environ.get("EXAMSHIELD_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")))
    srv = ThreadingHTTPServer(("127.0.0.1", port), H); srv.daemon_threads = True; return srv

INDEX = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), encoding="utf-8").read()

if __name__ == "__main__":
    srv = make_server(int(sys.argv[1]) if len(sys.argv) > 1 else 8000)
    print(f"ExamShield on http://127.0.0.1:{srv.server_address[1]}  (admin/admin123, teacher/teacher123, student/student123)")
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
