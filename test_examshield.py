import base64, json, os, tempfile, threading, unittest, urllib.request, urllib.error, glob
import server

class C:
    def __init__(s, base): s.base, s.ck = base, ""
    def req(s, method, path, body=None, raw=False):
        r = urllib.request.Request(s.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                   headers={"Content-Type": "application/json", "Cookie": s.ck})
        try:
            with urllib.request.urlopen(r) as x:
                if x.headers.get("Set-Cookie"): s.ck = x.headers["Set-Cookie"].split(";")[0]
                d = x.read(); return x.status, (d if raw else json.loads(d))
        except urllib.error.HTTPError as e: return e.code, (e.read() if raw else json.loads(e.read()))
    def login(s, u, p): return s.req("POST", "/api/login", {"username": u, "password": p})

class T(unittest.TestCase):
    @classmethod
    def setUpClass(c):
        c.tmp = tempfile.mkdtemp(); c.srv = server.make_server(0, c.tmp)
        threading.Thread(target=c.srv.serve_forever, daemon=True).start()
        c.base = f"http://127.0.0.1:{c.srv.server_address[1]}"
    @classmethod
    def tearDownClass(c): c.srv.shutdown()
    def cl(s, u, p):
        c = C(s.base); assert c.login(u, p)[0] == 200; return c

    def test_1_auth_and_roles(self):
        self.assertEqual(C(self.base).login("teacher", "bad")[0], 401)
        self.assertEqual(C(self.base).req("GET", "/api/exams")[0], 401)
        st = self.cl("student", "student123"); te = self.cl("teacher", "teacher123")
        self.assertEqual(st.req("POST", "/api/questions", {"text": "x", "options": ["a", "b"], "answer": 0})[0], 403)
        self.assertEqual(te.req("GET", "/api/users")[0], 403)
        self.assertEqual(st.req("POST", "/api/notes", {"title": "t", "filename": "a.txt", "data": ""})[0], 403)
        ad = self.cl("admin", "admin123")
        self.assertEqual(ad.req("POST", "/api/users", {"username": "kid2", "password": "secret1", "role": "student", "name": "Kid Two", "parent_email": "p2@example.com"})[0], 201)
        self.assertEqual(ad.req("POST", "/api/users", {"username": "kid2", "password": "secret1", "role": "student", "name": "x"})[0], 409)

    def test_2_full_exam_flow(self):
        te = self.cl("teacher", "teacher123"); st = self.cl("student", "student123")
        self.assertEqual(te.req("POST", "/api/questions", {"text": "bad", "options": ["a", "b"], "answer": 5})[0], 400)
        ids = [te.req("POST", "/api/questions", {"text": f"2+{i}=?", "options": ["2", "3", "4", "5"], "answer": i + 0 if i < 3 else 0, "topic": "math"})[1]["id"] for i in range(1, 4)]
        eid = te.req("POST", "/api/exams", {"title": "Math Quiz", "qids": ids, "minutes": 5, "pass_pct": 60})[1]["id"]
        # live stream
        got = []
        def listen():
            r = urllib.request.Request(self.base + "/api/stream", headers={"Cookie": te.ck})
            with urllib.request.urlopen(r) as x:
                for line in x:
                    if line.startswith(b"data:"): got.append(json.loads(line[5:])); 
                    if len(got) >= 3: return
        th = threading.Thread(target=listen, daemon=True); th.start()
        import time; time.sleep(0.5)
        code, a = st.req("POST", f"/api/exams/{eid}/start")
        self.assertEqual(code, 201); self.assertTrue(all("answer" not in q for q in a["questions"]))
        self.assertEqual(st.req("POST", f"/api/exams/{eid}/start")[0], 409)
        for k in ("tab_hidden", "paste", "copy"): self.assertEqual(st.req("POST", f"/api/attempts/{a['attempt']}/signal", {"kind": k})[0], 200)
        self.assertEqual(st.req("POST", f"/api/attempts/{a['attempt']}/signal", {"kind": "nope"})[0], 400)
        self.assertEqual(st.req("GET", f"/api/attempts/{a['attempt']}/report.pdf")[0], 409)
        qs = {q["id"]: q for q in te.req("GET", "/api/questions")[1]}
        ans = {str(i): qs[i]["answer"] for i in ids[:2]}; ans[str(ids[2])] = (qs[ids[2]]["answer"] + 1) % 4
        code, r = st.req("POST", f"/api/attempts/{a['attempt']}/submit", {"answers": ans})
        self.assertEqual((code, r["score"], r["total"], r["pass"]), (200, 2, 3, True))
        self.assertEqual(r["parent_email"], "saved")
        self.assertEqual(st.req("POST", f"/api/attempts/{a['attempt']}/submit", {"answers": ans})[0], 409)
        th.join(5); kinds = [e["type"] for e in got]; self.assertIn("started", kinds); self.assertIn("signal", kinds)
        # risk + flagging
        res = te.req("GET", "/api/results")[1][0]; self.assertEqual(res["risk"], 7); self.assertTrue(res["flagged"])
        # PDF
        code, pdf = st.req("GET", f"/api/attempts/{a['attempt']}/report.pdf", raw=True)
        self.assertTrue(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"))
        # parent email saved with PDF attachment
        eml = open(glob.glob(os.path.join(self.tmp, "outbox", "*.eml"))[0], "rb").read()
        self.assertIn(b"parent@example.com", eml); self.assertIn(b"application/pdf", eml)
        self.assertEqual(te.req("POST", f"/api/attempts/{a['attempt']}/email")[1]["status"], "saved")
        self.assertEqual(len(te.req("GET", "/api/outbox")[1]), 2)

    def test_3_notes_upload(self):
        te = self.cl("teacher", "teacher123"); st = self.cl("student", "student123")
        data = os.urandom(300)
        code, n = te.req("POST", "/api/notes", {"title": "Algebra", "topic": "math", "filename": "../al ge.pdf", "data": base64.b64encode(data).decode()})
        self.assertEqual(code, 201)
        self.assertEqual(te.req("POST", "/api/notes", {"title": "x", "filename": "evil.exe", "data": "QQ=="})[0], 400)
        self.assertEqual(st.req("GET", "/api/notes")[1][0]["title"], "Algebra")
        self.assertEqual(st.req("GET", f"/api/notes/{n['id']}/file", raw=True)[1], data)
        self.assertTrue(all(os.path.dirname(f) == os.path.join(self.tmp, "uploads") for f in glob.glob(os.path.join(self.tmp, "uploads", "*"))))

    def test_4_pages(self):
        with urllib.request.urlopen(self.base + "/") as x: self.assertIn(b"ExamShield", x.read())

    def test_5_pdf_multipage(self):
        p = server.make_pdf([(10, 0, f"line {i} (paren) \\ back") for i in range(200)])
        self.assertGreaterEqual(p.count(b"/Type/Page/"), 3)

if __name__ == "__main__": unittest.main(verbosity=2)
