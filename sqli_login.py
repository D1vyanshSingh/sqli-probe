"""
sqli_login.py — deliberately vulnerable login page, single file, stdlib only.

USAGE:
    python sqli_login.py            (binds http://127.0.0.1:5050 — loopback only)

TEST PAYLOADS (type these into the username box):
    admin' --                       → logs in as admin (password ignored)
    ' OR 1=1 --                     → logs in as first user in table
    admin' AND '1'='1               → classic true condition
    admin' AND '1'='2               → false condition (compare the difference)

The vulnerable line is marked with "***" below — read it first, it's 1 line.
LAB USE ONLY. Binds to 127.0.0.1, no external network. Educated-understanding
of SQLi is the point; use against things you are authorized to attack only.
"""

import sqlite3
import http.server
import urllib.parse

PORT = 5050

# seed data: recreated fresh every run, so nothing persists
SEED = [("admin", "supersecret123"), ("dev", "d3vpass"), ("guest", "guestpass")]

PAGE = """<!doctype html>
<html><head><title>Corp Login</title><style>
  body {{ font-family: sans-serif; background:#1a1a1e; color:#e5e5e5;
         display:flex; justify-content:center; padding-top:80px; }}
  form {{ background:#26262c; padding:40px; border-radius:10px; width:320px; }}
  input {{ display:block; width:100%; margin:10px 0; padding:10px;
           border:1px solid #444; border-radius:5px; background:#1a1a1e; color:#eee; }}
  button {{ width:100%; padding:10px; background:#5a6cff; color:white;
            border:0; border-radius:5px; cursor:pointer; }}
  .err {{ color:#ff6b6b; }}
  .ok  {{ color:#4ce59f; }}
</style></head><body>
<form method="post" action="/login">
  <h2>Corp Portal</h2>
  {message}
  <input name=username placeholder="Username">
  <input name=password placeholder="Password" type="password">
  <button>Log in</button>
</form></body></html>"""


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.executemany("INSERT INTO users VALUES (?,?)", SEED)
    return conn


def login(user, password):
    """???Login check. Returns True if credentials accepted."""
    conn = get_db()
    try:
        # *** THE VULNERABLE LINE *** — string-formatting user input straight
        # into SQL. This is real-world CVE-shaped code on purpose, so you can
        # practice auth bypass against it. No parameter binding here. Ever.
        query = f"SELECT username FROM users WHERE username='{user}' " \
                f"AND password='{password}'"
        row = conn.execute(query).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


class Handler(http.server.BaseHTTPRequestHandler):
    def _html(self, message="<p>Enter your credentials.</p>", code=200):
        body = PAGE.format(message=message).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._html()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        user = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]
        if not user and not password:
            self._html("<p class='err'>Type something, hacker.</p>")
            return
        try:
            who = login(user, password)
        except sqlite3.OperationalError as exc:
            # vulnerable apps leak DB errors — this also enables error-based SQLi
            self._html(f"<p class='err'>DB error: {exc}</p>", code=500)
            return
        if who:
            self._html(f"<p class='ok'>Welcome <b>{who}</b>! Session granted.</p>")
        else:
            self._html("<p class='err'>Invalid credentials.</p>")


if __name__ == "__main__":
    print(f"sqli_login — vulnerable login page on http://127.0.0.1:{PORT}")
    print("Payloads are in the file header comment. Lab use only.")
    # loopback bind only — never 0.0.0.0
    http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
