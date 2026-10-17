# sqli-probe

**Detect SQL injection in login pages with one command.** A stdlib-only Python
tool that probes a login form with classic auth-bypass payloads, diffs the
responses against a baseline, and reports which payloads (if any) got through.

Two files:

- `sqli_probe.py` — the **detector**. Point it at a login page, it tells you if it's injectable.
- `sqli_login.py` — the **practice target**. A deliberately vulnerable login page (with the vulnerable line marked) so you have something honest to test against.

## Quick start

```bash
# terminal 1: start the practice target
python sqli_login.py            # serves http://127.0.0.1:5050

# terminal 2: fire the probe at it
python sqli_probe.py http://127.0.0.1:5050
```

Example output against the included vulnerable target:

```text
[*] form target : http://127.0.0.1:5050/login
[*] fields      : user='username', pass='password'
[*] baseline    : garbage creds -> status 200, length 890

payload                          status   length  signal
----------------------------------------------------------------
admin'--                          200      907  login echoed username  << POSSIBLE BYPASS
admin'#                           500      903  status 200->500  << POSSIBLE BYPASS
admin' or '1'='1                  200      907  login echoed username  << POSSIBLE BYPASS
admin"--                          200      890  same as baseline
' or 1=1--                        200      907  same as baseline
' or 1=1 #                        500      903  status 200->500  << POSSIBLE BYPASS
...
----------------------------------------------------------------

[!!] 8 payload(s) changed the response — input is probably reaching SQL unfiltered.
     Verify in a browser (login bypass) with:
       username: "admin'--"                   signal: login echoed username
```

## Usage

```bash
python sqli_probe.py <url> [--user-field uname] [--pass-field pwd]
```

| Argument | Meaning |
|---|---|
| `url` | Login page URL (the tool auto-derives the form action, and auto-detects field names from the HTML) |
| `--user-field` / `--pass-field` | Override field names if the form doesn't use obvious ones |

The form detection is plain regex (no dependencies, no JS rendering), which
covers most CTF/lamp-style login forms. For JS-rendered SPAs, pass the hidden
API endpoint manually if you know it.

## How the detection works

1. GET the page, regex out the `<form>` action and the first two visible `<input>` names.
2. POST garbage credentials → record the baseline response (status + length + error text).
3. Fire ~10 classic auth-bypass payloads into the username field.
4. Classify each response against the baseline:
   - **`login echoed username`** — the page now contains a username that didn't appear in baseline → the query returned a session (bypass).
   - **`status 200->500`** — DB error surfaced (error-based injection confirmed).
   - **`SERVER CRASHED on input`** — connection reset mid-request; input changed how the backend parsed SQL.
   - **`big body change`** — length diff > 40 chars from baseline.
5. Print a per-payload table + the top 3 "paste this in a browser" confirmations.

Detection is *behavioral*: no payloads that alter or delete data, no stacked
destructive queries, no exploit chains. It only observes whether the server's
response deviates when classic auth-bypass strings are tried.

## What it is not

- **Not sqlmap.** It doesn't enumerate databases, tables, or dump data — it's a fast go/no-go signal for auth-bypass SQLi on login forms, sized to a single file.
- **Not proof of safety.** "No classic bypass worked" ≠ not vulnerable. Blind/time-based/error-based injection happen deeper than this probe reaches.
- **Not an exploit tool.** It flags; you confirm manually in a browser.

## Requirements

- Python 3.10+ (no third-party packages — `urllib`, `sqlite3`, `re`, `http.server` only)
- The vulnerable target also needs nothing: it creates its own in-memory SQLite DB every run

## Ethics & scope

**Authorized targets only**: your own apps, CTF/THM/HackTheBox lab boxes, or
systems you have explicit written permission to test. The practice target
binds to `127.0.0.1` and touches nothing external. Default `User-Agent`
identifies itself as `sqli-probe (authorized lab use)`.

## License

MIT — see [LICENSE](LICENSE).
