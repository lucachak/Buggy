# dirb-like

A web directory brute-force scanner written in **pure Python** — zero external dependencies.

Built as a deliberate exercise in understanding what tools like DIRB and Gobuster actually do under the hood, before trusting them blindly. Every layer of the HTTP/HTTPS stack is implemented from scratch against the RFC spec — no `requests`, no `httpx`, nothing from PyPI.

---

## What it does

Sends HTTP/HTTPS requests to a target URL, appending words from a wordlist to discover hidden directories and files on web servers. This is a standard technique used in web application security assessments and CTF recon phases.

```
[200] http://target.com/admin
[200] http://target.com/backup
[403] http://target.com/.env
[301] http://target.com/dashboard
[404] http://target.com/notfound  (skipped)
```

---

## Why build it from scratch?

Most people install Gobuster or DIRB and run it. That's fine for pentesting, but it tells you nothing about *how* it works.

By implementing the HTTP client manually — parsing status lines, handling redirects, managing socket connections, dealing with TLS — you understand exactly what's happening on the wire. That understanding matters when the tool misbehaves, when you need to customize behavior, or when you're on the defensive side trying to detect this kind of traffic.

---

## Features

- HTTP and HTTPS support (TLS handled via `ssl` stdlib)
- Custom wordlist support
- Configurable status code filtering
- Concurrent scanning with Python's `threading` module
- Clean, color-coded terminal output
- Zero external dependencies — runs anywhere Python 3 does

---

## Usage

```bash
# Basic scan
python dirpy.py -u http://target.com -w wordlist.txt

# HTTPS target
python dirpy.py -u https://target.com -w wordlist.txt

# Filter specific status codes
python dirpy.py -u http://target.com -w wordlist.txt -s 200,301,403

# Set thread count
python dirpy.py -u http://target.com -w wordlist.txt -t 20
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL | required |
| `-w` | Path to wordlist | required |
| `-s` | Status codes to show (comma-separated) | `200,301,302,403` |
| `-t` | Number of threads | `10` |
| `-o` | Output file | none |

---

## Wordlists

This tool doesn't ship a wordlist. Recommended sources:

- [SecLists](https://github.com/danielmiessler/SecLists) — `Discovery/Web-Content/common.txt` is a good starting point
- [dirb's built-in wordlists](https://github.com/v0re/dirb/tree/master/wordlists)

---

## How the HTTP stack works

Instead of using `requests`, this tool builds raw HTTP/1.1 requests using Python's `socket` and `ssl` modules:

```python
# Raw GET request construction
request = f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
sock.sendall(request.encode())
response = b""
while chunk := sock.recv(4096):
    response += chunk
```

Status codes are parsed by reading the first line of the response and splitting on whitespace — no magic, no abstraction.

For HTTPS, the socket is wrapped with `ssl.create_default_context()` before the handshake, which handles certificate verification and TLS negotiation transparently.

---

## Disclaimer

This tool is intended for **authorized security testing only** — CTFs, lab environments (HackTheBox, TryHackMe, DVWA), and systems you own or have explicit written permission to test.

Scanning systems without authorization is illegal in most jurisdictions. The author is not responsible for misuse.

---

## What I learned building this

- How HTTP/1.1 request/response structure actually works at the byte level
- How TLS wrapping integrates with raw sockets
- Why connection pooling matters (and what the cost of not having it is)
- How to implement basic concurrency with threads without race conditions on shared state
- Why tools like `requests` exist — and exactly what complexity they're hiding

---

## Author

**Lucas Lucachak** — [github.com/lucachak](https://github.com/lucachak) · [portfolio](https://portifolio-vercel-inky.vercel.app)
