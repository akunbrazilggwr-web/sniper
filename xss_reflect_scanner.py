#!/usr/bin/env python3
from __future__ import annotations
import argparse, ipaddress, os, socket
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import html as htmlmod
import re
try:
    import requests
except ImportError:
    print("Dependency missing: requests\nInstall with: python -m pip install requests")
    raise SystemExit(2)

BANNER = r"""
▄▀▀▀ █▄  █ ▀█▀ █▀▀▄ █▀▀▀ █▀▀▄
 ▀▀▄ █ ▀▄█  █  █▀▀  █▀▀  █▀█
▀▀▀  ▀   ▀ ▀▀▀ ▀    ▀▀▀▀ ▀  ▀
                         create by Rahman
"""
DEFAULT_PAYLOAD_FILE = Path(__file__).with_name("All-In-One.txt")
TIMEOUT, MAX_BODY = 10, 2_000_000
USER_AGENT = "Authorized-Reflected-XSS-Checker/1.0"

def load_payloads(path):
    if not path.exists(): raise FileNotFoundError(f"Payload file not found: {path}")
    seen, out = set(), []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        p = raw.strip()
        if p and p not in seen: seen.add(p); out.append(p)
    return out

def is_loopback_host(host):
    if not host: return False
    h = host.lower().strip("[]")
    if h in {"localhost", "localhost.localdomain"}: return True
    try: return ipaddress.ip_address(h).is_loopback
    except ValueError:
        try:
            infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
            return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_loopback for i in infos)
        except OSError: return False

def safety_check(url):
    p = urlparse(url)
    if p.scheme not in {"http","https"} or not p.netloc:
        raise ValueError("URL harus diawali http:// atau https://")
    if not is_loopback_host(p.hostname or "") and os.getenv("ALLOW_REMOTE_TARGETS") != "1":
        raise PermissionError("Target remote diblokir default. Gunakan localhost/loopback untuk lab.")

def request(session, url):
    r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    return r, r.text[:MAX_BODY]

def reflected(body, payload):
    vals = {payload}
    try: vals.add(htmlmod.unescape(payload))
    except Exception: pass
    return any(v and v in body for v in vals)

def discover_parameters(session, base_url, max_links=50):
    safety_check(base_url)
    seen, queue, params = {base_url}, [base_url], set()
    host = urlparse(base_url).hostname
    while queue and len(seen) <= max_links:
        current = queue.pop(0)
        try: r, body = request(session, current)
        except requests.RequestException: continue
        for k, _ in parse_qsl(urlparse(r.url).query, keep_blank_values=True):
            if k: params.add(k)
        for href in re.findall(r"""(?:href|action)\s*=\s*["']([^"']+)["']""", body, re.I):
            absolute = urljoin(r.url, href)
            q = urlparse(absolute)
            if q.scheme in {"http","https"} and q.hostname == host:
                if absolute not in seen: seen.add(absolute); queue.append(absolute)
                for k, _ in parse_qsl(q.query, keep_blank_values=True):
                    if k: params.add(k)
    return sorted(params)

def scan_parameters(session, url, payloads, params, live, stop_on_first, report):
    found = []
    original = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    for param in params:
        vals = dict(original)
        vals.setdefault(param, "xss-test")
        for payload in payloads:
            vals[param] = payload
            test_url = urlunparse(urlparse(url)._replace(query=urlencode(vals, doseq=True)))
            try: r, body = request(session, test_url)
            except requests.RequestException as e:
                msg=f"[ERR] {param}: {e}"; report.append(msg)
                if live: print(msg)
                continue
            if reflected(body, payload):
                msg=f"[REFLECTED] parameter={param} status={r.status_code} url={r.url}"
                found.append(msg); report.append(msg)
                if live: print(msg)
                if stop_on_first: return found
        if live: print(f"[OK] selesai parameter: {param}")
    return found

def scan_no_parameter(session, url, payloads, live, report):
    try: r, body = request(session, url)
    except requests.RequestException as e:
        msg=f"[ERR] {e}"; report.append(msg)
        if live: print(msg)
        return []
    for payload in payloads:
        if reflected(body, payload):
            msg=f"[REFLECTED-ON-ORIGINAL] status={r.status_code} url={r.url}"
            report.append(msg)
            if live: print(msg)
            return [msg]
    msg=f"[NO-REFLECTION] status={r.status_code} url={r.url}"
    report.append(msg)
    if live: print(msg)
    return []

def main():
    ap=argparse.ArgumentParser(description="Reflected-input checker untuk lab/website yang Anda berwenang uji.")
    ap.add_argument("-c","--count",action="store_true",help="jumlah payload")
    ap.add_argument("-u","--url",help="URL target")
    ap.add_argument("-p","--parameter",metavar="URL",help="cari parameter GET dari URL dan same-host links")
    ap.add_argument("-l","--live",action="store_true",help="hasil langsung di terminal")
    ap.add_argument("--mode",choices=["params","no-params"],default="params")
    ap.add_argument("--lokasi",metavar="FILE",help="simpan hasil TXT")
    ap.add_argument("--payload-file",default=str(DEFAULT_PAYLOAD_FILE))
    ap.add_argument("--keep-going",action="store_true",help="lanjut setelah refleksi pertama")
    args=ap.parse_args()
    if not any([args.count,args.url,args.parameter]):
        print(BANNER)
        print("  -h                 bantuan")
        print("  -c                 cek jumlah payload")
        print("  -u URL             scan URL")
        print("  -p URL             cari parameter")
        print("  -l                 hasil live")
        print("  --mode params      scan URL dengan parameter")
        print("  --mode no-params   scan URL original tanpa injeksi query")
        print("  --lokasi FILE      simpan hasil ke TXT")
        return 0
    try: payloads=load_payloads(Path(args.payload_file))
    except Exception as e: print(f"[!] {e}"); return 1
    if args.count:
        print(f"[+] Payload tersedia: {len(payloads)}")
        if not (args.url or args.parameter): return 0
    session=requests.Session()
    session.headers.update({"User-Agent":USER_AGENT,"Accept":"text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"})
    report=[]
    print(BANNER); print(f"[+] Payload loaded: {len(payloads)}")
    if args.parameter:
        try: params=discover_parameters(session,args.parameter)
        except Exception as e: print(f"[!] {e}"); return 1
        print("[+] Parameter ditemukan:")
        if params:
            for p in params: print(f"  - {p}")
        else: print("  (tidak ditemukan)")
        if args.lokasi:
            Path(args.lokasi).write_text("\n".join(params)+"\n",encoding="utf-8")
            print(f"[+] List parameter disimpan: {args.lokasi}")
        return 0
    if args.url:
        try: safety_check(args.url)
        except Exception as e: print(f"[!] {e}"); return 1
        if args.mode=="no-params":
            scan_no_parameter(session,args.url,payloads,args.live,report)
        else:
            existing=[k for k,_ in parse_qsl(urlparse(args.url).query,keep_blank_values=True)]
            if not existing:
                print("[!] Mode params membutuhkan URL yang memiliki query parameter.")
                print("    Gunakan -p URL-original terlebih dahulu.")
                return 1
            scan_parameters(session,args.url,payloads,existing,args.live,not args.keep_going,report)
        if args.lokasi:
            Path(args.lokasi).write_text("\n".join(report)+"\n",encoding="utf-8")
            print(f"[+] Hasil disimpan: {args.lokasi}")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
