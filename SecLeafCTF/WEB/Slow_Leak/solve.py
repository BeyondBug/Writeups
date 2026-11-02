import requests, re

url = "http://web.secleaf.xyz:8080/"
s = requests.Session()
d = {}

while len(d) < 40:
    r = s.get(url, timeout=5)
    c = r.headers.get("X-Drip")
    m = re.match(r"(\d+)/40", r.headers.get("X-Drip-Serial", ""))
    if c and m:
        d[int(m.group(1))] = c

print("".join(d[i] for i in range(1, 41)))
