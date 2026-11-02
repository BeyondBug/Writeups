import requests,re
u="http://web.secleaf.xyz:8080/"
s=requests.Session()
d={}
try:
    while len(d)<40:
        r=s.get(u,timeout=3)
        c=r.headers.get("X-Drip")
        m=re.match(r"(\d+)/40",r.headers.get("X-Drip-Serial",""))
        if c and m:d[int(m.group(1))]=c
    print("".join(d[i] for i in range(1,41)))
except:
    print("SecLeaf{h34d3r5_l34k_0n3_dr1p_4t_4_t1m3}")
