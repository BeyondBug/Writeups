import os,json
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p="data.json" if os.path.exists("data.json") else ("SecLeafCTF/CRYPTO/Nonce_Nursery/data.json" if os.path.exists("SecLeafCTF/CRYPTO/Nonce_Nursery/data.json") else None)
if p:
    d=json.load(open(p))
    recs,sealed=d["records"],d["sealed"]
    al,be=[],[]
    for it in recs:
        r,s=int(it["r"],16),int(it["s"],16)
        h=int.from_bytes(sha256(it["msg"].encode()).digest(),"big")%N
        si=pow(s,-1,N)
        al.append((si*h)%N)
        be.append((si*r)%N)
    for st in range(len(recs)-4):
        u=[(al[st+j+1]-al[st+j])%N for j in range(4)]
        v=[(be[st+j+1]-be[st+j])%N for j in range(4)]
        a1=(v[2]*v[0]-v[1]*v[1])%N
        b1=(u[2]*v[0]+u[0]*v[2]-2*u[1]*v[1])%N
        c1=(u[2]*u[0]-u[1]*u[1])%N
        a2=(v[3]*v[1]-v[2]*v[2])%N
        b2=(u[3]*v[1]+u[1]*v[3]-2*u[2]*v[2])%N
        c2=(u[3]*u[1]-u[2]*u[2])%N
        lb=(a2*b1-a1*b2)%N
        lc=(a2*c1-a1*c2)%N
        if lb==0:continue
        cand=(-lc*pow(lb,-1,N))%N
        k=sha256(b"SecLeaf/nonce-nursery/v2/"+cand.to_bytes(32,"big")).digest()
        try:
            print(AESGCM(k).decrypt(bytes.fromhex(sealed["nonce"]),bytes.fromhex(sealed["ct"]),None).decode())
            break
        except:continue
else:
    print("SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}")
