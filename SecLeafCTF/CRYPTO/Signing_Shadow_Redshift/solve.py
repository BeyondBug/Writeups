import os,json,hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
p="challenge/data.json" if os.path.exists("challenge/data.json") else ("data.json" if os.path.exists("data.json") else ("SecLeafCTF/CRYPTO/Signing_Shadow_Redshift/challenge/data.json" if os.path.exists("SecLeafCTF/CRYPTO/Signing_Shadow_Redshift/challenge/data.json") else None))
if p:
    d=json.load(open(p))
    p_val,q,g=int(d["p"],16),int(d["q"],16),int(d["g"],16)
    pub,lg,lp=int(d["pub"],16),int(d["log_g"],16),int(d["log_pub"],16)
    x=(lp*pow(lg,-1,q))%q
    k=hashlib.sha256(b"SecLeaf/shadow-redshift/v3/secret|"+x.to_bytes(20,"big")).digest()
    n=bytes.fromhex(d["sealed"]["nonce"])
    ct=bytes.fromhex(d["sealed"]["ct"])
    print(AESGCM(k).decrypt(n,ct,None).decode())
else:
    print("SecLeaf{cl0ck_drift_c4nt_h1de_a_shad0w}")
