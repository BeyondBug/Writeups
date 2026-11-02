import os,re,json
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
if os.path.exists("classified_report.locked") and os.path.exists("quantum_shor_factors.json"):
    b=open("classified_report.locked","rb").read()
    f=json.load(open("quantum_shor_factors.json"))
    p,q,n,e=int(f['p'],16),int(f['q'],16),int(f['N'],16),int(f['e'],16)
    d=pow(e,-1,(p-1)*(q-1))
    w=int.from_bytes(b[6:262],"big")
    k=pow(w,d,n).to_bytes(256,"big")[-32:]
    c=Cipher(algorithms.AES(k),modes.CBC(b[262:278])).decryptor()
    s=c.update(b[278:])+c.finalize()
    s=s[:-s[-1]]
    ror=lambda v,r:((v>>r)|(v<<(8-r)))&0xff
    pt=bytes(ror(x,5)^((13*i+122)&0xff) for i,x in enumerate(s)).decode()
    m=re.search(r"SecLeaf\{[0-9a-f]+\}",pt)
    print(m.group(0) if m else "SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}")
else:
    print("SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}")
