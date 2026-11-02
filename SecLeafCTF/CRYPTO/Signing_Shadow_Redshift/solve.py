import hashlib, json, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

path = "challenge/data.json" if os.path.exists("challenge/data.json") else "data.json"
data = json.load(open(path))

p = int(data["p"], 16)
q = int(data["q"], 16)
g = int(data["g"], 16)
pub = int(data["pub"], 16)
log_g = int(data["log_g"], 16)
log_pub = int(data["log_pub"], 16)

x = (log_pub * pow(log_g, -1, q)) % q
assert pow(g, x, p) == pub

key = hashlib.sha256(b"SecLeaf/shadow-redshift/v3/secret|" + x.to_bytes(20, "big")).digest()
nonce = bytes.fromhex(data["sealed"]["nonce"])
ct = bytes.fromhex(data["sealed"]["ct"])

flag = AESGCM(key).decrypt(nonce, ct, None).decode()
print(flag)
