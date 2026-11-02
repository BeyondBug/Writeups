import base64
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
b64="ykt4faVZ2qGkcdWkMnDES8HXjpwvrTYiCVO65dg/1Vv/7R2+0KRe0XGDhfdwB0U2UyMzvb5ZqskJG4wlz9dXKUHcFqXTpF09hg2uAUJI0NASWuPw1h/H4Zi/1rRGmqnUJkdZzbW58HI2d81iUdS+XePbaQJ+bGwABg35WaJBizKXgQgtI3ptvQRGuZlZNv6TFHmvpVRyf/TWulZVJPkrE25z1Yu3C+XnqHcqn7ZByHC/SAOfOjj6gvFo7MaKw7yOai0IwmdcLwByJAG8fyounsNL7mjMr4nTo4+0C69Raic="
ct=base64.b64decode(b64)
k=b"01000144__984720"
c=Cipher(algorithms.AES(k),modes.ECB()).decryptor()
p=c.update(ct)+c.finalize()
p=p[:-p[-1]]
print(p.decode().split()[0])
