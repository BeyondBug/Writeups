import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

b64_msg = (
    "ykt4faVZ2qGkcdWkMnDES8HXjpwvrTYiCVO65dg/1Vv/7R2+0KRe0XGDhfdwB0U2UyMzv"
    "b5ZqskJG4wlz9dXKUHcFqXTpF09hg2uAUJI0NASWuPw1h/H4Zi/1rRGmqnUJkdZzbW58"
    "HI2d81iUdS+XePbaQJ+bGwABg35WaJBizKXgQgtI3ptvQRGuZlZNv6TFHmvpVRyf/TWulZ"
    "VJPkrE25z1Yu3C+XnqHcqn7ZByHC/SAOfOjj6gvFo7MaKw7yOai0IwmdcLwByJAG8fyoun"
    "sNL7mjMr4nTo4+0C69Raic="
)

ct = base64.b64decode(b64_msg)
key = b"01000144__984720"

cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
dec = cipher.decryptor()
pt = dec.update(ct) + dec.finalize()
pt = pt[:-pt[-1]]
print(pt.decode())
