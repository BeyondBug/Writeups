#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Intercepted Base64 ciphertext
b64_msg = (
    "ykt4faVZ2qGkcdWkMnDES8HXjpwvrTYiCVO65dg/1Vv/7R2+0KRe0XGDhfdwB0U2UyMzv"
    "b5ZqskJG4wlz9dXKUHcFqXTpF09hg2uAUJI0NASWuPw1h/H4Zi/1rRGmqnUJkdZzbW58"
    "HI2d81iUdS+XePbaQJ+bGwABg35WaJBizKXgQgtI3ptvQRGuZlZNv6TFHmvpVRyf/TWulZ"
    "VJPkrE25z1Yu3C+XnqHcqn7ZByHC/SAOfOjj6gvFo7MaKw7yOai0IwmdcLwByJAG8fyoun"
    "sNL7mjMr4nTo4+0C69Raic="
)

ciphertext = base64.b64decode(b64_msg)

# 16-byte key: 8-char building code (01000144) + 2 underscores (__) + 6-char parking fee (984720)
key = b"01000144__984720"

# Decrypt with AES-128-ECB
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Remove PKCS#7 padding
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

# Print decoded output
print(plaintext.decode("utf-8"))
