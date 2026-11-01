# Encoded Transmission

This challenge tied directly into the recon we did in *Riddled Code*. The intercepted chatter mentioned two specific numbers from the target's stay:
- Sanctuary Building Code: `01000144` (8 chars)
- Parking bleed in yen: `984720` (6 chars)

We're dealing with standard AES-128 which requires a 16-byte key. 8 + 6 gave 14 characters, so joining them with a double underscore `__` gave the exact 16-byte key: `01000144__984720`.

The transmission payload was a 300-char Base64 blob decoding to 224 bytes (14 blocks of 16 bytes). Decrypting with AES-128-ECB and stripping PKCS#7 padding popped the plaintext right open.

```python
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

ciphertext = base64.b64decode(b64_msg)
key = b"01000144__984720"

cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()
pt = decryptor.update(ciphertext) + decryptor.finalize()

# Strip PKCS#7 unpadding
pt = pt[:-pt[-1]]
print(pt.decode("utf-8"))
```

Running the solver dumped the full decrypted transmission containing the flag:

```text
CRY{ok_password_was_the_building_code_and_cost_in_yen_with_2underscore}
```
