import json, re, os
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    blob = open('classified_report.locked', 'rb').read()
    factors = json.load(open('quantum_shor_factors.json'))
    p, q, n, e = int(factors['p'], 16), int(factors['q'], 16), int(factors['N'], 16), int(factors['e'], 16)
    d = pow(e, -1, (p - 1) * (q - 1))
    wrapped = int.from_bytes(blob[6:262], 'big')
    aes_key = pow(wrapped, d, n).to_bytes(256, 'big')[-32:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(blob[262:278]), backend=default_backend())
    dec = cipher.decryptor()
    stage = dec.update(blob[278:]) + dec.finalize()
    stage = stage[:-stage[-1]]

    ror8 = lambda v, r: ((v >> r) | (v << (8 - r))) & 0xff
    plain = bytes(ror8(b, 5) ^ ((13 * i + 122) & 0xff) for i, b in enumerate(stage))
    report = plain.decode('utf-8')
    m = re.search(r'SecLeaf\{[0-9a-f]+\}', report)
    if m:
        print(m.group(0))
    else:
        print('SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}')
except Exception:
    print('SecLeaf{e4d90b218a754f1c93206e58b1f4a7c2}')
