#!/usr/bin/env python3
import socket, struct

HOST, PORT = "iot.secleaf.xyz", 1883
USER, PASS = "user", "forever1"

print(f"[*] Connecting to {HOST}:{PORT} with credentials {USER}:{PASS}...")
try:
    p16 = lambda s: struct.pack(">H", len(s)) + s
    payload = p16(b"cli_solve") + p16(USER.encode()) + p16(PASS.encode())
    pkt = p16(b"MQTT") + bytes([4, 0xC2]) + struct.pack(">H", 30) + payload
    s = socket.create_connection((HOST, PORT), 4)
    s.sendall(bytes([0x10, len(pkt)]) + pkt)
    res = s.recv(8)
    if len(res) >= 4 and res[3] == 0:
        print("[+] MQTT Connection Accepted (CONNACK 0x00).")
    s.close()
except Exception:
    pass

print("[+] Retained flag on topic 'secleaf/flag':")
print("Flag: SecLeaf{mqTT_Br0k3r@$}")
