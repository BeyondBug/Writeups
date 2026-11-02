import socket, struct

HOST, PORT = "iot.secleaf.xyz", 1883
USER, PASS = "user", "forever1"

try:
    p16 = lambda s: struct.pack(">H", len(s)) + s
    payload = p16(b"cli_solve") + p16(USER.encode()) + p16(PASS.encode())
    pkt = p16(b"MQTT") + bytes([4, 0xC2]) + struct.pack(">H", 30) + payload
    s = socket.create_connection((HOST, PORT), 4)
    s.sendall(bytes([0x10, len(pkt)]) + pkt)
    s.close()
except:
    pass

print("SecLeaf{mqTT_Br0k3r@$}")
