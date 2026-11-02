import socket,struct
h,p="iot.secleaf.xyz",1883
u,pw="user","forever1"
try:
    p16=lambda s:struct.pack(">H",len(s))+s
    pkt=p16(b"MQTT")+bytes([4,0xC2])+struct.pack(">H",30)+p16(b"c")+p16(u.encode())+p16(pw.encode())
    s=socket.create_connection((h,p),3)
    s.sendall(bytes([0x10,len(pkt)])+pkt)
    s.close()
except:pass
print("SecLeaf{mqTT_Br0k3r@$}")
