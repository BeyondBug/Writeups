# Blackroot Archive
## Step 1 (Inspected the PCAP)

I started by examining blackroot_archive.pcap to understand the
traffic and identify which communications were relevant to the
challenge.

The capture contained 119 frames,including tcp,dns/dp and
arp traffic. The activity took place over a short interval on 29
September 2026.

I noted the main endpoints in the capture:

-   `10.88.12.15` --- finance workstation
-   `10.88.12.22` --- operations workstation
-   `10.88.12.80:80` --- internal documentation server
-   `10.88.12.25:25` --- internal mail server
-   `198.51.100.144` --- external endpoint recorded in the capture

The external address belongs to a documentation/test range, so i treated
it as a value from the challenge environment rather than evidence of a
real public host.

## Step 2 (filtered the relevant traffic)

I used Wireshark display filters to narrow the capture to the
workstation http, smtp and the external archive service.

``` text
ip.addr == 10.88.12.15
http.request && ip.addr == 10.88.12.15
tcp.port == 25
ip.addr == 198.51.100.144 && tcp.port == 4711
```

The initial arp and dns packets provided context, but the important
sequence was the HTTP manifest request an internal email and the later
TCP/4711 connection.

## Step 3 (build the event timeline)

I followed the packets in timestamp order to understand how the
different services related to one another.

The finance workstation first resolved docs.blackroot.internal and
requested a ledger synchronization manifest. An internal smtp message
followed shortly afterward. The workstation then connected to the
external endpoint and exchanged archive-protocol messages.

The relevant frame groups were:

  Frames     Observation
  ---------- ------------------------------------------
  5--6       DNS lookup for `docs.blackroot.internal`
  28--31     HTTP request and manifest response
  52--56     SMTP archive notice
  102--117   Archive service exchange over TCP/4711

The manifest explicitly pointed to the mail notice as the key source and
identified tcp/4711 as the next service to inspect. This made the
sequence more meaningful than timing alone.

## Step 4 (Recovered the http manifest)

Frame 28 contained an http request from 10.88.12.15:52100 to the
internal documentation server.

``` http
GET /exports/ledger-sync.manifest HTTP/1.1
Host: docs.blackroot.internal
User-Agent: FinanceSync/2.1
Accept: application/octet-stream
Connection: close
```

The response began in frame 29 and continued through frames 30--31. It
returned a Base64-encoded manifest.

I reassembled the response body in tcp sequence order and decoded it
from Base64. The result was:

``` text
BLACKROOT_ARCHIVE_MANIFEST
artifact=ledger-sync-2026
encoding=base64
key_source=mail:archive-notice
next_service=tcp/4711
```

This gave me two useful leads: the recovery key was in the internal
archive notice and the archive records were sent over tcp port 4711.

## Step 5 (found the recovery Key in smtp)

I inspected the smtp exchange between 10.88.12.22:52325 and
10.88.12.25:25.

Frame 56 contained the email body. The message identified itself as an
internal archive synchronization notice and included the recovery key.

``` text
From: archive-notice@blackroot.internal
To: operations@blackroot.internal
Subject: Ledger archive synchronization
X-Classification: internal-training

Archive route confirmed.
Recovery key: rootleaf
Use the key only with the ledger synchronization service.
```

I used the key exactly as it appeared in the captured message:

``` text
rootleaf
```

No password guessing was necessary; the manifest directed me to the
email, and the email supplied the key.

## Step 6 (Inspected the archive service)

I then examined the TCP/4711 connection between the finance workstation
and 198.51.100.144.

The application payload identified the service and session:

``` text
BLACKROOT-SYNC/1.0
session=ledger-sync-2026
mode=archive
```

The session matched the artifact named in the HTTP manifest. Frames
105--114 carried ten numbered records, followed by a commit command in
frame 115. The server responded in frames 116--117 with messages
indicating that the channel was ready and the fragments had been
accepted.

## Step 7 (Extracted and reassemble the records)

I extracted the ten records and sorted them by their record numbers,
rather than relying only on packet arrival order.

The records contained hexadecimal data. Records 01--09 each held seven
bytes, and record 10 held one byte, giving a total of 64 bytes.

The record values were:

``` text
01: 275d391e382237
02: 0e28011b18092d
03: 231011013d1836
04: 2358102b021f18
05: 3556331c2a5c25
06: 180808370e1029
07: 56440d2237002b
08: 37251e0d220d54
09: 28395606363d0d
10: 5f
```

I converted each hexadecimal value to bytes and concatenated the
fragments in ascending record order. This produced the 64-byte
ciphertext used in the next step.

## Step 8 (decrypted the reassembled data)

The manifest specified base64 encoding, while the email provided the key
rootleaf. I therefore applied repeating-key XOR to the concatenated
bytes, starting with the first key byte at offset zero.

For each byte, the operation was:

``` text
P[i] = C[i] XOR K[i mod 8]
```

Here,C was the reassembled ciphertext and K was the ASCII byte
sequence for rootleaf.

The XOR result was a base64 string:

``` text
U2VjTGVhZntleHBvcnRlZF9vYmplY3Rz
X3JldmVhbF90aGVfYXJjaGl2ZV9rZXl9
```

I joined the two lines and decoded the result from base64.

## Step 9 (Reproduced the recovery with python)

I used Python and Scapy to automate the packet extraction and decoding
process. The following is a compact reproduction script for the numbered
archive records and final transformations.

Save it as solve.py beside blackroot_archive.pcap. The record values
below are transcribed from the relevant packets, so the decoding can be
reproduced independently of the Wireshark interface.

``` python
import base64

records = {
    1: "275d391e382237",
    2: "0e28011b18092d",
    3: "231011013d1836",
    4: "2358102b021f18",
    5: "3556331c2a5c25",
    6: "180808370e1029",
    7: "56440d2237002b",
    8: "37251e0d220d54",
    9: "28395606363d0d",
    10: "5f",
}

ciphertext = b"".join(
    bytes.fromhex(records[number])
    for number in sorted(records)
)

key = b"rootleaf"
xor_output = bytes(
    value ^ key[index % len(key)]
    for index, value in enumerate(ciphertext)
)

flag = base64.b64decode(xor_output, validate=True).decode("ascii")

print("Records:", len(records))
print("Ciphertext bytes:", len(ciphertext))
print("XOR output:", xor_output.decode("ascii"))
print("Flag:", flag)
```

Run the script with:

``` bash
python got.py
```

The expected result is:

``` text
Records: 10
Ciphertext bytes: 64
Flag: SecLeaf{exported_objects_reveal_the_archive_key}
```

## Step 10 (verified the result)

I checked that the recovered Base64 text decoded to a well-formed
SecLeaf{...} flag.

The result was consistent with the full evidence chain:

1.  The HTTP manifest identified the archive artifact and pointed to the
    mail notice.
2.  The SMTP notice supplied the XOR key.
3.  The TCP/4711 session carried ten indexed records for the same
    archive artifact.
4.  Reassembling the records, applying repeating-key XOR, and decoding
    Base64 recovered the flag.

The server's fragment-acceptance response was also consistent with the
archive records being received successfully.

## Final Flag

``` text
SecLeaf{exported_objects_reveal_the_archive_key}
```
