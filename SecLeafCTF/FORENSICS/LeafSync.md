# LeafSync 

In this challenge,i investigated a short packet capture to understand why a workstation downloaded a shell helper and then began sending unusual DNS queries. My goal was to establish the timeline then identify the suspicious domain reconstruct the encoded data and recover the flag.

The supplied forensic report identifies the workstation as 10.20.30.15, the DNS resolver as 10.20.30.53 and the internal documentation server as 10.20.30.80. The capture contains 55 packets over approximately 3.80 seconds.

## Step 1 (inspecting)

I started by checking the capture metadata to understand its size packet count and duration.

```bash
capinfos leafsync.pcap
```

If capinfos is unavailable,i can inspect the capture with wireshark or use a short python script with dpkt to read the packets.

The capture is small, so I could inspect the timeline manually. The key was to avoid looking at DNS in isolation: packet order helps establish what happened before the suspicious queries began.

## Step 2 (establishing the dns baseline)

First,i identified the workstations dns requests. The workstation repeatedly queried the internal resolver:

```text
10.20.30.15 -> 10.20.30.53:53
```

The capture includes ordinary names such as github.com,pypi.org,files.pythonhosted.org,docs.internal.local and several internal service names. These gave me a baseline for normal dns activity.

I used this wireshark display filter to focus on DNS queries originating from the workstation:

```text
dns.flags.response == 0 && ip.src == 10.20.30.15
```

I also extracted query names with TShark:

```bash
tshark -r leafsync.pcap \
  -Y 'dns.flags.response == 0 && ip.src == 10.20.30.15' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e dns.qry.type
```

Most names looked like ordinary infrastructure. One domain stood out because the workstation queried it repeatedly with numbered labels containing base64-looking text.

## Step 3 (finding the http download)

Before the suspicious DNS sequence,i found an http exchange between the workstation and the internal documentation server:

```text
10.20.30.15:51884 -> 10.20.30.80:80
```

The request was:

```http
GET /tools/leafsync-helper.sh HTTP/1.1
Host: docs.internal.local
User-Agent: curl/8.5.0
Accept: */*
Connection: close
```

The server returned HTTP/1.1 200 OK and identified the downloaded file as leafsync-helper.sh. The body shown in the capture was:

```sh
#!/bin/sh
echo 'LeafSync helper started'
```

I used this filter to isolate the http conversation:

```text
ip.addr == 10.20.30.15 && tcp.port == 80
```

The download itself is simple and the capture does not prove exactly how or whether the helper was executed. However the timeline shows that the download happened before the suspicious DNS sequence making it an important lead.

## Step 4 (Identified the suspicious dns domain)

After the http exchange, the workstation began querying:

```text
sync-cache.training.local
```

The suspicious query names were:

```text
01.U2VjTGVh.sync-cache.training.local
02.ZntkbnNf.sync-cache.training.local
03.bGFiZWxz.sync-cache.training.local
04.X2hpZGVf.sync-cache.training.local
05.dGhlX3Ry.sync-cache.training.local
06.dXRofQ==.sync-cache.training.local
```

I noticed a consistent structure:

```text
<sequence>.<encoded-fragment>.<covert-domain>
```

The sequence values run from 01 through 06. That ordering strongly suggests that the labels are fragments of one payload rather than unrelated hostnames.

I filtered for the domain in wireshark:

```text
dns.qry.name contains "sync-cache.training.local"
```

Or with TShark:

```bash
tshark -r leafsync.pcap \
  -Y 'dns.qry.name contains "sync-cache.training.local"' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e dns.qry.name
```

The encoded data is carried in the dns query names, specifically the left-most labels. The dns responses do not need to contain the payload for this reconstruction.

## Step 5 (extracted the encoded fragments)

I removed the numeric prefixes and the shared domain keeping only the encoded fragments in sequence order.

| Sequence | Fragment |
|---|---|
| `01` | `U2VjTGVh` |
| `02` | `ZntkbnNf` |
| `03` | `bGFiZWxz` |
| `04` | `X2hpZGVf` |
| `05` | `dGhlX3Ry` |
| `06` | `dXRofQ==` |

The numeric prefixes tell me the order in which to join the fragments. I concatenated them without adding spaces or line breaks:

```text
U2VjTGVhZntkbnNfbGFiZWxzX2hpZGVfdGhlX3RydXRofQ==
```

## Step 6 (decoding the payload)

The combined string has the form of base64, so I decoded it using the standard command-line utility:

```bash
printf '%s' \
  'U2VjTGVhZntkbnNfbGFiZWxzX2hpZGVfdGhlX3RydXRofQ==' \
  | base64 -d
printf '\n'
```

The output was:

```text
SecLeaf{dns_labels_hide_the_truth}
```

This is the recovered flag. The important part of the solve was preserving the order of the six DNS fragments before decoding them.

## Step 7 (python verification)

I can also verify the reconstruction programmatically. This compact script takes the observed fragments sorts them by their sequence number concatenates them and decodes the base64 payload.

```python
#!/usr/bin/env python3
import base64

fragments = [
    (1, "U2VjTGVh"),
    (2, "ZntkbnNf"),
    (3, "bGFiZWxz"),
    (4, "X2hpZGVf"),
    (5, "dGhlX3Ry"),
    (6, "dXRofQ=="),
]

fragments.sort(key=lambda item: item[0])
encoded = "".join(fragment for _, fragment in fragments)
decoded = base64.b64decode(encoded, validate=True).decode("utf-8")

print("Reconstructed Base64:", encoded)
print("Decoded payload:", decoded)

assert len(fragments) == 6
assert decoded == "SecLeaf{dns_labels_hide_the_truth}"
```

Save the script as gotthisss_leafsync.py and run:

```bash
python3 gotthisss_leafsync.py
```

Expected output:

```text
Reconstructed Base64: U2VjTGVhZntkbnNfbGFiZWxzX2hpZGVfdGhlX3RydXRofQ==
Decoded payload: SecLeaf{dns_labels_hide_the_truth}
```

This script verifies the fragment assembly and decoding. It uses the fragments observed in the capture rather than parsing the PCAP itself.

## Final Flag

```text
SecLeaf{dns_labels_hide_the_truth}
```
