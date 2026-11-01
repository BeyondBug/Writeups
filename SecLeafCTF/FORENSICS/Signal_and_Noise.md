# signal and noise 

In this challenge,i investigated a packet capture containing multiple attack patterns against the same target. The challenge was not simply to identify the largest traffic spike. I needed to distinguish the decoy vector from the meaningful attack chain, correlate activity across protocols and identify the ip address that connected the tcp and dns-reflection vectors.

The supplied report describes a raw ipv4 PCAP containing 2,211 packets over approximately 119.4 seconds. Since the capture uses raw ipv4 packets rather than ethernet frames, a custom parser needs to start decoding each packet at the ipv4 header.

## Step 1 (profiling the capture)

I started by checking the file type and capture metadata:

```bash
file signal-and-noise.pcap
capinfos signal-and-noise.pcap
```

The main target was 10.0.88.10. Three different traffic patterns converged on this host:

1. ICMP Echo Requests from 10.99.0.0/24.
2. TCP SYN traffic targeting port 443, mainly from 172.16.80.0/24 with some sources from 10.0.1.0/24.
3. DNS responses from systems in 198.18.0.0/24, directed at the target.

The initial lesson was that packet volume alone could be misleading. The ICMP vector was the largest by packet count, but the key to solving the challenge was finding the relationship between the TCP SYN traffic and the DNS-reflection activity.

## Step 2 (got the idea from this recon)

I compared the traffic patterns by protocol, destination, source ranges and packet size.

| Pattern | Count in the report | Typical size | Main source(s) | Initial interpretation |
|---|---:|---:|---|---|
| ICMP Echo Request | 800 | 84 bytes | `10.99.0.0/24` | Candidate decoy |
| TCP SYN to port 443 | 560 pure SYNs, within 620 TCP packets | 40 bytes | `172.16.80.0/24`, plus `10.0.1.0/24` | SYN flood |
| UDP responses from source port 53 | 350 | 714 bytes | `198.18.0.11`, `.22`, `.33`, `.44` | DNS reflection |

The sources are separated into distinct ranges. That meant I needed to look beyond packets directed at the target and examine whether any host participated in more than one vector.

## Step 3 (investigated the ICMP flood)

I first isolated the ICMP Echo Requests aimed at the target.

**Wireshark filter:**

```text
ip.dst == 10.0.88.10 && icmp.type == 8
```

**TShark command:**

```bash
tshark -r signal-and-noise.pcap \
  -Y 'ip.dst == 10.0.88.10 && icmp.type == 8' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e frame.len
```

The report identifies 800 Echo Requests, each 84 bytes, with source addresses ranging from 10.99.0.1 through 10.99.0.50. All were directed to 10.0.88.10.

The traffic looked like a distributed ping flood. However, the source range did not overlap the TCP source network or the DNS-reflection systems, and no host in 10.99.0.0/24 was observed issuing DNS control queries to the reflectors.

That lack of cross-vector linkage was the important clue: the ICMP flood was active, but it did not explain the coordination behind the other attack patterns.

## Step 4 (Investigated the TCP SYN flood)

Next, I inspected TCP SYN packets aimed at HTTPS on the target.

**Wireshark filter:**

```text
ip.dst == 10.0.88.10 &&
tcp.dstport == 443 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 0
```

**TShark command:**

```bash
tshark -r signal-and-noise.pcap \
  -Y 'ip.dst == 10.0.88.10 && tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e tcp.srcport \
  -e ip.dst \
  -e tcp.dstport \
  -e tcp.flags
```

The capture report describes 560 pure SYN packets within 620 TCP packets. The pure SYN packets were 40 bytes, consistent with a minimal IPv4 and TCP header, and targeted port `443`.

Most of the sources were in 172.16.80.0/24, with additional sources from 10.0.1.0/24.

One address immediately became important: 172.16.80.99. It participated in the TCP SYN vector and also appeared in the DNS activity that led to the reflected traffic. I treated it as a candidate pivot and investigated it further.

## Step 5 (investigated dns reflection and amplification)

I then filtered for UDP packets sent to the target from source port 53.

**Wireshark filter:**

```text
ip.dst == 10.0.88.10 && udp.srcport == 53
```

**TShark command:**

```bash
tshark -r signal-and-noise.pcap \
  -Y 'ip.dst == 10.0.88.10 && udp.srcport == 53' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e frame.len
```

The reflected responses came from four systems:

```text
198.18.0.11:53 -> 10.0.88.10:<random-port>
198.18.0.22:53 -> 10.0.88.10:<random-port>
198.18.0.33:53 -> 10.0.88.10:<random-port>
198.18.0.44:53 -> 10.0.88.10:<random-port>
```

The report identifies 350 such UDP packets, approximately 714 bytes each. That is substantially larger than the DNS queries sent by the candidate pivot, which were approximately 68 bytes at the IP-packet level.

## Step 6 (traced the dns queries back to the pivot)

To find the source of the DNS requests, I looked for outbound DNS traffic from 172.16.80.99.

**Wireshark filter:**

```text
ip.src == 172.16.80.99 && udp.dstport == 53
```

**TShark command:**

```bash
tshark -r signal-and-noise.pcap \
  -Y 'ip.src == 172.16.80.99 && udp.dstport == 53' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e dns.qry.name \
  -e dns.qry.type
```

The pivot queried all four systems:

```text
172.16.80.99:<ephemeral> -> 198.18.0.11:53
172.16.80.99:<ephemeral> -> 198.18.0.22:53
172.16.80.99:<ephemeral> -> 198.18.0.33:53
172.16.80.99:<ephemeral> -> 198.18.0.44:53
```

The query name was:

```text
big-record.example.org
```

The query type was ANY, which is consistent with an attempt to elicit a large DNS response. The much larger replies from source port 53 were then directed at 10.0.88.10.

This linked the outbound DNS requests from 172.16.80.99 to the reflected UDP traffic hitting the target. The reflector addresses were the responding systems; the cross-vector pivot was the host that sent the queries and also participated in the TCP SYN flood.

## Step 7 (I correlated the pivot across both vectors)

I checked the packets involving 172.16.80.99 to confirm the relationship.

```bash
tshark -r signal-and-noise.pcap \
  -Y 'ip.addr == 172.16.80.99' \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e ip.proto \
  -e tcp.srcport \
  -e tcp.dstport \
  -e udp.srcport \
  -e udp.dstport \
  -e dns.qry.name
```

The two important relationships were:

```text
172.16.80.99 -> 10.0.88.10:443
```

and:

```text
172.16.80.99:<ephemeral> -> 198.18.0.11:53
172.16.80.99:<ephemeral> -> 198.18.0.22:53
172.16.80.99:<ephemeral> -> 198.18.0.33:53
172.16.80.99:<ephemeral> -> 198.18.0.44:53
```

The first places the address in the TCP SYN-flood vector. The second shows it sending DNS queries to the systems that later returned larger UDP responses toward the target.

The capture report identifies 172.16.80.99 as the address that links these two vectors. That satisfies the pivot requirement.

## Step 8 (I got the fish, from thinking Why ICMP is the decoy)

I compared the ICMP pattern with the TCP/DNS chain:

| Test | ICMP vector | TCP/DNS chain |
|---|---|---|
| Targets `10.0.88.10` | Yes | Yes |
| Has multiple apparent sources | Yes | Yes |
| Shares a source across vectors | No | Yes - `172.16.80.99` |
| Issues DNS control queries | No | Yes |
| Leads to reflected traffic | No | Yes |
| Identifies the pivot | No | Yes |

The ICMP traffic is clearly suspicious, but it has no observed connection to the cross-vector coordination. It is therefore the decoy vector.

The meaningful chain is the TCP SYN flood combined with DNS reflection, linked by 172.16.80.99.

## Step 9 (reproduced with python verification)

The supplied report uses dpkt to parse the raw IPv4 PCAP. The following compact script verifies the core counts and the pivot's involvement in both vectors.


```python
#!/usr/bin/env python3
import collections
import socket
import dpkt

PCAP = "signal-and-noise.pcap"
TARGET = "10.0.88.10"
PIVOT = "172.16.80.99"

vectors = collections.Counter()
pivot_tcp_syn = False
pivot_dns_query = False

with open(PCAP, "rb") as handle:
    for _, (_, raw) in enumerate(dpkt.pcap.Reader(handle), start=1):
        try:
            # The capture uses raw IPv4 packets, not Ethernet frames.
            ip = dpkt.ip.IP(raw)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue

        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        transport = ip.data

        if dst == TARGET and isinstance(transport, dpkt.icmp.ICMP):
            if transport.type == 8:
                vectors["icmp"] += 1

        elif dst == TARGET and isinstance(transport, dpkt.tcp.TCP):
            is_syn = (
                transport.dport == 443
                and (transport.flags & dpkt.tcp.TH_SYN)
                and not (transport.flags & dpkt.tcp.TH_ACK)
            )
            if is_syn:
                vectors["tcp_syn"] += 1
                if src == PIVOT:
                    pivot_tcp_syn = True

        elif dst == TARGET and isinstance(transport, dpkt.udp.UDP):
            if transport.sport == 53:
                vectors["dns_reflection"] += 1

        if src == PIVOT and isinstance(transport, dpkt.udp.UDP):
            if transport.dport == 53:
                pivot_dns_query = True

print("Observed target-directed vector counts:")
for name, count in vectors.items():
    print(f"{name}: {count}")

print("Pivot sent TCP SYN to target:", pivot_tcp_syn)
print("Pivot sent DNS query:", pivot_dns_query)

assert vectors["icmp"] == 800
assert vectors["tcp_syn"] == 560
assert vectors["dns_reflection"] == 350
assert pivot_tcp_syn
assert pivot_dns_query

print("Result: ICMP is the decoy; pivot is 172.16.80.99")
print("FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}")
```

Run it with:

```bash
python3 gotttt.py
```

The assertions check the report's stated counts and verify that the pivot is present in both the TCP SYN and DNS-query activity. As with any parser, if the observed counts differ, I would inspect the PCAP and adjust the filters to match the precise packet definitions rather than assuming the report's numbers.

## final answer and flag

```text
Decoy: ICMP Echo flood
Pivot: 172.16.80.99
```

```text
FLOWTRIQ{decoy_icmp_pivot_172.16.80.99}
```

