# Reflected Storm

## Step 1 (inspected the capture)

I started by reviewing reflected-storm.pcap to understand the traffic
pattern and identify the target receiving the unusual responses.

The capture contained 1,340 Ethernet frames all carrying udp traffic.
The timestamps covered approximately 90 seconds.

I used wireshark and a packet-analysis script to focus on dns traffic
and compare requests with their corresponding replies.

## Step 2 (Filtered dns traffic)

I filtered for dnss packets involving the suspected victim address and
examined the direction of the requests and responses.

Useful wireshark display filters were:

``` text
udp.port == 53 && ip.addr == 10.0.55.200
dns.flags.response == 0 && ip.src == 10.0.55.200 && udp.dstport == 53
dns.flags.response == 1 && ip.dst == 10.0.55.200 && udp.srcport == 53
```

The request packets had 10.0.55.200 as their source address and were
sent to several dns servers on upd port 53. The larger dns responses
were sent back to 10.0.55.200.

## Step 3 (identifying the victim address)

I compared the source IPs in the dns queries with the destination IPs in
the matching responses.

The large replies consistently targeted 10.0.55.200, making it the
apparent victim of the reflected traffic.

The earliest observed request/response pair was in frames 21 and 22. The
reflected queries continued through frame 1338, with responses
continuing through frame 1340.

This pattern is consistent with dns reflection: requests carry the
victim's address as their source and dns servers send their replies to
that address. The capture alone does not prove that the victim actually
originated the queries because source ip addresses can be spoofed.

## Step 4 (Compared a query and its response)

I inspected frames 21 and 22 as a representative pair.

The query was sent from 10.0.55.200 to 198.51.100.22. It requested
openresolver-test.example.com using DNS QTYPE ANY (255).The
response returned from the DNS server to 10.0.55.200.

The packet sizes were:

  Measurement      Query (Frame 21)   Response (Frame 22)
  -------------- ------------------ ---------------------
  DNS message              47 bytes             986 bytes
  UDP datagram             55 bytes             994 bytes
  IPv4 packet              75 bytes           1,014 bytes

The response was much larger than the request, which supports the DNS
amplification interpretation.

## Step 5 (counted the distinct reflectors)

I grouped DNS responses by their source ip, keeping only responses
addressed to 10.0.55.200 and sent from udp source port 53.

The capture showed five distinct response sources:

  Reflector IP        Queries   Replies
  ----------------- --------- ---------
  `198.51.100.22`         133       133
  `203.0.113.5`           120       120
  `192.0.2.17`            119       119
  `198.51.100.10`         118       118
  `203.0.113.88`          110       110
  **Total**           **600**   **600**

I counted unique response source ips rather than udp source ports or
total packets. This gave five distinct reflectors and 600 matching
queries and replies.

The capture also included 70 local dns queries from 10.0.1.50 to
`10.0.1.1` and 70 corresponding replies. I excluded these because they
were separate local DNS traffic not large responses directed at the
suspected victim.

## Step 6 (measured the amplification)

I compared the request and response sizes at the dns,udp and ipv4
layers.

  Layer               Query      Response   Response/query ratio
  -------------- ---------- ------------- ----------------------
  DNS message      47 bytes     986 bytes                 20.98×
  UDP datagram     55 bytes     994 bytes                 18.07×
  IPv4 packet      75 bytes   1,014 bytes                 13.52×

There were 600 reflected replies, each with an ipv4 total length of
1,014 bytes. The total reflected ipv4 traffic recorded for the victim
was therefore:

``` text
600 * 1,014 = 608,400 bytes
```

These figures describe the packets in the supplied capture and do not
include Ethernet framing or traffic outside the capture interval.

## Step 7 (Reproduced the analysis with python)

I used Python and Scapy to count the victim-directed responses, identify
the unique reflector IPs, and check the packet sizes.

Save the following script as solve.py beside reflected-storm.pcap.

``` python
from collections import Counter
from scapy.all import rdpcap, IP, UDP, DNS

PCAP = "reflected-storm.pcap"
VICTIM = "10.0.55.200"

packets = rdpcap(PCAP)
queries = Counter()
responses = Counter()
query_sizes = Counter()
response_sizes = Counter()

for packet in packets:
    if IP not in packet or UDP not in packet or DNS not in packet:
        continue

    ip, udp, dns = packet[IP], packet[UDP], packet[DNS]

    if dns.qr == 0 and ip.src == VICTIM and udp.dport == 53:
        queries[ip.dst] += 1
        query_sizes[
            (len(bytes(dns)), int(udp.len), int(ip.len))
        ] += 1

    if dns.qr == 1 and ip.dst == VICTIM and udp.sport == 53:
        responses[ip.src] += 1
        response_sizes[
            (len(bytes(dns)), int(udp.len), int(ip.len))
        ] += 1

reflectors = sorted(responses)

print("Frames:", len(packets))
print("Victim:", VICTIM)
print("Distinct reflectors:", len(reflectors))

for reflector in reflectors:
    print(
        reflector,
        "queries:", queries[reflector],
        "replies:", responses[reflector],
    )

print("Query sizes (DNS, UDP, IPv4):", query_sizes)
print("Response sizes (DNS, UDP, IPv4):", response_sizes)

q_dns, r_dns = 47, 986
q_udp, r_udp = 55, 994
q_ip, r_ip = 75, 1014

print("DNS ratio:", round(r_dns / q_dns, 2))
print("UDP ratio:", round(r_udp / q_udp, 2))
print("IPv4 ratio:", round(r_ip / q_ip, 2))
print("Reflected IPv4 bytes:", sum(responses.values()) * r_ip)
print(f"Flag: FLOWTRIQ{{{VICTIM}_{len(reflectors)}_reflectors}}")
```

Run it with:

``` bash
python ans.py
```

The expected core results are:

``` text
Frames: 1340
Victim: 10.0.55.200
Distinct reflectors: 5
DNS ratio: 20.98
UDP ratio: 18.07
IPv4 ratio: 13.52
Reflected IPv4 bytes: 608400
Flag: FLOWTRIQ{10.0.55.200_5_reflectors}
```

## Step 8 (Interpreted the evidence)

The repeated DNS request/reply pairs the larger responses and the five
distinct response sources support the conclusion that the capture
records a DNS reflection/amplification pattern.

The reflector addresses are in documentation/test IP ranges, so I
treated them as scenario values rather than attributing the activity to
real public DNS servers or operators.

The PCAP establishes the packet contents and directions visible in the
capture. It does not establish the real origin of any spoofed request or
identify the person responsible.

## Final Flag

``` text
FLOWTRIQ{10.0.55.200_5_reflectors}
```
