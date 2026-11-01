# Subdomain Smuggling— CTF Write-up

**Category:** Network Forensics  
**Challenge File:** `suspicious_activity.pcap`  
**Tools:** Wireshark, tshark, Base64  
**Flag:** `SecLeaf{D474_3xf1l_DN5}`  
**Status:** Solved

## Challenge Analysis

We were provided with a packet capture file named `suspicious_activity.pcap`. Our objective was to analyze the captured network traffic, identify suspicious activity, and recover the hidden flag.

### Step 1: Analyze the PCAP

First, I opened the file using Wireshark:

`wireshark suspicious_activity.pcap`

The capture contained 1,038 packets, including TCP, HTTPS, and DNS traffic.

I started by filtering DNS traffic using:

`dns`

While inspecting the DNS queries, I noticed several legitimate domains, such as `google.com`, `github.com`, `microsoft.com`, and `cloudflare.com`.

However, there were also unusual requests to `evil.com`.

### Step 2: Filter Suspicious DNS Requests

I applied the following Wireshark filter:

`dns.qry.name contains "evil.com"`

This revealed eight packets: four DNS requests and four responses.

To display only DNS queries, I refined the filter:

`dns.flags.response == 0 && dns.qry.name contains "evil.com"`

All four suspicious requests originated from `192.168.1.20` and were sent to `8.8.8.8`.

### Step 3: Extract the Encoded Subdomains

The suspicious DNS queries were:

| Frame | DNS Query |
|---|---|
| 167 | `U2VjTGVhZn.evil.com` |
| 293 | `tENDc0XzN4.evil.com` |
| 395 | `ZjFsX0RONX.evil.com` |
| 502 | `0=.evil.com` |

The subdomains looked like fragments of encoded data.

This suggested DNS exfiltration, where information is encoded into DNS query names and transmitted to an attacker-controlled domain.

### Step 4: Reconstruct the Payload

I removed the `.evil.com` suffix from each query and combined the fragments in packet order.

The reconstructed string was:

`U2VjTGVhZntENDc0XzN4ZjFsX0RONX0=`

The character set and trailing `=` suggested Base64 encoding.

### Step 5: Decode the Payload

I decoded the string using the Linux terminal:

`printf '%s' 'U2VjTGVhZntENDc0XzN4ZjFsX0RONX0=' | base64 -d`

The decoded output was:

`SecLeaf{D474_3xf1l_DN5}`

## Final Flag

**`SecLeaf{D474_3xf1l_DN5}`**

## Conclusion

This challenge demonstrated how DNS can be used as a covert data-exfiltration channel. The attacker split the encoded information into multiple fragments and embedded them in DNS subdomains.

By identifying the suspicious domain, extracting the fragments in order, and decoding the reconstructed Base64 string, I successfully recovered the flag.

**Key Learning:** DNS traffic should be examined for unusual subdomain patterns, long encoded strings, and repeated queries to suspicious destinations.
