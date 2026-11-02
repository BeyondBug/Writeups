enc=b"SjcCenftl<g;cV_}eh1|T}YPm>g}a[1`nP274r"
print(bytes(b^(0x0F if i%2==1 else 0x00) for i,b in enumerate(enc)).decode())
