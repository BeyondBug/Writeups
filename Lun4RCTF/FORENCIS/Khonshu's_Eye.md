# Khonshu's Eye 

**Category:** Forensics / Steganography  
**Flag Format:** `Lun4R{...}`

---

## Challenge Description

A strange image was recovered from one of Marc Spector’s devices.

At first glance, the file appears to be a normal crime-scene image. However, the challenge description contains an important clue:

> The truth is hidden in plain sight.

That immediately suggests that the image itself contains more information than what is visible on the screen.

The task is therefore to examine the image at multiple levels: metadata, raw file structure, embedded files, and finally the pixel data itself.

---

# 1. Initial Inspection

The challenge provides the following file:

```text
case_evidence.png
```

Opening it normally shows a crime-scene style image containing several visible elements:

- Yellow `DO NOT CROSS` tape
- Crime-scene markings
- A body-outline illustration
- A magnifying-glass symbol
- The text `CASE #0417`

Nothing in the visible image directly reveals the flag.

Because this is a forensic challenge, the first step is to inspect the file without modifying it.

A simple check can be performed using:

```bash
file case_evidence.png
```

followed by:

```bash
exiftool case_evidence.png
```

The `file` command confirms that the artifact is a PNG image, while `exiftool` allows us to inspect any metadata stored inside the file.

---

# 2. Metadata Analysis

Running:

```bash
exiftool case_evidence.png
```

reveals several PNG metadata fields.

Two values immediately stand out.

The first is:

```text
archive_note = RnU0cTBqUzF5cl8yMDI0
```

The second appears to be a complete flag:

```text
Lun4R{th1s_1s_n0t_th3_r34l_fl4g_k33p_d1gg1ng}
```

<img width="1600" height="866" alt="image" src="https://github.com/user-attachments/assets/2ca35184-5a5f-4888-a7fa-0fd1c6a4dcfc" />



Although the second value follows the expected flag format, its content explicitly says:

```text
this is not the real flag, keep digging
```

It is therefore a deliberate decoy.

This is an important part of the challenge. The goal is not simply to search the file for a string beginning with `Lun4R{`, because doing so leads to the fake flag.

The more interesting artifact is:

```text
RnU0cTBqUzF5cl8yMDI0
```

The character set and length strongly suggest that it may be Base64 encoded.

---

# 3. Decoding the Metadata Value

The value can be decoded using:

```bash
echo 'RnU0cTBqUzF5cl8yMDI0' | base64 -d
```

The result is:

```text
Fu4q0jS1yr_2024
```

<img width="1600" height="866" alt="image" src="https://github.com/user-attachments/assets/c15d3340-294b-4af0-9fa6-36bda7d96614" />


This does not immediately resemble readable text, but its structure suggests another lightweight text transformation may have been used.

A common transformation in CTF challenges is ROT13.

The decoded string can therefore be processed with:

```bash
echo 'Fu4q0jS1yr_2024' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

The result is:

```text
Sh4d0wF1le_2024
```

This looks much more meaningful and strongly resembles a password.

The complete decoding chain is therefore:

```text
archive_note
    |
    v
RnU0cTBqUzF5cl8yMDI0
    |
    | Base64 decode
    v
Fu4q0jS1yr_2024
    |
    | ROT13
    v
Sh4d0wF1le_2024
```

At this stage, the recovered value is kept as a likely password for a later stage.

---

# 4. Inspecting the PNG Structure

The next step is to inspect the PNG file itself.

A standard PNG ends with an `IEND` chunk. Any significant data located after that chunk is suspicious because it is not required for normal image rendering.

A quick inspection can be performed with:

```bash
xxd case_evidence.png | tail
```

or:

```bash
binwalk case_evidence.png
```

The analysis shows that additional data exists after the logical end of the PNG.

Most importantly, the appended data begins with the bytes:

```text
50 4B
```

which correspond to:

```text
PK
```

`PK` is the standard file signature associated with ZIP archives.

This confirms that a ZIP archive has been appended to the PNG file.

The image therefore acts as a container for two separate pieces of data:

```text
PNG image
+
hidden ZIP archive
```

<img width="875" height="156" alt="image" src="https://github.com/user-attachments/assets/dcd67447-55ee-4f5a-a748-34e734bf391f" />


---

# 5. Extracting the Embedded ZIP Archive

The archive can be extracted automatically using:

```bash
binwalk -e case_evidence.png
```

Alternatively, its offset can be identified manually and the ZIP section carved from the file.

After extraction, the hidden archive contains:

```text
secret.png
```

However, the archive is password protected.

The password recovered earlier from the image metadata now becomes useful:

```text
Sh4d0wF1le_2024
```

The ZIP can therefore be extracted using:

```bash
unzip -P 'Sh4d0wF1le_2024' hidden.zip
```

After successful extraction, we obtain:

```text
secret.png
```

This confirms that the metadata value was not random and was deliberately designed to provide the archive password.

---

# 6. Inspecting `secret.png`

Opening `secret.png` does not reveal obvious text, QR codes, or visible symbols.

Instead, the image appears to consist mainly of a smooth color gradient.

At this point, visual inspection alone is not sufficient.

The challenge hint:

> The truth is hidden in plain sight.

becomes more relevant here.

The natural next step is to inspect the raw RGB pixel values.

Python and Pillow can be used:

```python
from PIL import Image

img = Image.open("secret.png").convert("RGB")

print(img.size)

for y in range(img.height):
    for x in range(img.width):
        print(x, y, img.getpixel((x, y)))
```

After inspecting the values, a very regular pattern becomes visible.

---

# 7. Identifying the Expected Gradient

The majority of the image follows a predictable RGB model.

For a pixel located at coordinates `(x, y)`, the expected RGB values are approximately:

```text
R = 2 × x
G = 2 × y
B = 90
```

In other words:

```python
expected = (
    2 * x,
    2 * y,
    90
)
```

This explains why the image appears visually smooth.

However, not every pixel exactly follows this pattern.

Some pixels differ slightly from the expected RGB values.

These differences are too small to be easily noticed visually, but they are systematic enough to suggest deliberate manipulation.

The hidden data is therefore not stored directly in the pixel values. Instead, it is encoded through deviations from the expected gradient.

---

# 8. Extracting the Pixel Deviations

For each pixel, the expected RGB value is calculated first.

Then the real pixel value is compared against it.

Conceptually:

```text
actual pixel
     |
     v
expected gradient value
     |
     v
difference
     |
     v
binary value
```

A normal pixel represents one bit value, while a deliberately altered pixel represents the other.

The exact extraction process can be implemented in Python.

A simplified version is:

```python
from PIL import Image

img = Image.open("secret.png").convert("RGB")

bits = []

for y in range(img.height):
    for x in range(img.width):

        actual = img.getpixel((x, y))

        expected = (
            2 * x,
            2 * y,
            90
        )

        if actual == expected:
            bits.append("0")
        else:
            bits.append("1")
```

The resulting bitstream can then be grouped into bytes.

For example:

```python
data = bytearray()

for i in range(0, len(bits), 8):

    byte = "".join(bits[i:i+8])

    if len(byte) == 8:
        data.append(int(byte, 2))

print(data)
```

After converting the encoded deviations into readable bytes, the following string appears:

```text
JR2W4NCSPNRTI4TWGFXGOX3NGN2DIZBUOQ2F6NDOMRPXAMLYGNWF653IGFZXAM3SON6Q====
```

The extracted stream also contains an explicit terminator:

```text
#####END#####
```

The end marker confirms that the extracted data is intentional and indicates where the hidden payload stops.

---

# 9. Identifying the Encoding

The extracted string is:

```text
JR2W4NCSPNRTI4TWGFXGOX3NGN2DIZBUOQ2F6NDOMRPXAMLYGNWF653IGFZXAM3SON6Q====
```

The string contains:

- Uppercase letters
- Digits between `2` and `7`
- `=` padding

These are characteristic of Base32 encoding.

The data can therefore be decoded using:

```bash
echo 'JR2W4NCSPNRTI4TWGFXGOX3NGN2DIZBUOQ2F6NDOMRPXAMLYGNWF653IGFZXAM3SON6Q====' | base32 -d
```

This produces:

```text
Lun4R{c4rv1ng_m3t4d4t4_4nd_p1x3l_wh1sp3rs}
```

---

# 10. Final Flag

```text
Lun4R{c4rv1ng_m3t4d4t4_4nd_p1x3l_wh1sp3rs}
```

---

# 11. Complete Attack Path

The full challenge can be summarized as:

```text
case_evidence.png
        |
        v
Inspect metadata
        |
        +---------------------------+
        |                           |
        v                           v
Fake flag                    archive_note
                              |
                              v
                  RnU0cTBqUzF5cl8yMDI0
                              |
                      Base64 decode
                              |
                              v
                      Fu4q0jS1yr_2024
                              |
                           ROT13
                              |
                              v
                     Sh4d0wF1le_2024
                              |
                              v
                  Password for ZIP archive
                              |
                              v
Inspect PNG after IEND
                              |
                              v
                       PK ZIP signature
                              |
                              v
                    Extract hidden archive
                              |
                              v
                         secret.png
                              |
                              v
                   Analyze RGB pixel values
                              |
                              v
               Compare against known gradient
                              |
                              v
                 Extract deviation bitstream
                              |
                              v
JR2W4NCSPNRTI4TWGFXGOX3NGN2DIZBUOQ2F6NDOMRPXAMLYGNWF653IGFZXAM3SON6Q====
                              |
                         Base32 decode
                              |
                              v
Lun4R{c4rv1ng_m3t4d4t4_4nd_p1x3l_wh1sp3rs}
```

---

# 12. Why the Challenge Works

The challenge uses several forensic techniques in sequence rather than relying on a single hiding mechanism.

The first layer abuses PNG metadata to store both a decoy and a useful clue.

The second layer uses simple text encoding and substitution to hide the archive password.

The third layer takes advantage of the fact that programs displaying PNG images generally ignore data placed after the `IEND` chunk.

This allows an additional ZIP archive to be appended without affecting how the PNG is displayed.

The final stage uses image steganography.

Instead of directly embedding visible text, the challenge modifies selected RGB values relative to a mathematically predictable gradient.

Because these changes are extremely small, the resulting image appears normal to the human eye while still carrying machine-readable information.

---

# 13. Important Findings

During the investigation, several artifacts were significant.

| Artifact | Finding |
|---|---|
| `case_evidence.png` | Primary forensic artifact |
| PNG metadata | Contained both a decoy flag and encoded archive clue |
| `archive_note` | Base64 encoded value |
| Base64 output | `Fu4q0jS1yr_2024` |
| ROT13 output | `Sh4d0wF1le_2024` |
| Appended file data | ZIP archive identified through `PK` signature |
| Hidden archive | Password protected |
| Archive password | `Sh4d0wF1le_2024` |
| Extracted artifact | `secret.png` |
| Pixel pattern | Predictable RGB gradient |
| Pixel anomalies | Encoded hidden bitstream |
| Hidden payload | Base32 encoded string |
| Final decoded value | Challenge flag |

---

# 14. Tools Used

The following tools were sufficient to solve the challenge:

```text
exiftool
xxd
binwalk
unzip
base64
tr
base32
Python
Pillow
```

Each tool served a specific purpose:

- `exiftool` — metadata inspection
- `xxd` — hexadecimal inspection
- `binwalk` — identifying appended embedded files
- `unzip` — extracting the protected archive
- `base64` — first-stage decoding
- `tr` — ROT13 transformation
- Python/Pillow — pixel-level image analysis
- `base32` — decoding the final extracted payload

---

![Uploading image.png…]()


# 15. Conclusion

`Khonshu's Eye` is a layered forensic and steganography challenge built around the idea that visually normal files can contain multiple hidden data channels.

The image initially appears harmless, but metadata inspection exposes an encoded clue. Decoding that clue reveals the password to an archive appended after the legitimate PNG data.

The extracted image then introduces a second form of hiding: small modifications to an otherwise predictable RGB gradient.

By modeling the expected pixel values and extracting only the deviations, the hidden bitstream can be recovered.

That bitstream contains a Base32 payload which finally decodes to:

```text
Lun4R{c4rv1ng_m3t4d4t4_4nd_p1x3l_wh1sp3rs}
```

The challenge therefore combines:

```text
metadata analysis
        +
file carving
        +
encoding recognition
        +
archive extraction
        +
pixel-level steganography
```

into a single forensic workflow.

**Final Flag:**

```text
Lun4R{c4rv1ng_m3t4d4t4_4nd_p1x3l_wh1sp3rs}
```
