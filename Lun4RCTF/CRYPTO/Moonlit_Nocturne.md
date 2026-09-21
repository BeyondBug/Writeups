# Moonlit Nocturne Challenge Write-up

## Overview
The challenge provides a MIDI file (`nocturne.mid`) accompanied by the following narrative:

> The moon remembers what the night forgets.  
> A melody was left behind in the darkness. No note seems out of place.  
> Yet something is hiding between the sounds.  
> Listen carefully. Not everything you need to hear is part of the music.

The key insight is that the required information is concealed in MIDI metadata and event properties rather than the audible melody itself.

---

## Step 1 — Initial Inspection

Confirm the file type and examine its internal structure using a MIDI parsing library:

```python
import mido

mid = mido.MidiFile("nocturne.mid")
for i, track in enumerate(mid.tracks):
    print(f"\nTrack {i}: {track.name if track.name else 'Unnamed'}")
    for msg in track:
        print(msg)
```

<img width="1600" height="367" alt="image" src="https://github.com/user-attachments/assets/70f37081-8674-4c49-8a90-0b33299aa698" />


The file contains multiple tracks and a sequence of note events with varying properties.

---

## Step 2 — Velocity Steganography

Most note velocities cluster around the values **72** and **73**. These differ by a single bit in the least-significant position:

| Velocity | Binary LSB | Bit |
|----------|------------|-----|
| 72       | ...0       | 0   |
| 73       | ...1       | 1   |

Extract the LSB of every `note_on` event (where velocity > 0):

```python
bits = []
for track in mid.tracks:
    for msg in track:
        if msg.type == "note_on" and msg.velocity > 0:
            bits.append(msg.velocity & 1)
```

Group the bits into bytes and convert to ASCII. The resulting plaintext is:

```
TIMING IS THE KEY
```

This message indicates that the next layer of data is encoded in event timing rather than velocity or pitch.

---

<img width="1600" height="425" alt="image" src="https://github.com/user-attachments/assets/53ae9d8d-5abc-4ab2-aead-d7dc82c97482" />


## Step 3 — Timing Steganography

MIDI events carry delta-time values. Two dominant intervals appear:

| Delta Time | Bit |
|------------|-----|
| 0 ticks    | 0   |
| 120 ticks  | 1   |

Extract these timing bits, assemble them into bytes, and decode. The ciphertext obtained is:

```
DO3_A00A_K1UAC_DV4G_LO3_H1QOH_U1V3Z
```

---

## Step 4 — Identify the Cipher Key

One of the MIDI tracks is named **Khonshu’s Shadow**. Khonshu is the Egyptian moon god, providing a natural key candidate:

```
KHONSHU
```

Applying a Vigenère cipher with this key decrypts the ciphertext to:

```
TH3_M00N_S1NGS_WH4T_TH3_N1GHT_H1D3S
```

<img width="1600" height="146" alt="image" src="https://github.com/user-attachments/assets/59fe898f-88e2-4762-9a58-d107bc4a5822" />


---

## Step 5 — Leetspeak Decoding

Simple character substitutions recover the final plaintext:

| Cipher | Plain |
|--------|-------|
| 3      | E     |
| 0      | O     |
| 1      | I     |
| 4      | A     |

```
TH3_M00N_S1NGS_WH4T_TH3_N1GHT_H1D3S
→ THE_MOON_SINGS_WHAT_THE_NIGHT_HIDES
```

---

## Final Flag

```
Lun4{THE_MOON_SINGS_WHAT_THE_NIGHT_HIDES}
```

---
