# Dead Letter Office — CTF Write-up

**Category:** Reverse Engineering  
**Challenge Files:**
- `dead_letter_office`
- `postcard.grid`

**Tools:** IDA Free, Python, objdump  
**Flag:** `SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}`  
**Status:** Solved

## Challenge Analysis

This challenge provided two files: an executable named `dead_letter_office` and a binary data file named `postcard.grid`.

The objective was to understand how the executable validated its input using the external data file and recover the correct flag.

### Step 1: Inspect the Files

I first identified the files:

`file dead_letter_office postcard.grid`

The executable was a stripped, 64-bit Linux ELF binary.

The `postcard.grid` file contained 208 bytes of binary data.

Running `strings` on the executable revealed:

- `Delivered.`
- `Returned to sender.`
- `postcard.grid`

These strings suggested that the program loaded the external file and used it to verify an input.

### Step 2: Analyze the Executable

I loaded `dead_letter_office` into IDA.

The main function was located at:

`0x1120`

The program opened `postcard.grid` using `fopen`, read its contents, checked its structure, and then processed the supplied input.

Important locations included:

| Address | Purpose |
|---|---|
| `0x1145` | Opens `postcard.grid` |
| `0x121C` | Checks file signature |
| `0x1238` | Checks flag length |
| `0x12E4` | File checksum verification |
| `0x1333` | Key reconstruction |
| `0x1389` | Main validation loop |
| `0x13FB` | Transformation rounds |
| `0x14BD` | Final verification |

### Step 3: Understand the Grid File

The external file began with the signature:

`HPL2`

Further inspection revealed that it contained:

- A 128-byte header
- A flag length of 40 bytes
- 20 encoded records
- Four bytes per record
- An FNV-1a checksum over the record data

The executable verified the file structure and checksum before processing the candidate flag.

### Step 4: Analyze the Custom Encryption

The program divided the 40-character flag into 20 pairs of bytes.

Each pair passed through a custom 14-round transformation.

The algorithm used:

- An internally reconstructed 8-byte key
- XOR operations
- Byte addition
- Bit rotations
- A Feistel-like transformation
- A changing 16-bit value derived from previous records

The records were also accessed in a shuffled order.

The record index was calculated as:

`index = (7 + 7 * i) % 20`

This made the encoded bytes difficult to interpret directly.

### Step 5: Reverse the Algorithm

After analyzing the assembly instructions, I reconstructed the algorithm in Python.

The important observation was that the transformation was reversible.

For every round, the program combined two bytes using a nonlinear function consisting of XOR, addition, and rotation.

The Feistel-like structure allowed the original byte pair to be recovered by processing the rounds backward.

I extracted the encoded records from `postcard.grid`, reconstructed the internal key, and reversed the 14 rounds for each pair.

The previous record value was also restored at each stage to recover the original character bytes.

After processing all 20 pairs, the reconstructed flag was:

`SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}`

### Step 6: Verify the Flag

I placed both files in the same directory and executed:

`./dead_letter_office 'SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}'`

The program returned:

`Delivered.`

The exit code was `0`, confirming that the input passed the complete verification process.

## Final Flag

**`SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}`**

## Conclusion

This challenge combined executable reverse engineering with analysis of a custom binary data format.

Unlike simple reversing challenges, the expected values were stored in a separate file rather than directly in the executable.

The solution required understanding the file structure, reconstructing the encryption key, identifying the shuffled record order, and reversing a 14-round Feistel-like transformation.

**Key Learning:** External data files can contain the essential verification information for a reversing challenge. Analyzing the executable and its companion files together is necessary to understand and reverse the full algorithm.
