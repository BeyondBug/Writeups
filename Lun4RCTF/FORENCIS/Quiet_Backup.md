
# Quiet Backup Challenge Write-up

## Overview
This challenge provides multi-source forensic evidence, including mail logs, Windows event logs, workstation artifacts, network logs, backup logs, and file hashes. The objective is to recover four distinct pieces of information and assemble them into the flag format:

```
Lun4R{A_B_C_D}
```

Each component is derived from a different part of the evidence set.

---

## A — Where did the first footprint fall?

The earliest malicious artifact appears in the workstation evidence (`EV-03_mft_usnjrnl.txt`):

```
C:\Users\t.nguyen\AppData\Roaming\Microsoft\OneDrive\OneDriveUpdater.exe
```

Source workstation:

```
SOURCE: WKS-DEV04
```

**Clue interpretation**  
> “The answer is hidden in the name of the place where the intrusion truly took hold. Clean its scars away, then let it speak in capitals.”

Remove the hyphen and convert to uppercase:

```
WKS-DEV04 → WKSDEV04
```

**Result:** `A = WKSDEV04`


<img width="1600" height="674" alt="image" src="https://github.com/user-attachments/assets/1467bf83-c5ac-4f74-8d79-fd51cf785f07" />

---

## B — The clock cannot always be trusted

Prefetch evidence shows a local timestamp:

```
Last run (local): 2025-09-08 08:12:20

```



MFT/USN journal records the authoritative creation event in UTC:

```
2025-09-08 14:12:03 UTC
USN 88214
FileCreate|DataExtend
C:\Users\t.nguyen\AppData\Roaming\Microsoft\OneDrive\OneDriveUpdater.exe
```

This entry marks the creation of the malicious loader. The flag requires only the UTC date.

**Result:** `B = 20250908`


---
<img width="880" height="618" alt="image" src="https://github.com/user-attachments/assets/f62abbf6-4684-4b9e-a1b9-3854d802d618" />


## C — Identify the real loader

The workstation contains multiple executables, including the legitimate Sysinternals tool `PSEXEC.EXE`. The malicious binary is:

```
OneDriveUpdater.exe
```

Amcache evidence confirms it is unsigned. Its SHA-256 hash (from `EV-16_hash_inventory.txt`) is:

```
9f2c8a41b7e3d9046c1a5f8b2e7d4c39a0f61b8d3e5c7a92146fbd0837c5e91a
```

**Hint:**  
> “First 8 hex characters of the real loader binary’s SHA-256 hash.”

**Result:** `C = 9f2c8a41`


<img width="1600" height="364" alt="image" src="https://github.com/user-attachments/assets/9217288e-eafd-4cf9-b320-1393648c5119" />

---

## D — Two identities cross the same trail

Server security log (Event ID 4624):

| Field                  | Value                  |
|------------------------|------------------------|
| Account Name           | d.reyes                |
| Account Domain         | MERIDIAN               |
| Logon Type             | 9 (NewCredentials)     |
| Source Network Address | 10.10.4.41 (WKS-DEV04) |
| Logon Process          | seclogo                |

**Hint:**  
> “Look for the numeric code that proves credential injection instead of a human at a keyboard…”

Logon Type **9** indicates NewCredentials (credential injection).

Correlation with the fraudulent backup:

- Legitimate backup window: 02:00–03:00 UTC  
- Legitimate archive: `Backup_Archive_20250909_0230.zip` (created by `BackupAgent.exe`)  
- Suspicious archive: `Backup_Archive_20250909_0751.zip`  
  - Size: 18.4 MB  
  - Contains sensitive paths under `\Finance\`  
  - No corresponding `BackupAgent.exe` telemetry  
  - NTFS owner: `MERIDIAN\svc-backup`

**Clue interpretation**  
> “One is what the record appears to say. The other is who actually walked it.”

Combine the numeric logon type with the service account responsible for the fake backup (hyphen retained, as the hyphen-removal rule applied only to component A):

```
9 + SVC-BACKUP → 9SVC-BACKUP
```

**Result:** `D = 9SVC-BACKUP`

<img width="717" height="492" alt="image" src="https://github.com/user-attachments/assets/c9f4275f-a43e-4413-8904-fe69bad9668e" />


---

## Final Flag Assembly

```
A = WKSDEV04
B = 20250908
C = 9f2c8a41
D = 9SVC-BACKUP
```

```
Lun4R{WKSDEV04_20250908_9f2c8a41_9SVC-BACKUP}
```

---

## Key Lessons

- **A**: Trace the initial malicious artifact back to its originating workstation and normalize the hostname as instructed.  
- **B**: Prefer authoritative UTC timestamps from MFT/USN over local Prefetch times.  
- **C**: Differentiate the unsigned malicious loader from legitimate tools and extract the required hash prefix.  
- **D**: Interpret Logon Type 9 (NewCredentials) in conjunction with the identity that created the fraudulent backup, rather than relying solely on the account name shown in the 4624 event.

The final structural clue — “Four answers. Three underscores.” — confirms the required format `A_B_C_D`.
```
