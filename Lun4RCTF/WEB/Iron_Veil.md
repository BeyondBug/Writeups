# Iron Veil — Web Writeup

Target: `http://ironveil.chall.rootriet.in`

Iron Veil is a multi-step web challenge involving asset discovery, an IDOR to leak JWT signing secrets, token privilege escalation, and a Jinja2 SSTI filter bypass to grab the flag from `/root/flag.txt`.

---

## 1. Recon & Finding the Archive

Checking `/robots.txt` right away gives a list of disallowed routes (`/archive/`, `/internal/`, `/api/v2/`, etc.) along with a ROT13 comment (`FLAG{1_r0b0gf_klm_w00_tmch}`).

Visiting `/archive/` exposes an open index with migration assets:

<img width="1280" height="850" alt="image" src="https://github.com/user-attachments/assets/5aa89b5b-1307-4864-83b0-cb4227bcd532" />


Two files stand out:
1. Running `strings` on `casefile_delta.png` reveals credentials appended past the image data: `operator_kessler:0p3r@t0r_Kx9`.
2. `incident_log.txt` is encoded in ROT13 and mentions that authentication was relocated after "incident-7", pointing to `/api/v2/incident`.

---

## 2. Leaking the JWT Secret (IDOR)

Checking `/api/v2/incident` gives a JSON response with incident notes and a file ID reference (`/api/v2/files?id=<id>`).

Querying `id=7` triggers an IDOR and returns the full incident report:

<img width="1280" height="650" alt="image" src="https://github.com/user-attachments/assets/df060cb4-d1b2-46df-865d-00bc28731c5c" />


Under `jwt_implementation`, it reveals:
> *"Tokens signed with HS256. Secret derived from organization name (lowercase)."*

The org name is **Iron Veil Systems**, which means the HMAC secret is simply `ironveil`.

---

## 3. Forging the JWT for Vault Access

Logging in at `/internal/auth/login` sets a cookie named `ivs_token` containing a JWT. On `/internal/dashboard`, we see the session is only **Clearance Level 1**, while the vault requires **Level 5**:

<img width="1280" height="900" alt="image" src="https://github.com/user-attachments/assets/bdcb787c-9148-4226-bb85-e7e463b14968" />


Since the token uses symmetric `HS256` and we have the secret key (`ironveil`), we can forge our own token with elevated clearance:

```json
{
  "sub": "operator_kessler",
  "username": "operator_kessler",
  "name": "Kessler M.",
  "role": "sysadmin",
  "clearance": 5
}
```

After re-signing the token with `ironveil` and hitting `/internal/vault`, the vault unlocks and gives us a checkpoint flag (`FLAG{6_trust_n0_t0ken}`):


<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/6bc585ab-bed1-4d45-8dbc-2d85afcec7cc" />


---

## 4. Jinja2 SSTI & Blacklist Bypass

The vault flag isn't in the final `lun4r{...}` format. Looking through the authenticated pages, `/internal/preview` provides a report template previewer running Jinja2.

Testing `{{ 7*7 }}` confirms SSTI, but there's a blacklist blocking common keywords like `open`, `flag`, `__globals__`, and `__builtins__`.

We can bypass the filter using the `cycler` object, `attr()`, and string concatenation to reconstruct the blocked attributes dynamically:

```jinja2
{{ cycler|attr('_' ~ '_init_' ~ '_' )
   |attr('_' ~ '_globals_' ~ '_')
   |attr('_' ~ '_getitem_' ~ '_')('_' ~ '_builtins_' ~ '_')
   |attr('_' ~ '_getitem_' ~ '_')('open')
   ('/root/' ~ 'f' ~ 'lag' ~ '.txt')
   |attr('r' ~ 'ead')() }}
```

Sending this in the `template` POST field evaluates the template and reads `/root/flag.txt`:

<img width="1280" height="950" alt="image" src="https://github.com/user-attachments/assets/73c7329f-8990-44e8-8922-1589a4ccce3d" />


**Flag:** `lun4r{v31l_sh4tt3r3d_n0_m0r3_s3cr3ts_7f9a2e}`
