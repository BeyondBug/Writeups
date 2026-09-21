# Runway 23 — Asteria International Airport

**Category:** Forensics / Incident Reconstruction  
**Flag:** `LUN4R{....}`

---

## 1. Challenge Description

Asteria International Airport reported an inconsistency involving **Flight LNR231**, which landed on **Runway 23** during normal evening operations.

The official airport systems claimed that the aircraft taxied directly to its assigned gate. However, an internal security audit discovered conflicting records across airport infrastructure, security systems, operational controller logs, and enterprise network traffic.

The objective is to reconstruct what actually happened and recover the following information:

```text
LUN4R{TAILREGISTRATION_PHYSICALDESTINATION_DECOYVEHICLEID_COMPROMISEDEMPLOYEEID_ATTACKERMAC}
```

---

<img width="925" height="285" alt="image" src="https://github.com/user-attachments/assets/932d1a7f-d0e6-46e8-ac76-018b772a0694" />


# 2. Initial Investigation

The supplied evidence contains several independent sources of telemetry.

The important systems are:

- Aircraft / ADS-B telemetry
- Surface movement radar
- Airport operational records
- Vehicle tracking
- Badge/access-control records
- Network traffic
- Gate controller logs

The key to solving the challenge is **not trusting a single airport system**.

The official operational record says the aircraft went directly to its assigned gate, but the independent telemetry tells a different story.

---

# 3. Identifying the Aircraft

The first required field is:

```text
TAILREGISTRATION
```

The flight under investigation is:

```text
LNR231
```

The aircraft telemetry associates this flight with tail registration:

```text
N231LA
```

Therefore:

```text
TAILREGISTRATION = N231LA
```

This gives the first component of the flag:

```text
N231LA
```

---

# 4. Establishing the Real Aircraft Movement

The next objective is determining where the aircraft actually went.

The airport's official system reports a normal taxi to the assigned gate.

However, the surface movement radar provides an independent track.

The radar track associated with the aircraft is:

```text
SMR-9042
```

The track begins after the Runway 23 landing and proceeds through the taxiway network.

Instead of terminating at the officially reported gate, the track continues toward the maintenance area.

The important radar location is:

```text
HANGAR_3_APRON
```

The airport map identifies this area as:

```text
MAINTENANCE HANGAR 3
```

The challenge's expected normalized destination is:

```text
HANGAR3
```

Therefore:

```text
PHYSICALDESTINATION = HANGAR3
```

The important discrepancy is:

```text
Official record:
RWY 23 → assigned gate

Independent radar:
RWY 23 → Taxiway November → Hangar 3
```

This establishes that the aircraft did **not** simply follow the official recorded route.

---

# 5. Finding the Decoy Vehicle

The next flag field is:

```text
DECOYVEHICLEID
```

The vehicle telemetry contains a suspicious vehicle:

```text
VEH-409
```

Its operational description identifies it as:

```text
VIP_SHUTTLE_DECOY
```

More importantly, the vehicle is observed emitting a transponder signal during the relevant time window.

This is significant because the airport's systems could use the vehicle's telemetry/transponder information to create a misleading picture of what was happening on the apron.

The decoy vehicle is therefore:

```text
VEH409
```

For the flag, the hyphen is removed.

---

# 6. Identifying the Compromised Employee

The challenge next asks for:

```text
COMPROMISEDEMPLOYEEID
```

The access-control evidence contains a suspicious badge event.

The relevant employee identifier is:

```text
EID-8842
```

The badge activity is associated with a cloned/duplicate credential and an override-related access event near the Hangar 3 area.

This is important because it connects the physical activity to an authorized airport identity that was apparently abused.

Therefore:

```text
COMPROMISEDEMPLOYEEID = EID8842
```

Again, the hyphen is removed for the flag format.

---

# 7. Investigating the Network Evidence

The final field is:

```text
ATTACKERMAC
```

The enterprise/network evidence contains an abnormal command sent to the gate-control infrastructure.

The suspicious command includes:

```text
OVERRIDE_GATE_STATE=FORCE_DOCKED
```

and targets the gate controller.

This is highly significant.

The airport's official records indicated that the aircraft was already at its assigned gate, while the independent physical telemetry contradicted that claim.

The network command effectively forces the gate system into a state that makes the official operational record appear legitimate.

The Ethernet source address of the suspicious traffic is:

```text
00:c0:ca:99:2b:11
```

The challenge flag format does not use colon separators, so normalize it to:

```text
00c0ca992b11
```

Thus:

```text
ATTACKERMAC = 00c0ca992b11
```

---

# 8. Reconstructing the Attack

Combining the independent evidence produces the following sequence.

### Step 1 — Aircraft lands

Flight:

```text
LNR231
```

lands normally on:

```text
Runway 23
```

The aircraft is:

```text
N231LA
```

---

### Step 2 — The official record claims a normal taxi

The airport operational system records the aircraft as travelling directly to its assigned gate.

This initially makes the event appear completely normal.

---

### Step 3 — Independent radar contradicts the official record

Surface movement radar shows the aircraft following a different route.

The track terminates around:

```text
Hangar 3
```

rather than the assigned gate.

This is the first major indication that the official operational record is unreliable.

---

### Step 4 — A decoy vehicle is active

At approximately the same time, the vehicle telemetry shows:

```text
VEH-409
```

The vehicle is specifically associated with the decoy operation and is transmitting a transponder signal.

This provides an explanation for the conflicting location telemetry.

---

### Step 5 — A compromised airport identity appears

Access-control records show suspicious activity associated with:

```text
EID-8842
```

The credential activity is consistent with a cloned/abused airport credential near the Hangar 3 infrastructure.

This links the physical activity to a compromised employee identity.

---

### Step 6 — Gate-control telemetry is manipulated

Network traffic reveals an unauthorized command:

```text
OVERRIDE_GATE_STATE=FORCE_DOCKED
```

The command manipulates the gate-control system so that the operational records can indicate the aircraft is docked at the expected gate.

The packet's source MAC is:

```text
00:c0:ca:99:2b:11
```

---

# 9. Evidence Correlation

The individual artifacts become much more meaningful when correlated:

| Evidence | Finding |
|---|---|
| Flight telemetry | `LNR231` → `N231LA` |
| Landing runway | `RWY 23` |
| Surface radar | Aircraft deviates from official route |
| Radar destination | `HANGAR_3_APRON` |
| Physical destination | `HANGAR3` |
| Vehicle telemetry | `VEH-409` |
| Vehicle role | Decoy / transponder-emitting vehicle |
| Access control | `EID-8842` |
| Network command | `FORCE_DOCKED` gate override |
| Ethernet source | `00:c0:ca:99:2b:11` |
| Flag normalization | Remove `-` and `:` separators |

The important insight is that **the official gate record is the manipulated portion of the evidence**.

The independent systems expose the real movement.

---

# 10. Flag Construction

The challenge specifies:

```text
LUN4R{TAILREGISTRATION_PHYSICALDESTINATION_DECOYVEHICLEID_COMPROMISEDEMPLOYEEID_ATTACKERMAC}
```

Substituting the recovered values:

```text
TAILREGISTRATION
    N231LA

PHYSICALDESTINATION
    HANGAR3

DECOYVEHICLEID
    VEH409

COMPROMISEDEMPLOYEEID
    EID8842

ATTACKERMAC
    00c0ca992b11
```

Therefore:

```text
LUN4R{N231LA_HANGAR3_VEH409_EID8842_00c0ca992b11}
```

# 11. Final Flag

```text
LUN4R{N231LA_HANGAR3_VEH409_EID8842_00c0ca992b11}
```

---

## 12. Key Takeaway

The challenge is fundamentally an **evidence-correlation problem**.

The official airport system alone suggests a normal flight:

```text
Runway 23 → Assigned Gate
```

But correlating the independent sources reveals:

```text
LNR231
   ↓
N231LA
   ↓
Runway 23
   ↓
Surface Radar
   ↓
Hangar 3
   ↓
VEH-409 decoy telemetry
   ↓
EID-8842 compromised credential
   ↓
Gate-control override
   ↓
00:c0:ca:99:2b:11
```

The attacker therefore manipulated the airport's operational picture while the independent telemetry preserved evidence of the actual movement.

**Final flag:**

```text
LUN4R{N231LA_HANGAR3_VEH409_EID8842_00c0ca992b11}
```
