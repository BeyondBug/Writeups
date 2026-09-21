# A Place Forgotten - CTF Write-up

**Challenge:** A Place Forgotten  
**Category:** OSINT / Geolocation  
**Points:** 140  
**Flag format:** `Lun4R{place_region_country_latitude_longitude}`

---

## 1. Challenge Description

> A single photograph was recovered. There is no known filename, no coordinates, no description, and no confirmed location. Somewhere, this entrance belongs to a place connected to an industry that left physical traces across an entire region. Find where the photograph was taken.

The objective is to identify the photographed building and determine its location and coordinates.

---

## 2. Challenge Photograph

The original challenge image shows a distinctive low-rise building constructed from pale stone blocks.

<img width="1536" height="805" alt="image" src="https://github.com/user-attachments/assets/663cbb0f-7c74-4674-8f2f-af7f4805c2ff" />

### Visual observations

Several features stand out:

- Three large arched openings.
- Pale/pinkish masonry.
- Decorative reddish panels beside the entrances.
- A long masonry wall extending from the entrance.
- Mining/industrial artefacts displayed outside.
- A bust mounted prominently in front of the building.
- A large sign above the entrance.

The sign is the most useful piece of evidence because it contains the institution's name.

---

## 3. Reading the Sign

A photograph/reference image makes the sign easier to inspect.

The visible Russian/Kazakh text identifies the institution as a museum of the history of mining and smelting in **Zhezdy**, named after **Maken Toregeldin**.

The important portion can be read approximately as:

> **Музей истории горного и плавильного дела в поселке Жезды имени Макена Торегельдина**

This translates approximately to:

> **Museum of the History of Mining and Smelting in the village of Zhezdy named after Maken Toregeldin.**

This provides the critical geographical lead: **Zhezdy, Kazakhstan**.

---

## 4. Visual Cross-Reference

The second image provides another clear view of the same entrance and its identifying sign.

<img width="480" height="142" alt="image" src="https://github.com/user-attachments/assets/e9c0f1ef-e5d0-4593-86f7-6aff5ba98199" />

The following visual elements are consistent between the challenge photograph and the reference:

1. The same pale stone facade.
2. The same three arched openings.
3. The same reddish decorative panels.
4. The same long masonry wall.
5. The same museum signage.
6. The same mining-related exhibits outside.
7. The same bust in front of the building.

This makes the building identification substantially stronger than relying only on a generic search for museums in Kazakhstan.

---

## 5. Identifying the Museum

The distinctive museum name leads to Kazakhstan's National E-Museum records.

The institution is identified as:

**Museum of the History of Mining and Smelting in the village of Zhezdy named after Maken Toregeldin**

The museum is located in:

- **Settlement:** Zhezdy
- **District:** Ulytau District
- **Region:** Ulytau Region
- **Country:** Kazakhstan
- **Address:** Kozhabay Akyn Street 4

The museum's collection focuses on the mining and metallurgical history of the area, including mining equipment, ore samples, metallurgical artefacts and historical material.

---

## 6. Why the Industry Clue Fits

The challenge says that the location is connected to:

> **“an industry that left physical traces across an entire region.”**

This fits Zhezdy's history particularly well.

Zhezdy became an important mining centre, especially because of its **manganese deposit**. A manganese mine was opened near the Zhezdy River in **1942**, during World War II.

Manganese was strategically important to steel production, including the production of armour and military equipment.

The Zhezdy mining area therefore left extensive physical traces in the surrounding landscape and became an important part of the region's industrial history.

The museum exists specifically to preserve this mining and metallurgical heritage.

---

## 7. Maken Toregeldin Connection

The museum is named after **Maken Toregeldin**, who played an important role in documenting and preserving the mining and metallurgical history of the region.

Historical material associated with the museum connects Toregeldin with the **Karsakpai copper-smelting plant** and the mining industry of the region.

The museum subsequently became a repository for historical objects associated with:

- Mining
- Ore extraction
- Metallurgy
- Smelting
- Industrial transportation
- Geological resources

This further reinforces the connection between the photograph and the challenge's industry clue.

---

## 8. Administrative Region Issue

One important complication during the investigation was the region name.

Older documentation refers to the area as part of **Karaganda Region**.

However, Kazakhstan subsequently established **Ulytau Region**, and Zhezdy is now administratively located in:

> **Ulytau District, Ulytau Region, Kazakhstan**

Therefore, for a modern geolocation answer, **Ulytau Region** is the relevant current administrative region.

This distinction is particularly important because the CTF flag format explicitly requires a `region` field.

---

## 9. Coordinate Investigation

The museum's documented address identifies the exact building as:

> **Kozhabay Akyn Street 4, Zhezdy, Ulytau District, Ulytau Region, Kazakhstan.**

It is important not to confuse:

- Coordinates for the Zhezdy settlement,
- Coordinates for the historical mining area,
- Coordinates for the museum itself.

For this challenge, the required coordinates should correspond to the **photographed museum/building**, not simply the centre of Zhezdy or the Zhezdy manganese mine.

This distinction matters because the challenge requires coordinates rounded to exactly two decimal places.

---

## 10. Failed Coordinate Attempts

During investigation, two candidate flags were tested:

```text
Lun4R{zhezdy_ulytau_kazakhstan_48.06_67.05}
```

and:

```text
Lun4R{zhezdy_ulytau_kazakhstan_48.06_67.06}
```

Both were rejected by the challenge.

This means that although the **building identification is strongly supported**, the exact coordinate pair expected by the challenge has not been conclusively established from the sources used so far.

Therefore, these rejected coordinates should **not** be presented as the final verified flag.

---

## 11. Conclusion

The photograph can be identified from the signage and architectural cross-reference as the:

> **Museum of the History of Mining and Smelting in Zhezdy named after Maken Toregeldin**

The location is:

> **Zhezdy, Ulytau District, Ulytau Region, Kazakhstan**

The industrial clue is consistent with Zhezdy's historic **manganese mining and metallurgical industry**, which played a significant role in the region during the Soviet period and particularly during World War II.

### Confirmed identification

| Field | Result |
|---|---|
| Place | Museum of the History of Mining and Smelting named after Maken Toregeldin |
| Settlement | Zhezdy |
| District | Ulytau District |
| Current region | Ulytau Region |
| Country | Kazakhstan |
| Industry | Mining and metallurgy |
| Major historical resource | Manganese |
| Museum address | Kozhabay Akyn Street 4 |

### Final flag status

The exact `Lun4R{...}` flag remains **unverified** because the two coordinate variants tested during the investigation were rejected.

The correct next step is to obtain the **exact coordinates of the museum entrance/building** from a reliable map or geolocation source and round those coordinates to two decimal places.

---

## Sources

- Kazakhstan National E-Museum - Museum of the History of Mining and Smelting in Zhezdy.
- Museum of Zhezdy - historical information about Maken Toregeldin and the museum.
- Geological research concerning the mining heritage of the Ulytau region.
- Historical/industrial documentation concerning the Zhezdy manganese deposit.

> **Note:** The building identification is supported independently by the visible signage, architectural comparison, and museum records. The exact challenge coordinate remains unresolved because the tested coordinate variants were rejected.

---

## Investigation Summary

**Photograph → Read museum sign → Identify Zhezdy → Cross-reference facade → Confirm mining/metallurgy connection → Determine current administrative region → Obtain exact museum coordinates → Construct final flag**

The strongest confirmed result from the investigation is therefore:

```text
Museum of the History of Mining and Smelting
Zhezdy
Ulytau Region
Kazakhstan
```
