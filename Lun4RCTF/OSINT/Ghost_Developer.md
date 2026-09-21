# Ghost Developer

## Challenge Information

- **Challenge name:** Ghost Developer
- **Category:** Open-source intelligence and Git forensics
- **Difficulty:** Lite
- **Flag format:** `Lun4R{...}`

## Summary

The challenge concerns Elias Voss, a developer who disappeared after leaving Lunar Dynamics. His public repository history contains evidence that was removed from the current project state but remains recoverable through Git history.

The decisive artifact is the deleted `archive-verification.txt` file in commit `d7c82ad` of the `nightshift404/archive-utils` repository. Its archive checksum is the required flag value.

## Investigation

The challenge description identifies several useful leads:

- Elias Voss worked at Lunar Dynamics.
- His employee ID was `442`.
- The repository was supposedly cleaned before his disappearance.
- A hidden `orbit-17` branch is associated with Elias’s public footprint.
- The relevant identity is connected to the “night shift” clue.

The first step is to locate the repository associated with the night-shift identity. The relevant repository is `nightshift404/archive-utils`.

The current branch contents do not directly reveal the answer. Because the description says that the project was cleaned, the next step is to inspect deleted files and earlier commits rather than only examining the current tree.

## Git-History Analysis

The deleted historical content can be inspected with standard Git commands:

```bash
git clone https://github.com/nightshift404/archive-utils.git
cd archive-utils

git log --all --oneline --decorate
```

The relevant historical commit is:

```text
d7c82ad
```

Inspecting the commit and its deleted files reveals `archive-verification.txt`:

```bash
git show d7c82ad --stat
git show d7c82ad -- archive-verification.txt
```
<img width="995" height="1001" alt="image" src="https://github.com/user-attachments/assets/230378d5-e3ed-4ad5-8a7d-00731a5c86ca" />

The file contains the following decisive text:

> Final archive checksum:
>
> `NF9-27-LUN4R`

This value matches the required challenge flag payload format.

## Flag Construction

The challenge specifies the wrapper format:

```text
Lun4R{...}
```

Substituting the recovered archive checksum produces:

```text
Lun4R{NF9-27-LUN4R}
```

## Final Answer

```text
Lun4R{NF9-27-LUN4R}
```

## References

[1]: https://github.com/nightshift404/archive-utils "nightshift404 archive-utils repository"

[2]: https://github.com/eliasvoss442/orbital-sync/tree/orbit-17 "Elias Voss orbital-sync orbit-17 branch"

[3]: https://git-scm.com/docs/git-show "Git show documentation"

[4]: https://git-scm.com/docs/git-log "Git log documentation"
