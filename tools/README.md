# tools/ — the responder payload (not committed)

This folder holds the **open-source responder tools** the collectors detect and use. The binaries are
**not** committed to the repo (licensing + size); build the payload on a trusted workstation with the
one-time kit builder, then carry the drive:

```
# Windows payload -> tools\
powershell -ExecutionPolicy Bypass -File ..\fetch-tools.ps1

# Linux payload -> tools/bin\
bash ../fetch-tools.sh
```

That pulls, from official GitHub releases (with SHA-256 provenance recorded in `PROVENANCE-*.txt`):

- **WinPmem** / **AVML** — memory acquisition
- **Velociraptor** / **CyLR** / **UAC** — artifact triage
- **SharpHound** — Active Directory (BloodHound)
- **Chainsaw** / **Hayabusa** / **EZ-Tools** — event-log & artifact parsing
- **busybox** (static) — Linux fallback core binaries

Free-but-proprietary tools (Sysinternals, KAPE, FTK Imager, Magnet RAM) are **not** auto-fetched — add
them here manually only if your engagement permits. The collectors run with zero tools present and
degrade to native/kernel-level collection.
