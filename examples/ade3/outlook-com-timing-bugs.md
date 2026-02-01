# ADE3-03 Example: Outlook COM Collection Multiple Timing Bugs

**Bug Categories:**
- ADE3-01 Context Development - Process Cloning
- ADE3-02 Context Development - Aggregation Hijacking
- ADE3-03 Context Development - Timing and Scheduling (2 bugs)

## Original Rule

**Source:** [Elastic Security - Collection Email Outlook Mailbox Via Com](https://github.com/elastic/detection-rules/blob/main/rules/windows/collection_email_outlook_mailbox_via_com.toml)

**Description:** This Elastic Query Language sequence rule looks for cases where a process starts and uses the Component Object Model to communicate with Outlook. Attackers may target email accounts to collect sensitive information or send emails on behalf of victims using API endpoints.

```SQL
from = "now-9m"
....
sequence with maxspan=1m
[process where host.os.type == "windows" and event.action == "start" and
  (
    process.name : (
      "rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
      "cmd.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"
    ) or
    (
      (process.code_signature.trusted == false or process.code_signature.exists == false) and
      (process.Ext.relative_file_creation_time <= 500 or process.Ext.relative_file_name_modify_time <= 500)
    )
  )
] by process.entity_id
[process where host.os.type == "windows" and event.action == "start" and process.name : "OUTLOOK.EXE" and
  process.Ext.effective_parent.name != null] by process.Ext.effective_parent.entity_id
```

## Detection Logic Analysis

**Sequence rule mechanics:**

A sequence rule runs as a state machine constrained to a timespan (`maxspan`). All matching records within the timespan must be present for a hit to occur ([EQL sequence syntax reference](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)).

- `from = "now-9m"` - Lookback period to include records with delayed ingest
- `maxspan=1m` - Both states must occur within 60 seconds
- Entity grouping joins `process.entity_id` (State 1) with `process.Ext.effective_parent.entity_id` (State 2)

**State 1:** Parent process creation
- `process.name` in listed suspicious processes (rundll32, powershell, etc.)
- OR both:
  - Untrusted/missing code signature
  - AND file created/modified ≤500 seconds before process start

**State 2:** Outlook process creation
- `process.name : "OUTLOOK.EXE"`
- Parent process ID exists

## Threat Context

**Referenced atomic:** [APT29 CALDERA payload - stepSeventeen_email.ps1](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1)

```PowerShell
function psemail {
	Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
	$olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
	$outlook = new-object -comobject outlook.application
	$namespace = $outlook.GetNameSpace("MAPI")
	$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
	$folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body
}
```

**Detection scope:** Any case where listed `process.name` creates `outlook.EXE` process, regardless of activity.

**This rule contains 4 separate detection logic bugs.**

---

## Bug 1: ADE3-01 Context Development - Process Cloning

**Vulnerability:** Field `process.name` is mutable.

**Bypass:**

If the attacker uses a process NOT in the hardcoded list:

```PowerShell
# Instead of using powershell.exe directly
cp C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Users\Public\legit.exe

# Run with cloned binary
C:\Users\Public\legit.exe -File collect_outlook.ps1
```

**Result:**
- State 1 checks `process.name` for exact matches
- `legit.exe` not in list → State 1 fails
- Unless file has untrusted signature AND was created ≤500 seconds ago

**Mitigation:** Use immutable identifiers (code signature, file hash, PE metadata).

---

## Bug 2: ADE3-03 Context Development - Timing (File Age)

**Vulnerability:** File metadata timing checks can be bypassed.

### Field Analysis

**Custom enrichment fields (Elastic Endgame):**
- `process.Ext.relative_file_creation_time`
- `process.Ext.relative_file_name_modify_time`

**Assumed calculation (no official documentation):**
- `relative_file_creation_time` = process created time - process file creation time (seconds)
- `relative_file_name_modify_time` = file last modification time - process creation time (seconds)

**Vulnerable logic:**
```SQL
(process.Ext.relative_file_creation_time <= 500 or process.Ext.relative_file_name_modify_time <= 500)
```

### Milliseconds vs Seconds?

**ADE assumes seconds** because:
1. Intent is to catch recent activity prior to process creation
2. Milliseconds would be too narrow in practice due to latencies across hosts
3. Although timestamps are in milliseconds, assuming larger unit is safer for False Negative analysis

### Bypass - Wait Out the File Age Check

**Attack:**

```PowerShell
# Step 1: Create malicious file
"malicious code" | Out-File C:\Users\Public\evil.ps1

# Step 2: Wait > 500 seconds (8.5 minutes)
Start-Sleep -Seconds 501

# Step 3: Execute
C:\Users\Public\evil.ps1
```

**Result:**
- Both `relative_file_creation_time` and `relative_file_name_modify_time` > 500
- Condition requires ≤500 → False
- Must also have untrusted signature → False
- State 1 fails if `process.name` not in hardcoded list

**Note:** File must have untrusted/missing signature to rely on this path.

---

## Bug 3: ADE3-03 Context Development - Timing (Sequence maxspan)

**Vulnerability:** Sequence rule requires all states within `maxspan=1m` (60 seconds).

### Bypass - Sleep Between COM Calls

**Modified atomic:**

```PowerShell
function false_negative_psemail {
	Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
	$olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]

	Start-Sleep -Seconds 120   # Wait > 60 seconds (maxspan)

	$outlook = new-object -comobject outlook.application
	$namespace = $outlook.GetNameSpace("MAPI")
	$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
	$folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body
}
```

**Result:**
- State 1: PowerShell process starts → logged
- **Wait 120 seconds** → exceeds `maxspan=1m`
- State 2: Outlook.exe process starts (via COM) → logged
- Sequence logic: Time between states > 60 seconds → **No match**

**Lookback period note:**
- `from = "now-9m"` allows delayed ingest events
- Old Outlook.exe creation event is NOT considered delayed
- Would be included in dataset from 120 seconds ago
- But State 1 event no longer within `maxspan` window

**Impact:** Simple `Start-Sleep` bypasses entire sequence rule.

---

## Bug 4: ADE3-02 Context Development - Aggregation Hijacking

**Vulnerability:** Outlook COM single-instance behavior.

### How COM Works

**Outlook is a single-instance COM local server:**
- If Outlook is already running, it's registered in COM
- PowerShell calls `new-object -comobject outlook.application`
- COM returns mapping to **existing instance** instead of launching new process
- **No new process creation event** is generated

### Bypass - Pre-launch Outlook

**Scenario 1: Outlook already running**

If `outlook.exe` is running when script executes:
- State 1: PowerShell starts → logged
- State 2: Expects `OUTLOOK.EXE` process start → **NOT logged** (reuses existing instance)
- Sequence fails → No alert

**Scenario 2: Attacker pre-launches Outlook**

```PowerShell
# Step 1: Launch Outlook legitimately (benign activity)
Start-Process "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"

# Step 2: Wait for process to fully start
Start-Sleep -Seconds 10

# Step 3: Run malicious collection script
powershell -File collect_emails.ps1
```

**Result:**
- Outlook.exe process creation logged BEFORE malicious script
- Malicious script connects to existing COM instance
- No second process creation event → State 2 never fires
- Sequence fails → **No alert**

### Context Development

**Attacker develops context by:**
1. Checking if Outlook is running: `Get-Process outlook -ErrorAction SilentlyContinue`
2. If not running, launch it legitimately
3. Wait for COM registration
4. Execute malicious script knowing it will reuse instance
5. Hijacks the aggregation (entity join on process IDs fails because no new PID created)

**Minimal permissions required:**
- Ability to create/run files (same as atomic requires)
- Ability to view running processes
- Both are standard user capabilities

---

## Combined Impact

**This rule can be bypassed via 4 independent paths:**

1. **Process cloning:** Use renamed PowerShell → State 1 fails
2. **File age timing:** Create file, wait >500s → State 1 alternative condition fails
3. **Sequence timing:** Sleep between steps >60s → Sequence maxspan exceeded
4. **Outlook pre-launch:** Start Outlook before script → State 2 never fires

**Stacked bugs:**
- Attacker can combine multiple bypasses
- Example: Clone PowerShell + pre-launch Outlook → Double bypass
- Detection rule has multiple single points of failure

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE3-01 Process Cloning](../../docs/taxonomy/ade3-context-development.md#ade3-01-context-development---process-cloning)
- [ADE3-02 Aggregation Hijacking](../../docs/taxonomy/ade3-context-development.md#ade3-02-context-development---aggregation-hijacking)
- [ADE3-03 Timing and Scheduling](../../docs/taxonomy/ade3-context-development.md#ade3-03-context-development---timing-and-scheduling)
