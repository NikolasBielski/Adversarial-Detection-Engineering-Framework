# Quick Start: Applying ADE to Detection Rules

This guide walks you through applying the ADE Framework to analyze your first detection rule.

## Prerequisites

- Familiarity with detection rules (SIEM, XDR, EDR queries)
- Understanding of [Core ADE Concepts](core-concepts.md)
- Access to a detection rule to analyze

## Step-by-Step Analysis

### Step 1: Identify Rule Scope

**Extract the rule's intended purpose:**

- ✅ Read the rule description
- ✅ Check MITRE ATT&CK mappings
- ✅ Review metadata (author notes, references)
- ✅ Understand *what* the rule is trying to detect

**Example:**
```yaml
title: Suspicious PowerShell Download
description: Detects suspicious PowerShell download command
tags:
    - attack.execution
    - attack.t1059.001
```

**Scope:** Detect when PowerShell scripts download files from remote hosts

### Step 2: Understand Detection Logic

**Analyze the hypothesis test:**

- ✅ What fields are being checked?
- ✅ What conditions must be met?
- ✅ What Boolean logic is used (AND/OR/NOT)?
- ✅ What is the *actual* query doing?

**Example:**
```yaml
detection:
    selection_webclient:
        Data|contains: 'Net.WebClient'
    selection_download:
        Data|contains:
            - '.DownloadFile('
            - '.DownloadString('
    condition: all of selection_*
```

**Logic:** `(Data contains 'Net.WebClient') AND (Data contains '.DownloadFile(' OR '.DownloadString(')`

### Step 3: Run the Bug Likelihood Test

Use the [Bug Likelihood Test](../guides/bug-likelihood-test.md) checklist:

**Quick questions:**

- [ ] Is there string matching on attacker-controlled fields? → **ADE1-01**
- [ ] Are there alternative methods/binaries omitted? → **ADE2-01**
- [ ] Are there OS/version-specific assumptions? → **ADE2-02**
- [ ] Does it rely on process names without additional checks, such as hashes or original file names? → **ADE3-01**
- [ ] Are there time-based constraints? → **ADE3-03**
- [ ] Multiple `NOT` clauses that could be simplified? → **ADE4-01**

**For our example:**
- [x] String matching: `contains '.DownloadFile('` → **ADE1-01 suspected**
- [x] Alternative methods: Only checks 2 methods → **ADE2-01 suspected**

### Step 4: Identify Specific Bugs

**For each suspected category, enumerate bypasses:**

#### ADE1-01: Substring Manipulation

**Can the attacker manipulate the matched string?**

```powershell
# Original (detected):
$wc = New-Object Net.WebClient
$file = $wc.DownloadFile($url, $path)

# Bypass 1: String concatenation
$methodName = "Down" + "loadFile"
$file = $wc.$methodName($url, $path)

# Bypass 2: Reflection
$file = $wc.GetType().InvokeMember("DownloadFile", ...)
```

✅ **Bug confirmed:** ADE1-01 Substring Manipulation

#### ADE2-01: Omit Alternatives

**Are there other APIs that achieve the same goal?**

```powershell
# Not detected - alternative methods:
Invoke-WebRequest -Uri $url -OutFile $path
Invoke-RestMethod -Uri $url | Out-File $path
[System.Net.WebClient]::new().DownloadFile($url, $path)
Start-BitsTransfer -Source $url -Destination $path
```

✅ **Bug confirmed:** ADE2-01 Omit Alternatives - Method/Binary

### Step 5: Test Bypasses

**Create test cases:**

```powershell
# Test 1: Original technique (should detect)
$wc = New-Object Net.WebClient
$wc.DownloadFile("http://test.com/file", "C:\temp\file")

# Test 2: String concat bypass (should detect, probably won't)
$method = "Down" + "loadFile"
$wc.$method("http://test.com/file", "C:\temp\file")

# Test 3: Alternative API (should detect, probably won't)
Invoke-WebRequest -Uri "http://test.com/file" -OutFile "C:\temp\file"
```

**Expected:** All 3 should trigger
**Actual:** Only Test 1 triggers
**Conclusion:** Bugs confirmed

### Step 6: Document Findings

**Create bug report:**

```markdown
## Detection Rule: Suspicious PowerShell Download

### Identified Bugs

**ADE1-01: Substring Manipulation**
- Relies on exact string `.DownloadFile(` and `.DownloadString(`
- Bypass: String concatenation, reflection
- Severity: High
- Evidence: [Test case 2]

**ADE2-01: Omit Alternatives - Method/Binary**
- Only detects `WebClient.DownloadFile` and `WebClient.DownloadString`
- Missing: Invoke-WebRequest, Invoke-RestMethod, BITS, .NET methods
- Severity: High
- Evidence: [Test case 3]

### Recommended Fixes

1. **Behavioral detection** instead of string matching:
   - PowerShell process creates network connection
   - File written to disk
   - Execution context suspicious

2. **Broaden API coverage:**
   - Include all HTTP download cmdlets
   - Monitor file I/O + network together

3. **Remove reliance on exact strings:**
   - Use regex patterns
   - Detect .NET type usage patterns
```

### Step 7: Implement Fixes

**Option A: Quick fix (partial improvement)**
```yaml
detection:
    selection_download_apis:
        Data|contains:
            - 'DownloadFile'      # Removed . and (
            - 'DownloadString'
            - 'Invoke-WebRequest'
            - 'Invoke-RestMethod'
            - 'Start-BitsTransfer'
    condition: selection_download_apis
```

**Option B: Robust fix (behavioral)**
```yaml
sequence by host.id, process.entity_id with maxspan=5s
    [network where process.name in ("powershell.exe", "pwsh.exe")]
    [file where event.action == "create" and
               process.name in ("powershell.exe", "pwsh.exe")]
```

### Step 8: Re-test

**Run all test cases against improved rule:**

- Test 1: Original → ✅ Detected
- Test 2: String concat → ✅ Detected (if behavioral)
- Test 3: Alternative API → ✅ Detected
- Test 4: New bypass attempts → Document for next iteration

## Summary Workflow

```
1. Identify Scope     →  What should be detected?
2. Understand Logic   →  What is actually being checked?
3. Run Bug Test       →  Which ADE categories apply?
4. Identify Bugs      →  Enumerate specific vulnerabilities
5. Test Bypasses      →  Confirm with real examples
6. Document Findings  →  Record bugs and severity
7. Implement Fixes    →  Update detection logic
8. Re-test            →  Validate improvements
```

## Common Patterns

### Pattern 1: String Matching on Command Lines

**Vulnerable:**
```yaml
CommandLine|contains: "specific_command"
```

**ADE Categories:**
- ADE1-01: String manipulation
- ADE3-04: Event fragmentation (if using pipes)

**Fix:** Use behavioral detection or sequence rules

### Pattern 2: Static Process Name

**Vulnerable:**
```yaml
Image|endswith: '/wget'
```

**ADE Categories:**
- ADE3-01: Process cloning

**Fix:** Add file hash, signature checks, or original file name

### Pattern 3: Single API Check

**Vulnerable:**
```yaml
EventName == "ModifyDBInstance"
```

**ADE Categories:**
- ADE2-01: Omit alternative methods/binaries
- ADE2-02: Version drift

**Fix:** Enumerate all related APIs

### Pattern 4: Multiple Negations

**Vulnerable:**
```yaml
selection and not filter1 and not filter2
```

**ADE Categories:**
- ADE4-01: Gate inversion

**Fix:** Simplify with De Morgan's Laws: `selection and not (filter1 or filter2)`

## Practice Exercise

**Analyze this rule yourself:**

```yaml
title: Suspicious Use of Cat for Network Activity
detection:
    selection:
        process.name: "cat"
        network.direction: "outbound"
    condition: selection
```

**Questions:**
1. What is the scope?
2. What bugs might exist?
3. What bypasses can you think of?
4. How would you fix it?

**Answers:** [See ADE3-01 Example](../../examples/ade3/process-cloning-cat.md)

## Next Steps

**Now that you've applied ADE:**

1. **Analyze your top 10 detection rules** using this process
2. **Prioritize fixes** based on rule criticality and bug severity
3. **Document** known limitations for rules you can't immediately fix
4. **Contribute** new bugs you discover to the ADE Framework

**Deep dive into categories:**
- [ADE1 - Reformatting in Actions](../taxonomy/ade1-reformatting-in-actions.md)
- [ADE2 - Omit Alternatives](../taxonomy/ade2-omit-alternatives.md)
- [ADE3 - Context Development](../taxonomy/ade3-context-development.md)
- [ADE4 - Logic Manipulation](../taxonomy/ade4-logic-manipulation.md)

---

**Need help?**
- [Bug Likelihood Test](../guides/bug-likelihood-test.md) - Quick assessment checklist
- [Examples](../../examples/) - Real-world bug analysis
- [Core Concepts](core-concepts.md) - Terminology reference
