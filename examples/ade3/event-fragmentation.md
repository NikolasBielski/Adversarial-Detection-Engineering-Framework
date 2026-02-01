# ADE3-04 Example: Event Fragmentation - LSASS Process Reconnaissance

**Bug Category:** ADE3-04 Context Development - Event Fragmentation

## Pseudo-Code Example

**Rule Intent:** Detect attempts to identify or enumerate the LSASS (Local Security Authority Subsystem Service) process on Windows systems.

```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_findstr:
        CommandLine|contains|all:
            - 'tasklist'
            - 'findstr'
            - 'lsass'
    condition: all of selection_*
```

## The Bug

**Detection logic expects:** A single process creation event containing all three substrings: `tasklist`, `findstr`, and `lsass`

**Reality:** Shell operators (`|`, `&`, `&&`, `||`) **fragment commands** into **multiple separate process creation events** at the OS level.

**Implicit assumption:** All command components appear in a single event

**What actually happens:** Each part of a piped command generates a distinct event

## Command Fragmentation Behavior

### Expected Command
```cmd
tasklist | findstr "lsass"
```

### Actual Process Creation Events

**Event 1:**
```
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c tasklist
```

**Event 2:**
```
Image: C:\Windows\System32\tasklist.exe
CommandLine: tasklist
```

**Event 3:**
```
Image: C:\Windows\System32\findstr.exe
CommandLine: findstr "lsass"
```

## Detection Logic Evaluation

**Rule requires:**
```yaml
CommandLine|contains|all:
    - 'tasklist'    ✓ (Event 2)
    - 'findstr'     ✓ (Event 3)
    - 'lsass'       ✓ (Event 3)
```

**Problem:** No single event contains all three substrings simultaneously

- Event 1: `cmd.exe /c tasklist` → Contains "tasklist" only
- Event 2: `tasklist` → Contains "tasklist" only
- Event 3: `findstr "lsass"` → Contains "findstr" and "lsass"

**Result:** `CommandLine|contains|all` = **False** for all events → **False Negative**

## Why This Happens

### Windows Command Processing

When you execute:
```cmd
cmd.exe /c "tasklist | findstr lsass"
```

Windows shell:
1. Creates `cmd.exe` process
2. Parses pipe operator `|`
3. Spawns `tasklist.exe` (writes to stdout)
4. Spawns `findstr.exe` (reads from stdin, filters)
5. Each spawn = separate Event ID 4688 (process creation)

### Shell Operators That Fragment

All of these cause command fragmentation:

**Pipe:**
```cmd
command1 | command2
```

**Background execution:**
```cmd
command1 & command2
```

**Conditional execution:**
```cmd
command1 && command2
command1 || command2
```

## Related Research

- [Detection Pitfalls by Jared Atkinson](https://detect.fyi/detection-pitfalls-you-might-be-sleeping-on-52b5a3d9a0c8)
- [Unintentional Evasion: Command Line Logging Gaps](https://detect.fyi/unintentional-evasion-investigating-how-cmd-fragmentation-hampers-detection-response-e5d7b465758e)

## Impact

**False Negative:** In-scope malicious activity (LSASS process enumeration) bypasses detection without the attacker needing to know the rule exists.

**Critical insight:** This isn't deliberate evasion - it's **unintentional** bypass caused by how operating systems process shell commands.

## Vulnerable Detection Patterns

**Any rule using multi-substring matching:**

**Sigma:**
```yaml
CommandLine|contains|all:
    - 'string1'
    - 'string2'
    - 'string3'
```

**KQL:**
```kql
CommandLine has_all ("string1", "string2", "string3")
```

**EQL:**
```eql
process where process.command_line like~ "*string1*" and
               process.command_line like~ "*string2*" and
               process.command_line like~ "*string3*"
```

## Mitigation Strategies

### 1. Use Sequence Rules (Recommended)

Detect the command flow across multiple events:

```yaml
# Pseudo-code
sequence by host.id with maxspan=5s
  [process where process.name == "tasklist.exe"]
  [process where process.name == "findstr.exe" and process.args contains "lsass"]
```

### 2. Detect Individual Components

Instead of requiring all substrings together:

```yaml
detection:
    tasklist_execution:
        Image|endswith: '\tasklist.exe'
    findstr_lsass:
        Image|endswith: '\findstr.exe'
        CommandLine|contains: 'lsass'
    condition: tasklist_execution or findstr_lsass
```

### 3. Focus on Outcome, Not Method

Detect what the command achieves:
- LSASS process access attempts
- Memory reads from LSASS PID
- Handle creation to LSASS

### 4. Parent-Child Relationships

Track process ancestry:

```yaml
sequence by host.id
  [process where process.name == "cmd.exe"]
  [process where process.parent.name == "cmd.exe" and
                  process.name in ("tasklist.exe", "findstr.exe")]
```

## Additional Fragmentation Scenarios

**PowerShell:**
```powershell
Get-Process | Where-Object {$_.Name -eq "lsass"}
```
Multiple events: `powershell.exe`, pipeline operations

**Bash:**
```bash
ps aux | grep lsass
```
Multiple events: `ps`, `grep`

**Batch scripts:**
```cmd
FOR /F %i IN ('tasklist ^| findstr lsass') DO echo %i
```
Complex fragmentation across loop iterations

## Testing Your Rules

**Questions to identify ADE3-04 vulnerabilities:**

- ✅ Does your rule use `contains|all` or equivalent multi-substring matching?
- ✅ Are you matching against `CommandLine` or similar fields?
- ✅ Could shell operators fragment the command you're detecting?
- ✅ Have you tested with piped commands (`|`)?
- ✅ Have you tested with chained commands (`&`, `&&`, `||`)?

If you answered "yes" to the first three questions and "no" to the last two, your rule is likely vulnerable to ADE3-04.

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
