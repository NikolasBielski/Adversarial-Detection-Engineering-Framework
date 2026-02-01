# ADE3 - Context Development

Context Development bugs occur when an attacker takes additional steps to **manipulate or poison contextual data** used by the detection logic, causing in-scope activity to bypass rule conditions.

Rather than changing the primary malicious action, the attacker shapes the **surrounding context** that the rule relies on.

## Subcategories

### ADE3-01: Context Development - Process Cloning

**Definition:** Detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries. If the attacker has sufficient privileges to duplicate and rename a binary, they can execute identical behavior under a different process name, resulting in a False Negative.

**Common Scenarios:**
- Linux: `cp /usr/bin/wget /tmp/foo` → Use `/tmp/foo` for malicious download
- Windows: Copy legitimate binary to user-writable location
- Any process name-based detection without hash/signature validation

**Why It Works:**
- Cloned binary has identical functionality
- File hash remains the same
- Only the process name field changes in logs
- Many detection rules only check `process.name` or `Image` fields

---

### ADE3-02: Context Development - Aggregation Hijacking

**Definition:** Detection logic relies on **aggregated values** that an attacker can influence or precondition.

**Common Patterns:**
- **Threshold-based rules:** "Alert if >10 failed logins" → Attacker stays at 9
- **"Newly seen" logic:** "Alert on first-time process" → Attacker runs benign version first
- **UEBA entity grouping:** `source.ip:user.name` → Attacker matches existing baseline
- **File size/name length aggregations:** Attacker manipulates to stay within expected ranges

**Examples:**
- Aggregations over file sizes, file name lengths, or counts
- UEBA-style entities (e.g., `source.ip:user.name`)
- "New terms" rules that group by abstract fields
- Threshold-based logic with attacker-visible counters

**Attack Pattern:**
1. Attacker reconnaissance: Observe current baselines/thresholds
2. Preparatory activity: Pre-condition aggregation buckets
3. Malicious action: Execute within established baseline → No alert

---

### ADE3-03: Context Development - Timing and Scheduling

**Definition:** Detection logic relies on **time-based assumptions**, such as execution frequency, duration, or inter-event timing. By spacing, batching, or scheduling actions to avoid inclusion within rule execution windows or aggregation periods, an attacker can bypass detection without changing the underlying behavior.

**Common Patterns:**
- **Sequence rules with maxspan:** `maxspan=1m` → Attacker waits >1 minute between steps
- **File age checks:** "Alert if file <500s old" → Attacker waits 501 seconds
- **Lookback periods:** "Check last 15 days" → Attacker waits 16 days
- **Rate limiting:** "Alert if >5 per minute" → Attacker does 4/minute

**Attack Pattern:**
1. Identify time constraints in detection logic
2. Space malicious actions to fall outside time windows
3. Achieve same outcome without triggering temporal thresholds

---

### ADE3-04: Context Development - Event Fragmentation

**Definition:** Detection logic relies on **multi-substring matching** (using `|all`, `contains|all`, or multiple `AND` conditions) while assuming all required substrings will appear in a single process creation event. However, shell operators like `|` and `&` cause commands to be split into multiple separate process creation events, preventing the detection logic from matching, resulting in a False Negative.

**Why This Happens:**
- Operating systems fragment piped commands at the OS level
- Each command in a pipe generates a separate process creation event
- No single event contains all the substrings the rule expects

**Result:** In-scope malicious activity bypasses detection without the attacker needing to know the rule exists. This is **unintentional evasion** - a natural consequence of OS behavior.

**Related Research:**
- [Detection Pitfalls by Jared Atkinson](https://detect.fyi/detection-pitfalls-you-might-be-sleeping-on-52b5a3d9a0c8)
- [Unintentional Evasion: Command Line Logging Gaps](https://detect.fyi/unintentional-evasion-investigating-how-cmd-fragmentation-hampers-detection-response-e5d7b465758e)

## Examples

### Real-World Detection Logic Bugs

**ADE3-01 - Process Cloning:**
1. **[Wget Download to Tmp - Process Cloning](../../examples/ade3/process-cloning-wget.md)**
   - Clone `/usr/bin/wget` → Use cloned binary
   - Platform: Linux (Sysmon for Linux)

**ADE3-04 - Event Fragmentation:**
2. **[LSASS Process Reconnaissance - Event Fragmentation](../../examples/ade3/event-fragmentation.md)**
   - Command: `tasklist | findstr lsass`
   - Fragmented across multiple process creation events
   - Platform: Windows Event ID 4688

## Detection Rule Patterns Vulnerable to ADE3

### ADE3-01 Patterns

**Process name-only matching:**
```yaml
Image|endswith: '/wget'
process.name: "powershell.exe"
```

**Without:**
- File hash validation
- Code signature checks
- Binary path immutability

### ADE3-02 Patterns

**Threshold rules:**
```
count > 10
length(field) > 30
```

**New terms rules:**
```yaml
type: "new_terms"
field: "host.id"  # Too abstract
```

**Time-based baselines:**
```
not seen in last 15 days
```

### ADE3-03 Patterns

**Sequence rules:**
```yaml
sequence by host.id with maxspan=1m
```

**File age checks:**
```
file.created < 500 seconds ago
```

**Aggregation windows:**
```
bucket_span: "5m"
lookback: "now-9m"
```

### ADE3-04 Patterns

**Multi-substring matching:**
```yaml
CommandLine|contains|all:
    - 'string1'
    - 'string2'
    - 'string3'
```

**With:**
- Shell operators: `|`, `&`, `&&`, `||`
- Piped commands
- Chained execution

## Mitigation Strategies

### For ADE3-01 (Process Cloning)

**1. Use immutable identifiers:**
```yaml
# Instead of process.name
file.hash.sha256: "abc123..."
process.code_signature.subject_name: "Microsoft Corporation"
```

**2. Combine with behavioral detection:**
```yaml
# Process + Network + File behavior
(process creates network connection) AND
(file written to sensitive location) AND
(execution context abnormal)
```

**3. Monitor binary cloning:**
```yaml
# Detect cp/copy operations on system binaries
event.action: "file_create" AND
file.path: "/usr/bin/*" AND
process.name: "cp"
```

### For ADE3-02 (Aggregation Hijacking)

**1. Use granular entity keys:**
```yaml
# Instead of just host.id
new_terms.fields: ["host.id", "user.name", "process.args"]
```

**2. Implement non-manipulable thresholds:**
```yaml
# Use ratios instead of counts
(failed_logins / total_logins) > 0.8
```

**3. Combine with absolute indicators:**
```yaml
# Even if below threshold, flag high-risk patterns
(count < 10) AND (process.name in high_risk_list)
```

### For ADE3-03 (Timing and Scheduling)

**1. Use longer time windows:**
```yaml
# Instead of maxspan=1m
maxspan=10m  # Harder to evade
```

**2. Remove time constraints when possible:**
```yaml
# Focus on outcome, not timing
any([event1, event2, event3]) within session
```

**3. Monitor timing anomalies:**
```yaml
# Detect suspiciously precise timing
event_interval == exactly 601 seconds  # Just outside 10min window
```

### For ADE3-04 (Event Fragmentation)

**1. Use sequence rules:**
```yaml
sequence by host.id with maxspan=5s
  [process where process.name == "tasklist.exe"]
  [process where process.name == "findstr.exe" and
                  process.args contains "lsass"]
```

**2. Detect individual components:**
```yaml
# Don't require all in one event
tasklist.exe OR (findstr.exe AND args contains "lsass")
```

**3. Focus on parent-child relationships:**
```yaml
sequence
  [process where process.name == "cmd.exe"]
  [process where process.parent.name == "cmd.exe"]
```

## Why Context Development Is Powerful

**Key Insight:** ADE3 bugs often don't require the attacker to know detection rules exist.

**ADE3-01:** Process cloning is a natural privilege escalation/evasion technique
**ADE3-02:** Attackers naturally do reconnaissance before attacking
**ADE3-03:** Operational security naturally involves timing spacing
**ADE3-04:** Piped commands are **standard shell usage** - not intentional evasion

## Related Bug Categories

ADE3 often appears alongside:
- **ADE1-01 (Substring Manipulation):** Context manipulation often involves string changes
- **ADE2-01 (Omit Alternatives):** Cloned binaries are "alternative" execution methods
- **ADE4-01 (Gate Inversion):** Timing/aggregation manipulation can flip Boolean gates

## Testing Your Rules

**Quick Test Questions:**

**For ADE3-01:**
- ✅ Does your rule only check process names, not hashes/signatures?
- ✅ Can the target binary be copied by users with expected privileges?
- ✅ Would renaming the binary bypass detection?

**For ADE3-02:**
- ✅ Can an attacker see current aggregation baselines?
- ✅ Are thresholds/counts visible to compromised accounts?
- ✅ Could preparatory "benign" activity poison aggregations?

**For ADE3-03:**
- ✅ Does your rule have hard-coded time windows (maxspan, lookback)?
- ✅ Could an attacker wait out the time constraint?
- ✅ Are file age checks based on attacker-controllable timestamps?

**For ADE3-04:**
- ✅ Does your rule use multi-substring matching (`contains|all`)?
- ✅ Are you matching against command-line fields?
- ✅ Could shell operators fragment the command?

If you answered "yes" to any category's questions, your rule likely has an ADE3 vulnerability.

---

**Navigation:**
- [← ADE2: Omit Alternatives](ade2-omit-alternatives.md)
- [Back to Taxonomy Overview](overview.md)
- [Theory: Detection Logic Bugs](../theory/detection-logic-bugs.md)
- [Next: ADE4 - Logic Manipulation →](ade4-logic-manipulation.md)
