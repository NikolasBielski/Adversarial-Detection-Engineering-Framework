# ADE4 - Logic Manipulation

Logic Manipulation occurs when an attacker analyzes detection logic as Boolean conditions and manipulates inputs or filters to invert, bypass, or neutralize the rule outcome.

Attackers assess detection rule logic as **Boolean Algebra** and undertake additional steps to force the chain of Boolean tests to flip the output value, resulting in no hits.

It is common to see a Logic Manipulation bug in a detection rule along with another bug from a different category, as every logic manipulation requires another bug to invert or skip detection logic.

## Subcategories

### ADE4-01: Logic Manipulation - Gate Inversion

**Definition:** Gate inversion occurs when the detection rule includes a NOT clause (negation) which looks for data values that are mutable by the attacker through insertion of poisoned data prior to the record being generated. It often appears in rule exceptions or filters, where this bug, coupled with another bug, results in an "inversion" of the cumulative Boolean outcome of the rule.

**Most cases occur when:** The detection rule author didn't consider that multiple negations can be simplified using [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws).

**De Morgan's Laws:**
```
NOT A AND NOT B  ⟺  NOT (A OR B)
NOT A OR NOT B   ⟺  NOT (A AND B)
```

**Common Pattern:**
```yaml
detection:
    selection:
        suspicious_activity: true
    filter1:
        not field1: "value1"
    filter2:
        not field2: "value2"
    condition: selection and not filter1 and not filter2
```

**Simplifies to:**
```yaml
condition: selection and not (filter1 or filter2)
```

**Attack:** If attacker can insert `value1` OR `value2`, the entire condition becomes False.

---

### ADE4-02: Logic Manipulation - Conjunction Inversion

**Definition:** Conjunction inversion bugs occur when conjunction conditions (AND) within the rule look for data values vulnerable to manipulation by the attacker through insertion of poisoned data prior to record generation. Often appears when detection rules are updated to include a conjuncted condition that can be easily flipped by an attacker with the assumed privilege level needed to perform the in-scope activity.

**Example:** Creating poisoned data to fill an array at rule execution time, which if non-empty gets evaluated as benign due to a filter.

**Common Pattern:**
```yaml
condition: suspicious_activity AND not (field contains "safe_string")
```

**Attack:** Attacker adds "safe_string" to malicious payload to flip the conjunction.

---

### ADE4-03: Logic Manipulation - Incorrect Expression

**Definition:** Incorrect Expression occurs when detection logic has been crafted in a way that the interpreted query would rarely create hits. This occurs when a detection rule uses incorrect choices between negations, conjunctions, or disjunctions.

**Why it happens:**
- Lack of adversarial emulation
- No testing with generated data before production deployment
- Logic construction errors (AND vs OR confusion)

**Result:** The rule is ineffective by design, not due to attacker action.

**Common Mistakes:**
- Using AND when OR is required
- Negating privileged accounts in non-privilege-escalation rules
- Requiring mutually exclusive conditions

## Examples

### Real-World Detection Logic Bugs

**ADE4-03 - Incorrect Expression:**
1. **[Suspicious Shell Script - curl AND wget](../../examples/ade4/shell-script-incorrect-expression.md)**
   - Requires both `curl` AND `wget` in same command line
   - Real attacks use one OR the other
   - Platform: Linux Syslog (Microsoft Sentinel)

## Detection Rule Patterns Vulnerable to ADE4

### ADE4-01 Patterns (Gate Inversion)

**Multiple negations:**
```yaml
not condition1 and not condition2 and not condition3
```

**Should be simplified:**
```yaml
not (condition1 or condition2 or condition3)
```

**Negations on attacker-controlled fields:**
```yaml
not (field contains "bypass_string")  # Attacker can insert this
```

### ADE4-02 Patterns (Conjunction Inversion)

**Filters on mutable data:**
```yaml
suspicious_action and not (
    script_content contains "legitimate_tool_signature"
)
```

**Array/list evaluations:**
```yaml
array is not empty and array does not contain "poison_value"
```

### ADE4-03 Patterns (Incorrect Expression)

**AND when OR is needed:**
```yaml
cmdline has "curl" and cmdline has "wget"  # Unlikely both present
```

**Should be:**
```yaml
cmdline has "curl" or cmdline has "wget"
```

**Excluding privileged accounts from non-privesc rules:**
```yaml
suspicious_action and not (user in ("root", "SYSTEM", "Administrator"))
```

## 🚨 Risk of Negating Privileged Accounts

**Critical Issue:** Many detection rules negate privileged accounts (root, SYSTEM, Administrator) to reduce noise from standard administrative activity.

**Problem:** This only makes sense for **privilege escalation** detections. For initial access, persistence, lateral movement, and other tactics, privileged account activity **must** be monitored.

### Why This Is Dangerous

**Recent CVEs demonstrating unauthenticated RCE as root/SYSTEM:**

#### 2025 Examples

**🚨 [CVE-2025-20281 / CVE-2025-20337 – Cisco ISE](https://nvd.nist.gov/vuln/detail/CVE-2025-20337)**
- Unauthenticated remote code execution as **root**
- No credentials required
- Actively exploited by APTs in mid-2025

**🚨 [CVE-2025-59287 – Microsoft WSUS](https://nvd.nist.gov/vuln/detail/CVE-2025-59287)**
- Unauthenticated RCE with **SYSTEM-equivalent** privileges
- Windows Server Update Services component

**🚨 [CVE-2025-46811 — SUSE Manager Missing Authorization](https://www.suse.com/security/cve/CVE-2025-46811.html)**
- Unauthenticated RCE as **root**
- Root privileges on SUSE Manager server and managed clients

**🚨 [CVE-2025-32463 — sudo chroot privilege escalation](https://www.upwind.io/feed/cve-2025-32463-critical-sudo-chroot-privilege-escalation-flaw)**
- Local flaw allowing any unprivileged user to escalate to **root**
- Actively bypassed (added to security advisories)

#### 2024 Examples

**🚨 [CVE-2024-6387 — OpenSSH "regreSSHion"](https://nvd.nist.gov/vuln/detail/cve-2024-6387)**
- Critical unauthenticated RCE in OpenSSH server
- Leads to **root shell** / full system takeover

**🚨 [CVE-2024-1086 — Linux kernel netfilter privilege escalation](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)**
- Use-after-free in netfilter subsystem
- PoCs published leading to **root** privilege

### Impact

**Detection rules that exclude root/SYSTEM will miss:**
- ✗ Unauthenticated RCE exploits gaining immediate root access
- ✗ Privilege escalation exploits where attacker already has root
- ✗ Initial access via vulnerable services running as SYSTEM
- ✗ Persistence mechanisms installed at system level
- ✗ Lateral movement using elevated credentials

### When Negating Privileged Accounts Is Acceptable

**ONLY for privilege escalation detections:**
```yaml
# Detecting privilege escalation to root
rule: detect_privesc_to_root
scope: "Activity indicating escalation FROM lower privilege TO root"
logic: user.previous != "root" and user.current == "root"
```

**NOT acceptable for:**
- Initial access detections
- Persistence mechanisms
- Lateral movement
- Defense evasion
- Credential access
- Collection/Exfiltration

## Mitigation Strategies

### For ADE4-01 (Gate Inversion)

**1. Simplify with De Morgan's Laws:**

**Before:**
```yaml
selection and not filter1 and not filter2 and not filter3
```

**After:**
```yaml
selection and not (filter1 or filter2 or filter3)
```

**2. Avoid negations on attacker-controlled fields:**

**Bad:**
```yaml
not (script_content contains "tool_signature")
```

**Better:**
```yaml
script_content matches suspicious_pattern AND
not (signature_verified == true)  # Immutable system field
```

**3. Use allowlists instead of denylists:**

**Bad:**
```yaml
not (field in blacklist)  # Attacker can avoid blacklist
```

**Better:**
```yaml
field not in whitelist  # Attacker must match exact whitelist
```

### For ADE4-02 (Conjunction Inversion)

**1. Avoid conjunctions on mutable data:**

**Bad:**
```yaml
suspicious_action AND not (field contains "safe")
```

**Better:**
```yaml
suspicious_action AND (immutable_indicator == malicious)
```

**2. Use separate rules for exceptions:**
```yaml
# Rule 1: Detect all suspicious activity
rule: detect_suspicious

# Rule 2: Exception handling (separate workflow)
rule: exception_for_known_tools
```

### For ADE4-03 (Incorrect Expression)

**1. Test with real-world data:**
```yaml
# Before deploying:
Test case 1: curl download → Should trigger
Test case 2: wget download → Should trigger
Test case 3: Both together → Should trigger (but rare)
```

**2. Use OR for alternatives:**
```yaml
# Instead of: field has "A" and field has "B"
Use: field has "A" or field has "B"
Or: field has_any ("A", "B")
```

**3. Never negate privileged accounts in non-privesc rules:**
```yaml
# Bad (for initial access/persistence rules)
activity and not (user in ("root", "SYSTEM"))

# Good (only for privilege escalation)
previous_user != "root" and current_user == "root"
```

## Testing Your Rules

**Quick Test Questions:**

**For ADE4-01 (Gate Inversion):**
- ✅ Do you have multiple `not` conditions chained with AND?
- ✅ Can these be simplified using De Morgan's Laws?
- ✅ Do your negations check attacker-controlled fields?
- ✅ Could an attacker insert data to flip the negation?

**For ADE4-02 (Conjunction Inversion):**
- ✅ Do you have AND conditions on mutable fields?
- ✅ Could an attacker add data to make the condition False?
- ✅ Are you checking array emptiness with attacker-influenced data?

**For ADE4-03 (Incorrect Expression):**
- ✅ Have you tested your rule with real-world attack samples?
- ✅ Did you validate that the Boolean logic matches your intent?
- ✅ Are you using AND where OR is needed (or vice versa)?
- ✅ Are you excluding privileged accounts in non-privesc rules?

If you answered "yes" to any of these, your rule likely has an ADE4 vulnerability.

## Related Bug Categories

ADE4 often appears alongside:
- **ADE1-01 (Substring Manipulation):** String manipulation used to flip negations
- **ADE3-02 (Aggregation Hijacking):** Manipulated aggregations flip Boolean gates
- **ADE2 (Omit Alternatives):** Logic errors compound with missing alternatives

## Logic Testing Framework

**Before deploying any rule:**

1. **Draw truth table** for your Boolean conditions
2. **Enumerate all input combinations** that should trigger
3. **Test with real attack samples** (not just theoretical)
4. **Apply De Morgan's Laws** to simplify negations
5. **Validate privileged account assumptions** match rule scope

---

**Navigation:**
- [← ADE3: Context Development](ade3-context-development.md)
- [Back to Taxonomy Overview](overview.md)
- [Theory: Detection Logic Bugs](../theory/detection-logic-bugs.md)
- [Bug Likelihood Test](../guides/bug-likelihood-test.md)
