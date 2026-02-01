# ADE1 - Reformatting in Actions

Reformatting in Actions occurs when a detection rule relies on **string match conditions**, and an attacker can manipulate the collected logs such that the match fails.

This has been widely exploited by threat actors for years and still appears in modern SIEM rules.

## Subcategories

### ADE1-01: Substring Manipulation

**Definition:** When detection logic relies on substring matches, an attacker can alter or obfuscate the input data so that the hypothesis conditions are not met, resulting in a False Negative.

**Common Scenarios:**
- Command-line argument obfuscation
- Method/function name manipulation
- Filename or path string modification
- Registry key/value name changes
- Any attacker-controlled string field in logs

**Why It's a Bug:** Detection logic assumes attackers will use exact, unmodified strings. In reality, most string-based indicators can be trivially obfuscated through:
- String concatenation
- Variable substitution
- Encoding/escaping
- Case manipulation
- Whitespace insertion
- Token splitting

## Examples

### Real-World Detection Logic Bugs

1. **[PowerShell Download Bypass](../../examples/ade1/powershell-download-bypass.md)**
   - Rule: Sigma - Suspicious PowerShell Download
   - Technique: Method name obfuscation via string concatenation
   - Platforms: Windows PowerShell Script Block Logging

2. **[Triple Cross eBPF Rootkit Persistence](../../examples/ade1/triple-cross-rootkit.md)**
   - Rule: Sigma - Triple Cross eBPF Rootkit Default Persistence
   - Technique: Filename modification
   - Platform: Linux file events

3. **[Get-NetTCPConnection Obfuscation](../../examples/ade1/get-nettcpconnection.md)**
   - Rule: Sigma - Use Get-NetTCPConnection
   - Technique: PowerShell command name concatenation
   - Platform: Windows process creation (Event ID 4688)

## Detection Rule Patterns Vulnerable to ADE1-01

**String matching operators that create risk:**
- `contains: 'exact_string'`
- `startswith: 'prefix'`
- `endswith: 'suffix'`
- Exact equality: `field: 'value'`

**When combined with attacker-controlled fields:**
- Command-line arguments
- Process names
- File names/paths
- Registry keys/values
- Script block content
- PowerShell cmdlet names
- URL paths
- Environment variables

## Related Bug Categories

ADE1-01 often appears alongside:
- **ADE2-01 (Omit Alternatives - API/Function):** Missing alternative methods that could achieve the same outcome
- **ADE4-01 (Logic Manipulation - Gate Inversion):** String manipulation used to flip negation conditions

## Testing Your Rules

**Quick Test Questions:**
- Does your rule rely on exact string matches in attacker-controlled fields?
- Can the matched string be split across variables or concatenated?
- Are there encoding schemes (Base64, hex, URL encoding) that could bypass the match?
- Would case changes or whitespace insertion break detection?

If you answered "yes" to any of these, your rule likely has an ADE1-01 vulnerability.

---

**Navigation:**
- [← Back to Taxonomy Overview](overview.md)
- [Theory: Detection Logic Bugs](../theory/detection-logic-bugs.md)
- [Next: ADE2 - Omit Alternatives →](ade2-omit-alternatives.md)
