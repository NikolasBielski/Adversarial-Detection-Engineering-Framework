# ADE2 - Omit Alternatives

A detection rule has been assessed using the ADE process and it is determined that an **alternative API/function, version, location or file type** is available during the attack AND this alternative is in the detection rule's scope, but the alternative has been **omitted from the detection logic**, resulting in a False Negative.

## Subcategories

### ADE2-01: Omit Alternatives - API/Function

**Definition:** Detection logic searches for specific API calls or functions, but alternative APIs/functions that achieve the same effect exist within scope and are omitted.

**Result:** Attack activity using alternative APIs is not detected.

**Common Examples:**
- Windows API alternatives (e.g., `CreateProcessA` vs `CreateProcessW` vs `NtCreateProcess`)
- PowerShell cmdlet alternatives (`Invoke-WebRequest` vs `Invoke-RestMethod` vs `.NET WebClient`)
- Cloud API versioning (AWS `ModifyDBInstance` omitted when detecting RDS changes)
- Reflection/invocation methods (`.Method()` vs `InvokeMember()` vs `GetMethod().Invoke()`)

---

### ADE2-02: Omit Alternatives - Versioning

**Definition:** Detection logic assumes a fixed software version, OS version, or API version, but alternative versions exist within scope and are omitted.

**Result:** Activity in alternative versions bypasses detection.

**Common Examples:**
- OS version differences (Linux distro-specific paths)
- API deprecation and replacement (AWS `PutImageScanningConfiguration` → `PutRegistryScanningConfiguration`)
- Protocol version changes (TLS 1.2 vs 1.3)
- Software version-specific behaviors (Cron paths in RedHat vs Debian)

---

### ADE2-03: Omit Alternatives - Locations

**Definition:** Detection logic only searches specific locations (file paths, registry keys, URLs), but other valid locations within scope are ignored.

**Result:** Activity from alternative locations is missed.

**Common Examples:**
- File system path variations (`C:\Program Files` vs `C:\Program Files (x86)`)
- User directory paths (`%USERPROFILE%` vs hardcoded paths)
- Registry hive alternatives (`HKLM` vs `HKCU`)
- Linux distribution path differences (`/usr/lib/cron/` vs `/etc/cron.d/`)
- Cloud region-specific endpoints

---

### ADE2-04: Omit Alternatives - File Types

**Definition:** Detection logic only checks specific file types/extensions, omitting others that are in scope.

**Result:** Malicious activity using alternative file types is not detected.

**Common Examples:**
- Archive formats (`.zip`, `.rar` detected, but `.7z`, `.tar`, `.gz` omitted)
- Executable formats (`.exe` detected, but `.com`, `.scr`, `.pif` omitted)
- Script types (`.ps1` detected, but `.psm1`, `.psd1` omitted)
- Document macros (`.docx` checked, but `.docm` with macros omitted)

## Examples

### Real-World Detection Logic Bugs

**ADE2-01 - API/Function:**
1. **[AWS RDS Changes - API Omissions](../../examples/ade2/aws-rds-changes.md)**
   - Missing `ModifyDBInstance`, `RebootDBInstance`, and snapshot restoration APIs
   - Platform: AWS CloudTrail

**ADE2-02 - Versioning:**
2. **[AWS RDS Changes - Version Drift](../../examples/ade2/aws-rds-changes.md)**
   - EC2-Classic vs EC2-VPC security group APIs
   - Platform: AWS CloudTrail

**ADE2-04 - File Types:**
3. **[BITS Ingress Transfer - Omitted File Types](../../examples/ade2/bits-ingress-transfer.md)**
   - Missing `.7z`, `.gz`, `.py`, `.sql`, macro-enabled Office documents
   - Platform: Windows Elastic Endgame EDR

## Detection Rule Patterns Vulnerable to ADE2

**API/Function Omissions:**
- Hardcoded function/method names without alternatives
- Single API endpoint when multiple exist
- Missing reflection/indirect invocation methods

**Versioning Omissions:**
- OS-specific assumptions (Windows 10 vs 11, Ubuntu vs RHEL)
- API version dependencies without fallbacks
- Deprecated API replacements not included

**Location Omissions:**
- Hardcoded file paths
- Single registry key without alternatives
- Platform-specific locations (x86 vs x64)

**File Type Omissions:**
- Extension-based filtering without magic byte checks
- Missing interpretable file types (scripts, configs)
- Archive format variations

## Why This Happens

**Common Root Causes:**
1. **Incomplete threat research** - Not exhaustively enumerating alternatives
2. **Platform assumptions** - Assuming one OS, version, or deployment model
3. **Tool-specific knowledge** - Only knowing the most common method
4. **Aging rules** - New APIs/versions released after rule creation
5. **Copy-paste detection engineering** - Reusing patterns without validation

## Related Bug Categories

ADE2 often appears alongside:
- **ADE1-01 (Substring Manipulation):** Alternative APIs also use different strings
- **ADE3-01 (Process Cloning):** Attackers clone binaries to alternative locations
- **ADE4-03 (Incorrect Expression):** Logic errors compound omission issues

## Testing Your Rules

**Quick Test Questions:**

**For ADE2-01 (API/Function):**
- Have you enumerated ALL APIs that achieve the same outcome?
- Did you check for reflection/indirect invocation methods?
- Are there language-specific alternatives (PowerShell vs .NET vs WMI)?

**For ADE2-02 (Versioning):**
- When was this rule created? Have APIs changed since then?
- Does it work across all supported OS versions?
- Are deprecated APIs being replaced with new ones?

**For ADE2-03 (Locations):**
- Did you check 32-bit AND 64-bit paths?
- Are user-writable locations covered?
- Did you account for different Linux distributions?

**For ADE2-04 (File Types):**
- Are all relevant file extensions included?
- Did you use magic bytes for file type validation?
- Are compressed/archived variants covered?

If you answered "no" or "unsure" to any of these, your rule likely has an ADE2 vulnerability.

---

**Navigation:**
- [← ADE1: Reformatting in Actions](ade1-reformatting-in-actions.md)
- [Back to Taxonomy Overview](overview.md)
- [Theory: Detection Logic Bugs](../theory/detection-logic-bugs.md)
- [Next: ADE3 - Context Development →](ade3-context-development.md)
