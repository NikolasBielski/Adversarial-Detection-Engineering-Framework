# ADE2-04 Example: Windows BITS Ingress Transfer File Types

**Bug Category:** ADE2-04 Omit Alternatives - File Type

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

The rule attempts to capture malicious file types by checking:

1. **Explicit extension list:**
   ```
   ("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl")
   ```

2. **PE header bytes fallback:**
   ```
   file.Ext.header_bytes : "4d5a*"
   ```
   - `4d5a` = bytes "MZ" in hex (PE executable header)
   - Catches executables with non-standard extensions

## The Bug

**Scope:** Ingress transfer of *archive or executable files* via BITS

**Bug:** Anything with an extension **not in the tuple** that **doesn't** have header bytes starting with `4d5a` (PE format) **will not trigger this rule**.

**Critical Fact:** BITS itself does not restrict transfers by file type or magic number. BITS only cares about:
- Transport protocols (HTTP/HTTPS/SMB)
- Job configuration
- Not the file's internal structure

## Bypasses - Omitted File Types

### Executable/Interpretable Files

**Python Scripts:**
```
evil.py (requires Python interpreter)
```

**C Source Code:**
```
evil.c (compiled post-transfer)
```

**SQL Scripts:**
```
malicious.sql (executed via sqlcmd, osql, etc.)
```

**PowerShell Scripts (alternate extension):**
```
script.ps1 is covered, but .psm1, .psd1 are not
```

### Archive Formats

**7-Zip:**
```
payload.7z (not detected)
```

**Gzip:**
```
data.gz (not detected)
```

**Bzip2:**
```
archive.bz2 (not detected)
```

**Tar archives:**
```
files.tar (not detected)
```

### Document Formats with Macros

The rule scope mentions "archive or executable files" to detect **compressed executables or documents with macros**. However, macro-enabled documents are omitted:

**Missing:**
- `xlsm` (Excel with macros)
- `xlsb` (Excel binary with macros)
- `docm` (Word with macros)
- `pptm` (PowerPoint with macros)

## Why This Matters

**Common Attack Pattern:**
1. Transfer archive (`.7z`, `.tar.gz`) via BITS → **Not detected**
2. Extract payload locally
3. Execute second-stage payload

**Alternative Pattern:**
1. Transfer macro-enabled document (`.xlsm`) via BITS → **Not detected**
2. User opens document
3. Macros execute malicious code

## Additional Bug: ADE3-02 (Aggregation Hijacking)

The same rule contains a filename length bypass:
```
not length(file.name) > 30
```

An attacker can use filenames >30 characters to bypass detection entirely. See [ADE3 example](../ade3/bits-filename-manipulation.md) for details.

## Additional Bug: ADE4-01 (Gate Inversion)

The negation logic can be inverted using De Morgan's Laws. See [ADE4 example](../ade4/bits-gate-inversion.md) for details.

## Impact

**False Negative:** Malicious files transferred via BITS bypass detection by using:
- Non-PE archive formats (7z, gz, bz2, tar)
- Interpreted scripts (Python, SQL)
- Macro-enabled Office documents
- Combined with filename >30 characters

---

**Related Documentation:**
- [ADE2 Omit Alternatives](../../docs/taxonomy/ade2-omit-alternatives.md)
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE4 Logic Manipulation](../../docs/taxonomy/ade4-logic-manipulation.md)
