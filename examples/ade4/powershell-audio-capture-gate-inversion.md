# ADE4-01 Example: PowerShell Audio Capture Gate Inversion

**Bug Category:** ADE4-01 Logic Manipulation - Gate Inversion

## Original Rule

**Source:** [Elastic Security - PowerShell Suspicious Script with Audio Capture Capabilities](https://github.com/elastic/detection-rules/blob/main/rules/windows/collection_posh_audio_capture.toml)

**Description:** Detects PowerShell script block content that invokes microphone capture routines or WinMM audio APIs. Adversaries may use audio recording to surveil users or capture sensitive conversations for theft or extortion.

```SQL
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "Get-MicrophoneAudio" or
    ("Get-AudioDevice" and "Recording" and "Set-AudioDevice") or
    "WindowsAudioDevice-Powershell-Cmdlet" or
    (
      "winmm.dll" and
      (
        "waveInGetNumDevs" or "waveInOpen" or "waveInStart" or
        "mciSendString" or "mciSendStringA" or "mciSendStringW"
      )
    )
  ) and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )
```

## Detection Logic Analysis

**Field type:** `powershell.file.script_block_text` is of type `text` in Elasticsearch

**How the negation works:**
```SQL
powershell.file.script_block_text : ("sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators")
```

This matches `true` when **all three substrings** are present in the script block.

**Intent:** The negation exists to filter out false positives created by security tools that continuously hunt for PowerShell misuse (like PowerSploit indicators).

## The Bug: ADE4-01 Logic Manipulation - Gate Inversion

**Definition:** Gate inversion occurs when a detection rule includes a NOT clause (negation) which looks for data values that are mutable by the attacker through insertion of poisoned data prior to record generation.

**In this case:**
- Rule uses negation to exclude scripts containing sentinel strings
- Attacker can intentionally add all three sentinel strings to malicious script
- Negation condition becomes `true` → entire rule result inverted to `false`
- No alert generated

## Bypass - Add Sentinel Strings

**Malicious script (original):**
```PowerShell
# Audio capture malware
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class AudioCapture {
        [DllImport("winmm.dll")]
        public static extern int waveInGetNumDevs();
        [DllImport("winmm.dll")]
        public static extern int waveInOpen(ref IntPtr hwi, int uDeviceID, ref WAVEFORMATEX lpFormat, IntPtr dwCallback, IntPtr dwInstance, int dwFlags);
    }
"@

# Capture audio
[AudioCapture]::waveInGetNumDevs()
```

**Result:** **Alert triggered** (contains `winmm.dll` and `waveInGetNumDevs`)

### Bypass - Inject False Positive Markers

**Modified malicious script (ADE4-01 bypass):**
```PowerShell
# Add sentinel strings to bypass detection
Write-Host "sentinelbreakpoints"  # Just output to console
Write-Host "Set-PSBreakpoint"      # Not actually used
Write-Host "PowerSploitIndicators" # Pure noise

# Same malicious audio capture code
Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class AudioCapture {
        [DllImport("winmm.dll")]
        public static extern int waveInGetNumDevs();
        [DllImport("winmm.dll")]
        public static extern int waveInOpen(ref IntPtr hwi, int uDeviceID, ref WAVEFORMATEX lpFormat, IntPtr dwCallback, IntPtr dwInstance, int dwFlags);
    }
"@

# Capture audio
[AudioCapture]::waveInGetNumDevs()
```

**Result:** **No alert** (False Negative)

**Why it works:**

1. **Selection condition:** `true` (contains `winmm.dll` and `waveInGetNumDevs`)
2. **Negation condition:**
   - Script contains "sentinelbreakpoints" ✓
   - Script contains "Set-PSBreakpoint" ✓
   - Script contains "PowerSploitIndicators" ✓
   - All three present → condition `true`
3. **Final logic:** `selection and not negation` → `true and not true` → `false`
4. **Alert:** None

## Why This Is ADE4-01 (Not ADE1-01)

**ADE1-01 (Substring Manipulation):** Attacker modifies the malicious action itself
- Example: Use string concatenation to obfuscate `waveInGetNumDevs`

**ADE4-01 (Gate Inversion):** Attacker adds data to flip a Boolean gate
- Example: Add sentinel strings that don't change behavior, just flip negation

**Difference:**
- ADE1: Changes the suspicious action
- ADE4: Adds noise data to manipulate Boolean logic

## Impact

**False Negative:** Attacker can:
- Keep malicious audio capture code unchanged
- Simply add three benign strings anywhere in script
- Completely bypass detection

**Minimal effort:**
- Add 3 lines of `Write-Host` or comment strings
- No functional code changes needed
- Works for any audio capture technique

## Why This Bug Exists

**Design flaw:** Negation relies on attacker-controlled field

**Assumption:** Attacker won't know about the sentinel strings

**Reality:**
- Detection rules are often public (GitHub, vendor docs)
- Attackers can analyze rules
- Adding strings is trivial

**Root cause:** Negation checks mutable data under attacker control

---

**Related Documentation:**
- [ADE4 Logic Manipulation](../../docs/taxonomy/ade4-logic-manipulation.md)
- [ADE4-01 Gate Inversion](../../docs/taxonomy/ade4-logic-manipulation.md#ade4-01-logic-manipulation---gate-inversion)
- [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws)
