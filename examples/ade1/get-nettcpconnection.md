# ADE1-01 Example: PowerShell Get-NetTCPConnection Obfuscation

**Bug Category:** ADE1-01 Reformatting in Actions - Substring Manipulation

## Original Rule

**Source:** [Sigma - Use Get-NetTCPConnection](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_module/posh_pm_susp_get_nettcpconnection.yml)

```yaml
title: Use Get-NetTCPConnection
id: b366adb4-d63d-422d-8a2c-186463b5ded0
status: test
description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell
author: frack113
date: 2021-12-10
modified: 2023-10-27
tags:
    - attack.discovery
    - attack.t1049
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection:
        Data|contains: 'Get-NetTCPConnection'
    condition: selection
falsepositives:
    - Unknown
level: low
```

## The Bug

Detection logic relies on process creation records (Windows Security Event ID 4688) that include the `Get-NetTCPConnection` substring in the `CommandLine` field.

**The bug:** Reliance on a mutable substring in command-line arguments.

## Log Source Context

- **Logsource category:** `ps_classic_start` in Sigma = Windows Security Event ID 4688 (process creation)
- **Logged fields:** `NewProcessName`, `CommandLine` (if enabled), `ParentProcessName`, `Process ID`, `User`, etc.
- **Vulnerable field:** `CommandLine`

## Bypass

### Method Name Obfuscation via PowerShell String Concatenation

```powershell
$ps = [System.Management.Automation.PowerShell]::Create();
$ps.AddCommand("Get-Net"+"TCP"+"Connection") | Out-Null;
$ps.AddParameter("State","Established") | Out-Null;
$result = $ps.Invoke();
$result | ConvertTo-Json -Depth 4 | Set-Content DIRECTORY_TO_WRITE_TO\tcp.json -Encoding utf8
```

**Result:** The command executes `Get-NetTCPConnection`, dumps connection information as JSON to `tcp.json`, but the substring match fails because the command name is constructed via string concatenation (`"Get-Net"+"TCP"+"Connection"`).

## Impact

False Negative: Network discovery via `Get-NetTCPConnection` succeeds without detection.

---

**Related Documentation:**
- [ADE1 Reformatting in Actions](../../docs/taxonomy/ade1-reformatting-in-actions.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
- [MITRE ATT&CK T1049 - System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)
