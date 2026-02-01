# ADE4 Logic Manipulation

Logic Manipulation occurs when an attacker analyzes detection logic as Boolean conditions and manipulates inputs or filters to invert, bypass, or neutralize the rule outcome.

This is where the attacker assesses the rule detection logic as Boolean Algebra and can undertakes an additional step to force the chain of Boolean tests throughout the rule to flip the output value, resulting in no hits. 
It is common to see a Logic Manipulation bug in a detection rule along with another bug from a different category. This is because every logic manipulation bug requires another to invert or skip detection logic.



**ADE4-01 Logic Manipulation - Gate Inversion**

Gate inversion occurs when the detection rule includes a NOT clause (i.e a negation) which looks for a data value that is mutable by the attacker by insertion of poisoned data prior to the record being generated. It often shows up as another bug in a rule exception or filter, where this bug coupled with the Gate Inversion bug, results in a "inversion" of the cumulated Boolean outcome of the rule. In most cases, it occurs when the detection rule author didn’t consider that multiple negations can be simplified as an algebraic expression using one of [De Morgan’s Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws).


**ADE4-02 Logic Manipulation - Conjunction Inversion**

Conjunction inversion bugs occur when the Conjunction conditions within the rule looks for a data value that is vulnerable to manipulation by the attacker by insertion of poisoned data prior to the record being generated. It often shows up when a detection rule has been updated to include a conjuncted condition which can be easily flipped by an attacker, with the assumed level of privileges that the attacker would have to undertake the in scope activity. For example, creating poisoned data to fill in an array at rule execution time, which if nonempty gets evaluated as benign due to a filter.


**ADE4-03 Logic Manipulation - Incorrect Expression**

Incorrect Expression occurs when the detection logic has been crafted in such a way that the interpreted query would rarely ever create a hit. This occurs when a detection rule uses incorrect choices between negations, conjunctions or disjunctions in the rule. Although rare to find, it usually occurs due to a lack of adversarial emulation or testing of the detection rule with generated data prior to use in proudction/share publically. 



## ADE4-01 Logic Manipulation - Gate Inversion, Examples

### ADE4-01, Example 1: [PowerShell Suspicious Script with Audio Capture Capabilities](https://github.com/elastic/detection-rules/blob/main/rules/windows/collection_posh_audio_capture.toml)

This detection rule, written in kuery language, intends to detects PowerShell script block content that invokes microphone capture routines or WinMM audio APIs. This is because adversaries may use audio recording to surveil users or capture sensitive conversations for theft or extortion.

The relevant query is below.

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

The field `powershell.file.script_block_text` is of type `text` in elasticsearch, which means that the line `powershell.file.script_block_text : ("sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators")` matches true when all of the substrings are present.

The negation ` and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )`  condition exists to filter out false positives created by other tools that continuously hunt for PS misuse. 
  
However, the adversary can intentionally add into the script block all three of `"sentinelbreakpoints"` and `"Set-PSBreakpoint"` and `"PowerSploitIndicators"` (ADE1-01 Reformatting in Actions - String Manipulation), even as a `Write-Host` call in order to bypass the Negation. 



### ADE4-01, Example 2: [Ingress Transfer via Windows BITS](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_ingress_transfer_bits.toml)

Recall that this example was given in [ADE2-03 Omit Alternatives - File Type](taxonomy/page_2_omit_alternative_methods.md) due to a bug in file type omissions, and by [ADE3-02 Context Development - Aggregation Hijacking](ADE3_Context_Development.md) This actually holds another detection logic bug.

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

Here, the aggregation bug, is also a trigger to inversing the negation. 

This is an example of De Morgan’s laws, where not A and not B  <==>  not (A or B).

De Morgan’s laws are a pair of rules in logic and set theory that state how to negate a compound statement or set:

"the negation of a conjunction (AND) is the disjunction (OR) of the negations, and the negation of a disjunction (OR) is the conjunction (AND) of the negations."

So, 
```
not length(file.name) > 30 and
not file.path : ( list of paths )
```

Is the same as 

```
.. not ( length(file.name) > 30 or file.path : ( ...list of paths... ) ) 
```

In fact, you can follow a process of simplification, so that query becomes:

 `X where A and B and C and D and (E or F) and not G and not H and not I`

Which using De Morgans law can simply to:

`A and B and C and D and (E or F) and not (G or H or I)`

After grouping the and not clauses. The `and not G and not H and not I` is a conjunction of three negations.

That means that if the file extension is anything in that list, such as  `.rar` and its name is 50 characters and it's not in any of the `file.path` listed, it will not create a hit.

Thus, based on [De Morgan’s Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws) the `not length(file.name) > 30 and not ... `  component of the detection logic relies on the file length condition to be true (i.e it's not) in order to utilize the remaining excluding conditions. This means that detection logic can have it's outcome inverted when the file.name length is greater than 30.

In windows, filenames have a 255 character limit. If the filename is greater than 30, such as `xv7qmw2p9z4adr1fks83ntc0bhy6lu5.exe` then the detection logic will return `false` when ` not length(file.name) > 30` is executed.


## ADE4-03 Logic Manipulation - Incorrect Expression

Incorrect Expression occurs when the detection logic has been crafted in such a way that the interpreted query would rarely ever create a hit.

This occurs when a detection rule uses incorrect choices between negations, conjunctions or disjunctions in the rule.

Although uncommon to find, it usually occurs due to a lack of adversarial emulation or testing of the detection rule with generated data prior to use in proudction/share publically. 

### ADE4-03 Logic Manipulation - Incorrect Expression, Examples

#### ADE4-03 Example 1, [Suspicious Shell script detected](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Apache%20Log4j%20Vulnerability%20Detection/Hunting%20Queries/Suspicious_ShellScript_Activity.yaml)


This Sigma hunting rule detects post-compromise suspicious shell scripts that attackers use for downloading and executing malicious files, and was created in response to the Log4j vulnerability.


Relevant Sigma portion below.
```yaml
query: |
  Syslog
  | where Facility == 'user'
  | where SyslogMessage has "AUOMS_EXECVE"
  | parse SyslogMessage with "type=" EventType " audit(" * "): " EventData
  | where EventType =~ "AUOMS_EXECVE"
  | project TimeGenerated, EventType, Computer, EventData
  | parse EventData with * "syscall=" syscall " syscall_r=" * " success=" success " exit=" exit " a0" * " ppid=" ppid " pid=" pid " audit_user=" audit_user " auid=" auid " user=" user " uid=" uid " group=" group " gid=" gid "effective_user=" effective_user " euid=" euid " set_user=" set_user " suid=" suid " filesystem_user=" filesystem_user " fsuid=" fsuid " effective_group=" effective_group " egid=" egid " set_group=" set_group " sgid=" sgid " filesystem_group=" filesystem_group " fsgid=" fsgid " tty=" tty " ses=" ses " comm=\"" comm "\" exe=\"" exe "\"" * "cwd=\"" cwd "\"" * "name=\"" name "\"" * "cmdline=" cmdline
  | extend cmdline = trim_end('redactors=.*',cmdline) 
  | where exe has_any ("bash","dash")
  | where cmdline matches regex  "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
  | where cmdline has "curl" and cmdline has "wget"
  | project TimeGenerated, Computer, audit_user, user, cmdline
  | extend timestamp = TimeGenerated
  | extend Host_0_HostName = Computer
  | extend Account_0_Name = user
  | sort by TimeGenerated desc
```

In this case, the following line:
```
  | where cmdline has "curl" and cmdline has "wget"
```

This is an example of **ADE4-03: Logic Manipulation – Incorrect Expression** as the detection logic is syntactically valid but logically impossible to satisfy under normal attack behavior. 

The rule intends to detect command execution involving either curl or wget, yet the Boolean condition requires both substrings to be present in the same cmdline value (has "curl" *and* has "wget").

In practice, attackers usually use one download utility at a time, meaning the expression will almost never evaluate to true, **resulting in permanent generation of False Negatives.**

This is not an attacker driven bypass but a logic construction error in the detection logic itself, where a conjunction (AND) was used instead of a disjunction (OR) rendering the detection ineffective by design.





## 🚨  Risk of Negating privileged accounts such as root, Administrator, SYSTEM

A lot of detection rules will include a negation (NOT) on the end of the detection logic to ignore accounts such as root or SYSTEM. The reason this is done is to focus on low priviledged accounts and reduce noise from standard root/SYSTEM activity.

However, this only makes sense when the detection rule is about priviledge escalation, and shouldn't be included in detection rules such as initial access, or persistence or lateral movement, etc. Most the detection rules capture activity that should be triaged regardless of account.

In 2025 there were multiple CVEs for unauthenticated Remote Code Execution as root/SYSTEM.

🚨 [CVE-2025-20281 / CVE-2025-20337 – Cisco ISE](https://nvd.nist.gov/vuln/detail/CVE-2025-20337)
- Affects Cisco Identity Services Engine (ISE) / ISE-PIC API.
- Unauthenticated remote code execution leading to arbitrary code execution as root.
- No credentials required.
- Actively Bypassed in the wild in mid-2025 by APTs

🚨 [CVE-2025-59287 – Microsoft WSUS](https://nvd.nist.gov/vuln/detail/CVE-2025-59287)
- Unauthenticated RCE in Windows Server Update Services (WSUS) component.
- Allows arbitrary code execution with SYSTEM-equivalent privileges on affected servers

🚨 [CVE‑2025‑46811 — SUSE Manager Missing Authorization](https://www.suse.com/security/cve/CVE-2025-46811.html?utm_source=chatgpt.com)
- Unauthenticated remote code execution leading to arbitrary code execution as root.
- No credentials required.
- Root privileges on the SUSE Manager server and potentially any managed client systems

🚨 [CVE‑2025‑32463 — sudo chroot privilege escalation](https://www.upwind.io/feed/cve%E2%80%912025%E2%80%9132463-critical-sudo-chroot-privilege-escalation-flaw)
- Local flaw in sudo (versions 1.9.14–1.9.17) allowing any unprivileged user to escalate to root by abusing the -R /chroot option.
- Active Bypass reported and added to security advisories

In 2024 there were a few memorable.

🚨 [CVE‑2024‑6387 — OpenSSH “regreSSHion”](https://nvd.nist.gov/vuln/detail/cve-2024-6387)
- Critical unauthenticated RCE in OpenSSH server (sshd).
- Bypass can lead to root shell / full takeover of systems running vulnerable versions of OpenSSH.


🚨 [CVE‑2024‑1086 — Linux kernel netfilter privilege escalation]
- Use‑after‑free in the Linux kernel’s netfilter subsystem.
- PoCs published and Bypass leads to root privilege for local attackers.

The list goes on, and so does the number of non priviledge escalation detection rules negating root and SYSTEM in thier conditions.

---


**Contents**
- [README.md](README.md)
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- [Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md)
- [ADE1 Reformatting in Actions](ADE1_Reformatting_in_Actions.md)
- [ADE2 Omit Alternatives](ADE2_Omit_Alternatives.md)
- [ADE3 Context Development](ADE3_Context_Development.md)
- **ADE4 Logic Manipulation (Current Page)**
- [Bug Likelihood Test](Bug_Likelihood_Test.md)
- [LICENCE](LICENSE)























