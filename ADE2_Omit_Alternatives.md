## ADE2 - Omit Alternatives

A detection rule has been assessed using the ADE process and it is determined that an alternative API/function, version, location or file type is available during the attack AND this alternative is in the detection rule's scope, but the alternative has been omitted from the detection logic, resulting in a False Negative.

**ADE2 Subcategories:**
- **ADE2-01 Omit Alternatives - API/Function**: Detection logic searches for specific API calls, but alternative APIs that achieve the same effect exist and are omitted.  
  *Result:* Attack activity using alternative APIs is not detected.

- **ADE2-02 Omit Alternatives - Versioning**: Detection logic assumes a fixed software version, but alternative versions exist and are omitted.  
  *Result:* Activity in alternative versions bypasses detection.

- **ADE2-03 Omit Alternatives - Locations**: Detection logic only searches a specific location, but other valid locations are ignored.  
  *Result:* Activity from alternative locations is missed.

- **ADE2-04 Omit Alternatives - File types**: Detection logic only checks specific file types, omitting others that are in scope.  
  *Result:* Malicious activity using alternative file types is not detected.

---

### ADE2-01 Omit Alternatives - API/Function

Where detection logic searches for specific API use, yet alternative APIs exist within the detection rule scope that the detection logic doesn't cover for. This is a bug by the omission of alternative APIs in the detection logic.

#### ADE2-01, Example 1: [Potential File Transfer via Curl for Windows](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_tool_transfer_via_curl.toml)

This elastic security detection rule, seeks to identify Curl for Windows making a HTTP request, because adversaries may abuse Curl to download files or upload data to a remote URL.

The related query logic is as below.
```SQL
query = '''
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "?:\\Windows\\System32\\curl.exe",
    "?:\\Windows\\SysWOW64\\curl.exe"
  ) and
  process.command_line : "*http*" and
  process.parent.name : (
    "cmd.exe", "powershell.exe",
    "rundll32.exe", "explorer.exe",
    "conhost.exe", "forfiles.exe",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "hh.exe", "mmc.exe"
  ) and 
  not (
    ?user.id == "S-1-5-18" and
    /* Don't apply the user.id exclusion to Sysmon for compatibility */
    not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
  ) and
  /* Exclude System Integrity Processes for Sysmon */
  not ?winlog.event_data.IntegrityLevel == "System"
```

##### Rule Bypass 1: Omitted functionality,  Bug subcategory: ADE2-01 Omit Alternative - API/Function

Curl for Windows is essentially an alias of `Invoke-WebRequest`, which will be called when using Curl for Windows. With `Invoke-WebRequest` you can chose to provide the protocol in the url itself or specify this as a parameter. What's uncommonly known is that in windows `curl` does not require the protocol to be provided *at all* in order to download a file using http/https. 

If you run in windows powershell;
```Powershell
curl raw.githubusercontent.com/elastic/detection-rules/refs/heads/main/rules/windows/command_and_control_tool_transfer_via_curl.toml
```
Powershell will quietly auto-append the protocol to the front of the url, prior to passing it to `Invoke-WebRequest`, resulting in the query's condition `process.command_line : "*http*" and` to **not catch anything (False Negative)** as the commandline doesn't include the substring `http`. An alternative function has been omitted, that is, the auto-append of the protocol.

In ADE we call this a bug by the omission of an alternative api/funtion, or **ADE2-01 Omit Alternative - API/Function.**

In this specific example, ADE also treats this as an **ADE4-02 Logic Manipulation - Conjunction Inversion** bug, as the condition `process.command_line : "*http*" and` can be intentionally flipped (or inverted) due to the Conjunction operator 'and'.



#### ADE2-01, Example 2: [Changes to internet facing AWS RDS Database instances](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_ChangeToRDSDatabase.yaml)

This Kusto rule looks for changes to Amazon Relational Database Services (RDS) in use within an AWS environment.

Description: *Amazon Relational Database Service (RDS) is scalable relational database in the cloud. If your organization have one or more AWS RDS Databases running, monitoring changes to especially internet facing AWS RDS (Relational Database Service). Once alerts triggered, validate if changes observed are authorized and adhere to change control policy.* [RDS API Reference Docs.](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html)

The relevant detection logic is below.
```SQL
let EventNameList = dynamic(["AuthorizeDBSecurityGroupIngress","CreateDBSecurityGroup","DeleteDBSecurityGroup","RevokeDBSecurityGroupIngress"]);
AWSCloudTrail
| where EventName in~ (EventNameList)
| extend UserIdentityArn = iif(isempty(UserIdentityArn), tostring(parse_json(Resources)[0].ARN), UserIdentityArn)
| extend UserName = tostring(split(UserIdentityArn, '/')[-1])
| extend AccountName = case( UserIdentityPrincipalid == "Anonymous", "Anonymous", isempty(UserIdentityUserName), UserName, UserIdentityUserName)
| extend AccountName = iif(AccountName contains "@", tostring(split(AccountName, '@', 0)[0]), AccountName),
  AccountUPNSuffix = iif(AccountName contains "@", tostring(split(AccountName, '@', 1)[0]), "")
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventName, EventTypeName, RecipientAccountId, AccountName, AccountUPNSuffix, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements
| extend timestamp = StartTimeUtc
```

The changes that the detection logic covers are:
- Network rule/policy changes: (edits) `AuthorizeDBSecurityGroupIngress`, (deletion) `RevokeDBSecurityGroupIngress`
- Security rule/policy changes: (creation) `CreateDBSecurityGroup`, (deletion) `DeleteDBSecurityGroup`

##### Rule Bypass 1: Omitted API functionality,  Bug subcategory: ADE2-01 Omit Alternative - API/Function

These changes are completed usually by valid acccounts, with AWS-managed policies that grant those actions. The most common answer to this is provided `rds:*` on specific RDS resources. This can also allow for other actions to RDS instances that may be of interest to an attacker, such as:
1. [`rds:ModifyDBInstance`](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html)
    - DB security group selection changes
    - Rotating and resetting master passwords
    - Change public accessibility
    - Change backup and storage configurations
2. [`rds:RebootDBInstance/StartDBInstance/StopDBInstance`](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RebootDBInstance.html)
    - Can be used for taking services offline, force parameter group changes (change then reboot)
3. Others, such as `RestoreDBInstanceFromDBSnapshot`, `RestoreDBInstanceToPointInTime`, `ModifyOptionGroup` and  `ModifyDBParameterGroup` when can be used for data exposure and exfiltration pathways.

If the actions are within a custom role, then it may be likely that these actions are included also. The above False Negative examples (rule bypasses) are excluded from DB versions such as:
- Aurora cluster APIs
- Redshift integrations (CreateIntegration)
- IAM role attachment APIs
- EC2 VPC security group APIs
- RDS Data API (Aurora only)

In ADE we call this a bug in detection logic by the omission of an alternative api/funtion, or **ADE2-01 Omit Alternative - API/Function.**

---

### ADE2-02 Omit Alternatives - Versioning

Where detection logic searches for information that in reality varies by versioning, i.e alternative versions exist in scope that the detection logic doesn't account for. This is a bug by the omission of alternative versioning in the detection logic.


#### ADE2-02 Example 1: [Changes to internet facing AWS RDS Database instances](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_ChangeToRDSDatabase.yaml)

Continuing from the above rule which looks to capture changes to RDS instances in AWS. In the rule, the detection logic is relies on the assumption that the RDS is in use with a EC2-Classic DB instance. We can see this as the API endpoints in the detection logic have `DB` in them, so they are calls to RDS DB Security Groups API endpoints. This is mostly legacy systems in practice.

##### Bypass 1: Omitted API version drift,  Bug subcategory: ADE2-02 Omit Alternative - Versioning

Most commonly we see RDS instances in EC2 VPC, where the APIs above are not utilized. This is because [EC2 VPC security groups are used](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html).  
```
ec2:AuthorizeSecurityGroupIngress
ec2:RevokeSecurityGroupIngress
```
Changes to make a RDS open to the internet in a VPC result in different strings in Cloudtrail logs.
```
(RDS in VPC) `AuthorizeSecurityGroupIngress` != (Kusto detection logic)`AuthorizeDBSecurityGroupIngress`
(RDS in VPC)`RevokeSecurityGroupIngress` != (Kusto detection logic)`RevokeDBSecurityGroupIngress`
```

The bug here is the omission of alternative versions in RDS configurations in AWS, leading to False Negatives. In ADE we call this a bug by the omission of alternative versioning, or **ADE2-02 Omit Alternatives - Versioning.**


#### ADE2-02 Example 2: [Automatic image scanning disabled for ECR](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_ECRImageScanningDisabled.yaml)

This Kusto rule tests for events where image scanning for ECR was disabled, which could lead to missing vulnerable container images in your environment. Attackers could disable the Image Scanning for defense evasion purposes.

The related portion of the detection logic is below.

```SQL
AWSCloudTrail
| where EventName == "PutImageScanningConfiguration" and isempty(ErrorCode) and isempty(ErrorMessage)
| extend scanOnPush = parse_json(tostring((parse_json(RequestParameters).imageScanningConfiguration))).scanOnPush
| where scanOnPush == false
| extend UserIdentityArn = iif(isempty(UserIdentityArn), tostring(parse_json(Resources)[0].ARN), UserIdentityArn)
| extend UserName = tostring(split(UserIdentityArn, '/')[-1])
| extend AccountName = case( UserIdentityPrincipalid == "Anonymous", "Anonymous", isempty(UserIdentityUserName), UserName, UserIdentityUserName)
| extend AccountName = iif(AccountName contains "@", tostring(split(AccountName, '@', 0)[0]), AccountName),
  AccountUPNSuffix = iif(AccountName contains "@", tostring(split(AccountName, '@', 1)[0]), "")
| distinct TimeGenerated, EventName, SourceIpAddress, UserIdentityArn, UserIdentityUserName, RecipientAccountId, AccountName, AccountUPNSuffix
| extend timestamp = TimeGenerated
```

The key API call is `PutImageScanningConfiguration`, which is used to update `scanOnPush` value as seen in the paylod below.

```json
{
   "imageScanningConfiguration": { 
      "scanOnPush": boolean
   },
   "registryId": "string",
   "repositoryName": "string"
}
```
##### Bypass 1: Omitted version drift,  Bug subcategory: ADE2-02 Omit Alternative - Versioning

However, the API call `PutImageScanningConfiguration` is being [deprecated](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutRegistryScanningConfiguration.html) in favour of the `PutRegistryScanningConfiguration` endpoint. This new version of Image Scanning Configuration updates utilizes the `rule` formatting, seen in the payload below.
```json
{
   "rules": [ 
      { 
         "repositoryFilters": [ 
            { 
               "filter": "string",
               "filterType": "string"
            }
         ],
         "scanFrequency": "string"
      }
   ],
   "scanType": "string"
}
```
An attacker with the ability to make these changes to Image Scanning configurations will be able to leave `scanFrequency` and `scanType` unspecified (not on push), [which will result in the `scanFrequency` to be `MANUAL`](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_RegistryScanningRule.html) which has the same effect as disabling an automatic scanning functionality.

Here we have a bug by the ommission of alternative versioning of the Image Scanning Configuration APIs, where when the new API endpoint is in use there will be False Negatives, and when the previous API endpoint is finally fully deprecated the provided kusto rule will never hit. In ADE we call this a bug by the omission of alternative versioning, or **ADE2-02 Omit Alternatives - Versioning.**


#### ADE2-02 Example 2: [File Event Linux Persistence via Cron Files](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_persistence_cron_files.yml)


This Sigma rule searches file event data looking for creation of cron file or files in Cron directories, which could indicates potential persistence. The scope is Linux, not specific flavors, distributions or versions. The sigma detection logic component is as below.
```yaml
detection:
    selection1:
        TargetFilename|startswith:
            - '/etc/cron.d/'
            - '/etc/cron.daily/'
            - '/etc/cron.hourly/'
            - '/etc/cron.monthly/'
            - '/etc/cron.weekly/'
            - '/var/spool/cron/crontabs/'
    selection2:
        TargetFilename|contains:
            - '/etc/cron.allow'
            - '/etc/cron.deny'
            - '/etc/crontab'
    condition: 1 of selection*
```
These pathways have been taken from MSTIC-Symon linux persistance configs, [here](https://github.com/microsoft/MSTIC-Sysmon/blob/f1477c0512b0747c1455283069c21faec758e29d/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml).

Due to this we can infer that the hypothesis assumes write access to Cron directories. Oftentimes write access to /etc/cron.* belongs to root:root drwxr-xr-x (755). So it makes sense that it’s looking for persistence activity, assuming compromise of a privileged account.


##### Bypass 1: Omitted OS version drift,  Bug subcategory: ADE2-02 Omit Alternative - Versioning

Some variants of linux use cron paths not included above:
- `/usr/lib/cron/`  is commonly seen in Red Hat-based distros (such as Fedora, CentOS, RHEL) and derivatives
- Package-managed cron scripts/binaries (Fedora/RHEL family) often contain scripts run by the system cron.
- `/usr/local/etc/cron.d/` is a less common location but sometimes is used for locally administered cron jobs, especially when administrators want to separate local configs from distro-managed configs.
- FreeBSD and some BSD-based systems often use `/usr/local/etc/` for locally installed software configs .e.g Periodic scripts that run daily by FreeBSD periodic utility.

A False Negative could exist where the machine's distribution being logged is one with the ommitted version file paths above. In ADE we call this a bug by the omission of alternative versioning, or **ADE2-02 Omit Alternatives - Versioning.**

More so, because the rule assumes root permissions as a possibility, an attacker versed in the bug may manipulate and create new file paths. In ADE we call this a bug by reformatting in actions, or **ADE1-01 Reformatting Actions - Substring Manipulation.**

---

### ADE2-03 Omit Alternatives - Locations

Where detection logic searches for information relating to a specific location, yet alternative locations exist that the detection rule doesn't account for due to differences in distributions, flavors of the technology or physical geolocations. This is a bug by the omission of alternative location in the detection logic.

#### ADE2-03 Example 1:  [Connection to Common Large Language Model Endpoints](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_common_llm_endpoint.toml)

This elastic detection rule tests data to identify DNS queries to known Large Language Model domains by unsigned binaries or common Windows scripting utilities. This is because malwares may leverage the capabilities of LLMs to perform actions in an affected system in a dynamic way.

The full query component is as below.
```SQL
query = '''
network where host.os.type == "windows" and dns.question.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  (
    process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") and
    (?process.code_signature.trusted == false or ?process.code_signature.exists == false)
  )
 ) and
    dns.question.name : (
    // Major LLM APIs
    "api.openai.com",
    "*.openai.azure.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.ai21.com",
    "api.groq.com",
    "api.perplexity.ai",
    "api.x.ai",
    "api.deepseek.com",
    "api.gemini.google.com",
    "generativelanguage.googleapis.com",
    "api.azure.com",
    "api.bedrock.aws",
    "bedrock-runtime.amazonaws.com",

    // Hugging Face & other ML infra
    "api-inference.huggingface.co",
    "inference-endpoint.huggingface.cloud",
    "*.hf.space",
    "*.replicate.com",
    "api.replicate.com",
    "api.runpod.ai",
    "*.runpod.io",
    "api.modal.com",
    "*.forefront.ai",

    // Consumer-facing AI chat portals
    "chat.openai.com",
    "chatgpt.com",
    "copilot.microsoft.com",
    "bard.google.com",
    "gemini.google.com",
    "claude.ai",
    "perplexity.ai",
    "poe.com",
    "chat.forefront.ai",
    "chat.deepseek.com"
  ) and

  not process.executable : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe",
          "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
          "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe"
        ) and
    not (?process.code_signature.trusted == true and
         ?process.code_signature.subject_name : ("Anthropic, PBC", "Google LLC", "Mozilla Corporation", "Brave Software, Inc.", "Island Technology Inc.", "Opera Norway AS"))
'''
```

##### Bypass 1: Omitted location,  Bug subcategory: ADE2-02 Omit Alternatives - Locations

Usually, a user account that doesn't have local administrator privileges, can write to their own file paths. E.g user "testUser" would usually be able to write to `Users\testUser`. 

In the query above, there is a negation on the process.executable file path match conditions. `not process.executible: (` followed by a list of executibles. The intention may be to remove cases of other standard tooling that can generate DNS requests to these domains. However, a standard user can bypass this by creating a file path in their user directory which will match to the file path in the negating condition.

For example, if malware is saved to a new folder called `\Users\TestUser\AppData\Local\Programs\Operation\` and called the process name `opera.exe`. Then this would result in a False Negative.

There are multiple detection logic bugs which apply here:
1. The omitted file path is a bug, which is the omission of an alternative location. i.e *ADE2-03 Omit Alternatives - Locations*. 
2. The renaming of the directory `\operations` and the process name to `opera.exe` is string manipulation, so ADE treats this as *ADE1-01 Reformatting in Actions - String Manipulation*
3. The combination of abusing bugs (1) and (2) and the logical structure of the negations results in the inversion of the negation outcome `not process.executile`, meaning there will be no hits (instead a False Negative), due to the logical structure of the rule. ADE treats this as the bug category ADE4-01 Logic Manipulation - Gate Inversion, as the first chained NOT clause is true. (Because `(NOT executable)` is `false`, then the entire `(NOT executable) AND (NOT (signed AND subject))` is also `false`. Explained deeper in ADE4 Logic Manipulation)



#### ADE2-03 Example 2:  [Kubernetes Direct API Request via Curl or Wget](https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_kubernetes_direct_api_request_via_curl_or_wget.toml)

This Elastic security rule monitors for the execution of curl or wget commands that directly access Kubernetes API endpoints. This is because the behavior may indicate an attempt to interact with Kubernetes resources in a potentially unauthorized manner.

The query is as set out below.

```SQL
query = '''
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started", "ProcessRollup2") and
process.name in ("curl", "wget") and process.args like~ (
  "*http*//*/apis/authorization.k8s.io/*",
  "*http*//*/apis/rbac.authorization.k8s.io/*",
  "*http*//*/api/v1/secrets*",
  "*http*//*/api/v1/namespaces/*/secrets*",
  "*http*//*/api/v1/configmaps*",
  "*http*//*/api/v1/pods*",
  "*http*//*/apis/apps/v1/deployments*"
)
'''
```
The resources included in the detection logic are specifically for gathering information about the Kubernetes environment such as; secrets, config maps, and other sensitive data.


##### Bypass 1: Omitted location,  Bug subcategory: ADE2-02 Omit Alternatives - Locations

However, there are a few other subresources in API groups that aren't included that are commonly abused in environments with poor RBAC.
- `*/api/v1/namespaces/*/pods/*/log*`
- `*/api/v1/namespaces/*/pods/*/exec*` which may provide an execution vector
- `*/api/v1/namespaces/*/pods/*/attach*`
- `*/api/v1/namespaces/*/pods/*/portforward*`
- `*/api/v1/namespaces/*/pods/*/proxy*` and service proxy
- `*/api/v1/namespaces/*/pods/*/eviction*` (evictions for service distruption)
- `*/authentication.k8s.io/*` (which is not `authorization.k8s.io/*`) for tokenreviews
- `*/certificates.k8s.io/*` for certificatesigningrequests resources such as client cert requests, CSRs etcc

In ADE, these are API locations due to the path being used in the search, so are also given the bug subcategory **ADE1-03 Omit Alternatives - Location** as well as **ADE1-01 Omit Alternatives - API/Function**


---

### ADE2-04 Omit Alternatives - File Type

Where detection logic searches for information that in reality varies by file type, as alternative file types exist in scope that the detection logic doesn't account for. This is a bug by the omission of alternative file types in the detection logic.


#### ADE2-04, Example 1: [Ingress Transfer via Windows BITS](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_ingress_transfer_bits.toml)

This is a detection rule in Elastic Endgame EDR, of query type Elastic Query Language (EQL). The query section is below.

Description: *"Identifies downloads of executable and archive files via the Windows Background Intelligent Transfer Service (BITS).
Adversaries could leverage Windows BITS transfer jobs to download remote payloads."*

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

If you read carefully you will see that in order to capture other potential extensions the rule relies on the extension header bytes that begin with `4d5a`. The related section is below.

```SQL
  (file.extension : ("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl") or
   file.Ext.header_bytes : "4d5a*")
```
This means that anything with an extension not in that tuple that *doesn't* have that header_bytes starting with "4d5a" (bytes 4D 5A in hex) **will not trigger this rule.**, so anything not in that tuple that isn't a PE.

##### Bypass 1, omitted file types, ADDE2-04 Omit Alternatives - File Type

The detection rule scope is about using Windows Background Intelligent Transfer Service (BITS) for ingress transfer of *archive or executable files*. BITS itself does not restrict transfers by file type or magic number. BITS itself only cares about transport protocols (HTTP/HTTPS/SMB) and the job configuration, but not the file’s internal structure.

Examples of archive or executables that would result in False Negatives include:
- Code/text files:  `.py`, `.c` (if compiled post transfer), `.sql`, `.ps1`, depending on interpreters avaliable
- Archives not in the above query, such as `.7z`, `.gz`, `.bz2`

Due to this ADE Framework determines it to be a bug, where there has been an omission of an alternative file type, or **ADE2-04 Omit Alternatives - File Type**.

This elastic detection rule looks for those extensions and header byte matches because they are commonly used by attackers. To dive deeper, a detection engineer or threat hunter may assume that the reason for archive files to be included in scope is to deliver compressed executables or documents with macros. In which case, documents with macros should also be included (e.g .xlsm, .docm).

---

**Contents**

- [README.md](README.md)
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- [Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md)
- [ADE1 Reformatting in Actions](ADE1_Reformatting_in_Actions.md)**
- **ADE2 Omit Alternatives (Current Page)**
- [ADE3 Context Development](ADE3_Context_Development.md)
- [ADE4 Logic Manipulation](ADE4_Logic_Manipulation.md)
- [Bug Likelihood Test](Bug_Likelihood_Test.md)
- [LICENCE](LICENSE)
