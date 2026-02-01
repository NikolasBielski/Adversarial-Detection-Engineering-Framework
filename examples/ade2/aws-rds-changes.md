# ADE2-01 & ADE2-02 Example: AWS RDS Database Changes

**Bug Categories:**
- ADE2-01 Omit Alternatives - API/Function
- ADE2-02 Omit Alternatives - Versioning

## Original Rule

**Source:** [Microsoft Sentinel - Changes to Internet Facing AWS RDS Database Instances](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_ChangeToRDSDatabase.yaml)

**Description:** Amazon Relational Database Service (RDS) is scalable relational database in the cloud. If your organization have one or more AWS RDS Databases running, monitoring changes to especially internet facing AWS RDS (Relational Database Service). Once alerts triggered, validate if changes observed are authorized and adhere to change control policy.

**Reference:** [RDS API Reference Docs](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html)

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

## Coverage Analysis

The detection logic covers:
- **Network rule/policy changes:**
  - `AuthorizeDBSecurityGroupIngress` (edits)
  - `RevokeDBSecurityGroupIngress` (deletion)
- **Security rule/policy changes:**
  - `CreateDBSecurityGroup` (creation)
  - `DeleteDBSecurityGroup` (deletion)

## Bug 1: ADE2-01 - Omitted API Functions

### The Bug

Accounts with AWS-managed policies granting RDS actions commonly receive `rds:*` permissions on specific RDS resources. This allows **additional dangerous actions** that are omitted from the detection logic.

### Bypasses - Omitted RDS API Calls

**1. [`rds:ModifyDBInstance`](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html)**
- DB security group selection changes
- Rotating and resetting master passwords
- Change public accessibility
- Change backup and storage configurations

**2. [`rds:RebootDBInstance`](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RebootDBInstance.html) / `StartDBInstance` / `StopDBInstance`**
- Taking services offline
- Force parameter group changes (change then reboot)

**3. Other Omissions:**
- `RestoreDBInstanceFromDBSnapshot` (data exposure)
- `RestoreDBInstanceToPointInTime` (data exposure)
- `ModifyOptionGroup` (configuration changes)
- `ModifyDBParameterGroup` (exfiltration pathways)

### Additional Exclusions

Not covered for other RDS deployment types:
- Aurora cluster APIs
- Redshift integrations (`CreateIntegration`)
- IAM role attachment APIs
- EC2 VPC security group APIs
- RDS Data API (Aurora only)

## Bug 2: ADE2-02 - Version Drift

### The Bug

The detection logic assumes **EC2-Classic DB instances** (legacy deployment model). The API endpoints include `DB` prefix (`AuthorizeDBSecurityGroupIngress`, etc.), which are specific to EC2-Classic RDS.

Modern deployments use **EC2 VPC**, where different APIs control security groups.

### Bypass - EC2 VPC RDS Instances

Most commonly, RDS instances run in EC2 VPC, where [EC2 VPC security groups are used](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html).

**VPC Security Group APIs (not detected):**
```
ec2:AuthorizeSecurityGroupIngress
ec2:RevokeSecurityGroupIngress
```

**Detection Logic Mismatch:**
```
(RDS in VPC) AuthorizeSecurityGroupIngress != (Kusto detection logic) AuthorizeDBSecurityGroupIngress
(RDS in VPC) RevokeSecurityGroupIngress   != (Kusto detection logic) RevokeDBSecurityGroupIngress
```

### Impact

Changes to make an RDS instance internet-accessible in VPC deployments generate **different CloudTrail event names**, resulting in False Negatives.

## Combined Impact

An attacker with RDS modification permissions can:
1. Use `ModifyDBInstance` to change public accessibility (ADE2-01)
2. Modify VPC security groups for RDS in VPC environments (ADE2-02)
3. Rotate master passwords and exfiltrate credentials (ADE2-01)
4. Restore snapshots to expose data (ADE2-01)

All without triggering the detection rule.

---

**Related Documentation:**
- [ADE2 Omit Alternatives](../../docs/taxonomy/ade2-omit-alternatives.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
