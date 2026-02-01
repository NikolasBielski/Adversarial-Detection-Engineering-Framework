# ADE1-01 Example: Triple Cross eBPF Rootkit Default Persistence

**Bug Category:** ADE1-01 Reformatting in Actions - Substring Manipulation

## Original Rule

**Source:** [Sigma - Triple Cross eBPF Rootkit Default Persistence](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_triple_cross_rootkit_persistence.yml)

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

## Original Implementation (TripleCross PoC)

**Source:** [TripleCross deployer.sh](https://github.com/h3xduck/TripleCross/blob/master/src/helpers/deployer.sh)

```shell
## Persistence
declare CRON_PERSIST="* * * * * osboxes /bin/sudo /home/osboxes/TFG/apps/deployer.sh"
declare SUDO_PERSIST="osboxes ALL=(ALL:ALL) NOPASSWD:ALL #"
echo "$CRON_PERSIST" > /etc/cron.d/ebpfbackdoor
echo "$SUDO_PERSIST" > /etc/sudoers.d/ebpfbackdoor
```

## The Bug

The rule relies on exact filename match `ebpfbackdoor`, which is trivially mutable by an attacker.

**Context:**
- TripleCross was detected in 2022 (see rule creation date)
- The rule is now part of base Sigma Linux file event rulesets (as of 2026)
- This represents threat intelligence-based detection that should have different timeliness expectations than robust TTP-based detections

## Bypass

### Simple Filename Modification

```shell
## Persistence
declare CRON_PERSIST="* * * * * osboxes /bin/sudo /home/osboxes/TFG/apps/deployer.sh"
declare SUDO_PERSIST="osboxes ALL=(ALL:ALL) NOPASSWD:ALL #"
echo "$CRON_PERSIST" > /etc/cron.d/<not_ebpfbackdoor>
echo "$SUDO_PERSIST" > /etc/sudoers.d/<not_ebpfbackdoor>
```

Any filename that doesn't match `ebpfbackdoor` results in a False Negative.

## Modern Rule Management Considerations

- **Threat Intelligence Rules** vs. **Robust Detection Rules** have different lifecycles
- TripleCross-specific indicators from 2022 should ideally evolve into more robust detections
- A more robust version would detect **any** file creation in `/etc/cron.d/` or `/etc/sudoers.d/` directories
- The ADE framework catches rules like this where query logic can be mutated by attackers or becomes outdated as tooling evolves

## Impact

False Negative: Attacker achieves identical persistence mechanism using any filename other than `ebpfbackdoor`.

---

**Related Documentation:**
- [ADE1 Reformatting in Actions](../../docs/taxonomy/ade1-reformatting-in-actions.md)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
