# Bug Likelihood Test

The Bug Likelihood Test is a fast pre‑analysis heuristic used to estimate whether a detection rule is likely to contain ADE‑class bugs before deep manual review or testing

---

## Capture Rule Parameters:

Before applying the ADE process, capture the key parameters of the detection rule:

1. Identify the detection rule's scope
   - Purpose of the rule
   - Description provided by the author
   - MITRE ATT&CK mapping(s)

2. Note the detection logic's hypothesis test
   - What the query is doing (the machine-interpretable logic)
   - Null and Alternative hypotheses
   - Query frequency, bucket time range

Then, continue on with the Bug Likelihoot Test.

## Bug Likelihood Test

- [ ] Is there another method or tool you know of that is in scope, which isn’t in a condition?

      - ADE2 – Omit Alternatives
      - Most commonly ADE2‑01 (API/Function) or ADE2‑04 (File Types).
      - The detection hypothesis assumes a single implementation path, while functionally equivalent alternatives exist within scope but are omitted.

- [ ] Is there another version of the OS, function or API since the rule was created?
      
      - ADE2‑02 – Omit Alternatives (Versioning)
      - The rule encodes version‑specific assumptions that no longer hold across supported or in‑scope versions.

- [ ] Does the query’s conditions paint an assumption of only covering certain flavors or distros of a tech, when the rule specifically didn’t say it intended to?

      - ADE2‑03 – Omit Alternatives (Locations)
      - Often manifests as distro‑specific paths, binaries, log formats, or platform nuances unintentionally narrowing coverage.

- [ ] Is there a process name string match assumption within a condition, and can the process be copied and renamed with attacker‑assumed permissions?
      
      - ADE3‑01 – Context Development (Process Cloning)
      - The attacker can alter surrounding context (binary name) without changing the in‑scope behavior.

- [ ] Is there a path being assumed used in a condition?
      
      - ADE2‑03 – Omit Alternatives (Locations)
      - The rule assumes a fixed filesystem or registry path while alternative valid locations exist within scope.

- [ ] Is the level of log manipulation potential high, such as command line logging?
      
      - ADE1‑01 – Reformatting in Actions (Substring Manipulation)
      - Attacker‑controlled string fields enable obfuscation, token splitting, encoding, or delimiter abuse that defeats exact or partial matches.

- [ ] Does the query include negations (NOT) or conjunctions (AND) whose condition relies on the attacker’s amendable data?
      
      - ADE4‑01 / ADE4‑02 – Logic Manipulation (Gate or Conjunction Inversion)
      - The attacker can poison inputs to flip Boolean outcomes, often by exploiting filters, exceptions, or conjunction logic.

- [ ] Are there any aggregation operators used, such as >= or <= etc?
      
      - ADE3‑02 – Context Development (Aggregation Hijacking)
      - The attacker may influence the aggregated value (counts, sizes, uniqueness, thresholds) to stay below or above detection boundaries.

- [ ] Is there a new terms rule, suppression, or coupling of an entity in an aggregation (e.g. source.ip, user.name)?
      
      - ADE3‑02 – Context Development (Aggregation Hijacking)
      - Entity coupling and suppression logic can be gamed to fold malicious activity into existing baselines or suppress alerts.

- [ ] Does the rule scope exclude privileged accounts such as root or administrator, yet isn’t for privilege escalation?
      
      - ADE4‑03 – Logic Manipulation (Incorrect Expression)
      - The detection hypothesis contradicts the threat model: excluding the very principals most likely required to perform the in‑scope activity, resulting in structural false negatives.


If multiple items in a single ADE category are flagged, a full ADE analysis of the rule is strongly recommended, starting with adversarial hypothesis testing.

**Contents**

- [README.md](README.md)
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- [Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md)
- [ADE1 Reformatting in Actions](ADE1_Reformatting_in_Actions.md)
- [ADE2 Omit Alternatives](ADE2_Omit_Alternatives.md)
- [ADE3 Context Development](ADE3_Context_Development.md)
- [ADE4 Logic Manipulation](ADE4_Logic_Manipulation.md)
- **Bug Likelihood Test (Current Page)**
- [LICENCE](LICENSE)
