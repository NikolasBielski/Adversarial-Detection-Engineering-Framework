# Detection Logic Bug Taxonomy

The following classes are for bugs found in multiple rulesets (see below table). The taxonomy will continue to grow and expand as more are found.

Rulesets currently informing the taxonomy:

| Integration/Record Source | SIGMA    | Microsoft Sentinel | Elastic Security SIEM | Elastic Security Endgame EDR |
|:-----------------------|:---------|:------------|:------------|:------------|
| AWS (CloudTrail)                        | <span style="color:red">❌</span>  | <span style="color:red">❌</span>           | <span style="color:red">❌</span>                      | <span style="color:red">❌</span>                            |
| Windows PowerShell Script Block Logging | <span style="color:red">❌</span>  | <span style="color:red">❌</span>           | <span style="color:red">❌</span>                      | <span style="color:red">❌</span>                            |
| Linux                                  | <span style="color:red">❌</span>  |  ✅        | <span style="color:red">❌</span>                      | <span style="color:red">❌</span>                            |
| Azure                                  | 🟡 TBC       | 🟡 TBC                | <span style="color:red">❌</span>                      | N/A                                 |
| O365                                   | 🟡 TBC       | 🟡 TBC                | <span style="color:red">❌</span>                      | N/A                                 |
| LLM                                    | 🟡 TBC       | 🟡 TBC                | <span style="color:red">❌</span>                      | N/A                                 |
| macOS                                  | 🟡 TBC       | 🟡 TBC                | <span style="color:red">❌</span>                      | <span style="color:red">❌</span>                            |
| Okta                                   | 🟡 TBC       | 🟡 TBC                | <span style="color:red">❌</span>                      | N/A                                 |
---
✅ = Unaffected (No logic bugs found)
❌ = Affected  (Logic bugs found)
🟡 TBC = To Be Confirmed (Unassessed) 


Other solutions and their rulesets have not yet been reviewed as part of creating the Detection Logic Bug taxonomy. The taxonomy is subject to expand based on newly seen examples, so is considered a living taxonomy.

## ADE Detection Logic Bug Taxonomy

The full taxonomy consists of 4 categories, and 11 sub-categories
- Each category is given a label, such as ADE1, ADE2, ...., ADE4.
- Subcategories are labels with their subcategory number. E.g ADE1-02, ADE3-03 This is for mappings to rules.

```
🌳 ADE1 – Reformatting in Actions
    └─ ADE1-01 Substring Manipulation
🌳 ADE2 – Omit Alternatives
    ├─ ADE2-01 API/Function
    ├─ ADE2-02 Versioning
    ├─ ADE2-03 Locations
    └─ ADE2-04 File Types
🌳 ADE3 – Context Development
    ├─ ADE3-01 Process Cloning
    ├─ ADE3-02 Aggregation Hijacking
    └─ ADE3-03 Timing and Scheduling
    └─ ADE3-04 Event Fragmentation
🌳 ADE4 – Logic Manipulation
    ├─ ADE4-01 Gate Inversion
    ├─ ADE4-02 Conjunction Inversion
    └─ ADE4-03 Incorrect Expression
```

### ADE1 - Reformatting in Actions
[Details in Taxonomy page 1](ADE1_Reformatting_in_Actions.md)

Reformatting in Actions occurs when a detection rule relies on **string match conditions**, and an attacker can manipulate the collected logs such that the match fails.  
This has been widely exploited by Threat Actors for years and still appears in modern SIEM rules.

**Subcategories:**
- **ADE1-01 Reformatting in Actions - Substring Manipulation**
  When detection logic relies on substring matches, an attacker can alter or obfuscate the input data so that the hypothesis conditions are not met, resulting in a False Negative.


### ADE2 - Omit Alternatives
[Details in Taxonomy page 2](ADE2_Omit_Alternatives.md)

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

### ADE3 Context Development
[Details in Taxonomy page 3](ADE3_Context_Development.md)

Context Development bugs occur when an attacker takes additional steps to **manipulate or poison contextual data** used by the detection logic, causing in‑scope activity to bypass rule conditions.  

Rather than changing the primary action, the attacker shapes the surrounding context that the rule relies on.


**ADE3-01 Context Development - Process Cloning**
This occurs when detection logic relies on **string-based identification of a process or binary**, while implicitly assuming the attacker cannot clone or rename binaries. If the attacker has sufficient privileges to duplicate and rename a binary, they can execute identical behavior under a different process name, resulting in a False Negative.

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


**ADE3-04 Context Development - Event Fragmentation**

This occurs when detection logic relies on **multi-substring matching** (`using |all`, `contains|all`, or multiple `AND` conditions) while assuming all required substrings will appear in a single process creation event. However, shell operators like `|` and `&` cause commands to be split into multiple separate process creation events, preventing the detection logic from matching, resulting in a False Negative.

*Result*: In-scope malicious activity bypasses detection without the attacker needing to know the rule exists


---

### ADE4 Logic Manipulation
[Details in Taxonomy page 4](ADE4_Logic_Manipulation.md)

Logic Manipulation occurs when an attacker analyzes detection logic as Boolean conditions and manipulates inputs or filters to invert, bypass, or neutralize the rule outcome.

**Subcategories:**
- **ADE4-01 Logic Manipulation - Gate Inversion**: Detection rules that include NOT clauses can be bypassed if attackers insert poisoned data prior to record generation, flipping the cumulative Boolean outcome. Often happens when multiple negations could be simplified using [De Morgan’s Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws).

- **ADE4-02 Logic Manipulation - Conjunction Inversion**: Conjunction (AND) conditions can be inverted by attacker controlled input. For example, an attacker may insert data into an array evaluated by the rule so that the condition evaluates as benign, resulting in a False Negative.

- **ADE4-03 Logic Manipulation - Incorrect Expression**: Detection logic contains structural errors, such as using AND instead of OR, that prevent True Positives from ever being detected. Rare, but can completely nullify the rule.

---

To explore taxonomy categories further and see examples, visit the relevant bug category page below.

**Contents**
- [README.md](README.md)
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- **Detection Logic Bug Taxonomy (Current Page)**
- [ADE1 Reformatting in Actions](ADE1_Reformatting_in_Actions.md)
- [ADE2 Omit Alternatives](ADE2_Omit_Alternatives.md)
- [ADE3 Context Development](ADE3_Context_Development.md)
- [ADE4 Logic Manipulation](ADE4_Logic_Manipulation.md)
- [Bug Likelihood Test](Bug_Likelihood_Test.md)
- [LICENCE](LICENSE)
