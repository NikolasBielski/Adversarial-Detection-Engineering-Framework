# Adversarial Detection Engineering (ADE) Framework

[![Author](https://img.shields.io/badge/Author-Nikolas_Bielski-blue)](https://github.com/NikolasBielski)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/NikolasBielski/Adversarial-Detection-Engineering-Framework)](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/commits/main)
[![GitHub License](https://img.shields.io/github/license/NikolasBielski/Adversarial-Detection-Engineering-Framework)](https://github.com/NikolasBielski/Adversarial-Detection-Engineering-Framework/blob/main/LICENSE)

- ✅ Get ahead of False Negatives by understanding how detection logic fails before threat actors exploit it
- ✅ Identify reproducible detection logic bugs and map them to formal ADE categories
- ✅ Embed an attacker’s mental model into how detection logic is designed and reviewed
- ✅ Expose structural weaknesses in rules used for hunts or production MDR tooling (SIEM, XDR, EDR)
- ✅ Equip red teams and detection engineers with actionable detection logic bug intelligence


## What is Adversarial Detection Engineering (ADE)?

Adversarial Detection Engineering (ADE) is the discipline of reasoning about False Negatives in detection rules on a per rule basis. These False Negatives are the result of bugs in detection logic, that is, mismatches between *what a detection rule is intended to identify* and *how its logic actually implements that intention*.

The ADE Framework provides a modern open source formalization of Detection Logic Bugs, including definitions, a taxonomy, and concrete examples drawn from multiple vendor and open source rulesets.

With ADE, instead of waiting for real world False Negatives to show, a detection engineer can iterate over a taxonomy of logic bugs, asking:

 *“What variations would cause this rule's detection logic to miss what it was intended to catch?”*.

This adversarial line of reasoning mirrors how threat actors abuse weaknesses in detection logic.

**The ADE Framework provides**:
- **A Theory of Detection Logic Bugs**, with specific definitions to be used consistently.

- **A Formal Taxonomy of Bug classes**, derived from analysis of multiple open-source rulesets, with clear terminology and categorization.

- **Concrete examples of rule bypasses resulting from logic bugs**. to help defenders recognize and reason about potential False Negatives before threat actors do.

## ADE Framework Contents

| Component | Page | Description |
|:------|:---------|:------------|
| 🔬 **Detection Logic Bug Theory** | [Foundation of Detection Logic Bugs](Detection_Logic_Bug_Theory.md) | Foundation of the Theory of Detection Logic Bugs, and how abusing them results in False Negatives (bypasses) |
| 🌳 **Detection Logic Bug Taxonomy** | [Formal Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md) | Comprehensive taxonomy of Detection Logic Bugs, with multiple examples and bug category labelling. |
| 🧩 **Bug Category ADE1 - Reformatting in Actions** | [ADE1 Details](ADE1_Reformatting_in_Actions.md) | Definitions and examples of ADE1 Logic Bugs and their bypasses. |
| 🔄 **Bug Category ADE2 - Omit Alternatives** | [ADE2 Details](ADE2_Omit_Alternatives.md) | Definitions and examples of ADE2 Logic Bugs and their bypasses. |
| 🎯 **Bug Category ADE3 - Context Development** | [ADE3 Details](ADE3_Context_Development.md) | Definitions and examples of ADE3 Logic Bugs and their bypasses. |
| 🔀 **Bug Category ADE4 - Logic Manipulation** | [ADE4 Details](ADE4_Logic_Manipulation.md) | Definitions and examples of ADE4 Logic Bugs and their bypasses. |
| 🔎 **Bug Likelihood Test** | [Identification Tooling](Bug_Likelihood_Test.md) | Quick checklist to examine detection rules for potential bugs. |

---

## ADE Detection Logic Bug Taxonomy

The full taxonomy consists of 4 categories, and 11 sub-categories, each including an example of a bug and it's resulting False Negative that can occur if abused.

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
🌳 ADE4 – Logic Manipulation
    ├─ ADE4-01 Gate Inversion
    ├─ ADE4-02 Conjunction Inversion
    └─ ADE4-03 Incorrect Expression
```


## Extend to Existing Detection Engineering Framework

ADE complements existing detection engineering frameworks, such as Kunal Hatode (Ke0xe)'s Detection Engineering Lifecycle Phases. In particular, the ['Improvement Phase'](https://github.com/Ke0xes/Detection-Engineering-Framework/blob/main/improvement-phase.md) emphasizes identifying gaps in detection rules.  

ADE provides a **formal lens to reason about Detection Logic Bugs** within this phase, offering a structured way to classify potential rule weaknesses and understand sources of False Negatives.

## ADE's Focus

ADE is specifically concerned with **Detection Logic Bugs**, instances where the logic of a detection rule contradicts its intended purpose, resulting in **rule-specific False Negatives**.

Other issues that may affect a detection rule, but are outside ADE’s scope, include:
- **Data Quality Issues:** Required signals are missing, unreliable, or inconsistent, leading to weak or incomplete detection coverage.  
- **Tuning Issues:** Detection logic is overly broad or “greedy,” which may cause false positives but is not a logic bug.  

## Want to contribute?

Author:  [Nikolas Bielski](Linkedin)

### Current Opportunities for Contributors

We are looking for contributors to help expand and improve the ADE Framework. Areas of active development include:
- Static Analyzer Development: Tools to analyze detection rules for potential logic bugs, designed for use in Detection-as-Code CI/CD pipelines or IDEs.
- Bug Repository Expansion: A curated collection of identified detection logic bugs, along with their resulting False Negatives, drawn from multiple open-source and vendor rulesets.

Contributions can range from coding and tooling to documentation, examples, and taxonomy refinement.

## How to Use ADE

ADE is designed to help detection engineers and security researchers reason about False Negatives. Recommended usage:

1. **Read the Theory & Taxonomy** to understand bug classes.  
2. **Map your rules or queries** against the taxonomy to identify potential logic weaknesses.  
3. **Document observations** in your own improvement process or detection engineering framework.  


## Related Work / References

ADE builds on and complements existing work in detection engineering, threat modeling and security analytics. While many frameworks focus on coverage, operational workflow, or rule formatting, **ADE is unique in formalizing logic-level causes of False Negatives**.

Some related work:
1. [MITRE ATT&CK](https://attack.mitre.org/) provides context for attacks but does not formally classify logic failures in detection rules.
2. [MITRE CAR (Cyber Analytics Repository)](https://car.mitre.org/) provides a collection of detection analytics and queries for SIEM/XDR systems. CAR is rule focused, but does not provide a theory or taxonomy of detection logic bugs.
3. [Detection Engineering Lifecycle by Kunal Hatode (Ke0xe)](https://github.com/Ke0xes/Detection-Engineering-Framework) defines phases of detection engineering, including “Improvement.” ADE provides a complementary lens for reasoning about logic level gaps within this phase.
4. Numerous academic papers discuss IDS/EDR rule quality, anomaly detection and signature evaluation (e.g., false positives/negatives). ADE differs by focusing on formal logic-level bug classification rather than statistical performance or tuning issues.

ADE fills a critical gap by providing a theory, taxonomy and examples of detection logic bugs, thus enabling defenders to proactively reason about False Negatives in ways that existing frameworks and rule repositories do not.


## License

This project is licensed under [GNU GPL v3](LICENSE).


## 🚨 DISCLAIMER 🚨

This framework is intended solely for defensive security research, detection engineering, and risk assessment. Its purpose is to help defenders identify, reason about, and remediate weaknesses in detection logic and security monitoring systems.

Users are solely responsible for ensuring that their use complies with all applicable laws, regulations, and authorization requirements. The authors and collaborators assume no liability for misuse, damage, or harm resulting from use of this framework.

This framework is provided "as is," without warranty of any kind, express or implied, including but not limited to fitness for a particular purpose, security effectiveness, or correctness of results.

Examples are provided with responsible disclosure considerations. Detection rules and monitoring content are generally out of scope for vendor vulnerability disclosure and bug bounty programs.

The authors and collaborators strongly discourage the use of this framework for malicious purposes. Security research should improve resilience, not enable harm. Always obtain explicit written authorization before testing detections, systems, or controls outside environments you own or operate.


## Full Contents
- **README.md (Current Page)**
- [Detection Logic Bug Theory](Detection_Logic_Bug_Theory.md)
- [Detection Logic Bug Taxonomy](Detection_Logic_Bug_Taxonomy.md)
- [ADE1 Reformatting in Actions](ADE1_Reformatting_in_Actions.md)
- [ADE2 Omit Alternatives](ADE2_Omit_Alternatives.md)
- [ADE3 Context Development](ADE3_Context_Development.md)
- [LICENCE](LICENSE)
