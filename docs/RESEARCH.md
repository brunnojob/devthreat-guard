# Research to implementation

Reviewed 2026-11-19. These sources inform design priorities, not empirical validation of this scanner. No downloaded article is redistributed and no source text is copied into detector rules. All research summaries below are original, brief paraphrases.

| Source | Evidence type and limits | Concrete design decision |
|---|---|---|
| [NIST SP 800-218, SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final), February 2022 | Final secure development guidance, not a checklist that certifies this project | Code-review findings and correction verification support PW.7/PW.8 practices; least privilege and dependency maintenance in CI. This is an informal mapping, not an assessment of conformity. |
| [Check Point Cyber Security Report 2026](https://research.checkpoint.com/2026/cyber-security-report-2026/), January 28, 2026 | Vendor observations about 2025; does not measure this scanner | Lessons cover identity, supply chain, edge inventory, ransomware recovery and untrusted agent content. No vendor statistic is presented as tool accuracy. |
| [arXiv cs.CR recent](https://arxiv.org/list/cs.CR/recent), specifically [Bian et al., Mitigating fix reversal](https://arxiv.org/abs/2611.24489), November 18, 2026 | Newly submitted preprint. Reports behavior of learned vulnerability detectors; not evidence about regex checks | Explicit paired vulnerable/fixed fixtures and regression tests. This project does not implement CFVul or a learned model. |
| João Victor Alves Vasconcelos, *Teste de Invasão: O segredo por trás de como funciona uma invasão hacker, a metodologia de invasão utilizada por hackers*. Supplied PDF `27956-2510-22889-1-10-20240326.pdf` | Explanatory educational article. Date 2024 inferred from supplied filename; individual publication page/date not independently verified. [SBC portal](https://sol.sbc.org.br/) timed out during review | Attack-stage awareness, defensive tool explanations and evidence-preserving reporting. We do not adopt the article's broad claims about all attackers or reproduce instructions for erasing traces. |
| Adji Kusuma, Suhirwan and Agus H. Sulistyono Reksoprodjo, *Forecasting Cyber Threat Landscapes in Indonesia (2025-2026): A Predictive Analysis Using the MITRE ATT&CK Framework*, IJEVSS 5(2), 2026. Supplied PDF `3121-Article Text-8158-1-10-20260330.pdf` | Predictive regional analysis, not measured worldwide incidence. Individual article URL/DOI not confirmed | Supply-chain lessons, recovery and least privilege. Referenced [MITRE ATT&CK](https://attack.mitre.org/) is used as study material, not proof that all techniques are detected. |
| Durga Akshaya Alapati et al., *AI-Enabled Cybersecurity: A Systems Framework for Evaluating Threat Detection, Defensive Capacity, and End-User Protection and Artificial Intelligence: The Evaluation of AI Technologies and Tools to Protect the End Users*, Engineering Proceedings 143, 93, November 9, 2026, [DOI](https://doi.org/10.3390/engproc2026143093). Supplied PDF `engproc-143-00093.pdf` | Conceptual systems framework. Its examples/accuracy discussions do not establish this product's efficacy | Zero dependency runtime, local analysis, explicit confidence and false-positive/negative limits. No unnecessary AI dependency or invented accuracy percentage. |

## Complementary tools

Catalog explanations use official documentation: [ZAP](https://www.zaproxy.org/docs/), [Nmap](https://nmap.org/book/man.html), [Wireshark](https://www.wireshark.org/docs/), [sqlmap](https://github.com/sqlmapproject/sqlmap/wiki), [Semgrep](https://semgrep.dev/docs/) and [Trivy](https://trivy.dev/). They are independent tools, not bundled, invoked or endorsed integrations. Automated active tests can affect availability and data; scope them to an authorized lab.

## Evaluation boundary

Tests demonstrate only selected patterns and corrected application boundaries. Included known false positive: a benign string containing `eval(input)`. Included known false negative: aliasing `eval` before calling the alias. These are documented weaknesses rather than suppressed accuracy failures. Real-world precision, recall, performance under load and adversarial robustness have not been measured.

## Platform

[GitHub Marketplace publishing requirements](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace) require public action metadata, a unique name, a tagged release and applicable account agreements. Pro/Developer Program membership does not bypass these requirements and does not itself add runtime protection.
