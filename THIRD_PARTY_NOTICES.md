# Third-Party Notices

ATMS itself is licensed under the Apache License, Version 2.0 (see `LICENSE`,
"Copyright 2026 anguiz7z"). The components listed below are bundled,
redistributed, or referenced by ATMS and retain their own respective licenses
and copyright. Inclusion here does not change the license of those components;
each remains governed by the terms reproduced or linked under its entry.

This file is organized into three sections:

- **Bundled code** — third-party source/binaries shipped inside ATMS.
- **Bundled sample data** — third-party sample architectures redistributed
  under `samples/corpus/` for benchmarking and ingester regression testing.
- **Referenced framework data** — external security frameworks whose
  identifiers and short titles ATMS cites (ATMS curates its own summaries and
  does not reproduce the source prose).

---

## Bundled code

### Mermaid

- File: `src/atms/static/mermaid.min.js`
- License: MIT
- Copyright: Copyright (c) 2014 - present Knut Sveidqvist
- Source: https://github.com/mermaid-js/mermaid

ATMS bundles the official, pre-minified Mermaid distribution to render
diagrams in the web UI offline (no CDN dependency). The minified bundle
statically includes several of Mermaid's own dependencies. Two upstream
license banners survive verbatim in the minified file and are reproduced as
sub-component notices below; the remaining bundled dependencies (for example
dayjs, d3, cytoscape, dagre/graphlib, khroma, stylis) are MIT-, BSD-, or
ISC-licensed open-source libraries distributed by the Mermaid project under
the terms published in the upstream repository.

#### Mermaid — MIT License (full text)

```
MIT License

Copyright (c) 2014 - present Knut Sveidqvist

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

#### Sub-component notices surviving in `mermaid.min.js`

The following upstream license banners are embedded verbatim in the minified
bundle and are reproduced here as required.

**DOMPurify 3.2.4** — dual-licensed Apache-2.0 OR MPL-2.0

```
@license DOMPurify 3.2.4 | (c) Cure53 and other contributors | Released under
the Apache license 2.0 and Mozilla Public License 2.0 |
github.com/cure53/DOMPurify/blob/3.2.4/LICENSE
```

- Source: https://github.com/cure53/DOMPurify
- Full license texts:
  - Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
  - MPL-2.0: https://www.mozilla.org/en-US/MPL/2.0/

An additional `@license MIT` banner also survives in the minified bundle,
covering MIT-licensed dependencies redistributed by the Mermaid project under
the standard MIT terms reproduced above.

---

## Bundled sample data

ATMS redistributes a small set of real-world, upstream infrastructure and
threat-model samples under `samples/corpus/`. These are used as benchmark
inputs and ingester regression targets. Each retains the license stated in its
own file header, reproduced below.

| File | Component | License | Source |
| --- | --- | --- | --- |
| `samples/corpus/aws_cfn_lambda_sample.yaml` | AWS CloudFormation Lambda sample (Amazon) | MIT-0 | https://github.com/aws-cloudformation/aws-cloudformation-templates |
| `samples/corpus/azure_keyvault.bicep` | Azure Quickstart Key Vault Bicep template (Microsoft) | MIT | https://github.com/Azure/azure-quickstart-templates |
| `samples/corpus/hashicorp_aws_two_tier.tf` | HashiCorp Terraform AWS two-tier example | MPL-2.0 | https://github.com/hashicorp/terraform |
| `samples/corpus/k8s_guestbook.yaml` | Kubernetes "Guestbook" tutorial manifest | Apache-2.0 | https://github.com/kubernetes/website |
| `samples/corpus/owasp_threat_dragon_demo.json` | OWASP Threat Dragon "Demo Threat Model" (source JSON) | Apache-2.0 | https://github.com/OWASP/threat-dragon |
| `samples/corpus/owasp_threat_dragon_demo.yaml` | OWASP Threat Dragon demo model, translated to ATMS System YAML | Apache-2.0 | https://github.com/OWASP/threat-dragon |

Notes on individual entries:

- **`aws_cfn_lambda_sample.yaml`** — sourced verbatim from the
  `aws-cloudformation/aws-cloudformation-templates` repository, which Amazon
  publishes under the **MIT-0** ("MIT No Attribution") license.
- **`azure_keyvault.bicep`** — sourced verbatim from the
  `Azure/azure-quickstart-templates` repository, published under the **MIT**
  license.
- **`hashicorp_aws_two_tier.tf`** — header declares
  `# Copyright IBM Corp. 2014, 2026` and `# SPDX-License-Identifier: MPL-2.0`;
  governed by the **Mozilla Public License, Version 2.0**.
- **`k8s_guestbook.yaml`** — Kubernetes website example content, published
  under the **Apache License, Version 2.0**.
- **`owasp_threat_dragon_demo.json`** and **`owasp_threat_dragon_demo.yaml`**
  — derived from the OWASP Threat Dragon demo threat model (project lead Mike
  Goodwin); the OWASP Threat Dragon project is published under the **Apache
  License, Version 2.0**. The `.yaml` file is an ATMS translation of the
  upstream `.json` topology into ATMS System YAML.

### Full license texts for verbatim-redistributed permissive licenses

#### MIT-0 ("MIT No Attribution") — applies to `aws_cfn_lambda_sample.yaml`

```
MIT No Attribution

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

#### MIT License — applies to `azure_keyvault.bicep`

```
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

#### Apache-2.0 and MPL-2.0 (sample data)

The Apache-2.0 samples (`k8s_guestbook.yaml`,
`owasp_threat_dragon_demo.json`, `owasp_threat_dragon_demo.yaml`) are governed
by the same Apache License, Version 2.0 already reproduced in full in this
repository's `LICENSE` file; its canonical text is also published at
https://www.apache.org/licenses/LICENSE-2.0.

The MPL-2.0 sample (`hashicorp_aws_two_tier.tf`) is governed by the Mozilla
Public License, Version 2.0, whose full text is published at
https://www.mozilla.org/en-US/MPL/2.0/.

---

## Referenced framework data

ATMS's knowledge base cites identifiers and short titles from the security
frameworks below and curates its own summaries; it does **not** reproduce the
copyrighted source prose of these frameworks. Each is listed with its
canonical URL.

| Framework | Notes | Canonical URL |
| --- | --- | --- |
| MITRE ATT&CK | Apache-2.0; ATMS references technique/tactic IDs and short titles | https://attack.mitre.org/ |
| MITRE ATLAS | Apache-2.0; adversarial ML technique IDs and short titles | https://atlas.mitre.org/ |
| MITRE D3FEND | Defensive countermeasure IDs and short titles | https://d3fend.mitre.org/ |
| OWASP Top 10 for LLM Applications | Risk IDs and short titles | https://genai.owasp.org/ |
| OWASP Agentic Security Initiative (Agentic Top 10 / threats) | Threat IDs and short titles | https://genai.owasp.org/ |
| OWASP API Security Top 10 | Risk IDs and short titles | https://owasp.org/API-Security/ |
| OWASP Machine Learning Security Top 10 | Risk IDs and short titles | https://owasp.org/www-project-machine-learning-security-top-10/ |
| CSA MAESTRO | Agentic threat-modeling framework; identifiers and short titles | https://cloudsecurityalliance.org/ |
| CSA "Singapore" Guidelines (Guidelines and Companion Guide for Securing AI Systems) | Control identifiers and short titles | https://cloudsecurityalliance.org/ |
| NIST AI Risk Management Framework (AI RMF 1.0) | Function/category identifiers | https://www.nist.gov/itl/ai-risk-management-framework |
| NIST AI 600-1 (Generative AI Profile) | Identifiers and short titles | https://doi.org/10.6028/NIST.AI.600-1 |
| NIST AI 100-2 (Adversarial ML taxonomy) | Identifiers and short titles | https://doi.org/10.6028/NIST.AI.100-2e2023 |
| CISA Known Exploited Vulnerabilities (KEV) Catalog | CVE identifiers and KEV status | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| FIRST EPSS (Exploit Prediction Scoring System) | CVE scores referenced by identifier | https://www.first.org/epss/ |
| LINDDUN | Privacy threat-category identifiers and short titles | https://www.linddun.org/ |

For each framework above, ATMS references identifiers and short titles and
curates its own descriptive summaries rather than reproducing source text.
Where a framework is published under Apache-2.0 (MITRE ATT&CK, MITRE ATLAS,
OWASP Threat Dragon), that license governs the underlying data; ATMS's curated
summaries are part of ATMS and licensed under Apache-2.0.
