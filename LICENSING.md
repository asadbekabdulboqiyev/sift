# Licensing

All software in Sift is open source. Every file in this repository is licensed
under the **Apache License 2.0**. An optional commercial **Enterprise** support
and services tier is a planning draft only: it is not a separate codebase, does
not gate any software feature, and no commercial offering is published today.

| Tier | License | What it covers |
|---|---|---|
| **Core** (this repository) | [Apache License 2.0](LICENSE) | Everything in this repository: the CLI, load engine, protocol clients, scenario engine, replay, scanner/pentest, VeriGate, dashboard (OIDC bearer-token verification and RBAC), persistent run history and audit log, reports, and the public Go library in `api/` |
| **Enterprise** (planned, not currently offered) | Planned commercial services agreement | Planned priority support, SLA, hosted/managed deployment, compliance/procurement package, and custom integration — services around the same Apache-2.0 software |

---

## 1. Core — Apache-2.0

Everything currently in this repository is licensed under the **Apache License,
Version 2.0**. You may use, modify, embed, self-host, and redistribute it,
including commercially and inside closed-source products, subject to the terms
in [`LICENSE`](LICENSE) and the attributions in [`NOTICE`](NOTICE).

The full text of the core license is in [`LICENSE`](LICENSE).

## 2. Enterprise tier — commercial support and services

Everything in this repository is licensed under **Apache-2.0**. Capabilities
actually present in the source tree include:

- OpenID Connect (OIDC) bearer-token verification and role-based access control
  (RBAC) in the dashboard;
- Persistent run history and the audit log of who ran what, against which
  target, when, and under whose approval;
- The distributed fleet coordination code.

**Not implemented:** SAML SSO and a multi-tenant control plane (teams, projects,
per-tenant isolation). `internal/tenant/` is unused scaffolding; multi-tenancy
is planned work, not a shipped feature. Sift is a local-first, single-operator
tool.

None of the existing capabilities are removed from the open-source repository,
withheld from Apache-2.0, or gated behind a commercial license, a license key,
or a build tag. The Apache-2.0 core is a complete, usable tool on its own.

The **Enterprise** tier is a *planned* set of services around that same
Apache-2.0 software. It is a planning draft (see `docs/ENTERPRISE.md`), not a
published offer: no contract, SLA, or hosted service is available today. If
pursued, it would cover only:

- Priority support (including 24/7 response targets, as defined by contract);
- A contractual Service Level Agreement (SLA);
- Hosted / managed deployment (including autoscaling and a hosted coordinator);
- A compliance and procurement package (documentation and support for InfoSec
  and procurement review — no certification is implied by this license);
- Custom integration work.

These would be support, deployment, and contractual offerings, not software
features absent from the repository. The Apache-2.0 core stands on its own.

There is no commercial agreement to discuss today. For questions about the
planning draft, contact the maintainer (see [`MAINTAINERS.md`](MAINTAINERS.md)).

## 3. Relicensing note (prior releases)

Earlier releases of Sift were published under
**AGPL-3.0**. A license already granted cannot be revoked: **anyone who received
a copy of an AGPL-3.0 release keeps the rights AGPL-3.0 granted them, for that
version, forever.** Relicensing applies going forward only — to this release and
later ones. If you need the terms that applied to an older version, use the
`LICENSE` file at the matching git tag.

`git shortlog -sne HEAD` currently reports four author identities:
329 commits as `Asadbek <asadbeksoon0421@icloud.com>`, 16 as
`TechCorp <cto@techcorp.example>`, 1 as
`Asadbek Abdulboqiyev <asadbeksoon0421@icloud.com>`, and 1 as
`VeriBench <vb@local>`. The tree is therefore not literally single-author, and
this document makes no claim that relicensing requires no one else's agreement.
The [`NOTICE`](NOTICE) file credits the maintainer and contributors. A DCO
sign-off is required for new contributions, including the maintainer's, as
described in §4; commits predating that requirement do not have one.

## 4. Contributions

Every contribution must carry a Developer Certificate of Origin (DCO) sign-off.
By adding `Signed-off-by`, you certify that you have the right to submit the
contribution under the repository license, Apache-2.0. There is no separate CLA
and no dual-license grant: the planned Enterprise tier licenses services, not a
second copy of the code.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) section 9 for the exact procedure.

## 4.1 Why a sign-off, and why now

A sign-off recorded at contribution time keeps the provenance of every patch
explicit, so future licensing work does not depend on reconstructing who agreed
to what. The requirement applies to all contributors, including the maintainer.

## 5. Third-party components

The binaries bundle third-party Go modules under their own licenses
(Apache-2.0, BSD-3-Clause, BSD-2-Clause, MIT). The full attribution list is in
[`NOTICE`](NOTICE). Those licenses apply to those components only; they do not
relicense the core.

## 6. Trademarks

"Sift" and the project logo are not covered by the Apache-2.0 grant.
Forks may use the source under Apache-2.0, but must not present themselves as
the official project or imply endorsement by the maintainer.
