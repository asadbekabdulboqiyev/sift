# Licensing

All software in Sift is open source. Every file in this repository is licensed
under the **Apache License 2.0**. An optional commercial **Enterprise** tier
consists of support and services around that same code — it is not a separate
codebase and it does not gate any software feature.

| Tier | License | What it covers |
|---|---|---|
| **Core** (this repository) | [Apache License 2.0](LICENSE) | Everything in this repository: the CLI, load engine, protocol clients, scenario engine, replay, scanner/pentest, VeriGate, dashboard (including OIDC/SAML and RBAC), multi-tenant control plane, persistent run history and audit log, reports, and the public Go library in `api/` |
| **Enterprise** (optional commercial services) | Commercial services agreement | Priority support, SLA, hosted/managed deployment, compliance/procurement package, and custom integration — services around the same Apache-2.0 software |

---

## 1. Core — Apache-2.0

Everything currently in this repository is licensed under the **Apache License,
Version 2.0**. You may use, modify, embed, self-host, and redistribute it,
including commercially and inside closed-source products, subject to the terms
in [`LICENSE`](LICENSE) and the attributions in [`NOTICE`](NOTICE).

The full text of the core license is in [`LICENSE`](LICENSE).

## 2. Enterprise tier — commercial support and services

Everything in this repository is licensed under **Apache-2.0**. This explicitly
includes the following capabilities, which are present in the source tree and
used by the dashboard and server:

- Single sign-on (OIDC / SAML) and role-based access control (RBAC);
- The multi-tenant control plane (teams, projects, per-tenant isolation);
- Persistent run history and the audit log of who ran what, against which
  target, when, and under whose approval;
- The distributed fleet coordination code.

None of these capabilities are removed from the open-source repository, withheld
from Apache-2.0, or gated behind a commercial license, a license key, or a build
tag. The Apache-2.0 core is a complete, usable tool on its own.

The commercial **Enterprise** tier is a set of *services* around that same
Apache-2.0 software. It covers only:

- Priority support (including 24/7 response targets, as defined by contract);
- A contractual Service Level Agreement (SLA);
- Hosted / managed deployment (including autoscaling and a hosted coordinator);
- A compliance and procurement package (documentation and support for InfoSec
  and procurement review — no certification is implied by this license);
- Custom integration work.

These are support, deployment, and contractual offerings, not software features
that are absent from the repository. The commercial tier does not reduce core
functionality in any way.

To discuss a commercial support agreement, contact the maintainer (see
[`MAINTAINERS.md`](MAINTAINERS.md)).

## 3. Relicensing note (prior releases)

Earlier releases of Sift were published under
**AGPL-3.0**. A license already granted cannot be revoked: **anyone who received
a copy of an AGPL-3.0 release keeps the rights AGPL-3.0 granted them, for that
version, forever.** Relicensing applies going forward only — to this release and
later ones. If you need the terms that applied to an older version, use the
`LICENSE` file at the matching git tag.

This project has a single copyright holder (`git shortlog -sne` shows one
author), so relicensing does not require a contributor agreement from anyone
else. To keep it that way, see §4.

## 4. Contributions

To keep the open-core model legally sound, every contribution must be
accompanied by a sign-off that you have the right to submit it and that it may be
distributed under **both** the Apache-2.0 core license and the commercial
license (a dual-license grant). This is what lets the project keep a single
licensing story without ever having to hunt down contributors.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the exact procedure (Developer
Certificate of Origin).

## 4.1 Why a CLA-style sign-off, and why now

If a contributor's code enters the tree without an explicit grant that covers
future relicensing, that contributor's code can permanently block the dual
license. The sign-off requirement is added **now**, while the project still has
a single author, precisely to avoid that trap later.

## 5. Third-party components

The binaries bundle third-party Go modules under their own licenses
(Apache-2.0, BSD-3-Clause, BSD-2-Clause, MIT). The full attribution list is in
[`NOTICE`](NOTICE). Those licenses apply to those components only; they do not
relicense the core.

## 6. Trademarks

"Sift" and the project logo are not covered by the Apache-2.0 grant.
Forks may use the source under Apache-2.0, but must not present themselves as
the official project or imply endorsement by the maintainer.
