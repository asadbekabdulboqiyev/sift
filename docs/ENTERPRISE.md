# Sift Enterprise (Planning Draft)

**Status:** Planning/mapping only (no SOC 2 / ISO 27001 certification claims)  
**Version:** 1.0  
**Date:** 2026-11-05

This document outlines a potential enterprise/support tier around the Sift project. It does **not** claim certifications, guarantees, or commercial availability unless explicitly stated elsewhere.

## 1. Open-core boundary

Every software capability that exists in Sift today is in this repository and
licensed under **Apache-2.0**. This includes OIDC bearer-token verification,
role-based access control (RBAC), persistent run history, and audit logging. No
feature is removed from the open-source repository or withheld behind a
commercial license, a license key, or a build tag.

SAML SSO and a multi-tenant control plane (teams, projects, per-tenant
isolation) are **not implemented**. The `internal/tenant/` package is unused
scaffolding. Sift is a local-first, single-operator tool; multi-tenancy is a
possible future direction, not a current capability.

| Capability | In this repository (Apache-2.0) |
|---|---:|
| HTTP load testing | ✅ |
| Security scanning (TLS/WAF/HTTP/security checks) | ✅ |
| Distributed mode + worker controls | ✅ |
| Dashboard (web UI) | ✅ |
| OIDC single sign-on | ✅ |
| SAML single sign-on | ❌ - planned, not implemented |
| Role-based access control (RBAC) | ✅ |
| Multi-tenant control plane (teams, projects, per-tenant isolation) | ❌ - planned, not implemented |
| Persistent run history and audit log | ✅ |
| HTTP/3/QUIC-related capabilities (as implemented) | ✅ |
| Browser-based testing (as implemented) | ✅ |

The commercial tier below adds **services only**; it adds no software features
and removes none.

## 2. Enterprise services (commercial, optional)

The Enterprise tier is a **planned** set of commercial services around the same
Apache-2.0 software. All entries below are planning targets, not current
offerings: no contract, SLA, or hosted service is available today. If pursued,
it would cover only:

| Service | Enterprise |
|---|---:|
| Priority support (24/7, response targets by severity) | ✅ (contractual) |
| SLA commitments | ✅ (contractual) |
| Hosted / managed deployment (including managed distributed fleet) | ✅ |
| Compliance / procurement documentation and support | ✅ (contractual) |
| Dedicated account management | ✅ (contractual) |
| Custom integration | ✅ (contractual) |
| SOC 2 Type II / ISO 27001 certification | ❌ — Not currently claimed |

### 2.1 Support and SLA
- Response-time targets by severity (contract-defined)
- Prioritized bug triage/fixes (scope-defined)
- Operational support guidance for self-hosted deployments

### 2.2 Compliance and governance (roadmap-dependent)
- Audit log export and retention guidance (the audit log itself is in the Apache-2.0 repository)
- Security/compliance documentation support
- Formal certifications would require separate audits and are **not** claimed by this document

### 2.3 Deployment assistance
- Hosted / managed deployment, including the managed distributed fleet
- Docker/Helm/Kubernetes deployment guidance
- On-prem/self-hosted rollout assistance
- Architecture review for distributed deployments

## 3. Example pricing tiers (placeholder)

> Pricing below is illustrative only and not a published offer. Plans describe
> support/services only — all software features are included in Apache-2.0
> regardless of plan.

| Plan | Example Price | Users/Admins | Support |
|---|---:|---:|---|
| Startup | $499/mo | 5 admins | Business-hours / defined SLA |
| Business | $1,499/mo | 25 admins | Priority support / defined SLA |
| Enterprise | Custom | Custom | Custom SLA/support package |

## 4. When an enterprise/support tier may be relevant

- Organizations requiring contractual support/SLA commitments
- Teams needing hosted/managed deployment or deployment assistance for production/self-hosted environments
- Customers with governance/audit workflow requirements (the underlying capabilities are available in Apache-2.0)

The open-core project provides all core technical capabilities under Apache-2.0; any commercial tier exclusively covers support, services, and contractual commitments.

## 5. Open items

- [ ] Implement SAML SSO (no SAML code exists today; OIDC is implemented)
- [ ] Decide whether multi-tenancy is in scope and implement it before claiming it
- [ ] Define actual commercial packaging and support boundaries (if pursued)
- [ ] Validate compliance roadmap separately (no certification claims until audited)
- [ ] Establish billing/support processes (if commercialized)
- [ ] Publish official support/contact channels for enterprise inquiries
