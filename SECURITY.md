# Security Policy

`ngx_l402` sits on the authentication path of every request it protects. It
verifies and mints L402 macaroons signed by a shared `ROOT_KEY`, talks to
Lightning and eCash backends (LND, LNC, CLN, Eclair, LNURL, NWC, BOLT12, Cashu)
on behalf of operators, and runs inside the Nginx worker process across an
`unsafe` FFI boundary. A bug here can mean bypassed authentication, leaked
secrets, or a crashed Nginx worker, so we take security reports seriously.

This is a community-maintained open-source project. Security triage and
response happen on a best-effort basis — please set expectations accordingly.
Thank you for helping keep the project and its users safe.

## Supported Versions

Security fixes are applied to the latest minor release line only. Users on
older lines should upgrade to the latest release before reporting.

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

The current released version is tracked in [`Cargo.toml`](Cargo.toml).

## Reporting a Vulnerability

**Please do not open a public GitHub issue, pull request, or discussion for
security vulnerabilities.** Public reports give attackers a head start against
operators who are already deployed. Please also test only against deployments
you own or have permission to test.

Report privately using one of the following, in order of preference:

1. **GitHub Private Vulnerability Reporting** (preferred)
   Open a report at
   <https://github.com/DhananjayPurohit/ngx_l402/security/advisories/new>.
   This keeps the report visible only to maintainers and lets us coordinate
   a fix and advisory in the same place.
2. **Direct contact with the maintainer**
   If GitHub advisories are not an option, reach out via the contact
   information on the maintainer's GitHub profile
   (<https://github.com/DhananjayPurohit>) and ask for a secure channel
   before sending details.

When reporting, please include as much of the following as you can:

- A description of the issue and its impact (auth bypass, RCE, info leak, DoS,
  memory corruption, payment/accounting bug, etc.).
- The affected version(s), commit SHA, and build configuration (features,
  backend type, platform).
- Reproduction steps, a proof-of-concept, or a crash/log excerpt. Please
  sanitize any real secrets (`ROOT_KEY`, macaroon data, invoices, node creds).
- Your assessment of severity and any known mitigations or workarounds.

Reports in any language are welcome; non-English reports may slow triage.

## What Is In Scope

The following are generally considered in scope:

- Authentication and authorization flaws in L402 / macaroon handling (bypass,
  forgery, replay, signature or caveat confusion, token reuse across tenants).
- Leakage or misuse of `ROOT_KEY`, macaroon secrets, node credentials, Redis
  credentials, or any other secret material the module touches.
- Memory-safety bugs in the Rust code, especially around the Nginx FFI
  boundary (`unsafe` blocks, pointer/null handling, lifetime issues) that
  could lead to crashes, undefined behavior, or RCE in an Nginx worker.
- Payment-integrity bugs where requests can be served without a valid
  payment, where payments are double-counted, or where invoice/price
  manipulation is possible.
- Cheap remote DoS that is expensive for the server (unbounded allocations in
  hot paths, blocking I/O in the request handler, panics reachable from
  untrusted input, etc.).
- Vulnerabilities in how the module integrates with upstream backends (LND,
  CLN, LNURL, NWC, Cashu mints, Redis) that a malicious peer could exploit.

## What Is Out Of Scope

The following are generally **not** considered security issues here and should
be filed as normal GitHub issues instead:

- Misconfiguration by the operator (weak `ROOT_KEY`, Redis exposed to the
  public internet, compromised upstream backend, etc.).
- Issues in Nginx itself, or in third-party backends (LND, CLN, mints, etc.),
  unless the module amplifies them in a non-obvious way.
- Denial of service that requires volumetric traffic indistinguishable from
  general network flooding.
- Static-analysis findings without a demonstrated impact.
- Social engineering, physical attacks, or attacks that require local root on
  the host.

If you're unsure, err on the side of reporting privately — we'd rather triage
an out-of-scope report than miss a real one.

## Response Expectations

The project is maintained by volunteers on a best-effort basis. We aim to:

- **Acknowledge** receipt of your report within about **a week**.
- **Share an initial assessment** (in scope / out of scope, rough severity)
  within **two to three weeks**.
- **Keep you updated** at a reasonable cadence while a fix is being
  developed, and let you know if something is going to take much longer.
- **Ship a fix and publish an advisory** when a patch is ready and verified.
  Critical issues will usually get a dedicated patch release; lower-severity
  issues may be batched into the next regular release.

If you haven't heard back within the acknowledgement window, please follow up
— messages occasionally get lost, and it's not a bother.

## Coordinated Disclosure

We prefer coordinated disclosure:

- Please give maintainers a reasonable window to develop and release a fix
  before going public. **90 days** from acknowledgement is a sensible
  default; we'll agree on the exact date together — shorter for issues
  already being actively exploited, longer for complex fixes that require
  operator migration.
- Reporters who follow this policy will typically be credited in the
  advisory and release notes (let us know if you'd rather remain anonymous).

## Thanks

Security reports directly improve the safety of every operator running
`ngx_l402`. We appreciate the time and care that goes into them.
