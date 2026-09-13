# Commercial licence

AutoGov is published under the AGPL-3.0-or-later. That licence is free and
permanent. This page covers the cases where it does not fit.

## Who needs a commercial licence

**You sell security services and want AutoGov inside them.** A managed security
provider running scans for clients, a consultancy shipping it as part of an
audit product, a platform that includes discovery as a feature — in all of these
the AGPL requires the source of your product to be released under the same terms.
A commercial licence removes that requirement.

**You redistribute it inside closed-source software.** Bundling the scanner into
a product you ship to customers triggers the same obligation.

**Your organisation forbids AGPL by policy.** Banks, telecoms and public bodies
often do, regardless of how the software is used. A commercial licence is usually
the fastest route through that review.

**You do not need one** to scan your own infrastructure, at any scale, with any
modifications you like, including inside a company with thousands of employees.
That case is covered by the AGPL and always will be.

## What the commercial licence grants

- The right to use, modify and redistribute AutoGov without the AGPL's
  source-disclosure obligation.
- The right to offer scanning as a service to third parties under your own brand.
- Priority on bug reports and a say in the roadmap.

## What it does not grant

- Ownership or exclusivity.
- A warranty beyond the signed agreement.
- Support hours, unless a separate support agreement says so.

## Pricing

Set per case: internal product, service sold to third parties, number of scanned
estates. Perpetual for a fixed version, or a subscription including updates.

## Why this project is worth licensing

AutoGov finds automations nobody approved and maps which production credentials
they can reach. It records that a secret exists — never its value — and by
default refuses to send anything outside the perimeter.

That last property is the reason it exists: discovery tools that phone home are
useless in exactly the environments that need discovery most. If you are building
a commercial offering on top of it, you are building on a scanner that auditors
can be shown without an argument.

## How to ask

Open an issue titled **"Commercial licence"** in this repository. Useful to
include:

- what the scanner would be part of;
- whether third parties would be scanned or served;
- expected scale — number of estates or instances;
- jurisdiction, if data-protection rules apply.
