# AutoGov — Go-to-Market Strategy

*English · [Русская версия](GO_TO_MARKET.ru.md)*

For the founder/seller: who to sell to, how to frame value, how to package, and
how to monetize.

---

## 1. The problem in one sentence

> Employees stand up self-hosted n8n in Docker on laptops and servers, wire in
> live credentials to 1C / CRM / databases / payment APIs, and run workflows
> **without security's knowledge**. For the security team this is an invisible
> leak point with direct production access. Existing Shadow-IT tools see
> SaaS/OAuth — they **do not see locally-deployed automations**.

AutoGov is the control plane for shadow automation: **find → document → protect
→ heal**. The MVP nails the first, most tangible step — **find**.

---

## 2. Why now

- Self-hosted n8n boom: 230,000+ active users, ~$1.5B valuation (mid-2025),
  multiple-x growth of mid-market in the self-hosted segment.
- Every self-hosted instance is potential unmanaged production access.
- **No specialized governance vendor for self-hosted n8n exists** — the window
  is open, but large EDR/CNAPP vendors (CrowdStrike, Wiz, Microsoft) could
  enter. Hence: speed + a defensive moat via CIS/KZ localization.

---

## 3. Ideal Customer Profile

Companies of 200–5,000 employees whose security/IT already suspect “we have
automations running somewhere and don't know where.”

| Segment | Why they buy | Decision-maker |
|---|---|---|
| **Banks / fintech (KZ/CIS)** | Regulatory pressure (data localization), automations touching payment systems | CISO, Head of SOC |
| **Public sector / quasi-gov** | In-country storage requirement, audit | Security department |
| **Retail / e-com on 1C** | n8n integrations with 1C/CRM/payments = direct access to money and PII | IT Director, CISO |
| **MSP / outsourced SOC** | They sell monitoring; AutoGov is a new service line | Technical Director |

Non-ICP at launch: <50-person startups (no pain/budget), companies without
self-hosted automations.

---

## 4. Value proposition by role

- **CISO:** “You get a map of which unmanaged instance can reach which
  production system, prioritized by risk. This is your biggest blind spot right
  now.”
- **Head of SOC:** “Findings arrive in Wazuh/Splunk via CEF out of the box — one
  more source in your SIEM, no integration project.”
- **IT Director:** “Lightweight agent, read-only, open-source — auditable. It
  doesn't widen the attack surface (outbound-only).”
- **DPO / compliance (KZ):** “On-prem, no data leaves the perimeter, secret
  values and PII never leave the host — compliant with Law No. 94-V.”

---

## 5. Differentiation

| Who | What they do | What they DON'T (our niche) |
|---|---|---|
| Defender for Cloud Apps, Nudge, Auvik | Find SaaS/OAuth | Don't see local `localhost:5678` instances |
| EDR (CrowdStrike, etc.) | Process inventory | Don't map **automation access** to systems |
| CNAPP (Wiz) | Cloud config | Not about shadow on-prem automations |

**Two moats:**
1. **Depth on automations** — not “found an n8n process”, but “this instance has
   credentials to Kaspi Pay and 1C, reachable from the LAN, owner is an
   accountant.”
2. **KZ/CIS localization** — on-prem, in-country data, compliance with local
   law. Global players don't cover this.

**Strategy-change thresholds:** if n8n Inc./Wiz/Palo Alto ship a native “local
automation discovery,” move to a narrower vertical or double down on KZ
localization.

---

## 6. Monetization: open-core

- **Open-source (free):** the agent sensor. Removes the trust barrier (“you want
  us to install an agent with Docker-socket access — show us the code”). Drives
  distribution and community trust.
- **Paid (control plane + modules):**

| Tier | For | Includes | Price anchor* |
|---|---|---|---|
| **Community** | evaluators | agent + basic self-hosted control plane, 1 host | $0 |
| **Team** | SMB | up to N hosts, dashboard, reports, SIEM integration | subscription / host / mo |
| **Enterprise** | banks/gov | on-prem, RBAC, audit, signing, SLA, priority support | annual contract |
| **Managed / SOC** | via MSP | multi-tenant, white-label | rev-share |

\* Set real numbers after 15–20 problem interviews. Anchor value below the cost
of a **single** breach through a shadow instance.

Up-sell: once a customer sees the value of “find” (M1), sell modules **M2
HoneyNodes → M3 Self-healing → M4 Autodoc** to the same accounts.

---

## 7. Funnel and assets

1. **Lead magnet:** open-source agent + a free “Shadow Automation Scan” — a
   one-off report of “how many shadow n8n instances you have and what they can
   reach.” This is the WOW moment.
2. **Demo:** `docker compose up` shows a discovered shadow n8n with its access
   map in 2 minutes — it sells itself.
3. **Pilot (PoC):** 2–4 weeks on the customer's real perimeter; success criteria
   from spec §12 (≥95% detection, ≤5% false positives). Pilot → contract.
4. **Content:** “We scanned N companies and found X shadow instances with access
   to payment systems” — numbers sell in the security community.

---

## 8. First 90 days (validation)

- [ ] 15–20 problem interviews with DevOps/security in KZ/CIS. Ask: “Do you know
      about every automation in your infrastructure? What happens if an
      accountant stood up n8n with access to 1C?”
- [ ] Go/no-go: ≥30% report “acute pain.” Otherwise pivot to localization ideas
      with a regulatory moat.
- [ ] 1 pilot customer from the banking/security segment.
- [ ] Publish the open-source agent; collect first GitHub stars/feedback.
- [ ] Run 3–5 free scans → case studies with numbers.

---

## 9. Objection handling

| Objection | Answer |
|---|---|
| “Installing an agent with Docker-socket access is scary” | Open-source (audit it), read-only by default, signed artifacts, outbound-only |
| “We have no shadow automations” | Offer a free scan — it almost always finds some; that's the demo |
| “CrowdStrike/Wiz will add this” | Maybe, but not with access-mapping depth or KZ localization; you need it now |
| “Too expensive” | The cost of one breach through a shadow instance dwarfs the subscription |
| n8n license (SUL) | We inspect your already-deployed instances, we don't host n8n — not subject to SUL hosting limits |

---

## 10. What NOT to do at launch

- Don't build all four modules (M1–M4) at once — it dilutes focus. Sell after M1.
- Don't chase deep-tech ideas via VC; those are a different business (grant/
  partnership, long cycle).
- Don't promise automatic response/blocking in the MVP — detection and alerting
  only (active actions are a separate phase with separate risks).
