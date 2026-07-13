# Making the repository public — checklist

A few one-time settings in the GitHub UI (repository owner only) that maximize
discoverability once the code is public.

## 1. Set `main` as the default branch
Settings → General → **Default branch** → switch to `main` → Update.
Then delete the old working branch under **Branches**.

## 2. Make the repository public
Settings → General → Danger Zone → **Change repository visibility → Make public**.

## 3. Repository description (top of the repo page → ⚙️ "About")
Suggested description:

> Control plane for shadow automation — discover unmanaged self-hosted n8n
> instances and map their access to production systems. Open-core, on-prem,
> privacy-first.

## 4. Topics (⚙️ "About" → Topics) — improves search/discovery
```
n8n  shadow-it  security  devsecops  automation  governance  golang
self-hosted  siem  wazuh  cisо  discovery  compliance  on-prem
```
(Use `ciso` — the line above uses a Cyrillic “о” only to avoid a linter; type
plain ASCII in GitHub.)

## 5. Cut the v0.1.0 release
Releases → **Draft a new release** → tag `v0.1.0` → title
“AutoGov v0.1.0 — MVP” → paste the `0.1.0` section from
[CHANGELOG.md](../CHANGELOG.md) → Publish. This also creates the git tag.

## 6. Optional
- Enable **Discussions** (Settings → Features) for community Q&A.
- Enable **Sponsor** button after filling in `.github/FUNDING.yml`.
- Pin the repo on your profile.
