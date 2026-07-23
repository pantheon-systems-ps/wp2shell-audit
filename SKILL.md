---
name: wp2shell-audit
description: Use when auditing a Pantheon WordPress site for the wp2shell vulnerability chain (CVE-2026-60137 SQL injection + CVE-2026-63030 REST batch-confusion) — runs deterministic log/DB checks via scripts/wp2shell-audit.sh, reviews recently registered users for anomalies a fixed regex can't catch, and publishes one formatted Google Doc containing both.
---

# wp2shell Audit

## Overview

Three-stage check for wp2shell compromise on a Pantheon WordPress site. Stage 1 is a deterministic script (no LLM needed) covering nginx/PHP-error-log/DB signatures, saved to a local markdown file — it does not publish anything. Stage 2 is an LLM-judged review of recently registered user accounts for patterns the Stage 1 regex can't express. Stage 3 merges Stage 2's findings into the Stage 1 file and publishes it once, as a single formatted Google Doc.

Publishing happens only once, after both stages are done, because the doc is built via structured Docs API calls (Poppins typography, purple table headers) — not plain markdown auto-conversion. A publish-then-patch flow would mean re-uploading markdown to update the doc, which strips that formatting back out. Merge first, publish once.

## Install

Clone or copy this repo into `~/.claude/skills/wp2shell-audit/` (personal, all projects) or `<project>/.claude/skills/wp2shell-audit/` (project-scoped). Claude Code auto-discovers `SKILL.md` files in either location. You can also run the scripts directly without Claude at all — see the README.

## Prerequisites

- `terminus` CLI installed and authenticated (`terminus auth:login`), with access to the target site.
- `dig`, `rsync`, `nc`, and `ssh` (only needed for `--site` mode) — Stage 1 fetches logs directly from every appserver backing the environment, not via `terminus logs:get`/the `terminus-site-debug` plugin (that plugin rsyncs to a resolved appserver IP, but Pantheon's SSH gateway routes by hostname, so it fails outright — confirmed directly — and even when it works, reaching only one of an environment's possibly-many appservers can silently miss the incident). Not needed for `--logs` mode.
- `gws` CLI installed and authenticated — only needed for Stage 3 (publishing). Stage 1 does not require it at all — confirm Stage 3 readiness with `gws drive about get --params '{"fields":"user"}'` when you get there.
- `python3` for the doc generator (`scripts/lib/generate_google_doc.py`, bundled in this repo — no external framework needed) — same Stage-3-only scope as `gws`.

## Stage 1 — deterministic audit

Run:
```
./scripts/wp2shell-audit.sh --site SITE.ENV
```

Pulls logs directly from every appserver backing the environment, runs nginx/PHP-error-log/DB checks (`batch/v1` traffic, `author_exclude` SQLi payloads — including the `author.exclude`/`author exclude` WAF-evasion spellings, nested privileged REST writes via batch (GET-based only), SQLi errors, forged `customize_changeset` rows in any status, forged `nav_menu_item` rows, `postmeta` rows referencing `example.invalid`, invalid `post_status` rows, `<prefix>_<hex>`-style usernames), and writes the findings to a local markdown file. It does **not** publish — that's Stage 3, after Stage 2's findings are merged in.

Output includes:
- A `[FLAG]`/`[ ok ]` line per check
- `Report saved to: /path/to/wp2shell-report-<pid>-<timestamp>.md` — capture this path, Stage 3 edits this exact file
- A block labeled `== Recent user accounts for anomaly review ==`: the site's 100 most recently registered users (`ID, user_login, user_email, user_registered, display_name`)
- A block labeled `== Administrator-role accounts for anomaly review ==`: every account holding the administrator role, by registration date — check these first, a nonzero count is normal (every site has admins), it's a priority list, not a flag

## Stage 2 — user-account anomaly review

Check the `== Administrator-role accounts for anomaly review ==` block first — a planted admin account is the highest-value target for this pattern of attack. Then read the `== Recent user accounts for anomaly review ==` block. Look for accounts that break the pattern of the rest of the list:

- `user_login` that looks auto-generated — random hex/alphanumeric, no relation to a real name
- `user_email` mismatched with `user_login`, or on a disposable/throwaway-mail domain
- A cluster of `user_registered` timestamps close together that doesn't match the site's normal onboarding cadence
- Anything registered on or near a known incident or CVE-disclosure date

State which specific pattern a flagged account breaks — don't flag on a hunch. Most accounts on most sites will be normal; expect to flag few or none most of the time.

**Calibration — match this register, not more, not less:**

> `142:jsmith2024:jsmith2024@gmail.com:2026-03-11` — normal: name-derived login, plausible address, unremarkable date.
> `98:x7f2a9b1c4d:x7f2a9b1c4d@mailinator.com:2026-07-21` — flagged: login is a bare hex string with no name relation, email domain is a known disposable-mail provider, and the registration date lands the same day as this audit.

A `user_login`/`display_name` matching the `<prefix>_<hex>` regex is not automatically suspicious on its own — apply the same three criteria above before flagging it, not the raw regex match. A real-name-derived login with a random suffix (e.g. `janedoe_a1b2c3`), a real consumer email domain (gmail/yahoo/outlook, not disposable), registration spread across months rather than clustered, and no administrator role — that's a normal auto-generated customer/membership username from an e-commerce or membership plugin, not a throwaway admin account. Confirmed directly: a site's own "suspicious usernames" regex match turned out to be exactly this — 16 real-looking customer accounts, non-admin, registered across 5 months, on real email providers.

## Stage 2b — post_status breakdown review (only if invalid `post_status` is non-zero)

If Section 4's `wp_posts` with invalid `post_status` count is non-zero, check the `== post_status breakdown for anomaly review ==` block (also printed to stdout, not written to the report — distinct status values with row counts, not per-row IDs) against the `== active plugins for post_status cross-reference ==` block printed right after it, before treating it as compromise:

- **Match the status prefix/name to an actual active plugin in that list, don't just judge the naming "plausible."** A status like `fgf_automatic` is meaningless on its own — check whether an active plugin's name/slug corresponds to that prefix (e.g. a plugin literally named or abbreviating to "fgf") and name that specific plugin in your write-up if so. "Looks like it could be a plugin" without checking the actual list is a guess, not a finding.
- A status that matches an active plugin, covering many rows (dozens to hundreds of thousands) — that plugin's own post type or workflow. Not evidence of compromise.
- A status with **no corresponding active plugin**, especially on exactly one or two rows, or one that looks like random/injected text — the suspicious case. Note explicitly that no installed plugin explains it.

**Calibration:**

> `wc-partial-refund: 340, wc-backorder: 12`, active plugins include `woocommerce` — normal: matches an actually-installed plugin, meaningful row counts across real store data.
> `xk29_temp: 1`, no plugin in the active list corresponds to `xk29` — flagged: single row, nothing installed explains this status.

State which specific plugin (or its absence) a status corresponds to — don't flag or clear on a hunch. Confirmed directly: a real WooCommerce site's `wc-completed` status alone accounted for 224,000+ of a 231,501-row false positive before this whitelist/review step existed.

## Stage 3 — merge findings and publish once

The findings belong inside **Section 4 (Database Analysis)**, directly after the "Suspicious usernames found" line (and after the assessment paragraph if there's no separate "sus users" list, e.g. on a clean site) — not tacked onto the end of the document.

1. Edit the Stage 1 markdown file directly (the path Stage 1 printed) — insert a `**User Account Anomaly Review:**` block (no parenthetical — keep the header plain) with your Stage 2 findings, and, if Stage 2b applied, a `**Post-Status Anomaly Review:**` block with those findings, right after the "Suspicious usernames found" line in Section 4, before that section's closing `**Assessment:**` paragraph.
2. Publish it once:
   ```
   python3 scripts/lib/generate_google_doc.py \
     --input /path/to/wp2shell-report-<pid>-<timestamp>.md \
     --title "wp2shell Security Audit — SITE.ENV (YYYY-MM-DD)" \
     --delete-after
   ```
   Match `--title` to what Stage 1 would have used (`wp2shell Security Audit — <site or log dir> (<today's date>)`). The script prints the finished doc's URL — share that with the requester. `--delete-after` removes the local markdown file itself once the doc is confirmed created, so no staging file is left behind on whoever's machine ran this.

This produces exactly one doc per audit, containing both stages, with no local file left over and no separate re-upload/patch step to strip the formatting back out.

## Notes

- Keep Stage 2's findings visibly separate from Stage 1's — never use "confirmed" language for a judgment call the way Stage 1 does for the invalid-`post_status`/SQLi/forged-changeset checks.
- Stage 1 alone is fully automated and needs no LLM in the loop, but no longer publishes on its own — Stage 3 is what puts a doc in front of anyone. Stages 2–3 require an agent — Claude or a person — actually reading the output; they don't run unattended.
- The generator does not share the doc with anyone — it's private to whoever's `gws` credentials created it. Share it yourself once it's published.
- There is no cover page or logo in the generated doc by design.
