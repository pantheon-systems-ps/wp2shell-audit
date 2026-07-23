# wp2shell-audit

[![Unofficial Support](https://img.shields.io/badge/Pantheon-Unofficial_Support-yellow?logo=pantheon&color=FFDC28)](https://docs.pantheon.io/oss-support-levels#unofficial-support)

Audit a Pantheon-hosted WordPress site for the wp2shell vulnerability chain (CVE-2026-60137 unauthenticated SQL injection + CVE-2026-63030 REST `batch/v1` route-confusion). Read-only — this checks for compromise, it does not remediate anything.

Works three ways:
- **As a Claude Code skill** — an agent runs the deterministic checks and reviews recently registered user accounts for anomalies a fixed regex can't catch, saving findings to markdown (or printing them to the terminal). It only publishes a Google Doc if you actually ask for one.
- **Standalone, no Claude required** — run the script directly for the deterministic checks (logs + database), either printed to your terminal or saved to a local markdown file (your choice).
- **By hand, no script at all** — see [`docs/self-audit-guide.md`](docs/self-audit-guide.md) for the same checks done manually via WP-Admin and copy-pasteable Terminus commands.

## Prerequisites

- [`terminus`](https://docs.pantheon.io/terminus/install) installed and authenticated (`terminus auth:login`), with access to the target site.
- `dig`, `rsync`, `nc`, and `ssh` (only needed for `--site` mode) — used to fetch logs directly from every appserver backing the environment. **Not** `terminus logs:get`/the `terminus-site-debug` plugin: that plugin rsyncs straight to a resolved appserver IP, but Pantheon's SSH gateway routes by hostname, so it fails outright (confirmed directly: exit 255 on every attempt) — and even when it does work, an environment can be backed by many appserver containers at once (confirmed directly: one real site resolved to 16), each with a different slice of traffic and log-rotation history, so reaching only one can silently miss the actual incident. Not needed for `--logs` mode (already-downloaded logs).
- [`gws`](https://github.com/googleworkspace/cli) installed and authenticated — **only if** you want to publish a Google Doc (`--gws`). The audit itself never requires it and doesn't check for it unless you pass `--gws`.
- `python3` (only needed for publishing — see above).
- `bash`, standard Unix tools (`grep`, `awk`, `gzip`, etc.) — nothing exotic.

## Option A: Use it as a Claude Code skill

Clone this repo into your Claude Code skills directory:

```
git clone <this-repo-url> ~/.claude/skills/wp2shell-audit
```

(Use `<project>/.claude/skills/wp2shell-audit` instead for a project-scoped install.)

Claude Code auto-discovers `SKILL.md` in that location. Start a session and ask it to run a wp2shell audit against a site — it'll run the deterministic script, review recent user accounts for anomalies, and ask you where to save the report if you haven't said. It only publishes a Google Doc if you explicitly ask for one.

## Option B: Run the script yourself, no Claude involved

```
./scripts/wp2shell-audit.sh --site SITE.ENV --output /path/to/dir
```

or, for terminal-only output with no file saved:

```
./scripts/wp2shell-audit.sh --site SITE.ENV --stdout
```

or, against logs you've already downloaded:

```
./scripts/wp2shell-audit.sh --logs /path/to/log/dir --wp "terminus wp SITE.ENV --" --output /path/to/dir
```

This runs every deterministic check (nginx access log, PHP error log, and — if `--wp`/`--site` is given — direct database queries), prints a `[FLAG]`/`[ ok ]` line per check, and either saves the full findings to a markdown file in the directory you gave `--output`, or prints them straight to the terminal with `--stdout`. One of `--output`/`--stdout` is required — there's no default location. It does not publish anywhere and never requires `gws` unless you ask for it. To publish as a Google Doc, add `--gws` to the same command (requires `gws` installed and authenticated), or run the generator yourself afterward against a saved report:

```
python3 scripts/lib/generate_google_doc.py --input /path/to/report.md --title "Your Title"
```

The user-account anomaly review (Stage 2 in `SKILL.md`) is a judgment call across ambiguous patterns (auto-generated-looking usernames, mismatched emails, suspicious registration clusters) — that part genuinely benefits from an LLM or a human reading the `== Recent user accounts for anomaly review ==` block that Stage 1 prints. Running standalone just means you do that part yourself, or skip it.

## What's in this repo

```
SKILL.md                          Claude Code skill definition
docs/
  self-audit-guide.md              Same checks, done by hand — no script, no Claude
scripts/
  wp2shell-audit.sh                Stage 1 — deterministic log/DB checks (no LLM needed)
  lib/
    generate_google_doc.py         Formats a markdown report as a Google Doc (Poppins typography,
                                    purple table headers, health-indicator cell coloring)
```

## What it checks for

- **Nginx access log**: `batch/v1` REST route hits, `author_exclude` SQLi payloads (non-numeric values, including the `author.exclude`/`author exclude` WAF-evasion spellings), nested privileged REST writes via batch — e.g. `wp/v2/users`/`wp/v2/plugins` co-occurring with `batch/v1` (GET-based variant only), `wp-admin` plugin-upload POSTs, `delete_user=` calls, a wp-login IP-hop heuristic, WordPress self-request UA/version fingerprinting, non-browser version-fingerprint requests.
- **PHP error log** (requires `WP_DEBUG_LOG`-style verbose logging to have been on at the time): `author__not_in` SQL injection errors, nested REST dispatch signature, changeset-publish pipeline stall marker.
- **Database** (requires `--wp`/`--site`): posts with an invalid `post_status` (whitelist includes WooCommerce's standard order statuses — confirmed directly that without this, an active store's legitimate orders produce a large false positive; a `post_status` breakdown block is printed for anything else non-standard, for a judgment call rather than an automatic flag), forged `customize_changeset` rows (any status), forged `nav_menu_item` rows, `postmeta` rows referencing `example.invalid`, orphaned `usermeta` rows, `<prefix>_<hex>`-style throwaway-admin usernames, and a full list of administrator-role accounts by registration date (for prioritizing the anomaly review).

The database checks are the highest-confidence signal — none of them depend on log retention or debug-logging configuration, and WordPress cannot produce these specific results through normal operation. Standard nginx access logs never capture POST body content, so any of the above sent entirely inside a POST body (rather than the URL/query string) is invisible to the nginx-log checks — that's a data-source limit, not a gap a different grep would close.

## Scope

This is audit-only. It does not delete, patch, or remediate anything on the target site.
