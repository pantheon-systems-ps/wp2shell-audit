# wp2shell-audit

[![Unofficial Support](https://img.shields.io/badge/Pantheon-Unofficial_Support-yellow?logo=pantheon&color=FFDC28)](https://docs.pantheon.io/oss-support-levels#unofficial-support)

Audit a Pantheon-hosted WordPress site for the wp2shell vulnerability chain (CVE-2026-60137 unauthenticated SQL injection + CVE-2026-63030 REST `batch/v1` route-confusion). Read-only — this checks for compromise, it does not remediate anything.

Works three ways:
- **As a Claude Code skill** — an agent runs the deterministic checks and reviews recently registered user accounts for anomalies a fixed regex can't catch, saving findings to markdown (or printing them to the terminal). It only publishes a Google Doc if you actually ask for one.
- **Standalone, no Claude required** — run the script directly for the deterministic checks (logs + database), either printed to your terminal or saved to a local markdown file (your choice).
- **By hand, no script at all** — see [`docs/self-audit-guide.md`](docs/self-audit-guide.md) for the same checks done manually via WP-Admin and copy-pasteable Terminus commands.

## Prerequisites

- [`terminus`](https://docs.pantheon.io/terminus/install) installed and authenticated (`terminus auth:login`), with access to the target site.
- `dig`, `rsync`, `nc`, and `ssh` — used to fetch logs directly from every appserver backing the environment when running with `--site` (the normal way this is used). Not needed if you're running against already-downloaded logs via `--logs` instead. `--site` checks for all four up front and tells you exactly which are missing rather than failing with a confusing DNS error. Minimal Docker/Lando dev containers commonly lack `dig`/`nc` specifically — on Debian/Ubuntu-based ones: `apt-get install -y dnsutils rsync netcat-openbsd openssh-client`. In a Lando project, add that as a `build_as_root` step in `.lando.yml` so it survives `lando rebuild` (a one-off `lando ssh -u root -c "apt-get install ..."` does not):
  ```yaml
  services:
    appserver:
      build_as_root:
        - apt-get update -y
        - apt-get install -y dnsutils rsync netcat-openbsd openssh-client
  ```
- [`gws`](https://github.com/googleworkspace/cli) installed and authenticated — **only if** you want to publish a Google Doc (`--gws`). The audit itself never requires it and doesn't check for it unless you pass `--gws`.
- `python3` (only needed for publishing — see above).
- `bash`, standard Unix tools (`grep`, `awk`, `gzip`, etc.).

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

or, if the site is a WordPress Multisite (WPMS) install, add `--multisite` to check every subsite, not just the main one:

```
./scripts/wp2shell-audit.sh --site SITE.ENV --multisite --output /path/to/dir
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
- **Database** (requires `--wp`/`--site`): posts with an invalid `post_status` (the whitelist includes WooCommerce's standard order statuses, since those can cover hundreds of thousands of legitimate rows on an active store; a `post_status` breakdown block is printed for anything else non-standard, for a judgment call rather than an automatic flag), forged `customize_changeset` rows (any status), forged `nav_menu_item` rows, `postmeta` rows referencing `example.invalid`, orphaned `usermeta` rows, `<prefix>_<hex>`-style throwaway-admin usernames, and a full list of administrator-role accounts by registration date (for prioritizing the anomaly review).

The database checks are the highest-confidence signal — none of them depend on log retention or debug-logging configuration, and WordPress cannot produce these specific results through normal operation. Standard nginx access logs never capture POST body content, so any of the above sent entirely inside a POST body (rather than the URL/query string) is invisible to the nginx-log checks — that's a data-source limit, not a gap a different grep would close.

### WordPress Multisite (WPMS)

By default, only the main site (blog ID 1) gets checked — a multisite install's other subsites have their own separate tables (`wp_<blog_id>_posts`, etc., WordPress's own per-site convention) that are silently skipped entirely, not just under-reported. Pass `--multisite` to check every subsite:

- The four post/postmeta-based checks above (invalid `post_status`, forged `customize_changeset`/`nav_menu_item` rows, `postmeta` referencing `example.invalid`) run against every subsite's own tables, not just the main site's. Row IDs are tagged `blog<ID>:<row-ID>`, since post IDs restart per subsite and aren't meaningful without knowing which subsite's table they came from.
- The administrator-role listing covers every subsite's own capability key, not just the main site's — a subsite-only admin is otherwise invisible.
- A new check: network **Super Admin** accounts (`wp_sitemeta`'s `site_admins` option) — full control over every subsite on the network, the single highest-value target on a compromised multisite. This has no single-site equivalent; it's only checked with `--multisite`.

`--multisite` costs one extra WP-CLI call (`wp site list`) to enumerate subsites. If it turns out the site isn't actually multisite after all, the script falls back to single-site behavior with a warning rather than failing — safe to pass whenever you're not sure.

### Reliability on a noisy wp-config.php

Some sites' `wp-config.php` prints a PHP warning/notice to stdout on every single WP-CLI bootstrap — most commonly custom multisite domain-mapping code that reads `$_SERVER['HTTP_HOST']` (or similar) without an `isset()` check, which has no meaning in a CLI context. Left unhandled, that text can land inside the table prefix or a query result and corrupt the SQL sent to the database.

This is handled, not just detected:
- **Table prefix / multisite blog-ID resolution**: noise lines are stripped out and the real value (even a non-standard prefix like `wp_xfpfyq561c`) is recovered from what's left. Only if nothing usable survives does it fall back to a hardcoded default (`wp_` / single-site), with a `WARNING:` explaining why.
- **Every other DB check**: if a query's output still looks contaminated after that, the result is treated as `0, unknown` — not silently counted as `0, confirmed clean`. A `WARNING: query for '<check>' failed or produced a PHP warning/notice` line is printed (stdout/terminal) identifying exactly which check, immediately followed by a `Spot-check manually: <exact wp-cli command>` line — the same query, ready to paste and re-run by hand to confirm the true answer wasn't silently swallowed.
- **The saved report**: since a saved `--output` file (or a published Google Doc) only ever shows the numeric count — indistinguishable from a real zero — Section 5 (Confidence Assessment) gets an explicit callout whenever any check was affected, so this is visible even to someone who never saw the original terminal output.

## Scope

This is audit-only. It does not delete, patch, or remediate anything on the target site.

## License

[MIT](LICENSE) — fork it, modify it, adapt it to your own environment as needed.
