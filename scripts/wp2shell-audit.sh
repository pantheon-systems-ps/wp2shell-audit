#!/usr/bin/env bash
# wp2shell-audit.sh — checks a site's logs and DB for the IOCs confirmed
# during a prior wp2shell (CVE-2026-60137 / CVE-2026-63030) incident
# investigation, and writes the full findings to a local markdown file.
# Read-only — see wp2shell-cleanup.sh for the destructive follow-up.
#
# No file-integrity/checksum checks: Pantheon's immutable container
# architecture means this class of exploit can't achieve persistent code
# tampering the way it could on a mutable host, so that work isn't run.
#
# Usage:
#   ./wp2shell-audit.sh --site SITE.ENV --output /path/to/dir
#   ./wp2shell-audit.sh --logs /path/to/log/dir --wp "wp" --output /path/to/dir
#   ./wp2shell-audit.sh --site SITE.ENV --stdout
#
# --site    Fetches logs directly (rsync over SSH) from EVERY appserver
#           backing SITE.ENV, and runs DB checks via `terminus wp SITE.ENV
#           --`. Requires Terminus auth already set up, plus `dig`, `rsync`,
#           `nc`, and `ssh` — standard tools, no Terminus plugin needed.
#           Does NOT use terminus-site-debug's `logs:get` — that plugin
#           rsyncs directly to a resolved appserver IP, but Pantheon's SSH
#           gateway routes by hostname, so that connection has been observed
#           to fail outright (confirmed directly: exit 255 on every retry,
#           against a real site) regardless of host-key trust. An
#           environment can also be backed by many appserver containers at
#           once (confirmed directly: one real site resolved to 16 distinct
#           IPs), each holding a different slice of traffic and log-rotation
#           history — fetching from only one, whichever happens to answer,
#           can silently miss the actual incident. This resolves every
#           backing appserver IP and fetches from each into its own
#           subdirectory; if some (not all) fail, the run proceeds on what
#           it has and says so explicitly in the report's Confidence
#           Assessment section, rather than either blocking entirely or
#           silently under-covering.
# --logs    Directory of already-downloaded logs (skips the fetch above).
# --wp      WP-CLI invocation prefix, for use with --logs. Omit to skip DB
#           checks (log-only run).
# --output  Directory to save the markdown report into. Required unless
#           --stdout is given instead.
# --stdout  Skip saving a report file — print the full findings to the
#           terminal instead. Mutually exclusive with --output.
# --gws     Optional. After the report is built, also publish it as a
#           Google Doc via lib/generate_google_doc.py (Poppins typography,
#           purple table headers — no cover page or logo). Requires `gws`
#           installed and authenticated — run
#           `gws drive about get --params '{"fields":"user"}'` once to
#           confirm. Requires --output (there must be a saved file to
#           upload). The doc is private to whoever's `gws` credentials
#           created it — nothing is shared automatically. Omit this flag
#           entirely (the default) and the audit runs fully without gws —
#           it is never required just to run the audit.
# --multisite  Opt-in only — without it, behavior is unchanged (single
#           implicit site, no extra WP-CLI calls). With it, requires --wp/
#           --site: enumerates every subsite via `wp site list` and runs
#           the four post/postmeta-based DB checks against EACH subsite's
#           own tables (WordPress's per-site table convention — blog 1 is
#           unprefixed, e.g. `wp_posts`; every other blog ID is
#           `<prefix><blog_id>_posts`, confirmed directly against a real
#           multisite install), tags findings by blog ID, and adds two
#           multisite-only checks: administrators on ANY subsite (not just
#           the main site), and network Super Admins (`wp_sitemeta`'s
#           `site_admins` option — full control over every subsite, the
#           highest-value target on a compromised network). Without this
#           flag, a multisite install only ever gets its main site (blog 1)
#           checked — every subsite's own tables are silently skipped.
#
# Also prints (not included in the report) the site's 100 most recently
# registered users, plus a separate list of every administrator-role
# account by registration date, for the anomaly-review pass described in
# SKILL.md — the <prefix>_<hex> regex above only catches one specific
# naming convention; that pass is the broader net, and the admin-role list
# is what to check first.

set -euo pipefail

# Report is written next to this script (not /tmp) since that's also where
# --logs paths and the doc generator script live, keeping everything local
# to one predictable directory.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

LOG_DIR=""
WP_CLI=""
SITE=""
CLEANUP_TMP=""
MD_FILE=""
OUTPUT_DIR=""
STDOUT_ONLY=0
DO_GWS=0
MULTISITE=0

# Only cleans up the terminus logs tempdir — MD_FILE is Stage 1's actual
# deliverable now (SKILL.md Stage 2/3 read and edit it before publishing),
# so it must survive past this script's exit, not get wiped on the way out.
cleanup() {
  # A bare `[[ ... ]] && rm ...` here would make cleanup()'s own exit status
  # (false, i.e. 1) leak out as the trap's status whenever CLEANUP_TMP is
  # unset (every --logs run) — which silently overrides the script's real
  # `exit 0`/`exit 2` with 1. Confirmed directly: every --logs invocation
  # exited 1 regardless of findings until this was an if-block instead.
  if [[ -n "$CLEANUP_TMP" ]]; then
    rm -rf "$CLEANUP_TMP"
  fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --site)   SITE="$2"; shift 2 ;;
    --logs)   LOG_DIR="$2"; shift 2 ;;
    --wp)     WP_CLI="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --stdout) STDOUT_ONLY=1; shift ;;
    --gws)    DO_GWS=1; shift ;;
    --multisite) MULTISITE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" && "$STDOUT_ONLY" -eq 0 ]]; then
  echo "Error: specify where to save the report — pass --output /path/to/dir, or --stdout to print findings to the terminal only (no file saved)." >&2
  exit 1
fi
if [[ -n "$OUTPUT_DIR" && "$STDOUT_ONLY" -eq 1 ]]; then
  echo "Error: --output and --stdout are mutually exclusive — pick one." >&2
  exit 1
fi
if [[ "$DO_GWS" -eq 1 && "$STDOUT_ONLY" -eq 1 ]]; then
  echo "Error: --gws needs a saved report file to publish — use --output instead of --stdout." >&2
  exit 1
fi

# An environment is backed by however many appserver containers Pantheon
# has provisioned for it — confirmed directly against a real site: its
# appserver hostname resolved to 16 distinct IPs, each holding a DIFFERENT
# slice of traffic and log-rotation history (different byte sizes, same
# rotation date). Fetching from only one appserver — whichever happens to
# answer — can silently miss the actual incident if it landed on a
# container this run didn't reach; there is no way to tell from the output
# alone that anything was missed.
#
# This does NOT use terminus-site-debug's `logs:get` (a plugin, not stock
# Terminus). That plugin rsyncs directly to a resolved appserver IP, but
# Pantheon's SSH gateway routes by hostname — confirmed directly, against a
# real site, that every such attempt fails with exit 255 regardless of
# retries. The working pattern is hostname-based SSH auth with the TCP
# connection pinned to a specific IP via a ProxyCommand — this fetches from
# EVERY resolved appserver IP this way, into its own subdirectory.
# access_stream()/error_log() below already recurse the whole log directory
# by filename pattern (not a fixed path), so nothing else needs to change
# to pick up every appserver's logs once they're all fetched here.
#
# Requires: dig, rsync, nc, ssh — standard tools, no Terminus plugin. Minimal
# Docker/Lando dev containers commonly lack dig and nc specifically (rsync
# and ssh are more often already present) — confirmed directly: a stock
# Lando appserver container had neither. Without this check, a missing `dig`
# makes the lookup below fail silently (empty output, stderr suppressed) and
# produces the exact same "No appserver DNS records found" message as a
# genuinely missing environment — misleading, since the site/environment is
# actually fine. Check up front so the real problem is reported plainly.
fetch_all_appserver_logs() {
  local site_name="$1" site_env="$2" dest="$3"
  local uuid host ips ip ok=0 failed=0
  local missing=()

  for tool in dig rsync nc ssh; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing required tool(s) for --site mode: ${missing[*]}." >&2
    echo "This is common in minimal Docker/Lando dev containers. Install them and retry — e.g. on Debian/Ubuntu-based containers:" >&2
    echo "  apt-get update && apt-get install -y dnsutils rsync netcat-openbsd openssh-client" >&2
    echo "For Lando specifically, add a build_as_root step to .lando.yml (a one-off apt-get inside the container won't survive a rebuild) — see README." >&2
    return 1
  fi

  uuid=$(terminus site:info "$site_name" --field=id 2>/dev/null)
  if [[ -z "$uuid" ]]; then
    echo "Could not resolve site UUID for '$site_name' via terminus site:info." >&2
    return 1
  fi

  host="appserver.${site_env}.${uuid}.drush.in"
  ips=$(dig +short "$host" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
  if [[ -z "$ips" ]]; then
    echo "No appserver DNS records found for ${site_name}.${site_env} (${host}) — environment may not exist or isn't provisioned." >&2
    return 1
  fi

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    ssh-keyscan -p 2222 -H "$ip" >> ~/.ssh/known_hosts 2>/dev/null
    mkdir -p "${dest}/appserver-${ip}"
    if rsync -rlz -e "ssh -p 2222 -o ProxyCommand='nc ${ip} 2222' -o StrictHostKeyChecking=accept-new" \
        "${site_env}.${uuid}@${host}:logs/" "${dest}/appserver-${ip}/" >&2 2>&1; then
      ok=$((ok + 1))
    else
      failed=$((failed + 1))
      echo "  [warn] appserver ${ip}: rsync failed — this appserver's logs are MISSING from this audit, not counted as clean" >&2
    fi
  done <<< "$ips"

  APPSERVERS_REACHED=$ok
  APPSERVERS_TOTAL=$((ok + failed))
  echo "Fetched logs from ${ok}/${APPSERVERS_TOTAL} appserver(s) for ${site_name}.${site_env}." >&2
  [[ "$ok" -gt 0 ]] && return 0 || return 1
}

APPSERVERS_REACHED=0
APPSERVERS_TOTAL=0

if [[ -n "$SITE" ]]; then
  SITE_NAME="${SITE%.*}"
  SITE_ENV="${SITE##*.}"
  CLEANUP_TMP=$(mktemp -d)
  echo "Fetching logs for $SITE from every backing appserver ..." >&2
  if ! fetch_all_appserver_logs "$SITE_NAME" "$SITE_ENV" "$CLEANUP_TMP"; then
    echo "Could not fetch logs from any appserver for $SITE — see output above." >&2
    exit 1
  fi
  LOG_DIR="$CLEANUP_TMP"
  WP_CLI="terminus wp $SITE --"
fi

if [[ -z "$LOG_DIR" || ! -d "$LOG_DIR" ]]; then
  echo "Usage: $0 (--site SITE.ENV | --logs /path/to/log/dir [--wp \"wp-cli invocation\"]) (--output /path/to/dir | --stdout) [--gws]" >&2
  exit 1
fi

pass=0
flag=0

strip_ansi() {
  # WP-CLI/Terminus color output embeds raw ANSI escapes; the Google Docs
  # API returns a bare 500 if any survive into the uploaded content.
  sed -E $'s/\x1b\\[[0-9;]*[a-zA-Z]//g'
}

# A DB query that legitimately finds nothing returns empty output. A query
# that FAILS instead (bad table-prefix resolution, a stray PHP notice/
# warning corrupting the SQL) has also been observed to produce non-empty
# output — WP-CLI's own Error:/Warning:/Notice: text — even with --silent
# and 2>/dev/null (confirmed directly: that text prints to stdout, not
# stderr, so neither suppresses it). Naively counting lines of output as
# "rows found" then misreads a failed query as a compromise signal —
# confirmed directly against real sites, where this made every one of the
# six high-confidence checks fire identically from a single underlying
# failure, not six independent findings.
is_query_failure() {
  printf '%s' "$1" | strip_ansi | grep -qE '(Error:|Warning:|Notice:|Fatal error:|Deprecated:)'
}

# Returns $1 unchanged if it looks like real data, or nothing (plus a
# stderr warning) if it looks like a failed query — callers should treat an
# empty result as "0, unknown" rather than "0, confirmed clean" (the
# warning printed here is what makes that distinction visible).
sanitize_query_result() {
  local raw="$1" label="$2"
  if is_query_failure "$raw"; then
    echo "WARNING: query for '$label' failed or produced a PHP warning/notice — treating as unknown (0), NOT counted as evidence. First line: $(printf '%s' "$raw" | strip_ansi | grep -m1 .)" >&2
    return
  fi
  printf '%s' "$raw"
}

report() {
  local label="$1" count="$2"
  shift 2
  if [[ "$count" -gt 0 ]]; then
    printf '[FLAG] %-45s %s\n' "$label" "$count"
    [[ $# -gt 0 ]] && printf '       %s\n' "$@"
    ((flag++)) || true
  else
    printf '[ ok ] %-45s %s\n' "$label" "$count"
    ((pass++)) || true
  fi
}

md_list() {
  # Renders args as a markdown bullet list, or "(none)" if empty.
  if [[ $# -eq 0 ]]; then
    echo "(none)"
  else
    printf -- '- `%s`\n' "$@"
  fi
}

# WordPress's own per-site table convention: blog 1 (the main site) uses
# unprefixed tables (e.g. wp_posts); every other blog ID gets its own
# infixed set (wp_<blog_id>_posts) — confirmed directly against a real
# multisite install.
blog_table() {
  local blog_id="$1" base="$2"
  if [[ "$blog_id" == "1" ]]; then
    echo "${TBL_PREFIX}${base}"
  else
    echo "${TBL_PREFIX}${blog_id}_${base}"
  fi
}

# Runs $3 (a query containing the literal token __TABLE__) once per blog ID
# in $BLOG_IDS, substituting each blog's own table name in turn, and
# accumulates a total count (MS_COUNT) plus a combined, blog-tagged row
# list (MS_LIST) — tags are only added when --multisite was actually given,
# so a default (non-multisite) run's output is byte-identical to a single
# direct query against $T_POSTS/etc. No `local -n` here: stock macOS bash
# (3.2.57) has no namerefs, so results are returned via these two globals
# by convention rather than a generic return value.
run_ms_check() {
  local label="$1" base_table="$2" query_tmpl="$3"
  local blog_id table query raw sanitized n_b tagged
  MS_COUNT=0
  MS_LIST=""
  for blog_id in $BLOG_IDS; do
    table=$(blog_table "$blog_id" "$base_table")
    query="${query_tmpl//__TABLE__/$table}"
    raw=$($WP_CLI db query --silent "$query" --skip-plugins --skip-themes 2>/dev/null || true)
    sanitized=$(sanitize_query_result "$raw" "$label (blog $blog_id)")
    n_b=$(printf '%s' "$sanitized" | grep -c . || true)
    if [[ "$n_b" -gt 0 ]]; then
      if [[ "$MULTISITE" -eq 1 ]]; then
        tagged=$(printf '%s\n' "$sanitized" | sed "s/^/blog${blog_id}:/")
      else
        tagged="$sanitized"
      fi
      MS_LIST="${MS_LIST}${MS_LIST:+$'\n'}${tagged}"
    fi
    MS_COUNT=$((MS_COUNT + n_b))
  done
}

# Recursive: fetch_all_appserver_logs lands each appserver's logs in its
# own appserver-<ip>/ subdirectory, so this has to search rather than
# assume a single fixed path — which is also exactly what makes multi-
# appserver coverage transparent to these two functions: every appserver
# that was fetched just gets swept up the same way.
#
# gzip -dc, not zcat: on stock macOS (no Homebrew gzip shadowing the
# system binary), zcat expects .Z (compress-format) input, not .gz —
# confirmed directly: it silently failed on every rotated .gz archive,
# so a run only ever scanned the current, unrotated logs and could
# report Section 2 as clean while missing the actual attack traffic in
# rotated history. gzip -dc handles .gz correctly on both macOS and
# Linux.
access_stream() {
  find "$LOG_DIR" -name 'nginx-access.log*' 2>/dev/null | sort | while read -r f; do
    case "$f" in
      *.gz) gzip -dc "$f" ;;
      *)    cat "$f" ;;
    esac
  done
}

error_log() {
  find "$LOG_DIR" -name 'php-error.log*' 2>/dev/null | while read -r f; do
    case "$f" in
      *.gz) gzip -dc "$f" ;;
      *)    cat "$f" ;;
    esac
  done
}

# --- Exploit-attempt timeline scan ----------------------------------------
# Single pass over the access stream computing first|last|count for three
# buckets, so the timeline does not multiply the script's gzip-decompression
# cost (re-streaming the rotated logs once per check is the dominant expense):
#   ATTEMPT — payload-shaped signatures only: non-numeric author_exclude
#             values, nested privileged writes inside a batch request, and
#             wp-admin plugin-upload POSTs. This is what feeds the
#             backup-restore-point boundary.
#   BATCH   — raw batch/v1 hits. Reported separately and NOT folded into the
#             boundary: this route is dominated by legitimate REST/Jetpack/
#             mobile traffic (thousands of benign hits spanning months on a
#             real site), so its earliest timestamp is not an attack marker.
#   LOG     — overall access-log span, for the log-retention caveat.
# Timestamps are UTC (Pantheon nginx logs are UTC — no tz conversion). The
# sort key is numeric yyyymmddHHMMSS because the raw dd/Mon/yyyy token is not
# lexically sortable. BSD/macOS awk only — no gawk-specific gensub/IGNORECASE.
# The author_exclude value is read from the original line up to the next
# & / quote / space, then tested for non-numeric content (a legitimate
# author_exclude=1,2,3 — %2c/%2C being the URL-encoded comma — is skipped),
# mirroring the count check's own numeric exclusion.
attempt_scan() {
  awk '
    function upd(b,key,disp){ if(!(b in cnt)||key<mnk[b]){mnk[b]=key;mnd[b]=disp}
                              if(!(b in cnt)||key>mxk[b]){mxk[b]=key;mxd[b]=disp}; cnt[b]++ }
    BEGIN{ split("jan feb mar apr may jun jul aug sep oct nov dec",M," ");
           for(i=1;i<=12;i++) mn[M[i]]=sprintf("%02d",i) }
    { ts=$4; sub(/^\[/,"",ts); mo=tolower(substr(ts,4,3)); if(mn[mo]=="") next
      key=substr(ts,8,4) mn[mo] substr(ts,1,2) substr(ts,13,2) substr(ts,16,2) substr(ts,19,2)
      disp=substr(ts,8,4)"-"mn[mo]"-"substr(ts,1,2)" "substr(ts,13,8)" UTC"
      upd("LOG",key,disp)
      low=tolower($0)
      if(index(low,"?rest_route=/batch/v1")||index(low,"/wp-json/batch/v1")) upd("BATCH",key,disp)
      a=0
      if(low ~ /author[._+]exclude=/ || index(low,"author%20exclude=")){
        p=index(low,"exclude="); rest=substr($0,p+8); n=length(rest); val=""
        for(i=1;i<=n;i++){c=substr(rest,i,1); if(c=="&"||c=="\""||c==" ")break; val=val c}
        t=val; gsub(/%2[cC]/,",",t); if(t !~ /^[0-9,]*$/) a=1 }
      if(index(low,"batch/v1") && (index(low,"wp/v2/users")||index(low,"wp/v2/plugins"))) a=1
      if(index(low,"update.php?action=upload-plugin")) a=1
      if(a) upd("ATTEMPT",key,disp) }
    END{ for(b in cnt) printf "%s|%s|%s|%d\n", b, mnd[b], mxd[b], cnt[b] }'
}

echo "== wp2shell audit: $LOG_DIR =="
echo

### --- Nginx access log checks — always run in full, every field captured ---

n_batch=$(access_stream | grep -cE '(\?rest_route=/batch/v1|/wp-json/batch/v1)' || true)
report "batch/v1 route hits" "$n_batch"

n_upload=$(access_stream | grep -c 'update.php?action=upload-plugin' || true)
report "wp-admin plugin-upload POSTs" "$n_upload"

users=$( { access_stream | grep -oE 'delete_user=[a-z0-9_]+' | sort -u; } || true)
n_deleteuser=$(printf '%s' "$users" | grep -c . || true)
report "delete_user= cleanup calls" "$n_deleteuser" $users

n_wplogin=$( { access_stream | awk '
  /POST \/wp-login\.php/ {
    ip=$1; ts=$4;
    if ($9 == "302") { if (!(ip in seen)) print ts, ip; }
    seen[ip]=1
  }' | wc -l | tr -d ' '; } || true)
report "wp-login 302 with no prior attempt logged (IP-hop heuristic, see header)" "$n_wplogin"

vers=$( { access_stream | grep -oE '"WordPress/[0-9.]+;' | sort -u | tr -d '"' | tr -d ';'; } || true)
n_selfua=$(printf '%s' "$vers" | grep -c . || true)
report "WordPress self-request UA (oEmbed loopback / version fingerprint)" "$n_selfua" $vers

n_recon=$(access_stream | grep -E 'readme\.html|wp-includes/version\.php' | grep -civE 'mozilla' || true)
report "non-browser version-fingerprint requests" "$n_recon"

# Attack payload itself, not just its PHP-error side effect (that side
# effect requires WP_DEBUG_LOG, which Live doesn't run by default — see
# Section 3). author.exclude / author exclude are alternate spellings a
# WAF-evading attacker can send instead of author_exclude — PHP folds all
# three into the same $_GET key when parsing query-string parameter names,
# so they're equally valid attack surface. A legitimate author_exclude
# value is always digits/commas; anything else is the payload.
authorexcl=$( { access_stream \
    | grep -oiE 'author([._+]|%20)exclude=[^&\" ]*' \
    | grep -viE '=([0-9]|%2c|,)*$' \
    | sort -u; } || true)
n_authorexcl=$(printf '%s' "$authorexcl" | grep -c . || true)
report "author_exclude SQLi payload (non-numeric value)" "$n_authorexcl" $authorexcl

# Only catches the GET-based variant (params in the query string, visible
# in the access log) — a POST-body-only nested write is invisible here for
# the same reason the batch/v1-in-body case is (see header).
n_nestedwrite=$(access_stream | grep -i 'batch/v1' | grep -icE 'wp/v2/users|wp/v2/plugins' || true)
report "nested privileged REST write in batch request (GET-based only)" "$n_nestedwrite"

# --- Exploit-attempt time window (backup restore-point boundary) ----------
# One pass over the access stream → per-bucket "first|last|count" (see
# attempt_scan above). Lets a site owner identify a backup taken before any
# observed attempt. Bounded by log retention and access-log-visible attempts
# only (POST bodies are not logged) — the report wording states both caveats.
SCAN=$(access_stream | attempt_scan || true)
ATTEMPT_WINDOW=""; BATCH_WINDOW=""; LOG_WINDOW=""
while IFS='|' read -r _b _f _l _c; do
  [[ -z "$_b" ]] && continue
  case "$_b" in
    ATTEMPT) ATTEMPT_WINDOW="$_f|$_l|$_c" ;;
    BATCH)   BATCH_WINDOW="$_f|$_l|$_c" ;;
    LOG)     LOG_WINDOW="$_f|$_l|$_c" ;;
  esac
done <<< "$SCAN"

# Split "first|last|count" into fields for the buckets we display.
AF=""; AL=""; AN=""
LF=${LOG_WINDOW%%|*}; _lr=${LOG_WINDOW#*|}; LL=${_lr%%|*}
BF=${BATCH_WINDOW%%|*}; _br=${BATCH_WINDOW#*|}; BL=${_br%%|*}

# Precompute the Section 2 markdown block here (plain shell context), then
# drop it into the report heredoc below via a simple ${ATTEMPT_BLOCK}
# expansion. Built by string concatenation rather than a `$(cat <<HEREDOC)` —
# a here-document nested inside command substitution is mis-parsed by the
# bash that ships with macOS, and derails the whole report write. Backticks
# are escaped so they land as literal characters in the value.
nl=$'\n'
if [[ -n "$ATTEMPT_WINDOW" ]]; then
  AF=${ATTEMPT_WINDOW%%|*}; _r=${ATTEMPT_WINDOW#*|}; AL=${_r%%|*}; AN=${_r##*|}
  echo
  echo "== Exploit-attempt time window (access-log-visible) =="
  echo "Earliest attack-payload request: $AF"
  echo "Latest attack-payload request:   $AL   ($AN request(s))"
  echo "=> Backups taken before $AF predate all attempt traffic visible in the retained logs."
  ATTEMPT_BLOCK="- **Earliest attack-payload request:** ${AF}${nl}"
  ATTEMPT_BLOCK+="- **Latest attack-payload request:** ${AL} (${AN} request(s): non-numeric \`author_exclude\` payloads, nested privileged writes, and plugin-upload POSTs)${nl}"
  ATTEMPT_BLOCK+="- **Restore-point guidance:** a backup captured **before ${AF}** predates every exploit attempt visible in the retained nginx logs.${nl}${nl}"
  ATTEMPT_BLOCK+="_Caveats:_ (1) **Bounded by log retention** — \`terminus logs:get\` returns only the retained rotated logs (the overall access-log span in this fetch is ${LF} → ${LL}); an attempt older than the oldest retained line would not appear here, so read this as \"no *visible* attempt before this,\" not proof of none. (2) **Attempt ≠ compromise** — this is an attempt boundary, not a compromise boundary; see Section 4 for whether any attempt succeeded. A clean Section 4 with attempts present means the attempts were observed but did not compromise the site. (3) **POST bodies are not logged** by nginx (see Section 5), so this window reflects access-log-visible attempts only. (4) Raw \`batch/v1\` hits are **excluded** from this boundary because they are dominated by legitimate REST/Jetpack/mobile traffic; that route's mixed-traffic span in this fetch is ${BF} → ${BL}."
else
  ATTEMPT_BLOCK="(no access-log-visible exploit-attempt signatures detected)"
fi

echo

### --- PHP error log checks ------------------------------------------------

n_sqli=$(error_log | grep -c 'post_author NOT IN' || true)
report "author__not_in SQLi errors (CVE-2026-60137)" "$n_sqli"

n_nested=$(error_log | grep -c 'Constant REST_REQUEST already defined' || true)
report "nested REST dispatch (CVE-2026-63030 signature)" "$n_nested"

n_stall=$(error_log | grep -c 'Undefined array key "user_login"' || true)
report "changeset-publish pipeline stall marker" "$n_stall"

echo

### --- DB checks (require --wp / --site) -------------------------------

n_invalid=0; invalid=""
n_changesets=0; changesets=""
n_navmenu=0; navmenu=""
n_postmeta=0; postmeta=""
n_orphans=0; orphans=""
n_suspusers=0; suspusers=""

if [[ -z "$WP_CLI" ]]; then
  echo "-- Skipping DB checks: no --wp or --site provided --"
else
  echo "== DB checks via: $WP_CLI =="

  # WordPress table prefix is frequently customized (e.g. wp_xfpfyq561c
  # instead of wp_) — never hardcode wp_* table names, always resolve this
  # first and build every query against it.
  TBL_PREFIX=$( { $WP_CLI config get table_prefix --skip-plugins --skip-themes 2>/dev/null; } || true)
  if [[ -z "$TBL_PREFIX" ]]; then
    echo "Could not resolve table prefix via wp config get — falling back to 'wp_'." >&2
    TBL_PREFIX="wp_"
  fi
  echo "Table prefix: ${TBL_PREFIX}"
  T_POSTS="${TBL_PREFIX}posts"
  T_USERS="${TBL_PREFIX}users"
  T_USERMETA="${TBL_PREFIX}usermeta"
  T_POSTMETA="${TBL_PREFIX}postmeta"

  # BLOG_IDS drives every post/postmeta check below via run_ms_check().
  # Without --multisite this is always just "1" (blog 1, unprefixed tables)
  # — identical to this script's behavior before multisite support existed,
  # and zero extra WP-CLI calls for the common (non-multisite) case.
  BLOG_IDS="1"
  if [[ "$MULTISITE" -eq 1 ]]; then
    blog_ids_raw=$($WP_CLI site list --field=blog_id --skip-plugins --skip-themes 2>/dev/null || true)
    if is_query_failure "$blog_ids_raw" || [[ -z "$(printf '%s' "$blog_ids_raw" | tr -d '[:space:]')" ]]; then
      echo "WARNING: --multisite was given but 'wp site list' returned nothing — this may not actually be a WordPress Multisite install. Falling back to a single site (blog 1)." >&2
    else
      BLOG_IDS="$blog_ids_raw"
      echo "Multisite install — auditing $(printf '%s' "$BLOG_IDS" | grep -c . || true) site(s): $(printf '%s' "$BLOG_IDS" | tr '\n' ' ')"
    fi
  fi

  # Beyond WordPress core's own statuses, several widely-used plugins
  # register their own legitimate custom post_status values — most
  # commonly WooCommerce's order-status set (wc-completed/wc-pending/etc.),
  # which on an active store can affect hundreds of thousands of rows and
  # would otherwise swamp this check with pure noise. Confirmed directly
  # against a real WooCommerce site's data: wc-completed accounted for the
  # overwhelming majority of a 231,501-row false positive here. This list
  # is WooCommerce's own standard, documented order statuses only — not a
  # place to add arbitrary/one-off statuses; anything else non-standard
  # still surfaces below for a judgment call instead of being silently
  # trusted or silently flagged.
  # Beyond WordPress core's own statuses, several widely-used plugins
  # register their own legitimate custom post_status values — most
  # commonly WooCommerce's order-status set (wc-completed/wc-pending/etc.),
  # which on an active store can affect hundreds of thousands of rows and
  # would otherwise swamp this check with pure noise. This list is
  # WooCommerce's own standard, documented order statuses only — not a
  # place to add arbitrary/one-off statuses; anything else non-standard
  # still surfaces below for a judgment call instead of being silently
  # trusted or silently flagged.
  run_ms_check "invalid post_status" "posts" "
    SELECT ID FROM __TABLE__ WHERE post_status NOT IN (
      'publish','future','draft','pending','private','trash',
      'auto-draft','inherit',
      'request-pending','request-confirmed','request-failed','request-completed',
      'acf-disabled',
      'wc-pending','wc-processing','wc-on-hold','wc-completed',
      'wc-cancelled','wc-refunded','wc-failed','wc-checkout-draft'
    );"
  n_invalid=$MS_COUNT
  invalid=$MS_LIST
  if [[ "$MULTISITE" -eq 1 ]]; then
    report "posts with invalid post_status (across all sites)" "$n_invalid" $invalid
  else
    report "${T_POSTS} with invalid post_status" "$n_invalid" $invalid
  fi

  # Distinct remaining status values (not per-row IDs, which is what made
  # this check unusable on a large site — one status shared by hundreds of
  # thousands of legitimate rows would otherwise dump that many bullet
  # points into the report). A handful of statuses each covering many rows
  # reads as "another plugin's normal post type," worth a judgment call in
  # Stage 2, not automatically as compromise; a status appearing on
  # exactly one or two rows, or one that looks like random/injected
  # content rather than a plugin's own naming, is the more suspicious
  # shape. This never overrides the automated verdict above — it's context
  # for whoever reviews a FLAGGED result. Looped per blog on multisite —
  # a GROUP BY against a clean blog's table simply returns no rows, so no
  # separate per-blog nonzero tracking is needed here.
  if [[ "$n_invalid" -gt 0 ]]; then
    for blog_id in $BLOG_IDS; do
      t_posts_b=$(blog_table "$blog_id" posts)
      echo
      if [[ "$MULTISITE" -eq 1 ]]; then
        echo "== post_status breakdown for anomaly review (blog ${blog_id}: ${t_posts_b}) =="
      else
        echo "== post_status breakdown for anomaly review =="
      fi
      $WP_CLI db query --silent "
        SELECT post_status, COUNT(*) AS row_count FROM ${t_posts_b} WHERE post_status NOT IN (
          'publish','future','draft','pending','private','trash',
          'auto-draft','inherit',
          'request-pending','request-confirmed','request-failed','request-completed',
          'acf-disabled',
          'wc-pending','wc-processing','wc-on-hold','wc-completed',
          'wc-cancelled','wc-refunded','wc-failed','wc-checkout-draft'
        ) GROUP BY post_status ORDER BY row_count DESC LIMIT 20;" --skip-plugins --skip-themes 2>/dev/null || true
    done

    # Cross-reference for the breakdown above — without this, "does this
    # look plugin-like" was a naming-convention guess. This is the actual
    # active-plugin list, so a status prefix can be matched to a real,
    # named, installed plugin instead of just judged plausible-looking.
    # Network-activated plugins show here regardless of blog; a plugin
    # activated on only one specific subsite (not network-wide) may not —
    # WP-CLI's plugin list without --url reflects the main site's context.
    echo
    echo "== active plugins for post_status cross-reference =="
    $WP_CLI plugin list --status=active --fields=name,title --format=csv --skip-plugins --skip-themes 2>/dev/null || true
  fi

  # Not filtered by post_status: a forged changeset can sit in any status
  # (e.g. 'auto-draft', which is a normal transient state for this post
  # type), so restricting to 'publish' let real forgeries slip through.
  # The post_date/post_content signature is specific enough on its own.
  run_ms_check "suspicious changesets" "posts" "
    SELECT ID FROM __TABLE__ WHERE post_type = 'customize_changeset'
      AND (post_date = '2020-01-01 00:00:00' OR post_content LIKE '%example.invalid%');"
  n_changesets=$MS_COUNT
  changesets=$MS_LIST
  report "suspicious changesets" "$n_changesets" $changesets

  run_ms_check "forged nav_menu_item rows" "posts" "
    SELECT ID FROM __TABLE__ WHERE post_type = 'nav_menu_item'
      AND post_date = '2020-01-01 00:00:00';"
  n_navmenu=$MS_COUNT
  navmenu=$MS_LIST
  report "forged nav_menu_item rows" "$n_navmenu" $navmenu

  run_ms_check "postmeta rows referencing example.invalid" "postmeta" "
    SELECT DISTINCT post_id FROM __TABLE__ WHERE meta_value LIKE '%example.invalid%';"
  n_postmeta=$MS_COUNT
  postmeta=$MS_LIST
  if [[ "$MULTISITE" -eq 1 ]]; then
    report "postmeta rows referencing example.invalid (across all sites)" "$n_postmeta" $postmeta
  else
    report "${T_POSTMETA} rows referencing example.invalid" "$n_postmeta" $postmeta
  fi

  orphans_raw=$($WP_CLI db query --silent "
    SELECT um.user_id FROM ${T_USERMETA} um
    LEFT JOIN ${T_USERS} u ON u.ID = um.user_id
    WHERE u.ID IS NULL LIMIT 20;" --skip-plugins --skip-themes 2>/dev/null || true)
  orphans=$(sanitize_query_result "$orphans_raw" "orphaned ${T_USERMETA} rows")
  n_orphans=$(printf '%s' "$orphans" | grep -c . || true)
  report "orphaned ${T_USERMETA} rows" "$n_orphans" $orphans

  # Flags accounts named like <prefix>_<hex> (e.g. wp2_74cc526ddf49,
  # wpsvc_a1b2c3d4e5f6) — the throwaway-admin naming convention seen in the
  # reference incident. Checks user_login and display_name only; user_email
  # is intentionally excluded per instruction. Deliberately not using SQL
  # REPLACE() here — some layer between WP-CLI and Terminus misclassifies
  # any query containing that keyword as a write statement and returns
  # "Rows affected: -1" instead of the actual result set.
  suspusers_raw=$($WP_CLI db query --silent "
    SELECT CONCAT(ID, ':', user_login)
    FROM ${T_USERS}
    WHERE user_login REGEXP '^[a-z0-9]+_[0-9a-f]{6,}\$'
       OR display_name REGEXP '^[a-z0-9]+_[0-9a-f]{6,}\$';" --skip-plugins --skip-themes 2>/dev/null || true)
  suspusers=$(sanitize_query_result "$suspusers_raw" "suspicious <prefix>_<hex>-style usernames")
  n_suspusers=$(printf '%s' "$suspusers" | grep -c . || true)
  report "suspicious <prefix>_<hex>-style usernames" "$n_suspusers" $suspusers

  # Raw data for the LLM/human judgment pass (see the wp2shell-audit skill) —
  # the regex above only catches one specific naming convention; this is the
  # broader net for anything that doesn't match it.
  echo
  echo "== Recent user accounts for anomaly review =="
  $WP_CLI db query --silent "
    SELECT ID, user_login, user_email, user_registered, display_name
    FROM ${T_USERS}
    ORDER BY user_registered DESC
    LIMIT 100;" --skip-plugins --skip-themes 2>/dev/null || true

  # Every site has admins — a nonzero count here is not itself a flag, it's
  # a priority list: check these specific accounts first during Stage 2
  # instead of scanning all 100 recent signups blind to role. On multisite,
  # admin status is granted per-blog via <prefix><blog_id>_capabilities
  # (blog 1: unprefixed <prefix>capabilities) — a single capabilities key
  # only ever caught blog 1's admins, missing subsite-only ones entirely.
  CAP_CLAUSE="um.meta_key = '${TBL_PREFIX}capabilities'"
  if [[ "$MULTISITE" -eq 1 ]]; then
    for blog_id in $BLOG_IDS; do
      [[ "$blog_id" == "1" ]] && continue
      CAP_CLAUSE="${CAP_CLAUSE} OR um.meta_key = '${TBL_PREFIX}${blog_id}_capabilities'"
    done
  fi
  echo
  echo "== Administrator-role accounts for anomaly review =="
  $WP_CLI db query --silent "
    SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name, um.meta_key AS site_role_key
    FROM ${T_USERS} u
    JOIN ${T_USERMETA} um ON um.user_id = u.ID
    WHERE (${CAP_CLAUSE})
      AND um.meta_value LIKE '%administrator%'
    ORDER BY u.user_registered DESC;" --skip-plugins --skip-themes 2>/dev/null || true

  # Network Super Admin — full control over EVERY subsite, the
  # highest-value target on a compromised multisite network. This is a
  # completely different mechanism from per-blog admin capabilities: a
  # serialized PHP array in wp_sitemeta's site_admins option, not user meta
  # at all. Extracted via the serialized-string marker (s:<len>:"<value>")
  # rather than writing a full PHP unserializer for one field — confirmed
  # directly this extracts cleanly against a real network's site_admins
  # value. wp_sitemeta doesn't exist on a non-multisite install, so this
  # only runs with --multisite.
  if [[ "$MULTISITE" -eq 1 ]]; then
    echo
    echo "== Network Super Admin accounts for anomaly review =="
    site_admins_raw=$($WP_CLI db query --silent "
      SELECT meta_value FROM ${TBL_PREFIX}sitemeta WHERE meta_key = 'site_admins';" --skip-plugins --skip-themes 2>/dev/null || true)
    site_admins=$( { printf '%s' "$site_admins_raw" | grep -oE 's:[0-9]+:"[^"]*"' | sed -E 's/^s:[0-9]+:"//; s/"$//'; } || true)
    if [[ -n "$site_admins" ]]; then
      printf '%s\n' "$site_admins"
    else
      echo "(none found, or could not parse wp_sitemeta site_admins — check manually)"
    fi
  fi
fi

echo
echo "== Summary: $pass ok, $flag flagged =="

### --- Build the report, save/print it, and optionally publish -------------

if [[ "$n_invalid" -gt 0 || "$n_changesets" -gt 0 || "$n_navmenu" -gt 0 || "$n_postmeta" -gt 0 || "$n_sqli" -gt 0 || "$n_suspusers" -gt 0 ]]; then
  VERDICT="CONFIRMED COMPROMISE — remediation required"
else
  VERDICT="NO EVIDENCE OF COMPROMISE FOUND"
fi

REPORT_SITE="${SITE:-$LOG_DIR}"
REPORT_DATE=$(date +%Y-%m-%d)
# Filesystem-safe identifier for the report filename — SITE.ENV with the dot
# swapped for a dash, or the log directory's basename when running via
# --logs (no --site). Falls back to "audit" if that's somehow still empty.
if [[ -n "$SITE" ]]; then
  REPORT_SLUG="${SITE//./-}"
else
  REPORT_SLUG="$(basename "$LOG_DIR")"
fi
REPORT_SLUG="${REPORT_SLUG:-audit}"

# Multisite covers more than one table set per check, so the single-table
# label ("wp_posts with invalid post_status") isn't accurate there — swap
# in a generic label instead. Single-site output is unaffected either way.
if [[ "$MULTISITE" -eq 1 ]]; then
  LABEL_INVALID="posts with invalid post_status (across all sites)"
  LABEL_POSTMETA="postmeta rows referencing example.invalid (across all sites)"
else
  LABEL_INVALID="${T_POSTS} with invalid post_status"
  LABEL_POSTMETA="${T_POSTMETA} rows referencing example.invalid"
fi

REPORT_CONTENT=$(cat <<EOF
# wp2shell Security Audit Report — ${REPORT_SITE}

> CONFIDENTIAL
> This report contains customer site data and security findings. Follow your organization's data-handling and confidentiality policies before sharing it outside your team.

| | |
|---|---|
| Site/Source | ${REPORT_SITE} |
| Audit Date | ${REPORT_DATE} |
| Tooling | wp2shell-audit.sh (automated, no manual write-up) |
| Scope | Audit only — no remediation/cleanup performed |
| Status | **${VERDICT}** |

---

## 1. Executive Summary

This report covers CVE-2026-60137 (unauthenticated SQL injection via \`author__not_in\`) and CVE-2026-63030 (REST API \`batch/v1\` route-confusion), the chained WordPress Core vulnerability disclosed by Wordfence 2026-07-20 following WordPress's 2026-07-17 emergency patch (6.8.6 / 6.9.5 / 7.0.2).

**Verdict: ${VERDICT}**

The six highest-confidence indicators — invalid \`post_status\` rows, forged \`customize_changeset\` rows, forged \`nav_menu_item\` rows, malicious \`postmeta\` rows referencing \`example.invalid\`, \`author__not_in\` SQLi errors, and \`<prefix>_<hex>\`-style usernames — are independent and mutually corroborating when non-zero. All other checks are supporting evidence only; see per-section assessments below.

---

## 2. Nginx Access Log Analysis

All results below come from every nginx-access.log file found under the fetched log directory (including rotated \`.gz\` archives), read as one continuous stream.

| Check | Result |
|---|---|
| \`batch/v1\` route hits | ${n_batch} |
| \`wp-admin\` plugin-upload POSTs | ${n_upload} |
| \`delete_user=\` cleanup calls | ${n_deleteuser} |
| wp-login 302-on-first-attempt pattern (IP-hop heuristic) | ${n_wplogin} |
| WordPress self-request UA (oEmbed loopback / version fingerprint) | ${n_selfua} |
| Non-browser version-fingerprint requests | ${n_recon} |
| \`author_exclude\` SQLi payload (non-numeric value) | ${n_authorexcl} |
| Nested privileged REST write in batch request (GET-based only) | ${n_nestedwrite} |

**\`delete_user=\` targets found:**
$(md_list $users)

**WordPress self-request versions found:**
$(md_list $vers)

**\`author_exclude\` payload values found:**
$(md_list $authorexcl)

**Exploit-attempt time window (access-log-visible):**
${ATTEMPT_BLOCK}

**Assessment:** prior to this CVE's disclosure, the \`batch/v1\` route had near-zero legitimate traffic platform-wide — elevated volume here should be read as a real signal leaning toward attack/probe activity, not dismissed as plausibly-organic REST/Jetpack/mobile-client usage. \`wp-admin\` upload POSTs, \`delete_user=\` calls, and the wp-login-first-try pattern are the direct nginx-side fingerprint of the later RCE/webshell stage seen in prior confirmed exploitation of this chain — zero here means no nginx-log evidence the attack reached that stage, not proof it didn't (see confidence notes below). The \`author_exclude\` check catches the SQLi payload itself (not just its PHP-error side effect in Section 3) and also matches the \`author.exclude\`/\`author exclude\` spellings an attacker can use to dodge a WAF rule written against the literal string \`author_exclude\` — PHP folds all three into the same request parameter when parsing. The nested-privileged-write check only catches a GET-based batch call with sub-request paths in the query string; a POST-body variant of either this or the raw \`batch/v1\` hit itself is invisible to nginx access logs, which do not capture POST body content — a zero on either of these two checks is not evidence the technique wasn't attempted, only that it wasn't attempted in a form the access log can see.

---

## 3. PHP Error Log Analysis

| Check | Result |
|---|---|
| \`author__not_in\` SQLi errors (CVE-2026-60137 signature) | ${n_sqli} |
| Nested REST dispatch / \`Constant REST_REQUEST already defined\` (CVE-2026-63030 signature) | ${n_nested} |
| Changeset-publish pipeline stall marker (\`Undefined array key "user_login"\`) | ${n_stall} |

**Assessment:** a non-zero SQLi count is direct, confirmed evidence CVE-2026-60137 fired — this is not inferred. All three signatures depend on verbose PHP error logging (\`WP_DEBUG_LOG\`-style) being enabled. This is common on Dev but Pantheon Live environments do not run with \`WP_DEBUG\` on — a zero result here on Live is not meaningful evidence of anything and should not be read as "no compromise"; rely on Section 4 instead. On Dev/Test, treat a zero result with the same caution unless debug logging is independently confirmed enabled.

---

## 4. Database Analysis

$(if [[ -z "$WP_CLI" ]]; then echo "**Skipped — no \`--wp\`/\`--site\` provided for this run.**"; else cat <<DBEOF
$(if [[ "$MULTISITE" -eq 1 ]]; then echo "Multisite install — the four post/postmeta-based checks below cover every subsite (blog IDs: $(printf '%s' "$BLOG_IDS" | tr '\n' ' ')), not just the main site. Row IDs are tagged \`blog<ID>:<row-ID>\` since post IDs restart per subsite and aren't meaningful without knowing which subsite's table they came from."; fi)

| Check | Result |
|---|---|
| \`${LABEL_INVALID}\` | ${n_invalid} |
| Suspicious \`customize_changeset\` rows (any status) | ${n_changesets} |
| Forged \`nav_menu_item\` rows | ${n_navmenu} |
| \`${LABEL_POSTMETA}\` | ${n_postmeta} |
| Orphaned \`${T_USERMETA}\` rows | ${n_orphans} |
| Suspicious \`<prefix>_<hex>\`-style usernames | ${n_suspusers} |

**Invalid post_status row IDs:**
$(md_list $invalid)

**Suspicious changeset row IDs:**
$(md_list $changesets)

**Forged nav_menu_item row IDs:**
$(md_list $navmenu)

**${LABEL_POSTMETA} (post IDs):**
$(md_list $postmeta)

**Orphaned ${T_USERMETA} user IDs:**
$(md_list $orphans)

**Suspicious usernames found (ID:user_login — matched via user_login or display_name):**
$(md_list $suspusers)

**Assessment:** the invalid-\`post_status\` check is the single highest-confidence signal in this entire report when the status values involved are actually unrecognized — WordPress core cannot natively produce a \`post_status\` outside its known set, and this check's whitelist also excludes WooCommerce's own standard order statuses (\`wc-completed\`, \`wc-pending\`, etc.), which otherwise produced a confirmed false positive at real-world scale (hundreds of thousands of legitimate order rows on one site). If this count is still non-zero, check the \`== post_status breakdown for anomaly review ==\` block printed during the audit (not written to this report) before treating it as compromise — a handful of distinct statuses each covering many rows reads as another plugin's own post type, not forged content; a status on exactly one or two rows, or one that looks like random/injected text rather than a plugin's naming convention, is the more suspicious shape. This does not depend on debug logging or any other environment-specific configuration, unlike Sections 2 and 3. The changeset check is no longer filtered to \`post_status = 'publish'\` — a forged changeset can sit in any status, including the transient \`auto-draft\` state this post type normally uses, so restricting to published rows let real forgeries through undetected. The \`nav_menu_item\` and \`postmeta\` checks target the same \`2020-01-01 00:00:00\` / \`example.invalid\` signature in other tables the exploit is known to touch — like the invalid-\`post_status\` check, these do not depend on debug logging. The suspicious-username check flags any \`user_login\` or \`display_name\` matching \`<prefix>_<hex-string>\` (e.g. \`wp2_74cc526ddf49\`, \`wpsvc_a1b2c3d4e5f6\`) — the throwaway-admin naming convention observed in the reference incident. Only \`user_login\`/\`display_name\` are checked; \`user_email\` is intentionally excluded. A non-zero result here is high-confidence on its own — this pattern does not occur in normal WordPress usage.
$(if [[ "$MULTISITE" -eq 1 ]]; then echo "On multisite, this also runs against every subsite's own tables — see \`== Administrator-role accounts for anomaly review ==\` (now tagged by which capability key/blog matched) and the new \`== Network Super Admin accounts for anomaly review ==\` block printed during the audit (both stdout-only, not written to this file, same as the existing user-review blocks) for the account-side anomaly review. A planted network Super Admin is the highest-value target on a compromised multisite — check that block first."; fi)
DBEOF
fi)

---

## 5. Confidence Assessment

- Section 4 (Database) results are the most reliable — they don't depend on log retention or debug-logging configuration.
- Section 3 (PHP error log) results corroborate Section 4 but can under-report on environments where verbose error logging is off.
- Section 2 (Nginx) is complete for the log retention window fetched from every appserver reached, but a fully clean Section 2 does not rule out compromise if Sections 3/4 are non-zero — it means the later attack stages left no nginx-visible trace in this window, not that they didn't happen.
- Standard nginx access logs never capture POST body content. A \`rest_route=/batch/v1\` reference, a nested privileged write, or an \`author_exclude\` payload sent entirely inside a POST body (rather than the URL/query string) is structurally invisible to every check in Section 2 — this is a data-source limit, not a detection gap that a different grep would close.
$(if [[ "$APPSERVERS_TOTAL" -gt 0 && "$APPSERVERS_REACHED" -lt "$APPSERVERS_TOTAL" ]]; then
cat <<APPEOF
- **Log coverage is INCOMPLETE: only ${APPSERVERS_REACHED} of ${APPSERVERS_TOTAL} backing appserver(s) were reached.** Each appserver can hold a different slice of traffic and a different log-rotation window — Section 2 above reflects only what the reached appserver(s) had, not the whole environment. Do not treat a clean Section 2 as conclusive here; re-run once connectivity to the missing appserver(s) is fixed before ruling anything out on nginx-log grounds alone.
APPEOF
elif [[ "$APPSERVERS_TOTAL" -gt 0 ]]; then
cat <<APPEOF
- Log coverage: all ${APPSERVERS_TOTAL} backing appserver(s) were reached.
APPEOF
fi)
EOF
)

DOC_TITLE="wp2shell Security Audit — ${REPORT_SITE} (${REPORT_DATE})"
GOOGLE_DOC_GENERATOR="$SCRIPT_DIR/lib/generate_google_doc.py"

echo
echo "== Stage 1 complete =="

if [[ -n "$OUTPUT_DIR" ]]; then
  mkdir -p "$OUTPUT_DIR"
  MD_FILE="${OUTPUT_DIR%/}/wp2shell-report-${REPORT_SLUG}-$(date +%s).md"
  printf '%s\n' "$REPORT_CONTENT" > "$MD_FILE"
  echo "Report saved to: $MD_FILE"
  echo
  echo "Next: run Stage 2 (LLM anomaly review of the recent-users block above)"
  echo "and insert the findings into that file — see SKILL.md Stage 3."
  if [[ "$DO_GWS" -eq 0 ]]; then
    echo "To publish this as a Google Doc later (optional, not required to use this report):"
    echo "  python3 \"$GOOGLE_DOC_GENERATOR\" --input \"$MD_FILE\" --title \"$DOC_TITLE\" --delete-after"
  fi
fi

if [[ "$STDOUT_ONLY" -eq 1 ]]; then
  echo
  echo "$REPORT_CONTENT"
fi

if [[ "$DO_GWS" -eq 1 ]]; then
  if ! command -v gws >/dev/null 2>&1; then
    echo "Error: --gws was requested but the gws CLI isn't installed/on PATH. Install it and try again, or omit --gws — the report at \"$MD_FILE\" is already complete without it." >&2
    exit 1
  fi
  if [[ ! -f "$GOOGLE_DOC_GENERATOR" ]]; then
    echo "Error: --gws was requested but the generator script is missing at $GOOGLE_DOC_GENERATOR — check lib/ wasn't stripped out of this checkout." >&2
    exit 1
  fi
  echo
  echo "== Publishing to Google Docs (--gws) =="
  python3 "$GOOGLE_DOC_GENERATOR" --input "$MD_FILE" --title "$DOC_TITLE" --delete-after
fi

[[ "$flag" -gt 0 ]] && exit 2 || exit 0
