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
#   ./wp2shell-audit.sh --site SITE.ENV
#   ./wp2shell-audit.sh --logs /path/to/log/dir --wp "wp"
#
# --site   Pulls logs via `terminus logs:get` and runs DB checks via
#          `terminus wp SITE.ENV --`. Requires Terminus auth already set up.
#          `logs:get` is NOT a stock Terminus command — it's provided by
#          the `terminus-site-debug` plugin
#          (https://github.com/pantheon-systems/terminus-site-debug).
#          Install it per that repo's own instructions before running this
#          with --site; this script checks for `logs:get` up front and
#          exits early with a pointer to that repo if it's missing, rather
#          than failing deep into a run. Self-heals SSH host-key
#          verification failures against never-before-contacted (or
#          since-recycled) appserver/dbserver containers automatically —
#          retries up to 3x, trusting whatever IP the failure names each
#          time.
# --logs   Directory of already-downloaded logs (skips the terminus fetch).
# --wp     WP-CLI invocation prefix, for use with --logs. Omit to skip DB
#          checks (log-only run).
#
# Every run writes a local markdown report next to this script and prints
# its path — it does NOT publish anything. Publishing is Stage 3 (see
# SKILL.md): Stage 2's LLM anomaly review gets inserted into that file
# first, then it's published ONCE as a Google Doc (Poppins typography,
# purple table headers — no cover page or logo) via
# lib/generate_google_doc.py, which requires `gws` installed and
# authenticated — run `gws drive about get --params '{"fields":"user"}'`
# once to confirm. The doc is private to whoever's `gws` credentials
# created it — nothing is shared automatically.
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

# Only cleans up the terminus logs tempdir — MD_FILE is Stage 1's actual
# deliverable now (SKILL.md Stage 2/3 read and edit it before publishing),
# so it must survive past this script's exit, not get wiped on the way out.
cleanup() {
  [[ -n "$CLEANUP_TMP" ]] && rm -rf "$CLEANUP_TMP"
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --site)  SITE="$2"; shift 2 ;;
    --logs)  LOG_DIR="$2"; shift 2 ;;
    --wp)    WP_CLI="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Pantheon's appserver containers are ephemeral and rotate between calls —
# a never-before-contacted (or since-recycled) container fails SSH host-key
# verification on the first hit, and pinning one IP doesn't stick since the
# next call can land on a different container entirely. Self-heal by
# trusting whatever IP the failure names and retrying, rather than a
# one-time keyscan.
fetch_logs_with_keyscan_retry() {
  local site="$1" dest="$2" attempt output status ips ip
  for attempt in 1 2 3; do
    output=$(terminus logs:get "$site" --all "$dest" 2>&1)
    status=$?
    echo "$output" >&2
    [[ $status -eq 0 ]] && return 0
    ips=$(echo "$output" | grep -oE '@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr -d '@' | sort -u)
    [[ -z "$ips" ]] && return 1
    while read -r ip; do
      ssh-keyscan -p 2222 -H "$ip" >> ~/.ssh/known_hosts 2>/dev/null
    done <<< "$ips"
  done
  return 1
}

if [[ -n "$SITE" ]]; then
  if ! terminus list 2>/dev/null | grep -q 'logs:get'; then
    echo "terminus logs:get is not available on this machine's Terminus install." >&2
    echo "It's provided by the terminus-site-debug plugin, not stock Terminus:" >&2
    echo "  https://github.com/pantheon-systems/terminus-site-debug" >&2
    echo "Install it per that repo's instructions, then re-run this." >&2
    exit 1
  fi
  CLEANUP_TMP=$(mktemp -d)
  echo "Fetching logs for $SITE via terminus logs:get ..." >&2
  if ! fetch_logs_with_keyscan_retry "$SITE" "$CLEANUP_TMP"; then
    echo "terminus logs:get failed after retrying with host-key trust — see output above." >&2
    exit 1
  fi
  LOG_DIR="$CLEANUP_TMP"
  WP_CLI="terminus wp $SITE --"
fi

if [[ -z "$LOG_DIR" || ! -d "$LOG_DIR" ]]; then
  echo "Usage: $0 --site SITE.ENV | --logs /path/to/log/dir [--wp \"wp-cli invocation\"]" >&2
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

# Recursive: terminus logs:get's exact directory layout isn't something
# this session could verify against a live fetch, so search rather than
# assume a fixed path.
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
n_deleteuser=$(echo -n "$users" | grep -c . || true)
report "delete_user= cleanup calls" "$n_deleteuser" $users

n_wplogin=$( { access_stream | awk '
  /POST \/wp-login\.php/ {
    ip=$1; ts=$4;
    if ($9 == "302") { if (!(ip in seen)) print ts, ip; }
    seen[ip]=1
  }' | wc -l | tr -d ' '; } || true)
report "wp-login 302 with no prior attempt logged (IP-hop heuristic, see header)" "$n_wplogin"

vers=$( { access_stream | grep -oE '"WordPress/[0-9.]+;' | sort -u | tr -d '"' | tr -d ';'; } || true)
n_selfua=$(echo -n "$vers" | grep -c . || true)
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
n_authorexcl=$(echo -n "$authorexcl" | grep -c . || true)
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
  invalid_raw=$($WP_CLI db query --silent "
    SELECT ID FROM ${T_POSTS} WHERE post_status NOT IN (
      'publish','future','draft','pending','private','trash',
      'auto-draft','inherit',
      'request-pending','request-confirmed','request-failed','request-completed',
      'acf-disabled',
      'wc-pending','wc-processing','wc-on-hold','wc-completed',
      'wc-cancelled','wc-refunded','wc-failed','wc-checkout-draft'
    );" --skip-plugins --skip-themes 2>/dev/null || true)
  invalid=$(sanitize_query_result "$invalid_raw" "invalid post_status")
  n_invalid=$(echo -n "$invalid" | grep -c . || true)
  report "${T_POSTS} with invalid post_status" "$n_invalid" $invalid

  # Distinct remaining status values (not per-row IDs, which is what made
  # this check unusable on a large site — one status shared by hundreds of
  # thousands of legitimate rows would otherwise dump that many bullet
  # points into the report). A handful of statuses each covering many rows
  # reads as "another plugin's normal post type," worth a judgment call in
  # Stage 2, not automatically as compromise; a status appearing on
  # exactly one or two rows, or one that looks like random/injected
  # content rather than a plugin's own naming, is the more suspicious
  # shape. This never overrides the automated verdict above — it's context
  # for whoever reviews a FLAGGED result.
  if [[ "$n_invalid" -gt 0 ]]; then
    echo
    echo "== post_status breakdown for anomaly review =="
    $WP_CLI db query --silent "
      SELECT post_status, COUNT(*) AS row_count FROM ${T_POSTS} WHERE post_status NOT IN (
        'publish','future','draft','pending','private','trash',
        'auto-draft','inherit',
        'request-pending','request-confirmed','request-failed','request-completed',
        'acf-disabled',
        'wc-pending','wc-processing','wc-on-hold','wc-completed',
        'wc-cancelled','wc-refunded','wc-failed','wc-checkout-draft'
      ) GROUP BY post_status ORDER BY row_count DESC LIMIT 20;" --skip-plugins --skip-themes 2>/dev/null || true

    # Cross-reference for the breakdown above — without this, "does this
    # look plugin-like" was a naming-convention guess. This is the actual
    # active-plugin list, so a status prefix can be matched to a real,
    # named, installed plugin instead of just judged plausible-looking.
    echo
    echo "== active plugins for post_status cross-reference =="
    $WP_CLI plugin list --status=active --fields=name,title --format=csv --skip-plugins --skip-themes 2>/dev/null || true
  fi

  # Not filtered by post_status: a forged changeset can sit in any status
  # (e.g. 'auto-draft', which is a normal transient state for this post
  # type), so restricting to 'publish' let real forgeries slip through.
  # The post_date/post_content signature is specific enough on its own.
  changesets_raw=$($WP_CLI db query --silent "
    SELECT ID FROM ${T_POSTS} WHERE post_type = 'customize_changeset'
      AND (post_date = '2020-01-01 00:00:00' OR post_content LIKE '%example.invalid%');" --skip-plugins --skip-themes 2>/dev/null || true)
  changesets=$(sanitize_query_result "$changesets_raw" "suspicious changesets")
  n_changesets=$(echo -n "$changesets" | grep -c . || true)
  report "suspicious changesets" "$n_changesets" $changesets

  navmenu_raw=$($WP_CLI db query --silent "
    SELECT ID FROM ${T_POSTS} WHERE post_type = 'nav_menu_item'
      AND post_date = '2020-01-01 00:00:00';" --skip-plugins --skip-themes 2>/dev/null || true)
  navmenu=$(sanitize_query_result "$navmenu_raw" "forged nav_menu_item rows")
  n_navmenu=$(echo -n "$navmenu" | grep -c . || true)
  report "forged nav_menu_item rows" "$n_navmenu" $navmenu

  postmeta_raw=$($WP_CLI db query --silent "
    SELECT DISTINCT post_id FROM ${T_POSTMETA} WHERE meta_value LIKE '%example.invalid%';" --skip-plugins --skip-themes 2>/dev/null || true)
  postmeta=$(sanitize_query_result "$postmeta_raw" "${T_POSTMETA} rows referencing example.invalid")
  n_postmeta=$(echo -n "$postmeta" | grep -c . || true)
  report "${T_POSTMETA} rows referencing example.invalid" "$n_postmeta" $postmeta

  orphans_raw=$($WP_CLI db query --silent "
    SELECT um.user_id FROM ${T_USERMETA} um
    LEFT JOIN ${T_USERS} u ON u.ID = um.user_id
    WHERE u.ID IS NULL LIMIT 20;" --skip-plugins --skip-themes 2>/dev/null || true)
  orphans=$(sanitize_query_result "$orphans_raw" "orphaned ${T_USERMETA} rows")
  n_orphans=$(echo -n "$orphans" | grep -c . || true)
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
  n_suspusers=$(echo -n "$suspusers" | grep -c . || true)
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
  # instead of scanning all 100 recent signups blind to role.
  echo
  echo "== Administrator-role accounts for anomaly review =="
  $WP_CLI db query --silent "
    SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name
    FROM ${T_USERS} u
    JOIN ${T_USERMETA} um ON um.user_id = u.ID
    WHERE um.meta_key = '${TBL_PREFIX}capabilities'
      AND um.meta_value LIKE '%administrator%'
    ORDER BY u.user_registered DESC;" --skip-plugins --skip-themes 2>/dev/null || true
fi

echo
echo "== Summary: $pass ok, $flag flagged =="

### --- Build and publish the Google Doc report ------------------------------

if [[ "$n_invalid" -gt 0 || "$n_changesets" -gt 0 || "$n_navmenu" -gt 0 || "$n_postmeta" -gt 0 || "$n_sqli" -gt 0 || "$n_suspusers" -gt 0 ]]; then
  VERDICT="CONFIRMED COMPROMISE — remediation required"
else
  VERDICT="NO EVIDENCE OF COMPROMISE FOUND"
fi

REPORT_SITE="${SITE:-$LOG_DIR}"
REPORT_DATE=$(date +%Y-%m-%d)
# Avoids mktemp's XXXXXX-template collision path entirely (seen to fail
# with "File exists" in some shell environments); PID+timestamp is unique
# enough for a single-invocation temp file. The combined trap set at the
# top of the script cleans this up on exit, including on failure.
MD_FILE="$SCRIPT_DIR/wp2shell-report-$$-$(date +%s).md"
: > "$MD_FILE"

{
cat <<EOF
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
| Check | Result |
|---|---|
| \`${T_POSTS}\` with invalid \`post_status\` | ${n_invalid} |
| Suspicious \`customize_changeset\` rows (any status) | ${n_changesets} |
| Forged \`nav_menu_item\` rows | ${n_navmenu} |
| \`${T_POSTMETA}\` rows referencing \`example.invalid\` | ${n_postmeta} |
| Orphaned \`${T_USERMETA}\` rows | ${n_orphans} |
| Suspicious \`<prefix>_<hex>\`-style usernames | ${n_suspusers} |

**Invalid post_status row IDs:**
$(md_list $invalid)

**Suspicious changeset row IDs:**
$(md_list $changesets)

**Forged nav_menu_item row IDs:**
$(md_list $navmenu)

**${T_POSTMETA} rows referencing example.invalid (post IDs):**
$(md_list $postmeta)

**Orphaned ${T_USERMETA} user IDs:**
$(md_list $orphans)

**Suspicious usernames found (ID:user_login — matched via user_login or display_name):**
$(md_list $suspusers)

**Assessment:** the invalid-\`post_status\` check is the single highest-confidence signal in this entire report when the status values involved are actually unrecognized — WordPress core cannot natively produce a \`post_status\` outside its known set, and this check's whitelist also excludes WooCommerce's own standard order statuses (\`wc-completed\`, \`wc-pending\`, etc.), which otherwise produced a confirmed false positive at real-world scale (hundreds of thousands of legitimate order rows on one site). If this count is still non-zero, check the \`== post_status breakdown for anomaly review ==\` block printed during the audit (not written to this report) before treating it as compromise — a handful of distinct statuses each covering many rows reads as another plugin's own post type, not forged content; a status on exactly one or two rows, or one that looks like random/injected text rather than a plugin's naming convention, is the more suspicious shape. This does not depend on debug logging or any other environment-specific configuration, unlike Sections 2 and 3. The changeset check is no longer filtered to \`post_status = 'publish'\` — a forged changeset can sit in any status, including the transient \`auto-draft\` state this post type normally uses, so restricting to published rows let real forgeries through undetected. The \`nav_menu_item\` and \`postmeta\` checks target the same \`2020-01-01 00:00:00\` / \`example.invalid\` signature in other tables the exploit is known to touch — like the invalid-\`post_status\` check, these do not depend on debug logging. The suspicious-username check flags any \`user_login\` or \`display_name\` matching \`<prefix>_<hex-string>\` (e.g. \`wp2_74cc526ddf49\`, \`wpsvc_a1b2c3d4e5f6\`) — the throwaway-admin naming convention observed in the reference incident. Only \`user_login\`/\`display_name\` are checked; \`user_email\` is intentionally excluded. A non-zero result here is high-confidence on its own — this pattern does not occur in normal WordPress usage.
DBEOF
fi)

---

## 5. Confidence Assessment

- Section 4 (Database) results are the most reliable — they don't depend on log retention or debug-logging configuration.
- Section 3 (PHP error log) results corroborate Section 4 but can under-report on environments where verbose error logging is off.
- Section 2 (Nginx) is complete for the log retention window fetched by \`terminus logs:get\`, but a fully clean Section 2 does not rule out compromise if Sections 3/4 are non-zero — it means the later attack stages left no nginx-visible trace in this window, not that they didn't happen.
- Standard nginx access logs never capture POST body content. A \`rest_route=/batch/v1\` reference, a nested privileged write, or an \`author_exclude\` payload sent entirely inside a POST body (rather than the URL/query string) is structurally invisible to every check in Section 2 — this is a data-source limit, not a detection gap that a different grep would close.
EOF
} > "$MD_FILE"

DOC_TITLE="wp2shell Security Audit — ${REPORT_SITE} (${REPORT_DATE})"
GOOGLE_DOC_GENERATOR="$SCRIPT_DIR/lib/generate_google_doc.py"

echo
echo "== Stage 1 complete — not yet published =="
echo "Report saved to: $MD_FILE"
echo
echo "Next: run Stage 2 (LLM anomaly review of the recent-users block above),"
echo "insert the findings into that file, then publish once via:"
echo "  python3 \"$GOOGLE_DOC_GENERATOR\" --input \"$MD_FILE\" --title \"$DOC_TITLE\" --delete-after"
echo "See SKILL.md Stage 3 for exactly where the findings go in the file."
[[ ! -f "$GOOGLE_DOC_GENERATOR" ]] && echo "Note: generator not found at $GOOGLE_DOC_GENERATOR — check lib/ wasn't stripped out of this checkout." >&2

[[ "$flag" -gt 0 ]] && exit 2 || exit 0
