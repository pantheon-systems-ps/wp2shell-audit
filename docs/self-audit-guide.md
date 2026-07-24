# Self-Audit Guide: Checking Your WordPress Site for the wp2shell Vulnerability Chain (CVE-2026-60137 / CVE-2026-63030)

**Scope: This guide is for detection only.** It does not cover remediation. If any step below flags a positive result, stop and contact Pantheon Support or your security team before taking any action — do not delete users, posts, or files based on this guide alone.

This guide walks through the same checks as `scripts/wp2shell-audit.sh`, done by hand — no script download, no Claude, just WP-Admin and copy-pasteable Terminus commands. If you'd rather run the script itself, see the main [README](../README.md).

## Background

On 2026-07-17, WordPress issued an emergency patch (6.8.6 / 6.9.5 / 7.0.2) for a chained vulnerability: an unauthenticated SQL injection (CVE-2026-60137) combined with a REST API route-confusion bug (CVE-2026-63030). Wordfence disclosed exploitation details on 2026-07-20. If your site is not yet on a patched core version, update first — but patching doesn't tell you whether you were already compromised before the update.

## Step 1: Confirm your WordPress version is patched

In `wp-admin`, go to **Dashboard → Updates**. Confirm you're on 6.8.6, 6.9.5, 7.0.2, or later. If not, update core now — this closes the hole but does not undo any prior compromise.

## Step 2: Review user accounts

1. Go to **Users → All Users**.
2. Click the **Administrator** filter link at the top of the list (above the table, next to "All"). Review every account there — a planted admin account is the single most urgent finding this guide can produce, and it's normal for this list to be short, so give it your full attention.
3. Back on **All Users**, click the **Registered** column header to sort by most recent first, and review the most recent 50–100 accounts for anything that breaks the pattern of your normal users:
   - A `Username` that looks like a random string of letters/numbers (e.g., `x7f2a9b1c4d`) rather than a real name.
   - An email address on a disposable/throwaway domain (e.g., mailinator.com, guerrillamail.com, or similar).
   - Several accounts registered within minutes of each other that don't match your normal onboarding pattern.
   - Any account registered on or right after 2026-07-17–2026-07-20 (the disclosure window) that you don't recognize.
4. A single account with a mismatched name/email (e.g., a staff member's old login paired with a new email after a name change) is common and not on its own suspicious — only flag accounts matching the *specific* patterns above.

## Step 3: Review site logs (requires Terminus CLI access)

If you or your development team have Terminus installed and authenticated (`terminus auth:login`), you can pull and search your own logs:

```
terminus logs:get <site>.<env> --all /path/to/local/logs
```

Then search the downloaded logs for these patterns:

```
# Elevated hits to the batch/v1 REST route — near-zero before this CVE's disclosure
zgrep -Ec '(\?rest_route=/batch/v1|/wp-json/batch/v1)' /path/to/local/logs/*/nginx-access.log*

# author_exclude SQL injection payload (non-numeric value) — also matches the
# author.exclude / author exclude WAF-evasion spellings, which PHP folds into
# the same parameter when parsing. A legitimate value is always digits/commas.
zgrep -oiE 'author([._+]|%20)exclude=[^&" ]*' /path/to/local/logs/*/nginx-access.log* | grep -viE '=([0-9]|%2c|,)*$'

# Nested privileged REST write via batch (e.g. creating an administrator, or
# installing a plugin, smuggled inside a batch sub-request) — this only
# catches the GET-based variant; see the note below.
zgrep -i 'batch/v1' /path/to/local/logs/*/nginx-access.log* | grep -icE 'wp/v2/users|wp/v2/plugins'

# Plugin-upload POST requests via wp-admin
zgrep -c 'update.php?action=upload-plugin' /path/to/local/logs/*/nginx-access.log*

# User-deletion cleanup calls (attacker covering tracks)
zgrep -oE 'delete_user=[a-z0-9_]+' /path/to/local/logs/*/nginx-access.log* | sort -u

# SQL injection error signature (CVE-2026-60137) — requires WP_DEBUG_LOG enabled
zgrep -c 'post_author NOT IN' /path/to/local/logs/*/php-error.log*

# REST route-confusion signature (CVE-2026-63030) — requires WP_DEBUG_LOG enabled
zgrep -c 'Constant REST_REQUEST already defined' /path/to/local/logs/*/php-error.log*
```

Any non-zero result on the batch/v1, author_exclude, nested-write, plugin-upload, or delete_user checks is worth investigating further. The PHP error log checks only work if verbose debug logging was enabled at the time — a zero result there doesn't clear the site on its own; treat Step 4 as more reliable.

**A note on what these logs can't show you:** standard nginx access logs never capture POST body content. If the batch endpoint, the author_exclude payload, or a nested privileged write was sent entirely inside a POST body rather than the URL/query string, none of the above greps will see it. A clean result here reduces confidence in an attack, it doesn't rule one out — Step 4 is not affected by this limitation.

## Step 4: Check the database directly (requires Terminus + WP-CLI access)

This is the most reliable set of checks — it doesn't depend on log retention or debug settings, because WordPress cannot produce these results through normal operation.

First, find your table prefix (skip plugins/themes so nothing on your site can interfere with this lookup):

```
terminus wp <site>.<env> -- config get table_prefix --skip-plugins --skip-themes
```

Use the value returned (commonly `wp_`, but yours may be customized) in place of `wp_` below.

**List every administrator-role account, by registration date** (a nonzero count is normal — every site has admins — this is a priority list for Step 2, not a flag on its own):

```
terminus wp <site>.<env> -- db query "
  SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name
  FROM wp_users u
  JOIN wp_usermeta um ON um.user_id = u.ID
  WHERE um.meta_key = 'wp_capabilities'
    AND um.meta_value LIKE '%administrator%'
  ORDER BY u.user_registered DESC;" --skip-plugins --skip-themes
```

**Check for injected posts with an invalid status** (this cannot happen through normal WordPress use — any result here is high-confidence evidence of injected data):

```
terminus wp <site>.<env> -- db query "
  SELECT ID FROM wp_posts WHERE post_status NOT IN (
    'publish','future','draft','pending','private','trash',
    'auto-draft','inherit',
    'request-pending','request-confirmed','request-failed','request-completed',
    'acf-disabled'
  );" --skip-plugins --skip-themes
```

**Check for forged "changeset" posts** (a known artifact of this exploit chain). This check is deliberately **not** filtered to `post_status = 'publish'` — a forged changeset can sit in any status, including `auto-draft`, which is a normal transient state for this post type. Restricting to published rows would let real forgeries through undetected:

```
terminus wp <site>.<env> -- db query "
  SELECT ID FROM wp_posts WHERE post_type = 'customize_changeset'
    AND (post_date = '2020-01-01 00:00:00' OR post_content LIKE '%example.invalid%');" --skip-plugins --skip-themes
```

**Check for forged navigation menu items** (the same exploit signature, in a different post type):

```
terminus wp <site>.<env> -- db query "
  SELECT ID FROM wp_posts WHERE post_type = 'nav_menu_item'
    AND post_date = '2020-01-01 00:00:00';" --skip-plugins --skip-themes
```

**Check for malicious metadata referencing the payload URL** (this can appear on any post, not just changesets or menu items):

```
terminus wp <site>.<env> -- db query "
  SELECT DISTINCT post_id FROM wp_postmeta WHERE meta_value LIKE '%example.invalid%';" --skip-plugins --skip-themes
```

**Check for orphaned user-meta rows** (leftover data from a deleted attacker account):

```
terminus wp <site>.<env> -- db query "
  SELECT um.user_id FROM wp_usermeta um
  LEFT JOIN wp_users u ON u.ID = um.user_id
  WHERE u.ID IS NULL LIMIT 20;" --skip-plugins --skip-themes
```

**Check for throwaway-admin-style usernames** (pattern: `<word>_<hex string>`, e.g. `wp2_74cc526ddf49`):

```
terminus wp <site>.<env> -- db query "
  SELECT CONCAT(ID, ':', user_login)
  FROM wp_users
  WHERE user_login REGEXP '^[a-z0-9]+_[0-9a-f]{6,}\$'
     OR display_name REGEXP '^[a-z0-9]+_[0-9a-f]{6,}\$';" --skip-plugins --skip-themes
```

Each of these (other than the administrator-list query, which is context, not a flag) should return no rows on a clean site. Any row returned is a finding, not a false positive — WordPress does not produce these values on its own.

## Step 4b: If your site is a WordPress Multisite (WPMS) network

**Every query above only checked your main site.** A multisite network's other subsites have their own separate tables — WordPress's own convention: the main site (blog ID 1) uses the unprefixed tables above (`wp_posts`, etc.), but every other subsite has its own set, named `wp_<blog_id>_posts`, `wp_<blog_id>_postmeta`, and so on. If you don't repeat the checks against those tables too, a compromised subsite's forged content is invisible — not just under-reported, completely missed.

First, list every subsite and its blog ID:

```
terminus wp <site>.<env> -- site list --fields=blog_id,url --skip-plugins --skip-themes
```

If this errors out ("not a multisite installation" or similar), your site isn't WPMS — skip this section, Step 4's checks already covered everything. Otherwise, for **each** blog ID returned (other than `1`, which you already checked above), repeat the four post/postmeta queries from Step 4 with that blog's own table names substituted in — e.g. for blog ID `5`, the invalid-`post_status` check becomes:

```
terminus wp <site>.<env> -- db query "
  SELECT ID FROM wp_5_posts WHERE post_status NOT IN (
    'publish','future','draft','pending','private','trash',
    'auto-draft','inherit',
    'request-pending','request-confirmed','request-failed','request-completed',
    'acf-disabled'
  );" --skip-plugins --skip-themes
```

...and likewise for the `customize_changeset`, `nav_menu_item`, and `postmeta`/`example.invalid` checks — swap `wp_posts`/`wp_postmeta` for `wp_5_posts`/`wp_5_postmeta` (or whichever blog ID you're checking).

**Administrator accounts on a specific subsite** use a per-blog capability key instead of the shared one — for blog ID `5`, that's `wp_5_capabilities` (not `wp_capabilities`). Repeat the administrator-list query from Step 4 once per blog ID, swapping in that blog's own key:

```
terminus wp <site>.<env> -- db query "
  SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name
  FROM wp_users u
  JOIN wp_usermeta um ON um.user_id = u.ID
  WHERE um.meta_key = 'wp_5_capabilities'
    AND um.meta_value LIKE '%administrator%'
  ORDER BY u.user_registered DESC;" --skip-plugins --skip-themes
```

**Check for network Super Admins** (full control over every subsite on the network — the single highest-value target on a compromised multisite, check this first):

```
terminus wp <site>.<env> -- db query "
  SELECT meta_value FROM wp_sitemeta WHERE meta_key = 'site_admins';" --skip-plugins --skip-themes
```

This returns one PHP-serialized value, not a clean list — look for `s:<length>:"<username>"` entries inside it; each one is a Super Admin's username. Every WPMS network has at least one (normal), but review the full list the same way you'd review the administrator list above — a name that doesn't belong is the highest-priority finding this guide can produce.

The orphaned-usermeta and throwaway-username checks from Step 4 don't need repeating — `wp_users`/`wp_usermeta` are shared network-wide, not per-subsite, so those two queries already covered every subsite in one pass.

## Step 5: If anything comes back positive

- Do not delete the flagged posts, users, or accounts yourself.
- Do not attempt to patch, restore, or roll back on your own based on this guide.
- Contact Pantheon Support (or your Pantheon Professional Services contact) with the specific IDs/rows returned, so a full incident review and safe remediation can be scoped.
