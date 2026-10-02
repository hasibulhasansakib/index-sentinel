=== Index Sentinel – SEO Spam & Malware Monitor ===
Contributors: hasibulhasanshakib
Donate link: https://hasibulhasansakib.com/
Tags: seo spam, malware scanner, japanese keyword hack, search console, security
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Catch SEO spam hacks before Google does. Malware scan, Googlebot cloaking check, Google index monitor, spam clean-up tracking and login protection.

== Description ==

**Index Sentinel watches the two things an SEO spam hack attacks: your files and your Google results.**

SEO spam hacks, such as the "Japanese keyword hack", hide thousands of fake pages on a site. They often show the spam only to Googlebot, so the owner sees nothing wrong while Google fills up with junk pages and the real pages lose their rankings. Index Sentinel was built after cleaning exactly this kind of hack. It checks for the infection, checks what Google really sees, and tracks the clean-up until Google forgets the spam.

= What it checks =

* **Malware and file integrity.** WordPress core and WordPress.org plugins are compared with their official checksums. Your own plugins and themes are compared with a trusted baseline, so any new or changed file stands out. Every other PHP file is checked against malware patterns.
* **Hacker tricks.** PHP code hidden inside images or fonts, hidden PHP files, PHP inside the uploads folder and the "folder inside a folder of the same name" layout used by spam hacks.
* **The database.** Injected scripts, hidden iframes, Japanese spam text in posts and new administrator accounts.
* **What Google sees (cloaking check).** Every hour the homepage is fetched the way Googlebot fetches it and checked for spam text and hidden links.
* **Google index (optional, via Site Kit by Google).** Which of your pages are indexed, sitemap status, and every URL that got impressions in Google. A URL that is not yours shows up in "Unknown URLs" the day Google starts showing it, which is the earliest warning of a new spam injection.
* **Spam clean-up progress.** Add the URL pattern of a past hack and see, from your server log, how many spam URLs Googlebot re-checks every day and finds gone. Matching URLs can answer "410 Gone" so Google drops them faster.
* **Traffic insights.** Visits by Googlebot, Bingbot and AI search bots (ChatGPT, Claude, Perplexity), hacker probes and the most requested missing pages, read from the server access log.
* **Login protection.** Too many failed logins from one IP locks it out. Every login is logged, and you get an email the moment a new administrator appears.
* **Hardening.** One-click switches to hide usernames, stop author scans, disable XML-RPC, hide the WordPress version and use generic login errors, plus a checklist that explains each fix.

= Built to be calm and clear =

* One dashboard with a 0–100 score and a card for each area.
* Daily automatic checks and an hourly Googlebot check. You only get an email when something serious and new is found, never the same alert twice.
* Quarantine suspicious files with one click and restore them just as easily.
* Every module can be switched off.
* WP-CLI commands for agencies and developers.
* No account, no API key, no tracking, no ads.

= WP-CLI =

`wp index-sentinel scan|google|traffic|cloak|daily|accept-baseline`

= For developers =

Index Sentinel is built to be extended. Useful hooks: `index_sentinel_loaded`, `index_sentinel_tabs`, `index_sentinel_render_tab_{id}`, `index_sentinel_signatures`, `index_sentinel_scan_findings`, `index_sentinel_hardening_checks`, `index_sentinel_spam_patterns`, `index_sentinel_firewall_probes`, `index_sentinel_score` and `index_sentinel_daily_jobs`.

Source code and issues: [github.com/hasibulhasansakib/index-sentinel](https://github.com/hasibulhasansakib/index-sentinel)

== External services ==

Index Sentinel only contacts the services below, only for the checks described, and never sends personal data or tracking information.

* **WordPress.org checksum API** (`api.wordpress.org` and `downloads.wordpress.org`). During a scan the plugin downloads the official checksums for your WordPress version and for each installed plugin from WordPress.org, so it can tell whether files were modified. Only the WordPress version, locale, plugin slugs and plugin versions are sent. [Terms](https://wordpress.org/about/privacy/)
* **Google Search Console API** (only if you use Site Kit by Google and connected it to Search Console). Index Sentinel uses Site Kit's existing connection to read your sitemap status, URL Inspection results and search performance by page. URLs of your own site are sent to Google. [Google Terms](https://policies.google.com/terms), [Privacy](https://policies.google.com/privacy)
* **Your own site.** The cloaking check and the hardening checklist request your own homepage (with a Googlebot user agent) and your own REST API to see what visitors and search engines receive.

== Installation ==

1. Install from Plugins > Add New (search for "Index Sentinel"), or upload the plugin folder to `/wp-content/plugins/`.
2. Activate the plugin.
3. Open **Index Sentinel** in the admin menu and click **Run full scan**.
4. Optional: if your site was hit by an SEO spam hack, add the spam URL pattern in Settings (one click adds the common Japanese keyword hack pattern).
5. Optional: install **Site Kit by Google** and connect Search Console to see your Google index status.
6. Send a test alert email from Settings. Everything else runs automatically.

== Frequently Asked Questions ==

= Does Index Sentinel remove malware automatically? =

No. It finds suspicious files and lets you move each one into a locked quarantine folder with one click (and restore it if it was a false alarm). Automatic deletion can break a site, so you stay in control.

= What is the Japanese keyword hack? =

It is an SEO spam hack that creates thousands of fake pages, often with Japanese text, at URLs such as `/word/word/abc123xyz.html`. The pages are usually shown only to Google. Index Sentinel's cloaking check, Unknown URLs report and spam clean-up tracker were built for exactly this hack.

= Do I need Site Kit by Google? =

Only for the Google Index tab. Everything else works without it. Index Sentinel uses Site Kit's existing Search Console connection, so there is no extra login or API key.

= Where does the traffic data come from? =

From your server's access log. On cPanel hosting the log is found automatically. On other hosts you can enter the log path in Settings. If no log is available, the traffic tab simply stays empty.

= Will the firewall or login lockout block me? =

The firewall only blocks obvious attack requests (secret files, web shells, SQL injection strings). The lockout only triggers after several failed logins in 15 minutes and expires on its own. Both can be switched off.

= Will this slow down my site? =

No. Scans and log analysis run in the background once a day. On normal page views only a few fast checks run.

= Does it work behind Cloudflare? =

Yes. With "Site is behind Cloudflare" enabled, the real visitor IP is used, but only for requests that really come from Cloudflare's network.

= Does it work on multisite? =

Version 1.0 is built and tested for single sites.

== Screenshots ==

1. Overview: security score, malware, cloaking, Google index, spam clean-up, logins and hardening at a glance.
2. Malware scan with one-click quarantine.
3. Google Index: sitemaps, unknown URLs and the index status of every page.
4. Traffic & Spam: Googlebot re-checking old spam URLs, bots, probes and missing pages.
5. Hardening checklist with clear fixes.
6. Settings: modules, hardening switches, spam URL patterns, alerts and log path.

== Changelog ==

= 1.0.0 =
* First public release.

== Upgrade Notice ==

= 1.0.0 =
First public release.
