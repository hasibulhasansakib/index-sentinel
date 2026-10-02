# Changelog

All notable changes to Index Sentinel are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-02

### Added
- Malware and file-integrity scan: WordPress core and WordPress.org plugins vs. official checksums, custom code vs. a trusted baseline, malware signatures.
- Detection of SEO spam hack tricks: PHP in media/font files, hidden PHP files, PHP in uploads, self-nested folders.
- Database checks: injected scripts, hidden iframes, Japanese spam text, new administrators.
- Hourly Googlebot cloaking check.
- Google index monitoring through Site Kit by Google: URL Inspection, sitemaps, unknown URLs with impressions, known-spam trend.
- Access log analysis: spam clean-up progress, search and AI bots, hacker probes, top 404s.
- Firewall for exploit probes and optional 410 Gone for spam URL patterns.
- Login lockout, login log and new-administrator alerts.
- Hardening switches and a security checklist.
- One-click quarantine and restore.
- Email alerts (each problem sent once), dashboard widget, WP-CLI commands.
