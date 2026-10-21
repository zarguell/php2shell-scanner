# Affected products — php2shell (CVE-2026-109618 / CVE-2026-109619)

> Machine-readable inventory of **confirmed-impact** products only.
> Excludes the thousands of NCSC-NL `Investigation` leads (PHP dependency
> present, CVE match unknown). Every row below has either a researcher
> RCE/memory-disclosure demonstration or a vendor/distro advisory confirming
> impact. Last verified: 2026-10-21 (UTC).

## Schema

Each row in `Table 1` is one record. Parse by splitting the pipe table;
`N/A` means no value exists (not "unknown" — unknown rows are excluded).

| Column | Type | Allowed values / format |
|---|---|---|
| `Product` | string | Human product name |
| `Vendor` | string | Human vendor/org name |
| `CPE` | string | CPE 2.3 (`cpe:2.3:…`) or `N/A` if none assigned |
| `Affected` | string | Vulnerable version/range, or `all` |
| `Fixed` | string | Fixed build, or `pending` / `see advisory` |
| `Status` | enum | `vulnerable` \| `fixed` \| `fix-pending` |
| `Evidence` | enum | `researcher-rce` (pre-auth RCE demoed) \| `vendor-confirmed` \| `distro-confirmed` \| `core-at-risk` (upstream SAPI statement) |
| `Vendor advisory` | URL or `N/A` | Primary vendor/distro/upstream source |
| `Community ref` | URL or `N/A` | Independent demo/writeup confirming impact |

Rules:

- One product-version-line per row; a product with separate fixed builds per
  branch gets one row per branch.
- `Status=vulnerable` means a vendor/researcher confirms impact on that line
  and no fix is recorded for it. `fix-pending` means vendor confirms impact
  and a fix is announced but not yet shipped. `fixed` means the listed build
  contains the backport/upstream fix.
- `Evidence=researcher-rce` rows inherit the underlying PHP-core flaw; the app
  version listed is the exact build the RCE was demonstrated against.

Upstream core fact (applies to all rows): PHP 5.4.0–8.5.11 affected; fixed in
8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. All web SAPIs at risk (FPM, mod_php,
php-cgi, FrankenPHP, LiteSpeed); mod_php highest risk (pre-application-code
trigger). Source: PHP security advisory 2026-10-21-5; CERT-EU 2026-018.

## Table 1 — confirmed impacted products

| Product | Vendor | CPE | Affected | Fixed | Status | Evidence | Vendor advisory | Community ref |
|---|---|---|---|---|---|---|---|---|
| PHP | PHP Group | `cpe:2.3:a:php:php:*:*:*:*:*:*:*:*` | 5.4.0–8.5.11 (8.5.x < 8.5.12, 8.4.x < 8.4.27, 8.3.x < 8.3.36, 8.2.x < 8.2.35; 8.1 and older EOL, source backports for 7.4/8.0/8.1 only) | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | fixed | vendor-confirmed | https://www.php.net/archive/2026.php#2026-10-21-5 | https://cert.europa.eu/publications/security-advisories/2026-018/ |
| WordPress 7.1.2 | WordPress project | `cpe:2.3:a:wordpress:wordpress:7.1.2:*:*:*:*:*:*:*` | 7.1.2 on unpatched PHP | update PHP to fixed build (app code unchanged) | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| WordPress (latest container at test time) | WordPress project / Docker | `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*` | `wordpress:latest` on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://www.wiz.io/blog/php2shell-php-rce |
| Drupal 11.4.3 | Drupal project | `cpe:2.3:a:drupal:drupal:11.4.3:*:*:*:*:*:*:*` | 11.4.3 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Drupal (latest container at test time) | Drupal project / Docker | `cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*` | `drupal:latest` on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://www.wiz.io/blog/php2shell-php-rce |
| Joomla 6.1.4 | Joomla project | `cpe:2.3:a:joomla:joomla:6.1.4:*:*:*:*:*:*:*` | 6.1.4 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Joomla (latest container at test time) | Joomla project / Docker | `cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*` | `joomla:latest` on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://www.wiz.io/blog/php2shell-php-rce |
| MediaWiki 1.46.2 | Wikimedia Foundation | `cpe:2.3:a:mediawiki:mediawiki:1.46.2:*:*:*:*:*:*:*` | 1.46.2 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Roundcube 1.7.4 | Roundcube project | `cpe:2.3:a:roundcube:webmail:1.7.4:*:*:*:*:*:*:*` | 1.7.4 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Magento 2.4.9 | Adobe / Magento | `cpe:2.3:a:magento:magento:2.4.9:*:*:*:*:*:*:*` | 2.4.9 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| phpMyAdmin 5.2.3 | phpMyAdmin project | `cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.3:*:*:*:*:*:*:*` | 5.2.3 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Nextcloud 35.0.1 | Nextcloud GmbH | `cpe:2.3:a:nextcloud:nextcloud_server:35.0.1:*:*:*:*:*:*:*` | 35.0.1 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Laravel 13.11 | Laravel project | `cpe:2.3:a:laravel:laravel:13.11:*:*:*:*:*:*:*` | 13.11 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Symfony 8.1 | Symfony project | `cpe:2.3:a:symfony:symfony:8.1:*:*:*:*:*:*:*` | 8.1 on unpatched PHP | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| WHMCS (self-hosted) | WHMCS Ltd. | `cpe:2.3:a:whmcs:whmcs:*:*:*:*:*:*:*:*` | all on unpatched PHP (demoed version not numbered) | update PHP to fixed build | vulnerable | researcher-rce | N/A | https://calif.io/php2shell/ |
| Plesk for Linux (shipped PHP) | Plesk (WebPros) | `cpe:2.3:a:plesk:plesk:*:*:*:*:*:*:*:*` | all shipped PHP (8.2–8.5 + EOL 7.4/8.0/8.1) | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (Linux); EOL rebuilds dated 2026-10-21 | fixed | vendor-confirmed | https://support.plesk.com/hc/en-us/articles/44397729587351 | https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_p.md |
| Plesk for Windows (shipped PHP) | Plesk (WebPros) | `cpe:2.3:a:plesk:plesk:*:*:*:*:*:*:*:*` | all shipped PHP (8.2–8.5) | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (Windows) | fixed | vendor-confirmed | https://support.plesk.com/hc/en-us/articles/44397729587351 | https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_p.md |
| Plesk sw-engine / plesk-engine (internal UI PHP) | Plesk (WebPros) | `cpe:2.3:a:plesk:plesk:*:*:*:*:*:*:*:*` | all versions | pending: hotfix 18.0.80#11 / 18.0.81#4 | fix-pending | vendor-confirmed | https://support.plesk.com/hc/en-us/articles/44397729587351 | N/A |
| cPanel EasyApache 4 / MultiPHP | WebPros / cPanel | `cpe:2.3:a:cpanel:cpanel:*:*:*:*:*:*:*:*` | ea-php 5.0+ (EA4 pre-25.91) | EA4 25.91: ea-php82 8.2.35, ea-php83 8.3.36, ea-php84 8.4.27, ea-php85 8.5.12; vendor backports ea-php74/80/81 | fixed | vendor-confirmed | https://support.cpanel.net/hc/en-us/articles/44397389677335 | https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_w.md |
| cPanel internal PHP (hooks/AppConfig) | WebPros / cPanel | `cpe:2.3:a:cpanel:cpanel:*:*:*:*:*:*:*:*` | pre-136.0.50 cpanel-php84 | cPanel & WHM 136.0.50 (cpanel-php84 8.4.27); also 11.110.0.153 / 11.134.0.66 / 11.138.0.18 / WP Squared 11.138.1.17 | fixed | vendor-confirmed | https://support.cpanel.net/hc/en-us/articles/44397389677335 | https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_w.md |
| Coolify (self-hosted) | Coolify (coollabsio) | N/A | pre-emergency-release Coolify (PHP runtime unpatched) | pending: emergency Coolify release (2026-10-21, post-PHP-patch) | fix-pending | vendor-confirmed | https://coolify.io/docs/knowledge-base/php-security-advisory-2026 | https://github.com/coollabsio/coolify/issues/12266 |
| PAN-OS | Palo Alto Networks | `cpe:2.3:a:palo_alto_networks:pan-os:*:*:*:*:*:*:*:*` | all | pending (ETA TBD) | fix-pending | vendor-confirmed | https://security.paloaltonetworks.com/CVE-2026-109618 | https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/ |
| Panorama | Palo Alto Networks | `cpe:2.3:a:palo_alto_networks:panorama:*:*:*:*:*:*:*:*` | all | pending (ETA TBD) | fix-pending | vendor-confirmed | https://security.paloaltonetworks.com/CVE-2026-109618 | https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_p.md |
| Passbolt (self-hosted API on unpatched PHP) | Passbolt SA | N/A | all Passbolt on PHP < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | Docker/AMI/OVA patched 2026-10-21; Cloud fixed; distro installs via OS PHP update; Helm rollout in progress at advisory time | fixed | vendor-confirmed | https://www.passbolt.com/incidents/critical-php-vulnerabilities-cvss-9-2 | https://github.com/passbolt/passbolt_docker/releases |
| Ubuntu php8.1 (jammy) | Canonical | `cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*` | < 8.1.2-1ubuntu2.28 | 8.1.2-1ubuntu2.28 (USN-8948-1/2) | fixed | distro-confirmed | https://ubuntu.com/security/CVE-2026-109618 | N/A |
| Ubuntu php8.3 (noble) | Canonical | `cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:lts:*:*:*` | < 8.3.6-0ubuntu0.24.04.13 | 8.3.6-0ubuntu0.24.04.13 (USN-8948-1/2) | fixed | distro-confirmed | https://ubuntu.com/security/CVE-2026-109618 | N/A |
| Ubuntu php8.5 (resolute / stonking) | Canonical | N/A | < 8.5.4-0ubuntu1.5 (resolute), < 8.5.9-0ubuntu2.1 (stonking) | 8.5.4-0ubuntu1.5 / 8.5.9-0ubuntu2.1 | fixed | distro-confirmed | https://ubuntu.com/security/CVE-2026-109618 | N/A |
| Ubuntu ESM PHP (trusty/xenial/bionic/focal) | Canonical | N/A | php5/7.0/7.2/7.4 pre-ESM builds | 5.5.9+dfsg-1ubuntu4.29+esm18, 7.0.33-0ubuntu0.16.04.16+esm22, 7.2.24-0ubuntu0.18.04.17+esm14, 7.4.3-4ubuntu2.29+esm5 (Ubuntu Pro) | fixed | distro-confirmed | https://ubuntu.com/security/CVE-2026-109618 | N/A |
| Debian php8.2 (bookworm) | Debian | `cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*` | 8.2.32-1~deb12u1 | 8.2.35-1~deb12u1 (DLA-4848-1) | fixed | distro-confirmed | https://security-tracker.debian.org/tracker/CVE-2026-109618 | N/A |
| Debian php8.4 (trixie) | Debian | `cpe:2.3:o:debian:debian_linux:13:*:*:*:*:*:*:*` | 8.4.24-1~deb13u1 | 8.4.27-1~deb13u1 (DSA-6574-1) | fixed | distro-confirmed | https://security-tracker.debian.org/tracker/CVE-2026-109618 | N/A |
| Red Hat PHP streams | Red Hat | `cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*` | affected (see RHSA) | see RHSA-2026:87079 / RHSA-2026:87080 (incl. php:7.4 stream rebuild) | fixed | distro-confirmed | https://access.redhat.com/errata/RHSA-2026:87079 | https://access.redhat.com/security/cve/cve-2026-109618 |
| AlmaLinux PHP streams (8/9/10) | AlmaLinux | N/A | all shipped streams incl. retired 7.2/7.3/8.0/8.1 | testing 2026-10-21 17:50 UTC (e.g. 8.2.33-1.el8 Alma rebuild w/ backport; 7.4 stream direct to production); restart php-fpm/httpd; production release pending verification | fix-pending | distro-confirmed | https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/ | N/A |
| Google Cloud serverless PHP runtimes | Google Cloud | N/A | PHP on App Engine / Cloud Run / Cloud Functions / GKE custom images, pre-patch | patched base images rolling out; PHP 8.2+ auto-patched where auto-update on, else rebuild+redeploy; 8.1 and older must upgrade to 8.2+ | fix-pending | vendor-confirmed | https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619 | N/A |
| FrankenPHP (PHP SAPI) | FrankenPHP project | N/A | all on unpatched PHP core | update embedded PHP to fixed build | vulnerable | core-at-risk | https://www.php.net/archive/2026.php#2026-10-21-5 | https://github.com/php/frankenphp/issues/2732 |

## Explicitly out of scope (not listed above)

- NCSC-NL `software_list_*.md` rows with `Investigation` status (PHP
  dependency confirmed, CVE match unknown): WooCommerce, Shopware, phpBB,
  PrestaShop, Roundcube-as-packaged, and hundreds more. Treat as leads, not
  confirmed impact. Source: https://github.com/NCSC-NL/php2shell/tree/main/software
- WAF/CDN mitigations (Cloudflare, Fastly, Google Cloud Armor): stopgaps, not
  product fixes.
- Dev/CI-only PHP tooling (Composer plugins, PHPStan, PHPUnit): runs outside a
  web SAPI; not remote-exploitable via this path.

## Sources

- PHP: https://www.php.net/archive/2026.php#2026-10-21-5 ·
  GHSA-w8hw-w9fx-j79w (618) · GHSA-6wmf-4rv5-p3rp (619)
- Calif writeup + version list: https://calif.io/php2shell/
- Wiz writeup + container demos: https://www.wiz.io/blog/php2shell-php-rce
- Sansec: https://sansec.io/research/php2shell (Magento 2.4.9 + 10 apps)
- JFrog: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- CERT-EU 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018/
- NCSC-NL inventory: https://github.com/NCSC-NL/php2shell
- Tenable FAQ: https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote
