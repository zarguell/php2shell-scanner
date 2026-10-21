#!/bin/bash
# Build vulnerable-app fleet images: real project code on php:8.5.11-apache.
# Usage: ./tests/lab/build-vuln-fleet.sh   (reads /tmp/fleet-apps/*)
# NOTE: mediawiki/nextcloud sources are huge (500M/800M) — their images are
# built on demand only; wordpress/roundcube/matomo/drupal build in minutes.
set -euo pipefail
SRC=/tmp/fleet-apps
for app in "$@"; do
  [ -d "$SRC/$app" ] || { echo "SKIP $app (no source in $SRC/$app)"; continue; }
  ctx=$(mktemp -d)
  mkdir -p "$ctx/docroot"
  case $app in
    drupal) cp -r "$SRC/$app/web/." "$ctx/docroot/" ;;
    *) cp -r "$SRC/$app/." "$ctx/docroot/" ;;
  esac
  rm -f "$ctx/docroot/.htaccess"  # stock php:8.5.11-apache lacks rewrite by default
  cat > "$ctx/Dockerfile" <<'EOF'
FROM php:8.5.11-apache
RUN a2enmod rewrite && echo 'display_errors=On\nlog_errors=Off\nexpose_php=On\nsession.upload_progress.enabled=1' > /usr/local/etc/php/conf.d/zz-lab.ini
COPY docroot/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EOF
  echo "== building php2shell-fleet/$app:8.5.11"
  docker build -q -t "php2shell-fleet/$app:8.5.11" "$ctx"
  rm -rf "$ctx"
done
docker images 'php2shell-fleet/*' --format '{{.Repository}}:{{.Tag}} ({{.Size}})'
