#!/bin/sh
set -e
if ! getent group licd >/dev/null 2>&1; then groupadd --system licd 2>/dev/null || addgroup -S licd; fi
if ! getent passwd licd >/dev/null 2>&1; then useradd --system --gid licd --home-dir /var/lib/licd --shell /usr/sbin/nologin licd 2>/dev/null || adduser -S -G licd -h /var/lib/licd -s /sbin/nologin licd; fi
install -d -m 0750 -o root -g licd /etc/licd
install -d -m 0700 -o licd -g licd /etc/licd/secrets
install -d -m 0750 -o root -g licd /etc/licd/tls
install -d -m 0750 -o licd -g licd /var/lib/licd /var/lib/licd/archive /var/lib/licd/backups /var/lib/licd/restores /var/lib/licd/recovery-drills
install -d -m 0750 -o licd -g licd /var/log/licd
if [ ! -e /etc/licd/licd.env ]; then install -m 0640 -o root -g licd /dev/null /etc/licd/licd.env; fi
