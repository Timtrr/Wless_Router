#!/usr/bin/env bash
# Собирает /tmp/panel-installer.sh из part1.sh + payloads + part2.sh
set -euo pipefail
B=/tmp/pbuild
SRC=/tmp/pbuild-src
rm -rf "$B" && mkdir -p "$B"

cp /opt/sb-ui/app.py                          "$B/app.py"
cp /usr/local/sbin/wg-redirect.sh             "$B/wg-redirect.sh"
cp /etc/systemd/system/wg-redirect.service    "$B/wg-redirect.service"
cp /etc/systemd/system/sing-box-auto.service  "$B/sing-box-auto.service"
cp /etc/systemd/system/sb-ui.service          "$B/sb-ui.service"
gzip -9c /usr/local/bin/sing-box > "$B/sing-box.gz"

OUT=/tmp/panel-installer.sh
{
  cat "$SRC/part1.sh"
  for pair in \
    "PAYLOAD_SB:sing-box.gz" \
    "PAYLOAD_APP:app.py" \
    "PAYLOAD_WGRED:wg-redirect.sh" \
    "PAYLOAD_UNIT_WGRED:wg-redirect.service" \
    "PAYLOAD_UNIT_SINGBOX:sing-box-auto.service" \
    "PAYLOAD_UNIT_SBUI:sb-ui.service"
  do
    var=${pair%%:*}; file=${pair##*:}
    echo "$var=\""
    base64 -w 76 "$B/$file"
    echo "\""
  done
  cat "$SRC/part2.sh"
} > "$OUT"
chmod 755 "$OUT"

bash -n "$OUT" && echo "SYNTAX OK"
ls -la "$OUT"
