# ---PAYLOADS-END---

echo "==> 3/8  sing-box (встроенный бинарник)"
printf '%s' "$PAYLOAD_SB" | base64 -d | gunzip -c > /usr/local/bin/sing-box
chmod 755 /usr/local/bin/sing-box
/usr/local/bin/sing-box version | head -1

echo "==> 4/8  WireGuard-сервер"
WG_IF=hiddifywg
WG_CONF=/etc/wireguard/hiddifywg.conf
PRIV=""
OLD_PEERS=""
if [ -f "$WG_CONF" ]; then
  cp "$WG_CONF" "$WG_CONF.bak.$(date +%Y%m%d%H%M%S)"
  PRIV=$(awk -F'= ' '/^PrivateKey/{print $2; exit}' "$WG_CONF" | tr -d ' \r')
  OLD_PEERS=$(awk 'f{print} /^\[Peer\]/{f=1}' "$WG_CONF")
  echo "    существующий конфиг найден — ключ и пиры сохранены (бэкап рядом)"
fi
[ -n "$PRIV" ] || PRIV=$(wg genkey)
PUB=$(printf '%s' "$PRIV" | wg pubkey)

if [ -n "$ROUTER_PUB" ] && ! printf '%s' "$OLD_PEERS" | grep -qF "$ROUTER_PUB"; then
  OLD_PEERS="$OLD_PEERS
[Peer]
# router (Keenetic)
PublicKey = $ROUTER_PUB
AllowedIPs = 10.90.0.2/32, fd42:42:90::2/128
"
  echo "    добавлен пир-роутер (10.90.0.2)"
fi

WAN_IF=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')
WAN_IF=${WAN_IF:-eth0}

cat > "$WG_CONF" <<WGEOF
[Interface]
Address = 10.90.0.1/24, fd42:42:90::1/64
ListenPort = $WG_PORT
PrivateKey = $PRIV

PostUp = iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT
PostUp = iptables -I FORWARD -i $WAN_IF -o $WG_IF -j ACCEPT
PostUp = iptables -I FORWARD -i $WG_IF -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

PostDown = iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT
PostDown = iptables -D FORWARD -i $WAN_IF -o $WG_IF -j ACCEPT
PostDown = iptables -D FORWARD -i $WG_IF -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $WAN_IF -j MASQUERADE
$OLD_PEERS
WGEOF
chmod 600 "$WG_CONF"

systemctl restart "wg-quick@$WG_IF"
systemctl enable "wg-quick@$WG_IF" >/dev/null 2>&1 || true
if wg show "$WG_IF" >/dev/null 2>&1; then
  echo "    интерфейс $WG_IF поднят"
else
  echo "    ОШИБКА: $WG_IF не поднялся — смотри: journalctl -u wg-quick@$WG_IF -n 20"
  exit 1
fi

echo "==> 5/8  Перенаправление туннельного трафика в sing-box"
printf '%s' "$PAYLOAD_WGRED" | base64 -d > /usr/local/sbin/wg-redirect.sh
chmod 755 /usr/local/sbin/wg-redirect.sh
printf '%s' "$PAYLOAD_UNIT_WGRED" | base64 -d > /etc/systemd/system/wg-redirect.service
systemctl daemon-reload
systemctl enable --now wg-redirect >/dev/null 2>&1 || systemctl restart wg-redirect

echo "==> 6/8  sing-box"
cat > /etc/sing-box/config.json <<'SBCONF'
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [
    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 2100},
    {"type": "redirect", "tag": "redir-in", "listen": "0.0.0.0", "listen_port": 12345}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "urltest", "tag": "auto", "outbounds": ["direct"], "url": "http://www.gstatic.com/generate_204", "interval": "300s", "tolerance": 50}
  ],
  "route": {"final": "auto", "auto_detect_interface": true},
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}}
}
SBCONF
chmod 600 /etc/sing-box/config.json
/usr/local/bin/sing-box check -c /etc/sing-box/config.json
printf '%s' "$PAYLOAD_UNIT_SINGBOX" | base64 -d > /etc/systemd/system/sing-box-auto.service
systemctl daemon-reload
systemctl enable --now sing-box-auto >/dev/null 2>&1 || systemctl restart sing-box-auto
sleep 2
if systemctl is-active --quiet sing-box-auto; then
  echo "    sing-box запущен"
else
  echo "    ОШИБКА: sing-box не запустился — смотри: journalctl -u sing-box-auto -n 20"
  exit 1
fi

echo "==> 7/8  Веб-панель"
printf '%s' "$PAYLOAD_APP" | base64 -d > /opt/sb-ui/app.py
chmod 755 /opt/sb-ui/app.py
echo '{}' > /opt/sb-ui/meta.json
echo '{}' > /opt/sb-ui/clients.json

PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(9))")
SALT=$(python3 -c "import secrets; print(secrets.token_hex(16))")
HASH=$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]).encode()).hexdigest())" "$SALT" "$PW")
printf '{"user": "admin", "salt": "%s", "hash": "%s"}\n' "$SALT" "$HASH" > /opt/sb-ui/auth.json
chmod 600 /opt/sb-ui/auth.json
printf 'user: admin\npassword: %s\n' "$PW" > /opt/sb-ui/INITIAL_PASSWORD.txt
chmod 600 /opt/sb-ui/INITIAL_PASSWORD.txt

PUBLIC_IP=$(curl -4 -s --max-time 8 https://api.ipify.org || true)
[ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="<IP-СЕРВЕРА>"
printf '{"endpoint": "%s:%s"}\n' "$PUBLIC_IP" "$WG_PORT" > /opt/sb-ui/wg.json

printf '%s' "$PAYLOAD_UNIT_SBUI" | base64 -d > /etc/systemd/system/sb-ui.service
systemctl daemon-reload
systemctl enable --now sb-ui >/dev/null 2>&1 || systemctl restart sb-ui
for i in $(seq 1 15); do
  curl -s -o /dev/null --max-time 2 http://127.0.0.1:8099/ && break
  sleep 1
done
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:8099/; then
  echo "    панель отвечает на порту 8099"
else
  echo "    ОШИБКА: панель не отвечает — смотри: journalctl -u sb-ui -n 20"
  exit 1
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${WG_PORT}/udp" >/dev/null 2>&1 || true
  ufw allow 8099/tcp >/dev/null 2>&1 || true
  echo "    ufw активен: открыты $WG_PORT/udp и 8099/tcp"
fi

echo "==> 8/8  Подписка"
if [ -n "$SUB_URL" ]; then
  COOKIE=$(mktemp)
  LOGIN=$(curl -s --max-time 8 -c "$COOKIE" -X POST http://127.0.0.1:8099/api/login \
          -H "Content-Type: application/json" \
          -d "{\"password\":\"$PW\"}" || true)
  if printf '%s' "$LOGIN" | grep -q '"ok"[^}]*true'; then
    SUBJSON=$(python3 -c "import json,sys; print(json.dumps({'url': sys.argv[1], 'skip_dead': False}))" "$SUB_URL")
    RES=$(curl -s --max-time 180 -b "$COOKIE" -X POST http://127.0.0.1:8099/api/sub \
          -H "Content-Type: application/json" -d "$SUBJSON" || true)
    echo "    импорт подписки: $RES"
  else
    echo "    не удалось войти в панель — импортируй подписку через веб-морду"
  fi
  rm -f "$COOKIE"
else
  echo "    ссылка не задана — импортируй её в панели (карточка «Подписка»)"
fi

echo
echo "================  УСТАНОВКА ЗАВЕРШЕНА  ================"
echo "  Сервер (WAN):        $PUBLIC_IP"
echo "  WireGuard:           порт $WG_PORT/udp, интерфейс $WG_IF"
echo "  Публичный ключ WG:   $PUB"
echo "  Веб-панель:          http://$PUBLIC_IP:8099  (логин admin)"
echo "  Пароль панели:       $PW"
echo "                       (продублирован в /opt/sb-ui/INITIAL_PASSWORD.txt)"
echo
echo "  Роутер (Keenetic), Интернет → Другие подключения → WireGuard:"
echo "    1. Создай WireGuard-подключение (роутер сгенерирует свои ключи)."
echo "    2. Пир-сервер: публичный ключ  $PUB"
echo "    3. Адрес сервера:              $PUBLIC_IP:$WG_PORT"
echo "    4. Разрешённые IP пира:        0.0.0.0/0, ::/0"
echo "    5. Keepalive: 25 сек; DNS подключения можно указать 1.1.1.1"
echo
echo "  Если роутер уже был настроен на старый сервер — просто поменяй"
echo "  в его WG-подключении адрес сервера и публичный ключ пира."
echo
echo "  Проверка позже:"
echo "    systemctl status wg-quick@$WG_IF wg-redirect sing-box-auto sb-ui"
echo "    wg show $WG_IF"
echo "======================================================="
