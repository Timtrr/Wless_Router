#!/usr/bin/env bash
# ============================================================
#  panel-installer.sh — WireGuard + sing-box + веб-панель
#  Универсальная установка на чистый Ubuntu/Debian (x86_64).
#
#  Ничего личного внутри нет: WG-ключи, пиры и пароль создаются
#  заново при установке. Подписка импортируется через веб-панель
#  (или сразу аргументом --sub).
#
#  Использование (от root):
#    sudo bash panel-installer.sh
#    sudo bash panel-installer.sh --port 29687
#    sudo bash panel-installer.sh --router-pub <ПУБЛИЧНЫЙ_КЛЮЧ_РОУТЕРА>
#    sudo bash panel-installer.sh --sub "https://ссылка-на-подписку"
#
#  Что ставится:
#    - WireGuard-сервер: интерфейс hiddifywg, порт 29687/udp
#    - sing-box 1.14.4 (встроен в этот файл, качать ниоткуда не надо)
#        входы: socks 127.0.0.1:2100, redirect 0.0.0.0:12345
#    - перенаправление клиентского трафика туннеля в sing-box
#    - веб-панель на порту 8099: серверы, импорт подписки, пиры WG
#
#  Повторный запуск безопасен: ключи и пиры сохраняются.
# ============================================================
set -euo pipefail

WG_PORT=29687
ROUTER_PUB=""
SUB_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --port)       WG_PORT="$2"; shift 2 ;;
    --router-pub) ROUTER_PUB="$2"; shift 2 ;;
    --sub)        SUB_URL="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *)
      echo "Неизвестный аргумент: $1 (см. --help)"; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Запусти от root: sudo bash panel-installer.sh"; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo "Нужен Debian/Ubuntu (apt)"; exit 1; }
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "?")
if [ "$ARCH" != "amd64" ]; then
  echo "Встроенный sing-box собран под x86_64, а тут: $ARCH — установка прервана."
  exit 1
fi

echo "==> 1/8  Пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard-tools iptables curl python3 ca-certificates >/dev/null

echo "==> 2/8  Форвардинг (sysctl)"
cat > /etc/sysctl.d/99-panel.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
SYSCTL
sysctl --system >/dev/null 2>&1 || true

mkdir -p /etc/sing-box /opt/sb-ui /etc/wireguard /usr/local/sbin
chmod 700 /etc/wireguard

# ---PAYLOADS-BEGIN---
