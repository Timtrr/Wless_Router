#!/usr/bin/env python3
"""Web UI: sing-box balancer + WireGuard server management."""
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = "/etc/sing-box/config.json"
SERVICE = "sing-box-auto"
CLASH = "http://127.0.0.1:9090"
PORT = 8099

WG_IF = "hiddifywg"
WG_CONF = "/etc/wireguard/hiddifywg.conf"
WG_CLIENTS = "/etc/wireguard/clients.json"
WG_SETTINGS = "/opt/sb-ui/wg.json"
META_FILE = "/opt/sb-ui/meta.json"
AUTH_FILE = "/opt/sb-ui/auth.json"
USER = "admin"


# ---------------------------------------------------------------- auth

def _hash(pw, salt):
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def auth_load():
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE) as f:
            return json.load(f)
    pw = secrets.token_urlsafe(9)
    salt = secrets.token_hex(16)
    d = {"user": USER, "salt": salt, "hash": _hash(pw, salt)}
    with open(AUTH_FILE, "w") as f:
        json.dump(d, f)
    os.chmod(AUTH_FILE, 0o600)
    with open("/opt/sb-ui/INITIAL_PASSWORD.txt", "w") as f:
        f.write("user: %s\npassword: %s\n" % (USER, pw))
    os.chmod("/opt/sb-ui/INITIAL_PASSWORD.txt", 0o600)
    return d


AUTH = auth_load()


def auth_ok(header):
    if not header or not header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(header[6:]).decode()
    except Exception:
        return False
    u, _, p = raw.partition(":")
    return u == AUTH["user"] and hmac.compare_digest(_hash(p, AUTH["salt"]), AUTH["hash"])


SESSION_TTL = 7 * 86400


def make_token():
    exp = int(time.time()) + SESSION_TTL
    sig = hmac.new(AUTH["hash"].encode(), str(exp).encode(), hashlib.sha256).hexdigest()[:32]
    return "%d.%s" % (exp, sig)


def check_token(tok):
    try:
        exp_s, sig = tok.split(".", 1)
        exp = int(exp_s)
    except Exception:
        return False
    if exp < time.time():
        return False
    want = hmac.new(AUTH["hash"].encode(), str(exp).encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, want)


def cookie_token(header):
    for part in (header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sbui":
            return v.strip()
    return None


# ---------------------------------------------------------------- sing-box

def load():
    with open(CONFIG) as f:
        return json.load(f)


def check_config(path=CONFIG):
    r = subprocess.run(["sing-box", "check", "-c", path], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:400]


def restart():
    subprocess.run(["systemctl", "restart", SERVICE], check=False)


def apply(d):
    tmp = CONFIG + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    ok, err = check_config(tmp)
    if not ok:
        subprocess.run(["rm", "-f", tmp], check=False)
        return {"ok": False, "error": "config check failed: " + err}
    subprocess.run(["mv", tmp, CONFIG], check=True)
    subprocess.run(["chmod", "600", CONFIG], check=True)
    restart()
    return {"ok": True}


def clash(path):
    try:
        with urllib.request.urlopen(CLASH + path, timeout=4) as r:
            return json.load(r)
    except Exception:
        return None


def proxy_outbounds(d):
    return [o for o in d.get("outbounds", []) if o.get("type") not in ("urltest", "direct", "block", "selector")]


def urltest(d):
    for o in d.get("outbounds", []):
        if o.get("type") == "urltest":
            return o
    return None


def slugify(name, taken):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    if not s:
        s = "srv"
    tag, n = s, 1
    while tag in taken:
        n += 1
        tag = "%s-%d" % (s, n)
    return tag


TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
    "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "ts",
    "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def translit(s):
    out = []
    for ch in s.lower():
        out.append(TRANSLIT.get(ch, ch))
    return "".join(out)


def parse_vless(link):
    u = urllib.parse.urlsplit(link.strip())
    if u.scheme != "vless":
        raise ValueError("поддерживается только vless://")
    q = dict(urllib.parse.parse_qsl(u.query))
    host = u.hostname
    port = u.port or 443
    name = urllib.parse.unquote(u.fragment) or host
    ob = {"type": "vless", "server": host, "server_port": port, "uuid": u.username}
    if q.get("flow"):
        ob["flow"] = q["flow"]
    sec = q.get("security", "none")
    if sec in ("reality", "tls"):
        tls = {"enabled": True, "server_name": q.get("sni", host)}
        if q.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
        if sec == "reality":
            tls["reality"] = {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        ob["tls"] = tls
    net = q.get("type", "tcp")
    if net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif net in ("ws", "httpupgrade"):
        ob["transport"] = {"type": net, "path": q.get("path", "/"), "headers": {"Host": q.get("host", host)}}
    return name, ob


def parse_trojan(link):
    u = urllib.parse.urlsplit(link.strip())
    q = dict(urllib.parse.parse_qsl(u.query))
    host = u.hostname
    port = u.port or 443
    name = urllib.parse.unquote(u.fragment) or host
    ob = {"type": "trojan", "server": host, "server_port": port,
          "password": urllib.parse.unquote(u.username or "")}
    tls = {"enabled": True, "server_name": q.get("sni", host)}
    if q.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
    if q.get("alpn"):
        tls["alpn"] = q["alpn"].split(",")
    ob["tls"] = tls
    net = q.get("type", "tcp")
    if net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}
    elif net in ("ws", "httpupgrade"):
        ob["transport"] = {"type": net, "path": q.get("path", "/"), "headers": {"Host": q.get("host", host)}}
    return name, ob


def http_get_direct(url):
    req = urllib.request.Request(url, headers={"User-Agent": "v2rayN/6.0 (sing-box)"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", "replace")


def http_get_proxy(url):
    r = subprocess.run(["curl", "-sS", "-m", "30", "-L", "--socks5-hostname", "127.0.0.1:2100",
                        "-A", "v2rayN/6.0 (sing-box)", url],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError((r.stderr or "пустой ответ").strip()[:200])
    return r.stdout


def http_get(url):
    try:
        return http_get_direct(url)
    except Exception as e:
        print("[sub] direct fetch failed (%s), retrying via tunnel" % e, flush=True)
        return http_get_proxy(url)


def decode_sub(text):
    t = text.strip()
    if "://" in t:
        return t
    s = re.sub(r"\s+", "", t)
    s += "=" * (-len(s) % 4)
    try:
        dec = base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return t
    return dec if "://" in dec else t


def parse_sub(text):
    items = []
    t = text.strip()
    unsupported = 0
    if t.startswith("[") or t.startswith("{"):
        try:
            items, unsupported = parse_xray_json(t)
        except Exception:
            items = []
    if not items:
        items = []
        seen = set()
        for ln in t.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            try:
                if ln.startswith("vless://"):
                    name, ob = parse_vless(ln)
                elif ln.startswith("trojan://"):
                    name, ob = parse_trojan(ln)
                else:
                    continue
            except Exception:
                continue
            key = (ob["type"], ob["server"], ob["server_port"])
            if key in seen:
                continue
            seen.add(key)
            items.append((name, ob))
    return items, unsupported


def xray_tls(st, host):
    sec = st.get("security") or "none"
    if sec not in ("tls", "reality"):
        return None
    src = st.get("realitySettings") if sec == "reality" else (st.get("tlsSettings") or {})
    tls = {"enabled": True, "server_name": src.get("serverName") or host}
    if src.get("fingerprint"):
        tls["utls"] = {"enabled": True, "fingerprint": src["fingerprint"]}
    if sec == "reality":
        tls["reality"] = {"enabled": True, "public_key": src.get("publicKey", ""), "short_id": src.get("shortId", "")}
    if src.get("alpn"):
        tls["alpn"] = src["alpn"]
    return tls


def convert_xray_outbound(o):
    """xray outbound -> sing-box outbound, or None if unsupported."""
    proto = o.get("protocol")
    st = o.get("streamSettings") or {}
    net = st.get("network") or "tcp"
    sec = st.get("security") or "none"
    if net == "xhttp" or proto == "hysteria":
        return None
    settings = o.get("settings") or {}
    ob = {}
    if proto == "vless":
        vnext = settings.get("vnext") or []
        if not vnext:
            return None
        v = vnext[0]
        user = (v.get("users") or [{}])[0]
        ob = {"type": "vless", "server": v.get("address"), "server_port": int(v.get("port") or 443),
              "uuid": user.get("id")}
        if user.get("flow"):
            ob["flow"] = user["flow"]
        identity = user.get("id") or ""
    elif proto == "trojan":
        servers = settings.get("servers") or []
        if not servers:
            return None
        s = servers[0]
        ob = {"type": "trojan", "server": s.get("address"), "server_port": int(s.get("port") or 443),
              "password": s.get("password")}
        identity = s.get("password") or ""
    else:
        return None
    if not ob.get("server") or not ob["server_port"]:
        return None
    tls = xray_tls(st, ob["server"])
    if tls:
        ob["tls"] = tls
    if net == "grpc":
        gs = st.get("grpcSettings") or {}
        ob["transport"] = {"type": "grpc", "service_name": gs.get("serviceName", "")}
    elif net == "ws":
        ws = st.get("wsSettings") or {}
        tr = {"type": "ws", "path": ws.get("path") or "/"}
        host = (ws.get("headers") or {}).get("Host")
        if host:
            tr["headers"] = {"Host": host}
        ob["transport"] = tr
    elif net == "httpupgrade":
        hs = st.get("httpupgradeSettings") or {}
        ob["transport"] = {"type": "httpupgrade", "host": hs.get("host") or ob["server"], "path": hs.get("path") or "/"}
    ob["_net"] = net
    ob["_ident"] = identity
    return ob


def parse_xray_json(text):
    d = json.loads(text)
    if isinstance(d, dict):
        d = [d]
    out, seen = [], set()
    unsupported = 0
    for el in d:
        if not isinstance(el, dict):
            continue
        remarks = (el.get("remarks") or "").strip()
        obs = [o for o in (el.get("outbounds") or []) if o.get("protocol") in ("vless", "trojan")]
        for o in obs:
            ob = convert_xray_outbound(o)
            if ob is None:
                unsupported += 1
                continue
            net = ob.pop("_net")
            ident = ob.pop("_ident")
            key = (ob["type"], ob["server"], ob["server_port"], net, ident)
            if key in seen:
                continue
            seen.add(key)
            tag = o.get("tag") or "proxy"
            if remarks and (len(obs) == 1 or tag == "proxy"):
                name = remarks
            elif remarks:
                name = "%s · %s" % (remarks, tag)
            else:
                name = "%s:%s" % (ob["server"], ob["server_port"])
            out.append((name, ob))
    return out, unsupported


# ---------------------------------------------------------------- meta

def meta_load():
    if os.path.exists(META_FILE):
        try:
            with open(META_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"url": "", "updated": 0, "tags": {}}


def meta_save(m):
    tmp = META_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)
    os.replace(tmp, META_FILE)


def probe(tag, timeout=8):
    q = urllib.parse.quote(tag, safe="")
    target = urllib.parse.quote("http://www.gstatic.com/generate_204", safe="")
    url = "%s/proxies/%s/delay?timeout=%d&url=%s" % (CLASH, q, timeout * 1000, target)
    best = 0
    for _ in range(2):
        try:
            with urllib.request.urlopen(url, timeout=timeout + 4) as r:
                best = max(best, int(json.load(r).get("delay") or 0))
        except Exception:
            pass
        if best:
            break
        time.sleep(1)
    return best


def sync_subscription(url, skip_dead=False):
    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "укажите ссылку на подписку"}
    if not re.match(r"^(https?|vless|trojan)://", url):
        return {"ok": False, "error": "ссылка должна начинаться с http:// или https://"}
    try:
        raw = http_get(url) if url.startswith("http") else url
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"ok": False, "error": "не удалось скачать подписку: %s" % str(e)[:200]}

    items, unsupported = parse_sub(decode_sub(raw))
    if not items:
        return {"ok": False, "error": "в подписке не найдено серверов vless/trojan"}

    d = load()
    m = meta_load()
    tags_meta = m.setdefault("tags", {})
    old = {o["tag"]: o for o in proxy_outbounds(d)}
    if not tags_meta:
        for t in old:
            tags_meta[t] = {"name": t, "sub": True}

    def key_of(o):
        net = (o.get("transport") or {}).get("type", "tcp")
        return (o.get("type"), o.get("server"), o.get("server_port"), net, o.get("uuid") or o.get("password") or "")

    by_key = {}
    for t, o in old.items():
        by_key.setdefault(key_of(o), t)

    ut = urltest(d)
    old_enabled = set(ut.get("outbounds") or []) if ut else set()
    used = set(old)
    sub_objs, sub_tags = [], []

    for name, ob in items:
        key = key_of(ob)
        t = by_key.get(key)
        if t and t not in sub_tags:
            ob["tag"] = t
            if t in tags_meta:
                tags_meta[t]["sub"] = True  # keep the old display name
            else:
                tags_meta[t] = {"name": name, "sub": True}
        else:
            base = slugify(translit(name), used)
            used.add(base)
            ob["tag"] = base
            tags_meta[ob["tag"]] = {"name": name, "sub": True}
        sub_objs.append(ob)
        sub_tags.append(ob["tag"])

    for t in list(tags_meta):
        if tags_meta[t].get("sub") and t not in sub_tags:
            tags_meta.pop(t, None)

    manual = [o for t, o in old.items() if not tags_meta.get(t, {}).get("sub")]
    others = [o for o in d["outbounds"] if o.get("type") in ("urltest", "direct", "block", "selector", "dns")]

    enabled = []
    for t in sub_tags + [o["tag"] for o in manual]:
        if t in old_enabled or t not in old:
            enabled.append(t)
    if not enabled:
        enabled = [o["tag"] for o in sub_objs + manual]

    d["outbounds"] = sub_objs + manual + others
    ut = urltest(d)
    if ut is not None:
        ut["outbounds"] = enabled
    res = apply(d)
    if not res.get("ok"):
        return res

    skipped = 0
    if skip_dead:
        time.sleep(4)  # let sing-box finish connecting before probing
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(lambda t: (t, probe(t)), sub_tags))
        dead = [t for t, dly in results if not dly]
        if dead and len(dead) < len(sub_tags):
            d2 = load()
            ut2 = urltest(d2)
            ut2["outbounds"] = [t for t in (ut2.get("outbounds") or []) if t not in dead]
            if not ut2["outbounds"]:
                ut2["outbounds"] = [o["tag"] for o in proxy_outbounds(d2) if o.get("tag") not in dead]
            d2["outbounds"] = [o for o in d2["outbounds"] if o.get("tag") not in dead]
            for t in dead:
                tags_meta.pop(t, None)
            apply(d2)
            skipped = len(dead)

    m["url"] = url
    m["updated"] = int(time.time())
    meta_save(m)
    res = {"ok": True, "added": len(sub_objs) - skipped, "skipped": skipped}
    if unsupported:
        res["unsupported"] = unsupported
    return res



# ---------------------------------------------------------------- wireguard

def wg_run(args, data=None):
    return subprocess.run(args, input=data, capture_output=True, text=True)


def wg_settings():
    default = {"endpoint": "192.168.0.101:29687"}
    if os.path.exists(WG_SETTINGS):
        try:
            with open(WG_SETTINGS) as f:
                default.update(json.load(f))
        except Exception:
            pass
    return default


def wg_clients():
    if os.path.exists(WG_CLIENTS):
        try:
            with open(WG_CLIENTS) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def wg_save_clients(d):
    tmp = WG_CLIENTS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, WG_CLIENTS)


def wg_dump():
    r = wg_run(["wg", "show", WG_IF, "dump"])
    if r.returncode != 0 or not r.stdout.strip():
        return None
    lines = r.stdout.strip().splitlines()
    iface = lines[0].split("\t")
    peers = []
    for ln in lines[1:]:
        f = ln.split("\t")
        if len(f) < 8:
            continue
        peers.append({
            "pubkey": f[0],
            "peer_psk": f[1],
            "endpoint": f[2] if f[2] != "(none)" else "",
            "allowed": f[3],
            "handshake": int(f[4] or 0),
            "rx": int(f[5] or 0),
            "tx": int(f[6] or 0),
        })
    return {"port": int(iface[2] or 0), "pubkey": iface[1], "peers": peers}


def wg_sync():
    strip = wg_run(["wg-quick", "strip", WG_CONF])
    if strip.returncode != 0:
        return False, strip.stderr.strip()[:300]
    tmp = "/tmp/wg.syncconf"
    with open(tmp, "w") as f:
        f.write(strip.stdout)
    r = wg_run(["wg", "syncconf", WG_IF, tmp])
    try:
        os.remove(tmp)
    except OSError:
        pass
    return r.returncode == 0, r.stderr.strip()[:300]


def wg_conf_text():
    with open(WG_CONF) as f:
        return f.read()


def wg_peer_blocks(text):
    """Return (header, [(pubkey, block_text), ...])."""
    parts = re.split(r"(?m)^\[Peer\]\s*$", text)
    header = parts[0].rstrip() + "\n"
    blocks = []
    for p in parts[1:]:
        m = re.search(r"(?m)^PublicKey\s*=\s*(\S+)", p)
        blocks.append((m.group(1) if m else "", "[Peer]\n" + p.strip() + "\n"))
    return header, blocks


def wg_next_ip(text):
    used = {int(x) for x in re.findall(r"10\.90\.0\.(\d+)/32", text)}
    n = 2
    while n in used:
        n += 1
    return n


def wg_add(name):
    name = (name or "").strip()
    if not name:
        return {"ok": False, "error": "укажите имя устройства"}
    text = wg_conf_text()
    priv = wg_run(["wg", "genkey"]).stdout.strip()
    pub = wg_run(["wg", "pubkey"], data=priv + "\n").stdout.strip()
    psk = wg_run(["wg", "genpsk"]).stdout.strip()
    if not priv or not pub or not psk:
        return {"ok": False, "error": "не удалось сгенерировать ключи"}
    n = wg_next_ip(text)
    ip, ip6 = "10.90.0.%d" % n, "fd42:42:90::%d" % n
    block = "\n[Peer]\n# name: %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32, %s/128\n" % (
        name.replace("\n", " "), pub, psk, ip, ip6)
    new = text.rstrip() + "\n" + block
    with open(WG_CONF, "w") as f:
        f.write(new)
    os.chmod(WG_CONF, 0o600)
    ok, err = wg_sync()
    if not ok:
        return {"ok": False, "error": "wg syncconf: " + err}
    c = wg_clients()
    c[pub] = {"name": name, "priv": priv, "psk": psk, "ip": ip, "ip6": ip6}
    wg_save_clients(c)
    return {"ok": True, "name": name, "pubkey": pub, "ip": ip}


def wg_delete(pub):
    text = wg_conf_text()
    header, blocks = wg_peer_blocks(text)
    keep = [b for p, b in blocks if p != pub]
    if len(keep) == len(blocks):
        return {"ok": False, "error": "пир не найден"}
    with open(WG_CONF, "w") as f:
        f.write(header.rstrip() + "\n")
        for b in keep:
            f.write("\n" + b)
    os.chmod(WG_CONF, 0o600)
    ok, err = wg_sync()
    if not ok:
        return {"ok": False, "error": "wg syncconf: " + err}
    c = wg_clients()
    if pub in c:
        del c[pub]
        wg_save_clients(c)
    return {"ok": True}


def client_conf(pub):
    c = wg_clients().get(pub)
    if not c:
        return None
    d = wg_dump()
    if not d:
        return None
    ep = wg_settings()["endpoint"]
    return (
        "[Interface]\n"
        "PrivateKey = %s\n"
        "Address = %s/32, %s/128\n"
        "DNS = 1.1.1.1\n"
        "MTU = 1380\n"
        "\n"
        "[Peer]\n"
        "PublicKey = %s\n"
        "PresharedKey = %s\n"
        "Endpoint = %s\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    ) % (c["priv"], c["ip"], c["ip6"], d["pubkey"], c["psk"], ep)


# ---------------------------------------------------------------- html

LOGIN_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Вход</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0f1319;--card:#171d26;--line:#232c38;--txt:#e6edf5;--dim:#8b97a8;--acc:#3b82f6;--bad:#e5534b}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:var(--bg);color:var(--txt);font:15px/1.45 -apple-system,Segoe UI,Roboto,sans-serif}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;width:320px}
h1{font-size:18px;margin:0 0 16px}
input{width:100%;background:#0d1219;border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:10px;font-size:14px}
button{width:100%;margin-top:12px;background:var(--acc);border:0;color:#fff;border-radius:8px;padding:10px;font-size:14px;cursor:pointer}
#e{color:var(--bad);font-size:13px;min-height:18px;margin-top:10px}
</style></head><body>
<form class="card" onsubmit="go(event)">
  <h1>VPN</h1>
  <input id="p" type="password" placeholder="Пароль" autofocus>
  <button type="submit">Войти</button>
  <div id="e"></div>
</form>
<script>
async function go(ev) {
  ev.preventDefault();
  const p = document.getElementById('p').value;
  const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password:p})});
  const d = await r.json();
  if (d.ok) location.href = '/'; else document.getElementById('e').textContent = d.error || 'ошибка';
}
</script></body></html>
"""

HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>VPN</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0f1319;--card:#171d26;--line:#232c38;--txt:#e6edf5;--dim:#8b97a8;--ok:#3ecf8e;--bad:#e5534b;--acc:#3b82f6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.45 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:22px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--dim);font-size:13px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
.card h2{font-size:16px;margin:0 0 12px}
.row{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
.name{font-weight:600}.host{color:var(--dim);font-size:12px;font-family:ui-monospace,Consolas,monospace}
.pill{font-size:11px;padding:2px 8px;border-radius:99px;background:#1f2937;color:var(--dim)}
.pill.on{background:rgba(62,207,142,.15);color:var(--ok)}
.pill.act{background:rgba(59,130,246,.18);color:#93c5fd}
.pill.off{background:rgba(229,83,75,.15);color:var(--bad)}
.grow{flex:1}
button{background:#1f2937;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 11px;cursor:pointer;font-size:13px}
button:hover{border-color:#3b4757}button.primary{background:var(--acc);border-color:var(--acc);color:#fff}
button.danger{color:var(--bad)}
input{background:#0d1219;border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:9px;font-size:13px}
input.full{width:100%}
.sw{position:relative;width:42px;height:24px;flex:0 0 auto}.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;inset:0;background:#2b3543;border-radius:99px;cursor:pointer;transition:.15s}
.sl:before{content:"";position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+.sl{background:var(--ok)}.sw input:checked+.sl:before{transform:translateX(18px)}
#msg{font-size:13px;min-height:18px;margin-top:8px}.err{color:var(--bad)}.good{color:var(--ok)}
.mrow{display:flex;gap:8px;align-items:center;margin-top:10px}
.hint{color:var(--dim);font-size:12px;margin-top:6px}
a.dl{color:#93c5fd;text-decoration:none;font-size:13px}
a.dl:hover{text-decoration:underline}
</style></head><body><div class="wrap">
<h1>VPN</h1>
<div class="sub">Балансировщик серверов и WireGuard-сервер</div>

<div class="card">
  <h2>Подписка</h2>
  <div class="mrow" style="margin-top:0">
    <input id="suburl" class="full" placeholder="https://... — ссылка на подписку">
    <button class="primary" onclick="sub()">Загрузить</button>
  </div>
  <label class="hint" style="display:flex;gap:8px;align-items:center;margin-top:10px">
    <input id="skipdead" type="checkbox" style="width:auto"> не добавлять серверы, которые не отвечают (проверка ~40 сек)
  </label>
  <div id="submsg" style="font-size:13px;min-height:18px;margin-top:8px"></div>
</div>

<div class="card">
  <h2>Серверы</h2>
  <div id="list">загрузка…</div>
  <div class="mrow" style="margin-top:14px">
    <input id="link" class="full" placeholder="vless://uuid@host:443?...#Название">
    <button class="primary" onclick="add()">Добавить</button>
  </div>
  <div id="msg"></div>
</div>

<div class="card">
  <h2>Автоподбор</h2>
  <div id="sbinfo" class="host" style="margin-bottom:10px">загрузка…</div>
  <div class="mrow">
    <input id="sbinterval" class="full" inputmode="numeric" placeholder="Интервал опроса, сек (10–3600)">
    <input id="sbtolerance" class="full" inputmode="numeric" placeholder="Tolerance, мс (0–1000)">
    <button class="primary" onclick="sbsave()">Сохранить</button>
  </div>
  <div class="hint">Опрос каждые N секунд выбирает самый быстрый сервер. Tolerance — минимальный выигрыш (мс), при котором произойдёт переключение.</div>
  <div id="sbmsg" style="font-size:13px;min-height:18px;margin-top:8px"></div>
</div>

<div class="card">
  <h2>WireGuard</h2>
  <div id="wginfo" class="host" style="margin-bottom:10px">загрузка…</div>
  <div id="wglist"></div>
  <div class="mrow" style="margin-top:14px">
    <input id="wgname" class="full" placeholder="Имя устройства, например Телефон">
    <button class="primary" onclick="wgadd()">Добавить пир</button>
  </div>
  <div class="mrow">
    <input id="wgendpoint" class="full" placeholder="Адрес сервера для конфига, e.g. 192.168.0.101:29687">
    <button onclick="wgsave()">Сохранить адрес</button>
  </div>
  <div class="hint">Конфиг — обычный .conf для WireGuard. Кнопка «конфиг» скачивает файл.</div>
  <div id="wgmsg" style="font-size:13px;min-height:18px;margin-top:8px"></div>
</div>

<div class="card">
  <h2>Пароль</h2>
  <div class="mrow" style="margin-top:0">
    <input id="oldpw" type="password" class="full" placeholder="Текущий пароль">
    <input id="newpw" type="password" class="full" placeholder="Новый пароль">
    <button onclick="chpw()">Сменить</button>
    <button onclick="logout()">Выйти</button>
  </div>
  <div id="pwmsg" style="font-size:13px;min-height:18px;margin-top:8px"></div>
</div>
</div>
<script>
const $ = id => document.getElementById(id);
const say = (id, t, cls) => { const m = $(id); m.textContent = t; m.className = cls || ''; };
async function api(url, body) {
  let r;
  try {
    r = await fetch(url, body ? {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)} : {});
  } catch (e) { return {ok:false, error:'нет связи со страницей, обнови её'}; }
  if (r.status === 401) { location.href = '/'; throw new Error('auth'); }
  try { return await r.json(); } catch (e) { return {ok:false, error:'некорректный ответ'}; }
}
const mb = b => b > 1048576 ? (b/1048576).toFixed(1) + ' МБ' : Math.round(b/1024) + ' КБ';
const ago = t => {
  if (!t) return 'нет связи';
  const s = Math.floor(Date.now()/1000 - t);
  if (s < 60) return s + ' сек назад';
  if (s < 3600) return Math.floor(s/60) + ' мин назад';
  if (s < 86400) return Math.floor(s/3600) + ' ч назад';
  return Math.floor(s/86400) + ' дн назад';
};
const short = k => k.slice(0, 10) + '…' + k.slice(-4);

async function load() {
  const d = await api('/api/list');
  const el = $('list');
  if (!d.ok) { el.textContent = d.error || 'ошибка'; return; }
  el.innerHTML = d.servers.map(s => `
    <div class="row">
      <div class="grow">
        <div class="name">${s.name} ${s.active ? '<span class="pill act">активен</span>' : ''} ${s.enabled ? '' : '<span class="pill off">выкл</span>'}</div>
        <div class="host">${s.server}:${s.server_port} · ${s.delay ? s.delay + ' мс' : 'нет ответа'}</div>
      </div>
      <label class="sw"><input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="toggle('${s.tag}', this.checked)"><span class="sl"></span></label>
      <button class="danger" onclick="del('${s.tag}')">✕</button>
    </div>`).join('');
}
async function toggle(tag, on) { const r = await api('/api/toggle', {tag, enabled: on}); if (!r.ok) say('msg', r.error, 'err'); load(); }async function del(tag) { if (!confirm('Удалить ' + tag + '?')) return; const r = await api('/api/delete', {tag}); if (!r.ok) say('msg', r.error, 'err'); load(); }
async function add() {
  const link = $('link').value.trim();
  if (!link) return;
  const r = await api('/api/add', {link});
  if (r.ok) { say('msg', 'Добавлено: ' + r.name, 'good'); $('link').value = ''; } else say('msg', r.error, 'err');
  load();
}
async function sub() {
  const url = $('suburl').value.trim();
  if (!url) return;
  say('submsg', 'Скачиваю и проверяю серверы…', '');
  const r = await api('/api/sub', {url, skip_dead: $('skipdead').checked});
  if (r.ok) {
    let t = 'Готово: серверов ' + r.added;
    if (r.skipped) t += ', нерабочих пропущено: ' + r.skipped;
    if (r.unsupported) t += ', неподдерживаемых (xhttp/hysteria) пропущено: ' + r.unsupported;
    say('submsg', t, 'good');
  } else say('submsg', r.error, 'err');
  load();
}
async function subinit() {
  const d = await api('/api/sub');
  if (d.ok && d.url) $('suburl').value = d.url;
}

async function sbload() {
  const d = await api('/api/sb');
  if (!d.ok) { $('sbinfo').textContent = d.error || 'ошибка'; return; }
  $('sbinfo').textContent = 'Серверов в автоподборе: ' + d.count + ' · сейчас: ' + (d.now || '—');
  if (document.activeElement !== $('sbinterval')) $('sbinterval').value = d.interval;
  if (document.activeElement !== $('sbtolerance')) $('sbtolerance').value = d.tolerance;
}
async function sbsave() {
  const r = await api('/api/sb/settings', {interval: parseInt($('sbinterval').value, 10), tolerance: parseInt($('sbtolerance').value, 10)});
  say('sbmsg', r.ok ? 'Сохранено, sing-box перезапущен' : (r.error || 'ошибка'), r.ok ? 'good' : 'err');
  sbload();
}

async function wgload() {
  const d = await api('/api/wg');
  if (!d.ok) { $('wginfo').textContent = d.error || 'ошибка'; return; }
  $('wginfo').textContent = 'Порт ' + d.port + ' · ключ ' + d.pubkey;
  if (document.activeElement !== $('wgendpoint')) $('wgendpoint').value = d.endpoint;
  $('wglist').innerHTML = d.peers.map(p => `
    <div class="row">
      <div class="grow">
        <div class="name">${p.name || short(p.pubkey)} ${p.handshake ? '<span class="pill on">' + ago(p.handshake) + '</span>' : '<span class="pill off">не подключён</span>'}</div>
        <div class="host">${p.ip ? p.ip + ' · ' : ''}${p.endpoint || '—'} · ↓ ${mb(p.rx)} ↑ ${mb(p.tx)}</div>
      </div>
      ${p.downloadable ? `<a class="dl" href="/api/wg/config?p=${encodeURIComponent(p.pubkey)}">конфиг</a>` : ''}
      <button class="danger" onclick="wgdel('${p.pubkey}')">✕</button>
    </div>`).join('');
}
async function wgadd() {
  const name = $('wgname').value.trim();
  if (!name) return;
  const r = await api('/api/wg/add', {name});
  if (r.ok) { say('wgmsg', 'Пир создан: ' + r.name + ' (' + r.ip + ')', 'good'); $('wgname').value = ''; }
  else say('wgmsg', r.error, 'err');
  wgload();
}
async function wgdel(pub) { if (!confirm('Удалить пир?')) return; const r = await api('/api/wg/delete', {pubkey: pub}); if (!r.ok) say('wgmsg', r.error, 'err'); wgload(); }
async function wgsave() { const r = await api('/api/wg/settings', {endpoint: $('wgendpoint').value.trim()}); say('wgmsg', r.ok ? 'Адрес сохранён' : r.error, r.ok ? 'good' : 'err'); }
async function chpw() {
  const r = await api('/api/password', {old: $('oldpw').value, new: $('newpw').value});
  if (r.ok) { say('pwmsg', 'Пароль изменён, войдите заново', 'good'); setTimeout(() => location.href = '/', 1200); }
  else say('pwmsg', r.error, 'err');
}
async function logout() { await fetch('/api/logout', {method:'POST'}); location.href = '/'; }
load(); wgload(); subinit(); sbload(); setInterval(() => { load(); wgload(); sbload(); }, 15000);
</script></body></html>
"""


# ---------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _authed(self):
        return check_token(cookie_token(self.headers.get("Cookie")) or "") or auth_ok(self.headers.get("Authorization"))

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path in ("/", "/index.html", "/login"):
            if not self._authed():
                return self._send(200, LOGIN_HTML, "text/html")
            if u.path == "/login":
                return self._send(302, "", "text/plain", {"Location": "/"})
            return self._send(200, HTML, "text/html")
        if not self._authed():
            return self._json({"ok": False, "error": "нужен вход"}, 401)
        if u.path == "/api/list":
            return self._json(self.list_servers())
        if u.path == "/api/wg":
            return self._json(self.wg_list())
        if u.path == "/api/sub":
            m = meta_load()
            return self._json({"ok": True, "url": m.get("url", ""), "updated": m.get("updated", 0)})
        if u.path == "/api/sb":
            return self._json(self.sb_info())
        if u.path == "/api/wg/config":
            pub = urllib.parse.parse_qs(u.query).get("p", [""])[0]
            pub = pub.replace(" ", "+")
            txt = client_conf(pub)
            if not txt:
                return self._json({"ok": False, "error": "конфиг не найден"}, 404)
            name = (wg_clients().get(pub) or {}).get("name", "client")
            fn = re.sub(r"[^A-Za-z0-9_.-]+", "_", name) or "client"
            return self._send(200, txt, "application/octet-stream",
                              {"Content-Disposition": 'attachment; filename="%s.conf"' % fn})
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json({"ok": False, "error": "bad request"}, 400)

        if self.path == "/api/login":
            pw = body.get("password") or ""
            if hmac.compare_digest(_hash(pw, AUTH["salt"]), AUTH["hash"]):
                tok = make_token()
                return self._send(200, json.dumps({"ok": True}), "application/json",
                                  {"Set-Cookie": "sbui=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                                   % (tok, SESSION_TTL)})
            time.sleep(0.4)
            return self._json({"ok": False, "error": "неверный пароль"})
        if self.path == "/api/logout":
            return self._send(200, json.dumps({"ok": True}), "application/json",
                              {"Set-Cookie": "sbui=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"})

        if not self._authed():
            return self._json({"ok": False, "error": "нужен вход"}, 401)

        routes = {
            "/api/toggle": self.toggle,
            "/api/delete": self.delete,
            "/api/add": self.add,
            "/api/sub": self.sub_ep,
            "/api/wg/add": self.wg_add_ep,
            "/api/wg/delete": self.wg_del_ep,
            "/api/wg/settings": self.wg_settings_ep,
            "/api/sb/settings": self.sb_settings_ep,
            "/api/password": self.password_ep,
        }
        fn = routes.get(self.path)
        if not fn:
            return self._send(404, "not found", "text/plain")
        try:
            return self._json(fn(body))
        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._json({"ok": False, "error": "внутренняя ошибка: %s" % str(e)[:200]})

    # --- sing-box endpoints

    def list_servers(self):
        try:
            d = load()
        except Exception as e:
            return {"ok": False, "error": str(e)}
        ut = urltest(d) or {}
        enabled = set(ut.get("outbounds") or [])
        auth = clash("/proxies/auto") or {}
        active = auth.get("now")
        tags_meta = meta_load().get("tags", {})
        out = []
        for o in proxy_outbounds(d):
            tag = o.get("tag")
            info = clash("/proxies/" + urllib.parse.quote(tag)) or {}
            hist = info.get("history") or []
            delay = hist[-1].get("delay") if hist else None
            if delay == 0:
                delay = None
            out.append({
                "tag": tag,
                "name": (tags_meta.get(tag) or {}).get("name") or tag,
                "server": o.get("server"),
                "server_port": o.get("server_port"),
                "enabled": tag in enabled,
                "active": tag == active,
                "delay": delay,
            })
        return {"ok": True, "servers": out, "active": active}

    def toggle(self, body):
        tag = body.get("tag")
        on = bool(body.get("enabled"))
        d = load()
        ut = urltest(d)
        if not ut:
            return {"ok": False, "error": "urltest outbound не найден"}
        lst = ut.setdefault("outbounds", [])
        if on:
            if tag not in lst:
                lst.append(tag)
        else:
            if tag in lst and len(lst) <= 1:
                return {"ok": False, "error": "нельзя выключить последний сервер"}
            if tag in lst:
                lst.remove(tag)
        return apply(d)

    def delete(self, body):
        tag = body.get("tag")
        d = load()
        ut = urltest(d)
        if ut and tag in (ut.get("outbounds") or []) and len(ut["outbounds"]) <= 1:
            return {"ok": False, "error": "нельзя удалить последний сервер"}
        d["outbounds"] = [o for o in d["outbounds"] if o.get("tag") != tag]
        if ut and tag in (ut.get("outbounds") or []):
            ut["outbounds"].remove(tag)
        return apply(d)

    def add(self, body):
        link = (body.get("link") or "").strip()
        d = load()
        taken = {o.get("tag") for o in d["outbounds"]}
        try:
            if link.startswith("trojan://"):
                name, ob = parse_trojan(link)
            else:
                name, ob = parse_vless(link)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        ob["tag"] = slugify(translit(name), taken)
        m = meta_load()
        m.setdefault("tags", {})[ob["tag"]] = {"name": name, "sub": False}
        d["outbounds"].insert(-1 if urltest(d) else len(d["outbounds"]), ob)
        ut = urltest(d)
        if ut is not None:
            ut.setdefault("outbounds", []).append(ob["tag"])
        res = apply(d)
        if res.get("ok"):
            meta_save(m)
        res["name"] = name
        return res

    def sub_ep(self, body):
        return sync_subscription(body.get("url"), bool(body.get("skip_dead")))

    # --- wireguard endpoints

    def wg_list(self):
        d = wg_dump()
        if not d:
            return {"ok": False, "error": "интерфейс WireGuard не поднят"}
        clients = wg_clients()
        peers = []
        for p in d["peers"]:
            c = clients.get(p["pubkey"]) or {}
            ip = c.get("ip")
            if not ip:
                m = re.search(r"10\.90\.0\.(\d+)/32", p["allowed"])
                ip = "10.90.0." + m.group(1) if m else ""
            peers.append({
                "pubkey": p["pubkey"],
                "name": c.get("name", ""),
                "ip": ip,
                "endpoint": p["endpoint"],
                "handshake": p["handshake"],
                "rx": p["rx"],
                "tx": p["tx"],
                "downloadable": bool(c.get("priv")),
            })
        return {"ok": True, "port": d["port"], "pubkey": d["pubkey"],
                "endpoint": wg_settings()["endpoint"], "peers": peers}

    def wg_add_ep(self, body):
        return wg_add(body.get("name"))

    def wg_del_ep(self, body):
        return wg_delete(body.get("pubkey"))

    def sb_info(self):
        ut = urltest(load())
        if not ut:
            return {"ok": False, "error": "urltest не найден в конфиге"}
        m = re.match(r"^(\d+)(s|m)?$", str(ut.get("interval", "30s")))
        secs = int(m.group(1)) * (60 if (m.group(2) or "s") == "m" else 1) if m else 30
        tol = int(ut.get("tolerance", 50))
        auto = clash("/proxies/auto") or {}
        return {"ok": True, "interval": secs, "tolerance": tol,
                "count": len(ut.get("outbounds", [])), "now": auto.get("now", "")}

    def sb_settings_ep(self, body):
        try:
            iv = int(body.get("interval"))
            tol = int(body.get("tolerance"))
        except (TypeError, ValueError):
            return {"ok": False, "error": "нужны числа"}
        if not (10 <= iv <= 3600):
            return {"ok": False, "error": "интервал должен быть 10–3600 сек"}
        if not (0 <= tol <= 1000):
            return {"ok": False, "error": "tolerance должен быть 0–1000 мс"}
        d = load()
        ut = urltest(d)
        if not ut:
            return {"ok": False, "error": "urltest не найден в конфиге"}
        ut["interval"] = "%ds" % iv
        ut["tolerance"] = tol
        res = apply(d)
        if not res.get("ok"):
            return res
        return {"ok": True, "interval": iv, "tolerance": tol}

    def wg_settings_ep(self, body):
        ep = (body.get("endpoint") or "").strip()
        if not re.match(r"^[A-Za-z0-9.\-]+:\d{1,5}$", ep):
            return {"ok": False, "error": "формат: адрес:порт"}
        tmp = WG_SETTINGS + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"endpoint": ep}, f)
        os.replace(tmp, WG_SETTINGS)
        return {"ok": True}

    def password_ep(self, body):
        global AUTH
        old = body.get("old") or ""
        new = body.get("new") or ""
        if not hmac.compare_digest(_hash(old, AUTH["salt"]), AUTH["hash"]):
            return {"ok": False, "error": "текущий пароль неверный"}
        if len(new) < 6:
            return {"ok": False, "error": "новый пароль короче 6 символов"}
        salt = secrets.token_hex(16)
        AUTH = {"user": AUTH["user"], "salt": salt, "hash": _hash(new, salt)}
        with open(AUTH_FILE, "w") as f:
            json.dump(AUTH, f)
        os.chmod(AUTH_FILE, 0o600)
        return {"ok": True}

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
