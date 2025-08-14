import argparse
import os
import time
import re
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
import json

AUTH_STATE_FILE = "auth_state.json"
USER_DATA_DIR = "pw_profile"

CONFIG = {
    "base_url": "https://www.paribu.com",
    "login_url": "https://www.paribu.com/auth/sign-in",
    "wallet_url": "https://www.paribu.com/wallet",
    "selectors": {
        "wallet_search_input_placeholder": "Varlık arayın",
        "asset_row_by_name": lambda asset: f'role=button[name="{asset}"]',
        "network_tab_by_name": lambda net: f'role=tab[name="{net}"]',
        "deposit_address_value": 'input[name="depositAddress"], textarea[name="depositAddress"]',
        "balance_text": 'data-test-id=available-balance',
        "sell_tab": 'role=tab[name="Sat"]',
        "market_order_tab": 'role=tab[name="Piyasa"]',
        "amount_input": 'input[name="sellAmount"]',
        "sell_submit": 'role=button[name="Sat"]',
    },
    "market_url_template": "https://www.paribu.com/markets/{pair}",
}

# Hızlı yol dosyaları
AUTH_HEADERS_FILE = "auth_headers.json"
ADDR_CACHE_FILE = "addresses_cache.json"

def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}

def _save_json(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def _open_persistent(pw, headless=True):
    context = pw.chromium.launch_persistent_context(
        USER_DATA_DIR,
        headless=headless,
        channel="chrome",
        args=["--disable-blink-features=AutomationControlled"],
        viewport=None,
    )
    page = context.new_page()
    return context, page

def cmd_init_login():
    with sync_playwright() as pw:
        context, page = _open_persistent(pw, headless=False)
        page.goto(CONFIG["login_url"], wait_until="domcontentloaded")
        print("Lütfen giriş yapın, 2FA/CAPTCHA tamamlayın. Giriş bittikten sonra konsola dönün.")
        input("Giriş tamamlandıysa Enter'a basın...")
        page.goto(CONFIG["wallet_url"], wait_until="domcontentloaded")
        context.storage_state(path=AUTH_STATE_FILE)
        print(f"Oturum kaydedildi: {AUTH_STATE_FILE}")
        context.close()

def _ensure_auth(page):
    page.goto(CONFIG["wallet_url"], wait_until="domcontentloaded")
    need_login = False
    if "auth" in page.url or "sign-in" in page.url.lower():
        need_login = True
    else:
        try:
            if page.get_by_text("Giriş Yap").first.is_visible(timeout=1200) or page.get_by_text("Giriş yap").first.is_visible(timeout=1200):
                need_login = True
        except Exception:
            pass
    if need_login:
        raise SystemExit("Kayıtlı oturum geçerli değil. init-login'i (görünür modda) tekrar çalıştırın.")

def _goto_wallet(page):
    page.goto(CONFIG["wallet_url"], wait_until="domcontentloaded")

def _goto_wallet_asset(page, asset):
    page.goto(f"{CONFIG['wallet_url']}/{asset.lower()}", wait_until="domcontentloaded")

def _goto_wallet_asset_deposit(page, asset):
    page.goto(f"{CONFIG['wallet_url']}/{asset.lower()}/deposit", wait_until="domcontentloaded")

def _safe_fill_search(page, text):
    placeholder = CONFIG["selectors"]["wallet_search_input_placeholder"]
    try:
        inp = page.get_by_placeholder(placeholder).first
        inp.fill("", timeout=1500)
        inp.fill(text, timeout=1500)
        time.sleep(0.2)
        return True
    except Exception:
        pass
    try:
        inp = page.locator('input.p-search-input__field').first
        inp.fill("", timeout=1500)
        inp.fill(text, timeout=1500)
        time.sleep(0.2)
        return True
    except Exception:
        return False

def _try_click(page, tries):
    for t in tries:
        try:
            if t["type"] == "role":
                page.locator(t["selector"]).first.click(timeout=t.get("timeout", 4000))
                return True
            elif t["type"] == "role_re":
                role_name = t.get("role", "button")
                page.get_by_role(role_name, name=re.compile(t["name"], re.I)).first.click(timeout=t.get("timeout", 4000))
                return True
            elif t["type"] == "text":
                page.getby_text(t["text"], exact=t.get("exact", True)).first.click(timeout=t.get("timeout", 4000))
                return True
            elif t["type"] == "text_icontains":
                page.get_by_text(t["text"]).first.click(timeout=t.get("timeout", 4000))
                return True
            elif t["type"] == "css":
                page.locator(t["selector"]).first.click(timeout=t.get("timeout", 4000))
                return True
        except Exception:
            continue
    return False

def _open_deposit_modal(page):
    if not _try_click(page, [
        {"type": "role", "selector": 'role=button[name="Yatırma"]'},
        {"type": "text", "text": "Yatırma", "exact": True},
        {"type": "css", "selector": 'button:has-text("Yatırma")'},
    ]):
        raise RuntimeError("Yatırma butonu bulunamadı.")
    dlg = page.get_by_role("dialog").first
    try:
        dlg.wait_for(state="visible", timeout=4000)
        return dlg
    except Exception:
        return page  # bazı sayfalarda dialog role olmayabilir

def _click_in_scope(scope, kind, value, timeout=4000):
    try:
        if kind == "role":
            scope.get_by_role("tab", name=value).first.click(timeout=timeout)
        elif kind == "role_re":
            scope.get_by_role("tab", name=re.compile(value, re.I)).first.click(timeout=timeout)
        elif kind == "text":
            scope.get_by_text(value, exact=True).first.click(timeout=timeout)
        elif kind == "text_icontains":
            scope.get_by_text(value).first.click(timeout=timeout)
        elif kind == "css":
            scope.locator(value).first.click(timeout=timeout)
        return True
    except Exception:
        return False

def _open_network_dropdown(scope):
    # 1) Accessible yollar
    candidates = [
        lambda: scope.get_by_role("button", name=re.compile("Yatırma ağı", re.I)).first,
        lambda: scope.get_by_role("combobox").first,
        lambda: scope.get_by_text(re.compile("^Yatırma ağı seçin$", re.I)).first,
        lambda: scope.locator('button:has-text("Yatırma ağı")').first,
        lambda: scope.locator('[role="button"]:has-text("Yatırma ağı")').first,
        lambda: scope.locator('[aria-haspopup="listbox"]').first,
        lambda: scope.locator('[role="combobox"]').first,
        lambda: scope.locator('.p-select__control').first,
    ]
    for build in candidates:
        try:
            el = build()
            el.click(timeout=1200)
            return True
        except Exception:
            continue
    # 2) XPath ile metne yakın ata-konteyneri tıkla
    xpaths = [
        'xpath=//*[normalize-space(text())="Yatırma ağı seçin"]/ancestor::*[self::button or @role="button" or @aria-haspopup="listbox"][1]',
        'xpath=//*[contains(normalize-space(.),"Yatırma ağı")]/ancestor::*[self::button or @role="button" or @aria-haspopup="listbox"][1]',
    ]
    for xp in xpaths:
        try:
            scope.locator(xp).first.click(timeout=1200)
            return True
        except Exception:
            continue
    # 3) Son çare: metni bulup yakınındaki ilk clickable öğeyi tıkla
    try:
        label = scope.get_by_text(re.compile("Yatırma ağı", re.I)).first
        box = label.bounding_box()
        if box:
            scope.mouse.click(box["x"] + box["width"] + 10, box["y"] + box["height"]/2)
            return True
    except Exception:
        pass
    return False

def _select_network_in(scope, network):
    if not network:
        return

    if not _open_network_dropdown(scope):
        try:
            scope.screenshot(path="debug_dropdown.png")
        except Exception:
            pass
        raise RuntimeError("Yatırma ağı dropdown açılamadı.")

    # Seçeneklerin listbox/menü olarak açıldığını bekle
    try:
        scope.get_by_role("listbox").first.wait_for(state="visible", timeout=1500)
    except Exception:
        pass

    up = network.upper()
    candidates = ["Tron (TRC-20)","TRC-20","TRC20","TRON"] if up == "TRC20" else (
                 ["Ethereum (ERC-20)","ERC-20","ERC20","ETHEREUM"] if up == "ERC20" else [network])

    picked = False
    for cand in candidates:
        for pick in [
            lambda: scope.get_by_role("option", name=re.compile(cand, re.I)).first.click(timeout=1500),
            lambda: scope.locator(f'[role="option"]:has-text("{cand}")').first.click(timeout=1500),
            lambda: scope.get_by_text(cand).first.click(timeout=1500),
            lambda: scope.locator(f'li:has-text("{cand}")').first.click(timeout=1500),
            lambda: scope.locator(f'button:has-text("{cand}")').first.click(timeout=1500),
        ]:
            try:
                pick()
                picked = True
                break
            except Exception:
                continue
        if picked:
            break

    if not picked:
        try:
            scope.screenshot(path="debug_dropdown_options.png")
        except Exception:
            pass
        raise RuntimeError(f'Ağ seçeneği bulunamadı: {network}')

    time.sleep(0.2)

def _extract_deposit_address(page, scope=None):
    root = scope or page
    # 1) Bilinen input/textarea
    addr_sel = CONFIG["selectors"]["deposit_address_value"]
    try:
        return root.locator(addr_sel).first.input_value(timeout=3000)
    except Exception:
        pass
    # 2) Readonly/input benzeri alanlar
    try:
        loc = root.locator('input[readonly], textarea[readonly], input, textarea').first
        val = loc.input_value(timeout=1500)
        if val and len(val) >= 20:
            return val.strip()
    except Exception:
        pass
    # 3) Görünen metinler arasında regex ile ara
    try:
        texts = root.eval_on_selector_all(
            "*:not(script):not(style)",
            "els => els.map(e => (e.innerText||'').trim()).filter(Boolean).slice(0,200)"
        )
        pattern = re.compile(r'(0x[a-fA-F0-9]{40}|T[a-zA-Z0-9]{25,50}|(bc1|[13])[a-zA-HJ-NP-Z0-9]{14,90})')
        for t in texts:
            m = pattern.search(t)
            if m:
                return m.group(1)
    except Exception:
        pass
    raise RuntimeError("Yatırma adresi bulunamadı.")

def cmd_get_deposit(asset, network, show=False):
    with sync_playwright() as pw:
        context, page = _open_persistent(pw, headless=not show)
        try:
            _ensure_auth(page)
            _goto_wallet_asset_deposit(page, asset)  # doğrudan deposit sayfası
            scope = page
            _select_network_in(scope, network)
            address = _extract_deposit_address(page, scope=scope)
            print(address)
        finally:
            try:
                context.storage_state(path=AUTH_STATE_FILE)
            except Exception:
                pass
            context.close()

def _read_balance(page):
    sel = CONFIG["selectors"]["balance_text"]
    try:
        txt = page.locator(sel).first.inner_text(timeout=4000)
        return float(txt.replace(".", "").replace(",", ".").split()[0])
    except PWTimeout:
        return 0.0

def _place_market_sell(page, pair, amount=None):
    market_url = CONFIG["market_url_template"].format(pair=pair)
    page.goto(market_url, wait_until="domcontentloaded")
    s = CONFIG["selectors"]
    try:
        page.locator(s["sell_tab"]).first.click(timeout=4000)
    except PWTimeout:
        pass
    try:
        page.locator(s["market_order_tab"]).first.click(timeout=4000)
    except PWTimeout:
        pass
    if amount is not None:
        page.fill(s["amount_input"], "")
        page.fill(s["amount_input"], str(amount))
    page.locator(s["sell_submit"]).first.click(timeout=6000)

def cmd_monitor_and_sell(asset, network, pair, min_amount, interval, dry_run, show=False):
    with sync_playwright() as pw:
        context, page = _open_persistent(pw, headless=not show)
        try:
            _ensure_auth(page)
            print(f"{asset} cüzdanı izleniyor. Eşik: {min_amount}. Döngü: {interval}s. Dry-run: {dry_run}")
            while True:
                _goto_wallet_asset(page, asset)
                bal = _read_balance(page)
                print(f"Aktif bakiye: {bal}")
                if bal >= min_amount:
                    print(f"Eşik aşıldı: {bal} >= {min_amount}")
                    if dry_run:
                        print(f"[DRY-RUN] {pair} piyasasında satış EMRİ verilecekti.")
                    else:
                        _place_market_sell(page, pair, amount=bal)
                        print("Satış emri gönderildi.")
                    break
                time.sleep(interval)
        finally:
            try:
                context.storage_state(path=AUTH_STATE_FILE)
            except Exception:
                pass
            context.close()

def cmd_auth_info():
    import json
    data = json.loads(Path(AUTH_STATE_FILE).read_text(encoding="utf-8"))
    domains = sorted({c.get("domain") for c in data.get("cookies", [])})
    origins = [o.get("origin") for o in data.get("origins", [])]
    print("cookies.domains =", domains)
    print("origins =", origins)

import re
import json

def _pick_address_from_user_payload(payload: dict, asset: str, network: str) -> str:
    addrs = (payload or {}).get("payload", {}).get("addresses", {})
    if not isinstance(addrs, dict):
        raise RuntimeError("Beklenen alan yok: payload.addresses")

    asset_up = asset.upper()
    net_up = network.upper()

    tron_re = re.compile(r"^T[a-zA-Z0-9]{25,50}$")
    evm_re  = re.compile(r"^0x[a-fA-F0-9]{40}$")
    btc_re  = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{14,90}$")

    candidates = []

    for _, v in addrs.items():
        if not isinstance(v, dict):
            continue
        if v.get("direction") != "deposit":
            continue
        addr = (v.get("address") or "").strip()
        label = (v.get("label") or "").upper()
        n = (v.get("network") or "").upper()
        nt = (v.get("network_type") or "").upper()

        score = 0
        if net_up in ("TRC20", "TRC-20"):
            if not tron_re.match(addr):
                continue
            if n in ("TRX", "TRC20", "TRC-20"): score += 3
            if nt in ("TRX", "TRON", "TRC20"):  score += 3
            if "TRX" in label or "TRON" in label: score += 2
            if asset_up in ("USDT", "TRX"): score += 1
            candidates.append((score, addr))
        elif net_up in ("ERC20", "ETH", "ETHEREUM"):
            if not evm_re.match(addr):
                continue
            if n in ("ETH", "ERC20"): score += 3
            if nt in ("ETH", "ERC20", "ETHEREUM"): score += 3
            if "ETH" in label or "ERC" in label: score += 2
            if asset_up in ("USDT", "USDC", "ETH"): score += 1
            candidates.append((score, addr))
        else:
            # Diğer ağlar için genel doğrulama
            if tron_re.match(addr) or evm_re.match(addr) or btc_re.match(addr):
                candidates.append((1, addr))

    if not candidates:
        raise RuntimeError(f"{asset_up} {net_up} için yatırma adresi bulunamadı.")
    candidates.sort(reverse=True)
    return candidates[0][1]

def _api_ctx_with_auth(pw, auth_token: str):
    return pw.request.new_context(
        base_url="https://web.paribu.com",
        extra_http_headers={
            "authorization": auth_token,
            "origin": "https://www.paribu.com",
            "referer": "https://www.paribu.com/",
        },
        timeout=10000,
    )

def _sniff_auth_token(pw, show=False, trigger_url=None, wait_ms=7000):
    context, page = _open_persistent(pw, headless=not show)
    token = {"val": None}
    def on_request(req):
        if "https://web.paribu.com/" in req.url:
            a = req.headers.get("authorization")
            if a and len(a) > 50 and not token["val"]:
                token["val"] = a
    context.on("request", on_request)
    page.goto(trigger_url or CONFIG["wallet_url"], wait_until="domcontentloaded")
    page.wait_for_timeout(wait_ms)
    context.close()
    return token["val"]

def _sniff_and_save_auth_headers(show=False, wait_ms=6000):
    with sync_playwright() as pw:
        context, page = _open_persistent(pw, headless=not show)
        captured = {"authorization": None, "pragma-cache-local": None}
        def on_request(req):
            if "https://web.paribu.com/" in req.url:
                a = req.headers.get("authorization")
                p = req.headers.get("pragma-cache-local")
                if a and not captured["authorization"]:
                    captured["authorization"] = a
                    captured["pragma-cache-local"] = p
        context.on("request", on_request)
        page.goto(CONFIG["wallet_url"], wait_until="domcontentloaded")
        page.reload()
        page.wait_for_timeout(wait_ms)
        context.close()
    if not captured["authorization"]:
        raise SystemExit("Authorization yakalanamadı. Önce giriş yapın, sonra tekrar deneyin.")
    _save_json(AUTH_HEADERS_FILE, captured)
    return captured

def _get_auth_headers(pw=None, show=False, force_sniff=False):
    if not force_sniff and Path(AUTH_HEADERS_FILE).exists():
        data = _load_json(AUTH_HEADERS_FILE)
        if data.get("authorization"):
            return data
    # gerekirse yakala
    return _sniff_and_save_auth_headers(show=show)

def cmd_get_deposit_direct(asset: str, network: str, auth: str = None, refresh: bool = False, show: bool = False):
    # 1) Adres cache
    key = f"{asset.upper()}|{network.upper()}"
    cache = _load_json(ADDR_CACHE_FILE)
    if not refresh and key in cache:
        print(cache[key])
        return

    # 2) Yetkili başlıkları hazırla
    headers = None
    if auth:
        headers = {"authorization": auth}
    else:
        headers = _get_auth_headers(show=show)

    # 3) Sadece HTTP (tarayıcı açmadan). storage_state ile aynı çerezler de yüklensin.
    with sync_playwright() as pw:
        rc = pw.request.new_context(
            base_url="https://web.paribu.com",
            storage_state=AUTH_STATE_FILE if Path(AUTH_STATE_FILE).exists() else None,
            extra_http_headers={
                "authorization": headers.get("authorization"),
                "origin": "https://www.paribu.com",
                "referer": "https://www.paribu.com/",
                **({"pragma-cache-local": headers.get("pragma-cache-local")} if headers.get("pragma-cache-local") else {}),
            },
            timeout=8000,
        )
        r = rc.get("/user")
        if r.status >= 400:
            # Son çare: tek sefer kalıcı profilden çağır (çok nadir)
            with sync_playwright() as pw2:
                context, _ = _open_persistent(pw2, headless=True)
                rr = context.request.get("https://web.paribu.com/user", headers={
                    "authorization": headers.get("authorization"),
                    "origin": "https://www.paribu.com",
                    "referer": "https://www.paribu.com/",
                    **({"pragma-cache-local": headers.get("pragma-cache-local")} if headers.get("pragma-cache-local") else {}),
                })
                if rr.status >= 400:
                    context.close()
                    raise SystemExit(f"HTTP {rr.status}: {rr.text()[:300]}")
                data = rr.json()
                context.close()
        else:
            data = r.json()

    addr = _pick_address_from_user_payload(data, asset, network)
    cache[key] = addr
    _save_json(ADDR_CACHE_FILE, cache)
    print(addr)

def cmd_grab_auth(show=False):
    _sniff_and_save_auth_headers(show=show)
    print(f"Kaydedildi: {AUTH_HEADERS_FILE}")

def cmd_clear_cache():
    for f in [AUTH_HEADERS_FILE, ADDR_CACHE_FILE]:
        try:
            Path(f).unlink()
            print(f"Silindi: {f}")
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("init-login", help="Manuel giriş ve kalıcı profilin kaydı")
    p1.set_defaults(func=lambda args: cmd_init_login())

    p2 = sub.add_parser("get-deposit", help="Belirli varlık/ağ için yatırma adresini yazdır")
    p2.add_argument("--asset", required=True)
    p2.add_argument("--network", required=True)
    p2.add_argument("--show", action="store_true", help="Görünür modda çalıştır")
    p2.set_defaults(func=lambda args: cmd_get_deposit(args.asset.upper(), args.network.upper(), show=args.show))

    p3 = sub.add_parser("monitor-and-sell", help="Bakiye eşiği aşıldığında TRY paritesinde piyasa satış")
    p3.add_argument("--asset", required=True)
    p3.add_argument("--network", required=True)
    p3.add_argument("--pair", required=True, help="Örn: USDT-TRY")
    p3.add_argument("--min-amount", type=float, required=True)
    p3.add_argument("--interval", type=int, default=15)
    p3.add_argument("--execute", action="store_true", help="Dry-run kapatıp gerçekten satış yapar")
    p3.add_argument("--show", action="store_true", help="Görünür modda çalıştır")
    p3.set_defaults(func=lambda args: cmd_monitor_and_sell(
        args.asset.upper(), args.network.upper(), args.pair.upper(), args.min_amount, args.interval, not args.execute, show=args.show
    ))

    p0 = sub.add_parser("auth-info", help="auth_state.json içeriğini özetle")
    p0.set_defaults(func=lambda args: cmd_auth_info())

    pG = sub.add_parser("grab-auth", help="Authorization/başlıkları yakala ve kaydet")
    pG.add_argument("--show", action="store_true")
    pG.set_defaults(func=lambda args: cmd_grab_auth(show=args.show))

    pCC = sub.add_parser("clear-cache", help="auth/addr cache dosyalarını sil")
    pCC.set_defaults(func=lambda args: cmd_clear_cache())

    # get-deposit-direct’e bayraklar
    pD2 = sub.add_parser("get-deposit-direct", help="Adres (asset/network) için /user JSON'undan direkt çek")
    pD2.add_argument("--asset", required=True)
    pD2.add_argument("--network", required=True)
    pD2.add_argument("--auth", help="Authorization; yoksa kaydedilmiş başlıklar kullanılır")
    pD2.add_argument("--refresh", action="store_true", help="Adres cache’ini yenile")
    pD2.add_argument("--show", action="store_true", help="Gerekirse yakalama için görünür mod")
    pD2.set_defaults(func=lambda args: cmd_get_deposit_direct(args.asset.upper(), args.network.upper(), args.auth, args.refresh, args.show))

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()