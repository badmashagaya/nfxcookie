# payload_parser.py
import json
import re
from typing import Optional, Any, List

# --- HELPER FUNCTIONS ---
def js_hex_to_json_escapes(s: str) -> str:
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: "\\u00" + m.group(1), s)

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

def _deep_find_key(obj, target_key):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == target_key and value: return value
            result = _deep_find_key(value, target_key)
            if result: return result
    elif isinstance(obj, list):
        for item in obj:
            result = _deep_find_key(item, target_key)
            if result: return result
    return None

# --- MAIN PAYLOAD EXTRACTOR ---
def parse_html(html: str) -> dict:
    """
    Hunts down the Netflix reactContext payload, converts it to JSON, 
    and returns a standardized dictionary of values to core.py.
    """
    rc_obj = find_object_after_marker(html, "netflix.reactContext")
    
    if not rc_obj: 
        return {"error": True}

    rc_root = safe_load_json(rc_obj)
    
    models = rc_root.get("models", {})
    user_info = models.get("userInfo", {})
    
    # Gracefully handle nested data nodes
    if "data" in user_info:
        user_info = user_info["data"]
        
    fields = get_path(models, ["signupContext", "data", "flow", "fields"], {})
    plan_f = fields.get("currentPlan", {}).get("fields", {})

    email_value = (user_info.get("emailAddress") or "").strip().lower()
    user_guid = user_info.get("userGuid") or user_info.get("guid") or "Unknown"

    raw_plan_name = get_path(plan_f, ["localizedPlanName", "value"]) or "Unknown"
    
    # Language Extraction
    raw_display_lang = None
    user_locale_obj = _deep_find_key(rc_root, "userLocale")
    if user_locale_obj and isinstance(user_locale_obj, dict):
        loc_data = user_locale_obj.get("locale", {})
        raw_display_lang = loc_data.get("displayName") or loc_data.get("fallbackDisplayName")

    quality = get_path(plan_f, ["videoQuality", "value"]) or "Unknown"

    membership_status = user_info.get("membershipStatus")
    is_subscribed = (membership_status == "CURRENT_MEMBER")
    is_on_hold = (fields.get("isPaused", {}).get("value") is True) or (fields.get("isPendingPause", {}).get("value") is True)

    # Payment Extraction
    payment_type = "Unknown"
    masked_card = None
    pm_list = fields.get("paymentMethods", {}).get("value") or []
    
    if pm_list and isinstance(pm_list, list):
        pm_val = pm_list[0].get("value", {})
        ptype = pm_val.get("type", {}).get("value")
        pdisplay = pm_val.get("displayText", {}).get("value")
        
        if ptype:
            payment_type = ptype
            if ptype.upper() in ["VISA", "MASTERCARD", "AMEX", "DISCOVER", "CC", "CREDITCARD"] or pm_val.get("paymentMethod", {}).get("value") == "CC":
                payment_type = "CC"
                masked_card = pdisplay
            elif pdisplay:
                 masked_card = pdisplay

    price = get_path(plan_f, ["planPrice", "value"])
    next_billing = get_path(fields, ["nextBillingDate", "value"])
    member_since = user_info.get("memberSince") or get_path(fields, ["memberSince", "value"])
    phone = get_path(user_info, ["phoneNumber", "value"]) or "Unknown"
    max_streams = get_path(plan_f, ["maxStreams", "value"])
    
    # Fallback to regex for profiles count as it's abstracted out of standard Context 
    profiles_count = "Unknown"
    match = re.search(r'>(\d+)\s+profiles<', html, re.IGNORECASE)
    if match:
        profiles_count = match.group(1)

    return {
        "error": False,
        "guid": user_guid,
        "email": email_value,
        "name": user_info.get("name"),
        "country": user_info.get("countryOfSignup") or user_info.get("currentCountry"),
        "raw_plan_name": raw_plan_name,
        "raw_display_lang": raw_display_lang,
        "quality": quality,
        "price": price,
        "member_since": member_since,
        "next_billing": next_billing,
        "payment_type": payment_type,
        "masked_card": masked_card,
        "phone": phone,
        "max_streams": max_streams,
        "is_on_hold": is_on_hold,
        "is_subscribed": is_subscribed,
        "membership_status": membership_status,
        "profiles_count": profiles_count
    }

