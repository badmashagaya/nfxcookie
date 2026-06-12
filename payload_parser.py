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

def find_key_recursively(data, target_key):
    if isinstance(data, dict):
        for k, v in data.items():
            if k == target_key: return v
            if isinstance(v, (dict, list)):
                result = find_key_recursively(v, target_key)
                if result is not None: return result
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                result = find_key_recursively(item, target_key)
                if result is not None: return result
    return None

def extract_brace_matched_json(text, prefix):
    start_idx = text.find(prefix)
    if start_idx == -1: return None
    brace_start = text.find('{', start_idx)
    if brace_start == -1: return None
        
    brace_count, in_string, escape = 0, False, False
    for i in range(brace_start, len(text)):
        char = text[i]
        if escape: escape = False; continue
        if char == '\\': escape = True; continue
        if char == '"': in_string = not in_string; continue
            
        if not in_string:
            if char == '{': brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    return text[brace_start:i+1]
    return None

# --- MAIN PAYLOAD EXTRACTOR ---
def parse_html(acc_html: str, browse_html: Optional[str] = None) -> dict:
    # 1. Extract Hold Status strictly from GraphQL using direct string indexing (No CPU bottleneck)
    is_on_hold_graphql = None
    graphql_marker = "netflix.reactContext.models.graphql"
    if graphql_marker in acc_html:
        idx = acc_html.find(graphql_marker)
        parse_idx = acc_html.find("JSON.parse('", idx)
        if parse_idx != -1 and (parse_idx - idx) < 150:
            end_idx = acc_html.find("');", parse_idx)
            if end_idx != -1:
                raw_graphql_str = acc_html[parse_idx + 12:end_idx]
                try:
                    cleaned_str = raw_graphql_str.replace('\\"', '"').replace('\\\\', '\\')
                    cleaned_str = re.sub(r'\\x([0-9a-fA-F]{2})', r'\\u00\1', cleaned_str)
                    graphql_data = json.loads(cleaned_str)
                    
                    hold_val = find_key_recursively(graphql_data, "isUserOnHold")
                    if hold_val is not None:
                        is_on_hold_graphql = hold_val
                except json.JSONDecodeError:
                    pass

    # 2. Extract Profiles from falcorCache directly
    total_adult_profiles = 0
    locked_count = 0
    falcor_found = False

    def extract_profiles_from_html(html_string):
        nonlocal total_adult_profiles, locked_count, falcor_found
        if not html_string: return False
        
        if 'netflix.falcorCache' in html_string:
            falcor_json_str = extract_brace_matched_json(html_string, "netflix.falcorCache")
            if falcor_json_str:
                try:
                    sanitized_json_str = re.sub(r'\\x([0-9a-fA-F]{2})', r'\\u00\1', falcor_json_str)
                    falcor_data = json.loads(sanitized_json_str)
                    profiles_dict = falcor_data.get('profiles', {})
                    
                    if profiles_dict:
                        falcor_found = True
                        
                    for profile_id, profile_obj in profiles_dict.items():
                        summary = profile_obj.get('summary', {})
                        value = summary.get('value')
                        
                        if isinstance(value, dict):
                            is_kids = value.get('isKids', False)
                            if is_kids: continue
                            
                            is_locked = value.get('isPinLocked', False)
                            total_adult_profiles += 1
                            if is_locked:
                                locked_count += 1
                                
                    if falcor_found:
                        return True
                except json.JSONDecodeError:
                    pass
        return False

    if not extract_profiles_from_html(acc_html):
        extract_profiles_from_html(browse_html)

    unlocked_profiles = (total_adult_profiles - locked_count) if falcor_found else None

    # 3. Fallback extraction logic using standard reactContext
    rc_obj = find_object_after_marker(acc_html, "netflix.reactContext")
    
    if not rc_obj: 
        return {"error": True}

    rc_root = safe_load_json(rc_obj)
    
    models = rc_root.get("models", {})
    user_info = models.get("userInfo", {})
    
    if "data" in user_info:
        user_info = user_info["data"]
        
    fields = get_path(models, ["signupContext", "data", "flow", "fields"], {})
    plan_f = fields.get("currentPlan", {}).get("fields", {})

    email_value = (user_info.get("emailAddress") or "").strip().lower()
    user_guid = user_info.get("userGuid") or user_info.get("guid") or "Unknown"

    raw_plan_name = get_path(plan_f, ["localizedPlanName", "value"]) or "Unknown"
    
    raw_display_lang = None
    user_locale_obj = _deep_find_key(rc_root, "userLocale")
    if user_locale_obj and isinstance(user_locale_obj, dict):
        loc_data = user_locale_obj.get("locale", {})
        raw_display_lang = loc_data.get("displayName") or loc_data.get("fallbackDisplayName")

    quality = get_path(plan_f, ["videoQuality", "value"]) or "Unknown"

    membership_status = user_info.get("membershipStatus")
    is_subscribed = (membership_status == "CURRENT_MEMBER")
    
    if is_on_hold_graphql is not None:
        is_on_hold = is_on_hold_graphql
    else:
        is_on_hold = (fields.get("isPaused", {}).get("value") is True) or (fields.get("isPendingPause", {}).get("value") is True)

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
        "falcor_found": falcor_found,
        "unlocked_profiles": unlocked_profiles
    }
