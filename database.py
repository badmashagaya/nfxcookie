import redis
import json
import os

UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "https://optimal-shad-3679.upstash.io")
UPSTASH_PORT = os.getenv("UPSTASH_REDIS_PORT", 6379)
UPSTASH_PASS = os.getenv("UPSTASH_REDIS_REST_TOKEN", "AQ5fAAImcDFmNTZjOWYyZDkyZGE0NmEyODI5OTUxMTRjOTY0MTk1MHAxMzY3OQ")

r = redis.Redis(
    host=UPSTASH_URL.replace("https://", ""),
    port=UPSTASH_PORT,
    password=UPSTASH_PASS,
    ssl=True,
    decode_responses=True
)

def save_cookie_db(data: dict):
    nid = data["netflix_id"]
    try:
        # Save exact JSON directly to redis key
        r.set(f"cookie:{nid}", json.dumps(data))
        
        r.sadd("all_hits", nid)
        if data.get("plan"): r.sadd(f"filter:plan:{data['plan']}", nid)
        if data.get("quality"): r.sadd(f"filter:quality:{data['quality']}", nid)
        if data.get("language"): r.sadd(f"filter:language:{data['language']}", nid)
    except Exception as e:
        print(f"Redis Save Error: {e}")

def get_filtered_cookies(plan=None, quality=None, language=None):
    try:
        # Safely prevents 500 Internal Error if DB is empty or disconnected
        if not r.exists("all_hits"):
            return []
            
        sets_to_intersect = ["all_hits"]
        if plan: sets_to_intersect.append(f"filter:plan:{plan}")
        if quality: sets_to_intersect.append(f"filter:quality:{quality}")
        if language: sets_to_intersect.append(f"filter:language:{language}")
        
        valid_ids = r.sinter(*sets_to_intersect)
        if not valid_ids: return []
        
        results = []
        for nid in valid_ids:
            raw = r.get(f"cookie:{nid}")
            if raw:
                try: results.append(json.loads(raw))
                except: pass
        return results
    except Exception as e:
        print(f"Redis Fetch Error: {e}")
        return []

def delete_cookie(nid: str):
    try:
        raw = r.get(f"cookie:{nid}")
        if raw:
            data = json.loads(raw)
            r.srem("all_hits", nid)
            if data.get("plan"): r.srem(f"filter:plan:{data['plan']}", nid)
            if data.get("quality"): r.srem(f"filter:quality:{data['quality']}", nid)
            if data.get("language"): r.srem(f"filter:language:{data['language']}", nid)
            r.delete(f"cookie:{nid}")
    except: pass
    
# --- API KEY & QUOTA MANAGEMENT ---
import datetime
import pytz

def create_api_key(api_key: str, role: str, label: str, quota_limit: int, quota_period: str):
    r.hset(f"apikey:{api_key}", mapping={
        "role": role, 
        "label": label,          # <--- Now saves the custom label
        "active": "true",        # <--- Defaults to active
        "quota_limit": quota_limit,
        "quota_period": quota_period,
        "created_at": datetime.datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M')
    })

def toggle_api_key(api_key: str, active: bool):
    # Switches the key between "true" and "false" in the database
    r.hset(f"apikey:{api_key}", "active", "true" if active else "false")


def get_api_key(api_key: str):
    return r.hgetall(f"apikey:{api_key}")

def get_usage(api_key: str, period: str):
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist)
    if period == 'daily': suffix = now.strftime('%Y-%m-%d')
    elif period == 'monthly': suffix = now.strftime('%Y-%m')
    elif period == 'yearly': suffix = now.strftime('%Y')
    else: suffix = 'lifetime'
    
    val = r.get(f"usage:{api_key}:{suffix}")
    return int(val) if val else 0

def increment_quota(api_key: str, period: str):
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist)
    if period == 'daily': suffix = now.strftime('%Y-%m-%d'); ttl = 86400
    elif period == 'monthly': suffix = now.strftime('%Y-%m'); ttl = 2592000
    elif period == 'yearly': suffix = now.strftime('%Y'); ttl = 31536000
    else: suffix = 'lifetime'; ttl = None
    
    key = f"usage:{api_key}:{suffix}"
    new_val = r.incr(key)
    if new_val == 1 and ttl: r.expire(key, ttl)
    return new_val

def get_all_keys():
    keys = r.keys("apikey:*")
    result = []
    for k in keys:
        data = r.hgetall(k)
        raw_key = k.replace("apikey:", "")
        data['key'] = raw_key
        data['current_usage'] = get_usage(raw_key, data.get('quota_period', 'lifetime'))
        result.append(data)
    return result

def delete_api_key(api_key: str):
    r.delete(f"apikey:{api_key}")
