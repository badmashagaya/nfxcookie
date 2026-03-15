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

    if key_data.get("active") == "false":
        raise HTTPException(status_code=403, detail="API Key has been deactivated. Access Denied.")

    key_data['api_key'] = api_key

    # --- QUOTA CHECK ---
    quota_limit = int(key_data.get("quota_limit", 0))
    quota_period = key_data.get("quota_period", "lifetime")
    
    if quota_limit > 0:
        current_usage = database.get_usage(api_key, quota_period)
        if current_usage >= quota_limit:
            raise HTTPException(status_code=429, detail=f"Quota Exceeded. Limit of {quota_limit} requests ({quota_period}) reached.")

    return key_data


# ==========================================
# --- BACKGROUND AUTO-SCANNER ENGINE ---
# ==========================================
IS_RESCANNING = False
CURRENT_SCHEDULE = "0,8,16"

def revalidate_db_task():
    global IS_RESCANNING
    if IS_RESCANNING: return
    IS_RESCANNING = True

    try:
        all_ids = database.r.smembers("all_hits")
        if not all_ids: return
        
        q = Queue()
        for nid in all_ids: q.put(nid)
        
        stats = {"hits": 0, "free": 0, "holds": 0, "dead": 0, "errors": 0, "unknown": 0, "duplicates": 0, "qualities": {}, "plans": {}}
        print_lock = threading.Lock()
        guid_lock = threading.Lock()
        processed_guids = set()
        
        def db_cleanup_hook(data): pass 
        def db_delete_hook(netflix_id):
            database.delete_cookie_db(netflix_id)

        threads = []
        db_threads = min(20, max(5, len(all_ids) // 10))
        for _ in range(db_threads):
            t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, PROXIES, processed_guids, guid_lock, db_cleanup_hook, db_delete_hook))
            t.daemon = True
            t.start()
            threads.append(t)
            
        q.join()
        print(f"[*] Rescan Complete! | Alive: {stats['hits']} | Dead/Removed: {stats['dead']} | On Hold/Removed: {stats['holds']}")
    
    finally:
        IS_RESCANNING = False

ist_tz = pytz.timezone('Asia/Kolkata')
scheduler = BackgroundScheduler(timezone=ist_tz)
# Note the id='rescan_job' so we can modify it later!
scheduler.add_job(revalidate_db_task, 'cron', hour=CURRENT_SCHEDULE, id='rescan_job', replace_existing=True)
scheduler.start()


# ==========================================
# --- RESCAN API & UI DASHBOARD ---
# ==========================================
@app.get("/api/rescan/status")
def get_rescan_status(user: str = Depends(verify_admin)):
    return {"is_running": IS_RESCANNING, "schedule": CURRENT_SCHEDULE}

@app.post("/api/rescan/now")
def trigger_rescan_now(background_tasks: BackgroundTasks, user: str = Depends(verify_admin)):
    global IS_RESCANNING
    if IS_RESCANNING:
        return {"success": False, "message": "A rescan is already running."}
    
    # Run it instantly in the background so the UI doesn't freeze
    background_tasks.add_task(revalidate_db_task)
    return {"success": True, "message": "Rescan triggered! It is running in the background."}

@app.post("/api/rescan/schedule")
def update_rescan_schedule(hours: str = Form(...), user: str = Depends(verify_admin)):
    global CURRENT_SCHEDULE
    clean_hours = "".join(c for c in hours if c.isdigit() or c == ",")
    if not clean_hours:
        return {"success": False, "message": "Invalid format. Use numbers and commas (e.g., '0,8,16')"}
    
    try:
        scheduler.add_job(revalidate_db_task, 'cron', hour=clean_hours, id='rescan_job', replace_existing=True)
        CURRENT_SCHEDULE = clean_hours
        return {"success": True, "message": f"Schedule updated successfully to hours: {clean_hours}"}
    except Exception as e:
        return {"success": False, "message": f"Failed to update schedule: {str(e)}"}

@app.get("/rescan", response_class=HTMLResponse)
def rescan_dashboard(request: Request, user: str = Depends(verify_admin)):
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>OOR Database Maintenance</title>
        <style>@import url('https://fonts.cdnfonts.com/css/nexa-bold');</style>
        <style>
            :root {{ --bg-color: #000; --card-bg: #06060c; --text-primary: #fff; --text-secondary: #8e8e99; --accent: rgb(0, 136, 255); --border: rgba(255, 255, 255, 0.1); --input-bg: rgba(255, 255, 255, 0.05); }}
            * {{ -webkit-tap-highlight-color: transparent; outline: none; box-sizing: border-box; }}
            body {{ margin: 0; padding: 40px 20px; font-family: 'Nexa', sans-serif; font-weight: 300; background: var(--bg-color); color: var(--text-primary); display: flex; flex-direction: column; align-items: center; min-height: 100vh; }}
            
            .import-card {{
                background: var(--card-bg); border-radius: 20px; padding: 40px 30px; width: 100%; max-width: 480px; position: relative; margin-bottom: 30px;
                box-shadow: 0 0 0 0.5px rgba(255,255,255,0.05), 0 20px 40px rgba(0,0,0,0.5);
            }}
            .import-card::before {{
                content: ''; position: absolute; inset: 0; border-radius: 20px; padding: 1px;
                background: linear-gradient(170deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 30%, transparent 55%, rgba(255,255,255,0.04) 80%, rgba(255,255,255,0.09) 100%);
                -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0); -webkit-mask-composite: xor; mask-composite: exclude; pointer-events: none;
            }}
            h2 {{ margin: 0 0 10px 0; font-size: 20px; font-weight: 700; text-align: center; letter-spacing: 0.5px;}}
            p {{ font-size: 13px; color: var(--text-secondary); line-height: 1.5; margin: 0 0 25px 0; text-align: center;}}
            
            .status-badge {{
                display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 50px; font-size: 12px; font-weight: 700; margin: 0 auto 30px auto;
            }}
            .status-idle {{ background: rgba(255,255,255,0.05); color: var(--text-secondary); border: 1px solid rgba(255,255,255,0.1); }}
            .status-running {{ background: rgba(52, 199, 89, 0.1); color: #34c759; border: 1px solid rgba(52, 199, 89, 0.2); animation: pulse 2s infinite; }}
            @keyframes pulse {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} 100% {{ opacity: 1; }} }}
            
            .form-group {{ margin-bottom: 20px; position: relative; }}
            label {{ display: block; margin-bottom: 8px; font-size: 12px; color: var(--text-secondary); font-weight: 700; padding-left: 4px;}}
            input[type="text"] {{ width: 100%; height: 50px; padding: 0 16px; border-radius: 12px; background: var(--input-bg); border: 1px solid var(--border); color: white; font-size: 14px; font-weight: 700; font-family: 'Nexa', sans-serif; transition: 0.2s; }}
            input[type="text"]:focus {{ border-color: var(--accent); background: rgba(255,255,255,0.08); }}
            
            .btn-white {{ width: 100%; height: 54px; border-radius: 14px; margin-top: 5px; background: #ffffff; color: #000000; border: none; font-size: 15px; font-weight: 700; font-family: 'Nexa', sans-serif; cursor: pointer; transition: transform 0.1s ease; box-shadow: 0 4px 14px rgba(255,255,255,0.1); }}
            .btn-white:active {{ transform: scale(0.96); }}
            
            .btn-outline {{ width: 100%; height: 54px; border-radius: 14px; background: transparent; color: var(--accent); border: 1px solid var(--accent); font-size: 15px; font-weight: 700; font-family: 'Nexa', sans-serif; cursor: pointer; transition: 0.2s; margin-bottom: 20px; }}
            .btn-outline:active {{ transform: scale(0.96); background: rgba(0, 136, 255, 0.1); }}

            .toast {{ position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(50px); background: #1c1c1e; color: #fff; padding: 12px 24px; border-radius: 100px; font-size: 13px; font-weight: 700; opacity: 0; transition: 0.3s; pointer-events: none; border: 1px solid rgba(255,255,255,0.1); }}
            .toast.show {{ transform: translateX(-50%) translateY(0); opacity: 1; }}
        </style>
    </head>
    <body>
        <div class="import-card" style="display: flex; flex-direction: column; align-items: center;">
            <h2>Database Rescan Engine</h2>
            <p>Automatically verify all stored cookies to clean out dead accounts.</p>
            
            <div id="statusBadge" class="status-badge status-idle">Checking Status...</div>
            
            <button class="btn-outline" id="btnNow" onclick="triggerRescan()">+ Force Rescan Now</button>
            
            <div style="width: 100%; height: 1px; background: var(--border); margin: 10px 0 25px 0;"></div>
            
            <div style="width: 100%;">
                <div class="form-group">
                    <label>Automated Schedule (Hours in IST)</label>
                    <input type="text" id="scheduleInput" value="{CURRENT_SCHEDULE}" placeholder="e.g. 0,8,16">
                    <p style="text-align: left; font-size: 11px; margin-top: 8px; margin-bottom: 0;">Example: <b>0,8,16</b> means 12 AM, 8 AM, 4 PM.</p>
                </div>
                <button class="btn-white" id="btnSchedule" onclick="updateSchedule()">Update Schedule</button>
            </div>
        </div>

        <div class="toast" id="toast"></div>

        <script>
            function showToast(msg) {{
                const t = document.getElementById('toast');
                t.innerText = msg;
                t.classList.add('show');
                setTimeout(() => t.classList.remove('show'), 3000);
            }}

            async function checkStatus() {{
                try {{
                    const res = await fetch('/api/rescan/status');
                    const data = await res.json();
                    const badge = document.getElementById('statusBadge');
                    if (data.is_running) {{
                        badge.className = 'status-badge status-running';
                        badge.innerText = '🟢 Rescan is currently running...';
                    }} else {{
                        badge.className = 'status-badge status-idle';
                        badge.innerText = '⚪ System is Idle';
                    }}
                }} catch(e) {{}}
            }}

            async function triggerRescan() {{
                const btn = document.getElementById('btnNow');
                btn.disabled = true;
                try {{
                    const res = await fetch('/api/rescan/now', {{ method: 'POST' }});
                    const data = await res.json();
                    showToast(data.message);
                    checkStatus();
                }} catch(e) {{ showToast('Network Error'); }}
                setTimeout(() => btn.disabled = false, 1000);
            }}

            async function updateSchedule() {{
                const btn = document.getElementById('btnSchedule');
                const val = document.getElementById('scheduleInput').value;
                btn.disabled = true;
                
                const formData = new FormData();
                formData.append("hours", val);

                try {{
                    const res = await fetch('/api/rescan/schedule', {{ method: 'POST', body: formData }});
                    const data = await res.json();
                    showToast(data.message);
                }} catch(e) {{ showToast('Network Error'); }}
                btn.disabled = false;
            }}

            // Poll status every 5 seconds
            checkStatus();
            setInterval(checkStatus, 5000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


# ==========================================
# --- GENERAL API ENDPOINTS ---
# ==========================================

@app.post("/api/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    proxy_file: UploadFile = File(None), 
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

    request_proxies = PROXIES
    if proxy_file and proxy_file.filename:
        proxy_bytes = await proxy_file.read()
        custom_proxies = core.parse_proxies_from_bytes(proxy_bytes)
        if custom_proxies:
            request_proxies = custom_proxies

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
            t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, request_proxies, processed_guids, guid_lock, db_save_hook))
            t.daemon = True
            t.start()
            threads.append(t)
            
        while any(t.is_alive() for t in threads):
            upload_tasks[task_id]["checked"] = num_cookies - q.qsize()
            time.sleep(0.5)

        q.join()
        local_ip, proxy_status = core.get_public_ip(request_proxies)
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

@app.get("/api/cookies")
@app.get("/api/cookie")
def get_all_cookies(
    plan: Optional[str] = None, 
    quality: Optional[str] = None, 
    language: Optional[str] = None, 
    user: str = Depends(verify_admin) 
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
    
    if success:
        database.increment_quota(key_data['api_key'], key_data.get('quota_period', 'lifetime'))
    
    return {
        "success": success, 
        "message": msg,
        "refreshed_cookie": refreshed
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
