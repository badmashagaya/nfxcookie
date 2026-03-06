from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
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

app = FastAPI(title="OOR Full System")
PROXIES = core.load_proxies()

upload_tasks = {}

# --- BACKGROUND AUTO-SCANNER ---
def revalidate_db_task():
    print("[*] Starting Scheduled DB Revalidation...")
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
    
    def db_cleanup_hook(data):
        pass 

    threads = []
    # Smart threading for DB background task
    db_threads = min(20, max(5, len(all_ids) // 10))
    for _ in range(db_threads):
        t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, PROXIES, processed_guids, guid_lock, db_cleanup_hook))
        t.daemon = True
        t.start()
        threads.append(t)
    q.join()
    print("[*] Database revalidation finished.")

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
    req_language: str = Form("")
):
    contents = await file.read()
    filename = getattr(file, "filename", "") or "" 
    extracted_ids = core.extract_ids_from_bytes(contents, filename)
    
    if not extracted_ids: 
        return JSONResponse(content={"error": "No NetflixIds found"}, status_code=400)

    id_list = list(extracted_ids)
    task_id = str(uuid.uuid4())
    
    upload_tasks[task_id] = {
        "status": "running",
        "total": len(id_list),
        "checked": 0,
        "summary": None,
        "start_time": time.time(),
        "eta": 0
    }

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
        
        # --- SMART THREADING ALGORITHM ---
        # Adjusts dynamically based on load to prevent Netflix blocks
        # Minimum 3 threads, Maximum 50 threads.
        num_cookies = len(id_list)
        if num_cookies <= 20:
            num_threads = min(3, num_cookies)
        elif num_cookies <= 100:
            num_threads = 10
        elif num_cookies <= 500:
            num_threads = 25
        else:
            num_threads = 50
            
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
        upload_tasks[task_id]["summary"] = {
            "Checked": num_cookies,
            "Base VPN/IP": local_ip,
            "Proxy Status": proxy_status,
            "Breakdown by Quality (Hits Only)": stats["qualities"],
            "Breakdown by Plan (Hits Only)": stats["plans"]
        }

    background_tasks.add_task(run_nfx_and_store)
    return {"task_id": task_id, "message": "Engine Started."}


@app.get("/api/status/{task_id}")
def get_task_status(task_id: str):
    if task_id not in upload_tasks:
        return JSONResponse(content={"error": "Task not found"}, status_code=404)
        
    task_data = upload_tasks[task_id]
    
    # --- ETA CALCULATION ---
    if task_data["status"] == "running" and task_data["checked"] > 0:
        elapsed = time.time() - task_data["start_time"]
        rate = elapsed / task_data["checked"] # seconds per cookie
        remaining = task_data["total"] - task_data["checked"]
        task_data["eta"] = max(0, int(rate * remaining))
        
    return task_data


@app.get("/api/cookies")
@app.get("/api/cookie")
def get_all_cookies(plan: Optional[str] = None, quality: Optional[str] = None, language: Optional[str] = None):
    results = database.get_filtered_cookies(plan, quality, language)
    return {"count": len(results), "data": results}

@app.post("/api/tv-login")
def tv_login(netflix_id: str = Form(...), tv_code: str = Form(...)):
    success, msg = core.automate_tv_login(netflix_id, tv_code, PROXIES)
    return {"success": success, "message": msg}

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
