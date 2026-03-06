from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import uvicorn
import threading
from queue import Queue
import random

import core
import database

app = FastAPI(title="OOR Full System")
PROXIES = core.load_proxies()

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
        pass # Ignore, we just let the CLI script run

    threads = []
    for _ in range(min(10, len(all_ids))):
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
    # Safely get filename to prevent 500 error
    filename = getattr(file, "filename", "") or "" 
    extracted_ids = core.extract_ids_from_bytes(contents, filename)
    
    if not extracted_ids: 
        return JSONResponse(content={"error": "No NetflixIds found"}, status_code=400)

    id_list = list(extracted_ids)

    def run_nfx_and_store():
        q = Queue()
        for nid in id_list: q.put(nid)
        
        stats = {"hits": 0, "free": 0, "holds": 0, "dead": 0, "errors": 0, "unknown": 0, "duplicates": 0, "qualities": {}, "plans": {}}
        print_lock = threading.Lock()
        guid_lock = threading.Lock()
        processed_guids = set() 
        
        # This hook runs EXACTLY when nfx_live_fast identifies a HIT that is NOT on hold
        def db_save_hook(data):
            # Strict Case-Insensitive Filtering
            if req_plan and req_plan.lower() != data["plan"].lower(): return
            if req_quality and req_quality.lower() != data["quality"].lower(): return
            if req_language and req_language.lower() != data["language"].lower(): return
            database.save_cookie_db(data)

        threads = []
        for _ in range(min(20, len(id_list))):
            t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, PROXIES, processed_guids, guid_lock, db_save_hook))
            t.daemon = True
            t.start()
            threads.append(t)
        q.join()

    background_tasks.add_task(run_nfx_and_store)
    return {"message": f"Started processing {len(id_list)} cookies with Exact CLI engine."}


@app.get("/api/cookies")
@app.get("/api/cookie") # Prevents 404/500 if user types singular
def get_all_cookies(plan: Optional[str] = None, quality: Optional[str] = None, language: Optional[str] = None):
    results = database.get_filtered_cookies(plan, quality, language)
    return {"count": len(results), "data": results}



@app.post("/api/tv-login")
def tv_login(
    tv_code: str = Form(...),
    netflix_id: Optional[str] = Form(None),
    plan: Optional[str] = Form(None),
    quality: Optional[str] = Form(None),
    language: Optional[str] = Form(None)
):
    target_id = netflix_id
    
    # If the user didn't provide a specific NetflixId, search the DB using the filters
    if not target_id:
        available_cookies = database.get_filtered_cookies(plan, quality, language)
        
        if not available_cookies:
            return {"success": False, "message": "No cookies found in the database matching those filters."}
        
        # Randomly select one cookie from the matching results
        chosen_cookie = random.choice(available_cookies)
        target_id = chosen_cookie["netflix_id"]

    # Execute the automation
    success, msg, refreshed_cookie = core.automate_tv_login(target_id, tv_code, PROXIES)
    
    return {
        "success": success, 
        "message": msg, 
        "original_cookie_used": target_id,
        "refreshed_cookie": refreshed_cookie
    }



@app.get("/", response_class=HTMLResponse)
def serve_ui():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
