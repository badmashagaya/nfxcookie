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
import os
import datetime

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

    quota_limit = int(key_data.get("quota_limit", 0))
    quota_period = key_data.get("quota_period", "lifetime")
    
    if quota_limit > 0:
        current_usage = database.get_usage(api_key, quota_period)
        if current_usage >= quota_limit:
            raise HTTPException(status_code=429, detail=f"Quota Exceeded. Limit of {quota_limit} requests ({quota_period}) reached.")

    return key_data


# ==========================================
# --- CENTRAL LOGGING SYSTEM ---
# ==========================================
def write_scan_log(scan_type: str, total_checked: int, stats: dict, proxy_status: str):
    try:
        ist = pytz.timezone('Asia/Kolkata')
        now_str = datetime.datetime.now(ist).strftime('%Y-%m-%d %I:%M:%S %p IST')
        
        log = [
            "==========================================",
            "          OOR LAST SCAN LOG               ",
            "==========================================",
            f"Date & Time : {now_str}",
            f"Scan Type   : {scan_type}",
            f"Network     : {proxy_status}",
            "------------------------------------------",
            "              SUMMARY                     ",
            "------------------------------------------",
            f"Total Checked : {total_checked}",
            f"Hits (Alive)  : {stats.get('hits', 0)}",
            f"Dead/Invalid  : {stats.get('dead', 0)}",
            f"On Hold       : {stats.get('holds', 0)}",
            f"Free Accounts : {stats.get('free', 0)}",
            f"Errors/Blocks : {stats.get('errors', 0)}",
            f"Duplicates    : {stats.get('duplicates', 0)}",
            f"Unknown       : {stats.get('unknown', 0)}",
            "------------------------------------------"
        ]
        
        if stats.get('plans'):
            log.append("           PLANS (HITS)           ")
            for p, c in stats['plans'].items():
                log.append(f" - {p}: {c}")
            log.append("------------------------------------------")
            
        if stats.get('qualities'):
            log.append("         QUALITIES (HITS)         ")
            for q, c in stats['qualities'].items():
                log.append(f" - {q}: {c}")
            log.append("==========================================")

        # "w" completely overwrites the file every time
        with open("last_scan.log", "w", encoding="utf-8") as f:
            f.write("\n".join(log) + "\n")
    except Exception as e:
        print(f"Log Write Error: {e}")


# ==========================================
# --- BACKGROUND AUTO-SCANNER ENGINE ---
# ==========================================
IS_RESCANNING = False

# Fetch the permanently saved config from Redis!
db_conf = database.get_rescan_config()
CURRENT_SCHEDULE = db_conf["schedule"]
USE_PROXIES_RESCAN = db_conf["use_proxies"]

def revalidate_db_task():
    global IS_RESCANNING, USE_PROXIES_RESCAN
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
        def db_delete_hook(netflix_id): database.delete_cookie_db(netflix_id)

        # --- DYNAMIC PERSISTENT PROXY LOADER ---
        worker_proxies = []
        if USE_PROXIES_RESCAN:
            if os.path.exists("rescan_proxies.txt"):
                with open("rescan_proxies.txt", "rb") as f:
                    worker_proxies = core.parse_proxies_from_bytes(f.read())
            else:
                # Fallback to the main proxy.txt if the custom rescan one is missing
                worker_proxies = PROXIES

        threads = []
        db_threads = min(20, max(5, len(all_ids) // 10))
        for _ in range(db_threads):
            t = threading.Thread(target=core.check_worker, args=(q, print_lock, stats, worker_proxies, processed_guids, guid_lock, db_cleanup_hook, db_delete_hook))
            t.daemon = True
            t.start()
            threads.append(t)
            
        q.join()
        
        # Pull final network status and generate the log!
        local_ip, proxy_status = core.get_public_ip(worker_proxies)
        write_scan_log("Database Rescan", len(all_ids), stats, proxy_status)
        
        proxy_mode = "PROXIES" if USE_PROXIES_RESCAN else "DIRECT IP"
        print(f"[*] Rescan Complete ({proxy_mode}) | Alive: {stats['hits']} | Dead: {stats['dead']} | Hold: {stats['holds']}")
    
    finally:
        IS_RESCANNING = False

ist_tz = pytz.timezone('Asia/Kolkata')
scheduler = BackgroundScheduler(timezone=ist_tz)
scheduler.add_job(revalidate_db_task, 'cron', hour=CURRENT_SCHEDULE, id='rescan_job', replace_existing=True)
scheduler.start()


# ==========================================
# --- RESCAN API & UI DASHBOARD ---
# ==========================================
@app.get("/api/rescan/status")
def get_rescan_status(user: str = Depends(verify_admin)):
    return {
        "is_running": IS_RESCANNING, 
        "schedule": CURRENT_SCHEDULE,
        "use_proxies": USE_PROXIES_RESCAN,
        "has_proxies": os.path.exists("rescan_proxies.txt")
    }

@app.post("/api/rescan/now")
def trigger_rescan_now(background_tasks: BackgroundTasks, user: str = Depends(verify_admin)):
    global IS_RESCANNING
    if IS_RESCANNING: 
        return {"success": False, "message": "A rescan is already running in the background."}
    background_tasks.add_task(revalidate_db_task)
    return {"success": True, "message": "Rescan triggered! It is running in the background."}

@app.post("/api/rescan/config")
def update_rescan_config(
    hours: Optional[str] = Form(None), 
    use_proxies: Optional[str] = Form(None), 
    user: str = Depends(verify_admin)
):
    global CURRENT_SCHEDULE, USE_PROXIES_RESCAN
    
    if hours is not None:
        clean_hours = "".join(c for c in hours if c.isdigit() or c == ",")
        if not clean_hours: return {"success": False, "message": "Invalid schedule format. Use numbers and commas."}
        try:
            scheduler.add_job(revalidate_db_task, 'cron', hour=clean_hours, id='rescan_job', replace_existing=True)
            CURRENT_SCHEDULE = clean_hours
        except Exception as e:
            return {"success": False, "message": f"Failed to update schedule: {str(e)}"}
            
    if use_proxies is not None:
        USE_PROXIES_RESCAN = (use_proxies.lower() == "true")

    # Save permanently to Redis!
    database.set_rescan_config(CURRENT_SCHEDULE, USE_PROXIES_RESCAN)
    
    return {"success": True, "message": "Configuration saved perfectly."}

@app.post("/api/rescan/proxy")
async def upload_rescan_proxy(proxy_file: UploadFile = File(...), user: str = Depends(verify_admin)):
    contents = await proxy_file.read()
    with open("rescan_proxies.txt", "wb") as f:
        f.write(contents)
    return {"success": True, "message": "Custom proxies stored permanently."}

@app.post("/api/rescan/proxy/delete")
def delete_rescan_proxy(user: str = Depends(verify_admin)):
    if os.path.exists("rescan_proxies.txt"):
        os.remove("rescan_proxies.txt")
    return {"success": True, "message": "Custom proxies deleted successfully."}

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
            
            body {{ 
                margin: 0; padding: 40px 20px; 
                font-family: 'Nexa', sans-serif; font-weight: 300; 
                background: var(--bg-color); color: var(--text-primary); 
                display: flex; flex-direction: column; 
                align-items: center; justify-content: center; 
                min-height: 100vh;
            }}

            .main-content {{ display: flex; align-items: center; justify-content: center; width: 100%; }}

            
            .import-card {{
                background: var(--card-bg); border-radius: 20px; padding: 30px 20px; width: 100%; max-width: 380px; position: relative;
                box-shadow: 0 0 0 0.5px rgba(255,255,255,0.05), 0 20px 40px rgba(0,0,0,0.5);
                display: flex; flex-direction: column; align-items: center;
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
            .status-running {{ background: rgba(52, 199, 89, 0.1); color: #34c759; border: 1px solid rgba(52, 199, 89, 0.2); }}
            
            .spin {{ animation: spin 2s linear infinite; }}
            @keyframes spin {{ 100% {{ transform: rotate(360deg); }} }}
            
            .form-group {{ margin-bottom: 20px; position: relative; width: 100%; }}
            label {{ display: block; margin-bottom: 8px; font-size: 12px; color: var(--text-secondary); font-weight: 700; padding-left: 4px;}}
            input[type="text"] {{ width: 100%; height: 50px; padding: 0 16px; border-radius: 12px; background: var(--input-bg); border: 1px solid var(--border); color: white; font-size: 14px; font-weight: 700; font-family: 'Nexa', sans-serif; transition: 0.2s; }}
            input[type="text"]:focus {{ border-color: var(--accent); background: rgba(255,255,255,0.08); }}
            
            .btn-white {{ width: 100%; height: 54px; border-radius: 14px; margin-top: 5px; background: #ffffff; color: #000000; border: none; font-size: 15px; font-weight: 700; font-family: 'Nexa', sans-serif; cursor: pointer; transition: transform 0.1s ease; box-shadow: 0 4px 14px rgba(255,255,255,0.1); }}
            .btn-white:active {{ transform: scale(0.96); }}
            
            .btn-outline {{ width: 100%; height: 54px; border-radius: 14px; background: transparent; color: var(--accent); border: 1px solid var(--accent); font-size: 15px; font-weight: 700; font-family: 'Nexa', sans-serif; cursor: pointer; transition: 0.2s; margin-bottom: 20px; }}
            .btn-outline:active {{ transform: scale(0.96); background: rgba(0, 136, 255, 0.1); }}

            /* Sleek Apple Toggle Switch */
            .toggle-container {{ width: 100%; display: flex; align-items: center; justify-content: space-between; background: var(--input-bg); padding: 16px; border-radius: 14px; border: 1px solid var(--border); margin-bottom: 20px; }}
            .toggle-label {{ font-size: 13px; font-weight: 700; color: #fff; }}
            .toggle-sub {{ font-size: 11px; font-weight: 400; color: var(--text-secondary); margin-top: 4px; }}
            .switch {{ position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0; }}
            .switch input {{ opacity: 0; width: 0; height: 0; }}
            .slider {{ position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(255,255,255,0.1); transition: .4s; border-radius: 24px; }}
            .slider:before {{ position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }}
            input:checked + .slider {{ background-color: #34c759; }}
            input:checked + .slider:before {{ transform: translateX(20px); }}

            /* Proxy File Upload UI */
            .file-upload-wrapper {{ position: relative; border: 1px dashed rgba(255,255,255,0.2); border-radius: 12px; height: 70px; background: rgba(0,0,0,0.2); transition: all 0.3s ease; cursor: pointer; display: flex; justify-content: center; align-items: center; margin-bottom: 10px; width: 100%; }}
            .file-upload-wrapper:hover {{ border-color: rgba(255,255,255,0.5); background: rgba(255,255,255,0.05); }}
            .file-upload-wrapper input[type="file"] {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; z-index: 2; }}
            .file-upload-content {{ display: flex; align-items: center; gap: 10px; pointer-events: none; }}
            .file-upload-text {{ font-size: 12px; color: var(--text-secondary); font-weight: 700; }}
            
            .proxy-active-state {{ width: 100%; background: rgba(52, 199, 89, 0.08); border: 1px solid rgba(52, 199, 89, 0.2); border-radius: 12px; padding: 14px 16px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}

            /* Beautiful Toast Notifications */
            .toast-container {{ position: fixed; top: 20px; right: 20px; display: flex; flex-direction: column; gap: 10px; z-index: 9999; }}
            .toast-card {{ background: #1c1c1e; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 16px 20px; color: #fff; width: 320px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); transform: translateX(120%); transition: transform 0.4s cubic-bezier(0.25, 1, 0.5, 1); display: flex; align-items: flex-start; gap: 12px; }}
            .toast-card.show {{ transform: translateX(0); }}
            .toast-icon {{ flex-shrink: 0; width: 22px; height: 22px; }}
            .toast-content {{ flex: 1; display: flex; flex-direction: column; }}
            .toast-title {{ font-size: 14px; font-weight: 700; margin-bottom: 4px; }}
            .toast-message {{ font-size: 12px; color: var(--text-secondary); line-height: 1.4; }}

            .site-footer {{ margin-top: 0px; font-size: 13px; opacity: 0.7; font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'SF Pro Display', system-ui, sans-serif; font-weight: 400; color: var(--text-secondary); text-align: center; width: 100%; padding-top: 30px; }}


            /* Responsive Media Queries */
            @media (min-width: 420px) {{
                .import-card {{ padding: 40px 30px; }}
            }}
            @media (min-width: 768px) {{
                .import-card {{ max-width: 480px; padding: 48px 40px; border-radius: 24px; }}
                .import-card::before {{ border-radius: 24px; }}
                h2 {{ font-size: 22px; }}
                .toast-container {{ bottom: 30px; right: 30px; top: auto; }}
            }}
            @media (min-width: 1200px) {{
                .import-card {{ max-width: 520px; padding: 52px 48px; }}
            }}
        </style>
    </head>
    <body>
        
        <div class="toast-container" id="toastContainer"></div>

        <div class="main-content">
            <div class="import-card">
                <h2>Database Rescan Engine</h2>
                <p>Automatically verify all stored cookies to clean out dead accounts.</p>
                
                <div id="statusBadge" class="status-badge status-idle">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    Checking Status...
                </div>
                
                <button class="btn-outline" id="btnNow" onclick="triggerRescan()">Force Rescan Now</button>
                
                <div style="width: 100%; height: 1px; background: var(--border); margin: 10px 0 25px 0;"></div>
                
                <div style="width: 100%;">
                    <div class="toggle-container">
                        <div>
                            <div class="toggle-label">Use Custom Proxies</div>
                            <div class="toggle-sub">Prevents IP blocks during deep scans</div>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="proxyToggle" onchange="updateProxySetting()">
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div id="proxyManager" style="display:none; width: 100%; margin-bottom: 20px;">
                        
                        <div id="proxyUploadState">
                            <div class="file-upload-wrapper" onclick="document.getElementById('proxyFileInput').click()">
                                <input type="file" id="proxyFileInput" accept=".txt" onchange="handleProxyUpload(this)">
                                <div class="file-upload-content">
                                    <svg viewBox="0 0 24 24" width="20" height="20" stroke="var(--text-secondary)" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                                    <span class="file-upload-text">Upload custom proxies (.txt)</span>
                                </div>
                            </div>
                        </div>
                        
                        <div id="proxyActiveState" class="proxy-active-state" style="display:none;">
                            <div>
                                <strong style="color: #34c759; font-size: 13px; display:block; margin-bottom:2px;">Proxies Installed</strong>
                                <div style="font-size:11px; color:var(--text-secondary)">Safely stored on server</div>
                            </div>
                            <button onclick="deleteProxies()" style="background: rgba(255, 59, 48, 0.1); color: #ff3b30; border: 1px solid rgba(255, 59, 48, 0.2); padding: 8px 14px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 11px; transition: 0.2s;">Remove</button>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Automated Schedule (Hours in IST)</label>
                        <input type="text" id="scheduleInput" value="" placeholder="e.g. 0,8,16">
                        <p style="text-align: left; font-size: 11px; margin-top: 8px; margin-bottom: 0;">Example: <b>0,8,16</b> means 12 AM, 8 AM, 4 PM.</p>
                    </div>
                    <button class="btn-white" id="btnSchedule" onclick="updateSchedule()">Save Configuration</button>
                </div>
            </div>
        </div>

        <div class="site-footer" id="siteFooter"></div>

        <script>
            document.getElementById('siteFooter').textContent = '\u00A9 ' + new Date().getFullYear() + ' OORverse. All rights reserved.';

            function showToast(title, message, type = 'success') {{
                const container = document.getElementById('toastContainer');
                const card = document.createElement('div');
                card.className = 'toast-card';
                
                let color = type === 'success' ? '#34c759' : (type === 'error' ? '#ff3b30' : '#0088ff');
                card.style.borderLeft = `4px solid ${{color}}`;
                
                let iconHtml = type === 'success' 
                    ? `<svg viewBox="0 0 24 24" fill="none" stroke="${{color}}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="toast-icon"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`
                    : `<svg viewBox="0 0 24 24" fill="none" stroke="${{color}}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="toast-icon"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

                card.innerHTML = `
                    ${{iconHtml}}
                    <div class="toast-content">
                        <div class="toast-title" style="color: ${{color}}">${{title}}</div>
                        <div class="toast-message">${{message}}</div>
                    </div>
                `;
                
                container.appendChild(card);
                void card.offsetWidth; // trigger reflow
                card.classList.add('show');
                
                setTimeout(() => {{
                    card.classList.remove('show');
                    setTimeout(() => card.remove(), 400);
                }}, 4000);
            }}

            async function checkStatus() {{
                try {{
                    const res = await fetch('/api/rescan/status');
                    const data = await res.json();
                    
                    const badge = document.getElementById('statusBadge');
                    if (data.is_running) {{
                        badge.className = 'status-badge status-running';
                        badge.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="spin"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.3"/></svg> Rescan is currently running...`;
                    }} else {{
                        badge.className = 'status-badge status-idle';
                        badge.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> System is Idle`;
                    }}
                    
                    // UI Updates for inputs (only if user isn't actively typing)
                    if (document.activeElement.id !== 'scheduleInput') {{
                        document.getElementById('scheduleInput').value = data.schedule;
                        document.getElementById('proxyToggle').checked = data.use_proxies;
                    }}

                    // Proxy Manager Visibility Logic
                    const proxyManager = document.getElementById('proxyManager');
                    const proxyUpload = document.getElementById('proxyUploadState');
                    const proxyActive = document.getElementById('proxyActiveState');
                    
                    if (data.use_proxies) {{
                        proxyManager.style.display = 'block';
                        if (data.has_proxies) {{
                            proxyUpload.style.display = 'none';
                            proxyActive.style.display = 'flex';
                        }} else {{
                            proxyUpload.style.display = 'block';
                            proxyActive.style.display = 'none';
                        }}
                    }} else {{
                        proxyManager.style.display = 'none';
                    }}

                }} catch(e) {{}}
            }}

            async function triggerRescan() {{
                const btn = document.getElementById('btnNow');
                btn.disabled = true;
                try {{
                    const res = await fetch('/api/rescan/now', {{ method: 'POST' }});
                    const data = await res.json();
                    if(data.success) {{
                        showToast('Started', data.message, 'success');
                    }} else {{
                        showToast('Hold On', data.message, 'info');
                    }}
                    checkStatus();
                }} catch(e) {{ showToast('Error', 'Network Error', 'error'); }}
                setTimeout(() => btn.disabled = false, 1000);
            }}

            async function updateProxySetting() {{
                const isChecked = document.getElementById('proxyToggle').checked;
                const formData = new FormData();
                formData.append("use_proxies", isChecked);
                
                try {{
                    await fetch('/api/rescan/config', {{ method: 'POST', body: formData }});
                    checkStatus();
                }} catch(e) {{ showToast('Error', 'Network Error', 'error'); }}
            }}

            async function handleProxyUpload(input) {{
                if (!input.files || input.files.length === 0) return;
                const formData = new FormData();
                formData.append("proxy_file", input.files[0]);
                
                try {{
                    const res = await fetch('/api/rescan/proxy', {{ method: 'POST', body: formData }});
                    const data = await res.json();
                    if(data.success) showToast('Success', data.message, 'success');
                    else showToast('Error', data.message, 'error');
                    checkStatus();
                }} catch(e) {{ showToast('Error', 'Network Error', 'error'); }}
                input.value = '';
            }}

            async function deleteProxies() {{
                try {{
                    const res = await fetch('/api/rescan/proxy/delete', {{ method: 'POST' }});
                    const data = await res.json();
                    showToast('Deleted', data.message, 'info');
                    checkStatus();
                }} catch(e) {{ showToast('Error', 'Network Error', 'error'); }}
            }}

            async function updateSchedule() {{
                const btn = document.getElementById('btnSchedule');
                const val = document.getElementById('scheduleInput').value;
                btn.disabled = true;
                
                const formData = new FormData();
                formData.append("hours", val);

                try {{
                    const res = await fetch('/api/rescan/config', {{ method: 'POST', body: formData }});
                    const data = await res.json();
                    if(data.success) showToast('Saved', data.message, 'success');
                    else showToast('Error', data.message, 'error');
                }} catch(e) {{ showToast('Error', 'Network Error', 'error'); }}
                btn.disabled = false;
            }}

            checkStatus();
            setInterval(checkStatus, 4000);
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
        
        # Pull final network status and generate the log!
        local_ip, proxy_status = core.get_public_ip(request_proxies)
        write_scan_log("Manual File Upload", num_cookies, stats, proxy_status)
        
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
