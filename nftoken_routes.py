import os
import random
from typing import Optional
from fastapi import APIRouter, Depends, Form, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader

import database
import nftoken_generator
import core
from admin import verify_admin 

nftoken_router = APIRouter()

# --- Security Dependency (Local to avoid circular import) ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_security(api_key: str = Depends(api_key_header)):
    if not api_key: raise HTTPException(status_code=401, detail="Missing X-API-Key")
    key_data = database.get_api_key(api_key)
    if not key_data or key_data.get("active") == "false":
        raise HTTPException(status_code=403, detail="Invalid or Inactive Key")
    key_data['api_key'] = api_key
    
    # Check Quota
    quota_limit = int(key_data.get("quota_limit", 0))
    quota_period = key_data.get("quota_period", "lifetime")
    if quota_limit > 0:
        if database.get_usage(api_key, quota_period) >= quota_limit:
            raise HTTPException(status_code=429, detail="Quota Exceeded.")
    return key_data

# --- API ENDPOINTS ---

@nftoken_router.post("/api/nftoken/generate")
async def api_generate_nftoken(
    plan: Optional[str] = Form(""),
    quality: Optional[str] = Form(""),
    language: Optional[str] = Form(""),
    use_proxy: bool = Form(True),
    proxy_file: UploadFile = File(None),
    key_data: dict = Depends(verify_security) 
):
    available = database.get_filtered_cookies(
        plan if plan and plan.lower() != "any" else None, 
        quality if quality and quality.lower() != "any" else None, 
        language if language and language.lower() != "any" else None
    )
    
    # Filter out HOLD, FREE, and accounts with exactly 0 unlocked_profiles!
    active = [
        c for c in available 
        if "HOLD" not in str(c.get("status", "")).upper() 
        and "FREE" not in str(c.get("status", "")).upper()
        and c.get("unlocked_profiles") != 0
    ]
    
    if not active: 
        return {"success": False, "message": "No matching active accounts found in database."}

    
    target = random.choice(active)

    # Read custom proxies into memory ONLY (Never overwrites VPS file)
    custom_proxies = None
    custom_proxy_name = None
    if proxy_file and proxy_file.filename:
        proxy_bytes = await proxy_file.read()
        custom_proxies = core.parse_proxies_from_bytes(proxy_bytes)
        custom_proxy_name = proxy_file.filename
    
    success, token, msg, debug_info = await nftoken_generator.execute_token_generation(
        target["netflix_id"], 
        use_proxy=use_proxy,
        custom_proxies=custom_proxies,
        custom_proxy_name=custom_proxy_name
    )
    
    # --- SERVER CONSOLE LOGGING (PM2) ---
    print(f"\n[NFTOKEN ASYNC GEN] Target: {target['netflix_id'][:15]}...")
    print(f"  -> File Priority : {debug_info.get('file_used')}")
    print(f"  -> Loaded Pool   : {debug_info.get('pool_size')} Proxies")
    print(f"  -> Selected IP   : {debug_info.get('ip_used_for_this_req')}")
    print(f"  -> Success       : {success}")

    if success:
        database.increment_quota(key_data['api_key'], key_data.get('quota_period', 'lifetime'))
        return {
            "success": True, 
            "account_used": {
                "plan": target.get("plan"), 
                "quality": target.get("quality")
            },
            "network_debug": debug_info,
            "links": {
                "pc": f"https://netflix.com/?nftoken={token}", 
                "phone": f"https://netflix.com/unsupported?nftoken={token}", 
                "tv": f"https://netflix.com/tv2?nftoken={token}"
            }
        }
    return {"success": False, "message": msg, "network_debug": debug_info}

# --- WEB UI ENDPOINT ---

@nftoken_router.get("/nftoken", response_class=HTMLResponse)
def nftoken_dashboard(request: Request, user: str = Depends(verify_admin)):
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>OORvault | NFToken Engine</title>
        <style>@import url('https://fonts.cdnfonts.com/css/nexa-bold');</style>
        <style>
            :root {{
                --bg-color: #000000;
                --card-bg: #06060c;
                --text-primary: #ffffff;
                --text-secondary: #8e8e99;
                --accent: rgb(0, 136, 255);
                --border: rgba(255, 255, 255, 0.1);
                --input-bg: rgba(255, 255, 255, 0.05);
            }}

            * {{
                -webkit-tap-highlight-color: transparent;
                outline: none;
                box-sizing: border-box;
            }}

            body {{
                margin: 0; 
                padding: 40px 20px; 
                font-family: 'Nexa', sans-serif;
                font-weight: 300;
                background: var(--bg-color);
                color: var(--text-primary);
                display: flex; 
                flex-direction: column; 
                align-items: center; 
                justify-content: center;
                min-height: 100vh;
                -webkit-font-smoothing: antialiased;
            }}
            
            .main-content {{ width: 100%; max-width: 500px; }}

            .import-card {{
                background: var(--card-bg);
                border-radius: 20px;
                padding: 40px 30px;
                width: 100%; 
                border: none;
                display: none; 
                position: relative;
                box-shadow: 
                    0 0 0 0.5px rgba(255,255,255,0.05),
                    0 0 40px rgba(255,255,255,0.02),
                    0 20px 40px rgba(0,0,0,0.5);
            }}
            .import-card.active-card {{ display: block; animation: fadeIn 0.4s cubic-bezier(0.25, 1, 0.5, 1) forwards; }}
            
            .import-card::before {{
                content: ''; position: absolute; inset: 0; border-radius: 20px; padding: 1px;
                background: linear-gradient(170deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 30%, transparent 55%, rgba(255,255,255,0.04) 80%, rgba(255,255,255,0.09) 100%);
                -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
                -webkit-mask-composite: xor; mask-composite: exclude; pointer-events: none;
            }}

            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}

            h2 {{ margin: 0 0 10px 0; font-size: 22px; font-weight: 700; text-align: center; letter-spacing: 0.5px;}}
            p {{ font-size: 13px; color: var(--text-secondary); line-height: 1.5; margin: 0 0 30px 0; text-align: center;}}

            /* --- Exactly Like index.html Inputs --- */
            .form-group {{ margin-bottom: 20px; position: relative; width: 100%; }}
            label {{ display: block; margin-bottom: 8px; font-size: 12px; color: var(--text-secondary); font-weight: 700; padding-left: 4px;}}





                .input-icon-wrapper {{ 
                position: relative; 
                display: flex; 
                align-items: center; 
                width: 100%;
                background: var(--input-bg); 
                border: 1px solid var(--border); 
                border-radius: 12px;
                overflow: hidden; 
            }}

            .input-icon-wrapper:focus-within {{
                border-color: var(--accent);
                background: rgba(255,255,255,0.08);
            }}

            .input-icon-wrapper input {{ 
                flex: 1;
                height: 50px;
                padding: 0 16px; 
                background: transparent; 
                border: none;
                color: white; 
                font-size: 14px; 
                font-weight: 700; 
                font-family: 'Nexa', sans-serif;
            }}

            .eye-btn {{ 
                display: flex; 
                align-items: center; 
                justify-content: center;
                padding: 0 16px; 
                height: 50px;
                color: var(--text-secondary); 
                cursor: pointer; 
                transition: color 0.2s;
                border-left: 1px solid var(--border); 
                background: rgba(255,255,255,0.03);
            }}
            .eye-btn:hover {{ color: #fff; background: rgba(255,255,255,0.06); }}
            .eye-btn svg {{ width: 18px; height: 18px; display: block; }}
   

            
            select, input[type="password"], input[type="text"] {{
                width: 100%; padding: 16px; border-radius: 12px;
                background: var(--input-bg); border: 1px solid var(--border);
                color: white; outline: none; font-size: 14px; font-weight: 700;
                font-family: 'Nexa', sans-serif; transition: 0.2s;
                appearance: none; -webkit-appearance: none;
            }}

            
            select:focus, input[type="password"]:focus, input[type="text"]:focus {{
                border-color: var(--accent);
                background: rgba(255,255,255,0.08);
            }}

            

            .input-icon-wrapper input[type="password"],
.input-icon-wrapper input[type="text"] {{
    border: none;
    border-radius: 0;
    background: transparent;
    padding: 0 16px;
    width: auto;
}}
.input-icon-wrapper input[type="password"]:focus,
.input-icon-wrapper input[type="text"]:focus {{
    border: none;
    background: transparent;
}}
            
            .select-wrapper::after {{
                content: ''; position: absolute; right: 16px; bottom: 20px;
                width: 12px; height: 12px;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
                background-size: contain; background-repeat: no-repeat;
                pointer-events: none; opacity: 0.5;
            }}
            option {{ background: #1c1c1e; color: white; font-weight: 300; padding: 10px; }}

            .filter-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 25px; }}

            /* --- Sleek Custom Proxy Toggle --- */
            .proxy-toggle-container {{ width: 100%; display: flex; align-items: center; justify-content: space-between; background: var(--input-bg); padding: 16px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 15px; cursor: pointer; }}
            .proxy-toggle-container:active {{ transform: scale(0.98); }}
            .toggle-label {{ font-size: 13px; font-weight: 700; color: #fff; }}
            .toggle-sub {{ font-size: 11px; font-weight: 400; color: var(--text-secondary); margin-top: 4px; }}
            
            .switch {{ position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0; pointer-events: none; }}
            .switch input {{ opacity: 0; width: 0; height: 0; }}
            .slider {{ position: absolute; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(255,255,255,0.1); transition: .3s; border-radius: 24px; }}
            .slider:before {{ position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }}
            input:checked + .slider {{ background-color: #34c759; }}
            input:checked + .slider:before {{ transform: translateX(20px); }}

            .file-upload-wrapper {{ position: relative; border: 1px dashed rgba(255,255,255,0.2); border-radius: 12px; height: 70px; background: var(--input-bg); transition: all 0.3s ease; cursor: pointer; display: flex; justify-content: center; align-items: center; margin-bottom: 25px; display: none; }}
            .file-upload-wrapper:hover {{ border-color: rgba(255,255,255,0.5); background: rgba(255,255,255,0.08); }}
            .file-upload-wrapper.error {{ border-color: #ff3b30 !important; background: rgba(255, 59, 48, 0.1) !important; animation: shake 0.4s cubic-bezier(.36,.07,.19,.97) both; }}
            
            @keyframes shake {{ 10%, 90% {{ transform: translate3d(-2px, 0, 0); }} 20%, 80% {{ transform: translate3d(4px, 0, 0); }} 30%, 50%, 70% {{ transform: translate3d(-8px, 0, 0); }} 40%, 60% {{ transform: translate3d(8px, 0, 0); }} }}

            .file-upload-wrapper input[type="file"] {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; z-index: 2; }}
            .file-upload-content {{ display: flex; align-items: center; gap: 12px; pointer-events: none; }}
            .file-name-display {{ font-size: 13px; color: var(--text-secondary); font-weight: 700; transition: color 0.3s; }}

            /* --- Exact core.py Main Button --- */
            .btn-white {{
                width: 100%; padding: 16px; border-radius: 14px; margin-top: 10px;
                background: #ffffff; color: #000000; border: none;
                font-size: 15px; font-weight: 700; font-family: 'Nexa', sans-serif;
                cursor: pointer; transition: transform 0.1s ease, opacity 0.2s;
                box-shadow: 0 4px 14px rgba(255,255,255,0.1);
            }}
            .btn-white:active {{ transform: scale(0.96); }}
            .btn-white:disabled {{ background: #333; color: #666; cursor: not-allowed; box-shadow: none; transform: none; }}

            /* --- Modern Deployment Link Cards --- */
            .success-pill {{ display: flex; justify-content: center; align-items: center; background: rgba(52, 199, 89, 0.1); color: #34c759; padding: 10px 16px; border-radius: 6px; font-size: 12px; font-weight: 700; border: 1px solid rgba(52, 199, 89, 0.2); margin-bottom: 25px; letter-spacing: 0.5px;}}
            
            .deploy-card {{
                background: var(--input-bg);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 16px 20px;
                margin-bottom: 15px;
                display: flex;
                flex-direction: column;
                cursor: pointer;
                transition: transform 0.15s ease, border-color 0.2s;
                position: relative;
            }}
            .deploy-card:hover {{ border-color: rgba(255,255,255,0.4); }}
            .deploy-card:active {{ transform: scale(0.98); }}

            .deploy-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; pointer-events: none; }}
            .deploy-title {{ font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }}
            .deploy-title svg {{ width: 16px; height: 16px; color: var(--text-secondary); }}
            
            .deploy-badge {{ font-size: 11px; font-weight: 700; color: var(--text-secondary); letter-spacing: 0.5px; text-transform: uppercase; transition: color 0.2s ease; }}
            .deploy-badge.copied {{ color: #34c759; }}

            .deploy-input {{ background: transparent; border: none; color: var(--text-secondary); font-family: monospace; font-size: 12px; width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; pointer-events: none; padding: 0; margin: 0; outline: none; }}

            .error-msg {{ color: #ff453a; font-size: 13px; font-weight: 700; text-align: center; margin-top: 20px; display: none; }}

            @media (min-width: 768px) {{
                .import-card {{ max-width: 480px; padding: 48px 40px; border-radius: 24px; }}
                h2 {{ font-size: 22px; }}
            }}
            @media (max-width: 600px) {{
                .filter-grid {{ grid-template-columns: 1fr; gap: 0; margin-bottom: 10px; }}
                .form-group {{ margin-bottom: 16px; }}
            }}
        </style>
    </head>
    <body>

        <div class="main-content">
            
            <div class="import-card active-card" id="view-generate">
                <div class="header-sec">
                    <h2>NFToken Engine</h2>
                    <p>Securely extract an active account and<br>deploy login links to all devices.</p>
                </div>



                                   <div class="form-group">
                    <label>Admin API Key</label>
                    <div class="input-icon-wrapper">
                        <input type="password" id="apiKey" placeholder="Enter your X-API-Key">
                        <div class="eye-btn" onclick="toggleKeyVisibility()">
                            <svg id="eyeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </div>
                    </div>
                </div>
                


                <div class="filter-grid">
                    <div class="form-group select-wrapper">
                        <label>Plan</label>
                        <select id="plan">
                            <option value="">Any Plan</option>
                            <option value="Premium">Premium</option>
                            <option value="Standard">Standard</option>
                            <option value="Basic">Basic</option>
                            <option value="Mobile">Mobile</option>
                        </select>
                    </div>
                    <div class="form-group select-wrapper">
                        <label>Quality</label>
                        <select id="quality">
                            <option value="">Any Quality</option>
                            <option value="UHD">UHD</option>
                            <option value="HD">HD</option>
                            <option value="SD">SD</option>
                        </select>
                    </div>
                    <div class="form-group select-wrapper">
                        <label>Language</label>
                        <select id="language">
                            <option value="">Any Language</option>
                            <option value="English">English</option>
                            <option value="Arabic">Arabic</option>
                            <option value="Chinese">Chinese</option>
                            <option value="Czech">Czech</option>
                            <option value="Danish">Danish</option>
                            <option value="Dutch">Dutch</option>
                            <option value="Filipino">Filipino</option>
                            <option value="Finnish">Finnish</option>
                            <option value="French">French</option>
                            <option value="German">German</option>
                            <option value="Greek">Greek</option>
                            <option value="Hebrew">Hebrew</option>
                            <option value="Hindi">Hindi</option>
                            <option value="Hungarian">Hungarian</option>
                            <option value="Indonesian">Indonesian</option>
                            <option value="Italian">Italian</option>
                            <option value="Japanese">Japanese</option>
                            <option value="Korean">Korean</option>
                            <option value="Malay">Malay</option>
                            <option value="Norwegian">Norwegian</option>
                            <option value="Polish">Polish</option>
                            <option value="Portuguese">Portuguese</option>
                            <option value="Romanian">Romanian</option>
                            <option value="Russian">Russian</option>
                            <option value="Spanish">Spanish</option>
                            <option value="Swedish">Swedish</option>
                            <option value="Thai">Thai</option>
                            <option value="Turkish">Turkish</option>
                            <option value="Ukrainian">Ukrainian</option>
                            <option value="Vietnamese">Vietnamese</option>
                        </select>
                    </div>
                </div>

                <div class="proxy-toggle-container" onclick="toggleProxyBox()">
                    <div>
                        <div class="toggle-label">Use Proxy Rotation</div>
                        <div class="toggle-sub">Protect server IP (Recommended)</div>
                    </div>
                    <label class="switch">
                        <input type="checkbox" id="useProxyToggle" checked>
                        <span class="slider"></span>
                    </label>
                </div>

                <div class="file-upload-wrapper" id="proxyUploadArea">
                    <input type="file" id="proxyFileInput" accept=".txt" onchange="handleProxyUpload(this)">
                    <div class="file-upload-content">
                        <svg viewBox="0 0 24 24" width="20" height="20" stroke="var(--text-secondary)" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" id="proxyIcon"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                        <span class="file-name-display" id="proxyText">Attach Custom Proxies (.TXT)</span>
                    </div>
                </div>

                <button class="btn-white" id="btnGen" onclick="generateToken()">Generate Links</button>
                <div id="errorMsg" class="error-msg"></div>
            </div>

            <div class="import-card" id="view-results">
                <div class="header-sec">
                    <h2>Deployment Links</h2>
                    <p>Tap any card below to instantly copy<br>your direct login link.</p>
                </div>

                <div id="accountPill" class="success-pill">Deployed: Premium - UHD</div>
                
                <div class="deploy-card" onclick="copyCard('linkPc', 'badgePc')">
                    <div class="deploy-header">
                        <div class="deploy-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                            Desktop / PC Login
                        </div>
                        <div class="deploy-badge" id="badgePc">COPY</div>
                    </div>
                    <input type="text" class="deploy-input" id="linkPc" readonly>
                </div>

                <div class="deploy-card" onclick="copyCard('linkPhone', 'badgePhone')">
                    <div class="deploy-header">
                        <div class="deploy-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                            Mobile Phone Login
                        </div>
                        <div class="deploy-badge" id="badgePhone">COPY</div>
                    </div>
                    <input type="text" class="deploy-input" id="linkPhone" readonly>
                </div>

                <div class="deploy-card" onclick="copyCard('linkTv', 'badgeTv')">
                    <div class="deploy-header">
                        <div class="deploy-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"></rect><polyline points="17 2 12 7 7 2"></polyline></svg>
                            Smart TV Login
                        </div>
                        <div class="deploy-badge" id="badgeTv">COPY</div>
                    </div>
                    <input type="text" class="deploy-input" id="linkTv" readonly>
                </div>

                <button class="btn-white" onclick="goBack()" style="margin-top: 25px;">Generate Another</button>
            </div>

        </div>

        <script>


           function toggleKeyVisibility() {{
                const input = document.getElementById('apiKey');
                const icon = document.getElementById('eyeIcon');
                
                if (input.type === 'password') {{
                    input.type = 'text';
                    // Slashed eye icon
                    icon.innerHTML = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>`;
                }} else {{
                    input.type = 'password';
                    // Open eye icon
                    icon.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>`;
                }}
            }}


                    
            // Persistence on load
            window.onload = function() {{
                const savedKey = localStorage.getItem('oor_nftoken_apikey');
                if (savedKey) document.getElementById('apiKey').value = savedKey;
            }};

            function showError(msg, isSuccess = false) {{
                const errBox = document.getElementById('errorMsg');
                if (!msg) {{ errBox.style.display = 'none'; return; }}
                
                errBox.innerText = msg;
                errBox.style.color = isSuccess ? '#34c759' : '#ff453a';
                errBox.style.display = 'block';
            }}

            function copyCard(inputId, badgeId) {{
                const inputEl = document.getElementById(inputId);
                const badgeEl = document.getElementById(badgeId);
                
                inputEl.style.pointerEvents = 'auto';
                inputEl.select();
                document.execCommand('copy');
                inputEl.style.pointerEvents = 'none';
                window.getSelection().removeAllRanges();
                
                // Sleek inline feedback WITH EMOJI! 🎉
                const originalText = badgeEl.innerText;
                badgeEl.innerText = 'COPIED! 🎉';
                badgeEl.classList.add('copied');
                
                setTimeout(() => {{
                    badgeEl.innerText = 'COPY';
                    badgeEl.classList.remove('copied');
                }}, 1500);
            }}

            function toggleProxyBox() {{
                const toggle = document.getElementById('useProxyToggle');
                const area = document.getElementById('proxyUploadArea');
                
                toggle.checked = !toggle.checked;
                if (toggle.checked) {{
                    area.style.display = 'flex';
                }} else {{
                    area.style.display = 'none';
                }}
            }}
            
            // Initialize upload area display
            document.getElementById('proxyUploadArea').style.display = document.getElementById('useProxyToggle').checked ? 'flex' : 'none';

            function handleProxyUpload(input) {{
                const display = document.getElementById('proxyText');
                const wrapper = input.closest('.file-upload-wrapper');

                if (!input.files || input.files.length === 0) return;
                
                const fileName = input.files[0].name;
                const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
                
                if (ext !== '.txt') {{
                    input.value = ''; 
                    display.innerText = "Invalid! Only .TXT allowed";
                    display.style.color = "#ff3b30";
                    wrapper.classList.remove('error'); 
                    void wrapper.offsetWidth; 
                    wrapper.classList.add('error');
                    setTimeout(() => wrapper.classList.remove('error'), 400);
                    return;
                }}

                // Stateless UI update! No fetch call to server yet.
                const iconEl = document.getElementById('proxyIcon');
                display.innerText = fileName + ' Attached!';
                display.style.color = '#34c759';
                iconEl.style.stroke = '#34c759';
                wrapper.classList.remove('error');
            }}

            function goBack() {{
                document.getElementById('view-results').classList.remove('active-card');
                document.getElementById('view-generate').classList.add('active-card');
                showError(''); 
                
                document.getElementById('badgePc').innerText = 'COPY';
                document.getElementById('badgePc').classList.remove('copied');
                document.getElementById('badgePhone').innerText = 'COPY';
                document.getElementById('badgePhone').classList.remove('copied');
                document.getElementById('badgeTv').innerText = 'COPY';
                document.getElementById('badgeTv').classList.remove('copied');
            }}

            async function generateToken() {{
                const btn = document.getElementById('btnGen');
                const apiKey = document.getElementById('apiKey').value.trim();
                const plan = document.getElementById('plan').value;
                const quality = document.getElementById('quality').value;
                const lang = document.getElementById('language').value;
                const useProxy = document.getElementById('useProxyToggle').checked;
                const proxyFile = document.getElementById('proxyFileInput').files[0];

                if(!apiKey) {{ showError('Please enter your Admin API Key.'); return; }}

                localStorage.setItem('oor_nftoken_apikey', apiKey);
                showError('');

                btn.disabled = true;
                btn.textContent = "Authenticating...";

                const formData = new FormData();
                if(plan) formData.append("plan", plan);
                if(quality) formData.append("quality", quality);
                if(lang) formData.append("language", lang);
                formData.append("use_proxy", useProxy);
                
                // Append file directly to generation payload!
                if(proxyFile && useProxy) {{
                    formData.append("proxy_file", proxyFile);
                }}

                try {{
                    const res = await fetch('/api/nftoken/generate', {{ 
                        method: 'POST', 
                        headers: {{ 'X-API-Key': apiKey }},
                        body: formData 
                    }});
                    
                    if(res.status === 401 || res.status === 403 || res.status === 429) {{
                        const err = await res.json();
                        showError(err.detail || 'Access Denied.');
                    }} else {{
                        const data = await res.json();
                        if(data.success) {{
                            document.getElementById('linkPc').value = data.links.pc;
                            document.getElementById('linkPhone').value = data.links.phone;
                            document.getElementById('linkTv').value = data.links.tv;
                            
                            const pText = data.account_used.plan || 'Any Plan';
                            const qText = data.account_used.quality || 'Any Quality';
                            document.getElementById('accountPill').innerText = `Deployed: ${{pText}} - ${{qText}}`;
                            
                            document.getElementById('view-generate').classList.remove('active-card');
                            document.getElementById('view-results').classList.add('active-card');
                        }} else {{
                            showError(data.message);
                        }}
                    }}
                }} catch(e) {{
                    showError('Network Error. Could not connect to server.');
                }}

                btn.disabled = false;
                btn.textContent = "Generate Links";
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
