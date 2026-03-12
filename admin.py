from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, RedirectResponse
import secrets
import os
import database

admin_router = APIRouter()
security = HTTPBasic()

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "oor123")

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != ADMIN_USER or credentials.password != ADMIN_PASS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

@admin_router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, user: str = Depends(verify_admin)):
    keys = database.get_all_keys()
    
    key_cards_html = ""
    alerts_html = ""
    
    for k in keys:
        role = k.get('role', 'N/A').upper()
        domain = k.get('domain', 'ALL DOMAINS')
        key_str = k['key']
        limit = int(k.get('quota_limit', 0))
        period = k.get('quota_period', 'lifetime').capitalize()
        usage = k.get('current_usage', 0)
        
        role_color = "#34c759" if role == "OWNER" else "#0088ff"
        
        # Math for progress bar
        percentage = min((usage / limit * 100), 100) if limit > 0 else 0
        bar_color = "#34c759" # Green
        if percentage >= 90: bar_color = "#ff9f0a" # Orange
        if percentage >= 100: bar_color = "#ff3b30" # Red
        
        # Generate Alerts
        if percentage >= 90 and role != "OWNER":
            alerts_html += f"<div class='alert-box'>⚠️ Reseller <b>{domain}</b> is at {int(percentage)}% of their {period} quota.</div>"
        
        limit_display = "Unlimited" if limit == 0 else f"{limit} ({period})"
        
        key_cards_html += f"""
        <div class="key-card">
            <div class="key-info">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="key-role" style="color: {role_color};">{role}</span>
                    <span class="key-domain">{domain}</span>
                </div>
                <span class="key-string">{key_str}</span>
                
                <div class="quota-section">
                    <div style="display:flex; justify-content:space-between; font-size:11px; color:#8e8e99; margin-bottom:4px;">
                        <span>Usage: {usage} / {limit_display}</span>
                        <span>{int(percentage)}%</span>
                    </div>
                    <div class="progress-bg">
                        <div class="progress-fill" style="width: {percentage}%; background: {bar_color};"></div>
                    </div>
                </div>
            </div>
            
            <form action="/admin/delete" method="POST" style="margin:0; width:100%;">
                <input type="hidden" name="api_key" value="{key_str}">
                <button type="submit" class="btn-revoke">Revoke Access</button>
            </form>
        </div>
        """

    if not key_cards_html:
        key_cards_html = "<p style='text-align:center; color:#8e8e99;'>No API keys generated yet.</p>"

    css = """
    <style>
        @import url('https://fonts.cdnfonts.com/css/nexa-bold');
        :root { --bg-color: #000000; --card-bg: #06060c; --text-primary: #ffffff; --text-secondary: #8e8e99; --border: rgba(255, 255, 255, 0.1); --input-bg: rgba(255, 255, 255, 0.05); }
        * { -webkit-tap-highlight-color: transparent; outline: none; box-sizing: border-box; }
        body { margin: 0; padding: 40px 20px; font-family: 'Nexa', sans-serif; font-weight: 300; background: var(--bg-color); color: var(--text-primary); display: flex; flex-direction: column; align-items: center; min-height: 100vh; }
        
        .import-card {
            background: var(--card-bg); border-radius: 20px; padding: 40px 30px; width: 100%; max-width: 480px; position: relative; margin-bottom: 30px;
            box-shadow: 0 0 0 0.5px rgba(255,255,255,0.05), 0 20px 40px rgba(0,0,0,0.5);
        }
        .import-card::before {
            content: ''; position: absolute; inset: 0; border-radius: 20px; padding: 1px;
            background: linear-gradient(170deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 30%, transparent 55%, rgba(255,255,255,0.04) 80%, rgba(255,255,255,0.09) 100%);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0); -webkit-mask-composite: xor; mask-composite: exclude; pointer-events: none;
        }
        h2 { margin: 0 0 10px 0; font-size: 20px; font-weight: 700; text-align: center; letter-spacing: 0.5px;}
        p { font-size: 13px; color: var(--text-secondary); line-height: 1.5; margin: 0 0 30px 0; text-align: center;}
        
        .form-row { display: flex; gap: 15px; margin-bottom: 16px; }
        .form-group { flex: 1; position: relative; }
        label { display: block; margin-bottom: 8px; font-size: 12px; color: var(--text-secondary); font-weight: 700; padding-left: 4px;}
        select, input[type="text"], input[type="number"] { width: 100%; height: 50px; padding: 0 16px; border-radius: 12px; background: var(--input-bg); border: 1px solid var(--border); color: white; font-size: 14px; font-weight: 700; font-family: 'Nexa', sans-serif; transition: 0.2s; appearance: none; -webkit-appearance: none; }
        select:focus, input:focus { border-color: rgb(0, 136, 255); background: rgba(255,255,255,0.08); }
        .select-wrapper::after { content: ''; position: absolute; right: 16px; bottom: 19px; width: 12px; height: 12px; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E"); background-size: contain; background-repeat: no-repeat; pointer-events: none; opacity: 0.5; }
        option { background: #1c1c1e; color: white; font-weight: 300;}
        
        .btn-white { width: 100%; height: 54px; border-radius: 14px; margin-top: 10px; background: #ffffff; color: #000000; border: none; font-size: 15px; font-weight: 700; font-family: 'Nexa', sans-serif; cursor: pointer; transition: transform 0.1s ease, opacity 0.2s; box-shadow: 0 4px 14px rgba(255,255,255,0.1); }
        .btn-white:active { transform: scale(0.96); }

        .key-card { background: var(--input-bg); border: 1px solid var(--border); border-radius: 14px; padding: 16px; margin-bottom: 12px; display: flex; flex-direction: column; gap: 16px; transition: border-color 0.2s; }
        .key-card:hover { border-color: rgba(255,255,255,0.3); }
        .key-info { display: flex; flex-direction: column; gap: 8px; width: 100%; }
        .key-role { font-size: 11px; font-weight: 700; letter-spacing: 1px; }
        .key-string { font-family: ui-monospace, monospace; font-size: 13px; color: var(--text-primary); background: rgba(0,0,0,0.5); padding: 8px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05);}
        .key-domain { font-size: 11px; color: var(--text-secondary); background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 6px;}
        
        .quota-section { margin-top: 8px; }
        .progress-bg { width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 6px; overflow: hidden; }
        .progress-fill { height: 100%; border-radius: 6px; transition: width 0.5s cubic-bezier(0.25, 1, 0.5, 1); }

        .btn-revoke { width: 100%; background: rgba(255, 59, 48, 0.1); color: #ff3b30; border: 1px solid rgba(255, 59, 48, 0.2); padding: 12px; border-radius: 10px; font-weight: 700; font-family: 'Nexa', sans-serif; cursor: pointer; font-size: 13px; transition: 0.2s; }
        .btn-revoke:hover { background: #ff3b30; color: #fff; }
        
        .alert-box { background: rgba(255, 159, 10, 0.1); border: 1px solid rgba(255, 159, 10, 0.3); color: #ff9f0a; padding: 12px 16px; border-radius: 10px; font-size: 12px; margin-bottom: 20px; font-weight: 700; }
    </style>
    """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>OOR Security Vault</title>
        {css}
    </head>
    <body>
        <div class="import-card">
            <h2>Security Vault</h2>
            <p>Generate secure API keys with strict quota limits.</p>
            
            {alerts_html}
            
            <form action="/admin/create" method="POST">
                <div class="form-group select-wrapper">
                    <label>Assign Role</label>
                    <select name="role">
                        <option value="reseller">Reseller (Locked to Domain)</option>
                        <option value="owner">Owner (Unrestricted Access)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Allowed Domain</label>
                    <input type="text" name="domain" placeholder="e.g. https://their-site.com">
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label>Quota Limit</label>
                        <input type="number" name="quota_limit" placeholder="e.g. 100" required>
                    </div>
                    <div class="form-group select-wrapper">
                        <label>Reset Period</label>
                        <select name="quota_period">
                            <option value="daily">Daily</option>
                            <option value="monthly">Monthly</option>
                            <option value="yearly">Yearly</option>
                            <option value="lifetime">Lifetime</option>
                        </select>
                    </div>
                </div>
                
                <button type="submit" class="btn-white">+ Generate API Key</button>
            </form>
        </div>

        <div class="import-card">
            <h2 style="font-size: 16px; text-align: left; margin-bottom: 20px;">Active API Keys & Usage</h2>
            {key_cards_html}
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@admin_router.post("/admin/create")
def create_key(role: str = Form(...), domain: str = Form(""), quota_limit: int = Form(...), quota_period: str = Form(...), user: str = Depends(verify_admin)):
    new_key = "oor_" + secrets.token_hex(16)
    if role == "owner": domain = "ALL"
    database.create_api_key(new_key, role, domain, quota_limit, quota_period)
    return RedirectResponse(url="/admin", status_code=303)

@admin_router.post("/admin/delete")
def delete_key(api_key: str = Form(...), user: str = Depends(verify_admin)):
    database.delete_api_key(api_key)
    return RedirectResponse(url="/admin", status_code=303)
