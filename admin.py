from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, RedirectResponse
import secrets
import os
import database

admin_router = APIRouter()
security = HTTPBasic()

# Read from Render Environment Variables (Fallback to defaults for local testing)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "oor123")

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != ADMIN_USER or credentials.password != ADMIN_PASS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@admin_router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, user: str = Depends(verify_admin)):
    keys = database.get_all_keys()
    
    # Generate the table rows dynamically
    rows = ""
    for k in keys:
        rows += f"""
        <tr>
            <td style="padding:10px; border-bottom:1px solid #333; font-family:monospace; color:#34c759;">{k['key']}</td>
            <td style="padding:10px; border-bottom:1px solid #333; text-transform:uppercase;">{k.get('role', 'N/A')}</td>
            <td style="padding:10px; border-bottom:1px solid #333; color:#8e8e99;">{k.get('domain', 'ALL')}</td>
            <td style="padding:10px; border-bottom:1px solid #333;">
                <form action="/admin/delete" method="POST" style="margin:0;">
                    <input type="hidden" name="api_key" value="{k['key']}">
                    <button type="submit" style="background:#ff3b30; color:white; border:none; padding:5px 10px; border-radius:5px; cursor:pointer;">Revoke</button>
                </form>
            </td>
        </tr>"""

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><title>OOR API Vault</title>
    <style>
        body {{ background:#000; color:#fff; font-family:-apple-system, sans-serif; padding:40px; }}
        .card {{ background:#06060c; padding:30px; border-radius:15px; border:1px solid rgba(255,255,255,0.1); max-width:800px; margin:0 auto; }}
        input, select {{ width:100%; padding:10px; margin-bottom:15px; background:rgba(255,255,255,0.05); border:1px solid #333; color:#fff; border-radius:8px; }}
        button {{ background:#0088ff; color:#fff; border:none; padding:10px 20px; border-radius:8px; cursor:pointer; font-weight:bold; }}
        table {{ width:100%; border-collapse:collapse; margin-top:20px; text-align:left; }}
    </style>
    </head>
    <body>
        <div class="card">
            <h2>OOR Security Vault</h2>
            <form action="/admin/create" method="POST">
                <label>Role</label>
                <select name="role">
                    <option value="reseller">Reseller (Restricted to Domain)</option>
                    <option value="owner">Owner (Unrestricted)</option>
                </select>
                <label>Allowed Domain (For Resellers - e.g., https://their-site.vercel.app)</label>
                <input type="text" name="domain" placeholder="Leave blank for Owner">
                <button type="submit">+ Generate New Key</button>
            </form>
            
            <h3 style="margin-top:40px;">Active API Keys</h3>
            <table>
                <tr><th>API Key</th><th>Role</th><th>Allowed Origin</th><th>Action</th></tr>
                {rows}
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@admin_router.post("/admin/create")
def create_key(role: str = Form(...), domain: str = Form(""), user: str = Depends(verify_admin)):
    new_key = "oor_" + secrets.token_hex(16)
    if role == "owner": domain = "ALL"
    database.create_api_key(new_key, role, domain)
    return RedirectResponse(url="/admin", status_code=303)

@admin_router.post("/admin/delete")
def delete_key(api_key: str = Form(...), user: str = Depends(verify_admin)):
    database.delete_api_key(api_key)
    return RedirectResponse(url="/admin", status_code=303)
