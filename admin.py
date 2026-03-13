from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
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
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>OORvault</title>
<style>@import url('https://fonts.cdnfonts.com/css/nexa-bold');</style>
<style>
:root{--bg:#000;--card-bg:#06060c;--text:#fff;--text2:#8e8e99;--accent:rgb(0,136,255);--border:rgba(255,255,255,0.1);--input-bg:rgba(255,255,255,0.05);--green:#34c759;--red:#ff3b30;--orange:#ff9f0a}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;outline:none}
body{font-family:'Nexa',sans-serif;font-weight:300;background:var(--bg);color:var(--text);min-height:100vh;padding:40px 20px;display:flex;flex-direction:column;align-items:center;-webkit-font-smoothing:antialiased}
.layout{width:100%;max-width:340px}

.admin-header{position:relative;text-align:center;margin-bottom:28px}
.admin-header h1{font-size:22px;font-weight:700;letter-spacing:0.5px;margin-bottom:8px;line-height:1.2}
.admin-header p{font-size:13px;color:var(--text2);line-height:1.5}
.alert-bell{position:absolute;top:2px;right:0;width:36px;height:36px;border-radius:10px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.06);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:0.15s;color:var(--text2)}
.alert-bell:active{transform:scale(0.9)}
.alert-bell svg{width:16px;height:16px}
.alert-bell-badge{position:absolute;top:-3px;right:-3px;width:16px;height:16px;border-radius:50%;background:var(--orange);font-size:9px;font-weight:700;color:#000;display:none;align-items:center;justify-content:center;line-height:1;border:2px solid var(--bg);font-family:'Nexa',sans-serif}
.alert-bell-badge.show{display:flex}

.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px}
.stat-card{background:var(--card-bg);border-radius:14px;padding:18px 8px;text-align:center;position:relative;box-shadow:0 0 0 .5px rgba(255,255,255,0.05),0 8px 20px rgba(0,0,0,0.3)}
.stat-card::before{content:'';position:absolute;inset:0;border-radius:14px;padding:1px;background:linear-gradient(170deg,rgba(255,255,255,0.1) 0%,transparent 40%,transparent 60%,rgba(255,255,255,0.07) 100%);-webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.stat-value{font-size:24px;font-weight:700;line-height:1;margin-bottom:6px}
.stat-label{font-size:10px;color:var(--text2);font-weight:700;text-transform:uppercase;letter-spacing:.8px;line-height:1}
.stat-value.green{color:var(--green)}.stat-value.red{color:var(--red)}

.main-card{background:var(--card-bg);border-radius:20px;padding:24px 20px;position:relative;box-shadow:0 0 0 .5px rgba(255,255,255,0.05),0 0 40px rgba(255,255,255,0.02),0 20px 40px rgba(0,0,0,0.5)}
.main-card::before{content:'';position:absolute;inset:0;border-radius:20px;padding:1px;background:linear-gradient(170deg,rgba(255,255,255,0.12) 0%,rgba(255,255,255,0.03) 30%,transparent 55%,rgba(255,255,255,0.04) 80%,rgba(255,255,255,0.09) 100%);-webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}

.card-header{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.section-title{font-size:15px;font-weight:700;line-height:1}
.key-count{font-size:11px;font-weight:700;background:rgba(255,255,255,0.08);color:var(--text2);padding:4px 10px;border-radius:11px;line-height:1}

.action-row{display:flex;gap:8px;margin-bottom:14px;align-items:center}
.search-input{flex:1;height:42px;padding:0 14px;border-radius:12px;background:var(--input-bg);border:1px solid var(--border);color:#fff;font-size:13px;font-weight:700;font-family:'Nexa',sans-serif;transition:.2s}
.search-input:focus{border-color:var(--accent);background:rgba(255,255,255,0.08)}
.search-input::placeholder{color:var(--text2)}
.btn-add{width:42px;height:42px;border-radius:12px;background:#fff;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform .1s;flex-shrink:0}
.btn-add:active{transform:scale(.92)}
.btn-add svg{width:18px;height:18px}

.key-list{max-height:400px;overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain}
.key-list::-webkit-scrollbar{width:3px}
.key-list::-webkit-scrollbar-track{background:transparent}
.key-list::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.12);border-radius:3px}
.key-item{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:14px;margin-bottom:8px;animation:slideIn .3s ease}
.key-item:last-child{margin-bottom:0}
@keyframes slideIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.key-item.removing{animation:removeItem .3s ease forwards}
@keyframes removeItem{to{opacity:0;transform:translateX(-20px);height:0;margin:0;padding:0;border:0;overflow:hidden}}

.key-top-row{display:flex;align-items:center;gap:8px;margin-bottom:10px;min-height:18px}
.status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.status-dot.active{background:var(--green);box-shadow:0 0 8px rgba(52,199,89,0.4)}
.status-dot.inactive{background:var(--red);box-shadow:0 0 8px rgba(255,59,48,0.3)}
.role-badge-owner{font-size:9px;font-weight:700;letter-spacing:.8px;padding:0 7px;border-radius:6px;height:18px;display:inline-flex;align-items:center;justify-content:center;text-transform:uppercase;background:rgba(52,199,89,0.12);color:var(--green);border:1px solid rgba(52,199,89,0.2);flex-shrink:0;line-height:1;font-family:'Nexa',sans-serif}
.key-label{font-size:13px;font-weight:700;line-height:1;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

.key-mid-row{display:flex;align-items:center;gap:8px}
.key-value{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px;color:var(--text2);background:rgba(0,0,0,0.3);height:30px;padding:0 10px;border-radius:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;transition:.2s;border:1px solid transparent;display:flex;align-items:center}
.key-value:active{border-color:var(--accent)}
.key-actions{display:flex;gap:5px;flex-shrink:0}
.btn-icon{width:30px;height:30px;border-radius:8px;border:1px solid rgba(255,255,255,0.06);background:rgba(255,255,255,0.03);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
.btn-icon:active{transform:scale(.88)}
.btn-icon svg{width:13px;height:13px}

.quota-section{margin-top:14px}
.quota-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.quota-text{font-size:10px;font-weight:700;color:var(--text2);line-height:1}
.quota-percent{font-size:10px;font-weight:700;line-height:1}
.quota-bar-bg{width:100%;height:4px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden}
.quota-bar-fill{height:100%;border-radius:4px;transition:width .5s cubic-bezier(.25,1,.5,1)}

.empty-state{text-align:center;padding:36px 16px;display:none}
.empty-state svg{width:40px;height:40px;color:var(--text2);opacity:.25;margin-bottom:14px}
.empty-state .empty-title{font-size:14px;font-weight:700;color:var(--text2);margin-bottom:4px;line-height:1.3}
.empty-state .empty-sub{font-size:12px;color:var(--text2);opacity:.6;line-height:1.3}
.skeleton{height:100px;border-radius:14px;margin-bottom:8px;background:linear-gradient(90deg,rgba(255,255,255,0.03) 25%,rgba(255,255,255,0.06) 50%,rgba(255,255,255,0.03) 75%);background-size:200% 100%;animation:shimmer 1.5s infinite}
.skeleton:last-child{margin-bottom:0}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.75);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);display:none;align-items:center;justify-content:center;z-index:100;padding:20px}
.modal-overlay.show{display:flex}
.modal{background:var(--card-bg);border-radius:20px;padding:30px 24px;width:100%;max-width:320px;position:relative;animation:modalIn .3s ease;box-shadow:0 0 0 .5px rgba(255,255,255,0.05),0 20px 60px rgba(0,0,0,0.8);max-height:90vh;overflow-y:auto}
.modal::-webkit-scrollbar{width:0}
.modal::before{content:'';position:absolute;inset:0;border-radius:20px;padding:1px;background:linear-gradient(170deg,rgba(255,255,255,0.12) 0%,rgba(255,255,255,0.03) 30%,transparent 55%,rgba(255,255,255,0.04) 80%,rgba(255,255,255,0.09) 100%);-webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
@keyframes modalIn{from{opacity:0;transform:scale(.95) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal h3{font-size:18px;font-weight:700;text-align:center;margin-bottom:6px;line-height:1.2}
.modal .modal-desc{font-size:12px;color:var(--text2);text-align:center;margin-bottom:24px;line-height:1.5}
.modal-label{display:block;font-size:12px;color:var(--text2);font-weight:700;margin-bottom:8px;padding-left:4px;line-height:1}
.modal-input{width:100%;padding:14px 16px;border-radius:12px;background:var(--input-bg);border:1px solid var(--border);color:#fff;font-size:13px;font-weight:700;font-family:'Nexa',sans-serif;transition:.2s;margin-bottom:14px;appearance:none;-webkit-appearance:none}
.modal-input:focus{border-color:var(--accent);background:rgba(255,255,255,0.08)}
.modal-input::placeholder{color:var(--text2);opacity:.6}
.modal-select-box{position:relative;margin-bottom:14px}
.modal-select-box select{width:100%;padding:14px 16px;border-radius:12px;background:var(--input-bg);border:1px solid var(--border);color:#fff;font-size:13px;font-weight:700;font-family:'Nexa',sans-serif;transition:.2s;appearance:none;-webkit-appearance:none;margin:0}
.modal-select-box select:focus{border-color:var(--accent);background:rgba(255,255,255,0.08)}
.modal-select-box option{background:#1c1c1e;color:#fff;font-weight:300}
.modal-select-box::after{content:'';position:absolute;right:16px;top:50%;transform:translateY(-50%);width:12px;height:12px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");background-size:contain;background-repeat:no-repeat;pointer-events:none;opacity:.5}
.modal-row{display:flex;gap:10px}.modal-row>div{flex:1;min-width:0}

.gen-key-box{background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:10px;padding:14px;padding-right:48px;margin-bottom:20px;position:relative;min-height:60px;display:flex;flex-direction:column;justify-content:center}
.gen-key-label{font-size:10px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;line-height:1}
.gen-key-value{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px;color:var(--green);word-break:break-all;line-height:1.5;user-select:all}
.gen-key-copy{position:absolute;right:10px;top:50%;transform:translateY(-50%);width:28px;height:28px;border-radius:7px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:.15s}
.gen-key-copy:active{transform:translateY(-50%) scale(.88)}
.gen-key-copy svg{width:12px;height:12px}

.modal-btns{display:flex;gap:10px;margin-top:6px}
.btn-cancel{flex:1;height:48px;border-radius:12px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);color:#fff;font-size:14px;font-weight:700;font-family:'Nexa',sans-serif;cursor:pointer;transition:.1s;display:flex;align-items:center;justify-content:center}
.btn-cancel:active{transform:scale(.96)}
.btn-submit{flex:1;height:48px;border-radius:12px;background:#fff;border:none;color:#000;font-size:14px;font-weight:700;font-family:'Nexa',sans-serif;cursor:pointer;transition:.1s;display:flex;align-items:center;justify-content:center}
.btn-submit:active{transform:scale(.96)}
.btn-submit:disabled{background:#333;color:#666;cursor:not-allowed;transform:none}
.btn-danger{flex:1;height:48px;border-radius:12px;background:var(--red);border:none;color:#fff;font-size:14px;font-weight:700;font-family:'Nexa',sans-serif;cursor:pointer;transition:.1s;display:flex;align-items:center;justify-content:center}
.btn-danger:active{transform:scale(.96)}

.alert-list{max-height:300px;overflow-y:auto}
.alert-list::-webkit-scrollbar{width:3px}
.alert-list::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.12);border-radius:3px}
.alert-item{background:rgba(255,159,10,0.06);border:1px solid rgba(255,159,10,0.15);border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;align-items:flex-start;gap:10px}
.alert-item:last-child{margin-bottom:0}
.alert-icon{font-size:13px;flex-shrink:0;line-height:1.4}
.alert-item-text{font-size:12px;font-weight:700;color:var(--orange);line-height:1.4}
.no-alerts{text-align:center;padding:30px 10px}
.no-alerts-icon{font-size:28px;margin-bottom:10px;opacity:.4}
.no-alerts-text{font-size:13px;color:var(--text2);font-weight:700}

.toast{position:fixed;bottom:36px;left:50%;transform:translateX(-50%) translateY(60px) scale(.92);background:#1c1c1e;border-radius:100px;height:40px;padding:0 20px 0 16px;display:flex;align-items:center;gap:10px;z-index:200;opacity:0;transition:all .45s cubic-bezier(.25,1,.5,1);box-shadow:0 6px 24px rgba(0,0,0,0.5),0 0 0 .5px rgba(255,255,255,0.06);pointer-events:none}
.toast.show{transform:translateX(-50%) translateY(0) scale(1);opacity:1}
.toast-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.toast-text{font-size:13px;font-weight:700;color:rgba(255,255,255,0.85);font-family:'Nexa',sans-serif;white-space:nowrap;line-height:1}

.site-footer{margin-top:0;padding-top:30px;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',system-ui,sans-serif;font-size:13px;font-weight:400;color:var(--text2);text-align:center;opacity:.7;letter-spacing:.2px}

@media(min-width:420px){.layout{max-width:400px}.modal{max-width:360px}}
@media(min-width:768px){
body{padding:60px 40px;justify-content:center}
.layout{max-width:440px}
.admin-header h1{font-size:24px}
.main-card{padding:28px 24px;border-radius:24px}
.main-card::before{border-radius:24px}
.key-list{max-height:500px}
.stat-value{font-size:28px}
.modal{max-width:380px}
}
@media(min-width:1200px){
body{background:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(255,255,255,0.015) 0%,transparent 70%),var(--bg)}
.layout{max-width:560px}
.admin-header h1{font-size:28px;margin-bottom:10px}
.admin-header p{font-size:14px}
.alert-bell{width:40px;height:40px;border-radius:12px}
.alert-bell svg{width:18px;height:18px}
.stats-row{gap:14px;margin-bottom:20px}
.stat-card{padding:24px 12px;border-radius:16px}
.stat-card::before{border-radius:16px}
.stat-value{font-size:32px;margin-bottom:8px}
.stat-label{font-size:11px}
.main-card{padding:36px 32px;border-radius:28px}
.main-card::before{border-radius:28px}
.section-title{font-size:17px}
.search-input{height:46px;font-size:14px;border-radius:14px}
.btn-add{width:46px;height:46px;border-radius:14px}
.btn-add svg{width:20px;height:20px}
.key-item{padding:18px;border-radius:16px;margin-bottom:10px}
.key-label{font-size:14px}
.key-value{height:34px;font-size:12px;border-radius:10px}
.btn-icon{width:34px;height:34px;border-radius:10px}
.btn-icon svg{width:14px;height:14px}
.quota-section{margin-top:16px}
.quota-text{font-size:11px}
.quota-percent{font-size:11px}
.quota-bar-bg{height:5px;border-radius:5px}
.key-list{max-height:540px}
.modal{max-width:420px;padding:36px 30px}
}
@media(hover:hover){
.key-item{transition:border-color .2s}
.key-item:hover{border-color:rgba(255,255,255,0.12)}
.btn-icon{transition:all .15s}
.btn-icon:hover{background:rgba(255,255,255,0.08);color:var(--text)}
.key-value{transition:border-color .2s}
.key-value:hover{border-color:rgba(255,255,255,0.12)}
.alert-bell{transition:background .15s}
.alert-bell:hover{background:rgba(255,255,255,0.08)}
.stat-card{transition:box-shadow .2s}
.stat-card:hover{box-shadow:0 0 0 .5px rgba(255,255,255,0.1),0 12px 28px rgba(0,0,0,0.4)}
.btn-add{transition:transform .1s,opacity .15s}
.btn-add:hover{opacity:.85}
.gen-key-copy{transition:.15s}
.gen-key-copy:hover{background:rgba(255,255,255,0.1)}
}
</style>
</head>
<body>
<div class="layout">
<div class="admin-header">
<div class="alert-bell" id="alertBellBtn">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
<div class="alert-bell-badge" id="alertBadge">0</div>
</div>
<h1>OORvault</h1>
<p>Manage 128-bit API keys with<br>quota limits and role control.</p>
</div>
<div class="stats-row">
<div class="stat-card"><div class="stat-value" id="statTotal">&ndash;</div><div class="stat-label">Total</div></div>
<div class="stat-card"><div class="stat-value green" id="statActive">&ndash;</div><div class="stat-label">Active</div></div>
<div class="stat-card"><div class="stat-value red" id="statInactive">&ndash;</div><div class="stat-label">Inactive</div></div>
</div>
<div class="main-card">
<div class="card-header"><span class="section-title">API Keys</span><span class="key-count" id="keyCount">0</span></div>
<div class="action-row">
<input type="text" class="search-input" id="searchInput" placeholder="Search by key or label...">
<button class="btn-add" id="addBtn" title="Generate Key"><svg viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg></button>
</div>
<div id="loadingSkeletons"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div>
<div class="key-list" id="keyList" style="display:none"></div>
<div class="empty-state" id="emptyState">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
<div class="empty-title" id="emptyTitle">No API keys yet</div>
<div class="empty-sub" id="emptySub">Tap + to generate your first key</div>
</div>
</div>
<div class="site-footer" id="siteFooter"></div>
</div>

<div class="modal-overlay" id="addModal">
<div class="modal">
<h3>Generate API Key</h3>
<p class="modal-desc">Create a secure 128-bit key with<br>role assignment and quota limits.</p>
<label class="modal-label">Assign Role</label>
<div class="modal-select-box"><select id="addRole"><option value="reseller">Reseller</option><option value="owner">Owner</option></select></div>
<label class="modal-label">Label (Optional)</label>
<input type="text" class="modal-input" id="addLabel" placeholder="e.g. Production Key">
<div class="modal-row">
<div><label class="modal-label">Quota Limit</label><input type="number" class="modal-input" id="addQuota" placeholder="0 = Unlimited" min="0" value="0"></div>
<div><label class="modal-label">Reset Period</label><div class="modal-select-box"><select id="addPeriod"><option value="daily">Daily</option><option value="monthly" selected>Monthly</option><option value="yearly">Yearly</option><option value="lifetime">Lifetime</option></select></div></div>
</div>
<div class="gen-key-box">
<div class="gen-key-label">Generated Key</div>
<div class="gen-key-value" id="genKeyDisplay">&ndash;</div>
<button class="gen-key-copy" id="genKeyCopyBtn" title="Copy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>
</div>
<div class="modal-btns">
<button class="btn-cancel" id="addCancelBtn">Cancel</button>
<button class="btn-submit" id="addSubmitBtn">Create Key</button>
</div>
</div>
</div>

<div class="modal-overlay" id="deleteModal">
<div class="modal">
<h3>Revoke Key?</h3>
<p class="modal-desc">This action cannot be undone.<br>The key will be permanently revoked.</p>
<div class="modal-btns">
<button class="btn-cancel" id="delCancelBtn">Cancel</button>
<button class="btn-danger" id="delConfirmBtn">Revoke</button>
</div>
</div>
</div>

<div class="modal-overlay" id="alertModal">
<div class="modal">
<h3>Quota Alerts</h3>
<p class="modal-desc">Keys approaching or exceeding<br>their usage limits.</p>
<div class="alert-list" id="alertList"></div>
<div class="modal-btns" style="margin-top:16px"><button class="btn-cancel" id="alertDismissBtn" style="flex:1">Dismiss</button></div>
</div>
</div>

<div class="toast" id="toast"><div class="toast-dot" id="toastDot"></div><span class="toast-text" id="toastText"></span></div>

<script>
let allKeys=[];
let deleteTargetKey=null;
let currentGenKey='';

document.getElementById('siteFooter').textContent='\u00A9 '+new Date().getFullYear()+' OORverse. All rights reserved.';

function gen128Key(){const b=new Uint8Array(16);crypto.getRandomValues(b);return 'oor_'+Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('')}
function escHtml(s){if(!s)return '';const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function escAttr(s){if(!s)return '';return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function maskKey(k){if(!k)return '\u2022\u2022\u2022\u2022\u2022\u2022';if(k.length<=12)return k.substring(0,4)+'\u2022\u2022\u2022\u2022'+k.substring(k.length-4);return k.substring(0,8)+'\u2022\u2022\u2022\u2022\u2022\u2022'+k.substring(k.length-4)}
function cap(s){return s?s.charAt(0).toUpperCase()+s.slice(1):''}
function quotaColor(p){if(p>=100)return 'var(--red)';if(p>=90)return 'var(--orange)';return 'var(--green)'}
function sortKeys(a){return[...a].sort((x,y)=>{if(x.role==='owner'&&y.role!=='owner')return-1;if(x.role!=='owner'&&y.role==='owner')return 1;return 0})}

document.addEventListener('DOMContentLoaded',function(){
loadKeys();
document.getElementById('searchInput').addEventListener('input',filterKeys);
document.getElementById('addBtn').addEventListener('click',openAddModal);
document.getElementById('alertBellBtn').addEventListener('click',function(){renderAlerts();openModal('alertModal')});
document.getElementById('addCancelBtn').addEventListener('click',function(){closeModal('addModal')});
document.getElementById('addSubmitBtn').addEventListener('click',addKey);
document.getElementById('genKeyCopyBtn').addEventListener('click',function(){if(currentGenKey)doCopy(currentGenKey)});
document.getElementById('delCancelBtn').addEventListener('click',function(){closeModal('deleteModal')});
document.getElementById('delConfirmBtn').addEventListener('click',confirmDelete);
document.getElementById('alertDismissBtn').addEventListener('click',function(){closeModal('alertModal')});
['addModal','deleteModal','alertModal'].forEach(function(id){document.getElementById(id).addEventListener('click',function(e){if(e.target===this)closeModal(id)})});
document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeModal('addModal');closeModal('deleteModal');closeModal('alertModal')}});
document.getElementById('keyList').addEventListener('click',function(e){
var btn=e.target.closest('[data-action]');
if(!btn)return;
var act=btn.dataset.action,key=btn.dataset.key;
if(act==='copy')doCopy(key);
else if(act==='toggle')toggleKey(key);
else if(act==='delete')promptDelete(key);
});
});

async function loadKeys(){
try{var r=await fetch('/admin/api/keys');var d=await r.json();allKeys=d.keys||[]}catch(e){allKeys=[]}
document.getElementById('loadingSkeletons').style.display='none';
document.getElementById('keyList').style.display='block';
renderKeys(allKeys);updateStats();updateAlertBadge();
}

function renderKeys(keys){
var list=document.getElementById('keyList');
var empty=document.getElementById('emptyState');
var count=document.getElementById('keyCount');
var q=document.getElementById('searchInput').value.trim();
var sorted=sortKeys(keys);
count.textContent=sorted.length;
if(sorted.length===0){list.innerHTML='';empty.style.display='block';
document.getElementById('emptyTitle').textContent=q?'No matching keys':'No API keys yet';
document.getElementById('emptySub').textContent=q?'Try a different search term':'Tap + to generate your first key';return}
empty.style.display='none';
list.innerHTML=sorted.map(function(k){
var ek=escAttr(k.key);
var limit=parseInt(k.quota_limit)||0;
var usage=parseInt(k.current_usage)||0;
var period=cap(k.quota_period||'lifetime');
var pct=limit>0?Math.min(Math.round(usage/limit*100),100):0;
var limitStr=limit===0?'Unlimited':usage+' / '+limit;
var pctStr=limit===0?'\u221E':pct+'%';
var bw=limit===0?100:pct;
var bc=limit===0?'var(--green)':quotaColor(pct);
var isActive=k.active!==false;
var ob=k.role==='owner'?'<span class="role-badge-owner">OWNER</span>':'';
var lbl=escHtml(k.label||'Unnamed Key');
return '<div class="key-item" data-key="'+ek+'">'
+'<div class="key-top-row">'
+'<div class="status-dot '+(isActive?'active':'inactive')+'"></div>'
+ob
+'<div class="key-label">'+lbl+'</div>'
+'</div>'
+'<div class="key-mid-row">'
+'<div class="key-value" data-action="copy" data-key="'+ek+'" title="Tap to copy">'+maskKey(k.key)+'</div>'
+'<div class="key-actions">'
+'<button class="btn-icon" data-action="copy" data-key="'+ek+'" title="Copy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>'
+'<button class="btn-icon" data-action="toggle" data-key="'+ek+'" title="'+(isActive?'Deactivate':'Activate')+'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 11-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg></button>'
+'<button class="btn-icon" data-action="delete" data-key="'+ek+'" title="Revoke"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg></button>'
+'</div></div>'
+'<div class="quota-section"><div class="quota-row">'
+'<span class="quota-text">'+limitStr+' \u00B7 '+period+'</span>'
+'<span class="quota-percent" style="color:'+bc+'">'+pctStr+'</span>'
+'</div><div class="quota-bar-bg"><div class="quota-bar-fill" style="width:'+bw+'%;background:'+bc+'"></div></div></div>'
+'</div>'}).join('');
}

function updateStats(){
var t=allKeys.length,a=allKeys.filter(function(k){return k.active!==false}).length;
document.getElementById('statTotal').textContent=t;
document.getElementById('statActive').textContent=a;
document.getElementById('statInactive').textContent=t-a;
}

function getAlerts(){
return allKeys.filter(function(k){
if(k.role==='owner')return false;
var l=parseInt(k.quota_limit)||0;if(l===0)return false;
return((parseInt(k.current_usage)||0)/l*100)>=90;
});
}
function updateAlertBadge(){
var a=getAlerts(),b=document.getElementById('alertBadge');
if(a.length>0){b.textContent=a.length;b.classList.add('show')}else{b.classList.remove('show')}
}
function renderAlerts(){
var alerts=getAlerts(),list=document.getElementById('alertList');
if(alerts.length===0){list.innerHTML='<div class="no-alerts"><div class="no-alerts-icon">\u2705</div><div class="no-alerts-text">All keys within limits</div></div>';return}
list.innerHTML=alerts.map(function(k){
var pct=Math.round((parseInt(k.current_usage)||0)/(parseInt(k.quota_limit)||1)*100);
var period=cap(k.quota_period||'lifetime');
return '<div class="alert-item"><span class="alert-icon">\u26A0\uFE0F</span><span class="alert-item-text">'+escHtml(k.label||'Unnamed Key')+' is at '+pct+'% of its '+period+' quota</span></div>';
}).join('');
}

function filterKeys(){
var q=document.getElementById('searchInput').value.toLowerCase().trim();
if(!q){renderKeys(allKeys);return}
renderKeys(allKeys.filter(function(k){
return k.key.toLowerCase().indexOf(q)!==-1||(k.label&&k.label.toLowerCase().indexOf(q)!==-1);
}));
}

function openAddModal(){
currentGenKey=gen128Key();
document.getElementById('genKeyDisplay').textContent=currentGenKey;
document.getElementById('addRole').value='reseller';
document.getElementById('addLabel').value='';
document.getElementById('addQuota').value='0';
document.getElementById('addPeriod').value='monthly';
openModal('addModal');
}

// FIX: Label is now properly passed to the Python Backend
async function addKey(){
    var role=document.getElementById('addRole').value;
    var label=document.getElementById('addLabel').value.trim();
    var quota=parseInt(document.getElementById('addQuota').value)||0;
    var period=document.getElementById('addPeriod').value;
    
    if(!currentGenKey){showToast('Key generation failed','error');return;}
    
    var btn=document.getElementById('addSubmitBtn');
    btn.disabled=true;btn.textContent='Creating...';
    
    try{
        var r=await fetch('/admin/api/keys',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({
                key: currentGenKey,
                role: role,
                label: label, 
                quota_limit: quota,
                quota_period: period
            })
        });
        var d=await r.json();
        if(!d.success){showToast(d.error||'Failed to create key','error');btn.disabled=false;btn.textContent='Create Key';return;}
    }catch(e){
        showToast('Network error','error');btn.disabled=false;btn.textContent='Create Key';return;
    }
    
    allKeys.unshift({key:currentGenKey,label:label||'Unnamed Key',role:role,active:true,quota_limit:quota,quota_period:period,current_usage:0});
    renderKeys(allKeys);updateStats();updateAlertBadge();
    closeModal('addModal');showToast('API key created','success');
    btn.disabled=false;btn.textContent='Create Key';
}

// FIX: Database synchronization added so activation/deactivation is saved!
async function toggleKey(key){
    var k=allKeys.find(function(x){return x.key===key});
    if(!k)return;
    
    var newStatus = k.active === false ? true : false;
    
    try{
        var r=await fetch('/admin/api/keys/toggle',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({api_key: key, active: newStatus})
        });
        var d=await r.json();
        
        if(d.success){
            k.active = newStatus;
            renderKeys(allKeys);updateStats();
            showToast(k.active?'Key activated':'Key deactivated',k.active?'success':'error');
        } else {
            showToast('Failed to toggle key','error');
        }
    }catch(e){
        showToast('Network error','error');
    }
}

function promptDelete(key){deleteTargetKey=key;openModal('deleteModal')}

async function confirmDelete(){
if(!deleteTargetKey)return;
try{await fetch('/admin/api/keys/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_key:deleteTargetKey})})}catch(e){}
var items=document.querySelectorAll('.key-item');
items.forEach(function(item){if(item.dataset.key===deleteTargetKey)item.classList.add('removing')});
var ktd=deleteTargetKey;
setTimeout(function(){
allKeys=allKeys.filter(function(k){return k.key!==ktd});
renderKeys(allKeys);updateStats();updateAlertBadge();
closeModal('deleteModal');showToast('Key revoked','error');deleteTargetKey=null;
},300);
}

async function doCopy(val){
try{await navigator.clipboard.writeText(val)}catch(e){var t=document.createElement('textarea');t.value=val;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t)}
showToast('Copied to clipboard','success');
}

function openModal(id){document.getElementById(id).classList.add('show');document.body.style.overflow='hidden';var i=document.getElementById(id).querySelector('input');if(i)setTimeout(function(){i.focus()},100)}
function closeModal(id){document.getElementById(id).classList.remove('show');document.body.style.overflow=''}

var toastTimer;
function showToast(msg,type){
var t=document.getElementById('toast');
document.getElementById('toastDot').style.background=type==='error'?'var(--red)':'var(--green)';
document.getElementById('toastText').textContent=msg;
t.className='toast show';clearTimeout(toastTimer);
toastTimer=setTimeout(function(){t.className='toast'},2200);
}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)


# ── API Endpoints ──

@admin_router.get("/admin/api/keys")
def get_keys(user: str = Depends(verify_admin)):
    keys = database.get_all_keys()
    
    # FIX: Convert Redis string 'true'/'false' into an actual Boolean for Javascript 
    for k in keys:
        k["active"] = False if k.get("active") == "false" else True
        
    return {"keys": keys}


@admin_router.post("/admin/api/keys")
async def create_key_api(request: Request, user: str = Depends(verify_admin)):
    body = await request.json()
    key = body.get("key", "oor_" + secrets.token_hex(16))
    role = body.get("role", "reseller")
    label = body.get("label", "Unnamed Key") # <--- Extracts label from UI
    quota_limit = int(body.get("quota_limit", 0))
    quota_period = body.get("quota_period", "lifetime")
    
    database.create_api_key(key, role, label, quota_limit, quota_period)
    return {"success": True}


@admin_router.post("/admin/api/keys/delete")
async def delete_key_api(request: Request, user: str = Depends(verify_admin)):
    body = await request.json()
    api_key = body.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    database.delete_api_key(api_key)
    return {"success": True}

# --- FIX: NEW ENDPOINT TO HANDLE THE ACTIVATE/DEACTIVATE TOGGLE ---
@admin_router.post("/admin/api/keys/toggle")
async def toggle_key_api(request: Request, user: str = Depends(verify_admin)):
    body = await request.json()
    api_key = body.get("api_key")
    active = body.get("active", True)
    
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
        
    database.toggle_api_key(api_key, active)
    return {"success": True}
