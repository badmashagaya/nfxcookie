from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
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
    <title>OOR Admin</title>
    <style>@import url('https://fonts.cdnfonts.com/css/nexa-bold');</style>
    <style>
        :root {
            --bg: #000000;
            --card-bg: #06060c;
            --text: #ffffff;
            --text2: #8e8e99;
            --accent: rgb(0, 136, 255);
            --border: rgba(255,255,255,0.1);
            --input-bg: rgba(255,255,255,0.05);
            --green: #34c759;
            --red: #ff3b30;
            --orange: #ff9f0a;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; outline: none; }

        body {
            font-family: 'Nexa', sans-serif;
            font-weight: 300;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            -webkit-font-smoothing: antialiased;
        }

        .layout { width: 100%; max-width: 340px; }

        /* Header */
        .admin-header {
            text-align: center;
            margin-bottom: 28px;
            position: relative;
        }
        .admin-header h1 {
            font-size: 22px;
            font-weight: 700;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
            line-height: 1.2;
        }
        .admin-header p {
            font-size: 13px;
            color: var(--text2);
            line-height: 1.5;
        }

        /* Alert Bell */
        .alert-bell {
            position: absolute;
            top: 2px; right: 0;
            width: 36px; height: 36px;
            border-radius: 10px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.06);
            display: flex; align-items: center; justify-content: center;
            cursor: pointer;
            transition: 0.15s;
            color: var(--text2);
        }
        .alert-bell:active { transform: scale(0.9); }
        .alert-bell svg { width: 16px; height: 16px; }
        .alert-bell-badge {
            position: absolute;
            top: -3px; right: -3px;
            width: 16px; height: 16px;
            border-radius: 50%;
            background: var(--orange);
            font-size: 9px;
            font-weight: 700;
            color: #000;
            display: none;
            align-items: center;
            justify-content: center;
            line-height: 1;
            border: 2px solid var(--bg);
        }
        .alert-bell-badge.show { display: flex; }

        /* Stats */
        .stats-row {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-bottom: 16px;
        }
        .stat-card {
            background: var(--card-bg);
            border-radius: 14px;
            padding: 18px 8px;
            text-align: center;
            position: relative;
            box-shadow: 0 0 0 0.5px rgba(255,255,255,0.05), 0 8px 20px rgba(0,0,0,0.3);
        }
        .stat-card::before {
            content: '';
            position: absolute; inset: 0;
            border-radius: 14px; padding: 1px;
            background: linear-gradient(170deg, rgba(255,255,255,0.1) 0%, transparent 40%, transparent 60%, rgba(255,255,255,0.07) 100%);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor; mask-composite: exclude;
            pointer-events: none;
        }
        .stat-value { font-size: 24px; font-weight: 700; line-height: 1; margin-bottom: 6px; }
        .stat-label { font-size: 10px; color: var(--text2); font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; line-height: 1; }
        .stat-value.green { color: var(--green); }
        .stat-value.red { color: var(--red); }

        /* Main Card */
        .main-card {
            background: var(--card-bg);
            border-radius: 20px;
            padding: 24px 20px;
            position: relative;
            box-shadow: 0 0 0 0.5px rgba(255,255,255,0.05), 0 0 40px rgba(255,255,255,0.02), 0 20px 40px rgba(0,0,0,0.5);
        }
        .main-card::before {
            content: '';
            position: absolute; inset: 0;
            border-radius: 20px; padding: 1px;
            background: linear-gradient(170deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 30%, transparent 55%, rgba(255,255,255,0.04) 80%, rgba(255,255,255,0.09) 100%);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor; mask-composite: exclude;
            pointer-events: none;
        }

        .card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
        .section-title { font-size: 15px; font-weight: 700; line-height: 1; }
        .key-count { font-size: 11px; font-weight: 700; background: rgba(255,255,255,0.08); color: var(--text2); padding: 4px 10px; border-radius: 11px; line-height: 1; }

        .action-row { display: flex; gap: 8px; margin-bottom: 14px; align-items: center; }
        .search-input {
            flex: 1; height: 42px; padding: 0 14px; border-radius: 12px;
            background: var(--input-bg); border: 1px solid var(--border);
            color: white; font-size: 13px; font-weight: 700;
            font-family: 'Nexa', sans-serif; transition: 0.2s;
        }
        .search-input:focus { border-color: var(--accent); background: rgba(255,255,255,0.08); }
        .search-input::placeholder { color: var(--text2); }

        .btn-add {
            width: 42px; height: 42px; border-radius: 12px;
            background: white; border: none; cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            transition: transform 0.1s; flex-shrink: 0;
        }
        .btn-add:active { transform: scale(0.92); }
        .btn-add svg { width: 18px; height: 18px; }

        /* Key List */
        .key-list {
            max-height: 400px; overflow-y: auto; overflow-x: hidden;
            overscroll-behavior: contain;
        }
        .key-list::-webkit-scrollbar { width: 3px; }
        .key-list::-webkit-scrollbar-track { background: transparent; }
        .key-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 3px; }

        .key-item {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 14px; padding: 14px;
            margin-bottom: 8px; animation: slideIn 0.3s ease;
        }
        .key-item:last-child { margin-bottom: 0; }

        @keyframes slideIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .key-item.removing { animation: removeItem 0.3s ease forwards; }
        @keyframes removeItem { to { opacity: 0; transform: translateX(-20px); height: 0; margin: 0; padding: 0; border: 0; overflow: hidden; } }

        .key-top-row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .status-dot.active { background: var(--green); box-shadow: 0 0 8px rgba(52,199,89,0.4); }
        .status-dot.inactive { background: var(--red); box-shadow: 0 0 8px rgba(255,59,48,0.3); }

        .role-badge-owner {
            font-size: 9px; font-weight: 700; letter-spacing: 1px;
            padding: 3px 7px; border-radius: 6px;
            line-height: 1; flex-shrink: 0; text-transform: uppercase;
            background: rgba(52,199,89,0.12); color: var(--green);
            border: 1px solid rgba(52,199,89,0.2);
            display: inline-flex; align-items: center; justify-content: center;
            height: 18px;
        }

        .key-label { font-size: 13px; font-weight: 700; line-height: 1; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        .key-mid-row { display: flex; align-items: center; gap: 8px; }
        .key-value {
            flex: 1; min-width: 0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 11px; color: var(--text2);
            background: rgba(0,0,0,0.3); height: 30px; padding: 0 10px;
            border-radius: 8px; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; cursor: pointer; transition: 0.2s;
            border: 1px solid transparent;
            display: flex; align-items: center;
        }
        .key-value:active { border-color: var(--accent); }

        .key-actions { display: flex; gap: 5px; flex-shrink: 0; }
        .btn-icon {
            width: 30px; height: 30px; border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.06);
            background: rgba(255,255,255,0.03); color: var(--text2);
            cursor: pointer; display: flex; align-items: center; justify-content: center;
            transition: all 0.15s;
        }
        .btn-icon:active { transform: scale(0.88); }
        .btn-icon svg { width: 13px; height: 13px; }

        /* Quota */
        .quota-section { margin-top: 12px; }
        .quota-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
        .quota-text { font-size: 10px; font-weight: 700; color: var(--text2); line-height: 1; }
        .quota-percent { font-size: 10px; font-weight: 700; line-height: 1; }
        .quota-bar-bg { width: 100%; height: 4px; background: rgba(255,255,255,0.08); border-radius: 4px; overflow: hidden; }
        .quota-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s cubic-bezier(0.25, 1, 0.5, 1); }

        /* Empty */
        .empty-state { text-align: center; padding: 36px 16px; display: none; }
        .empty-state svg { width: 40px; height: 40px; color: var(--text2); opacity: 0.25; margin-bottom: 14px; }
        .empty-state .empty-title { font-size: 14px; font-weight: 700; color: var(--text2); margin-bottom: 4px; line-height: 1.3; }
        .empty-state .empty-sub { font-size: 12px; color: var(--text2); opacity: 0.6; line-height: 1.3; }

        /* Skeleton */
        .skeleton {
            height: 100px; border-radius: 14px; margin-bottom: 8px;
            background: linear-gradient(90deg, rgba(255,255,255,0.03) 25%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.03) 75%);
            background-size: 200% 100%; animation: shimmer 1.5s infinite;
        }
        .skeleton:last-child { margin-bottom: 0; }
        @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

        /* Modal */
        .modal-overlay {
            position: fixed; inset: 0;
            background: rgba(0,0,0,0.75);
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            display: none; align-items: center; justify-content: center;
            z-index: 100; padding: 20px;
        }
        .modal-overlay.show { display: flex; }

        .modal {
            background: var(--card-bg); border-radius: 20px;
            padding: 30px 24px; width: 100%; max-width: 320px;
            position: relative; animation: modalIn 0.3s ease;
            box-shadow: 0 0 0 0.5px rgba(255,255,255,0.05), 0 20px 60px rgba(0,0,0,0.8);
            max-height: 90vh; overflow-y: auto;
        }
        .modal::-webkit-scrollbar { width: 0; }
        .modal::before {
            content: '';
            position: absolute; inset: 0;
            border-radius: 20px; padding: 1px;
            background: linear-gradient(170deg, rgba(255,255,255,0.12) 0%, rgba(255,255,255,0.03) 30%, transparent 55%, rgba(255,255,255,0.04) 80%, rgba(255,255,255,0.09) 100%);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor; mask-composite: exclude;
            pointer-events: none;
        }
        @keyframes modalIn { from { opacity: 0; transform: scale(0.95) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }

        .modal h3 { font-size: 18px; font-weight: 700; text-align: center; margin-bottom: 6px; line-height: 1.2; }
        .modal .modal-desc { font-size: 12px; color: var(--text2); text-align: center; margin-bottom: 24px; line-height: 1.5; }
        .modal-label { display: block; font-size: 12px; color: var(--text2); font-weight: 700; margin-bottom: 8px; padding-left: 4px; line-height: 1; }

        .modal input[type="text"],
        .modal input[type="number"] {
            width: 100%; padding: 14px 16px; border-radius: 12px;
            background: var(--input-bg); border: 1px solid var(--border);
            color: white; font-size: 13px; font-weight: 700;
            font-family: 'Nexa', sans-serif; transition: 0.2s;
            margin-bottom: 14px; appearance: none; -webkit-appearance: none;
        }
        .modal input:focus { border-color: var(--accent); background: rgba(255,255,255,0.08); }
        .modal input::placeholder { color: var(--text2); opacity: 0.6; }

        .modal select {
            width: 100%; padding: 14px 16px; border-radius: 12px;
            background: var(--input-bg); border: 1px solid var(--border);
            color: white; font-size: 13px; font-weight: 700;
            font-family: 'Nexa', sans-serif; transition: 0.2s;
            margin-bottom: 14px; appearance: none; -webkit-appearance: none;
        }
        .modal select:focus { border-color: var(--accent); background: rgba(255,255,255,0.08); }
        .modal option { background: #1c1c1e; color: white; font-weight: 300; }

        .modal-select-wrapper { position: relative; }
        .modal-select-wrapper::after {
            content: ''; position: absolute; right: 16px; top: 40px;
            width: 12px; height: 12px;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
            background-size: contain; background-repeat: no-repeat;
            pointer-events: none; opacity: 0.5;
        }

        .modal-row { display: flex; gap: 10px; }
        .modal-row > div { flex: 1; min-width: 0; }

        /* Generated Key Box */
        .generated-key-box {
            background: rgba(0,0,0,0.3); border: 1px solid var(--border);
            border-radius: 10px; padding: 14px; padding-right: 44px;
            margin-bottom: 20px; position: relative; min-height: 60px;
        }
        .generated-key-label {
            font-size: 10px; font-weight: 700; color: var(--text2);
            text-transform: uppercase; letter-spacing: 0.8px;
            margin-bottom: 8px; line-height: 1;
        }
        .generated-key-value {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 11px; color: var(--green);
            word-break: break-all; line-height: 1.5; user-select: all;
        }
        .generated-key-copy {
            position: absolute; top: 50%; right: 10px;
            transform: translateY(-50%);
            width: 28px; height: 28px; border-radius: 7px;
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.08);
            color: var(--text2); cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            transition: 0.15s;
        }
        .generated-key-copy:active { transform: translateY(-50%) scale(0.88); }
        .generated-key-copy svg { width: 12px; height: 12px; }

        .modal-btns { display: flex; gap: 10px; margin-top: 6px; }
        .btn-cancel {
            flex: 1; height: 48px; border-radius: 12px;
            background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08);
            color: white; font-size: 14px; font-weight: 700;
            font-family: 'Nexa', sans-serif; cursor: pointer; transition: 0.1s;
            display: flex; align-items: center; justify-content: center;
        }
        .btn-cancel:active { transform: scale(0.96); }
        .btn-submit {
            flex: 1; height: 48px; border-radius: 12px;
            background: white; border: none; color: black;
            font-size: 14px; font-weight: 700;
            font-family: 'Nexa', sans-serif; cursor: pointer; transition: 0.1s;
            display: flex; align-items: center; justify-content: center;
        }
        .btn-submit:active { transform: scale(0.96); }
        .btn-submit:disabled { background: #333; color: #666; cursor: not-allowed; transform: none; }
        .btn-danger {
            flex: 1; height: 48px; border-radius: 12px;
            background: var(--red); border: none; color: white;
            font-size: 14px; font-weight: 700;
            font-family: 'Nexa', sans-serif; cursor: pointer; transition: 0.1s;
            display: flex; align-items: center; justify-content: center;
        }
        .btn-danger:active { transform: scale(0.96); }

        /* Alert Modal Content */
        .alert-list { max-height: 300px; overflow-y: auto; }
        .alert-list::-webkit-scrollbar { width: 3px; }
        .alert-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 3px; }
        .alert-item {
            background: rgba(255, 159, 10, 0.06);
            border: 1px solid rgba(255, 159, 10, 0.15);
            border-radius: 10px; padding: 12px 14px;
            margin-bottom: 8px; display: flex;
            align-items: flex-start; gap: 10px;
        }
        .alert-item:last-child { margin-bottom: 0; }
        .alert-icon { font-size: 13px; flex-shrink: 0; line-height: 1.4; }
        .alert-item-text { font-size: 12px; font-weight: 700; color: var(--orange); line-height: 1.4; }
        .no-alerts { text-align: center; padding: 30px 10px; }
        .no-alerts-icon { font-size: 28px; margin-bottom: 10px; opacity: 0.4; }
        .no-alerts-text { font-size: 13px; color: var(--text2); font-weight: 700; }

        /* Toast */
        .toast {
            position: fixed; bottom: 36px; left: 50%;
            transform: translateX(-50%) translateY(60px) scale(0.92);
            background: #1c1c1e; border-radius: 100px;
            height: 40px; padding: 0 20px 0 16px;
            display: flex; align-items: center; gap: 10px;
            z-index: 200; opacity: 0;
            transition: all 0.45s cubic-bezier(0.25, 1, 0.5, 1);
            box-shadow: 0 6px 24px rgba(0,0,0,0.5), 0 0 0 0.5px rgba(255,255,255,0.06);
            pointer-events: none;
        }
        .toast.show { transform: translateX(-50%) translateY(0) scale(1); opacity: 1; }
        .toast-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .toast-text { font-size: 13px; font-weight: 700; color: rgba(255,255,255,0.85); font-family: 'Nexa', sans-serif; white-space: nowrap; line-height: 1; }

        /* Footer */
        .site-footer {
            margin-top: 0; padding-top: 30px;
            font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', system-ui, sans-serif;
            font-size: 11px; font-weight: 400; color: var(--text2);
            text-align: center; opacity: 0.4; letter-spacing: 0.2px;
        }

        @media (min-width: 420px) { .layout { max-width: 400px; } .modal { max-width: 360px; } }
        @media (min-width: 768px) {
            body { padding: 60px 40px; justify-content: center; }
            .layout { max-width: 440px; }
            .admin-header h1 { font-size: 24px; }
            .main-card { padding: 28px 24px; border-radius: 24px; }
            .main-card::before { border-radius: 24px; }
            .key-list { max-height: 500px; }
            .stat-value { font-size: 28px; }
            .modal { max-width: 380px; }
        }
        @media (min-width: 1200px) {
            .layout { max-width: 480px; }
            .main-card { padding: 32px 28px; }
            .modal { max-width: 400px; }
        }
    </style>
</head>
<body>

    <div class="layout">
        <div class="admin-header">
            <h1>Admin Panel</h1>
            <p>Manage 128-bit API keys with<br>quota limits and role control.</p>
            <div class="alert-bell" onclick="openModal('alertModal')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                    <path d="M13.73 21a2 2 0 01-3.46 0"/>
                </svg>
                <div class="alert-bell-badge" id="alertBadge">0</div>
            </div>
        </div>

        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value" id="statTotal">&ndash;</div>
                <div class="stat-label">Total</div>
            </div>
            <div class="stat-card">
                <div class="stat-value green" id="statActive">&ndash;</div>
                <div class="stat-label">Active</div>
            </div>
            <div class="stat-card">
                <div class="stat-value red" id="statInactive">&ndash;</div>
                <div class="stat-label">Inactive</div>
            </div>
        </div>

        <div class="main-card">
            <div class="card-header">
                <span class="section-title">API Keys</span>
                <span class="key-count" id="keyCount">0</span>
            </div>
            <div class="action-row">
                <input type="text" class="search-input" id="searchInput" placeholder="Search keys..." oninput="filterKeys()">
                <button class="btn-add" onclick="openAddModal()" title="Generate Key">
                    <svg viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                    </svg>
                </button>
            </div>
            <div id="loadingSkeletons">
                <div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>
            </div>
            <div class="key-list" id="keyList" style="display:none;"></div>
            <div class="empty-state" id="emptyState">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
                </svg>
                <div class="empty-title" id="emptyTitle">No API keys yet</div>
                <div class="empty-sub" id="emptySub">Tap + to generate your first key</div>
            </div>
        </div>
        <div class="site-footer" id="siteFooter"></div>
    </div>

    <!-- Generate Key Modal -->
    <div class="modal-overlay" id="addModal" onclick="if(event.target===this)closeModal('addModal')">
        <div class="modal">
            <h3>Generate API Key</h3>
            <p class="modal-desc">Create a secure 128-bit key with<br>role assignment and quota limits.</p>
            <div class="modal-select-wrapper">
                <label class="modal-label">Assign Role</label>
                <select id="addRole"><option value="reseller">Reseller</option><option value="owner">Owner</option></select>
            </div>
            <label class="modal-label">Label (Optional)</label>
            <input type="text" id="addLabel" placeholder="e.g. Production Key">
            <div class="modal-row">
                <div>
                    <label class="modal-label">Quota Limit</label>
                    <input type="number" id="addQuota" placeholder="0 = Unlimited" min="0" value="0">
                </div>
                <div class="modal-select-wrapper">
                    <label class="modal-label">Reset Period</label>
                    <select id="addPeriod">
                        <option value="daily">Daily</option><option value="monthly" selected>Monthly</option>
                        <option value="yearly">Yearly</option><option value="lifetime">Lifetime</option>
                    </select>
                </div>
            </div>
            <div class="generated-key-box">
                <div class="generated-key-label">Generated Key</div>
                <div class="generated-key-value" id="generatedKeyDisplay">&ndash;</div>
                <button class="generated-key-copy" onclick="copyGeneratedKey()" title="Copy">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                    </svg>
                </button>
            </div>
            <div class="modal-btns">
                <button class="btn-cancel" onclick="closeModal('addModal')">Cancel</button>
                <button class="btn-submit" id="addSubmitBtn" onclick="addKey()">Create Key</button>
            </div>
        </div>
    </div>

    <!-- Delete Modal -->
    <div class="modal-overlay" id="deleteModal" onclick="if(event.target===this)closeModal('deleteModal')">
        <div class="modal">
            <h3>Revoke Key?</h3>
            <p class="modal-desc">This action cannot be undone.<br>The key will be permanently revoked.</p>
            <div class="modal-btns">
                <button class="btn-cancel" onclick="closeModal('deleteModal')">Cancel</button>
                <button class="btn-danger" onclick="confirmDelete()">Revoke</button>
            </div>
        </div>
    </div>

    <!-- Alerts Modal -->
    <div class="modal-overlay" id="alertModal" onclick="if(event.target===this)closeModal('alertModal')">
        <div class="modal">
            <h3>Quota Alerts</h3>
            <p class="modal-desc">Keys approaching or exceeding<br>their usage limits.</p>
            <div class="alert-list" id="alertList"></div>
            <div class="modal-btns" style="margin-top:16px;">
                <button class="btn-cancel" onclick="closeModal('alertModal')" style="flex:1;">Dismiss</button>
            </div>
        </div>
    </div>

    <div class="toast" id="toast">
        <div class="toast-dot" id="toastDot"></div>
        <span class="toast-text" id="toastText"></span>
    </div>

<script>
    let allKeys = [];
    let deleteTargetKey = null;
    let currentGeneratedKey = '';

    document.getElementById('siteFooter').textContent = '\\u00A9 ' + new Date().getFullYear() + ' OORverse. All rights reserved.';
    document.addEventListener('DOMContentLoaded', loadKeys);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { closeModal('addModal'); closeModal('deleteModal'); closeModal('alertModal'); }
    });

    function generate128BitKey() {
        const b = new Uint8Array(16);
        crypto.getRandomValues(b);
        return 'oor_' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    }

    function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

    function maskKey(key) {
        if (!key) return '\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022';
        if (key.length <= 12) return key.substring(0, 4) + '\\u2022\\u2022\\u2022\\u2022' + key.substring(key.length - 4);
        return key.substring(0, 8) + '\\u2022\\u2022\\u2022\\u2022\\u2022\\u2022' + key.substring(key.length - 6);
    }

    function getQuotaColor(pct) {
        if (pct >= 100) return 'var(--red)';
        if (pct >= 90) return 'var(--orange)';
        return 'var(--green)';
    }

    function sortKeys(keys) {
        return [...keys].sort((a, b) => {
            if (a.role === 'owner' && b.role !== 'owner') return -1;
            if (a.role !== 'owner' && b.role === 'owner') return 1;
            return 0;
        });
    }

    async function loadKeys() {
        try {
            const res = await fetch('/admin/api/keys');
            const data = await res.json();
            allKeys = data.keys || [];
        } catch (e) { allKeys = []; }
        document.getElementById('loadingSkeletons').style.display = 'none';
        document.getElementById('keyList').style.display = 'block';
        renderKeys(allKeys); updateStats(); updateAlertBadge();
    }

    function renderKeys(keys) {
        const list = document.getElementById('keyList');
        const empty = document.getElementById('emptyState');
        const count = document.getElementById('keyCount');
        const query = document.getElementById('searchInput').value.trim();
        const sorted = sortKeys(keys);
        count.textContent = sorted.length;

        if (sorted.length === 0) {
            list.innerHTML = '';
            empty.style.display = 'block';
            document.getElementById('emptyTitle').textContent = query ? 'No matching keys' : 'No API keys yet';
            document.getElementById('emptySub').textContent = query ? 'Try a different search term' : 'Tap + to generate your first key';
            return;
        }
        empty.style.display = 'none';

        list.innerHTML = sorted.map(k => {
            const limit = parseInt(k.quota_limit) || 0;
            const usage = parseInt(k.current_usage) || 0;
            const period = (k.quota_period || 'lifetime').charAt(0).toUpperCase() + (k.quota_period || 'lifetime').slice(1);
            const pct = limit > 0 ? Math.min(Math.round(usage / limit * 100), 100) : 0;
            const limitStr = limit === 0 ? 'Unlimited' : usage + ' / ' + limit;
            const pctStr = limit === 0 ? '\\u221E' : pct + '%';
            const barWidth = limit === 0 ? 100 : pct;
            const barColor = limit === 0 ? 'var(--green)' : getQuotaColor(pct);
            const ownerBadge = k.role === 'owner' ? '<span class="role-badge-owner">OWNER</span>' : '';

            return '<div class="key-item" id="key-' + escapeHtml(k.key) + '">' +
                '<div class="key-top-row">' +
                    '<div class="status-dot ' + (k.active !== false ? 'active' : 'inactive') + '"></div>' +
                    ownerBadge +
                    '<div class="key-label">' + escapeHtml(k.label || 'Unnamed Key') + '</div>' +
                '</div>' +
                '<div class="key-mid-row">' +
                    '<div class="key-value" onclick="copyKey(\\'' + escapeHtml(k.key) + '\\')" title="Tap to copy">' + maskKey(k.key) + '</div>' +
                    '<div class="key-actions">' +
                        '<button class="btn-icon" onclick="copyKey(\\'' + escapeHtml(k.key) + '\\')" title="Copy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>' +
                        '<button class="btn-icon" onclick="toggleKey(\\'' + escapeHtml(k.key) + '\\')" title="Toggle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 11-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg></button>' +
                        '<button class="btn-icon" onclick="promptDelete(\\'' + escapeHtml(k.key) + '\\')" title="Revoke"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg></button>' +
                    '</div>' +
                '</div>' +
                '<div class="quota-section">' +
                    '<div class="quota-row">' +
                        '<span class="quota-text">' + limitStr + ' \\u00B7 ' + period + '</span>' +
                        '<span class="quota-percent" style="color:' + barColor + '">' + pctStr + '</span>' +
                    '</div>' +
                    '<div class="quota-bar-bg"><div class="quota-bar-fill" style="width:' + barWidth + '%;background:' + barColor + ';"></div></div>' +
                '</div>' +
            '</div>';
        }).join('');
    }

    function updateStats() {
        const total = allKeys.length;
        const active = allKeys.filter(k => k.active !== false).length;
        document.getElementById('statTotal').textContent = total;
        document.getElementById('statActive').textContent = active;
        document.getElementById('statInactive').textContent = total - active;
    }

    function getAlerts() {
        return allKeys.filter(k => {
            if (k.role === 'owner') return false;
            const limit = parseInt(k.quota_limit) || 0;
            if (limit === 0) return false;
            return ((parseInt(k.current_usage) || 0) / limit * 100) >= 90;
        });
    }

    function updateAlertBadge() {
        const alerts = getAlerts();
        const badge = document.getElementById('alertBadge');
        if (alerts.length > 0) {
            badge.textContent = alerts.length;
            badge.classList.add('show');
        } else {
            badge.classList.remove('show');
        }
    }

    function renderAlerts() {
        const alerts = getAlerts();
        const list = document.getElementById('alertList');
        if (alerts.length === 0) {
            list.innerHTML = '<div class="no-alerts"><div class="no-alerts-icon">\\u2705</div><div class="no-alerts-text">All keys within limits</div></div>';
            return;
        }
        list.innerHTML = alerts.map(k => {
            const pct = Math.round((parseInt(k.current_usage) || 0) / (parseInt(k.quota_limit) || 1) * 100);
            const period = (k.quota_period || 'lifetime').charAt(0).toUpperCase() + (k.quota_period || 'lifetime').slice(1);
            return '<div class="alert-item"><span class="alert-icon">\\u26A0\\uFE0F</span><span class="alert-item-text">' + escapeHtml(k.label || 'Unnamed Key') + ' is at ' + pct + '% of its ' + period + ' quota</span></div>';
        }).join('');
    }

    function filterKeys() {
        const q = document.getElementById('searchInput').value.toLowerCase().trim();
        if (!q) { renderKeys(allKeys); return; }
        renderKeys(allKeys.filter(k =>
            (k.label && k.label.toLowerCase().includes(q)) ||
            k.key.toLowerCase().includes(q) ||
            k.role.toLowerCase().includes(q)
        ));
    }

    function openAddModal() {
        currentGeneratedKey = generate128BitKey();
        document.getElementById('generatedKeyDisplay').textContent = currentGeneratedKey;
        document.getElementById('addRole').value = 'reseller';
        document.getElementById('addLabel').value = '';
        document.getElementById('addQuota').value = '0';
        document.getElementById('addPeriod').value = 'monthly';
        openModal('addModal');
    }

    function copyGeneratedKey() { if (currentGeneratedKey) copyKey(currentGeneratedKey); }

    async function addKey() {
        const role = document.getElementById('addRole').value;
        const label = document.getElementById('addLabel').value.trim();
        const quota = parseInt(document.getElementById('addQuota').value) || 0;
        const period = document.getElementById('addPeriod').value;
        if (!currentGeneratedKey) { showToast('Key generation failed', 'error'); return; }

        const btn = document.getElementById('addSubmitBtn');
        btn.disabled = true; btn.textContent = 'Creating...';

        try {
            const res = await fetch('/admin/api/keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: currentGeneratedKey, role: role, label: label, quota_limit: quota, quota_period: period })
            });
            const data = await res.json();
            if (!data.success) {
                showToast(data.error || 'Failed to create key', 'error');
                btn.disabled = false; btn.textContent = 'Create Key'; return;
            }
        } catch (e) {}

        allKeys.unshift({
            key: currentGeneratedKey, label: label || 'Unnamed Key', role: role,
            active: true, quota_limit: quota, quota_period: period, current_usage: 0
        });
        renderKeys(allKeys); updateStats(); updateAlertBadge();
        closeModal('addModal');
        showToast('API key created', 'success');
        btn.disabled = false; btn.textContent = 'Create Key';
    }

    async function toggleKey(key) {
        const k = allKeys.find(x => x.key === key);
        if (!k) return;
        k.active = !k.active;
        try {
            await fetch('/admin/api/keys/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: key, active: k.active })
            });
        } catch (e) {}
        renderKeys(allKeys); updateStats();
        showToast(k.active ? 'Key activated' : 'Key deactivated', k.active ? 'success' : 'error');
    }

    function promptDelete(key) { deleteTargetKey = key; openModal('deleteModal'); }

    async function confirmDelete() {
        if (!deleteTargetKey) return;
        try {
            await fetch('/admin/api/keys/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: deleteTargetKey })
            });
        } catch (e) {}
        const el = document.getElementById('key-' + deleteTargetKey);
        if (el) el.classList.add('removing');
        const keyToDelete = deleteTargetKey;
        setTimeout(() => {
            allKeys = allKeys.filter(k => k.key !== keyToDelete);
            renderKeys(allKeys); updateStats(); updateAlertBadge();
            closeModal('deleteModal');
            showToast('Key revoked', 'error');
            deleteTargetKey = null;
        }, 300);
    }

    async function copyKey(value) {
        try { await navigator.clipboard.writeText(value); }
        catch (e) { const t = document.createElement('textarea'); t.value = value; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t); }
        showToast('Copied to clipboard', 'success');
    }

    function openModal(id) {
        if (id === 'alertModal') renderAlerts();
        document.getElementById(id).classList.add('show');
        document.body.style.overflow = 'hidden';
        const i = document.getElementById(id).querySelector('input');
        if (i) setTimeout(() => i.focus(), 100);
    }
    function closeModal(id) { document.getElementById(id).classList.remove('show'); document.body.style.overflow = ''; }

    let toastTimer;
    function showToast(msg, type) {
        const t = document.getElementById('toast');
        document.getElementById('toastDot').style.background = type === 'error' ? 'var(--red)' : 'var(--green)';
        document.getElementById('toastText').textContent = msg;
        t.className = 'toast show';
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { t.className = 'toast'; }, 2200);
    }
</script>
</body>
</html>"""
    return HTMLResponse(content=html)


# ── API Endpoints for the UI ──

@admin_router.get("/admin/api/keys")
def get_keys(user: str = Depends(verify_admin)):
    keys = database.get_all_keys()
    return {"keys": keys}


@admin_router.post("/admin/api/keys")
async def create_key(request: Request, user: str = Depends(verify_admin)):
    body = await request.json()
    key = body.get("key", "oor_" + secrets.token_hex(16))
    role = body.get("role", "reseller")
    label = body.get("label", "")
    quota_limit = body.get("quota_limit", 0)
    quota_period = body.get("quota_period", "lifetime")
    
    database.create_api_key(key, role, quota_limit, quota_period, label)
    return {"success": True}


@admin_router.post("/admin/api/keys/toggle")
async def toggle_key(request: Request, user: str = Depends(verify_admin)):
    body = await request.json()
    api_key = body.get("api_key")
    active = body.get("active", True)
    
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    
    database.toggle_api_key(api_key, active)
    return {"success": True}


@admin_router.post("/admin/api/keys/delete")
async def delete_key(request: Request, user: str = Depends(verify_admin)):
    body = await request.json()
    api_key = body.get("api_key")
    
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    
    database.delete_api_key(api_key)
    return {"success": True}
