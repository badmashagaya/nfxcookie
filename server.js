const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

// --- Configuration (Set these in Render's Environment Variables) ---
const PORT = process.env.PORT || 3000;
const PYTHON_API_URL = process.env.PYTHON_API_URL || 'http://194.242.56.38:8888/'; // --- 187.127.141.77 ---

const OWNER_API_KEY = process.env.OWNER_API_KEY || 'oor_4a21a86defdca8eccbf4b5f63912d564';

// 1. Serve your index.html safely to the browser
app.use(express.static(path.join(__dirname, 'public')));

// 2. The Secure Proxy Interceptor
// When index.html calls "/api/...", this server catches it.
app.use('/api', createProxyMiddleware({
    target: PYTHON_API_URL,
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
        
        // RULE 1: If a Reseller or curl already provided an API Key, leave it alone!
        if (req.headers['x-api-key']) {
            return; 
        }

        // RULE 2: If NO key is provided, check if the request is coming from YOUR own website UI
        const origin = req.headers.origin || req.headers.referer || '';
        const host = req.headers.host || '';
        
        // If the origin matches your Render app's host, safely inject the Owner Key
        if (origin.includes(host)) {
            proxyReq.setHeader('X-API-Key', OWNER_API_KEY);
        }
    }
}));

// 3. The Secure Admin Proxy
// Forwards /admin requests from Render to your VPS Admin Dashboard
app.use('/admin', createProxyMiddleware({
    target: PYTHON_API_URL,
    changeOrigin: true
}));

// 4. The Secure Rescan Proxy (NEW)
// Forwards /rescan requests from Render to your VPS Rescan Dashboard
app.use('/rescan', createProxyMiddleware({
    target: PYTHON_API_URL,
    changeOrigin: true
}));

// 5. The Documentation Route
// This makes the pretty /oordocs URL work instantly
app.get('/oordocs', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

// Catch-all: Route everything else back to index.html (Handles React/Vue style routing if needed)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Secure Frontend Server running on port ${PORT}`);
});
