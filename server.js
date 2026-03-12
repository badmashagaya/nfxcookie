const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

// --- Configuration (Set these in Render's Environment Variables) ---
const PORT = process.env.PORT || 3000;
const PYTHON_API_URL = process.env.PYTHON_API_URL || 'http://194.242.56.38:8888/';
const OWNER_API_KEY = process.env.OWNER_API_KEY || 'OTTONRENT';

// 1. Serve your index.html safely to the browser
app.use(express.static(path.join(__dirname, 'public')));

// 2. The Secure Proxy Interceptor
// When index.html calls "/api/upload", this server catches it, 
// secretly attaches your API key, and forwards it to the Python API.
app.use('/api', createProxyMiddleware({
    target: PYTHON_API_URL,
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
        // The browser never sees this happen!
        proxyReq.setHeader('X-API-Key', OWNER_API_KEY);
    }
}));

// 3. The Secure Admin Proxy
// Forwards /admin requests from Render to your VPS Admin Dashboard
app.use('/admin', createProxyMiddleware({
    target: PYTHON_API_URL,
    changeOrigin: true
}));


// 4. The Documentation Route (NEW)
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
