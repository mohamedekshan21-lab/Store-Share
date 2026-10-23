// =============================================================================
// Expo Distributed Storage — Dedicated Frontend Development Server
// =============================================================================
// Serves the Single-Page Application (SPA) UI and proxies API requests
// seamlessly to the Coordinator backend on port 8000.
// Zero third-party dependencies required (uses native Node.js standard library).

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:8000';
const BACKEND_PARSED = new url.URL(BACKEND_URL);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
};

// Prefixes that should be proxied to the Coordinator backend
const PROXY_PREFIXES = [
  '/auth',
  '/consumer',
  '/provider',
  '/admin',
  '/nodes',
  '/health',
  '/observability',
  '/capabilities',
  '/files',
  '/relay',
  '/metrics',
];

function shouldProxy(pathname) {
  return PROXY_PREFIXES.some(prefix => pathname === prefix || pathname.startsWith(prefix + '/'));
}

function proxyRequest(req, res, targetUrl) {
  const options = {
    hostname: BACKEND_PARSED.hostname,
    port: BACKEND_PARSED.port,
    path: req.url,
    method: req.method,
    headers: {
      ...req.headers,
      host: `${BACKEND_PARSED.hostname}:${BACKEND_PARSED.port}`,
      'x-forwarded-for': req.socket.remoteAddress,
      'x-forwarded-proto': 'http',
      'x-forwarded-host': req.headers.host || `127.0.0.1:${PORT}`,
    },
  };

  const proxy = http.request(options, (backendRes) => {
    res.writeHead(backendRes.statusCode, backendRes.headers);
    backendRes.pipe(res, { end: true });
  });

  proxy.on('error', (err) => {
    console.error(`[Proxy Error] ${req.method} ${req.url} -> ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        detail: `Bad Gateway: Could not reach Coordinator backend at ${BACKEND_URL}. Ensure the backend is running.`,
        error: err.message,
      }));
    }
  });

  req.pipe(proxy, { end: true });
}

function serveStatic(req, res, pathname) {
  let relativePath = pathname;
  if (relativePath.startsWith('/static/')) {
    relativePath = relativePath.slice('/static/'.length);
  } else if (relativePath.startsWith('/')) {
    relativePath = relativePath.slice(1);
  }

  if (!relativePath || relativePath === 'app' || relativePath === 'dashboard') {
    relativePath = 'index.html';
  }

  const filePath = path.join(__dirname, relativePath);

  // Security: prevent path traversal outside __dirname
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fall back to index.html for SPA routes
      const fallbackIndex = path.join(__dirname, 'index.html');
      fs.readFile(fallbackIndex, (err2, data) => {
        if (err2) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(data);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
    });

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname || '/';

  if (shouldProxy(pathname)) {
    proxyRequest(req, res, req.url);
  } else {
    serveStatic(req, res, pathname);
  }
});

server.listen(PORT, HOST, () => {
  console.log('=============================================================');
  console.log(`🪐 Expo Frontend Server running at http://${HOST === '0.0.0.0' ? '127.0.0.1' : HOST}:${PORT}/`);
  console.log(`📡 Connected Backend Proxy: ${BACKEND_URL}`);
  console.log('=============================================================');
});
