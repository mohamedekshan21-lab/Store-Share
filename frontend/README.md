# Expo Distributed Storage — Frontend Application

This folder contains the complete, dedicated frontend application for the Expo Distributed Storage platform.

## Architecture

- **UI Stack:** Modern responsive Single-Page Application (SPA) using HTML5, modern CSS3 with glassmorphism design system tokens, and asynchronous vanilla JavaScript.
- **Port:** Runs by default on `http://127.0.0.1:3000/`.
- **Backend Proxy:** The built-in dev server automatically proxies all API calls (`/auth`, `/consumer`, `/provider`, `/admin`, `/nodes`, `/health`, `/observability`) to the Coordinator backend on `http://127.0.0.1:8000/`, avoiding CORS issues and cookie domain mismatches.

## Directory Structure

```
frontend/
├── index.html       # Main unified application portal SPA
├── dashboard.css    # Design system, themes, and responsive layouts
├── dashboard.js     # Asynchronous API interactions and view routing
├── server.js        # Zero-dependency Node.js HTTP server & reverse proxy
├── package.json     # Node.js project definition and scripts
└── README.md        # Documentation
```

## Running the Frontend

### Prerequisites
Node.js v18+ (tested with Node.js v24). Zero external npm modules needed.

### Start Command
From this `frontend` directory:
```bash
npm start
# or
node server.js
```

Or from the project root:
```bash
node frontend/server.js
```

### Configuration Options (Environment Variables)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3000` | Port for the frontend web server |
| `HOST` | `0.0.0.0` | Network binding interface |
| `BACKEND_URL` | `http://127.0.0.1:8000` | URL of the Coordinator backend service |
