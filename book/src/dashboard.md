# Dashboard Guide

SentinelX includes a React-based single-page application dashboard for visualizing security data.

## Building the Dashboard

```bash
cd apps/dashboard
npm install
npm run build
```

The built output is in `apps/dashboard/dist/`.

### Prerequisites

| Dependency | Version |
|------------|---------|
| Node.js | 18+ |
| npm | 9+ |

## Technology Stack

- **Framework**: React 18
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Build Tool**: Vite
- **Theme**: Dark theme (security-focused design)

## Dashboard Features

The dashboard connects to the SentinelX backend REST API and provides:

- **System Overview** — System health, uptime, and detection summary
- **Threat View** — Active threats with severity, MITRE ATT&CK mapping, and risk scores
- **Incident Tracker** — Security incidents with status and evidence links
- **Process Monitor** — Running processes with trust assessments
- **Module Viewer** — Kernel modules with integrity and trust status
- **Network Monitor** — Active connections with detection indicators
- **Telemetry Dashboard** — Real-time telemetry event stream and provider health
- **Timeline** — Chronological event visualization
- **Forensics** — Forensic snapshot viewer
- **Fleet Overview** — Agent status and fleet health (if fleet management is enabled)

## Configuration

The dashboard communicates with the backend API. Configure the API URL in the dashboard settings or ensure CORS is properly configured:

```toml
[api]
host = "0.0.0.0"
port = 8443
cors_origins = ["http://localhost:3000"]
```

## Development Mode

```bash
cd apps/dashboard
npm install
npm run dev
```

The development server runs on `http://localhost:5173` with hot module replacement.

## Serving Options

### Standalone

Serve the built `dist/` directory with any static file server:

```bash
npx serve apps/dashboard/dist -p 3000
```

### Behind Reverse Proxy

Use nginx or Caddy to serve the dashboard and proxy API requests:

```nginx
server {
    listen 443 ssl;
    server_name sentinelx.example.com;

    location / {
        root /path/to/sentinelx/apps/dashboard/dist;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8443;
    }
}
```

## Dark Theme

The dashboard uses a dark theme optimized for security operations centers:

- High-contrast text for readability
- Color-coded severity indicators (green, yellow, orange, red)
- Compact data tables for dense information display
- Responsive layout for various screen sizes
