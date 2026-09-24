# SPECTRA SOC dashboard

The React/Vite dashboard reads the FastAPI runtime through `GET /health`, `GET /stats`, `GET /alerts`, and `GET /alerts/{id}`. It receives new alerts from `WS /ws`; it does not poll for alerts. REST history and live messages are merged by `alert_id`, and the original backend alert object is retained for display.

## Install and run

```sh
npm install
npm run dev
```

Run the FastAPI backend separately. By default the dashboard uses the Vite page's origin for REST and derives `ws:` or `wss:` for the WebSocket. For a backend on another origin, set `VITE_API_BASE_URL` to its HTTP(S) base URL, for example `http://localhost:8000` (no trailing slash required). Set `VITE_WS_URL` to override the WebSocket URL directly, for example `ws://localhost:8000/ws`. Put these settings in `frontend/.env.local`; Vite exposes `VITE_` variables to browser code.

## Build

```sh
npm run build
```

Only values returned by the backend are shown. Missing metrics are represented as `N/A`; no alert or performance sample data is bundled with the UI.
